%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Leaky bucket pacer for outgoing media, as a sans-IO engine.
%%
%% Packets are `{Class, Size, Data}' with `Class' one of `audio', `rtx'
%% (retransmissions) or `video'; `Size' is the number of bytes on the
%% wire and `Data' is opaque. The pacer sends at the pacing rate (the
%% rate given to `new/1' or `set_rate/3', normally `pacing_factor' times
%% the target bitrate of the congestion controller):
%%
%% <ul>
%% <li>The budget grows by rate x elapsed time and is capped at `burst_ms'
%%     worth of the rate (at least one 1500 byte packet), so an idle
%%     period never turns into a long burst.</li>
%% <li>A packet leaves while the budget is positive; its size is taken
%%     from the budget, which may go negative by at most one packet.
%%     Over any interval the bytes sent are at most rate x interval plus
%%     the burst cap plus one packet.</li>
%% <li>Audio leaves before retransmissions, which leave before video.
%%     Each class is first in, first out.</li>
%% <li>The queue holds at most `max_packets'. When it is full the oldest
%%     video packet is dropped (the incoming one when it is video and no
%%     video is queued), then the oldest retransmission, then the oldest
%%     audio packet. Drops are counted per class.</li>
%% <li>With `max_queue_ms' set, the pacer temporarily sends faster when
%%     the queue would otherwise take longer than that to drain (as
%%     libwebrtc's pacer does), which bounds the queuing delay.</li>
%% </ul>
%%
%% Times are integer milliseconds supplied by the caller.
-module(webrtc_pacer).

-export([
    new/1,
    set_rate/3,
    rate/1,
    enqueue/3,
    handle_timeout/2,
    next_timeout/1,
    flush/1,
    queue_length/1,
    stats/1
]).

-export_type([pacer/0, packet/0, class/0]).

-type class() :: audio | rtx | video.
-type packet() :: {class(), pos_integer(), term()}.

-define(MAX_PACKET, 1500).
-define(CLASSES, [audio, rtx, video]).

-record(pacer, {
    %% Pacing rate in bits per second.
    rate :: pos_integer(),
    burst_ms :: pos_integer(),
    %% Budget in millibits (bits x 1000), so rate x ms stays an integer.
    budget :: integer(),
    last :: undefined | integer(),
    queues :: #{class() => queue:queue({integer(), packet()})},
    len = 0 :: non_neg_integer(),
    bytes = 0 :: non_neg_integer(),
    max_packets :: pos_integer(),
    max_queue_ms :: pos_integer() | infinity,
    sent = 0 :: non_neg_integer(),
    sent_bytes = 0 :: non_neg_integer(),
    dropped = #{audio => 0, rtx => 0, video => 0} :: #{class() => non_neg_integer()},
    max_delay = 0 :: non_neg_integer()
}).

-opaque pacer() :: #pacer{}.

%% @doc Options: `rate' (bits per second, required), `burst_ms'
%% (default 10), `max_packets' (default 1000), `max_queue_ms' (default
%% `infinity').
-spec new(#{rate := pos_integer(), _ => _}) -> pacer().
new(#{rate := Rate} = Opts) when is_integer(Rate), Rate > 0 ->
    P = #pacer{
        rate = Rate,
        burst_ms = maps:get(burst_ms, Opts, 10),
        budget = 0,
        queues = maps:from_list([{C, queue:new()} || C <- ?CLASSES]),
        max_packets = maps:get(max_packets, Opts, 1000),
        max_queue_ms = maps:get(max_queue_ms, Opts, infinity)
    },
    P#pacer{budget = cap(P)}.

%% @doc Change the pacing rate. The budget earned so far is kept.
-spec set_rate(pos_integer(), integer(), pacer()) -> pacer().
set_rate(Rate, Now, P) when is_integer(Rate), Rate > 0 ->
    P1 = refill(Now, P),
    P1#pacer{rate = Rate, budget = min(P1#pacer.budget, cap(P1#pacer{rate = Rate}))}.

-spec rate(pacer()) -> pos_integer().
rate(#pacer{rate = R}) -> R.

%% @doc Queue a packet and return the packets that may leave now, in
%% order (possibly including packets queued earlier).
-spec enqueue(packet(), integer(), pacer()) -> {[packet()], pacer()}.
enqueue({Class, Size, _} = Pkt, Now, P0) when is_integer(Size), Size > 0 ->
    true = lists:member(Class, ?CLASSES),
    P1 = refill(Now, P0),
    P2 =
        case P1#pacer.len >= P1#pacer.max_packets of
            true -> make_room(Pkt, Now, P1);
            false -> {insert, P1}
        end,
    case P2 of
        {insert, P3} -> drain(Now, insert(Pkt, Now, P3), []);
        {dropped, P3} -> drain(Now, P3, [])
    end.

-spec handle_timeout(integer(), pacer()) -> {[packet()], pacer()}.
handle_timeout(Now, P) ->
    drain(Now, refill(Now, P), []).

%% @doc When the next packet may leave, `infinity' when the queue is
%% empty.
-spec next_timeout(pacer()) -> integer() | infinity.
next_timeout(#pacer{len = 0}) ->
    infinity;
next_timeout(#pacer{last = Last, budget = B}) when B > 0 ->
    Last;
next_timeout(#pacer{last = Last, budget = B} = P) ->
    R = effective_rate(Last, P),
    Last + max(1, ceil_div(1 - B, R)).

%% @doc Remove every queued packet, in priority order, without pacing.
-spec flush(pacer()) -> {[packet()], pacer()}.
flush(P) ->
    Pkts = lists:append([[Pkt || {_, Pkt} <- queue:to_list(maps:get(C, P#pacer.queues))] || C <- ?CLASSES]),
    {Pkts, P#pacer{queues = maps:from_list([{C, queue:new()} || C <- ?CLASSES]), len = 0, bytes = 0}}.

-spec queue_length(pacer()) -> non_neg_integer().
queue_length(#pacer{len = L}) -> L.

-spec stats(pacer()) -> map().
stats(#pacer{} = P) ->
    #{
        rate => P#pacer.rate,
        queued => P#pacer.len,
        queued_bytes => P#pacer.bytes,
        sent => P#pacer.sent,
        sent_bytes => P#pacer.sent_bytes,
        dropped => P#pacer.dropped,
        max_queue_delay => P#pacer.max_delay
    }.

%%====================================================================
%% Internal
%%====================================================================

cap(#pacer{rate = R, burst_ms = B}) ->
    max(R * B, ?MAX_PACKET * 8000).

%% The drain rate: the pacing rate, or faster when the queue would not
%% drain before its oldest packet has waited max_queue_ms.
effective_rate(_Now, #pacer{rate = R, max_queue_ms = infinity}) ->
    R;
effective_rate(_Now, #pacer{rate = R, len = 0}) ->
    R;
effective_rate(Now, #pacer{rate = R, max_queue_ms = Q, bytes = Bytes} = P) ->
    Left = max(1, Q - (Now - oldest(P))),
    max(R, ceil_div(Bytes * 8000, Left)).

oldest(#pacer{queues = Qs}) ->
    lists:min([T || C <- ?CLASSES, {value, {T, _}} <- [queue:peek(maps:get(C, Qs))]]).

refill(Now, #pacer{last = undefined} = P) ->
    P#pacer{last = Now};
refill(Now, #pacer{last = Last} = P) when Now =< Last ->
    P;
refill(Now, #pacer{last = Last, budget = B} = P) ->
    Earned = effective_rate(Last, P) * (Now - Last),
    P#pacer{last = Now, budget = min(B + Earned, cap(P))}.

drain(Now, #pacer{len = L, budget = B} = P, Acc) when L > 0, B > 0 ->
    {Enq, {_, Size, _} = Pkt, P1} = pop(P),
    drain(Now, P1#pacer{
        budget = B - Size * 8000,
        sent = P1#pacer.sent + 1,
        sent_bytes = P1#pacer.sent_bytes + Size,
        max_delay = max(P1#pacer.max_delay, Now - Enq)
    }, [Pkt | Acc]);
drain(_Now, P, Acc) ->
    {lists:reverse(Acc), P}.

pop(#pacer{queues = Qs} = P) ->
    [C | _] = [C || C <- ?CLASSES, not queue:is_empty(maps:get(C, Qs))],
    {{value, {Enq, {_, Size, _} = Pkt}}, Q1} = queue:out(maps:get(C, Qs)),
    {Enq, Pkt, P#pacer{queues = Qs#{C := Q1}, len = P#pacer.len - 1, bytes = P#pacer.bytes - Size}}.

insert({Class, Size, _} = Pkt, Now, #pacer{queues = Qs} = P) ->
    P#pacer{
        queues = Qs#{Class := queue:in({Now, Pkt}, maps:get(Class, Qs))},
        len = P#pacer.len + 1,
        bytes = P#pacer.bytes + Size
    }.

%% The queue is full: drop the oldest video packet, or the incoming
%% packet when it is video and no video is queued, then the oldest
%% retransmission, then the oldest audio packet.
make_room({Class, _, _}, _Now, #pacer{queues = Qs} = P) ->
    case queue:is_empty(maps:get(video, Qs)) of
        false ->
            {insert, drop_oldest(video, P)};
        true when Class =:= video ->
            {dropped, count_drop(video, P)};
        true ->
            case queue:is_empty(maps:get(rtx, Qs)) of
                false -> {insert, drop_oldest(rtx, P)};
                true -> {insert, drop_oldest(audio, P)}
            end
    end.

drop_oldest(C, #pacer{queues = Qs} = P) ->
    {{value, {_, {_, Size, _}}}, Q1} = queue:out(maps:get(C, Qs)),
    count_drop(C, P#pacer{queues = Qs#{C := Q1}, len = P#pacer.len - 1, bytes = P#pacer.bytes - Size}).

count_drop(C, #pacer{dropped = D} = P) ->
    P#pacer{dropped = D#{C := maps:get(C, D) + 1}}.

ceil_div(A, B) -> (A + B - 1) div B.
