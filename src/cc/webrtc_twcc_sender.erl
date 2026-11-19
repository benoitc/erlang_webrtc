%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Sender side of transport-wide congestion control
%% (draft-holmer-rmcat-transport-wide-cc-extensions-01).
%%
%% Every RTP packet sent on the transport, media and retransmissions
%% alike, carries the next transport-wide sequence number in the
%% transport-wide-cc header extension (§2). `next_seq/1' returns the
%% number to put in the packet and `sent/3' records its send time and
%% size once it leaves; numbers are consecutive, so the two calls must
%% alternate.
%%
%% `feedback/3' consumes a decoded `#rtcp_twcc{}' (§3.1) and returns one
%% result per packet it reports, in sequence order:
%% `{SendTimeUs, ArrivalTimeUs | lost, Size}'. Send times are on the
%% sender clock (the `Now' of `sent/3', converted to microseconds),
%% arrival times on the receiver clock, so only differences of arrival
%% times are meaningful. A packet reported twice is returned once as
%% received; a packet first reported lost and then received (late or
%% reordered) is returned again as received. Sequence numbers we never
%% sent, or forgot, are ignored.
%%
%% The send history is bounded: `max_packets' entries (default 8192)
%% and `max_age' milliseconds (default 10000).
-module(webrtc_twcc_sender).

-include("webrtc_rtp_rtcp.hrl").

-export([new/1, next_seq/1, sent/3, sent/4, feedback/3, tagged_feedback/3, in_flight/1]).

-export_type([state/0, result/0]).

-type result() :: {SendUs :: integer(), ArrivalUs :: integer() | lost, Size :: non_neg_integer()}.

-record(tx, {
    %% Unwrapped sequence number of the next packet.
    next = 0 :: non_neg_integer(),
    oldest = 0 :: non_neg_integer(),
    %% Ext => {SendMs, Size, unreported | lost | received, Tag}.
    history = #{} :: #{non_neg_integer() => {integer(), non_neg_integer(), atom(), term()}},
    max_packets :: pos_integer(),
    max_age :: pos_integer()
}).

-opaque state() :: #tx{}.

-spec new(map()) -> state().
new(Opts) ->
    First = maps:get(initial_seq, Opts, 0),
    #tx{
        next = First,
        oldest = First,
        max_packets = maps:get(max_packets, Opts, 8192),
        max_age = maps:get(max_age, Opts, 10000)
    }.

%% @doc The transport-wide sequence number of the next packet.
-spec next_seq(state()) -> 0..65535.
next_seq(#tx{next = N}) -> N band 16#FFFF.

%% @doc Record the packet carrying `next_seq/1' as sent at `Now' (ms).
-spec sent(non_neg_integer(), integer(), state()) -> state().
sent(Size, Now, S) ->
    sent(Size, Now, undefined, S).

%% @doc The same with a tag returned by `tagged_feedback/3' (a probe
%% cluster, for instance).
-spec sent(non_neg_integer(), integer(), term(), state()) -> state().
sent(Size, Now, Tag, #tx{next = N, history = H} = S) ->
    prune(Now, S#tx{next = N + 1, history = H#{N => {Now, Size, unreported, Tag}}}).

%% @doc Number of recorded packets not yet reported received.
-spec in_flight(state()) -> non_neg_integer().
in_flight(#tx{history = H}) ->
    maps:fold(fun(_, {_, _, St, _}, Acc) when St =/= received -> Acc + 1; (_, _, Acc) -> Acc end, 0, H).

-spec feedback(#rtcp_twcc{}, integer(), state()) -> {[result()], state()}.
feedback(Fb, Now, S) ->
    {Results, _Tagged, S1} = tagged_feedback(Fb, Now, S),
    {Results, S1}.

%% @doc `feedback/3', plus `{Tag, SendUs, ArrivalUs | lost, Size}' for
%% the reported packets that were sent with a tag.
-spec tagged_feedback(#rtcp_twcc{}, integer(), state()) ->
    {[result()], [{term(), integer(), integer() | lost, non_neg_integer()}], state()}.
tagged_feedback(#rtcp_twcc{base_seq = Base} = Fb, Now, #tx{next = N} = S0) when N > 0 ->
    S = prune(Now, S0),
    BaseExt = webrtc_rtp_seq:seq_unwrap(Base, N - 1),
    {_, Results, Tagged, H} = lists:foldl(
        fun({_Seq, Arr}, {Ext, Acc, TAcc, Hist}) ->
            case report(maps:find(Ext, Hist), Arr) of
                skip ->
                    {Ext + 1, Acc, TAcc, Hist};
                {Status, {SendMs, Size, _, Tag}} ->
                    R = {SendMs * 1000, result_arrival(Arr), Size},
                    TAcc1 = case Tag of undefined -> TAcc; _ -> [{Tag, SendMs * 1000, result_arrival(Arr), Size} | TAcc] end,
                    {Ext + 1, [R | Acc], TAcc1, Hist#{Ext := {SendMs, Size, Status, Tag}}}
            end
        end,
        {BaseExt, [], [], S#tx.history},
        webrtc_rtcp_twcc:arrivals(Fb)
    ),
    {lists:reverse(Results), lists:reverse(Tagged), S#tx{history = H}};
tagged_feedback(_Fb, _Now, S) ->
    {[], [], S}.

report(error, _) -> skip;
report({ok, {_, _, received, _}}, _) -> skip;
report({ok, {_, _, lost, _}}, not_received) -> skip;
report({ok, Entry}, not_received) -> {lost, Entry};
report({ok, Entry}, _Arrival) -> {received, Entry}.

result_arrival(not_received) -> lost;
result_arrival(Us) -> Us.

prune(Now, #tx{oldest = O, next = N, history = H, max_packets = Max, max_age = Age} = S) when O < N ->
    case maps:find(O, H) of
        {ok, {SentAt, _, _, _}} when N - O > Max; Now - SentAt > Age ->
            prune(Now, S#tx{oldest = O + 1, history = maps:remove(O, H)});
        {ok, _} ->
            S;
        error ->
            prune(Now, S#tx{oldest = O + 1})
    end;
prune(_Now, S) ->
    S.
