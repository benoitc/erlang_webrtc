%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Token bucket that holds one media stream to a bit rate, as a
%% sans-IO engine: the limit a peer set with TMMBR (RFC 5104 §4.2.1.2,
%% RFC 8834 §5.1.6).
%%
%% <ul>
%% <li>Items are opaque, each with the number of bits it counts for.
%%     The budget grows by rate x elapsed time and is capped at
%%     `burst_ms' of the rate (at least one 1500 byte packet); an item
%%     leaves while the budget is positive and takes its bits from it.
%%     Over any interval the bits released are at most rate x interval
%%     plus the cap plus one item.</li>
%% <li>`charge/3' takes bits sent outside the queue (FEC) from the
%%     budget.</li>
%% <li>The queue holds at most `max_items'; when full the oldest item is
%%     dropped. At rate 0 every item is dropped. Drops are counted.</li>
%% <li>With rate `infinity' items pass at once.</li>
%% <li>`packet_rate/2' is the number of items released over the last
%%     second, for the limits that depend on it.</li>
%% </ul>
%%
%% Times are integer milliseconds supplied by the caller.
-module(webrtc_rate_limit).

-export([
    new/1,
    set_rate/3,
    rate/1,
    enqueue/4,
    charge/3,
    handle_timeout/2,
    next_timeout/1,
    packet_rate/2,
    queue_length/1,
    dropped/1
]).
-export_type([state/0]).

-define(MAX_PACKET_BITS, 12000).
-define(WINDOW, 1000).

-record(rl, {
    rate = infinity :: non_neg_integer() | infinity,
    burst_ms :: pos_integer(),
    %% Budget in millibits, so rate x ms stays an integer.
    budget = 0 :: integer(),
    last :: undefined | integer(),
    queue = queue:new() :: queue:queue({pos_integer(), term()}),
    len = 0 :: non_neg_integer(),
    max_items :: pos_integer(),
    %% Release times over the last second.
    released = queue:new() :: queue:queue(integer()),
    dropped = 0 :: non_neg_integer()
}).

-opaque state() :: #rl{}.

%% @doc Options: `rate' (bits per second or `infinity', default
%% `infinity'), `burst_ms' (default 40), `max_items' (default 256).
-spec new(map()) -> state().
new(Opts) ->
    L = #rl{
        rate = maps:get(rate, Opts, infinity),
        burst_ms = maps:get(burst_ms, Opts, 40),
        max_items = maps:get(max_items, Opts, 256)
    },
    L#rl{budget = cap(L)}.

%% @doc Change the rate; the budget earned so far is kept up to the new
%% cap. Queued items are released by the next `handle_timeout/2'.
-spec set_rate(non_neg_integer() | infinity, integer(), state()) -> state().
set_rate(Rate, Now, L) when Rate =:= infinity; is_integer(Rate), Rate >= 0 ->
    L1 = refill(Now, L),
    L2 = L1#rl{rate = Rate},
    L2#rl{budget = min(L2#rl.budget, cap(L2))}.

-spec rate(state()) -> non_neg_integer() | infinity.
rate(#rl{rate = R}) -> R.

%% @doc Queue an item that counts for `Bits'; returns the items that
%% may leave now, in order.
-spec enqueue(term(), pos_integer(), integer(), state()) -> {[term()], state()}.
enqueue(_Item, _Bits, _Now, #rl{rate = 0, dropped = D} = L) ->
    {[], L#rl{dropped = D + 1}};
enqueue(Item, Bits, Now, #rl{len = Len, max_items = Max} = L0) ->
    L1 = case Len >= Max of
             true ->
                 {_, Q} = queue:out(L0#rl.queue),
                 L0#rl{queue = Q, len = Len - 1, dropped = L0#rl.dropped + 1};
             false ->
                 L0
         end,
    L2 = L1#rl{queue = queue:in({Bits, Item}, L1#rl.queue), len = L1#rl.len + 1},
    handle_timeout(Now, L2).

%% @doc Take `Bits' sent without the queue from the budget.
-spec charge(non_neg_integer(), integer(), state()) -> state().
charge(_Bits, _Now, #rl{rate = infinity} = L) ->
    L;
charge(Bits, Now, L) ->
    L1 = refill(Now, L),
    L1#rl{budget = L1#rl.budget - Bits * 1000}.

-spec handle_timeout(integer(), state()) -> {[term()], state()}.
handle_timeout(_Now, #rl{rate = 0, len = Len} = L) when Len > 0 ->
    {[], L#rl{queue = queue:new(), len = 0, dropped = L#rl.dropped + Len}};
handle_timeout(Now, L) ->
    drain(Now, refill(Now, L), []).

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#rl{len = 0}) ->
    infinity;
next_timeout(#rl{rate = R, last = Last}) when R =:= infinity; R =:= 0 ->
    Last;
next_timeout(#rl{rate = R, last = Last, budget = B}) when B > 0 ->
    _ = R,
    Last;
next_timeout(#rl{rate = R, last = Last, budget = B}) ->
    Last + ceil_div(1 - B, R).

%% @doc Items released over the last second, as a packet rate.
-spec packet_rate(integer(), state()) -> non_neg_integer().
packet_rate(Now, #rl{released = Q}) ->
    length([T || T <- queue:to_list(Q), T > Now - ?WINDOW]).

-spec queue_length(state()) -> non_neg_integer().
queue_length(#rl{len = L}) -> L.

-spec dropped(state()) -> non_neg_integer().
dropped(#rl{dropped = D}) -> D.

%%====================================================================
%% Internal
%%====================================================================

cap(#rl{rate = infinity}) -> 0;
cap(#rl{rate = R, burst_ms = B}) -> max(R * B, ?MAX_PACKET_BITS * 1000).

refill(Now, #rl{last = undefined} = L) ->
    L#rl{last = Now};
refill(Now, #rl{last = Last} = L) when Now =< Last ->
    L;
refill(Now, #rl{rate = infinity} = L) ->
    L#rl{last = Now};
refill(Now, #rl{last = Last, budget = B, rate = R} = L) ->
    L#rl{last = Now, budget = min(cap(L), B + R * (Now - Last))}.

drain(Now, #rl{len = Len, rate = R, budget = B} = L, Acc) when Len > 0, R =:= infinity orelse B > 0 ->
    {{value, {Bits, Item}}, Q} = queue:out(L#rl.queue),
    B1 = case R of infinity -> B; _ -> B - Bits * 1000 end,
    drain(Now, L#rl{queue = Q, len = Len - 1, budget = B1, released = mark(Now, L#rl.released)}, [Item | Acc]);
drain(_Now, L, Acc) ->
    {lists:reverse(Acc), L}.

mark(Now, Q) ->
    trim(Now, queue:in(Now, Q)).

trim(Now, Q) ->
    case queue:peek(Q) of
        {value, T} when T =< Now - ?WINDOW -> trim(Now, queue:drop(Q));
        _ -> Q
    end.

ceil_div(A, B) -> (A + B - 1) div B.
