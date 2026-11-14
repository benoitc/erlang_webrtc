%% @doc Bit rate over a sliding time window, in one-millisecond buckets.
%%
%% `add/3' records bytes at a time in milliseconds and `rate/2' returns
%% the bit rate over the window ending at a time. A sample older than
%% the newest bucket is merged into it (reordering by a few
%% milliseconds does not matter at the window scale). The rate is
%% `undefined' until the first sample is a whole window old, so a short
%% burst at start is not reported as a high rate. Memory is bounded by
%% the window length: at most one bucket per millisecond.
-module(webrtc_cc_rate).

-export([new/1, add/3, rate/2, bytes/2]).

-export_type([rate/0]).

-record(rate, {
    window :: pos_integer(),
    buckets = queue:new() :: queue:queue({integer(), non_neg_integer()}),
    sum = 0 :: non_neg_integer(),
    first :: undefined | integer()
}).

-opaque rate() :: #rate{}.

-spec new(pos_integer()) -> rate().
new(WindowMs) when is_integer(WindowMs), WindowMs > 0 ->
    #rate{window = WindowMs}.

-spec add(integer(), non_neg_integer(), rate()) -> rate().
add(T, Bytes, #rate{first = undefined} = R) ->
    add(T, Bytes, R#rate{first = T});
add(T, Bytes, R0) ->
    R = prune(T, R0),
    case queue:peek_r(R#rate.buckets) of
        {value, {Last, B}} when T =< Last ->
            Q1 = queue:in({Last, B + Bytes}, queue:drop_r(R#rate.buckets)),
            R#rate{buckets = Q1, sum = R#rate.sum + Bytes};
        _ ->
            R#rate{buckets = queue:in({T, Bytes}, R#rate.buckets), sum = R#rate.sum + Bytes}
    end.

%% @doc Bits per second over `(T - window, T]'.
-spec rate(integer(), rate()) -> non_neg_integer() | undefined.
rate(_T, #rate{first = undefined}) ->
    undefined;
rate(T, #rate{first = F, window = W}) when T - F < W ->
    undefined;
rate(T, R0) ->
    #rate{sum = Sum, window = W} = prune(T, R0),
    Sum * 8000 div W.

%% @doc Bytes recorded in `(T - window, T]'.
-spec bytes(integer(), rate()) -> non_neg_integer().
bytes(T, R) ->
    (prune(T, R))#rate.sum.

prune(T, #rate{buckets = Q, sum = Sum, window = W} = R) ->
    case queue:peek(Q) of
        {value, {At, B}} when At =< T - W ->
            prune(T, R#rate{buckets = queue:drop(Q), sum = Sum - B});
        _ ->
            R
    end.
