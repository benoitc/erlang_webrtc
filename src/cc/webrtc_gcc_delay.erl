%% @doc Delay-based over-use detection of Google Congestion Control
%% (draft-ietf-rmcat-gcc-02 §5.1 to §5.4).
%%
%% <ul>
%% <li>Pre-filtering (§5.2): packets sent within `burst_time' (5 ms) of
%%     the first packet of a group form a group; a packet that arrives
%%     within 5 ms of the previous one with a negative delay variation
%%     belongs to the current group (a burst after an outage), as long
%%     as the group does not span more than 100 ms of arrivals. Packets
%%     sent before the current group are out of order and ignored.</li>
%% <li>Arrival-time filter (§5.3): the draft allows any adaptive filter.
%%     This module uses the trendline estimator of libwebrtc: the
%%     accumulated inter-group delay variation d(i) is smoothed
%%     (coefficient 0.9) and the slope of a least squares fit over the
%%     last 20 groups is the estimate m(i), scaled by
%%     min(groups, 60) x 4.</li>
%% <li>Over-use detector (§5.4): over-use when m(i) stays above the
%%     adaptive threshold for more than overuse_time_th (10 ms) and two
%%     groups and m(i) is not decreasing; under-use when m(i) is below
%%     minus the threshold. The threshold follows the dynamic equation
%%     of §5.4 with libwebrtc's trendline gains (K_u 0.0087, K_d 0.039),
%%     is not updated when |m(i)| exceeds it by more than 15, and is
%%     clamped to [6, 600], starting at 12.5.</li>
%% </ul>
%%
%% `batch/2' takes the received packets of one feedback message as
%% `{SendUs, ArrivalUs}' in sequence order and returns the signal for
%% the rate controller: `overuse' when over-use was detected while
%% processing the batch, otherwise the detector state. Memory is
%% constant.
-module(webrtc_gcc_delay).

-export([new/0, batch/2, info/1]).

-export_type([state/0, signal/0]).

-type signal() :: overuse | underuse | normal.

-define(BURST_US, 5000).
-define(MAX_BURST_US, 100000).
-define(WINDOW, 20).
-define(SMOOTHING, 0.9).
-define(GAIN, 4.0).
-define(MIN_DELTAS, 60).
-define(MAX_DELTAS, 1000).
-define(OVERUSE_MS, 10.0).
-define(K_UP, 0.0087).
-define(K_DOWN, 0.039).
-define(MAX_ADAPT, 15.0).

%% A group: {FirstSendUs, LastSendUs, FirstArrivalUs, LastArrivalUs}.
-record(delay, {
    cur :: undefined | {integer(), integer(), integer(), integer()},
    prev :: undefined | {integer(), integer(), integer(), integer()},
    deltas = 0 :: non_neg_integer(),
    first_arrival :: undefined | float(),
    acc = 0.0 :: float(),
    smoothed = 0.0 :: float(),
    window = queue:new() :: queue:queue({float(), float()}),
    wlen = 0 :: non_neg_integer(),
    trend = 0.0 :: float(),
    prev_trend = 0.0 :: float(),
    threshold = 12.5 :: float(),
    last_update :: undefined | float(),
    time_over = -1.0 :: float(),
    over_count = 0 :: non_neg_integer(),
    modified = 0.0 :: float(),
    state = normal :: signal()
}).

-opaque state() :: #delay{}.

-spec new() -> state().
new() -> #delay{}.

-spec batch([{integer(), integer()}], state()) -> {signal(), state()}.
batch(Packets, D0) ->
    {Over, D} = lists:foldl(
        fun({S, A}, {O, D1}) ->
            D2 = packet(S, A, D1),
            {O orelse (D2#delay.state =:= overuse andalso D1#delay.state =/= overuse), D2}
        end,
        {false, D0},
        Packets
    ),
    case Over of
        true -> {overuse, D};
        false -> {D#delay.state, D}
    end.

-spec info(state()) -> map().
info(#delay{} = D) ->
    #{state => D#delay.state, trend => D#delay.modified, threshold => D#delay.threshold}.

%%====================================================================
%% Pre-filtering: packet groups
%%====================================================================

packet(S, A, #delay{cur = undefined} = D) ->
    D#delay{cur = {S, S, A, A}};
packet(S, _A, #delay{cur = {FS, _, _, _}} = D) when S < FS ->
    D;
packet(S, A, #delay{cur = {FS, LS, FA, LA} = Cur} = D) ->
    case belongs(S, A, Cur) orelse S - FS =< ?BURST_US of
        true ->
            D#delay{cur = {FS, max(LS, S), FA, max(LA, A)}};
        false ->
            D1 =
                case D#delay.prev of
                    undefined -> D;
                    {_, PLS, _, PLA} -> group_delta(LA - PLA, LS - PLS, LA, D)
                end,
            D1#delay{prev = Cur, cur = {S, S, A, A}}
    end.

belongs(S, A, {_, LS, FA, LA}) ->
    ArrDelta = A - LA,
    SendDelta = S - LS,
    SendDelta =:= 0 orelse
        (ArrDelta - SendDelta < 0 andalso ArrDelta =< ?BURST_US andalso A - FA < ?MAX_BURST_US).

%% Reordered groups (negative arrival delta) carry no delay information.
group_delta(ArrDeltaUs, _SendDeltaUs, _ArrUs, D) when ArrDeltaUs < 0 ->
    D;
group_delta(ArrDeltaUs, SendDeltaUs, ArrUs, D) ->
    trendline(ArrDeltaUs / 1000, SendDeltaUs / 1000, ArrUs / 1000, D).

%%====================================================================
%% Trendline estimator
%%====================================================================

trendline(RecvDelta, SendDelta, Arrival, D) ->
    N = min(D#delay.deltas + 1, ?MAX_DELTAS),
    First =
        case D#delay.first_arrival of
            undefined -> Arrival;
            F -> F
        end,
    Acc = D#delay.acc + (RecvDelta - SendDelta),
    Smoothed = ?SMOOTHING * D#delay.smoothed + (1 - ?SMOOTHING) * Acc,
    W0 = queue:in({Arrival - First, Smoothed}, D#delay.window),
    {W, Len} =
        case D#delay.wlen + 1 > ?WINDOW of
            true -> {queue:drop(W0), ?WINDOW};
            false -> {W0, D#delay.wlen + 1}
        end,
    Trend =
        case Len =:= ?WINDOW andalso slope(queue:to_list(W)) of
            false -> D#delay.trend;
            undefined -> D#delay.trend;
            Slope -> Slope
        end,
    detect(Trend, SendDelta, Arrival, D#delay{
        deltas = N, first_arrival = First, acc = Acc, smoothed = Smoothed, window = W, wlen = Len, trend = Trend
    }).

slope(Points) ->
    N = length(Points),
    Xa = lists:sum([X || {X, _} <- Points]) / N,
    Ya = lists:sum([Y || {_, Y} <- Points]) / N,
    Num = lists:sum([(X - Xa) * (Y - Ya) || {X, Y} <- Points]),
    Den = lists:sum([(X - Xa) * (X - Xa) || {X, _} <- Points]),
    case Den == 0 of
        true -> undefined;
        false -> Num / Den
    end.

%%====================================================================
%% Over-use detector with adaptive threshold
%%====================================================================

detect(_Trend, _SendDelta, _Now, #delay{deltas = N} = D) when N < 2 ->
    D#delay{state = normal};
detect(Trend, SendDelta, Now, #delay{threshold = Th} = D) ->
    M = min(D#delay.deltas, ?MIN_DELTAS) * Trend * ?GAIN,
    D1 =
        if
            M > Th ->
                TimeOver =
                    case D#delay.time_over < 0 of
                        true -> SendDelta / 2;
                        false -> D#delay.time_over + SendDelta
                    end,
                Count = D#delay.over_count + 1,
                case TimeOver > ?OVERUSE_MS andalso Count > 1 andalso Trend >= D#delay.prev_trend of
                    true -> D#delay{time_over = 0.0, over_count = 0, state = overuse};
                    false -> D#delay{time_over = TimeOver, over_count = Count}
                end;
            M < -Th ->
                D#delay{time_over = -1.0, over_count = 0, state = underuse};
            true ->
                D#delay{time_over = -1.0, over_count = 0, state = normal}
        end,
    threshold(M, Now, D1#delay{prev_trend = Trend, modified = M}).

threshold(M, Now, #delay{last_update = undefined} = D) ->
    threshold(M, Now, D#delay{last_update = Now});
threshold(M, Now, #delay{threshold = Th} = D) when abs(M) > Th + ?MAX_ADAPT ->
    D#delay{last_update = Now};
threshold(M, Now, #delay{threshold = Th, last_update = Last} = D) ->
    K =
        case abs(M) < Th of
            true -> ?K_DOWN;
            false -> ?K_UP
        end,
    Dt = min(Now - Last, 100.0),
    Th1 = Th + K * (abs(M) - Th) * Dt,
    D#delay{threshold = min(max(Th1, 6.0), 600.0), last_update = Now}.
