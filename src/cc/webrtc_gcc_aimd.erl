%% @doc AIMD rate controller of the delay-based part of Google
%% Congestion Control (draft-ietf-rmcat-gcc-02 §5.5).
%%
%% States Hold, Increase and Decrease follow the transition table of
%% §5.5: over-use moves to Decrease, normal moves Hold to Increase and
%% Decrease to Hold, under-use moves to Hold.
%%
%% <ul>
%% <li>Increase: multiplicative (at most 8% per second) while far from
%%     convergence, additive (half an expected packet per response time,
%%     response time = RTT + 100 ms) when the incoming rate R_hat is
%%     within three standard deviations of the average rate measured at
%%     the previous decreases (exponential average, smoothing 0.95). An
%%     R_hat above that range resets the average, and so does one below
%%     it at a decrease (as libwebrtc does: the capacity fell). The
%%     estimate never goes above 1.5 R_hat + 10 kbps.</li>
%% <li>Decrease: A_hat = beta R_hat with beta 0.85, never above the
%%     current estimate, then Hold. A further decrease waits one RTT
%%     (between 10 and 200 ms) unless R_hat fell below half the
%%     estimate.</li>
%% <li>Startup: RFC 8836 §2 item 4 allows a faster startup. Until the
%%     first decrease, the multiplicative increase uses `startup_gain'
%%     per second (default 1.5) instead of 1.08.</li>
%% </ul>
%%
%% Rates are bits per second, times milliseconds.
-module(webrtc_gcc_aimd).

-export([new/1, update/5, rate/1, set_rate/2, set_limits/3, last_decrease/1, info/1]).

-export_type([state/0]).

-define(BETA, 0.85).
-define(GAIN, 1.08).

-record(aimd, {
    rate :: pos_integer(),
    min :: pos_integer(),
    max :: pos_integer(),
    state = increase :: hold | increase | decrease,
    region = max_unknown :: max_unknown | near_max,
    %% Average and normalized variance of R_hat at decreases, kbps.
    avg_max :: undefined | float(),
    var_max = 0.4 :: float(),
    last_change :: undefined | integer(),
    last_decrease :: undefined | integer(),
    startup = true :: boolean(),
    startup_gain :: float()
}).

-opaque state() :: #aimd{}.

-spec new(#{start := pos_integer(), min := pos_integer(), max := pos_integer(), startup_gain => float()}) ->
    state().
new(#{start := Start, min := Min, max := Max} = Opts) ->
    #aimd{
        rate = clamp(Start, Min, Max),
        min = Min,
        max = Max,
        startup_gain = float(maps:get(startup_gain, Opts, 1.5))
    }.

-spec rate(state()) -> pos_integer().
rate(#aimd{rate = R}) -> R.

%% @doc Set the estimate (a feedback timeout or new limits).
-spec set_rate(pos_integer(), state()) -> state().
set_rate(R, #aimd{min = Min, max = Max} = A) -> A#aimd{rate = clamp(R, Min, Max)}.

%% @doc When the estimate was last decreased on over-use.
-spec last_decrease(state()) -> integer() | undefined.
last_decrease(#aimd{last_decrease = T}) -> T.

%% @doc Change the bounds, keeping the controller state.
-spec set_limits(pos_integer(), pos_integer(), state()) -> state().
set_limits(Min, Max, A) -> set_rate(A#aimd.rate, A#aimd{min = Min, max = Max}).

-spec info(state()) -> map().
info(#aimd{} = A) ->
    #{rate => A#aimd.rate, state => A#aimd.state, region => A#aimd.region, startup => A#aimd.startup,
      avg_max => A#aimd.avg_max}.

%% @doc Run the controller with the detector signal, the incoming rate
%% R_hat (`undefined' while unknown), the RTT and the current time.
-spec update(webrtc_gcc_delay:signal(), non_neg_integer() | undefined, pos_integer(), integer(), state()) ->
    state().
update(Signal, RHat, Rtt, Now, A0) ->
    Dt =
        case A0#aimd.last_change of
            undefined -> 0;
            T -> min(Now - T, 1000)
        end,
    A = A0#aimd{state = transition(Signal, A0#aimd.state)},
    case A#aimd.state of
        hold ->
            A#aimd{last_change = Now};
        increase ->
            increase(RHat, Rtt, Dt, Now, A);
        decrease ->
            case may_decrease(RHat, Rtt, Now, A) of
                true -> decrease(RHat, Now, A);
                false -> A
            end
    end.

transition(overuse, _) -> decrease;
transition(normal, hold) -> increase;
transition(normal, decrease) -> hold;
transition(normal, S) -> S;
transition(underuse, _) -> hold.

increase(RHat, Rtt, Dt, Now, #aimd{rate = R} = A0) ->
    A = check_range(RHat, A0),
    Inc =
        case A#aimd.region of
            near_max -> additive(R, Rtt, Dt);
            max_unknown -> multiplicative(R, Dt, A)
        end,
    New0 = R + Inc,
    New =
        case RHat of
            undefined -> New0;
            _ -> min(New0, max(R, round(1.5 * RHat) + 10000))
        end,
    A#aimd{rate = clamp(New, A#aimd.min, A#aimd.max), last_change = Now}.

%% R_hat above the average of the previous decreases: the congestion
%% level changed, start over with multiplicative increase.
check_range(undefined, A) ->
    A;
check_range(_RHat, #aimd{avg_max = undefined} = A) ->
    A;
check_range(RHat, #aimd{avg_max = Avg, var_max = Var} = A) ->
    Std = math:sqrt(Var * Avg),
    case RHat / 1000 > Avg + 3 * Std of
        true -> A#aimd{avg_max = undefined, region = max_unknown};
        false -> A
    end.

%% R_hat at a decrease far below the average: the capacity fell, the
%% old average says nothing about the new level. Start it over, as the
%% reference implementation does, so the increase after the next
%% recovery is not held back by a stale average.
below_range(_Kbps, #aimd{avg_max = undefined} = A) ->
    A;
below_range(Kbps, #aimd{avg_max = Avg, var_max = Var} = A) ->
    case Kbps < Avg - 3 * math:sqrt(Var * Avg) of
        true -> A#aimd{avg_max = undefined};
        false -> A
    end.

multiplicative(R, Dt, #aimd{startup = Startup, startup_gain = G}) ->
    Gain =
        case Startup of
            true -> G;
            false -> ?GAIN
        end,
    Eta = math:pow(Gain, Dt / 1000),
    max(round(R * (Eta - 1)), 1000).

additive(R, Rtt, Dt) ->
    Response = 100 + Rtt,
    Alpha = 0.5 * min(Dt / Response, 1.0),
    BitsPerFrame = R / 30,
    PacketsPerFrame = max(1, ceil(BitsPerFrame / (1200 * 8))),
    AvgPacketBits = BitsPerFrame / PacketsPerFrame,
    max(1000, round(Alpha * AvgPacketBits)).

may_decrease(_RHat, _Rtt, _Now, #aimd{last_decrease = undefined}) ->
    true;
may_decrease(RHat, Rtt, Now, #aimd{last_decrease = Last, rate = R}) ->
    Interval = min(max(Rtt, 10), 200),
    Now - Last >= Interval orelse (RHat =/= undefined andalso RHat < R / 2).

decrease(undefined, Now, #aimd{rate = R} = A) ->
    after_decrease(round(R * ?BETA), Now, A);
decrease(RHat, Now, #aimd{rate = R} = A0) ->
    A = update_max(RHat / 1000, below_range(RHat / 1000, A0)),
    after_decrease(min(round(?BETA * RHat), R), Now, A#aimd{region = near_max}).

after_decrease(New, Now, A) ->
    A#aimd{
        rate = clamp(New, A#aimd.min, A#aimd.max),
        state = hold,
        last_change = Now,
        last_decrease = Now,
        startup = false
    }.

update_max(Kbps, #aimd{avg_max = undefined} = A) ->
    update_var(Kbps, A#aimd{avg_max = Kbps});
update_max(Kbps, #aimd{avg_max = Avg} = A) ->
    update_var(Kbps, A#aimd{avg_max = 0.95 * Avg + 0.05 * Kbps}).

update_var(Kbps, #aimd{avg_max = Avg, var_max = Var} = A) ->
    Norm = max(Avg, 1.0),
    V = 0.95 * Var + 0.05 * (Avg - Kbps) * (Avg - Kbps) / Norm,
    A#aimd{var_max = min(max(V, 0.4), 2.5)}.

clamp(V, Min, Max) -> min(max(V, Min), Max).
