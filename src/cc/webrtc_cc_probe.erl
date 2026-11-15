%% @doc Bandwidth probing, without I/O: probe clusters sent ahead of the
%% estimate and the bitrate they show, as libwebrtc's probe controller
%% and probe bitrate estimator do.
%%
%% Without probes the estimate grows from its start value by about 8%
%% a second (draft-ietf-rmcat-gcc §5.5), so a 2 Mbps link takes seconds
%% to fill. Once media flows with transport-wide feedback, clusters of
%% padding packets are sent at 3 and 6 times the start bitrate, each for
%% at least 15 ms and 5 packets. The feedback on a cluster gives a send
%% rate and a receive rate; with 80% of its packets received the result
%% is the smaller of the two, 95% of the receive rate when the link
%% could not carry the cluster. A result above 70% of the probed rate
%% probes again at twice the result, up to `max_bitrate'.
%%
%% After start-up, `update/3' follows the estimate and the sending
%% rate and probes again, as libwebrtc's ProbeController does:
%% <ul>
%% <li>Application limited (ALR): sending under 65% of the estimate for
%%     500 ms, until it is back over 80%. While it lasts a cluster at
%%     twice the estimate goes every 5 s, so the estimate keeps up with
%%     the link while the application sends little.</li>
%% <li>After a large drop: the estimate fell under 66% of its previous
%%     value, the delay detector leaves over-use within 5 s, and a probe
%%     at 85% of the rate before the drop would still raise it.</li>
%% <li>On a raised `max_bitrate' (`max_raised/5'): the estimate was at
%%     the old maximum, so the new one is probed at once.</li>
%% </ul>
%% At most one cluster is in flight, and these probes are limited to
%% 10 a minute.
%%
%% `handle_timeout/2' returns `{probe, Cluster, Size}' padding packets
%% to send now; the caller tags them with the cluster in the
%% transport-wide send history so `feedback/3' sees which results belong
%% to a probe.
-module(webrtc_cc_probe).

-export([new/1, start/3, update/3, max_raised/5, handle_timeout/2, next_timeout/1, feedback/3, info/1]).

-export_type([state/0]).

%% libwebrtc's ProbeController and ProbeBitrateEstimator constants.
-define(MIN_DURATION_MS, 15).
-define(MIN_PACKETS, 5).
-define(PACKET_SIZE, 250).
-define(MIN_RECEIVED, 0.80).
-define(MAX_INTERVAL_US, 1000000).
-define(UNSATURATED, 0.90).
-define(UTILIZATION, 0.95).
-define(MAX_RATIO, 2.0).
-define(FURTHER, 0.70).
%% A cluster that got no usable feedback in this time is given up.
-define(RESULT_TIMEOUT, 2000).
%% AlrDetector and ProbeController.
-define(ALR_START, 0.65).
-define(ALR_STOP, 0.80).
-define(ALR_MS, 500).
-define(ALR_INTERVAL, 5000).
-define(ALR_SCALE, 2).
-define(DROP, 0.66).
-define(DROP_TIMEOUT, 5000).
-define(AFTER_DROP, 0.85).
-define(UNCERTAINTY, 0.05).
-define(CAPPED, 0.9).
-define(BUDGET, 10).
-define(BUDGET_MS, 60000).

-record(cluster, {
    id :: pos_integer(),
    rate :: pos_integer(),
    packets :: pos_integer(),
    sent = 0 :: non_neg_integer(),
    started :: undefined | integer(),
    %% {SendUs, Size} sent and {ArrivalUs, Size} received, from feedback.
    tx = [] :: [{integer(), non_neg_integer()}],
    rx = [] :: [{integer(), non_neg_integer()}],
    finished :: undefined | integer()
}).

-record(probe, {
    enabled :: boolean(),
    started = false :: boolean(),
    max :: pos_integer(),
    next_id = 1 :: pos_integer(),
    %% Clusters to send, the one being sent, and those awaiting feedback.
    queue = [] :: [#cluster{}],
    sending :: undefined | #cluster{},
    waiting = [] :: [#cluster{}],
    results = [] :: [{pos_integer(), pos_integer() | failed}],
    %% The last estimate, when sending first fell under ALR_START, and
    %% since when the sender is application limited.
    estimate :: undefined | pos_integer(),
    low_since :: undefined | integer(),
    alr_since :: undefined | integer(),
    %% The estimate before the last large drop, and when it happened.
    drop :: undefined | {pos_integer(), integer()},
    delay_state = normal :: atom(),
    %% Start times of the probes after start-up, within BUDGET_MS.
    probed = [] :: [integer()]
}).

-opaque state() :: #probe{}.

%% @doc Options: `probing' (default true) and `max_bitrate'.
-spec new(map()) -> state().
new(Opts) ->
    #probe{enabled = maps:get(probing, Opts, true), max = maps:get(max_bitrate, Opts, 50000000)}.

%% @doc Media started with transport-wide feedback: schedule the initial
%% clusters from the start bitrate. Only the first call counts.
-spec start(integer(), pos_integer(), state()) -> state().
start(Now, StartBps, #probe{enabled = true, started = false} = P) ->
    Rates = lists:usort([min(R, P#probe.max) || R <- [3 * StartBps, 6 * StartBps]]),
    schedule(Rates, Now, P#probe{started = true});
start(_Now, _StartBps, P) ->
    P.

%% @doc Follow the estimate (`estimate'), the rate being sent
%% (`sending', bps over the last second) and the delay detector state
%% (`delay_state'), probing when the sender is application limited or
%% after a large drop.
-spec update(integer(), #{estimate := pos_integer(), sending := non_neg_integer(), delay_state := atom()}, state()) ->
    state().
update(Now, #{estimate := E, sending := Sent, delay_state := D}, #probe{enabled = true, started = true} = P0) ->
    P1 = alr(Now, E, Sent, P0),
    P2 = drop(Now, E, D, P1),
    P3 = alr_probe(Now, E, P2),
    P3#probe{estimate = E, delay_state = D};
update(_Now, #{estimate := E}, P) ->
    P#probe{estimate = E}.

alr(Now, E, Sent, #probe{low_since = Low, alr_since = Alr} = P) ->
    if
        Sent > 0, Sent < ?ALR_START * E ->
            Since = case Low of undefined -> Now; _ -> Low end,
            InAlr = case Alr of undefined when Now - Since >= ?ALR_MS -> Now; _ -> Alr end,
            P#probe{low_since = Since, alr_since = InAlr};
        Sent > ?ALR_STOP * E; Sent =:= 0 ->
            P#probe{low_since = undefined, alr_since = undefined};
        true ->
            P
    end.

alr_probe(Now, E, #probe{alr_since = Alr} = P) when Alr =/= undefined ->
    Last = lists:max([Alr | P#probe.probed]),
    Rate = min(?ALR_SCALE * E, P#probe.max),
    case Now - Last >= ?ALR_INTERVAL andalso Rate > E of
        true -> probe(Now, Rate, P);
        false -> P
    end;
alr_probe(_Now, _E, P) ->
    P.

%% A large drop is remembered for DROP_TIMEOUT; leaving over-use in that
%% time probes back towards the rate before it.
drop(Now, E, D, #probe{estimate = Prev} = P) ->
    P1 =
        case Prev of
            _ when is_integer(Prev), E < ?DROP * Prev -> P#probe{drop = {Prev, Now}};
            _ -> P
        end,
    case {P1#probe.drop, P1#probe.delay_state, D} of
        {{Before, At}, overuse, S} when S =/= overuse, Now - At < ?DROP_TIMEOUT ->
            Rate = min(round(?AFTER_DROP * Before), P1#probe.max),
            case (1 - ?UNCERTAINTY) * Rate > E of
                true -> probe(Now, Rate, P1#probe{drop = undefined});
                false -> P1
            end;
        {{_, At}, _, _} when Now - At >= ?DROP_TIMEOUT ->
            P1#probe{drop = undefined};
        _ ->
            P1
    end.

%% @doc `max_bitrate' went from `Old' to `New': an estimate capped at
%% `Old' probes `New' at once.
-spec max_raised(integer(), pos_integer(), pos_integer(), pos_integer(), state()) -> state().
max_raised(Now, Old, New, E, #probe{enabled = true, started = true} = P) when New > Old ->
    P1 = P#probe{max = New},
    case E >= ?CAPPED * Old of
        true -> probe(Now, New, P1);
        false -> P1
    end;
max_raised(_Now, _Old, New, _E, P) ->
    P#probe{max = New}.

%% One cluster at a time, within the budget.
probe(Now, Rate, P) ->
    Recent = [T || T <- P#probe.probed, Now - T < ?BUDGET_MS],
    case idle(P) andalso length(Recent) < ?BUDGET of
        true -> schedule([Rate], Now, P#probe{probed = [Now | Recent]});
        false -> P#probe{probed = Recent}
    end.

idle(#probe{queue = [], sending = undefined, waiting = []}) -> true;
idle(_) -> false.

schedule(Rates, _Now, #probe{next_id = Id0, queue = Q} = P) ->
    {Clusters, Next} = lists:mapfoldl(
        fun(R, Id) -> {#cluster{id = Id, rate = R, packets = packets(R)}, Id + 1} end,
        Id0,
        Rates
    ),
    P#probe{queue = Q ++ Clusters, next_id = Next}.

packets(Rate) ->
    Bytes = Rate * ?MIN_DURATION_MS div 8000,
    max(?MIN_PACKETS, (Bytes + ?PACKET_SIZE - 1) div ?PACKET_SIZE).

%% @doc Padding packets due now, `{probe, ClusterId, Size}'.
-spec handle_timeout(integer(), state()) -> {[{probe, pos_integer(), pos_integer()}], state()}.
handle_timeout(Now, P0) ->
    P = expire(Now, P0),
    case P#probe.sending of
        undefined ->
            case P#probe.queue of
                [] -> {[], P};
                [C | Q] -> handle_timeout(Now, P#probe{sending = C#cluster{started = Now}, queue = Q})
            end;
        #cluster{id = Id, rate = R, packets = N, sent = S, started = T0} = C ->
            %% Packet I is due at T0 + I * Size * 8 / Rate.
            Due = min(N, ((Now - T0) * R) div (?PACKET_SIZE * 8000) + 1),
            Out = [{probe, Id, ?PACKET_SIZE} || _ <- lists:seq(1, max(0, Due - S))],
            C1 = C#cluster{sent = max(S, Due)},
            case C1#cluster.sent >= N of
                true ->
                    {Out, P#probe{sending = undefined, waiting = P#probe.waiting ++ [C1#cluster{finished = Now}]}};
                false ->
                    {Out, P#probe{sending = C1}}
            end
    end.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#probe{sending = undefined, queue = [], alr_since = undefined}) ->
    infinity;
next_timeout(#probe{sending = undefined, queue = [], alr_since = Alr, probed = Probed}) ->
    %% The next ALR probe, for update/3 to send.
    lists:max([Alr | Probed]) + ?ALR_INTERVAL;
next_timeout(#probe{sending = undefined}) ->
    0;
next_timeout(#probe{sending = #cluster{rate = R, sent = S, started = T0}}) ->
    T0 + (S * ?PACKET_SIZE * 8000 + R - 1) div R.

%% @doc Transport-wide results of probe packets, `{Cluster, SendUs,
%% ArrivalUs | lost, Size}'. Returns the bitrates of the clusters that
%% are complete.
-spec feedback([{pos_integer(), integer(), integer() | lost, non_neg_integer()}], integer(), state()) ->
    {[pos_integer()], state()}.
feedback(Results, Now, P) ->
    Waiting = [add_results(C, [R || {Id, _, _, _} = R <- Results, Id =:= C#cluster.id]) || C <- P#probe.waiting],
    {Done, Left} = lists:partition(fun(C) -> length(C#cluster.tx) >= C#cluster.packets end, Waiting),
    lists:foldl(fun(C, {Bps, Acc}) -> conclude(C, Now, Bps, Acc) end, {[], P#probe{waiting = Left}}, Done).

add_results(C, Rs) ->
    C#cluster{
        tx = C#cluster.tx ++ [{S, Sz} || {_, S, _, Sz} <- Rs],
        rx = C#cluster.rx ++ [{A, Sz} || {_, _, A, Sz} <- Rs, A =/= lost]
    }.

conclude(C, _Now, Bps, P) ->
    case estimate(C) of
        undefined ->
            {Bps, P#probe{results = P#probe.results ++ [{C#cluster.id, failed}]}};
        Rate ->
            P1 = P#probe{results = P#probe.results ++ [{C#cluster.id, Rate}]},
            %% A probe that got through: probe further while the link
            %% keeps up (and nothing else is queued).
            Further = 2 * Rate,
            P2 =
                case Rate >= ?FURTHER * C#cluster.rate andalso Further =< P#probe.max andalso
                         P1#probe.queue =:= [] andalso P1#probe.sending =:= undefined of
                    true -> schedule([Further], undefined, P1);
                    false -> P1
                end,
            {Bps ++ [Rate], P2}
    end.

%% ProbeBitrateEstimator::HandleProbeAndEstimateBitrate.
estimate(#cluster{tx = Tx, rx = Rx, packets = N}) when length(Rx) < ?MIN_RECEIVED * N; length(Rx) < 2 ->
    _ = Tx,
    undefined;
estimate(#cluster{tx = Tx, rx = Rx}) ->
    SendT = [S || {S, _} <- Tx],
    RecvT = [A || {A, _} <- Rx],
    SendI = lists:max(SendT) - lists:min(SendT),
    RecvI = lists:max(RecvT) - lists:min(RecvT),
    {_, LastSize} = lists:last(lists:keysort(1, Tx)),
    {_, FirstSize} = hd(lists:keysort(1, Rx)),
    SendBytes = lists:sum([Sz || {_, Sz} <- Tx]) - LastSize,
    RecvBytes = lists:sum([Sz || {_, Sz} <- Rx]) - FirstSize,
    if
        SendI =< 0; SendI > ?MAX_INTERVAL_US; RecvI =< 0; RecvI > ?MAX_INTERVAL_US ->
            undefined;
        true ->
            SendRate = SendBytes * 8000000 / SendI,
            RecvRate = RecvBytes * 8000000 / RecvI,
            if
                RecvRate > ?MAX_RATIO * SendRate ->
                    undefined;
                RecvRate < ?UNSATURATED * SendRate ->
                    max(1, round(?UTILIZATION * RecvRate));
                true ->
                    max(1, round(min(SendRate, RecvRate)))
            end
    end.

%% Clusters without feedback in time fail.
expire(Now, #probe{waiting = W} = P) ->
    {Old, Left} = lists:partition(fun(#cluster{finished = F}) -> Now - F > ?RESULT_TIMEOUT end, W),
    P#probe{waiting = Left, results = P#probe.results ++ [{Id, failed} || #cluster{id = Id} <- Old]}.

-spec info(state()) -> map().
info(#probe{} = P) ->
    #{
        enabled => P#probe.enabled,
        started => P#probe.started,
        pending => length(P#probe.queue) + length(P#probe.waiting) + case P#probe.sending of undefined -> 0; _ -> 1 end,
        results => P#probe.results,
        application_limited => P#probe.alr_since =/= undefined
    }.
