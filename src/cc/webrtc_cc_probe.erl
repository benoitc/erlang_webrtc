%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
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
%% <li>After a large drop while application limited or within 3 s of it:
%%     the estimate fell under 66% of its previous value, the delay
%%     detector leaves over-use within 5 s, a probe at 85% of the rate
%%     before the drop would still raise it, and no such probe went in
%%     the last 5 s. A sender that fills its share does not probe after
%%     a drop: the drop came from a competing flow or a smaller link,
%%     and probing it back refills the queue.</li>
%% <li>On a raised `max_bitrate' (`max_raised/5'): the estimate was at
%%     the old maximum, so the new one is probed at once.</li>
%% </ul>
%% At most one cluster is in flight, and these probes are limited to
%% 10 a minute.
%%
%% While a cluster is sent, media that leaves is part of it (`media/3'),
%% as libwebrtc's pacer does: padding only makes up the difference with
%% the cluster's rate, and the result counts every packet of the
%% cluster, so media in flight does not make the link look slower.
%%
%% `handle_timeout/2' returns `{probe, Cluster, Size}' padding packets
%% to send now; the caller tags them with the cluster in the
%% transport-wide send history so `feedback/3' sees which results belong
%% to a probe.
-module(webrtc_cc_probe).

-export([new/1, start/3, update/3, max_raised/5, media/3, handle_timeout/2, next_timeout/1, feedback/3, info/1]).

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
-define(ALR_ENDED, 3000).
-define(DROP_INTERVAL, 5000).
-define(AFTER_DROP, 0.85).
-define(UNCERTAINTY, 0.05).
-define(CAPPED, 0.9).
-define(BUDGET, 10).
-define(BUDGET_MS, 60000).

-record(cluster, {
    id :: pos_integer(),
    rate :: pos_integer(),
    %% At least `bytes' (MIN_DURATION_MS at the rate) and MIN_PACKETS
    %% packets, media and padding together.
    bytes :: pos_integer(),
    sent = 0 :: non_neg_integer(),
    sent_bytes = 0 :: non_neg_integer(),
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
    alr_ended :: undefined | integer(),
    %% The estimate before the last large drop, when it happened, and
    %% when the last probe after a drop went.
    drop :: undefined | {pos_integer(), integer()},
    drop_probed :: undefined | integer(),
    delay_state = normal :: atom(),
    %% Start times of the probes after start-up, within BUDGET_MS.
    probed = [] :: [integer()],
    %% A raised maximum to probe once no cluster is in flight.
    raise :: undefined | pos_integer()
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
    P4 = pending_raise(Now, E, P3),
    P4#probe{estimate = E, delay_state = D};
update(_Now, #{estimate := E}, P) ->
    P#probe{estimate = E}.

alr(Now, E, Sent, #probe{low_since = Low, alr_since = Alr} = P) ->
    if
        Sent > 0, Sent < ?ALR_START * E ->
            Since = case Low of undefined -> Now; _ -> Low end,
            InAlr = case Alr of undefined when Now - Since >= ?ALR_MS -> Now; _ -> Alr end,
            P#probe{low_since = Since, alr_since = InAlr};
        Sent > ?ALR_STOP * E; Sent =:= 0 ->
            Ended = case Alr of undefined -> P#probe.alr_ended; _ -> Now end,
            P#probe{low_since = undefined, alr_since = undefined, alr_ended = Ended};
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
            case (1 - ?UNCERTAINTY) * Rate > E andalso app_limited(Now, P1) andalso since(Now, P1#probe.drop_probed) of
                true -> probe(Now, Rate, P1#probe{drop = undefined, drop_probed = Now});
                false -> P1
            end;
        {{_, At}, _, _} when Now - At >= ?DROP_TIMEOUT ->
            P1#probe{drop = undefined};
        _ ->
            P1
    end.

app_limited(_Now, #probe{alr_since = Alr}) when Alr =/= undefined -> true;
app_limited(Now, #probe{alr_ended = Ended}) when is_integer(Ended) -> Now - Ended < ?ALR_ENDED;
app_limited(_Now, _P) -> false.

since(_Now, undefined) -> true;
since(Now, At) -> Now - At > ?DROP_INTERVAL.

%% @doc `max_bitrate' went from `Old' to `New': an estimate capped at
%% `Old' probes `New' at once.
-spec max_raised(integer(), pos_integer(), pos_integer(), pos_integer(), state()) -> state().
max_raised(Now, Old, New, E, #probe{enabled = true, started = true} = P) when New > Old ->
    P1 = P#probe{max = New},
    case {E >= ?CAPPED * Old, idle(P1)} of
        {true, true} -> probe(Now, New, P1);
        %% A cluster is in flight: probe the new maximum after it.
        {true, false} -> P1#probe{raise = New};
        {false, _} -> P1
    end;
max_raised(_Now, _Old, New, _E, P) ->
    P#probe{max = New}.

pending_raise(Now, E, #probe{raise = R} = P) when is_integer(R) ->
    case idle(P) of
        true when E < R -> probe(Now, R, P#probe{raise = undefined});
        true -> P#probe{raise = undefined};
        false -> P
    end;
pending_raise(_Now, _E, P) ->
    P.

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
        fun(R, Id) -> {#cluster{id = Id, rate = R, bytes = bytes(R)}, Id + 1} end,
        Id0,
        Rates
    ),
    P#probe{queue = Q ++ Clusters, next_id = Next}.

bytes(Rate) ->
    max(?MIN_PACKETS * ?PACKET_SIZE, Rate * ?MIN_DURATION_MS div 8000).

%% @doc A media packet of `Size' bytes leaves now: while a cluster is
%% being sent it is part of it, and the caller tags it with the cluster
%% (`{probe, Id}') in the transport-wide send history.
-spec media(integer(), non_neg_integer(), state()) -> {undefined | pos_integer(), state()}.
media(Now, Size, #probe{sending = #cluster{id = Id, started = T0} = C} = P) when is_integer(T0) ->
    {Id, finish(Now, C#cluster{sent = C#cluster.sent + 1, sent_bytes = C#cluster.sent_bytes + Size}, P)};
media(_Now, _Size, P) ->
    {undefined, P}.

finish(Now, #cluster{sent = N, sent_bytes = B, bytes = Target} = C, P) when N >= ?MIN_PACKETS, B >= Target ->
    P#probe{sending = undefined, waiting = P#probe.waiting ++ [C#cluster{finished = Now}]};
finish(_Now, C, P) ->
    P#probe{sending = C}.

%% @doc Padding packets due now, `{probe, ClusterId, Size}': what the
%% cluster's rate allows since it started, less what already left.
-spec handle_timeout(integer(), state()) -> {[{probe, pos_integer(), pos_integer()}], state()}.
handle_timeout(Now, P0) ->
    P = expire(Now, P0),
    case P#probe.sending of
        undefined ->
            case P#probe.queue of
                [] -> {[], P};
                [C | Q] -> handle_timeout(Now, P#probe{sending = C#cluster{started = Now}, queue = Q})
            end;
        #cluster{id = Id, rate = R, bytes = Target, sent = N, sent_bytes = B, started = T0} = C ->
            %% One packet ahead of the rate, so the cluster starts at once.
            Due = min(Target, (Now - T0) * R div 8000 + ?PACKET_SIZE),
            ByBytes = max(0, (Due - B + ?PACKET_SIZE - 1) div ?PACKET_SIZE),
            %% Bytes done but too few packets: the rest now.
            K = case B >= Target of true -> max(0, ?MIN_PACKETS - N); false -> ByBytes end,
            Out = [{probe, Id, ?PACKET_SIZE} || _ <- lists:seq(1, K)],
            {Out, finish(Now, C#cluster{sent = N + K, sent_bytes = B + K * ?PACKET_SIZE}, P)}
    end.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#probe{sending = undefined, queue = [], alr_since = undefined}) ->
    infinity;
next_timeout(#probe{sending = undefined, queue = [], alr_since = Alr, probed = Probed}) ->
    %% The next ALR probe, for update/3 to send.
    lists:max([Alr | Probed]) + ?ALR_INTERVAL;
next_timeout(#probe{sending = undefined}) ->
    0;
next_timeout(#probe{sending = #cluster{bytes = Target, sent_bytes = B}}) when B >= Target ->
    %% Only packets are missing.
    0;
next_timeout(#probe{sending = #cluster{rate = R, sent_bytes = B, started = T0}}) ->
    %% When the next padding packet is due.
    T0 + ((B + 1 - ?PACKET_SIZE) * 8000 + R - 1) div R.

%% @doc Transport-wide results of probe packets, `{Cluster, SendUs,
%% ArrivalUs | lost, Size}'. Returns the bitrates of the clusters that
%% are complete.
-spec feedback([{pos_integer(), integer(), integer() | lost, non_neg_integer()}], integer(), state()) ->
    {[pos_integer()], state()}.
feedback(Results, Now, P) ->
    Waiting = [add_results(C, [R || {Id, _, _, _} = R <- Results, Id =:= C#cluster.id]) || C <- P#probe.waiting],
    {Done, Left} = lists:partition(fun(C) -> length(C#cluster.tx) >= C#cluster.sent end, Waiting),
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
estimate(#cluster{tx = Tx, rx = Rx, sent = N}) when length(Rx) < ?MIN_RECEIVED * N; length(Rx) < 2 ->
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
