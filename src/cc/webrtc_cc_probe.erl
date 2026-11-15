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
%% `handle_timeout/2' returns `{probe, Cluster, Size}' padding packets
%% to send now; the caller tags them with the cluster in the
%% transport-wide send history so `feedback/3' sees which results belong
%% to a probe.
-module(webrtc_cc_probe).

-export([new/1, start/3, handle_timeout/2, next_timeout/1, feedback/3, info/1]).

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
    results = [] :: [{pos_integer(), pos_integer() | failed}]
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
next_timeout(#probe{sending = undefined, queue = []}) ->
    infinity;
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
        results => P#probe.results
    }.
