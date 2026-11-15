%% Bandwidth probing (webrtc_cc_probe).
-module(webrtc_cc_probe_tests).
-include_lib("eunit/include/eunit.hrl").

-define(P, webrtc_cc_probe).

%% Send every packet of the clusters due up to `Until' ms.
drain(P, Now, Until, Acc) when Now > Until -> {Acc, P};
drain(P, Now, Until, Acc) ->
    {Out, P1} = ?P:handle_timeout(Now, P),
    drain(P1, Now + 1, Until, Acc ++ [{Now, C, Sz} || {probe, C, Sz} <- Out]).

%% Feedback for cluster packets sent at {Ms, Cluster, Size}, arriving
%% spread as if the link carried `Bps'.
results(Sent, Bps) ->
    {_, Rs} = lists:foldl(
        fun({Ms, C, Sz}, {Arr, Acc}) ->
            A = max(Arr, Ms * 1000) + Sz * 8000000 div Bps,
            {A, Acc ++ [{C, Ms * 1000, A, Sz}]}
        end,
        {0, []},
        Sent
    ),
    Rs.

%% Two initial clusters at 3x and 6x the start, each 15 ms and 5 packets
%% at least, paced at their rate.
initial_clusters_test() ->
    P0 = ?P:start(0, 300000, ?P:new(#{})),
    {Sent, _} = drain(P0, 0, 100, []),
    ByCluster = maps:groups_from_list(fun({_, C, _}) -> C end, Sent),
    ?assertEqual([1, 2], lists:sort(maps:keys(ByCluster))),
    [C1, C2] = [maps:get(I, ByCluster) || I <- [1, 2]],
    ?assert(length(C1) >= 5),
    %% 900 kbps over 15 ms is 1688 bytes; 1.8 Mbps is 3375.
    ?assert(lists:sum([S || {_, _, S} <- C2]) >= 3375),
    {T0, _, _} = hd(C2),
    {T1, _, _} = lists:last(C2),
    ?assert(T1 - T0 >= 13),
    %% Only the first start counts.
    ?assertEqual(P0, ?P:start(5, 300000, P0)).

%% The result is the rate the link carried, and a good result probes
%% further at twice it.
estimate_test() ->
    P0 = ?P:start(0, 300000, ?P:new(#{max_bitrate => 10000000})),
    {Sent, P1} = drain(P0, 0, 100, []),
    C1 = [X || {_, 1, _} = X <- Sent],
    {[R1], P2} = ?P:feedback(results(C1, 5000000), 200, P1),
    %% Not saturated: about the probed 900 kbps.
    ?assert(R1 >= 700000 andalso R1 =< 1100000),
    C2 = [X || {_, 2, _} = X <- Sent],
    {[R2], P3} = ?P:feedback(results(C2, 1000000), 200, P2),
    %% Saturated at 1 Mbps: 95% of what got through.
    ?assert(R2 >= 800000 andalso R2 =< 1000000),
    #{results := Rs} = ?P:info(P3),
    ?assertEqual([1, 2], [Id || {Id, _} <- Rs]),
    %% The first result was at least 70% of its probe: a further
    %% cluster at twice it was queued.
    ?assertMatch(#{pending := 1}, ?P:info(P3)).

%% Fewer than 80% of a cluster received: no result.
lost_probe_test() ->
    P0 = ?P:start(0, 300000, ?P:new(#{})),
    {Sent, P1} = drain(P0, 0, 100, []),
    [_ | _] = C1 = [X || {_, 1, _} = X <- Sent],
    Rs = [case I rem 2 of 0 -> {C, S, lost, Sz}; 1 -> R end || {I, {C, S, _, Sz} = R} <- lists:enumerate(results(C1, 5000000))],
    {[], P2} = ?P:feedback(Rs, 200, P1),
    ?assertMatch(#{results := [{1, failed}]}, ?P:info(P2)).

%% A cluster without feedback is given up.
no_feedback_test() ->
    P0 = ?P:start(0, 300000, ?P:new(#{})),
    {_, P1} = drain(P0, 0, 100, []),
    {[], P2} = ?P:handle_timeout(5000, P1),
    ?assertMatch(#{results := [{1, failed}, {2, failed}], pending := 0}, ?P:info(P2)).

disabled_test() ->
    P = ?P:start(0, 300000, ?P:new(#{probing => false})),
    ?assertEqual(infinity, ?P:next_timeout(P)),
    ?assertEqual({[], P}, ?P:handle_timeout(10, P)).

%% After start-up: the initial clusters went out and got no result.
settled(Opts) ->
    P0 = ?P:start(0, 300000, ?P:new(Opts)),
    {_, P1} = drain(P0, 0, 100, []),
    {[], P2} = ?P:handle_timeout(5000, P1),
    P2.

up(Now, E, Sent, P) -> up(Now, E, Sent, normal, P).
up(Now, E, Sent, D, P) -> ?P:update(Now, #{estimate => E, sending => Sent, delay_state => D}, P).

%% The packets of the next cluster: 15 ms at its rate, 250 byte packets.
next_cluster(Now, P) ->
    {Sent, P1} = drain(P, Now, Now + 100, []),
    {lists:sum([Sz || {_, _, Sz} <- Sent]) * 8000 div 15, P1}.

%% Application limited: under 65% of the estimate for 500 ms, then a
%% cluster at twice the estimate every 5 s, until sending is back over
%% 80%.
alr_probe_test() ->
    P0 = up(6000, 1000000, 300000, settled(#{})),
    P1 = up(6400, 1000000, 300000, P0),
    ?assertMatch(#{application_limited := false}, ?P:info(P1)),
    P2 = up(6500, 1000000, 300000, P1),
    ?assertMatch(#{application_limited := true, pending := 0}, ?P:info(P2)),
    ?assertEqual(11500, ?P:next_timeout(P2)),
    P3 = up(11499, 1000000, 300000, P2),
    ?assertMatch(#{pending := 0}, ?P:info(P3)),
    P4 = up(11500, 1000000, 300000, P3),
    ?assertMatch(#{pending := 1}, ?P:info(P4)),
    {Rate, _} = next_cluster(11500, P4),
    ?assert(Rate >= 2000000 andalso Rate < 2200000),
    P5 = up(12000, 1000000, 900000, P4),
    ?assertMatch(#{application_limited := false}, ?P:info(P5)),
    %% Nothing sent at all is not application limited.
    P6 = up(20000, 1000000, 0, up(19000, 1000000, 0, settled(#{}))),
    ?assertMatch(#{application_limited := false}, ?P:info(P6)).

%% A drop under 66% and a recovery from over-use within 5 s: a cluster
%% at 85% of the rate before the drop.
drop_probe_test() ->
    P0 = up(6000, 2000000, 1800000, settled(#{})),
    P1 = up(6100, 1000000, 1800000, overuse, P0),
    ?assertMatch(#{pending := 0}, ?P:info(P1)),
    P2 = up(7000, 1000000, 1000000, normal, P1),
    ?assertMatch(#{pending := 1}, ?P:info(P2)),
    {Rate, _} = next_cluster(7000, P2),
    ?assert(Rate >= 1700000 andalso Rate < 1900000),
    %% Recovered too late: no probe.
    Q1 = up(6100, 1000000, 1800000, overuse, P0),
    Q2 = up(11200, 1000000, 1000000, normal, Q1),
    ?assertMatch(#{pending := 0}, ?P:info(Q2)),
    %% Already back near the old rate: no probe either.
    R1 = up(6100, 1300000, 1800000, overuse, up(6050, 2000000, 1800000, P0)),
    R2 = up(6200, 1700000, 1800000, normal, R1),
    ?assertMatch(#{pending := 0}, ?P:info(R2)).

%% A raised maximum probes at once when the estimate sat at the old one.
max_raised_test() ->
    P0 = settled(#{max_bitrate => 1000000}),
    P1 = ?P:max_raised(6000, 1000000, 3000000, 950000, P0),
    ?assertMatch(#{pending := 1}, ?P:info(P1)),
    {Rate, _} = next_cluster(6000, P1),
    ?assert(Rate >= 3000000 andalso Rate < 3300000),
    ?assertMatch(#{pending := 0}, ?P:info(?P:max_raised(6000, 1000000, 3000000, 500000, P0))),
    ?assertMatch(#{pending := 0}, ?P:info(?P:max_raised(6000, 3000000, 1000000, 950000, P0))).

%% One cluster in flight, and at most 10 of these probes a minute.
bounds_test() ->
    P0 = ?P:max_raised(6000, 1000000, 3000000, 950000, settled(#{max_bitrate => 1000000})),
    P1 = ?P:max_raised(6001, 3000000, 6000000, 3000000, P0),
    ?assertMatch(#{pending := 1}, ?P:info(P1)),
    Fire = fun(I, P) ->
        Now = 6000 + I * 100,
        Pa = ?P:max_raised(Now, I * 1000000, (I + 1) * 1000000, I * 1000000, P),
        {_, Pb} = drain(Pa, Now, Now + 50, []),
        {[], Pc} = ?P:handle_timeout(Now + 2100 + 50, Pb),
        Pc
    end,
    P2 = lists:foldl(Fire, settled(#{max_bitrate => 1000000}), lists:seq(1, 12)),
    #{results := Rs} = ?P:info(P2),
    %% Two initial clusters, then ten.
    ?assertEqual(12, length(Rs)).

%% Media leaving during a cluster counts towards it: less padding, and
%% the cluster is complete once media and padding reach its size.
media_in_cluster_test() ->
    P0 = ?P:start(0, 300000, ?P:new(#{})),
    {[{probe, 1, 250}], P1} = ?P:handle_timeout(0, P0),
    {1, P2} = ?P:media(1, 1200, P1),
    %% 900 kbps for 15 ms is 1687 bytes: 1450 sent, one packet more due
    %% only once the rate allows it.
    {[], P3} = ?P:handle_timeout(2, P2),
    {Pad, P4} = drain(P3, 3, 30, []),
    Ids = lists:usort([C || {_, C, _} <- Pad]),
    ?assertEqual([1, 2], Ids),
    %% Cluster 1 needed 5 packets: 2 sent, 3 of padding.
    ?assertEqual(3, length([x || {_, 1, _} <- Pad])),
    %% Outside a cluster media is not tagged.
    {_, P5} = drain(P4, 31, 100, []),
    ?assertMatch({undefined, _}, ?P:media(200, 1200, P5)).

%% A raise while a cluster is in flight is probed once it is done.
max_raised_while_busy_test() ->
    P0 = ?P:max_raised(6000, 1000000, 3000000, 950000, settled(#{max_bitrate => 1000000})),
    ?assertMatch(#{pending := 1}, ?P:info(P0)),
    P1 = ?P:max_raised(6001, 3000000, 5000000, 2900000, P0),
    ?assertMatch(#{pending := 1}, ?P:info(P1)),
    %% The first cluster goes out and gets no answer.
    {_, P2} = drain(P1, 6001, 6100, []),
    {[], P3} = ?P:handle_timeout(8200, P2),
    ?assertMatch(#{pending := 0}, ?P:info(P3)),
    P4 = up(8200, 2900000, 2800000, P3),
    ?assertMatch(#{pending := 1}, ?P:info(P4)),
    {Rate, _} = next_cluster(8200, P4),
    ?assert(Rate >= 5000000 andalso Rate < 5500000).
