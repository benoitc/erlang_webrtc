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
