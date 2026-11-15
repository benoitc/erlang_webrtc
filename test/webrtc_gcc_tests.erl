%% Tests for Google Congestion Control (webrtc_gcc, webrtc_gcc_delay,
%% webrtc_gcc_aimd): unit behaviour of each part, then convergence of
%% the whole send path (webrtc_cc) over the simulated bottleneck of
%% webrtc_cc_sim / webrtc_cc_link.
-module(webrtc_gcc_tests).
-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Delay-based detector
%%====================================================================

%% Packets sent every 10 ms; ExtraUs(I) is the queuing delay of packet I.
batches(N, ExtraUs) ->
    [{I * 10000, I * 10000 + 20000 + ExtraUs(I)} || I <- lists:seq(1, N)].

run_detector(Packets) ->
    {Signals, _} = lists:mapfoldl(
        fun(Batch, D) -> webrtc_gcc_delay:batch(Batch, D) end,
        webrtc_gcc_delay:new(),
        chunks(Packets, 10)
    ),
    Signals.

chunks([], _) -> [];
chunks(L, N) when length(L) =< N -> [L];
chunks(L, N) ->
    {A, B} = lists:split(N, L),
    [A | chunks(B, N)].

constant_delay_is_normal_test() ->
    Signals = run_detector(batches(300, fun(_) -> 0 end)),
    ?assertEqual([normal], lists:usort(Signals)).

growing_queue_is_overuse_test() ->
    %% Steady for 1 s, then the queue grows by 1 ms per packet.
    Signals = run_detector(batches(200, fun(I) when I > 100 -> (I - 100) * 1000; (_) -> 0 end)),
    {Before, After} = lists:split(10, Signals),
    ?assertEqual([normal], lists:usort(Before)),
    ?assert(lists:member(overuse, After)).

draining_queue_is_underuse_test() ->
    %% A 200 ms queue drains by 2 ms per packet.
    Signals = run_detector(batches(200, fun(I) when I =< 100 -> 200000 - I * 2000; (_) -> 0 end)),
    ?assert(lists:member(underuse, Signals)),
    ?assertNot(lists:member(overuse, Signals)).

%% Packets sent before the current group are ignored, and a burst that
%% arrives at once after an outage is merged into one group.
reordering_and_burst_test() ->
    D0 = webrtc_gcc_delay:new(),
    {normal, D1} = webrtc_gcc_delay:batch([{0, 20000}, {10000, 30000}, {5000, 31000}], D0),
    Burst = [{I * 10000, 600000 + I * 100} || I <- lists:seq(2, 40)],
    {S, _} = webrtc_gcc_delay:batch(Burst, D1),
    ?assertNotEqual(overuse, S).

%%====================================================================
%% AIMD rate controller
%%====================================================================

aimd() -> webrtc_gcc_aimd:new(#{start => 1000000, min => 30000, max => 10000000, startup_gain => 1.08}).

aimd_decrease_test() ->
    A0 = aimd(),
    A1 = webrtc_gcc_aimd:update(overuse, 900000, 50, 0, A0),
    ?assertEqual(765000, webrtc_gcc_aimd:rate(A1)),
    ?assertMatch(#{state := hold, region := near_max}, webrtc_gcc_aimd:info(A1)),
    %% Another over-use within one RTT does not decrease again.
    A2 = webrtc_gcc_aimd:update(overuse, 800000, 50, 20, A1),
    ?assertEqual(765000, webrtc_gcc_aimd:rate(A2)),
    %% Never above the current estimate on over-use.
    A3 = webrtc_gcc_aimd:update(overuse, 5000000, 50, 500, A2),
    ?assertEqual(765000, webrtc_gcc_aimd:rate(A3)).

aimd_transitions_test() ->
    A1 = webrtc_gcc_aimd:update(overuse, 900000, 50, 0, aimd()),
    %% Hold -> Increase on normal; under-use -> Hold (rate unchanged).
    A2 = webrtc_gcc_aimd:update(normal, 760000, 50, 100, A1),
    ?assertMatch(#{state := increase}, webrtc_gcc_aimd:info(A2)),
    ?assert(webrtc_gcc_aimd:rate(A2) > 765000),
    A3 = webrtc_gcc_aimd:update(underuse, 760000, 50, 200, A2),
    ?assertMatch(#{state := hold}, webrtc_gcc_aimd:info(A3)),
    ?assertEqual(webrtc_gcc_aimd:rate(A2), webrtc_gcc_aimd:rate(A3)).

%% Far from convergence the increase is at most 8% per second; near the
%% previous decreases it is additive (well below 8%).
aimd_increase_test() ->
    A0 = aimd(),
    %% The first update has no elapsed time: the minimum step, 1 kbps.
    A1 = webrtc_gcc_aimd:update(normal, 1000000, 50, 0, A0),
    ?assertEqual(1001000, webrtc_gcc_aimd:rate(A1)),
    A2 = webrtc_gcc_aimd:update(normal, 1000000, 50, 1000, A1),
    ?assertEqual(round(1001000 * 1.08), webrtc_gcc_aimd:rate(A2)),
    %% Capped at 1.5 R_hat + 10 kbps.
    A3 = webrtc_gcc_aimd:update(normal, 100000, 50, 2000, A2),
    ?assertEqual(webrtc_gcc_aimd:rate(A2), webrtc_gcc_aimd:rate(A3)),
    B1 = webrtc_gcc_aimd:update(overuse, 1000000, 50, 0, A0),
    B2 = webrtc_gcc_aimd:update(normal, 850000, 50, 100, B1),
    B3 = webrtc_gcc_aimd:update(normal, 850000, 50, 1100, B2),
    Inc = webrtc_gcc_aimd:rate(B3) - webrtc_gcc_aimd:rate(B2),
    ?assert(Inc > 0 andalso Inc < 0.08 * webrtc_gcc_aimd:rate(B2)).

%%====================================================================
%% Combined estimate
%%====================================================================

%% Results for N packets sent every 10 ms from T0 (ms), constant delay,
%% with the packets in Lost lost.
results(T0, N, Lost) ->
    [{(T0 + I * 10) * 1000, case lists:member(I, Lost) of true -> lost; false -> (T0 + I * 10 + 20) * 1000 end, 1200}
     || I <- lists:seq(0, N - 1)].

no_estimate_before_feedback_test() ->
    G = webrtc_gcc:new(#{}),
    ?assertNot(webrtc_gcc:has_input(G)),
    ?assertEqual(300000, webrtc_gcc:target(G)),
    ?assertEqual({[], G}, webrtc_gcc:handle_timeout(100000, G)),
    {Events, G1} = webrtc_gcc:feedback(results(0, 10, []), 300, G),
    ?assertMatch([{bandwidth_estimate, _}], Events),
    ?assert(webrtc_gcc:has_input(G1)).

%% draft-ietf-rmcat-gcc §6: more than 10% loss decreases the estimate
%% by half the loss ratio.
loss_decrease_test() ->
    G0 = webrtc_gcc:new(#{start_bitrate => 1000000}),
    {_, G1} = webrtc_gcc:feedback(results(0, 40, [3, 7, 11, 15, 19, 23, 27, 31, 35, 39]), 400, G0),
    %% 10 of 40 lost: 25%, target x 0.875.
    ?assertEqual(875000, webrtc_gcc:target(G1)).

%% The same with the negative times of the BEAM's monotonic clock: every
%% packet of the first feedback counts.
loss_decrease_negative_clock_test() ->
    T0 = -576460751000,
    G0 = webrtc_gcc:new(#{start_bitrate => 1000000}),
    {_, G1} = webrtc_gcc:feedback(results(T0, 40, [3, 7, 11, 15, 19, 23, 27, 31, 35, 39]), T0 + 400, G0),
    ?assertEqual(875000, webrtc_gcc:target(G1)).

moderate_loss_holds_test() ->
    G0 = webrtc_gcc:new(#{start_bitrate => 1000000}),
    {_, G1} = webrtc_gcc:feedback(results(0, 20, []), 200, G0),
    T1 = webrtc_gcc:target(G1),
    %% 1 of 20 lost (5%): the loss-based estimate freezes the target.
    {_, G2} = webrtc_gcc:feedback(results(200, 20, [5]), 1400, G1),
    {_, G3} = webrtc_gcc:feedback(results(400, 20, []), 2400, G2),
    ?assertMatch(#{loss_based := L} when L =< T1 + 1, webrtc_gcc:info(G2)),
    ?assert(webrtc_gcc:target(G3) =< webrtc_gcc:target(G2) * 1.06).

%% Without transport-wide feedback the REMB value is the estimate; with
%% it, REMB is an upper bound of the delay-based estimate.
remb_test() ->
    G0 = webrtc_gcc:new(#{start_bitrate => 1000000}),
    {[{bandwidth_estimate, 400000}], G1} = webrtc_gcc:remb(400000, 0, G0),
    ?assert(webrtc_gcc:has_input(G1)),
    {[{bandwidth_estimate, 5000000}], _} = webrtc_gcc:remb(5000000, 10, G1),
    {_, G2} = webrtc_gcc:feedback(results(0, 10, []), 200, G0),
    T = webrtc_gcc:target(G2),
    {[], G3} = webrtc_gcc:remb(5000000, 210, G2),
    ?assertEqual(T, webrtc_gcc:target(G3)),
    {[{bandwidth_estimate, 200000}], _} = webrtc_gcc:remb(200000, 220, G3).

%% Receiver report loss drives the estimate while no transport-wide
%% feedback arrived, and is ignored after.
loss_report_test() ->
    G0 = webrtc_gcc:new(#{start_bitrate => 1000000}),
    ?assertNot(webrtc_gcc:has_input(G0)),
    {[{bandwidth_estimate, 750000}], G1} = webrtc_gcc:loss_report(128, 0, G0),
    ?assertEqual(750000, webrtc_gcc:target(G1)),
    ?assert(webrtc_gcc:has_input(G1)),
    {_, G2} = webrtc_gcc:feedback(results(0, 10, []), 200, G1),
    T = webrtc_gcc:target(G2),
    {[], G3} = webrtc_gcc:loss_report(255, 300, G2),
    ?assertEqual(T, webrtc_gcc:target(G3)).

limits_test() ->
    G0 = webrtc_gcc:new(#{start_bitrate => 1000000}),
    {_, G1} = webrtc_gcc:feedback(results(0, 10, []), 200, G0),
    {[{bandwidth_estimate, 500000}], G2} = webrtc_gcc:set_limits(#{max_bitrate => 500000}, G1),
    ?assertEqual(500000, webrtc_gcc:target(G2)).

%% RFC 8836 §2 item 10: packets sent and no feedback for the timeout
%% cut the estimate, once per timeout.
feedback_timeout_test() ->
    G0 = webrtc_gcc:new(#{start_bitrate => 1000000, feedback_timeout => 1000}),
    {_, G1} = webrtc_gcc:feedback(results(0, 10, []), 200, G0),
    T = webrtc_gcc:target(G1),
    ?assertEqual(infinity, webrtc_gcc:next_timeout(G1)),
    G2 = webrtc_gcc:sent(1200, 300, G1),
    ?assertEqual(1200, webrtc_gcc:next_timeout(G2)),
    {[], G2} = webrtc_gcc:handle_timeout(1199, G2),
    {[{bandwidth_estimate, T2}], G3} = webrtc_gcc:handle_timeout(1200, G2),
    ?assertEqual(round(T * 0.8), T2),
    ?assertEqual(2200, webrtc_gcc:next_timeout(G3)).

%%====================================================================
%% Simulated bottleneck (webrtc_cc_sim)
%%====================================================================

bottleneck(C) -> #{capacity => C, delay_ms => 20, queue_ms => 300}.

sim(Opts) -> webrtc_cc_sim:run(maps:merge(#{flows => [#{}], duration_ms => 40000}, Opts)).

avg_queue(Samples, From, To) ->
    Qs = [Q || {T, _, Q} <- Samples, T >= From, T =< To],
    lists:sum(Qs) / length(Qs).

converges(C, From) ->
    #{samples := S} = sim(#{link => bottleneck(C)}),
    Avg = webrtc_cc_sim:average(S, 1, From, 40000),
    ?debugFmt("capacity ~p: average target ~.3f of capacity, queue ~.1f ms", [C, Avg / C, avg_queue(S, From, 40000)]),
    ?assert(Avg >= 0.75 * C),
    ?assert(Avg =< 1.05 * C),
    %% Low delay: the bottleneck queue stays short once converged.
    ?assert(avg_queue(S, From, 40000) < 100).

converges_500k_test_() -> {timeout, 60, fun() -> converges(500000, 10000) end}.
converges_2m_test_() -> {timeout, 60, fun() -> converges(2000000, 15000) end}.
converges_10m_test_() -> {timeout, 60, fun() -> converges(10000000, 20000) end}.

%% Capacity drops from 2 Mbps to 500 kbps at 20 s.
capacity_drop_test_() ->
    {timeout, 60, fun() ->
        #{samples := S} = sim(#{link => bottleneck(2000000), events => [{20000, {capacity, 500000}}]}),
        [{_, [At22], _}] = [X || {T, _, _} = X <- S, T =:= 22000],
        ?assert(At22 =< 600000),
        ?assert(avg_queue(S, 24000, 40000) < 100),
        Avg = webrtc_cc_sim:average(S, 1, 25000, 40000),
        ?assert(Avg >= 0.7 * 500000 andalso Avg =< 1.05 * 500000)
    end}.

%% 1% random loss is below the 2% threshold: no starvation.
random_loss_test_() ->
    {timeout, 60, fun() ->
        #{samples := S} = sim(#{link => (bottleneck(2000000))#{loss => 0.01, seed => 3}}),
        ?assert(webrtc_cc_sim:average(S, 1, 20000, 40000) >= 0.6 * 2000000),
        ?assert(webrtc_cc_sim:min_after(S, 1, 20000, 40000) >= 0.5 * 2000000)
    end}.

%% Two flows over the same 2 Mbps link, the second starting 5 s later,
%% share it within a factor of 1.5 and use most of it.
fairness_test_() ->
    {timeout, 120, fun() ->
        #{samples := S} = sim(#{
            link => bottleneck(2000000), flows => [#{}, #{start_ms => 5000}], duration_ms => 120000
        }),
        A = webrtc_cc_sim:average(S, 1, 60000, 120000),
        B = webrtc_cc_sim:average(S, 2, 60000, 120000),
        ?debugFmt("two flows: ~p and ~p bps", [round(A), round(B)]),
        ?assert(max(A, B) / min(A, B) =< 1.5),
        ?assert(A + B >= 0.75 * 2000000 andalso A + B =< 1.05 * 2000000)
    end}.

deterministic_test_() ->
    {timeout, 60, fun() ->
        Opts = #{link => (bottleneck(1000000))#{loss => 0.02, seed => 5}, duration_ms => 10000},
        ?assertEqual(maps:get(samples, sim(Opts)), maps:get(samples, sim(Opts)))
    end}.

%% RFC 8834 §7.1: with receiver reports only, the first report seeds the
%% estimate with the measured sending rate (a forwarded 2 Mbps stream is
%% not cut to the 300 kbps start guess), heavy loss cuts it, and low
%% loss never takes it under the rate getting through.
rr_only_peer_test() ->
    G0 = webrtc_gcc:new(#{}),
    %% 2 Mbps: 250 bytes every millisecond for 1.5 s.
    G1 = lists:foldl(fun(T, G) -> webrtc_gcc:sent(250, T, G) end, G0, lists:seq(0, 1500)),
    ?assertNot(webrtc_gcc:has_input(G1)),
    {[{bandwidth_estimate, T1}], G2} = webrtc_gcc:loss_report(0, 1500, G1),
    ?assert(T1 >= 1900000),
    ?assert(webrtc_gcc:has_input(G2)),
    %% 30% loss: cut by 15%.
    {[{bandwidth_estimate, T2}], G3} = webrtc_gcc:loss_report(77, 2500, G2),
    ?assert(T2 < T1 * 0.9),
    ?assert(T2 > T1 * 0.8),
    %% Loss gone while still sending 2 Mbps: back to at least that rate.
    G4 = lists:foldl(fun(T, G) -> webrtc_gcc:sent(250, T, G) end, G3, lists:seq(2501, 4000)),
    {_, G5} = webrtc_gcc:loss_report(0, 4000, G4),
    ?assert(webrtc_gcc:target(G5) >= 1900000).
