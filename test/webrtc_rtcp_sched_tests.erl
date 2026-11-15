%% Tests of the RTCP scheduler (RFC 3550 §6.3, Appendix A.7; RFC 4585
%% §3.5). The randomisation factor is fixed at 0.5, so every dither
%% factor (U + 0.5) is exactly 1.
-module(webrtc_rtcp_sched_tests).
-include_lib("eunit/include/eunit.hrl").

-define(S, webrtc_rtcp_sched).

new(Opts) ->
    ?S:new(0, maps:merge(#{uniform => fun() -> 0.5 end}, Opts)).

%% RFC 3550 §6.3.1 with A.7's e - 3/2 compensation, in ms.
rfc3550(AvgSize, N, Bw) ->
    round(AvgSize * N / Bw / 1.21828 * 1000).

%% RFC 4585 §3.4 d: point to point, the first report has no minimum.
first_report_early_test() ->
    S = new(#{}),
    %% 600 kbit/s session: 3750 B/s RTCP; one sender of two members is
    %% more than a quarter, so both share it; 100 octet average.
    ?assertEqual(rfc3550(100, 2, 3750), ?S:next_timeout(S)),
    ?assert(?S:next_timeout(S) < 100).

%% RFC 4585 §3.5.3: later reports no closer than T_rr_interval.
report_interval_floor_test() ->
    S0 = new(#{}),
    {send, S1} = ?S:expire(?S:next_timeout(S0), S0),
    S2 = ?S:regular_sent(40, 100, S1),
    ?assertEqual(40 + 1000, ?S:next_timeout(S2)).

%% Without a floor the RFC 3550 interval applies: senders share 25% of
%% the RTCP bandwidth when they are at most a quarter of the members.
bandwidth_interval_test() ->
    S0 = new(#{report_interval => 0, session_bandwidth => 64000, members => 8, senders => 2}),
    S1 = ?S:set_membership(0, 8, 2, true, S0),
    S2 = ?S:regular_sent(0, 72, S1),
    %% 64 kbit/s: 400 B/s RTCP, 100 B/s for the two senders; the
    %% average moved to 100 + (100 - 100) / 16 with 72 + 28 octets.
    ?assertEqual(rfc3550(100, 2, 100), ?S:next_timeout(S2)).

%% §6.3.6: at expiry the interval is recomputed; more members push the
%% report later instead of sending it.
reconsideration_test() ->
    S0 = new(#{report_interval => 0, session_bandwidth => 64000}),
    S1 = ?S:regular_sent(0, 72, S0),
    Tn = ?S:next_timeout(S1),
    ?assertMatch({wait, _}, ?S:expire(Tn - 1, S1)),
    S2 = ?S:set_membership(Tn, 20, 1, false, S1),
    {wait, S3} = ?S:expire(Tn, S2),
    ?assert(?S:next_timeout(S3) > Tn),
    {send, _} = ?S:expire(?S:next_timeout(S3), S3).

%% §6.3.4: members leaving move both timers towards now.
reverse_reconsideration_test() ->
    S0 = new(#{report_interval => 0, session_bandwidth => 64000, members => 10}),
    S1 = ?S:regular_sent(0, 72, ?S:set_membership(0, 10, 1, false, S0)),
    Tn = ?S:next_timeout(S1),
    S2 = ?S:set_membership(100, 5, 1, false, S1),
    ?assertEqual(100 + round((Tn - 100) / 2), ?S:next_timeout(S2)).

%% RFC 4585 §3.5.2: feedback goes out at once within the RTCP bandwidth,
%% then waits for the budget to refill.
feedback_budget_test() ->
    %% 64 kbit/s: 400 B/s of RTCP, budget one datagram (1500).
    S0 = new(#{session_bandwidth => 64000}),
    {S1, Sent} = burst(0, 100, S0, 0),
    ?assertEqual(15, Sent),
    {later, S2} = ?S:feedback(0, 100, S1),
    %% 100 octets at 400 B/s: 250 ms.
    ?assertMatch({later, _}, ?S:feedback(249, 100, S2)),
    ?assertMatch({now, _}, ?S:feedback(250, 100, S2)).

burst(Now, Size, S, N) ->
    case ?S:feedback(Now, Size, S) of
        {now, S1} -> burst(Now, Size, S1, N + 1);
        {later, _} -> {S, N}
    end.

%% A packet larger than the whole budget still goes out once it is full.
oversized_feedback_test() ->
    S0 = new(#{session_bandwidth => 64000}),
    ?assertMatch({now, _}, ?S:feedback(0, 5000, S0)).

info_test() ->
    #{rtcp_bandwidth := 30000, members := 2} = ?S:info(new(#{})).
