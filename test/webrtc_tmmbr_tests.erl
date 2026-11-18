%% RFC 5104 §3.5.4: the bounding set of TMMBR tuples and the state of
%% the limits on one stream we send.
-module(webrtc_tmmbr_tests).
-include_lib("eunit/include/eunit.hrl").

-define(T, webrtc_tmmbr).

%% The example of §3.5.4.2: A limits below 31.25 packets/s, B above.
rfc_example_test() ->
    A = {1, 35000, 40},
    B = {2, 40000, 60},
    ?assertEqual([A, B], ?T:bounding_set([B, A])),
    %% Equations (1) and (2) at PR = 20.
    ?assertEqual(28600, ?T:net_rate([A], 20)),
    ?assertEqual(30400, ?T:net_rate([B], 20)),
    ?assertEqual(28600, ?T:net_rate([A, B], 20)),
    ?assertEqual(40000 - 8 * 60 * 40, ?T:net_rate([A, B], 40)).

%% Line c of Figure 1: parallel to a with a higher intercept.
parallel_higher_set_aside_test() ->
    A = {1, 35000, 40},
    C = {3, 50000, 40},
    ?assertEqual([A], ?T:bounding_set([A, C])).

%% A tuple that is above the envelope everywhere is not in the set.
dominated_test() ->
    A = {1, 35000, 40},
    B = {2, 40000, 60},
    D = {4, 60000, 50},
    ?assertEqual([A, B], ?T:bounding_set([A, D, B])).

%% Step 8: each tuple bounds the polygon from where it meets the
%% previous one (A, B at 41.7 packets/s, E at 62.5).
envelope_test() ->
    A = {1, 30000, 10},
    B = {2, 40000, 40},
    E = {5, 45000, 50},
    ?assertEqual([A, B, E], ?T:bounding_set([E, A, B])).

%% Step 7: F is lower than B from 6.25 packets/s, before B gets below
%% A at 41.7, so B never bounds the polygon.
cut_off_test() ->
    A = {1, 30000, 10},
    B = {2, 40000, 40},
    F = {6, 40500, 50},
    ?assertEqual([A, F], ?T:bounding_set([A, B, F])).

zero_overhead_test() ->
    A = {1, 20000, 0},
    B = {2, 50000, 30},
    ?assertEqual([A, B], ?T:bounding_set([A, B])),
    ?assertEqual(20000, ?T:net_rate([A, B], 10)),
    ?assertEqual(0, ?T:net_rate([A, B], 1000)).

zero_bitrate_test() ->
    ?assertEqual([{1, 0, 40}], ?T:bounding_set([{1, 0, 40}, {2, 30000, 60}])),
    %% A line on the X axis bounds everything (found by PropEr).
    ?assertEqual([{2, 0, 0}], ?T:bounding_set([{1, 1, 1}, {2, 0, 0}])),
    ?assertEqual(0, ?T:net_rate([{1, 0, 40}], 0)).

no_limit_test() ->
    ?assertEqual([], ?T:bounding_set([])),
    ?assertEqual(infinity, ?T:net_rate([], 50)).

%% A stricter request applies at once; a relaxed one waits for the
%% hold-off (§4.2.1.2).
hold_off_test() ->
    S1 = ?T:request(7, 100000, 40, 0, 200, ?T:new()),
    ?assertEqual([{7, 100000, 40}], ?T:enforced(0, S1)),
    S2 = ?T:request(7, 50000, 40, 10, 200, S1),
    ?assertEqual([{7, 50000, 40}], ?T:enforced(10, S2)),
    S3 = ?T:request(7, 300000, 40, 20, 200, S2),
    ?assertEqual([{7, 300000, 40}], ?T:set(S3)),
    ?assertEqual([{7, 50000, 40}], ?T:enforced(219, S3)),
    ?assertEqual(220, ?T:next_timeout(S3)),
    S4 = ?T:handle_timeout(220, S3),
    ?assertEqual([{7, 300000, 40}], ?T:enforced(220, S4)),
    ?assertEqual(infinity, ?T:next_timeout(S4)).

%% A request from a non-owner that does not limit more leaves the set
%% as it was; the caller still answers it with TMMBN (§4.2.2.2).
non_owner_test() ->
    S1 = ?T:request(1, 50000, 40, 0, 0, ?T:new()),
    S2 = ?T:request(2, 90000, 40, 0, 0, S1),
    ?assertEqual([{1, 50000, 40}], ?T:set(S2)).

%% The owner's new tuple replaces its old one, even when higher.
owner_replaces_test() ->
    S1 = ?T:request(1, 50000, 40, 0, 0, ?T:new()),
    S2 = ?T:request(1, 90000, 40, 0, 0, S1),
    ?assertEqual([{1, 90000, 40}], ?T:set(S2)).

leave_test() ->
    S1 = ?T:request(1, 50000, 40, 0, 100, ?T:new()),
    ?assertMatch({false, _}, ?T:leave(9, 10, 100, S1)),
    {true, S2} = ?T:leave(1, 10, 100, S1),
    ?assertEqual([], ?T:set(S2)),
    %% Lifting the limit is an increase, so it waits too.
    ?assertEqual([{1, 50000, 40}], ?T:enforced(50, S2)),
    ?assertEqual([], ?T:enforced(110, ?T:handle_timeout(110, S2))).

expire_test() ->
    S1 = ?T:request(1, 35000, 40, 0, 0, ?T:new()),
    S2 = ?T:request(2, 40000, 60, 0, 0, S1),
    S3 = ?T:touch(2, 20000, S2),
    {Gone, S4} = ?T:expire(25000, 25000, 0, S3),
    ?assertEqual([1], Gone),
    ?assertEqual([{2, 40000, 60}], ?T:set(S4)).
