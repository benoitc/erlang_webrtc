%% RTP stream pause and resume (RFC 7728).
-module(webrtc_rtp_pause_tests).
-include_lib("eunit/include/eunit.hrl").

-define(P, webrtc_rtp_pause).

%% §6.2: PAUSE with the current PauseID pauses at once with nowait;
%% PAUSED goes out then and in the next two regular reports.
pause_resume_test() ->
    S0 = ?P:sender(false),
    {S1, [{paused, 0, 100}], paused} = ?P:sender_in(pause, 0, 100, {0, 0}, S0),
    ?assert(?P:is_paused(S1)),
    {S2, [{paused, 0, 100}]} = ?P:sender_report(105, S1),
    {S3, [{paused, 0, 100}]} = ?P:sender_report(105, S2),
    {S4, []} = ?P:sender_report(105, S3),
    %% A repeated PAUSE is ignored.
    {S4, [], none} = ?P:sender_in(pause, 0, 100, {0, 0}, S4),
    %% RESUME with the current PauseID resumes; the next pause uses 1.
    {S5, [], resumed} = ?P:sender_in(resume, 0, 100, {0, 0}, S4),
    ?assertNot(?P:is_paused(S5)),
    {_, [{paused, 1, 200}], paused} = ?P:sender_in(pause, 1, 200, {0, 0}, S5).

%% §8.1: requests with another PauseID are refused with the current one,
%% except a RESUME with a past PauseID while playing.
refused_test() ->
    S0 = ?P:sender(false),
    {S0, [{refused, 0}], none} = ?P:sender_in(pause, 7, 0, {0, 0}, S0),
    {S1, _, paused} = ?P:sender_in(pause, 0, 0, {0, 0}, S0),
    {S1, [{refused, 0}], none} = ?P:sender_in(resume, 3, 0, {0, 0}, S1),
    {S2, [], resumed} = ?P:sender_in(resume, 0, 0, {0, 0}, S1),
    {S2, [], none} = ?P:sender_in(resume, 0, 0, {0, 0}, S2),
    {S2, [], none} = ?P:sender_in(resume, 40000, 0, {0, 0}, S2),
    {S2, [{refused, 1}], none} = ?P:sender_in(resume, 3, 0, {0, 0}, S2).

%% Without nowait the sender waits the hold-off; a RESUME in it keeps
%% the stream playing.
hold_off_test() ->
    S0 = ?P:sender(false),
    {S1, [], none} = ?P:sender_in(pause, 0, 10, {1000, 300}, S0),
    ?assertEqual(1300, ?P:sender_next_timeout(S1)),
    {S1, [], none} = ?P:sender_timeout({1200, 10}, S1),
    {S2, [{paused, 0, 12}], paused} = ?P:sender_timeout({1300, 12}, S1),
    ?assertEqual(infinity, ?P:sender_next_timeout(S2)),
    {S3, [], none} = ?P:sender_in(pause, 0, 10, {0, 300}, S0),
    {S4, [], none} = ?P:sender_in(resume, 0, 10, {100, 300}, S3),
    ?assertNot(?P:is_paused(S4)),
    ?assertEqual(infinity, ?P:sender_next_timeout(S4)).

%% A stream the answer marked paused starts paused with PauseID 0.
initially_paused_test() ->
    S0 = ?P:sender(true),
    ?assert(?P:is_paused(S0)),
    {_, [], resumed} = ?P:sender_in(resume, 0, 0, {0, 0}, S0).

%% §6.1, §6.4: the requester retransmits until PAUSED, and learns the
%% PauseID from REFUSED.
requester_test() ->
    R0 = ?P:requester(),
    {R1, [{pause, 0}]} = ?P:request(pause, {0, undefined}, R0),
    ?assertEqual(500, ?P:requester_next_timeout(R1)),
    {R1, []} = ?P:requester_timeout(400, undefined, R1),
    {R2, [{pause, 0}]} = ?P:requester_timeout(500, 40, R1),
    ?assertEqual(580, ?P:requester_next_timeout(R2)),
    {R3, paused} = ?P:requester_in({paused, 0, 99}, 510, R2),
    ?assertEqual(paused, ?P:remote_state(R3)),
    ?assertEqual(infinity, ?P:requester_next_timeout(R3)),
    {R4, [{resume, 0}]} = ?P:request(resume, {600, 40}, R3),
    %% The first packet after the resume: next PauseID.
    {R5, resumed} = ?P:requester_rtp(R4),
    ?assertEqual(playing, ?P:remote_state(R5)),
    {R6, [{pause, 1}]} = ?P:request(pause, {700, 40}, R5),
    {R7, refused} = ?P:requester_in({refused, 5}, 710, R6),
    {_, [{pause, 5}]} = ?P:request(pause, {800, 40}, R7).

%% A PAUSED with a past PauseID is stale.
stale_paused_test() ->
    {R1, [_]} = ?P:request(resume, {0, 10}, element(1, ?P:requester_rtp(element(1, ?P:requester_in({paused, 0, 1}, 0, ?P:requester()))))),
    {R1, none} = ?P:requester_in({paused, 0, 1}, 0, R1).
