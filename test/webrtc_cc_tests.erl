%% Tests for webrtc_cc, the congestion control engine of a media
%% session: when pacing applies, the retransmission limit and run time
%% options.
-module(webrtc_cc_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

cc() ->
    webrtc_cc:configure(#{twcc_send => true, twcc_recv => false, sender_ssrc => 1}, webrtc_cc:new(#{})).

with_remb(Bps, Cc) ->
    {[{bandwidth_estimate, Bps}], Cc1} = webrtc_cc:rtcp(#rtcp_remb{bitrate = Bps}, 0, Cc),
    Cc1.

burst(N, Class, Cc) ->
    lists:foldl(
        fun(I, {Out, C}) ->
            {O, C1} = webrtc_cc:enqueue({Class, 1200, I}, 0, C),
            {Out ++ O, C1}
        end,
        {[], Cc},
        lists:seq(1, N)
    ).

%% Without feedback the target is a guess: nothing is held back.
unpaced_without_feedback_test() ->
    {Out, Cc} = burst(100, video, cc()),
    ?assertEqual(lists:seq(1, 100), Out),
    ?assertMatch(#{pacing := false, unpaced := 100}, webrtc_cc:stats(Cc)).

%% With an estimate (REMB here), the burst is paced at 2.5 x target.
paced_with_estimate_test() ->
    Cc0 = with_remb(400000, cc()),
    {Now, Cc1} = burst(100, video, Cc0),
    ?assert(length(Now) < 5),
    ?assertMatch(#{pacing := true, pacer := #{rate := 1000000}}, webrtc_cc:stats(Cc1)),
    %% 120 KB at 1 Mbps: about a second.
    {Later, _} = drain(Cc1, 1, 2000, []),
    ?assertEqual(100, length(Now) + length(Later)),
    {LastT, _} = lists:last(Later),
    ?assert(LastT >= 900 andalso LastT =< 1000).

drain(Cc, T, To, Acc) when T > To -> {lists:reverse(Acc), Cc};
drain(Cc, T, To, Acc) ->
    {Out, _, _, Cc1} = webrtc_cc:handle_timeout(T, Cc),
    drain(Cc1, T + 1, To, lists:reverse([{T, X} || X <- Out]) ++ Acc).

%% Retransmissions are limited to the target over one second.
rtx_limit_test() ->
    Cc0 = with_remb(96000, cc()),
    %% 96 kbps over one second is 12000 bytes: ten 1200 byte packets.
    {_, Cc1} = burst(15, rtx, Cc0),
    ?assertMatch(#{rtx_limited := 5}, webrtc_cc:stats(Cc1)),
    {_, Cc2} = webrtc_cc:enqueue({rtx, 1200, late}, 1001, Cc1),
    ?assertMatch(#{rtx_limited := 5}, webrtc_cc:stats(Cc2)).

%% Turning pacing off releases the queue at once.
pacing_off_test() ->
    Cc0 = with_remb(100000, cc()),
    {Now, Cc1} = burst(20, video, Cc0),
    {Flushed, [], Cc2} = webrtc_cc:set_options(#{pacing => false}, 0, Cc1),
    ?assertEqual(lists:seq(1, 20), Now ++ Flushed),
    {[x], _} = webrtc_cc:enqueue({video, 1200, x}, 0, Cc2).

limits_test() ->
    Cc0 = with_remb(5000000, cc()),
    {[], [{bandwidth_estimate, 1000000}], Cc1} = webrtc_cc:set_options(#{max_bitrate => 1000000}, 0, Cc0),
    ?assertEqual(1000000, webrtc_cc:target(Cc1)).

%% Sequence numbers only when the extension is negotiated.
twcc_seq_test() ->
    ?assertEqual(undefined, webrtc_cc:twcc_seq(webrtc_cc:new(#{}))),
    Cc = cc(),
    S = webrtc_cc:twcc_seq(Cc),
    ?assertEqual((S + 1) band 16#FFFF, webrtc_cc:twcc_seq(webrtc_cc:sent(m, 100, 0, Cc))).

%% RFC 8083 §4.5: a tripped breaker halts the stream; it is resumed only
%% on request and not before the hold time.
circuit_breaker_halts_test() ->
    Cc0 = webrtc_cc:new(#{circuit_breaker_hold => 5000}),
    ?assertEqual(false, webrtc_cc:halted(<<"0">>, Cc0)),
    %% Sending for 16 s with no report: the RTCP timeout (15 s) trips.
    Cc2 = lists:foldl(fun(T, C) -> webrtc_cc:sent(<<"0">>, 1000, T, C) end, Cc0, lists:seq(0, 16000, 100)),
    {_, _, Events, Cc3} = webrtc_cc:handle_timeout(15000, Cc2),
    ?assertEqual([{circuit_breaker, <<"0">>, rtcp_timeout}], [E || {circuit_breaker, _, _} = E <- Events]),
    ?assertEqual({true, rtcp_timeout}, webrtc_cc:halted(<<"0">>, Cc3)),
    ?assertEqual(false, webrtc_cc:halted(<<"1">>, Cc3)),
    ?assertEqual({error, {retry_after, 4000}}, webrtc_cc:resume(<<"0">>, 16000, Cc3)),
    {ok, Cc4} = webrtc_cc:resume(<<"0">>, 20000, Cc3),
    ?assertEqual(false, webrtc_cc:halted(<<"0">>, Cc4)),
    ?assertEqual({error, not_halted}, webrtc_cc:resume(<<"0">>, 20000, Cc4)).

%% RFC 8083 §4.3: the congestion breaker first cuts the rate by ten; a
%% second trigger after re-arming halts the stream.
congestion_breaker_two_steps_test() ->
    Cc0 = webrtc_cc:new(#{circuit_breaker_hold => 30000}),
    %% Send 2 Mbps (250 B/ms) with 50% loss reported every second, RTT 300 ms.
    Step = fun(T0, C0) ->
        C1 = lists:foldl(fun(T, C) -> webrtc_cc:sent(<<"0">>, 250, T, C) end, C0, lists:seq(T0, T0 + 999)),
        Rb = #rtcp_rb{ssrc = 1, fraction_lost = 128, lost = 0, ext_seq = T0, jitter = 0, lsr = 0, dlsr = 0},
        {Ev, C2} = webrtc_cc:report(<<"0">>, Rb, 300, T0 + 1000, C1),
        {Ev, C2}
    end,
    {Events, Cc} = lists:foldl(
        fun(I, {Acc, C}) -> {E, C1} = Step(I * 1000, C), {Acc ++ E, C1} end,
        {[], Cc0},
        lists:seq(0, 30)
    ),
    Trips = [R || {circuit_breaker, _, R} <- Events],
    ?assertMatch([congestion, congestion | _], Trips),
    ?assertEqual({true, congestion}, webrtc_cc:halted(<<"0">>, Cc)),
    %% The first trip cut the target to about a tenth of 2 Mbps.
    ?assert(lists:any(fun({bandwidth_estimate, B}) -> B =< 250000; (_) -> false end, Events)).
