%% Tests for webrtc_rtcp_interval (RFC 3550 §6.3, A.7; RFC 4585 §3.5; RFC 8834 §5.1).
-module(webrtc_rtcp_interval_tests).
-include_lib("eunit/include/eunit.hrl").

-define(I, webrtc_rtcp_interval).

params(Over) ->
    maps:merge(
        #{members => 2, senders => 1, rtcp_bw => 400, we_sent => true, avg_rtcp_size => 100, tmin => 5.0},
        Over
    ).

deterministic_test_() ->
    [
        %% two members: interval below the minimum
        ?_assertEqual(5.0, ?I:deterministic(params(#{}))),
        %% 1000 receivers, 10 senders: receivers share 75%
        ?_assertEqual(330.0, ?I:deterministic(params(#{members => 1000, senders => 10, we_sent => false}))),
        %% a sender among few senders shares 25%
        ?_assertEqual(10.0, ?I:deterministic(params(#{members => 1000, senders => 10, tmin => 0}))),
        %% more senders than a quarter: everyone shares the whole bandwidth
        ?_assertEqual(25.0, ?I:deterministic(params(#{members => 100, senders => 50, tmin => 0}))),
        ?_assertEqual(infinity, ?I:deterministic(params(#{rtcp_bw => 0})))
    ].

randomised_test_() ->
    P = params(#{}),
    [
        ?_assertEqual(5.0 / 1.21828, ?I:interval(P, 0.5)),
        ?_assertEqual(2.5 / 1.21828, ?I:interval(P, 0.0)),
        ?_assertEqual(infinity, ?I:interval(params(#{rtcp_bw => 0}), 0.3)),
        ?_test(
            [
                ?assert(T >= 2.5 / 1.21828 andalso T < 7.5 / 1.21828)
             || T <- [?I:interval(P) || _ <- lists:seq(1, 100)]
            ]
        ),
        ?_assertError(function_clause, ?I:interval(P, 1.0))
    ].

min_interval_test_() ->
    [
        ?_assertEqual(5.0, ?I:min_interval(#{})),
        ?_assertEqual(2.5, ?I:min_interval(#{initial => true})),
        %% RFC 3550 §6.2 reduced minimum: 360 / kbps
        ?_assertEqual(0.36, ?I:min_interval(#{reduced => true, session_bw_kbps => 1000})),
        ?_assertEqual(0.18, ?I:min_interval(#{reduced => true, session_bw_kbps => 1000, initial => true})),
        ?_assertEqual(5.0, ?I:min_interval(#{reduced => true, session_bw_kbps => 10})),
        %% RFC 4585 §3.5.1 / §3.5.3
        ?_assertEqual(0.0, ?I:min_interval(#{profile => avpf, initial => true})),
        ?_assertEqual(1.0, ?I:min_interval(#{profile => avpf, initial => true, p2p => false})),
        ?_assertEqual(0.0, ?I:min_interval(#{profile => avpf, p2p => false}))
    ].

timeout_test_() ->
    [
        %% the reduced minimum is not used for the timeout (RFC 8834 §5.1)
        ?_assertEqual(25.0, ?I:timeout(params(#{tmin => 0.36}))),
        ?_assertEqual(165.0 * 10, ?I:timeout(params(#{members => 1000, senders => 10, we_sent => false}))),
        %% AVPF with T_rr_interval (RFC 4585 §3.5.3)
        ?_assertEqual(10.0, ?I:timeout(params(#{tmin => 0, trr_interval => 2})))
    ].

avpf_helpers_test_() ->
    [
        ?_assertEqual(1.0, ?I:trr_current(2, 0.0)),
        ?_assertEqual(2.0, ?I:trr_current(2, 0.5)),
        ?_assertEqual(0.0, ?I:dither_max(p2p, 4)),
        ?_assertEqual(2.0, ?I:dither_max(multiparty, 4)),
        ?_assertEqual(100.0, ?I:avg_rtcp_size(100, 100)),
        ?_assertEqual(110.0, ?I:avg_rtcp_size(100, 260)),
        ?_test(begin
            U = ?I:uniform(),
            ?assert(U >= 0.0 andalso U < 1.0)
        end)
    ].
