%% Tests for webrtc_rtcp_ccfb (RFC 8888 congestion control feedback).
-module(webrtc_rtcp_ccfb_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

-import(webrtc_test_hex, [b/1]).

ccfb() ->
    b(
        "8b cd 00 06 00 00 00 01\n"
        "       2a 3b 4c 5d 03 e8 00 03\n"
        "       80 10 00 00 c0 00 00 00\n"
        "       12 34 56 78"
    ).

ccfb_test() ->
    Bin = ccfb(),
    C = #rtcp_ccfb{
        sender_ssrc = 1,
        reports = [{16#2a3b4c5d, 1000, [{0, 16}, not_received, {2, 0}]}],
        timestamp = 16#12345678
    },
    ?assertEqual({ok, [C]}, webrtc_rtcp:decode(Bin)),
    ?assertEqual(Bin, webrtc_rtcp:encode(C)),
    [
        ?assertMatch({error, _}, webrtc_rtcp:decode(binary:part(Bin, 0, N)))
     || N <- lists:seq(0, byte_size(Bin) - 1)
    ].

ccfb_multi_and_empty_test() ->
    C = #rtcp_ccfb{
        sender_ssrc = 1,
        reports = [{1, 65535, [{1, 8191}, {3, 16#1FFE}]}, {2, 7, []}],
        timestamp = 0
    },
    ?assertEqual({ok, [C]}, webrtc_rtcp:decode(webrtc_rtcp:encode(C))),
    Empty = #rtcp_ccfb{sender_ssrc = 1, reports = [], timestamp = 5},
    ?assertEqual(b("8b cd 00 02 00 00 00 01 00 00 00 05"), webrtc_rtcp:encode(Empty)),
    ?assertEqual({ok, [Empty]}, webrtc_rtcp:decode(webrtc_rtcp:encode(Empty))).

%% R = 0: ECN and ATO must be ignored.
ccfb_not_received_ignores_bits_test() ->
    Bin = b("8b cd 00 05 00 00 00 01 00 00 00 02 00 00 00 01 7f ff 00 00 00 00 00 09"),
    ?assertMatch(
        {ok, [#rtcp_ccfb{reports = [{2, 0, [not_received]}], timestamp = 9}]},
        webrtc_rtcp:decode(Bin)
    ).

ccfb_limits_test_() ->
    [
        ?_assertError(
            badarg,
            webrtc_rtcp:encode(#rtcp_ccfb{reports = [{1, 0, lists:duplicate(16385, not_received)}]})
        ),
        ?_assertMatch(
            {error, {bad_packet, 205, too_many_metrics}},
            webrtc_rtcp:decode(<<16#8b, 16#cd, 0, 4, 1:32, 2:32, 0:16, 16385:16, 0:32>>)
        ),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_ccfb{reports = [{1, 0, [{4, 0}]}]}))
    ].

ato_test_() ->
    [
        ?_assertEqual(512, webrtc_rtcp_ccfb:ato(500000)),
        ?_assertEqual(0, webrtc_rtcp_ccfb:ato(0)),
        ?_assertEqual(16#1FFD, webrtc_rtcp_ccfb:ato(7997000)),
        ?_assertEqual(16#1FFE, webrtc_rtcp_ccfb:ato(7999000)),
        ?_assertEqual(16#1FFE, webrtc_rtcp_ccfb:ato(9000000)),
        ?_assertEqual(16#1FFF, webrtc_rtcp_ccfb:ato(-1))
    ].
