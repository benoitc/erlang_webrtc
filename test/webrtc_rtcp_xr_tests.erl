%% Tests for webrtc_rtcp_xr (RFC 3611 RRTR and DLRR blocks).
-module(webrtc_rtcp_xr_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

-import(webrtc_test_hex, [b/1]).

roundtrip(Bin, Expected) ->
    ?assertEqual({ok, [Expected]}, webrtc_rtcp:decode(Bin)),
    ?assertEqual(Bin, webrtc_rtcp:encode(Expected)),
    %% every cut is an error
    [?assertMatch({error, _}, webrtc_rtcp:decode(binary:part(Bin, 0, N))) || N <- lists:seq(0, byte_size(Bin) - 1)],
    ok.

%% RFC 3611 §4.4 and §4.5.
xr_test() ->
    Bin = b("80 cf 00 08 00 00 00 01
             04 00 00 02 e5 4f 3a 2b 80 00 00 00
             05 00 00 03 2a 3b 4c 5d 3a 2b 80 00 00 00 80 00"),
    roundtrip(
        Bin,
        #rtcp_xr{
            ssrc = 1,
            blocks = [{rrtr, 16#e54f3a2b80000000}, {dlrr, [{16#2a3b4c5d, 16#3a2b8000, 16#8000}]}]
        }
    ).

xr_unknown_block_test() ->
    Bin = b("80 cf 00 03 00 00 00 01 07 2a 00 01 01 02 03 04"),
    roundtrip(Bin, #rtcp_xr{ssrc = 1, blocks = [{7, 42, <<1, 2, 3, 4>>}]}).

xr_errors_test_() ->
    [
        ?_assertMatch(
            {error, {bad_packet, 207, bad_rrtr}}, webrtc_rtcp:decode(b("80 cf 00 03 00 00 00 01 04 00 00 01 00 00 00 00"))
        ),
        ?_assertMatch(
            {error, {bad_packet, 207, bad_dlrr}}, webrtc_rtcp:decode(b("80 cf 00 03 00 00 00 01 05 00 00 01 00 00 00 00"))
        ),
        ?_assertMatch(
            {error, {bad_packet, 207, truncated}}, webrtc_rtcp:decode(b("80 cf 00 02 00 00 00 01 04 00 00 02"))
        ),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_xr{blocks = [{9, 0, <<1>>}]}))
    ].
