%% Tests for RTCP feedback messages: generic NACK, PLI, SLI (RFC 4585),
%% TMMBR/TMMBN, FIR (RFC 5104) and REMB.
-module(webrtc_rtcp_fb_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

-import(webrtc_test_hex, [b/1]).

roundtrip(Bin, Expected) ->
    ?assertEqual({ok, [Expected]}, webrtc_rtcp:decode(Bin)),
    ?assertEqual(Bin, webrtc_rtcp:encode(Expected)),
    %% every cut is an error
    [
        ?assertMatch({error, _}, webrtc_rtcp:decode(binary:part(Bin, 0, N)))
     || N <- lists:seq(0, byte_size(Bin) - 1)
    ],
    ok.

%% RFC 4585 §6.2.1: lost 100, 101, 105, 116 -> PID 100 BLP 0x8011; 117
%% starts a new item.
nack_test() ->
    Bin = b("81 cd 00 04 00 00 00 01 2a 3b 4c 5d 00 64 80 11 00 75 00 00"),
    Nack = #rtcp_nack{
        sender_ssrc = 1, media_ssrc = 16#2a3b4c5d, items = [{100, 16#8011}, {117, 0}]
    },
    roundtrip(Bin, Nack),
    ?assertEqual([{100, 16#8011}, {117, 0}], webrtc_rtcp_fb:nack_items([100, 101, 105, 116, 117])),
    ?assertEqual([100, 101, 105, 116, 117], webrtc_rtcp_fb:nack_seqs([{100, 16#8011}, {117, 0}])).

nack_helpers_test_() ->
    F = webrtc_rtcp_fb,
    [
        ?_assertEqual([], F:nack_items([])),
        ?_assertEqual([{5, 0}], F:nack_items([5, 5])),
        %% unordered input
        ?_assertEqual([{1, 16#0003}], F:nack_items([3, 1, 2])),
        %% wraparound: 65534 65535 0 1
        ?_assertEqual([{65534, 7}], F:nack_items([65534, 65535, 0, 1])),
        ?_assertEqual([65534, 65535, 0, 1], F:nack_seqs([{65534, 7}])),
        %% all 16 bits
        ?_assertEqual([{10, 16#FFFF}], F:nack_items(lists:seq(10, 26))),
        ?_assertEqual([{10, 16#FFFF}, {27, 0}], F:nack_items(lists:seq(10, 27)))
    ].

nack_errors_test_() ->
    [
        ?_assertMatch(
            {error, {bad_packet, 205, empty_nack}},
            webrtc_rtcp:decode(b("81 cd 00 02 00 00 00 01 00 00 00 02"))
        ),
        %% TMMBR entries are 8 bytes
        ?_assertMatch(
            {error, {bad_packet, 205, bad_fci_length}},
            webrtc_rtcp:decode(b("83 cd 00 03 00 00 00 01 00 00 00 00 00 00 00 01"))
        ),
        %% feedback without the two SSRCs
        ?_assertMatch(
            {error, {bad_packet, 205, truncated}}, webrtc_rtcp:decode(b("81 cd 00 01 00 00 00 01"))
        ),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_nack{items = []})),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_nack{items = [{70000, 0}]}))
    ].

pli_test() ->
    roundtrip(b("81 ce 00 02 00 00 00 01 2a 3b 4c 5d"), #rtcp_pli{
        sender_ssrc = 1, media_ssrc = 16#2a3b4c5d
    }),
    ?assertMatch(
        {error, {bad_packet, 206, bad_pli}},
        webrtc_rtcp:decode(b("81 ce 00 03 00 00 00 01 00 00 00 02 00 00 00 00"))
    ).

%% RFC 4585 §6.3.2: First 13 bits, Number 13 bits, PictureID 6 bits.
sli_test() ->
    roundtrip(
        b("82 ce 00 03 00 00 00 01 2a 3b 4c 5d 00 50 05 21"),
        #rtcp_sli{sender_ssrc = 1, media_ssrc = 16#2a3b4c5d, entries = [{10, 20, 33}]}
    ).

%% RFC 4585 §6.3.3, the packet of libwebrtc's former rpsi_unittest.cc
%% (branch-heads/55): PB 24, payload type 100, the VP8 picture id
%% 0x106143 as a 3 byte native string.
rpsi_libwebrtc_test() ->
    roundtrip(
        b("83 ce 00 04 12 34 56 78 23 45 67 89 18 64 c1 c2 43 00 00 00"),
        #rtcp_rpsi{sender_ssrc = 16#12345678, media_ssrc = 16#23456789, pt = 100, bits = <<16#c1, 16#c2, 16#43>>}
    ).

%% A native string of any bit length: 16 bits fill the first word, 17
%% need 31 bits of padding.
rpsi_padding_test() ->
    roundtrip(b("83 ce 00 03 00 00 00 01 00 00 00 02 00 60 ab cd"),
              #rtcp_rpsi{sender_ssrc = 1, media_ssrc = 2, pt = 96, bits = <<16#ab, 16#cd>>}),
    roundtrip(b("83 ce 00 04 00 00 00 01 00 00 00 02 1f 60 ab cd 80 00 00 00"),
              #rtcp_rpsi{sender_ssrc = 1, media_ssrc = 2, pt = 96, bits = <<16#ab, 16#cd, 1:1>>}),
    roundtrip(b("83 ce 00 03 00 00 00 01 00 00 00 02 08 60 ab 00"),
              #rtcp_rpsi{sender_ssrc = 1, media_ssrc = 2, pt = 96, bits = <<16#ab>>}).

rpsi_errors_test_() ->
    [?_assertMatch({error, _}, webrtc_rtcp:decode(b(H)))
     || H <- [%% PB too large for the FCI: no native string left
              "83 ce 00 03 00 00 00 01 00 00 00 02 10 60 ab cd",
              %% PB of a whole word
              "83 ce 00 04 00 00 00 01 00 00 00 02 20 60 ab cd 00 00 00 00",
              %% the bit after PB must be zero
              "83 ce 00 03 00 00 00 01 00 00 00 02 00 e0 ab cd",
              %% no FCI
              "83 ce 00 02 00 00 00 01 00 00 00 02"]].

%% RFC 6051 §3.2, Figure 4: RTPFB FMT 5, no FCI, length 2.
srreq_test() ->
    roundtrip(b("85 cd 00 02 00 00 00 01 2a 3b 4c 5d"), #rtcp_srreq{sender_ssrc = 1, media_ssrc = 16#2a3b4c5d}),
    ?assertMatch({error, _}, webrtc_rtcp:decode(b("85 cd 00 03 00 00 00 01 2a 3b 4c 5d 00 00 00 00"))).

%% RFC 5104 §4.3.1: media SSRC 0, FCI SSRC + seq nr + 24 reserved bits.
fir_test() ->
    roundtrip(
        b("84 ce 00 04 00 00 00 01 00 00 00 00 2a 3b 4c 5d 05 00 00 00"),
        #rtcp_fir{sender_ssrc = 1, media_ssrc = 0, entries = [{16#2a3b4c5d, 5}]}
    ),
    %% reserved bits are ignored on receive
    ?assertMatch(
        {ok, [#rtcp_fir{entries = [{2, 9}]}]},
        webrtc_rtcp:decode(b("84 ce 00 04 00 00 00 01 00 00 00 00 00 00 00 02 09 ff ff ff"))
    ).

%% RFC 5104 §4.2.1: 1 Mbit/s = 125000 << 3, overhead 40.
tmmbr_test() ->
    Bin = b("83 cd 00 04 00 00 00 01 00 00 00 00 2a 3b 4c 5d 0f d0 90 28"),
    roundtrip(Bin, #rtcp_tmmbr{sender_ssrc = 1, entries = [{16#2a3b4c5d, 1000000, 40}]}),
    ?assertEqual({3, 125000}, webrtc_rtcp_fb:bitrate_exp(1000000, 17)).

tmmbn_test() ->
    roundtrip(
        b("84 cd 00 04 00 00 00 01 00 00 00 00 2a 3b 4c 5d 0f d0 90 28"),
        #rtcp_tmmbn{sender_ssrc = 1, entries = [{16#2a3b4c5d, 1000000, 40}]}
    ),
    %% an empty bounding set is valid
    roundtrip(b("84 cd 00 02 00 00 00 01 00 00 00 00"), #rtcp_tmmbn{sender_ssrc = 1}).

%% RFC 7728 §8: FMT 9, media SSRC 0, PAUSE then PAUSED with the
%% extended sequence number of the last packet sent.
pause_test() ->
    roundtrip(
        b("89 cd 00 07 00 00 00 01 00 00 00 00 2a 3b 4c 5d 00 00 00 07 2a 3b 4c 5d 20 01 00 07 00 01 00 10"),
        #rtcp_pause{sender_ssrc = 1, entries = [{16#2a3b4c5d, pause, 7, undefined}, {16#2a3b4c5d, paused, 7, 16#10010}]}
    ),
    roundtrip(b("89 cd 00 04 00 00 00 05 00 00 00 00 00 00 00 09 30 00 ff ff"),
              #rtcp_pause{sender_ssrc = 5, entries = [{9, refused, 65535, undefined}]}),
    %% Reserved types are ignored, unknown type specific data skipped.
    ?assertEqual(
        {ok, [#rtcp_pause{sender_ssrc = 1, entries = [{9, resume, 2, undefined}]}]},
        webrtc_rtcp:decode(b("89 cd 00 07 00 00 00 01 00 00 00 00 00 00 00 09 40 00 00 01 00 00 00 09 10 01 00 02 de ad be ef"))
    ),
    ?assertMatch({error, _}, webrtc_rtcp:decode(b("89 cd 00 02 00 00 00 01 00 00 00 00"))).

bitrate_precision_test() ->
    %% values that need more than 17 bits lose their low bits, never round up
    {Exp, Mant} = webrtc_rtcp_fb:bitrate_exp(1000001, 17),
    ?assert((Mant bsl Exp) =< 1000001),
    ?assertEqual({0, 0}, webrtc_rtcp_fb:bitrate_exp(0, 18)),
    ?assertEqual({0, 262143}, webrtc_rtcp_fb:bitrate_exp(262143, 18)),
    ?assertEqual({1, 131072}, webrtc_rtcp_fb:bitrate_exp(262144, 18)).

remb_test() ->
    Bin = b("8f ce 00 06 00 00 00 01 00 00 00 00 52 45 4d 42 02 16 dc 6c 2a 3b 4c 5d 00 00 00 07"),
    roundtrip(Bin, #rtcp_remb{sender_ssrc = 1, bitrate = 6000000, ssrcs = [16#2a3b4c5d, 7]}),
    %% SSRC count larger than the packet
    ?assertMatch(
        {error, {bad_packet, 206, bad_remb}},
        webrtc_rtcp:decode(
            b("8f ce 00 05 00 00 00 01 00 00 00 00 52 45 4d 42 02 16 dc 6c 2a 3b 4c 5d")
        )
    ).

afb_other_raw_test() ->
    Bin = b("8f ce 00 03 00 00 00 01 00 00 00 00 41 42 43 44"),
    ?assertEqual(
        {ok, [#rtcp_raw{pt = 206, count = 15, body = binary:part(Bin, 4, 12)}]},
        webrtc_rtcp:decode(Bin)
    ).
