%% Tests for webrtc_rtcp: SR, RR, SDES, BYE, APP, compound validation
%% (RFC 3550 §6, Appendix A.2) and reduced-size RTCP (RFC 5506).
-module(webrtc_rtcp_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

-import(webrtc_test_hex, [b/1]).

%% Browser sender report: SR without report blocks followed by SDES
%% with a 16 character CNAME.
sr_sdes() ->
    b("80 c8 00 06  2a 3b 4c 5d
       e5 4f 3a 2b  80 00 00 00
       00 01 e2 40  00 00 01 f4  00 01 86 a0
       81 ca 00 06  2a 3b 4c 5d
       01 10 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 00 00").

%% Browser receiver: RR with one report block followed by REMB.
rr_remb() ->
    b("81 c9 00 07  00 00 00 01
       2a 3b 4c 5d  05 00 00 0a  00 01 12 34  00 00 00 20
       4f 3a 2b 80  00 01 00 00
       8f ce 00 05  00 00 00 01  00 00 00 00
       52 45 4d 42  01 16 dc 6c  2a 3b 4c 5d").

sr_sdes_test() ->
    Bin = sr_sdes(),
    {ok, [SR, SDES]} = webrtc_rtcp:decode(Bin, #{mode => compound}),
    ?assertEqual(
        #rtcp_sr{
            ssrc = 16#2a3b4c5d,
            ntp = 16#e54f3a2b80000000,
            rtp_ts = 123456,
            packets = 500,
            octets = 100000
        },
        SR
    ),
    ?assertEqual(#rtcp_sdes{chunks = [{16#2a3b4c5d, [{cname, <<"abcdefghijklmnop">>}]}]}, SDES),
    ?assertEqual(ok, webrtc_rtcp:validate_compound([SR, SDES])),
    ?assertEqual(Bin, webrtc_rtcp:encode([SR, SDES])).

rr_remb_test() ->
    Bin = rr_remb(),
    {ok, [RR, REMB]} = webrtc_rtcp:decode(Bin, #{mode => compound}),
    ?assertEqual(
        #rtcp_rr{
            ssrc = 1,
            reports = [
                #rtcp_rb{
                    ssrc = 16#2a3b4c5d,
                    fraction_lost = 5,
                    lost = 10,
                    ext_seq = 16#11234,
                    jitter = 32,
                    lsr = 16#4f3a2b80,
                    dlsr = 65536
                }
            ]
        },
        RR
    ),
    ?assertEqual(
        #rtcp_remb{sender_ssrc = 1, media_ssrc = 0, bitrate = 6000000, ssrcs = [16#2a3b4c5d]}, REMB
    ),
    ?assertEqual({error, no_cname}, webrtc_rtcp:validate_compound([RR, REMB])),
    ?assertEqual(Bin, webrtc_rtcp:encode([RR, REMB])).

negative_lost_test() ->
    %% Duplicates make the cumulative lost negative (24-bit signed).
    RB = #rtcp_rb{ssrc = 1, lost = -3},
    Bin = webrtc_rtcp:encode(#rtcp_rr{ssrc = 2, reports = [RB]}),
    <<_:8/binary, _:4/binary, _, 16#FF, 16#FF, 16#FD, _/binary>> = Bin,
    ?assertEqual({ok, [#rtcp_rr{ssrc = 2, reports = [RB]}]}, webrtc_rtcp:decode(Bin)).

sr_with_reports_and_extension_test() ->
    RBs = [#rtcp_rb{ssrc = N, ext_seq = N * 100} || N <- lists:seq(1, 31)],
    SR = #rtcp_sr{ssrc = 9, ntp = 1, rtp_ts = 2, packets = 3, octets = 4, reports = RBs, ext = <<1, 2, 3, 4>>},
    Bin = webrtc_rtcp:encode(SR),
    <<2:2, 0:1, 31:5, 200, _/binary>> = Bin,
    ?assertEqual({ok, [SR]}, webrtc_rtcp:decode(Bin)),
    ?assertError(badarg, webrtc_rtcp:encode(SR#rtcp_sr{reports = [#rtcp_rb{} | RBs]})).

sdes_items_test() ->
    Items = [
        {cname, <<"user@host">>},
        {name, <<"n">>},
        {email, <<"e">>},
        {phone, <<"p">>},
        {loc, <<"l">>},
        {tool, <<"t">>},
        {note, <<"note">>},
        {{priv, <<"pfx">>}, <<"value">>},
        {mid, <<"0">>},
        {rid, <<"hi">>},
        {repaired_rid, <<"hi">>},
        {11, <<"other">>}
    ],
    P = #rtcp_sdes{chunks = [{1, Items}, {2, []}, {3, [{cname, <<"abc">>}]}]},
    Bin = webrtc_rtcp:encode(P),
    ?assertEqual(0, byte_size(Bin) rem 4),
    ?assertEqual({ok, [P]}, webrtc_rtcp:decode(Bin)).

sdes_empty_chunk_layout_test() ->
    %% A chunk without items is the SSRC and one word of null octets.
    ?assertEqual(b("81 ca 00 02 00 00 00 07 00 00 00 00"), webrtc_rtcp:encode(#rtcp_sdes{chunks = [{7, []}]})).

sdes_errors_test_() ->
    [
        %% item length runs past the packet
        ?_assertMatch(
            {error, {bad_packet, 202, truncated}},
            webrtc_rtcp:decode(b("81 ca 00 02 00 00 00 07 01 05 61 00"))
        ),
        %% missing null terminator
        ?_assertMatch(
            {error, {bad_packet, 202, truncated}},
            webrtc_rtcp:decode(b("81 ca 00 02 00 00 00 07 01 02 61 62"))
        ),
        %% fewer chunks than SC
        ?_assertMatch(
            {error, {bad_packet, 202, truncated}},
            webrtc_rtcp:decode(b("82 ca 00 02 00 00 00 07 00 00 00 00"))
        ),
        %% non-zero padding after the terminator
        ?_assertMatch(
            {error, {bad_packet, 202, bad_sdes_padding}},
            webrtc_rtcp:decode(b("81 ca 00 03 00 00 00 07 01 02 61 62 00 00 01 00"))
        )
    ].

bye_test() ->
    Bin = b("81 cb 00 03 2a 3b 4c 5d 04 62 79 65 21 00 00 00"),
    {ok, [Bye]} = webrtc_rtcp:decode(Bin),
    ?assertEqual(#rtcp_bye{ssrcs = [16#2a3b4c5d], reason = <<"bye!">>}, Bye),
    ?assertEqual(Bin, webrtc_rtcp:encode(Bye)),
    Multi = #rtcp_bye{ssrcs = [1, 2, 3]},
    ?assertEqual({ok, [Multi]}, webrtc_rtcp:decode(webrtc_rtcp:encode(Multi))),
    ?assertEqual({ok, [#rtcp_bye{}]}, webrtc_rtcp:decode(b("80 cb 00 00"))),
    ?assertMatch({error, {bad_packet, 203, truncated}}, webrtc_rtcp:decode(b("82 cb 00 01 00 00 00 01"))),
    %% reason length past the end
    ?assertMatch(
        {error, {bad_packet, 203, truncated}},
        webrtc_rtcp:decode(b("81 cb 00 02 00 00 00 01 09 61 62 63"))
    ).

app_test() ->
    Bin = b("82 cc 00 03 00 00 00 01 54 45 53 54 de ad be ef"),
    {ok, [App]} = webrtc_rtcp:decode(Bin),
    ?assertEqual(#rtcp_app{subtype = 2, ssrc = 1, name = <<"TEST">>, data = <<16#deadbeef:32>>}, App),
    ?assertEqual(Bin, webrtc_rtcp:encode(App)),
    ?assertMatch({error, {bad_packet, 204, truncated}}, webrtc_rtcp:decode(b("80 cc 00 01 00 00 00 01"))).

unknown_type_preserved_test() ->
    %% RSI (PT 208) and an unknown PSFB format are kept raw.
    Bin = b("85 d0 00 01 01 02 03 04  9f ce 00 02 00 00 00 01 00 00 00 02"),
    {ok, [R1, R2]} = webrtc_rtcp:decode(Bin),
    ?assertEqual(#rtcp_raw{pt = 208, count = 5, body = <<1, 2, 3, 4>>}, R1),
    ?assertEqual(#rtcp_raw{pt = 206, count = 31, body = <<0, 0, 0, 1, 0, 0, 0, 2>>}, R2),
    ?assertEqual(Bin, webrtc_rtcp:encode([R1, R2])).

%% RFC 3550 §6.4.1 / A.2: padding count includes itself.
padding_test_() ->
    Pkt = b("a1 cb 00 02 00 00 00 01 00 00 00 04"),
    [
        ?_assertEqual({ok, [#rtcp_bye{ssrcs = [1]}]}, webrtc_rtcp:decode(Pkt)),
        ?_assertEqual({error, bad_padding}, webrtc_rtcp:decode(b("a0 cb 00 01 00 00 00 00"))),
        ?_assertEqual({error, bad_padding}, webrtc_rtcp:decode(b("a0 cb 00 01 00 00 00 05"))),
        ?_assertEqual({error, bad_padding}, webrtc_rtcp:decode(b("a0 cb 00 00")))
    ].

compound_validation_test_() ->
    SR = binary:part(sr_sdes(), 0, 28),
    SDES = binary:part(sr_sdes(), 28, 28),
    Padded = b("a1 cb 00 02 00 00 00 01 00 00 00 04"),
    Pli = b("81 ce 00 02 00 00 00 01 00 00 00 02"),
    [
        %% RFC 5506: reduced-size packets start with any type
        ?_assertMatch({ok, [#rtcp_pli{}]}, webrtc_rtcp:decode(Pli)),
        ?_assertMatch({ok, [#rtcp_sdes{}, #rtcp_sr{}]}, webrtc_rtcp:decode(<<SDES/binary, SR/binary>>)),
        ?_assertEqual(
            {error, first_not_report}, webrtc_rtcp:decode(<<SDES/binary, SR/binary>>, #{mode => compound})
        ),
        ?_assertEqual({error, first_not_report}, webrtc_rtcp:decode(Pli, #{mode => compound})),
        %% padding only on the last packet
        ?_assertMatch({ok, [_, _, _]}, webrtc_rtcp:decode(<<SR/binary, SDES/binary, Padded/binary>>, #{mode => compound})),
        ?_assertEqual(
            {error, padding_not_last},
            webrtc_rtcp:decode(<<SR/binary, Padded/binary, SDES/binary>>, #{mode => compound})
        ),
        ?_assertMatch({ok, _}, webrtc_rtcp:decode(<<SR/binary, Padded/binary, SDES/binary>>)),
        %% version of a later packet
        ?_assertEqual(
            {error, bad_version}, webrtc_rtcp:decode(<<SR/binary, 16#41, 16#ca, 0, 0>>)
        ),
        %% length fields must add up to the datagram size
        ?_assertEqual({error, truncated}, webrtc_rtcp:decode(<<SR/binary, 16#80, 16#cb>>)),
        ?_assertEqual({error, bad_version}, webrtc_rtcp:decode(<<SR/binary, 0, 0>>)),
        ?_assertEqual({error, truncated}, webrtc_rtcp:decode(<<>>)),
        ?_assertEqual({error, first_not_report}, webrtc_rtcp:validate_compound([])),
        ?_assertEqual({error, first_not_report}, webrtc_rtcp:validate_compound([#rtcp_pli{}]))
    ].

%% Every cut of a compound packet is an error, except cuts at packet
%% boundaries which leave a shorter valid compound.
truncation_test_() ->
    Packets = [
        sr_sdes(),
        rr_remb(),
        webrtc_rtcp:encode([
            #rtcp_rr{ssrc = 1},
            #rtcp_bye{ssrcs = [1], reason = <<"x">>},
            #rtcp_app{ssrc = 1, name = <<"abcd">>, data = <<1, 2, 3, 4>>}
        ])
    ],
    [?_test(check_truncations(Bin)) || Bin <- Packets].

check_truncations(Bin) ->
    Bounds = boundaries(Bin, 0),
    lists:foreach(
        fun(N) ->
            R = webrtc_rtcp:decode(binary:part(Bin, 0, N)),
            case lists:member(N, Bounds) of
                true -> ?assertMatch({ok, _}, R);
                false -> ?assertMatch({error, _}, R)
            end
        end,
        lists:seq(0, byte_size(Bin) - 1)
    ).

boundaries(Bin, Off) when Off >= byte_size(Bin) ->
    [];
boundaries(Bin, Off) ->
    <<_:Off/binary, _:16, Len:16, _/binary>> = Bin,
    Next = Off + (Len + 1) * 4,
    [Next || Next > 0, Next < byte_size(Bin)] ++ boundaries(Bin, Next).

encode_badarg_test_() ->
    [
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_rr{ssrc = -1})),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_rr{ssrc = 1, ext = <<1, 2>>})),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_app{name = <<"ab">>})),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_raw{pt = 210, body = <<1>>})),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_rr{reports = [#rtcp_rb{fraction_lost = 256}]})),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_rr{reports = [#rtcp_rb{lost = 16#800000}]})),
        ?_assertError(badarg, webrtc_rtcp:encode({not_a_packet}))
    ].

has_cname_test() ->
    ?assert(webrtc_rtcp:has_cname([#rtcp_rr{}, #rtcp_sdes{chunks = [{1, [{cname, <<"c">>}]}]}])),
    ?assertNot(webrtc_rtcp:has_cname([#rtcp_rr{}, #rtcp_sdes{chunks = [{1, [{name, <<"c">>}]}]}])).
