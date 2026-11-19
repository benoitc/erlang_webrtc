%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Conformance tests for webrtc_sdp (RFC 8866 and WebRTC attributes) on
%% realistic browser and server session descriptions.
-module(webrtc_sdp_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_sdp.hrl").

-define(S, webrtc_sdp_samples).
-define(M, webrtc_sdp_media).

parse(Bin) ->
    {ok, Sdp} = webrtc_sdp:parse(Bin),
    Sdp.

lines(Lines) -> iolist_to_binary([[L, "\r\n"] || L <- Lines]).

header() -> [<<"v=0">>, <<"o=- 1 1 IN IP4 127.0.0.1">>, <<"s=-">>, <<"t=0 0">>].

%%--------------------------------------------------------------------
%% Round trip
%%--------------------------------------------------------------------

roundtrip_test_() ->
    [
        {atom_to_list(Name), fun() -> ?assertEqual(Bin, webrtc_sdp:encode(parse(Bin))) end}
     || {Name, Bin} <- ?S:all()
    ].

lf_only_test_() ->
    [
        {atom_to_list(Name), fun() ->
            Lf = binary:replace(Bin, <<"\r\n">>, <<"\n">>, [global]),
            ?assertEqual(parse(Bin), parse(Lf)),
            ?assertEqual(Bin, webrtc_sdp:encode(parse(Lf)))
        end}
     || {Name, Bin} <- ?S:all()
    ].

missing_final_newline_test() ->
    Bin = ?S:chrome_offer(),
    Trimmed = binary:part(Bin, 0, byte_size(Bin) - 2),
    ?assertEqual(parse(Bin), parse(Trimmed)).

%%--------------------------------------------------------------------
%% Samples
%%--------------------------------------------------------------------

chrome_offer_test() ->
    Sdp = parse(?S:chrome_offer()),
    #sdp{origin = O, media = [A, V, D]} = Sdp,
    ?assertEqual(4215775240449105457, O#sdp_origin.sess_id),
    ?assertEqual(2, O#sdp_origin.sess_version),
    ?assertEqual([[<<"0">>, <<"1">>, <<"2">>]], ?M:groups(<<"BUNDLE">>, Sdp)),
    ?assertEqual({ok, true}, ?M:attr(extmap_allow_mixed, Sdp)),
    {ok, #{semantic := <<"WMS">>, ids := [_]}} = ?M:attr(msid_semantic, Sdp),
    %% audio
    ?assertEqual(<<"0">>, ?M:mid(A)),
    ?assertEqual(sendrecv, ?M:direction(A, Sdp)),
    ?assertEqual({ok, #{ufrag => <<"EsAw">>, pwd => <<"P2uYro0UCOQ4zxjKXaWCBui1">>}}, ?M:ice_credentials(A, Sdp)),
    ?assertEqual([<<"trickle">>], ?M:ice_options(A, Sdp)),
    ?assertEqual({ok, actpass}, ?M:setup(A, Sdp)),
    [#{hash := sha256, value := Fp}] = ?M:fingerprints(A, Sdp),
    ?assertEqual(32, byte_size(Fp)),
    ?assertEqual(<<16#D2, 16#FA>>, binary:part(Fp, 0, 2)),
    ?assertEqual({ok, #{port => 9, connection => #sdp_connection{}}}, ?M:attr(rtcp, A)),
    [Opus, Red | _] = ?M:codecs(A),
    ?assertEqual(
        #{
            pt => 111,
            name => <<"opus">>,
            clock_rate => 48000,
            channels => 2,
            fmtp => [{<<"minptime">>, <<"10">>}, {<<"useinbandfec">>, <<"1">>}],
            rtcp_fb => [#{type => <<"transport-cc">>, param => undefined}]
        },
        Opus
    ),
    ?assertMatch(#{pt := 63, name := <<"red">>, fmtp := [<<"111/111">>]}, Red),
    ?assertEqual([111, 63, 9, 0, 8, 13, 110, 126], [Pt || #{pt := Pt} <- ?M:codecs(A)]),
    ?assertMatch(
        [#{id := 1, uri := <<"urn:ietf:params:rtp-hdrext:ssrc-audio-level">>, direction := undefined} | _],
        ?M:attrs(extmap, A)
    ),
    {ok, #{stream := <<"5b4ef5e8-", _/binary>>, track := <<"a7c3e1f0-", _/binary>>}} = ?M:attr(msid, A),
    ?assertMatch([#{ssrc := 3570614608, attribute := <<"cname">>, value := <<"4TOk42mSjXCkVIa6">>} | _], ?M:attrs(ssrc, A)),
    %% video
    Codecs = ?M:codecs(V),
    ?assertEqual(
        [<<"VP8">>, <<"rtx">>, <<"VP9">>, <<"rtx">>, <<"H264">>, <<"rtx">>, <<"AV1">>, <<"rtx">>, <<"red">>, <<"rtx">>, <<"ulpfec">>],
        [N || #{name := N} <- Codecs]
    ),
    [Vp8, Rtx | _] = Codecs,
    ?assertEqual(5, length(maps:get(rtcp_fb, Vp8))),
    ?assertEqual([{<<"apt">>, <<"96">>}], maps:get(fmtp, Rtx)),
    ?assertEqual([#{semantics => <<"FID">>, ssrcs => [1105218712, 2851338383]}], ?M:attrs(ssrc_group, V)),
    ?assertEqual(11, length(?M:attrs(extmap, V))),
    %% data channel
    ?assertEqual(<<"application">>, D#sdp_media.media),
    ?assertEqual(<<"UDP/DTLS/SCTP">>, D#sdp_media.proto),
    ?assertEqual([<<"webrtc-datachannel">>], D#sdp_media.fmts),
    ?assertEqual({ok, 5000}, ?M:attr(sctp_port, D)),
    ?assertEqual({ok, 262144}, ?M:attr(max_message_size, D)),
    ?assertEqual([], ?M:codecs(D)).

chrome_answer_test() ->
    Sdp = parse(?S:chrome_answer()),
    [A, V, _] = Sdp#sdp.media,
    ?assertEqual({ok, active}, ?M:setup(A, Sdp)),
    ?assertEqual(recvonly, ?M:direction(A, Sdp)),
    ?assertEqual(recvonly, ?M:direction(V, Sdp)),
    ?assertEqual(error, ?M:attr(msid, A)),
    {ok, #{semantic := <<"WMS">>, ids := []}} = ?M:attr(msid_semantic, Sdp),
    ?assertEqual([96, 97, 45, 46], ?M:payload_types(V)).

firefox_offer_test() ->
    Sdp = parse(?S:firefox_offer()),
    [A, V, D] = Sdp#sdp.media,
    %% session-level fingerprint applies to every section
    [#{hash := sha256}] = ?M:fingerprints(A, Sdp),
    ?assertEqual([], ?M:attrs(fingerprint, A)),
    ?assertEqual({ok, #{semantic => <<"WMS">>, ids => [<<"*">>]}}, ?M:attr(msid_semantic, Sdp)),
    ?assertMatch([_, #{id := 2, direction := recvonly}, _], ?M:attrs(extmap, A)),
    ?assertMatch(
        [#{name := <<"opus">>, fmtp := [{<<"maxplaybackrate">>, <<"48000">>} | _]} | _],
        ?M:codecs(A)
    ),
    ?assertMatch(#{name := <<"telephone-event">>, channels := 1, fmtp := [<<"0-15">>]}, lists:last(?M:codecs(A))),
    ?assertEqual(
        [
            #{id => <<"h">>, direction => send, pts => [], params => []},
            #{id => <<"m">>, direction => send, pts => [], params => []},
            #{id => <<"l">>, direction => send, pts => [], params => []}
        ],
        ?M:attrs(rid, V)
    ),
    ?assertEqual(
        {ok, [{send, [[{<<"h">>, false}], [{<<"m">>, false}], [{<<"l">>, false}]]}]},
        ?M:attr(simulcast, V)
    ),
    ?assertEqual(3, length(?M:attrs(ssrc_group, V))),
    ?assertEqual({ok, 1073741823}, ?M:attr(max_message_size, D)),
    ?assertEqual(sendrecv, ?M:direction(D, Sdp)).

firefox_legacy_datachannel_test() ->
    Sdp = parse(?S:firefox_legacy_datachannel()),
    [D] = Sdp#sdp.media,
    ?assertEqual(<<"DTLS/SCTP">>, D#sdp_media.proto),
    ?assertEqual({ok, #{port => 5000, protocol => <<"webrtc-datachannel">>, streams => 256}}, ?M:attr(sctpmap, D)),
    ?assertEqual([[<<"sdparta_0">>]], ?M:groups(<<"BUNDLE">>, Sdp)).

safari_offer_test() ->
    Sdp = parse(?S:safari_offer()),
    [_, V] = Sdp#sdp.media,
    [H264 | _] = ?M:codecs(V),
    ?assertMatch(#{pt := 96, name := <<"H264">>}, H264),
    ?assertEqual(
        {ok, <<"640c1f">>},
        maps:find(<<"profile-level-id">>, maps:from_list(maps:get(fmtp, H264)))
    ).

pion_answer_test() ->
    Sdp = parse(?S:pion_answer()),
    [A, D] = Sdp#sdp.media,
    [#{hash := sha256}] = ?M:fingerprints(A, Sdp),
    [#{hash := sha256}] = ?M:fingerprints(D, Sdp),
    ?assertEqual({ok, active}, ?M:setup(D, Sdp)),
    Cands = ?M:candidates(A),
    ?assertEqual(4, length(Cands)),
    ?assertEqual([1, 2, 1, 1], [C#sdp_candidate.component || C <- Cands]),
    Srflx = lists:last(Cands),
    ?assertEqual(srflx, Srflx#sdp_candidate.type),
    ?assertEqual({0, 0, 0, 0}, Srflx#sdp_candidate.raddr),
    ?assertEqual(51234, Srflx#sdp_candidate.rport),
    ?assert(?M:end_of_candidates(A)),
    ?assertNot(?M:end_of_candidates(D)),
    ?assertMatch([_, _, #{attribute := <<"mslabel">>, value := <<"pion-stream">>}, _], ?M:attrs(ssrc, A)).

ice_lite_answer_test() ->
    Sdp = parse(?S:ice_lite_answer()),
    [A, V] = Sdp#sdp.media,
    ?assert(?M:ice_lite(Sdp)),
    [#{hash := sha512, value := Fp}] = ?M:fingerprints(A, Sdp),
    ?assertEqual(64, byte_size(Fp)),
    ?assertEqual({ok, passive}, ?M:setup(A, Sdp)),
    ?assertEqual([<<"renomination">>], ?M:ice_options(A, Sdp)),
    [_, Tcp] = ?M:candidates(A),
    ?assertEqual(<<"tcp">>, Tcp#sdp_candidate.transport),
    ?assertEqual(passive, Tcp#sdp_candidate.tcptype),
    ?assertEqual({203, 0, 113, 10}, Tcp#sdp_candidate.address),
    ?assertEqual([{<<"AS">>, 2500}, {<<"TIAS">>, 2500000}], V#sdp_media.bandwidths),
    ?assertEqual(sendonly, ?M:direction(V, Sdp)),
    ?assertMatch([_, #{id := 10, attributes := <<"vad=on">>}], ?M:attrs(extmap, A)).

trickle_candidates_test() ->
    Sdp = parse(?S:trickle_candidates()),
    [D] = Sdp#sdp.media,
    [V4, V6, LinkLocal, Mdns, Srflx, Tcp, Relay] = ?M:candidates(D),
    ?assertEqual({192, 168, 0, 196}, V4#sdp_candidate.address),
    ?assertEqual(
        [{<<"generation">>, <<"0">>}, {<<"network-id">>, <<"1">>}, {<<"network-cost">>, <<"10">>}],
        V4#sdp_candidate.extensions
    ),
    ?assertEqual({16#2001, 16#db8, 16#85a3, 0, 0, 16#8a2e, 16#370, 16#7334}, V6#sdp_candidate.address),
    ?assertMatch({16#fe80, 0, 0, 0, _, _, _, _}, LinkLocal#sdp_candidate.address),
    ?assertEqual(<<"4c1e3a8f-6b2d-4e57-9c0a-1d2e3f4a5b6c.local">>, Mdns#sdp_candidate.address),
    ?assert(webrtc_sdp_candidate:is_mdns(Mdns)),
    ?assertNot(webrtc_sdp_candidate:is_mdns(V4)),
    ?assertEqual({ok, <<"EsAw">>}, webrtc_sdp_candidate:extension(<<"ufrag">>, Mdns)),
    ?assertEqual({{0, 0, 0, 0}, 0}, {Srflx#sdp_candidate.raddr, Srflx#sdp_candidate.rport}),
    ?assertEqual({active, 9}, {Tcp#sdp_candidate.tcptype, Tcp#sdp_candidate.port}),
    ?assertEqual(relay, Relay#sdp_candidate.type),
    ?assert(?M:end_of_candidates(D)),
    %% media-level ice-options override the session-level ones
    ?assertEqual([<<"trickle">>, <<"renomination">>], ?M:ice_options(D, Sdp)),
    ?assertEqual({ok, [<<"trickle">>, <<"ice2">>]}, ?M:attr(ice_options, Sdp)).

simulcast_paused_test() ->
    Sdp = parse(?S:simulcast_paused()),
    [V] = Sdp#sdp.media,
    ?assertEqual(
        {ok, [
            {send, [[{<<"f">>, false}], [{<<"h">>, true}, {<<"h2">>, false}], [{<<"q">>, true}]]},
            {recv, [[{<<"r0">>, false}]]}
        ]},
        ?M:attr(simulcast, V)
    ),
    [F, _, _, Q, R0] = ?M:attrs(rid, V),
    ?assertEqual(
        #{
            id => <<"f">>,
            direction => send,
            pts => [96, 98],
            params => [
                {<<"max-width">>, <<"1280">>}, {<<"max-height">>, <<"720">>}, {<<"max-fps">>, <<"30">>}
            ]
        },
        F
    ),
    ?assertMatch(#{pts := [], params := [_, _, {<<"max-br">>, <<"150000">>}, {<<"depend">>, <<"h">>}]}, Q),
    ?assertMatch(#{id := <<"r0">>, direction := recv}, R0),
    ?assertEqual({ok, 29.97}, ?M:attr(framerate, V)),
    ?assertEqual({ok, true}, ?M:attr(rtcp_mux_only, V)),
    %% the wildcard feedback is merged into every codec
    [Vp8, Rtx, H264, _] = ?M:codecs(V),
    ?assertEqual(6, length(maps:get(rtcp_fb, Vp8))),
    ?assertEqual([#{type => <<"nack">>, param => undefined}], maps:get(rtcp_fb, Rtx)),
    ?assertEqual([#{type => <<"nack">>, param => undefined}], maps:get(rtcp_fb, H264)).

rfc8866_example_test() ->
    Sdp = parse(?S:rfc8866_example()),
    ?assertEqual(<<"Call to John Smith">>, Sdp#sdp.session_name),
    ?assertEqual(<<"SDP Offer #1">>, Sdp#sdp.information),
    ?assertEqual([<<"Jane Doe <jane@jdoe.example.com>">>], Sdp#sdp.emails),
    ?assertEqual([<<"+1 617 555-6011">>], Sdp#sdp.phones),
    ?assertEqual([{<<"AS">>, 2000}], Sdp#sdp.bandwidths),
    ?assertEqual(
        [
            #sdp_time{
                start = 3034423619,
                stop = 3042462419,
                repeats = [
                    [<<"604800">>, <<"3600">>, <<"0">>, <<"90000">>],
                    [<<"7d">>, <<"1h">>, <<"0">>, <<"25h">>]
                ],
                zones = [{2882844526, <<"-1h">>}, {2898848070, <<"0">>}]
            },
            #sdp_time{}
        ],
        Sdp#sdp.times
    ),
    ?assertEqual(<<"prompt">>, Sdp#sdp.key),
    ?assertEqual([{direction, recvonly}, {<<"tool">>, <<"custom">>}], Sdp#sdp.attributes),
    [A1, A2, V] = Sdp#sdp.media,
    ?assertEqual(<<"Voice">>, A1#sdp_media.information),
    ?assertEqual([{ptime, 20}, {maxptime, 40}], A1#sdp_media.attributes),
    ?assertEqual(recvonly, ?M:direction(A1, Sdp)),
    ?assertEqual({49180, 2}, {A2#sdp_media.port, A2#sdp_media.port_count}),
    ?assertEqual([#sdp_connection{address = <<"233.252.0.1/127">>}], A2#sdp_media.connections),
    ?assertEqual([#{pt => 0, name => <<"PCMU">>, clock_rate => 8000, channels => 1, fmtp => [], rtcp_fb => []},
                  #{pt => 8, name => <<"PCMA">>, clock_rate => 8000, channels => 1, fmtp => [], rtcp_fb => []}],
                 ?M:codecs(A2)),
    ?assertEqual(<<"clear:secret">>, V#sdp_media.key),
    ?assertEqual({ok, [<<"main">>, <<"slides">>]}, ?M:attr(content, V)),
    ?assertEqual({ok, new}, ?M:attr(connection, V)),
    ?assertEqual({ok, <<"abc3de65cddef001be82">>}, ?M:attr(tls_id, V)).

%%--------------------------------------------------------------------
%% Malformed input
%%--------------------------------------------------------------------

malformed_test_() ->
    H = header(),
    M = [<<"m=audio 9 UDP/TLS/RTP/SAVPF 111">>],
    Cases = [
        {<<>>, 1, missing_version},
        {lines([<<"o=- 1 1 IN IP4 127.0.0.1">>]), 1, missing_version},
        {lines([<<"v=1">> | tl(H)]), 1, bad_version},
        {lines([<<"v=0">>, <<"s=-">>, <<"t=0 0">>]), 2, missing_origin},
        {lines([<<"v=0">>]), 2, missing_origin},
        {lines([<<"v=0">>, <<"o=- x 1 IN IP4 127.0.0.1">>, <<"s=-">>, <<"t=0 0">>]), 2, bad_origin},
        {lines([<<"v=0">>, <<"o=- 1 1 IN IP4">>, <<"s=-">>, <<"t=0 0">>]), 2, bad_origin},
        {lines([<<"v=0">>, <<"o=- 1 1 IN IP4 127.0.0.1">>, <<"t=0 0">>]), 3, missing_session_name},
        {lines([<<"v=0">>, <<"o=- 1 1 IN IP4 127.0.0.1">>, <<"s=-">>]), 4, missing_time},
        {lines([<<"v=0">>, <<"o=- 1 1 IN IP4 127.0.0.1">>, <<"s=-">>, <<"a=foo">>, <<"t=0 0">>]), 4, missing_time},
        {lines(H ++ [<<"t=12 0">>]), 5, bad_time},
        {lines(H ++ [<<"c=IN IP4 0.0.0.0">>]), 5, {unexpected_field, <<"c">>}},
        {lines(H ++ [<<"x=1">>]), 5, {unknown_field, <<"x">>}},
        {lines(H ++ [<<"V=0">>]), 5, bad_line},
        {lines(H ++ [<<"a">>]), 5, bad_line},
        {lines(H ++ [<<>>, <<"a=foo">>]), 5, empty_line},
        {lines(H ++ [<<"a=fo", 0, "o">>]), 5, bad_character},
        {lines(H ++ [<<"a=foo\rbar">>]), 5, bad_character},
        {lines(H ++ [<<"m=audio 9">>]), 5, bad_media},
        {lines(H ++ [<<"m=audio 9 UDP/TLS/RTP/SAVPF">>]), 5, bad_media},
        {lines(H ++ [<<"m=audio  9 UDP/TLS/RTP/SAVPF 111">>]), 5, bad_media},
        {lines(H ++ [<<"m=audio 70000 UDP/TLS/RTP/SAVPF 111">>]), 5, bad_port},
        {lines(H ++ [<<"m=audio x9 UDP/TLS/RTP/SAVPF 111">>]), 5, bad_port},
        {lines(H ++ [<<"m=audio 9/0 RTP/AVP 0">>]), 5, bad_port},
        {lines(H ++ [<<"m=audio 9 UDP//SAVPF 111">>]), 5, bad_proto},
        {lines(H ++ M ++ [<<"i=a">>, <<"i=b">>]), 7, {unexpected_field, <<"i">>}},
        {lines(H ++ M ++ [<<"a=mid:0">>, <<"c=IN IP4 0.0.0.0">>]), 7, {unexpected_field, <<"c">>}},
        {lines(H ++ M ++ [<<"b=AS">>]), 6, bad_bandwidth},
        {lines(H ++ M ++ [<<"c=IN IP4">>]), 6, bad_connection},
        {lines(H ++ M ++ [<<"k=bogus">>]), 6, bad_key},
        {lines(H ++ [<<"a=ice-pacing:">>]), 5, {bad_attribute, <<"ice-pacing">>}},
        {lines(H ++ [<<"a=ice-pacing:-1">>]), 5, {bad_attribute, <<"ice-pacing">>}},
        {lines(H ++ [<<"a=ice-pacing:5 ms">>]), 5, {bad_attribute, <<"ice-pacing">>}},
        {lines(H ++ [<<"a=ice-pacing:12345678901">>]), 5, {bad_attribute, <<"ice-pacing">>}},
        {lines(H ++ [<<"a=ice-pacing">>]), 5, {bad_attribute, <<"ice-pacing">>}},
        {lines(H ++ M ++ [<<"a=rtpmap:111 opus">>]), 6, {bad_attribute, <<"rtpmap">>}},
        {lines(H ++ M ++ [<<"a=rtpmap:128 opus/48000/2">>]), 6, {bad_attribute, <<"rtpmap">>}},
        {lines(H ++ M ++ [<<"a=rtpmap:111 opus/0">>]), 6, {bad_attribute, <<"rtpmap">>}},
        {lines(H ++ M ++ [<<"a=rtpmap:111 opus/48000/2/1">>]), 6, {bad_attribute, <<"rtpmap">>}},
        {lines(H ++ M ++ [<<"a=fmtp:111">>]), 6, {bad_attribute, <<"fmtp">>}},
        {lines(H ++ M ++ [<<"a=rtcp-fb:x nack">>]), 6, {bad_attribute, <<"rtcp-fb">>}},
        {lines(H ++ M ++ [<<"a=fingerprint:sha-256 ZZ:FA">>]), 6, {bad_attribute, <<"fingerprint">>}},
        {lines(H ++ M ++ [<<"a=fingerprint:sha-256 D2:FA">>]), 6, {bad_attribute, <<"fingerprint">>}},
        {lines(H ++ M ++ [<<"a=fingerprint:sha-1 D2:FA:">>]), 6, {bad_attribute, <<"fingerprint">>}},
        {lines(H ++ M ++ [<<"a=fingerprint:sha-256 D2FA">>]), 6, {bad_attribute, <<"fingerprint">>}},
        {lines(H ++ M ++ [<<"a=fingerprint:sha-256">>]), 6, {bad_attribute, <<"fingerprint">>}},
        {lines(H ++ M ++ [cand(<<"1 0 udp 1 192.0.2.1 1 typ host">>)]), 6, {bad_attribute, <<"candidate">>}},
        {lines(H ++ M ++ [cand(<<"1 257 udp 1 192.0.2.1 1 typ host">>)]), 6, {bad_attribute, <<"candidate">>}},
        {lines(H ++ M ++ [cand(<<"1 1 udp 0 192.0.2.1 1 typ host">>)]), 6, {bad_attribute, <<"candidate">>}},
        {lines(H ++ M ++ [cand(<<"1 1 udp 1 192.0.2.1 65536 typ host">>)]), 6, {bad_attribute, <<"candidate">>}},
        {lines(H ++ M ++ [cand(<<"1 1 udp 1 192.0.2.1 1 host">>)]), 6, {bad_attribute, <<"candidate">>}},
        {lines(H ++ M ++ [cand(<<"1 1 udp 1 192.0.2.300 1 typ host">>)]), 6, {bad_attribute, <<"candidate">>}},
        {lines(H ++ M ++ [<<"a=rtcp-mux:1">>]), 6, {bad_attribute, <<"rtcp-mux">>}},
        {lines(H ++ M ++ [<<"a=sendrecv:x">>]), 6, {bad_attribute, <<"sendrecv">>}},
        {lines(H ++ M ++ [<<"a=mid">>]), 6, {bad_attribute, <<"mid">>}},
        {lines(H ++ M ++ [<<"a=ice-pwd:short">>]), 6, {bad_attribute, <<"ice-pwd">>}},
        {lines(H ++ M ++ [<<"a=ice-ufrag:ab$c">>]), 6, {bad_attribute, <<"ice-ufrag">>}},
        {lines(H ++ M ++ [<<"a=setup:client">>]), 6, {bad_attribute, <<"setup">>}},
        {lines(H ++ M ++ [<<"a=extmap:0 urn:x">>]), 6, {bad_attribute, <<"extmap">>}},
        {lines(H ++ M ++ [<<"a=extmap:300 urn:x">>]), 6, {bad_attribute, <<"extmap">>}},
        {lines(H ++ M ++ [<<"a=extmap:1/both urn:x">>]), 6, {bad_attribute, <<"extmap">>}},
        {lines(H ++ M ++ [<<"a=rid:h both">>]), 6, {bad_attribute, <<"rid">>}},
        {lines(H ++ M ++ [<<"a=rid:h send pt=x">>]), 6, {bad_attribute, <<"rid">>}},
        {lines(H ++ M ++ [<<"a=rid:h send depend">>]), 6, {bad_attribute, <<"rid">>}},
        {lines(H ++ M ++ [<<"a=simulcast:send h;;l">>]), 6, {bad_attribute, <<"simulcast">>}},
        {lines(H ++ M ++ [<<"a=simulcast:send h send l">>]), 6, {bad_attribute, <<"simulcast">>}},
        {lines(H ++ M ++ [<<"a=ssrc:4294967296 cname:x">>]), 6, {bad_attribute, <<"ssrc">>}},
        {lines(H ++ M ++ [<<"a=ssrc:1">>]), 6, {bad_attribute, <<"ssrc">>}},
        {lines(H ++ M ++ [<<"a=ssrc-group:FID 1 x">>]), 6, {bad_attribute, <<"ssrc-group">>}},
        {lines(H ++ M ++ [<<"a=msid:a b c">>]), 6, {bad_attribute, <<"msid">>}},
        {lines(H ++ M ++ [<<"a=sctp-port:65536">>]), 6, {bad_attribute, <<"sctp-port">>}},
        {lines(H ++ M ++ [<<"a=max-message-size:-1">>]), 6, {bad_attribute, <<"max-message-size">>}},
        {lines(H ++ M ++ [<<"a=ptime:0">>]), 6, {bad_attribute, <<"ptime">>}},
        {lines(H ++ M ++ [<<"a=tls-id:short">>]), 6, {bad_attribute, <<"tls-id">>}},
        {lines(H ++ M ++ [<<"a=group:BUNDLE  0">>]), 6, {bad_attribute, <<"group">>}},
        {lines(H ++ M ++ [<<"a=rtcp:9 IN IP4">>]), 6, {bad_attribute, <<"rtcp">>}},
        {lines(H ++ M ++ [<<"a=bad name:1">>]), 6, {bad_attribute, <<"bad name">>}}
    ],
    [
        {iolist_to_binary(io_lib:format("~p", [Reason])), fun() ->
            ?assertEqual({error, {Line, Reason}}, webrtc_sdp:parse(Bin))
        end}
     || {Bin, Line, Reason} <- Cases
    ].

cand(V) -> <<"a=candidate:", V/binary>>.

%% Every prefix of every sample, cut at any byte, returns a result. A cut
%% at a line boundary after the first t= line leaves a complete
%% description, which must parse.
truncation_test_() ->
    [
        {atom_to_list(Name), {timeout, 60, fun() -> truncations(Bin) end}}
     || {Name, Bin} <- ?S:all()
    ].

truncations(Bin) ->
    {T, _} = binary:match(Bin, <<"\r\nt=">>),
    Complete = [P + 1 || {P, _} <- binary:matches(Bin, <<"\n">>), P > T + 2],
    lists:foreach(
        fun(Cut) ->
            case webrtc_sdp:parse(binary:part(Bin, 0, Cut)) of
                {ok, #sdp{}} ->
                    ok;
                {error, {L, _}} when is_integer(L), L >= 1 ->
                    ?assertNot(lists:member(Cut, Complete))
            end
        end,
        lists:seq(0, byte_size(Bin))
    ).

%%--------------------------------------------------------------------
%% Encoding
%%--------------------------------------------------------------------

encode_minimal_test() ->
    Sdp = #sdp{
        origin = #sdp_origin{sess_id = 42, sess_version = 1},
        attributes = [{group, #{semantics => <<"BUNDLE">>, mids => [<<"0">>]}}],
        media = [
            #sdp_media{
                media = <<"application">>,
                proto = <<"UDP/DTLS/SCTP">>,
                fmts = [<<"webrtc-datachannel">>],
                connections = [#sdp_connection{}],
                attributes = [{mid, <<"0">>}, {sctp_port, 5000}, {setup, actpass}]
            }
        ]
    },
    Expected = lines([
        <<"v=0">>,
        <<"o=- 42 1 IN IP4 127.0.0.1">>,
        <<"s=-">>,
        <<"t=0 0">>,
        <<"a=group:BUNDLE 0">>,
        <<"m=application 9 UDP/DTLS/SCTP webrtc-datachannel">>,
        <<"c=IN IP4 0.0.0.0">>,
        <<"a=mid:0">>,
        <<"a=sctp-port:5000">>,
        <<"a=setup:actpass">>
    ]),
    ?assertEqual(Expected, webrtc_sdp:encode(Sdp)),
    ?assertEqual(Sdp, parse(Expected)).

encode_rejects_line_injection_test() ->
    ?assertError({invalid_sdp, _}, webrtc_sdp:encode(#sdp{session_name = <<"x\r\na=evil">>})),
    ?assertError({invalid_sdp, _}, webrtc_sdp:encode(#sdp{attributes = [{<<"x">>, <<"a\nb">>}]})),
    ?assertError({invalid_sdp, _}, webrtc_sdp:encode(#sdp{attributes = [{mid, <<"a b">>}]})),
    ?assertError({invalid_sdp, _}, webrtc_sdp:encode(#sdp{attributes = [{ice_pwd, <<"short">>}]})),
    ?assertError(
        {invalid_sdp, _},
        webrtc_sdp:encode(#sdp{attributes = [{fmtp, #{fmt => 96, params => [{<<"a">>, <<"1;b=2">>}]}}]})
    ),
    ?assertError({invalid_sdp, _}, webrtc_sdp:encode(#sdp{media = [#sdp_media{fmts = []}]})),
    ?assertError({invalid_sdp, _}, webrtc_sdp:encode(#sdp{attributes = [{foo, true}]})),
    ?assertError(
        {invalid_sdp, _},
        webrtc_sdp:encode(#sdp{attributes = [{fingerprint, #{hash => sha256, value => <<1, 2>>}}]})
    ).

fmtp_raw_preserved_test() ->
    Bin = lines(header() ++ [<<"m=audio 9 RTP/AVP 111">>, <<"a=fmtp:111 minptime=10; useinbandfec=1;">>]),
    Sdp = parse(Bin),
    ?assertEqual(Bin, webrtc_sdp:encode(Sdp)),
    [M] = Sdp#sdp.media,
    {ok, F} = ?M:attr(fmtp, M),
    %% changing the parameters drops the stale raw text
    M2 = ?M:put_attr(fmtp, F#{params => [{<<"minptime">>, <<"20">>}]}, M),
    Out = webrtc_sdp:encode(Sdp#sdp{media = [M2]}),
    ?assertMatch({_, _}, binary:match(Out, <<"a=fmtp:111 minptime=20\r\n">>)).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

codecs_inverse_test_() ->
    [
        {atom_to_list(Name), fun() ->
            Sdp = parse(Bin),
            lists:foreach(
                fun(M) ->
                    Codecs = ?M:codecs(M),
                    case Codecs of
                        [] ->
                            ok;
                        _ ->
                            M2 = ?M:set_codecs(M, Codecs),
                            ?assertEqual(Codecs, ?M:codecs(M2)),
                            ?assertEqual(M2, ?M:set_codecs(M2, Codecs)),
                            %% the result encodes and parses back
                            Sdp2 = Sdp#sdp{media = [M2]},
                            ?assertEqual(Sdp2, parse(webrtc_sdp:encode(Sdp2)))
                    end
                end,
                Sdp#sdp.media
            )
        end}
     || {Name, Bin} <- ?S:all()
    ].

codec_attributes_order_test() ->
    Codecs = [
        #{
            pt => 111,
            name => <<"opus">>,
            clock_rate => 48000,
            channels => 2,
            fmtp => [{<<"minptime">>, <<"10">>}, {<<"useinbandfec">>, <<"1">>}],
            rtcp_fb => [#{type => <<"transport-cc">>, param => undefined}]
        },
        #{pt => 0, name => <<"PCMU">>, clock_rate => 8000, channels => undefined, fmtp => [], rtcp_fb => []}
    ],
    M = ?M:set_codecs(#sdp_media{attributes = [{mid, <<"0">>}, {direction, sendrecv}]}, Codecs),
    ?assertEqual([<<"111">>, <<"0">>], M#sdp_media.fmts),
    Text = webrtc_sdp:encode(#sdp{media = [M]}),
    ?assertEqual(
        lines(header() ++ [
            <<"m=audio 9 UDP/TLS/RTP/SAVPF 111 0">>,
            <<"a=mid:0">>,
            <<"a=sendrecv">>,
            <<"a=rtpmap:111 opus/48000/2">>,
            <<"a=rtcp-fb:111 transport-cc">>,
            <<"a=fmtp:111 minptime=10;useinbandfec=1">>,
            <<"a=rtpmap:0 PCMU/8000">>
        ]),
        binary:replace(Text, <<"o=- 0 0 ">>, <<"o=- 1 1 ">>)
    ).

attribute_helpers_test() ->
    Sdp = parse(?S:pion_answer()),
    [A, _] = Sdp#sdp.media,
    ?assertEqual({ok, <<"0">>}, ?M:find_attr(mid, A, Sdp)),
    ?assertEqual({ok, true}, ?M:find_attr(extmap_allow_mixed, A, Sdp)),
    ?assertEqual(error, ?M:find_attr(ice_lite, A, Sdp)),
    A2 = ?M:put_attr(direction, inactive, A),
    ?assertEqual(inactive, ?M:direction(A2, Sdp)),
    ?assertEqual(length(A#sdp_media.attributes), length(A2#sdp_media.attributes)),
    A3 = ?M:delete_attrs(candidate, A2),
    ?assertEqual([], ?M:candidates(A3)),
    A4 = ?M:add_attr(<<"x-custom">>, <<"1">>, A3),
    ?assertEqual({ok, <<"1">>}, ?M:attr(<<"x-custom">>, A4)),
    NoCreds = ?M:delete_attrs(ice_pwd, A),
    ?assertEqual({error, missing_ice_credentials}, ?M:ice_credentials(NoCreds, Sdp)),
    %% session-level credentials are used when the section has none
    S2 = ?M:add_attr(ice_pwd, <<"SessionLevelPassword0123">>, Sdp),
    ?assertEqual(
        {ok, #{ufrag => <<"pQfRrAQjSHoyXvIW">>, pwd => <<"SessionLevelPassword0123">>}},
        ?M:ice_credentials(NoCreds, S2)
    ),
    ?assertEqual(error, ?M:setup(?M:delete_attrs(setup, A), Sdp)).

%% RFC 8839 §5.5: session level, 50 ms when absent.
ice_pacing_test() ->
    Sdp = parse(lines(header() ++ [<<"a=ice-pacing:100">>, <<"m=audio 9 UDP/TLS/RTP/SAVPF 111">>])),
    ?assertEqual(100, ?M:ice_pacing(Sdp)),
    ?assertEqual(50, ?M:ice_pacing(parse(lines(header() ++ [<<"m=audio 9 UDP/TLS/RTP/SAVPF 111">>])))),
    ?assertNotEqual(nomatch, binary:match(iolist_to_binary(webrtc_sdp:encode(Sdp)), <<"\r\na=ice-pacing:100\r\n">>)).

misc_attributes_test() ->
    Fp1 = webrtc_sdp_samples:fp_sha256(),
    Lower = webrtc_sdp_lex:lower(Fp1),
    Sha1 = <<"4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB">>,
    Bin = lines(
        header() ++
            [
                <<"m=video 0 UDP/TLS/RTP/SAVPF 96">>,
                <<"a=bundle-only">>,
                <<"a=ice-mismatch">>,
                <<"a=fingerprint:sha-256 ", Fp1/binary>>,
                <<"a=fingerprint:sha-1 ", Sha1/binary>>,
                <<"a=fingerprint:SHA-256 ", Lower/binary>>,
                <<"a=rtcp-fb:96 ccm tmmbr smaxpr=120">>,
                <<"a=rtcp-fb:96 trr-int 100">>,
                <<"a=identity:eyJpZHAiOnt9fQ== ext1 ext2">>,
                <<"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz">>
            ]
    ),
    Sdp = parse(Bin),
    [M] = Sdp#sdp.media,
    ?assertEqual(0, M#sdp_media.port),
    ?assertEqual({ok, true}, ?M:attr(bundle_only, M)),
    ?assertEqual({ok, true}, ?M:attr(ice_mismatch, M)),
    %% several fingerprints are kept in order; lowercase hex is accepted
    [#{hash := sha256, value := V}, #{hash := sha, value := V1}, #{hash := sha256, value := V}] =
        ?M:fingerprints(M, Sdp),
    ?assertEqual(20, byte_size(V1)),
    ?assertMatch(
        [#{type := <<"ccm">>, param := <<"tmmbr smaxpr=120">>}, #{type := <<"trr-int">>, param := <<"100">>}],
        ?M:attrs(rtcp_fb, M)
    ),
    ?assertEqual(
        {ok, #{assertion => <<"eyJpZHAiOnt9fQ==">>, extensions => [<<"ext1">>, <<"ext2">>]}},
        ?M:attr(identity, M)
    ),
    ?assertMatch({ok, <<"1 AES_CM_128_HMAC_SHA1_80 inline:", _/binary>>}, ?M:attr(<<"crypto">>, M)),
    %% the lowercase fingerprint is written back in canonical form
    ?assertEqual(
        binary:replace(Bin, <<"a=fingerprint:SHA-256 ", Lower/binary>>, <<"a=fingerprint:sha-256 ", Fp1/binary>>),
        webrtc_sdp:encode(Sdp)
    ).
