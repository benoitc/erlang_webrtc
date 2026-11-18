%% Conformance tests for webrtc_jsep (RFC 9429, RFC 3264, RFC 9143,
%% RFC 8842). Descriptions always go through encode and parse, as they
%% would through signaling.
-module(webrtc_jsep_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_sdp.hrl").

-define(M, webrtc_sdp_media).

new() ->
    new(#{}).

new(Extra) ->
    FP = {sha256, crypto:strong_rand_bytes(32)},
    webrtc_jsep:new(maps:merge(#{
        ice_ufrag => base64:encode(crypto:strong_rand_bytes(6)),
        ice_pwd => base64:encode(crypto:strong_rand_bytes(18)),
        fingerprints => [FP]
    }, Extra)).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

%% Full offer/answer between two engines.
exchange(A0, B0) ->
    {ok, Offer, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, A2} = webrtc_jsep:set_local_description(offer, Offer, A1),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), B0),
    {ok, Answer, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Answer, B2),
    {ok, A3} = webrtc_jsep:set_remote_description(answer, wire(Answer), A2),
    {A3, B3, wire(Offer), wire(Answer)}.

av_data(J0) ->
    {ok, _, J1} = webrtc_jsep:add_transceiver(audio, #{}, J0),
    {ok, _, J2} = webrtc_jsep:add_transceiver(video, #{}, J1),
    webrtc_jsep:add_data_channel(J2).

%% RFC 8445 §10: every section announces ice2. RFC 8445 §14.2, RFC 8839
%% §5.5: a Ta other than 50 ms is announced, and the default is not.
ice_options_and_pacing_test() ->
    {_, _, Offer, Answer} = exchange(av_data(new(#{ice_pacing => 20})), new()),
    [?assertEqual([<<"trickle">>, <<"ice2">>], ?M:ice_options(M, D)) || D <- [Offer, Answer], M <- D#sdp.media],
    ?assertEqual({ok, 20}, ?M:attr(ice_pacing, Offer)),
    ?assertEqual(error, ?M:attr(ice_pacing, Answer)),
    ?assertEqual(50, ?M:ice_pacing(Answer)).

%% RFC 5888 §4: a mid is unique within a description.
duplicate_mid_test() ->
    {ok, O, _} = webrtc_jsep:create_offer(#{}, av_data(new())),
    [M0, M1 | Rest] = O#sdp.media,
    Mid0 = ?M:mid(M0),
    Dup = M1#sdp_media{attributes = [case A of {mid, _} -> {mid, Mid0}; _ -> A end || A <- M1#sdp_media.attributes]},
    ?assertEqual({error, duplicate_mid},
                 webrtc_jsep:set_remote_description(offer, wire(O#sdp{media = [M0, Dup | Rest]}), new())).

basic_test() ->
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, _, B1} = webrtc_jsep:add_transceiver(video, #{}, B0),
    {A, B, Offer, Answer} = exchange(av_data(new()), B1),
    ?assertEqual(stable, webrtc_jsep:signaling_state(A)),
    ?assertEqual(stable, webrtc_jsep:signaling_state(B)),
    ?assertEqual([[<<"0">>, <<"1">>, <<"2">>]], ?M:groups(<<"BUNDLE">>, Offer)),
    ?assertEqual([[<<"0">>, <<"1">>, <<"2">>]], ?M:groups(<<"BUNDLE">>, Answer)),
    [OA | _] = Offer#sdp.media,
    [AA | _] = Answer#sdp.media,
    ?assertEqual({ok, actpass}, ?M:setup(OA, Offer)),
    %% RFC 8842 §5.3: the answerer is active, hence DTLS client.
    ?assertEqual({ok, active}, ?M:setup(AA, Answer)),
    #{dtls := #{role := RA}, media := MA, data := DA, ice := IA} = webrtc_jsep:negotiated(A),
    #{dtls := #{role := RB}, media := MB, data := DB, ice := IB} = webrtc_jsep:negotiated(B),
    ?assertEqual({server, client}, {RA, RB}),
    ?assertEqual(maps:get(local_ufrag, IA), maps:get(remote_ufrag, IB)),
    ?assertEqual(maps:get(local_ufrag, IB), maps:get(remote_ufrag, IA)),
    ?assertMatch(#{mid := <<"2">>, remote_port := 5000, remote_max_message_size := 262144}, DA),
    ?assertMatch(#{mid := <<"2">>}, DB),
    ?assertEqual([audio, video], [K || #{kind := K} <- MA]),
    ?assertEqual([audio, video], [K || #{kind := K} <- MB]),
    [#{direction := sendrecv, send_codecs := [#{name := <<"opus">>, pt := 111} | _],
       remote_ssrcs := [#{ssrc := S}]} | _] = MA,
    %% The SSRC A learns for B's audio is the one B sends with.
    [#{ssrc := SB} | _] = MB,
    ?assertEqual(SB, S),
    %% Same header extension ids on both sides.
    [#{send_extensions := EA} | _] = MA,
    [#{recv_extensions := EB} | _] = MB,
    ?assertEqual(EA, EB).

directions_test_() ->
    Cases = [
        {sendrecv, sendrecv, sendrecv, sendrecv},
        {sendonly, sendrecv, recvonly, sendonly},
        {recvonly, sendrecv, sendonly, recvonly},
        {sendrecv, recvonly, recvonly, sendonly},
        {inactive, sendrecv, inactive, inactive},
        {sendonly, sendonly, inactive, inactive}
    ],
    [?_test(begin
         {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{direction => OfferDir}, new()),
         {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{direction => AnsDesired}, new()),
         {A, B, _, Answer} = exchange(A0, B0),
         [M] = Answer#sdp.media,
         ?assertEqual(AnsDir, ?M:direction(M, Answer)),
         [#{direction := DB}] = maps:get(media, webrtc_jsep:negotiated(B)),
         ?assertEqual(AnsDir, DB),
         [#{direction := DA}] = maps:get(media, webrtc_jsep:negotiated(A)),
         ?assertEqual(OffererDir, DA)
     end)
     || {OfferDir, AnsDesired, AnsDir, OffererDir} <- Cases].

answer_creates_recvonly_transceiver_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(video, #{}, new()),
    {_, B, _, Answer} = exchange(A0, new()),
    [M] = Answer#sdp.media,
    ?assertEqual(recvonly, ?M:direction(M, Answer)),
    ?assertMatch([#{kind := video, direction := recvonly}], webrtc_jsep:transceivers(B)).

codec_intersection_test() ->
    Opus = hd(webrtc_jsep_caps:default_codecs(audio)),
    [Pcmu] = [C || #{name := <<"PCMU">>} = C <- webrtc_jsep_caps:default_codecs(audio)],
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    B0 = new(#{codecs => #{audio => [Pcmu]}}),
    {A, _, _, Answer} = exchange(A0, B0),
    [M] = Answer#sdp.media,
    ?assertEqual([0], ?M:payload_types(M)),
    [#{send_codecs := [#{name := <<"PCMU">>}]}] = maps:get(media, webrtc_jsep:negotiated(A)),
    _ = Opus.

no_common_codec_rejects_section_test() ->
    [Pcmu] = [C || #{name := <<"PCMU">>} = C <- webrtc_jsep_caps:default_codecs(audio)],
    Opus = hd(webrtc_jsep_caps:default_codecs(audio)),
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new(#{codecs => #{audio => [Opus]}})),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    B0 = new(#{codecs => #{audio => [Pcmu]}}),
    {_, _, _, Answer} = exchange(A1, B0),
    [MA, MV] = Answer#sdp.media,
    ?assertEqual(0, MA#sdp_media.port),
    ?assertEqual(9, MV#sdp_media.port),
    ?assertEqual([[<<"1">>]], ?M:groups(<<"BUNDLE">>, Answer)).

rtx_follows_primary_test() ->
    [Vp8, Rtx | _] = webrtc_jsep_caps:default_codecs(video),
    {ok, _, A0} = webrtc_jsep:add_transceiver(video, #{}, new()),
    {ok, _, B0} = webrtc_jsep:add_transceiver(video, #{}, new(#{codecs => #{video => [Vp8, Rtx]}})),
    {_, _, _, Answer} = exchange(A0, B0),
    [M] = Answer#sdp.media,
    ?assertEqual([96, 97], ?M:payload_types(M)),
    [#{ssrcs := [_, _]}] = ?M:attrs(ssrc_group, M).

renegotiation_keeps_order_and_role_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {A1, B1, _, _} = exchange(A0, new()),
    {ok, _, A2} = webrtc_jsep:add_transceiver(video, #{}, A1),
    A3 = webrtc_jsep:add_data_channel(A2),
    {A4, B2, Offer, Answer} = exchange(A3, B1),
    ?assertEqual([<<"0">>, <<"1">>, <<"2">>], [?M:mid(M) || M <- Offer#sdp.media]),
    ?assertEqual([<<"audio">>, <<"video">>, <<"application">>], [M#sdp_media.media || M <- Offer#sdp.media]),
    %% RFC 8842 §5.5: the established DTLS role is kept (A is server).
    ?assertEqual({ok, passive}, ?M:setup(hd(Offer#sdp.media), Offer)),
    ?assertEqual({ok, active}, ?M:setup(hd(Answer#sdp.media), Answer)),
    ?assertEqual(server, maps:get(role, maps:get(dtls, webrtc_jsep:negotiated(A4)))),
    ?assertEqual(client, maps:get(role, maps:get(dtls, webrtc_jsep:negotiated(B2)))),
    %% The answerer can now offer and keeps its client role.
    {B3, _A5, Offer2, _} = exchange(B2, A4),
    ?assertEqual({ok, active}, ?M:setup(hd(Offer2#sdp.media), Offer2)),
    ?assertEqual(client, maps:get(role, maps:get(dtls, webrtc_jsep:negotiated(B3)))).

stop_transceiver_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, VId, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {A2, B1, _, _} = exchange(A1, new()),
    {ok, A3} = webrtc_jsep:stop_transceiver(VId, A2),
    {A4, _, Offer, Answer} = exchange(A3, B1),
    [_, OV] = Offer#sdp.media,
    [_, AV] = Answer#sdp.media,
    ?assertEqual({0, 0}, {OV#sdp_media.port, AV#sdp_media.port}),
    ?assertEqual([[<<"0">>]], ?M:groups(<<"BUNDLE">>, Answer)),
    ?assertEqual([audio], [K || #{kind := K} <- maps:get(media, webrtc_jsep:negotiated(A4))]).

ice_restart_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {A1, B1, _, _} = exchange(A0, new()),
    A2 = webrtc_jsep:restart_ice(<<"newufrag">>, <<"newpasswordnewpassword">>, A1),
    {_, B2, Offer, _} = exchange(A2, B1),
    ?assertEqual({ok, #{ufrag => <<"newufrag">>, pwd => <<"newpasswordnewpassword">>}},
                 ?M:ice_credentials(hd(Offer#sdp.media), Offer)),
    ?assertEqual(<<"newufrag">>, maps:get(remote_ufrag, maps:get(ice, webrtc_jsep:negotiated(B2)))).

invalid_states_test() ->
    J = new(),
    {ok, _, J1} = webrtc_jsep:add_transceiver(audio, #{}, J),
    {ok, Offer, J2} = webrtc_jsep:create_offer(#{}, J1),
    ?assertEqual({error, invalid_state}, webrtc_jsep:set_remote_description(answer, Offer, J2)),
    ?assertEqual({error, invalid_state}, webrtc_jsep:create_answer(#{}, J2)),
    ?assertEqual({error, invalid_state}, webrtc_jsep:set_local_description(answer, Offer, J2)),
    ?assertEqual({error, invalid_state}, webrtc_jsep:set_local_description(rollback, undefined, J2)),
    {ok, J3} = webrtc_jsep:set_local_description(offer, Offer, J2),
    ?assertEqual(have_local_offer, webrtc_jsep:signaling_state(J3)),
    ?assertEqual({error, invalid_state}, webrtc_jsep:set_remote_description(offer, Offer, J3)),
    ?assertEqual({error, closed}, webrtc_jsep:set_local_description(offer, Offer, webrtc_jsep:close(J3))).

%% Glare (RFC 9429 §4.1.10.2): roll back the local offer, accept theirs.
glare_rollback_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, OA, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, A2} = webrtc_jsep:set_local_description(offer, OA, A1),
    {ok, OB, B1} = webrtc_jsep:create_offer(#{}, B0),
    {ok, B2} = webrtc_jsep:set_local_description(offer, OB, B1),
    ?assertEqual({error, invalid_state}, webrtc_jsep:set_remote_description(offer, wire(OB), A2)),
    {ok, A3} = webrtc_jsep:set_local_description(rollback, undefined, A2),
    ?assertEqual(stable, webrtc_jsep:signaling_state(A3)),
    {ok, A4} = webrtc_jsep:set_remote_description(offer, wire(OB), A3),
    {ok, Ans, A5} = webrtc_jsep:create_answer(#{}, A4),
    {ok, A6} = webrtc_jsep:set_local_description(answer, Ans, A5),
    {ok, B3} = webrtc_jsep:set_remote_description(answer, wire(Ans), B2),
    ?assertEqual(stable, webrtc_jsep:signaling_state(B3)),
    %% A's own audio transceiver was associated with B's audio m-line.
    ?assertMatch([#{kind := audio, direction := sendrecv, mid := <<"0">>}], webrtc_jsep:transceivers(A6)).

remote_rollback_removes_created_transceivers_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(video, #{}, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A0),
    B0 = new(),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), B0),
    ?assertMatch([_], webrtc_jsep:transceivers(B1)),
    {ok, B2} = webrtc_jsep:set_remote_description(rollback, undefined, B1),
    ?assertEqual([], webrtc_jsep:transceivers(B2)),
    ?assertEqual(stable, webrtc_jsep:signaling_state(B2)).

pranswer_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, Offer, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, A2} = webrtc_jsep:set_local_description(offer, Offer, A1),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), new()),
    {ok, Pr, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(pranswer, Pr, B2),
    ?assertEqual(have_local_pranswer, webrtc_jsep:signaling_state(B3)),
    {ok, A3} = webrtc_jsep:set_remote_description(pranswer, wire(Pr), A2),
    ?assertEqual(have_remote_pranswer, webrtc_jsep:signaling_state(A3)),
    ?assertMatch(#{media := [_]}, webrtc_jsep:negotiated(A3)),
    {ok, Ans, B4} = webrtc_jsep:create_answer(#{}, B3),
    {ok, B5} = webrtc_jsep:set_local_description(answer, Ans, B4),
    {ok, A4} = webrtc_jsep:set_remote_description(answer, wire(Ans), A3),
    ?assertEqual({stable, stable}, {webrtc_jsep:signaling_state(A4), webrtc_jsep:signaling_state(B5)}).

%% RFC 9429 §5.7: provisional answers can be rolled back, through either
%% setter, and the previous negotiation applies again.
pranswer_rollback_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {A1, B1, _, _} = exchange(A0, new()),
    Before = {webrtc_jsep:negotiated(A1), webrtc_jsep:negotiated(B1)},
    {ok, _, A2} = webrtc_jsep:add_transceiver(video, #{}, A1),
    {ok, Offer, A3} = webrtc_jsep:create_offer(#{}, A2),
    {ok, A4} = webrtc_jsep:set_local_description(offer, Offer, A3),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, wire(Offer), B1),
    {ok, Pr, B3} = webrtc_jsep:create_answer(#{}, B2),
    {ok, B4} = webrtc_jsep:set_local_description(pranswer, Pr, B3),
    {ok, A5} = webrtc_jsep:set_remote_description(pranswer, wire(Pr), A4),
    ?assertMatch(#{media := [_, _]}, webrtc_jsep:negotiated(A5)),
    ?assertMatch([_, _], webrtc_jsep:transceivers(B4)),
    %% Answerer: rollback from have-local-pranswer, through either setter.
    lists:foreach(
        fun(Set) ->
            {ok, B5} = webrtc_jsep:Set(rollback, undefined, B4),
            ?assertEqual(stable, webrtc_jsep:signaling_state(B5)),
            ?assertEqual(element(2, Before), webrtc_jsep:negotiated(B5)),
            ?assertMatch([_], webrtc_jsep:transceivers(B5)),
            ?assertEqual(webrtc_jsep:remote_description(B1), webrtc_jsep:remote_description(B5))
        end,
        [set_local_description, set_remote_description]
    ),
    %% Offerer: rollback from have-remote-pranswer.
    lists:foreach(
        fun(Set) ->
            {ok, A6} = webrtc_jsep:Set(rollback, undefined, A5),
            ?assertEqual(stable, webrtc_jsep:signaling_state(A6)),
            ?assertEqual(element(1, Before), webrtc_jsep:negotiated(A6)),
            ?assertEqual(webrtc_jsep:local_description(A1), webrtc_jsep:local_description(A6)),
            ?assertEqual(webrtc_jsep:remote_description(A1), webrtc_jsep:remote_description(A6))
        end,
        [set_local_description, set_remote_description]
    ),
    %% No rollback from stable.
    ?assertEqual({error, invalid_state}, webrtc_jsep:set_remote_description(rollback, undefined, A1)),
    ?assertEqual({error, invalid_state}, webrtc_jsep:set_local_description(rollback, undefined, A1)).

%% A rolled back ICE restart leaves the ICE credentials as they were.
ice_restart_rollback_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {A1, B1, _, Answer} = exchange(A0, new()),
    A2 = webrtc_jsep:restart_ice(<<"newufrag">>, <<"newpasswordnewpassword">>, A1),
    {ok, Offer, A3} = webrtc_jsep:create_offer(#{}, A2),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, wire(Offer), B1),
    B3 = webrtc_jsep:restart_ice(<<"bnewufrg">>, <<"bnewpasswordbnewpassword">>, B2),
    {ok, B4} = webrtc_jsep:set_remote_description(rollback, undefined, B3),
    #{ice := Ice} = webrtc_jsep:negotiated(B4),
    ?assertNotEqual(<<"newufrag">>, maps:get(remote_ufrag, Ice)),
    {ok, Offer2, _} = webrtc_jsep:create_offer(#{}, B4),
    {ok, Old} = ?M:ice_credentials(hd(Answer#sdp.media), Answer),
    ?assertEqual({ok, Old}, ?M:ice_credentials(hd(Offer2#sdp.media), Offer2)),
    %% The offerer's own restart survives a rollback of its offer: its
    %% agent already uses the new credentials.
    {ok, A4} = webrtc_jsep:set_local_description(offer, Offer, A3),
    {ok, A5} = webrtc_jsep:set_local_description(rollback, undefined, A4),
    {ok, Offer3, _} = webrtc_jsep:create_offer(#{}, A5),
    ?assertMatch({ok, #{ufrag := <<"newufrag">>}}, ?M:ice_credentials(hd(Offer3#sdp.media), Offer3)).

%% RFC 9429 §5.8.3, RFC 3264 §6: answers that do not match the offer
%% are refused. Each case edits a real answer.
tamper(Sdp, Re, Rep) ->
    {ok, P} = webrtc_sdp:parse(re:replace(webrtc_sdp:encode(Sdp), Re, Rep, [{return, binary}])),
    P.

answer_for(OfferOpts) ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, OfferOpts, new()),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, Offer, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, Offer, A2),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), new()),
    {ok, Answer, _} = webrtc_jsep:create_answer(#{}, B1),
    {A3, Answer}.

answer_validation_test_() ->
    {A, Answer} = answer_for(#{}),
    {Ar, AnswerR} = answer_for(#{direction => sendonly}),
    Refused = fun(J, Sdp) -> webrtc_jsep:set_remote_description(answer, Sdp, J) end,
    [
        ?_assertMatch({ok, _}, Refused(A, wire(Answer))),
        ?_assertEqual({error, mline_count_mismatch}, Refused(A, tamper(Answer, <<"m=video.*">>, <<"">>, [dotall]))),
        ?_assertEqual({error, {media_type_mismatch, <<"1">>}},
                      Refused(A, tamper(Answer, <<"m=video 9 UDP/TLS/RTP/SAVPF 96">>, <<"m=audio 9 UDP/TLS/RTP/SAVPF 96">>))),
        ?_assertEqual({error, {proto_mismatch, <<"0">>}},
                      Refused(A, tamper(Answer, <<"m=audio 9 UDP/TLS/RTP/SAVPF">>, <<"m=audio 9 RTP/SAVPF">>))),
        ?_assertEqual({error, {bad_setup, <<"0">>}}, Refused(A, tamper(Answer, <<"a=setup:active">>, <<"a=setup:actpass">>))),
        ?_assertEqual({error, {direction_mismatch, <<"0">>}},
                      Refused(Ar, tamper(AnswerR, <<"a=recvonly">>, <<"a=sendonly">>))),
        ?_assertEqual({error, {payload_type_mismatch, <<"0">>}},
                      Refused(A, tamper(Answer, <<"m=audio 9 UDP/TLS/RTP/SAVPF 111">>, <<"m=audio 9 UDP/TLS/RTP/SAVPF 111 35">>))),
        ?_assertEqual({error, {payload_type_mismatch, <<"0">>}},
                      Refused(A, tamper(Answer, <<"a=rtpmap:111 opus/48000/2">>, <<"a=rtpmap:111 ISAC/16000">>)))
    ].

tamper(Sdp, Re, Rep, Opts) ->
    {ok, P} = webrtc_sdp:parse(re:replace(webrtc_sdp:encode(Sdp), Re, Rep, [{return, binary} | Opts])),
    P.

%% RFC 8842 §5.5: the answer to a re-offer keeps the DTLS role.
answer_keeps_dtls_role_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {A1, B1, _, _} = exchange(A0, new()),
    {ok, Offer, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, Offer, A2),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, wire(Offer), B1),
    {ok, Answer, _} = webrtc_jsep:create_answer(#{}, B2),
    ?assertMatch({ok, _}, webrtc_jsep:set_remote_description(answer, wire(Answer), A3)),
    ?assertEqual({error, {bad_setup, <<"0">>}},
                 webrtc_jsep:set_remote_description(answer, tamper(Answer, <<"a=setup:active">>, <<"a=setup:passive">>), A3)).

%% RFC 8285 §6: only header extensions present in both descriptions are
%% used for sending.
answer_extensions_filtered_test() ->
    {A, Answer} = answer_for(#{}),
    Extra = tamper(Answer, <<"a=extmap:1 ">>, <<"a=extmap:9 urn:example:not-offered\r\na=extmap:1 ">>),
    {ok, A1} = webrtc_jsep:set_remote_description(answer, Extra, A),
    #{media := [#{send_extensions := Exts} | _]} = webrtc_jsep:negotiated(A1),
    ?assertNot(maps:is_key(<<"urn:example:not-offered">>, Exts)),
    ?assert(maps:is_key(<<"urn:ietf:params:rtp-hdrext:ssrc-audio-level">>, Exts)).

%% RFC 9429 §5.8.3: a re-offer keeps the existing m= sections in place.
reoffer_validation_test_() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {A2, B, _, _} = exchange(A1, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A2),
    Set = fun(Sdp) -> webrtc_jsep:set_remote_description(offer, Sdp, B) end,
    [
        ?_assertMatch({ok, _}, Set(wire(Offer))),
        ?_assertEqual({error, mline_removed}, Set(tamper(Offer, <<"m=video.*">>, <<"">>, [dotall]))),
        ?_assertEqual({error, {mid_changed, <<"7">>}},
                      Set(tamper(tamper(Offer, <<"a=mid:1">>, <<"a=mid:7">>), <<"BUNDLE 0 1">>, <<"BUNDLE 0 7">>))),
        ?_assertEqual({error, {media_type_changed, <<"1">>}},
                      Set(tamper(Offer, <<"m=video 9 UDP/TLS/RTP/SAVPF 96">>, <<"m=audio 9 UDP/TLS/RTP/SAVPF 96">>)))
    ].

validation_test_() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A0),
    Strip = fun(Key) ->
        Offer#sdp{media = [M#sdp_media{attributes = [A || {K, _} = A <- M#sdp_media.attributes, K =/= Key]}
                           || M <- Offer#sdp.media]}
    end,
    [
        ?_assertMatch({error, {missing_fingerprint, _}},
                      webrtc_jsep:set_remote_description(offer, Strip(fingerprint), new())),
        ?_assertMatch({error, {missing_rtcp_mux, _}},
                      webrtc_jsep:set_remote_description(offer, Strip(rtcp_mux), new())),
        ?_assertMatch({error, {missing_setup, _}},
                      webrtc_jsep:set_remote_description(offer, Strip(setup), new())),
        ?_assertMatch({error, {missing_ice_credentials, _}},
                      webrtc_jsep:set_remote_description(offer, Strip(ice_ufrag), new())),
        ?_assertMatch({error, missing_mid},
                      webrtc_jsep:set_remote_description(offer, Strip(mid), new())),
        ?_assertEqual({error, no_media},
                      webrtc_jsep:set_remote_description(offer, Offer#sdp{media = []}, new()))
    ].

%% RFC 9143 §7.3: an offer without BUNDLE gives every section its own
%% transport: distinct ICE credentials in the answer, no a=group, one
%% transport per section in the negotiated parameters.
unbundled_offer_test() ->
    A1 = av_data(new(#{bundle => false})),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A1),
    NoBundle = wire(Offer),
    ?assertEqual([], ?M:groups(<<"BUNDLE">>, NoBundle)),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, NoBundle, new()),
    {ok, Answer, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Answer, B2),
    A = wire(Answer),
    ?assertEqual([], ?M:groups(<<"BUNDLE">>, A)),
    Ufrags = [maps:get(ufrag, C) || M <- A#sdp.media, {ok, C} <- [?M:ice_credentials(M, A)]],
    ?assertEqual(3, length(lists:usort(Ufrags))),
    #{transports := Ts, media := Media, data := Data} = webrtc_jsep:negotiated(B3),
    ?assertEqual([[<<"0">>], [<<"1">>], [<<"2">>]], [Ms || #{mids := Ms} <- Ts]),
    ?assertEqual([<<"0">>, <<"1">>], [T || #{transport := T} <- Media]),
    ?assertMatch(#{transport := <<"2">>}, Data),
    %% Each transport has the remote credentials of its own section.
    ?assertEqual(3, length(lists:usort([maps:get(remote_ufrag, I) || #{ice := I} <- Ts]))),
    ?assertEqual(lists:usort(Ufrags), lists:usort([maps:get(local_ufrag, I) || #{ice := I} <- Ts])).

%% Two BUNDLE groups: one transport each, mirrored in the answer.
two_bundle_groups_test() ->
    A1 = av_data(new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A1),
    Attrs = [A || {K, _} = A <- Offer#sdp.attributes, K =/= group] ++
        [{group, #{semantics => <<"BUNDLE">>, mids => [<<"0">>, <<"2">>]}},
         {group, #{semantics => <<"BUNDLE">>, mids => [<<"1">>]}}],
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer#sdp{attributes = Attrs}), new()),
    {ok, Answer, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Answer, B2),
    ?assertEqual([[<<"0">>, <<"2">>], [<<"1">>]], ?M:groups(<<"BUNDLE">>, wire(Answer))),
    #{transports := Ts} = webrtc_jsep:negotiated(B3),
    ?assertEqual([{<<"0">>, [<<"0">>, <<"2">>]}, {<<"1">>, [<<"1">>]}], [{K, Ms} || #{key := K, mids := Ms} <- Ts]),
    %% A mid in two groups is refused.
    Bad = [A || {K, _} = A <- Offer#sdp.attributes, K =/= group] ++
        [{group, #{semantics => <<"BUNDLE">>, mids => [<<"0">>, <<"1">>]}},
         {group, #{semantics => <<"BUNDLE">>, mids => [<<"1">>, <<"2">>]}}],
    ?assertEqual({error, mid_in_two_bundle_groups},
                 webrtc_jsep:set_remote_description(offer, wire(Offer#sdp{attributes = Bad}), new())).

%% `bundle => false': our offer gives every section its own transport,
%% and the answerer keeps them apart.
unbundled_local_offer_test() ->
    A1 = av_data(new(#{bundle => false})),
    {A2, B2, Offer, Answer} = exchange(A1, new()),
    ?assertEqual([], ?M:groups(<<"BUNDLE">>, Offer)),
    ?assertEqual([], ?M:groups(<<"BUNDLE">>, Answer)),
    ?assertEqual(3, length(webrtc_jsep:transports(A2))),
    ?assertEqual(3, length(webrtc_jsep:transports(B2))),
    #{transports := TA} = webrtc_jsep:negotiated(A2),
    #{transports := TB} = webrtc_jsep:negotiated(B2),
    %% Each side's local credentials are the other's remote ones, per transport.
    ?assertEqual(lists:sort([{maps:get(local_ufrag, I), maps:get(remote_ufrag, I)} || #{ice := I} <- TA]),
                 lists:sort([{maps:get(remote_ufrag, I), maps:get(local_ufrag, I)} || #{ice := I} <- TB])),
    %% Credentials stay the same across renegotiation.
    {A3, _, Offer2, _} = exchange(A2, B2),
    ?assertEqual([?M:ice_credentials(M, Offer) || M <- Offer#sdp.media], [?M:ice_credentials(M, Offer2) || M <- Offer2#sdp.media]),
    ?assertEqual(webrtc_jsep:transports(A2), webrtc_jsep:transports(A3)).

%% RFC 9143 §7.3: an answer that bundles sections the offer did not
%% bundle is refused.
answer_adds_bundle_refused_test() ->
    {ok, Offer, A1} = webrtc_jsep:create_offer(#{}, av_data(new(#{bundle => false}))),
    {ok, A2} = webrtc_jsep:set_local_description(offer, Offer, A1),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), new()),
    {ok, Answer, _} = webrtc_jsep:create_answer(#{}, B1),
    Bin = binary:replace(webrtc_sdp:encode(Answer), <<"t=0 0\r\n">>, <<"t=0 0\r\na=group:BUNDLE 0 1 2\r\n">>),
    {ok, Bundled} = webrtc_sdp:parse(Bin),
    ?assertEqual({error, bundle_not_offered}, webrtc_jsep:set_remote_description(answer, Bundled, A2)).

%% Answering real browser offers.
browser_offer_test_() ->
    [?_test(answer_sample(Name)) || Name <- [chrome_offer, firefox_offer, safari_offer]].

answer_sample(Name) ->
    {ok, Offer} = webrtc_sdp:parse(webrtc_sdp_samples:Name()),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, Offer, new()),
    {ok, Answer, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Answer, B2),
    A = wire(Answer),
    ?assertEqual([?M:mid(M) || M <- Offer#sdp.media], [?M:mid(M) || M <- A#sdp.media]),
    #{media := Media, dtls := #{role := client, remote_fingerprints := [_ | _]}} = webrtc_jsep:negotiated(B3),
    ?assert(length(Media) >= 1),
    [?assertNotEqual([], maps:get(send_codecs, M)) || M <- Media],
    %% Answer payload types are a subset of the offered ones.
    lists:foreach(
        fun({OM, AM}) ->
            ?assertEqual([], ?M:payload_types(AM) -- ?M:payload_types(OM))
        end,
        lists:zip(Offer#sdp.media, A#sdp.media)
    ).

%% RFC 9143 §6, RFC 9429 §5.2.1: a max-bundle offerer (Firefox) gives the
%% non-tagged bundled sections port 0 and a=bundle-only. They are part of
%% the BUNDLE group and must be accepted, not rejected.
max_bundle_offer(BundleOnly) ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A1),
    [MA, MV] = Offer#sdp.media,
    Extra = [{bundle_only, true} || BundleOnly],
    wire(Offer#sdp{media = [MA, MV#sdp_media{port = 0, attributes = MV#sdp_media.attributes ++ Extra}]}).

bundle_only_section_accepted_test() ->
    Offer = max_bundle_offer(true),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, _, B1} = webrtc_jsep:add_transceiver(video, #{}, B0),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, Offer, B1),
    {ok, Answer, B3} = webrtc_jsep:create_answer(#{}, B2),
    {ok, B4} = webrtc_jsep:set_local_description(answer, Answer, B3),
    [_, AV] = (wire(Answer))#sdp.media,
    ?assertEqual(9, AV#sdp_media.port),
    %% bundle-only is never used in an answer (RFC 9143 §7.3).
    ?assertEqual(error, ?M:attr(bundle_only, AV)),
    ?assertEqual(sendrecv, ?M:direction(AV, wire(Answer))),
    ?assertEqual([[<<"0">>, <<"1">>]], ?M:groups(<<"BUNDLE">>, wire(Answer))),
    ?assertEqual([audio, video], [K || #{kind := K} <- maps:get(media, webrtc_jsep:negotiated(B4))]),
    %% The application still sees the description it set.
    #sdp{media = [_, RV]} = webrtc_jsep:remote_description(B4),
    ?assertEqual(0, RV#sdp_media.port).

port_zero_without_bundle_only_rejected_test() ->
    Offer = max_bundle_offer(false),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, Offer, B0),
    {ok, Answer, _} = webrtc_jsep:create_answer(#{}, B1),
    [_, AV] = (wire(Answer))#sdp.media,
    ?assertEqual(0, AV#sdp_media.port).

%% RFC 8842 §5, RFC 9429 §5.8.3: a re-offer with other fingerprints is
%% only acceptable as part of an ICE restart, and then starts a new DTLS
%% association (role negotiated again, new tls-id).
other_fingerprint(Sdp) ->
    FP = #{hash => sha256, value => crypto:strong_rand_bytes(32)},
    Sdp#sdp{media = [M#sdp_media{attributes = [case A of {fingerprint, _} -> {fingerprint, FP}; _ -> A end
                                               || A <- M#sdp_media.attributes]}
                     || M <- Sdp#sdp.media]}.

tls_id_offered_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A0),
    [M] = (wire(Offer))#sdp.media,
    ?assertMatch({ok, <<_:24/binary>>}, ?M:attr(tls_id, M)).

fingerprint_change_without_ice_restart_refused_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {A1, B1, _, _} = exchange(A0, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A1),
    ?assertEqual({error, dtls_identity_changed},
                 webrtc_jsep:set_remote_description(offer, other_fingerprint(wire(Offer)), B1)).

fingerprint_change_with_ice_restart_new_association_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {A1, B1, _, Answer1} = exchange(A0, new()),
    A2 = webrtc_jsep:restart_ice(<<"newufrag">>, <<"newpasswordnewpassword">>, A1),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A2),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, other_fingerprint(wire(Offer)), B1),
    {ok, Answer2, B3} = webrtc_jsep:create_answer(#{}, B2),
    {ok, B4} = webrtc_jsep:set_local_description(answer, Answer2, B3),
    Tls = fun(S) -> [M | _] = (wire(S))#sdp.media, ?M:attr(tls_id, M) end,
    ?assertNotEqual(Tls(Answer1), Tls(Answer2)),
    #{dtls := #{role := Role, remote_fingerprints := [{sha256, _}]}} = webrtc_jsep:negotiated(B4),
    ?assertNotEqual(undefined, Role).

identity_unchanged_renegotiation_ok_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {A1, B1, _, _} = exchange(A0, new()),
    {ok, _, A2} = webrtc_jsep:add_transceiver(video, #{}, A1),
    {_, B2, _, _} = exchange(A2, B1),
    ?assertEqual(stable, webrtc_jsep:signaling_state(B2)).

%%--------------------------------------------------------------------
%% RFC 6904 encrypted header extensions
%%--------------------------------------------------------------------

-define(AL, <<"urn:ietf:params:rtp-hdrext:ssrc-audio-level">>).
-define(ENC, <<"urn:ietf:params:rtp-hdrext:encrypt">>).

audio(J0) ->
    {ok, _, J1} = webrtc_jsep:add_transceiver(audio, #{}, J0),
    J1.

audio_media(J) ->
    [M] = maps:get(media, webrtc_jsep:negotiated(J)),
    M.

extmaps(Sdp) -> ?M:attrs(extmap, hd(Sdp#sdp.media)).

%% RFC 6904 §4.1, RFC 8834 §5.2.2: with `offer' the audio level is
%% offered in both forms and answered encrypted.
encrypted_audio_level_test() ->
    {A, B, Offer, Answer} = exchange(audio(new(#{encrypt_header_extensions => offer})), audio(new())),
    ?assert(lists:member(#{id => 1, direction => undefined, uri => ?AL, attributes => undefined}, extmaps(Offer))),
    ?assert(lists:member(#{id => 5, direction => undefined, uri => ?ENC, attributes => ?AL}, extmaps(Answer))),
    ?assertEqual([], [E || #{uri := ?AL} = E <- extmaps(Answer)]),
    [?assertMatch(#{send_extensions := #{?AL := 5}, send_encrypted := [5], recv_encrypted := [5]}, audio_media(J))
     || J <- [A, B]].

%% A peer that does not know the encrypt URI answers with the clear
%% form; one that turned encryption off too.
clear_fallback_test() ->
    {A, _, _, Answer} = exchange(audio(new(#{encrypt_header_extensions => offer})),
                                 audio(new(#{encrypt_header_extensions => false}))),
    ?assert(lists:member(#{id => 1, direction => undefined, uri => ?AL, attributes => undefined}, extmaps(Answer))),
    ?assertMatch(#{send_extensions := #{?AL := 1}, send_encrypted := [], recv_encrypted := []}, audio_media(A)),
    %% By default (accept) and with false, our offers have no encrypt
    %% line.
    [begin
         {_, _, Offer2, _} = exchange(audio(new(O)), audio(new())),
         ?assertEqual([], [E || #{uri := ?ENC} = E <- extmaps(Offer2)])
     end || O <- [#{}, #{encrypt_header_extensions => false}]].

%% An offer with the clear form only is answered in clear.
plain_offer_test() ->
    {A, B, _, Answer} = exchange(audio(new(#{extensions => #{audio => [#{id => 1, uri => ?AL}]}})), audio(new())),
    ?assertEqual([1], [Id || #{id := Id, uri := ?AL} <- extmaps(Answer)]),
    [?assertMatch(#{send_encrypted := [], recv_encrypted := []}, audio_media(J)) || J <- [A, B]].

%% An answer with both forms of one extension is refused.
both_forms_refused_test() ->
    {ok, Offer, A1} = webrtc_jsep:create_offer(#{}, audio(new(#{encrypt_header_extensions => offer}))),
    {ok, A2} = webrtc_jsep:set_local_description(offer, Offer, A1),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), audio(new())),
    {ok, Answer, _} = webrtc_jsep:create_answer(#{}, B1),
    Bin = webrtc_sdp:encode(Answer),
    Both = binary:replace(Bin, <<"a=extmap:5 ">>, <<"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\na=extmap:5 ">>),
    {ok, Bad} = webrtc_sdp:parse(Both),
    ?assertMatch({error, {both_extension_forms, _}}, webrtc_jsep:set_remote_description(answer, Bad, A2)).

%%====================================================================
%% RFC 5761 §4, RFC 8858, RFC 3550 §8.2
%%====================================================================

sdp_text(Sdp) -> webrtc_sdp:encode(Sdp).

reparse(Bin) -> {ok, P} = webrtc_sdp:parse(Bin), P.

%% An offer with a codec on payload type 70: never answered, we mux.
mux_payload_types_not_answered_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A0),
    Bin = binary:replace(sdp_text(Offer), <<"a=rtpmap:0 PCMU/8000">>, <<"a=rtpmap:70 PCMU/8000">>),
    Bin1 = re:replace(Bin, <<"(m=audio [0-9]+ [A-Z/]+ [0-9 ]*?)\\b0\\b">>, <<"\\g{1}70">>, [{return, binary}]),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, reparse(Bin1), B0),
    {ok, Answer, _} = webrtc_jsep:create_answer(#{}, B1),
    ?assertEqual(nomatch, binary:match(sdp_text(Answer), <<"a=rtpmap:70">>)).

%% Our offer (from a JSEP state given such a codec; peer connections
%% refuse it) carries payload type 70: an answer using it is refused.
mux_payload_type_answer_refused_test() ->
    [Opus | Rest] = webrtc_jsep_caps:default_codecs(audio),
    Codecs = #{audio => [Opus#{pt := 70} | Rest], video => webrtc_jsep_caps:default_codecs(video)},
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new(#{codecs => Codecs})),
    {ok, Offer, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, A2} = webrtc_jsep:set_local_description(offer, Offer, A1),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, new(#{codecs => Codecs})),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), B0),
    %% Answering ourselves drops it, so the peer's answer is written.
    {ok, Answer, _} = webrtc_jsep:create_answer(#{}, B1),
    ?assertEqual(nomatch, binary:match(sdp_text(Answer), <<"a=rtpmap:70 ">>)),
    Bad = re:replace(sdp_text(Answer), <<"(m=audio [0-9]+ [A-Z/]+ )">>, <<"\\g{1}70 ">>, [{return, binary}]),
    Bad1 = binary:replace(Bad, <<"a=rtcp-mux\r\n">>, <<"a=rtcp-mux\r\na=rtpmap:70 opus/48000/2\r\n">>),
    ?assertMatch({error, {payload_type_conflicts_with_rtcp, _}},
                 webrtc_jsep:set_remote_description(answer, reparse(Bad1), A2)).

%% rtcp-mux-only only with rtcp_mux_policy => require.
rtcp_mux_only_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, O1, _} = webrtc_jsep:create_offer(#{}, A0),
    ?assertEqual(nomatch, binary:match(sdp_text(O1), <<"a=rtcp-mux-only">>)),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, new(#{rtcp_mux_policy => require})),
    {ok, O2, _} = webrtc_jsep:create_offer(#{}, B0),
    ?assertNotEqual(nomatch, binary:match(sdp_text(O2), <<"a=rtcp-mux-only">>)),
    %% A peer offering rtcp-mux-only gets rtcp-mux in the answer.
    {ok, _, C0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, C1} = webrtc_jsep:set_remote_description(offer, wire(O2), C0),
    {ok, Ans, _} = webrtc_jsep:create_answer(#{}, C1),
    ?assertNotEqual(nomatch, binary:match(sdp_text(Ans), <<"a=rtcp-mux\r\n">>)).

%% The remote offer announces one of our SSRCs: ours changes before
%% the answer.
ssrc_clash_avoided_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A0),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, Probe, _} = webrtc_jsep:create_offer(#{}, B0),
    {match, [Ours]} = re:run(sdp_text(Probe), <<"a=ssrc:([0-9]+) cname">>, [{capture, all_but_first, binary}]),
    {match, [Theirs]} = re:run(sdp_text(Offer), <<"a=ssrc:([0-9]+) cname">>, [{capture, all_but_first, binary}]),
    Clash = binary:replace(sdp_text(Offer), Theirs, Ours, [global]),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, reparse(Clash), B0),
    {ok, Answer, _} = webrtc_jsep:create_answer(#{}, B1),
    ?assertEqual(nomatch, binary:match(sdp_text(Answer), <<"a=ssrc:", Ours/binary, " ">>)).

%% A peer connection is not created with codecs on 64..95.
mux_payload_types_refused_at_creation_test() ->
    [Opus | Rest] = webrtc_jsep_caps:default_codecs(audio),
    ?assertEqual({error, {badarg, {payload_type, 77}}},
                 webrtc:new_peer_connection(#{codecs => #{audio => [Opus#{pt := 77} | Rest]}})).
