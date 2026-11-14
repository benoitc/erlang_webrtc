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
    Pcmu = lists:nth(2, webrtc_jsep_caps:default_codecs(audio)),
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    B0 = new(#{codecs => #{audio => [Pcmu]}}),
    {A, _, _, Answer} = exchange(A0, B0),
    [M] = Answer#sdp.media,
    ?assertEqual([0], ?M:payload_types(M)),
    [#{send_codecs := [#{name := <<"PCMU">>}]}] = maps:get(media, webrtc_jsep:negotiated(A)),
    _ = Opus.

no_common_codec_rejects_section_test() ->
    Pcmu = lists:nth(2, webrtc_jsep_caps:default_codecs(audio)),
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

unbundled_media_rejected_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, new()),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A1),
    NoBundle = Offer#sdp{attributes = [A || {K, _} = A <- Offer#sdp.attributes, K =/= group]},
    ?assertEqual({error, {unsupported, unbundled_media}},
                 webrtc_jsep:set_remote_description(offer, NoBundle, new())).

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
