%% Conformance tests for rid and simulcast negotiation in JSEP
%% (RFC 9429 §5.2.1, §5.3.1, §5.8.3, RFC 8851 §6, RFC 8853 §5.3).
-module(webrtc_jsep_simulcast_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_sdp.hrl").

-define(M, webrtc_sdp_media).
-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).
-define(URI_RRID, <<"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>).

new() ->
    new(#{}).

new(Extra) ->
    webrtc_jsep:new(maps:merge(#{
        ice_ufrag => base64:encode(crypto:strong_rand_bytes(6)),
        ice_pwd => base64:encode(crypto:strong_rand_bytes(18)),
        fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]
    }, Extra)).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

%% Answer a remote offer given as text; returns the answer and the state.
answer(OfferText) ->
    answer(OfferText, new()).

answer(OfferText, J0) ->
    {ok, Offer} = webrtc_sdp:parse(OfferText),
    {ok, J1} = webrtc_jsep:set_remote_description(offer, Offer, J0),
    {ok, Answer, J2} = webrtc_jsep:create_answer(#{}, J1),
    {ok, J3} = webrtc_jsep:set_local_description(answer, Answer, J2),
    {wire(Answer), J3}.

section(Mid, #sdp{media = Ms}) ->
    hd([M || M <- Ms, ?M:mid(M) =:= Mid]).

media(Mid, J) ->
    hd([M || #{mid := X} = M <- maps:get(media, webrtc_jsep:negotiated(J)), X =:= Mid]).

rids(Sec) -> [{Id, D} || #{id := Id, direction := D} <- ?M:attrs(rid, Sec)].

%% Replace and remove lines of an SDP text.
edit(Text, Fun) ->
    Lines = binary:split(Text, <<"\r\n">>, [global, trim_all]),
    iolist_to_binary([[L, "\r\n"] || L0 <- Lines, L <- Fun(L0)]).

%%--------------------------------------------------------------------
%% Receiving simulcast
%%--------------------------------------------------------------------

chrome_simulcast_answer_test() ->
    {Answer, J} = answer(webrtc_sdp_samples:chrome_simulcast_offer()),
    V = section(<<"1">>, Answer),
    ?assertEqual(recvonly, ?M:direction(V, Answer)),
    %% RFC 8851 §6.3: same rid-ids, direction reversed.
    ?assertEqual([{<<"q">>, recv}, {<<"h">>, recv}, {<<"f">>, recv}], rids(V)),
    %% RFC 8853 §5.3.2: simulcast direction reversed, no pause marks.
    ?assertEqual([[{recv, [[{<<"q">>, false}], [{<<"h">>, false}], [{<<"f">>, false}]]}]],
                 ?M:attrs(simulcast, V)),
    Text = webrtc_sdp:encode(Answer),
    ?assertNotEqual(nomatch, binary:match(Text, <<"a=simulcast:recv q;h;f\r\n">>)),
    ?assertNotEqual(nomatch, binary:match(Text, <<"a=rid:q recv\r\n">>)),
    %% The rid and repaired-rid extensions keep the offered ids.
    Exts = webrtc_jsep_caps:extension_map(?M:attrs(extmap, V)),
    ?assertMatch(#{?URI_RID := 10, ?URI_RRID := 11}, Exts),
    #{recv_rids := Recv, send_rids := [], recv_extensions := #{?URI_RID := 10}} = media(<<"1">>, J),
    ?assertEqual([#{rid => R, paused => false} || R <- [<<"q">>, <<"h">>, <<"f">>]], Recv),
    %% Audio has no layers.
    ?assertMatch(#{recv_rids := [], send_rids := []}, media(<<"0">>, J)),
    ?assertEqual([], rids(section(<<"0">>, Answer))).

%% Firefox announces the SSRCs of its layers and their RTX pairs.
firefox_simulcast_answer_test() ->
    {Answer, J} = answer(webrtc_sdp_samples:firefox_offer()),
    V = section(<<"1">>, Answer),
    ?assertEqual([{<<"h">>, recv}, {<<"m">>, recv}, {<<"l">>, recv}], rids(V)),
    ?assertEqual([[{recv, [[{<<"h">>, false}], [{<<"m">>, false}], [{<<"l">>, false}]]}]],
                 ?M:attrs(simulcast, V)),
    #{recv_rids := Recv, remote_ssrcs := Ssrcs, recv_extensions := #{?URI_RID := 8, ?URI_RRID := 9}} =
        media(<<"1">>, J),
    ?assertEqual([<<"h">>, <<"m">>, <<"l">>], [R || #{rid := R} <- Recv]),
    ?assertEqual(3, length([S || #{rtx_ssrc := X} = S <- Ssrcs, is_integer(X)])).

%% Restrictions, pt= lists, alternatives, dependencies and paused
%% streams (RFC 8851 §6.2.2, §6.3, RFC 8853 §5.3.2).
restrictions_alternatives_and_paused_test() ->
    Vp8 = [C || #{name := <<"VP8">>} = C <- webrtc_jsep_caps:default_codecs(video)],
    Rtx = [C || #{name := <<"rtx">>, fmtp := [{<<"apt">>, <<"96">>}]} = C <- webrtc_jsep_caps:default_codecs(video)],
    J0 = new(#{codecs => #{video => Vp8 ++ Rtx}}),
    {Answer, J} = answer(webrtc_sdp_samples:simulcast_paused(), J0),
    [V] = Answer#sdp.media,
    [F, H, Q] = ?M:attrs(rid, V),
    %% pt=98 (H.264) is not answered: dropped from f, and h2 has no
    %% payload type left. The recv rid r0 is a request that we send
    %% simulcast and is discarded.
    ?assertMatch(#{id := <<"f">>, direction := recv, pts := [96],
                   params := [{<<"max-width">>, <<"1280">>}, {<<"max-height">>, <<"720">>},
                              {<<"max-fps">>, <<"30">>}]}, F),
    ?assertMatch(#{id := <<"h">>, direction := recv, pts := [96]}, H),
    %% No pt= in the offer: none in the answer.
    ?assertMatch(#{id := <<"q">>, pts := [], params := [_, _, _, {<<"depend">>, <<"h">>}]}, Q),
    ?assertEqual([[{recv, [[{<<"f">>, false}], [{<<"h">>, false}], [{<<"q">>, false}]]}]],
                 ?M:attrs(simulcast, V)),
    %% The pause marks of the sender are reported.
    #{recv_rids := Recv} = media(<<"0">>, J),
    ?assertEqual([#{rid => <<"f">>, paused => false}, #{rid => <<"h">>, paused => true},
                  #{rid => <<"q">>, paused => true}], Recv).

discarded_rid_lines_test() ->
    Offer = edit(webrtc_sdp_samples:chrome_simulcast_offer(), fun
        (<<"a=rid:q send">>) -> [<<"a=rid:q send">>, <<"a=rid:x send pt=77">>, <<"a=rid:d send depend=zz">>];
        (<<"a=rid:h send">>) -> [<<"a=rid:h send">>, <<"a=rid:h send max-width=100">>];
        (<<"a=simulcast:send q;h;f">>) -> [<<"a=simulcast:send q;h;x,f;d">>];
        (L) -> [L]
    end),
    {Answer, J} = answer(Offer),
    V = section(<<"1">>, Answer),
    %% Duplicated h (both lines), x (pt not on the m= line) and d
    %% (unknown dependency) are discarded.
    ?assertEqual([{<<"q">>, recv}, {<<"f">>, recv}], rids(V)),
    ?assertEqual([[{recv, [[{<<"q">>, false}], [{<<"f">>, false}]]}]], ?M:attrs(simulcast, V)),
    ?assertEqual([<<"q">>, <<"f">>], [R || #{rid := R} <- maps:get(recv_rids, media(<<"1">>, J))]).

two_simulcast_lines_disable_simulcast_test() ->
    Offer = edit(webrtc_sdp_samples:chrome_simulcast_offer(), fun
        (<<"a=simulcast:", _/binary>> = L) -> [L, <<"a=simulcast:send f">>];
        (L) -> [L]
    end),
    {Answer, _} = answer(Offer),
    V = section(<<"1">>, Answer),
    ?assertEqual([], ?M:attrs(simulcast, V)),
    ?assertEqual(3, length(rids(V))).

%% Layers cannot be told apart without the RtpStreamId extension.
no_rid_extension_no_layers_test() ->
    Exts = [E || #{uri := U} = E <- webrtc_jsep_caps:default_extensions(video), U =/= ?URI_RID],
    {Answer, J} = answer(webrtc_sdp_samples:chrome_simulcast_offer(), new(#{extensions => #{video => Exts}})),
    V = section(<<"1">>, Answer),
    ?assertEqual({[], []}, {rids(V), ?M:attrs(simulcast, V)}),
    ?assertEqual([], maps:get(recv_rids, media(<<"1">>, J))).

%% RFC 9429 §5.8.3: rid-ids of a=simulcast must exist as a=rid lines.
unknown_simulcast_rid_rejected_test() ->
    Offer = edit(webrtc_sdp_samples:chrome_simulcast_offer(), fun
        (<<"a=rid:h send">>) -> [];
        (L) -> [L]
    end),
    {ok, P} = webrtc_sdp:parse(Offer),
    ?assertEqual({error, {unknown_rid, <<"1">>}}, webrtc_jsep:set_remote_description(offer, P, new())).

%%--------------------------------------------------------------------
%% Sending simulcast
%%--------------------------------------------------------------------

layers() -> [#{rid => <<"q">>}, #{rid => <<"h">>}, #{rid => <<"f">>, restrictions => [{<<"max-width">>, <<"1280">>}]}].

sender() ->
    {ok, _, A} = webrtc_jsep:add_transceiver(video, #{direction => sendonly, send_encodings => layers()}, new()),
    A.

%% Offer from A, answer from B with the answer text edited by Fun.
exchange(A0, B0, Fun) ->
    {ok, Offer, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, A2} = webrtc_jsep:set_local_description(offer, Offer, A1),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), B0),
    {ok, Answer, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Answer, B2),
    {ok, Edited} = webrtc_sdp:parse(edit(webrtc_sdp:encode(Answer), Fun)),
    {ok, A3} = webrtc_jsep:set_remote_description(answer, Edited, A2),
    {A3, B3, wire(Offer)}.

keep(L) -> [L].

offer_test() ->
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, sender()),
    [V] = Offer#sdp.media,
    ?assertEqual([{<<"q">>, send}, {<<"h">>, send}, {<<"f">>, send}], rids(V)),
    Text = webrtc_sdp:encode(Offer),
    ?assertNotEqual(nomatch, binary:match(Text, <<"a=rid:f send max-width=1280\r\n">>)),
    ?assertNotEqual(nomatch, binary:match(Text, <<"a=simulcast:send q;h;f\r\n">>)),
    %% Layers are identified by rid, their SSRCs are not announced.
    ?assertEqual([], ?M:attrs(ssrc, V)),
    ?assertMatch([#{uri := ?URI_RID} | _], [E || #{uri := ?URI_RID} = E <- ?M:attrs(extmap, V)]).

erlang_to_erlang_layers_test() ->
    {A, B, _} = exchange(sender(), new(), fun keep/1),
    #{send_rids := Send, ssrc := Ssrc, rtx_ssrc := Rtx} = media(<<"0">>, A),
    ?assertEqual([<<"q">>, <<"h">>, <<"f">>], [R || #{rid := R} <- Send]),
    [#{ssrc := S1, rtx_ssrc := X1} | _] = Send,
    %% The first layer uses the SSRCs of the transceiver.
    ?assertEqual({Ssrc, Rtx}, {S1, X1}),
    All = lists:append([[S, X] || #{ssrc := S, rtx_ssrc := X} <- Send]),
    ?assertEqual(6, length(lists:usort(All))),
    ?assertEqual([false, false, false], [P || #{paused := P} <- Send]),
    ?assertEqual([<<"q">>, <<"h">>, <<"f">>], [R || #{rid := R} <- maps:get(recv_rids, media(<<"0">>, B))]),
    [#{send_encodings := Encs}] = webrtc_jsep:transceivers(A),
    ?assertEqual(Send, [E#{paused => false} || E <- Encs]).

%% RFC 8853 §5.3.3: removed rids are not sent, paused ones reported.
answer_removes_and_pauses_layers_test() ->
    {A, _, _} = exchange(sender(), new(), fun
        (<<"a=rid:h recv">>) -> [];
        (<<"a=simulcast:recv q;h;f">>) -> [<<"a=simulcast:recv q;~f">>];
        (L) -> [L]
    end),
    ?assertMatch([#{rid := <<"q">>, paused := false}, #{rid := <<"f">>, paused := true}],
                 maps:get(send_rids, media(<<"0">>, A))).

%% RFC 9429 §3.7: without simulcast only the first encoding is sent; it
%% keeps its rid when the answer accepted it.
answer_without_simulcast_test() ->
    {A1, _, _} = exchange(sender(), new(), fun
        (<<"a=simulcast:", _/binary>>) -> [];
        (L) -> [L]
    end),
    ?assertMatch([#{rid := <<"q">>}], maps:get(send_rids, media(<<"0">>, A1))),
    {A2, _, _} = exchange(sender(), new(), fun
        (<<"a=simulcast:", _/binary>>) -> [];
        (<<"a=rid:", _/binary>>) -> [];
        (L) -> [L]
    end),
    ?assertEqual([], maps:get(send_rids, media(<<"0">>, A2))).

%% RFC 8851 §6.4 steps 2 and 3.
answer_restrictions_test_() ->
    Case = fun(Line, Expected) ->
        ?_test(begin
            {A, _, _} = exchange(sender(), new(), fun
                (<<"a=rid:f recv", _/binary>>) -> [Line];
                (L) -> [L]
            end),
            ?assertEqual(Expected, [R || #{rid := R} <- maps:get(send_rids, media(<<"0">>, A))])
        end)
    end,
    [
        Case(<<"a=rid:f recv max-width=640">>, [<<"q">>, <<"h">>, <<"f">>]),
        Case(<<"a=rid:f recv max-width=1920">>, [<<"q">>, <<"h">>]),
        Case(<<"a=rid:f recv max-width=640;max-fps=15">>, [<<"q">>, <<"h">>]),
        Case(<<"a=rid:f recv pt=96">>, [<<"q">>, <<"h">>])
    ].

reoffer_keeps_rid_lines_test() ->
    {A, B, Offer1} = exchange(sender(), new(), fun keep/1),
    {_, _, Offer2} = exchange(A, B, fun keep/1),
    [V1] = Offer1#sdp.media,
    [V2] = Offer2#sdp.media,
    ?assertEqual(?M:attrs(rid, V1), ?M:attrs(rid, V2)),
    ?assertEqual(?M:attrs(simulcast, V1), ?M:attrs(simulcast, V2)).

not_sending_no_rid_lines_test() ->
    {ok, _, A} = webrtc_jsep:add_transceiver(video, #{direction => recvonly, send_encodings => layers()}, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A),
    [V] = Offer#sdp.media,
    ?assertEqual({[], []}, {rids(V), ?M:attrs(simulcast, V)}).

encodings_test() ->
    Add = fun(Encs) -> webrtc_jsep:add_transceiver(video, #{send_encodings => Encs}, new()) end,
    ?assertEqual({error, invalid_encodings}, Add([#{rid => <<"a">>}, #{rid => <<"a">>}])),
    ?assertEqual({error, invalid_encodings}, Add([#{rid => <<"a b">>}])),
    ?assertEqual({error, invalid_encodings}, Add([#{rid => <<"a">>, restrictions => [{<<"x;y">>, <<"1">>}]}])),
    ?assertEqual({error, invalid_encodings}, Add(not_a_list)),
    %% One encoding without a rid: no rid lines (RFC 9429 §5.2.1).
    {ok, _, J1} = Add([#{}]),
    ?assertMatch([#{send_encodings := []}], webrtc_jsep:transceivers(J1)),
    %% Missing rids are generated without colliding with given ones.
    {ok, _, J2} = Add([#{}, #{rid => <<"0">>}, #{}]),
    [#{send_encodings := Encs}] = webrtc_jsep:transceivers(J2),
    ?assertEqual([<<"1">>, <<"0">>, <<"2">>], [R || #{rid := R} <- Encs]).

%% RFC 9429 §5.10, RFC 8853 §5.3.2: an offer asking to receive three
%% layers (one paused) is answered by a transceiver without encodings
%% with send rids and a=simulcast:send; each side sees the layers.
answerer_sends_layers_test() ->
    Recv = [<<"q">>, #{rid => <<"h">>, paused => true}, <<"f">>],
    {ok, _, A0} = webrtc_jsep:add_transceiver(video, #{direction => recvonly, recv_rids => Recv}, new()),
    {ok, Offer, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, A2} = webrtc_jsep:set_local_description(offer, Offer, A1),
    OS = section(<<"0">>, wire(Offer)),
    ?assertEqual([{<<"q">>, recv}, {<<"h">>, recv}, {<<"f">>, recv}], [{I, D} || #{id := I, direction := D} <- ?M:attrs(rid, OS)]),
    ?assertEqual([[{recv, [[{<<"q">>, false}], [{<<"h">>, true}], [{<<"f">>, false}]]}]], ?M:attrs(simulcast, OS)),
    {ok, _, B0} = webrtc_jsep:add_transceiver(video, #{}, new()),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), B0),
    {ok, Answer, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Answer, B2),
    AS = section(<<"0">>, wire(Answer)),
    ?assertEqual([{<<"q">>, send}, {<<"h">>, send}, {<<"f">>, send}], [{I, D} || #{id := I, direction := D} <- ?M:attrs(rid, AS)]),
    ?assertEqual([[{send, [[{<<"q">>, false}], [{<<"h">>, false}], [{<<"f">>, false}]]}]], ?M:attrs(simulcast, AS)),
    #{send_rids := Send} = media(<<"0">>, B3),
    ?assertEqual([{<<"q">>, false}, {<<"h">>, true}, {<<"f">>, false}], [{R, P} || #{rid := R, paused := P} <- Send]),
    ?assertEqual(3, length(lists:usort([S || #{ssrc := S} <- Send]))),
    {ok, A3} = webrtc_jsep:set_remote_description(answer, wire(Answer), A2),
    #{recv_rids := Got} = media(<<"0">>, A3),
    ?assertEqual([<<"q">>, <<"h">>, <<"f">>], [R || #{rid := R} <- Got]).

%% A transceiver that already has encodings keeps them; one that does
%% not send answers without send rids.
answerer_layers_kept_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(video, #{direction => recvonly, recv_rids => [<<"a">>, <<"b">>]}, new()),
    {ok, Offer, _} = webrtc_jsep:create_offer(#{}, A0),
    {ok, _, B0} = webrtc_jsep:add_transceiver(video, #{direction => recvonly}, new()),
    {Answer, _} = answer(webrtc_sdp:encode(Offer), B0),
    ?assertEqual([], ?M:attrs(rid, section(<<"0">>, Answer))),
    ?assertEqual({error, invalid_recv_rids}, webrtc_jsep:add_transceiver(video, #{recv_rids => [<<"a">>, <<"a">>]}, new())).
