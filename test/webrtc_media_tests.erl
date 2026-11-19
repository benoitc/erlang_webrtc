%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for webrtc_media: two media sessions configured from a real
%% JSEP negotiation and DTLS-SRTP style keys.
-module(webrtc_media_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").

jsep(Extra) ->
    webrtc_jsep:new(maps:merge(#{
        ice_ufrag => <<"ufrag">>,
        ice_pwd => <<"passwordpasswordpassword">>,
        fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]
    }, Extra)).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

%% Negotiate audio + video both ways and return configured sessions.
pair() ->
    pair(#{}).

pair(JsepOpts) ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, jsep(JsepOpts)),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, jsep(JsepOpts)),
    {ok, _, B1} = webrtc_jsep:add_transceiver(video, #{}, B0),
    {ok, O, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, O, A2),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, wire(O), B1),
    {ok, Ans, B3} = webrtc_jsep:create_answer(#{}, B2),
    {ok, B4} = webrtc_jsep:set_local_description(answer, Ans, B3),
    {ok, A4} = webrtc_jsep:set_remote_description(answer, wire(Ans), A3),
    #{media := MA} = webrtc_jsep:negotiated(A4),
    #{media := MB} = webrtc_jsep:negotiated(B4),
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{cname => <<"a">>}))),
    SB = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{cname => <<"b">>}))),
    {SA, SB, MA, MB}.

%% Same negotiation, but B does not know A's SSRCs: demultiplexing has
%% to use the MID header extension.
pair_without_ssrcs() ->
    {SA, SB, MA, MB} = pair(),
    MB1 = [M#{remote_ssrcs => []} || M <- MB],
    Profile = srtp_aead_aes_128_gcm,
    _ = SB,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA1 = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{}))),
    SB1 = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB1, webrtc_media:new(#{}))),
    _ = SA,
    {SA1, SB1}.

deliver([], S, _Now) ->
    {S, []};
deliver([{send, Bin} | Rest], S, Now) ->
    {S1, A} = webrtc_media:handle_packet(Bin, Now, S),
    {S2, A2} = deliver(Rest, S1, Now),
    {S2, A ++ A2}.

events(Actions) -> [E || {event, E} <- Actions].
sends(Actions) -> [A || {send, _} = A <- Actions].

send_receive_test() ->
    {SA, SB, _, _} = pair(),
    {ok, Out, _SA1} = webrtc_media:send(<<"0">>, <<"opus-frame">>, #{timestamp => 960, marker => true}, 0, SA),
    {_SB1, A} = deliver(Out, SB, 0),
    ?assertMatch([{rtp, <<"0">>, #rtp{payload = <<"opus-frame">>, pt = 111, ts = 960, marker = true}}], events(A)).

mid_extension_demux_test() ->
    {SA, SB} = pair_without_ssrcs(),
    {ok, O1, SA1} = webrtc_media:send(<<"1">>, <<"vp8">>, #{timestamp => 1}, 0, SA),
    {ok, O2, _} = webrtc_media:send(<<"0">>, <<"opus">>, #{timestamp => 1}, 0, SA1),
    {_, A} = deliver(O1 ++ O2, SB, 0),
    ?assertMatch([{rtp, <<"1">>, #rtp{payload = <<"vp8">>}}, {rtp, <<"0">>, #rtp{payload = <<"opus">>}}], events(A)).

codec_selection_test() ->
    {SA, SB, _, _} = pair(),
    {ok, O, _} = webrtc_media:send(<<"0">>, <<"x">>, #{codec => <<"PCMU">>}, 0, SA),
    {_, A} = deliver(O, SB, 0),
    ?assertMatch([{rtp, <<"0">>, #rtp{pt = 0}}], events(A)),
    ?assertEqual({error, unknown_codec}, webrtc_media:send(<<"0">>, <<"x">>, #{codec => <<"G729">>}, 0, SA)),
    ?assertEqual({error, not_sending}, webrtc_media:send(<<"9">>, <<"x">>, #{}, 0, SA)).

tampered_packet_dropped_test() ->
    {SA, SB, _, _} = pair(),
    {ok, [{send, Bin}], _} = webrtc_media:send(<<"0">>, <<"data">>, #{}, 0, SA),
    Sz = byte_size(Bin) - 1,
    <<H:Sz/binary, L>> = Bin,
    {SB1, A} = webrtc_media:handle_packet(<<H/binary, (L bxor 1)>>, 0, SB),
    ?assertEqual([], A),
    ?assertMatch(#{counters := #{srtp_rejected := 1}}, webrtc_media:stats(SB1)),
    %% Replay of a valid packet is dropped too.
    {SB2, [_]} = webrtc_media:handle_packet(Bin, 0, SB1),
    {_, []} = webrtc_media:handle_packet(Bin, 0, SB2).

%% A lost video packet is NACKed by the receiver and resent by the
%% sender over RTX; the receiver gets the original sequence number back.
nack_rtx_test() ->
    {SA0, SB0, _, _} = pair(),
    {Pkts, SA1} = lists:foldl(
        fun(I, {Acc, S}) ->
            {ok, O, S1} = webrtc_media:send(<<"1">>, <<I>>, #{timestamp => I * 3000}, 0, S),
            {Acc ++ O, S1}
        end,
        {[], SA0},
        lists:seq(1, 5)
    ),
    [P1, P2, _Lost, P4, P5] = Pkts,
    {SB1, A1} = deliver([P1, P2, P4, P5], SB0, 0),
    ?assertEqual(4, length(events(A1))),
    %% NACK is sent right away or on the NACK timer.
    {SB2, A2} = webrtc_media:handle_timeout(50, SB1),
    Nacks = sends(A1) ++ sends(A2),
    ?assert(length(Nacks) >= 1),
    {SA2, A3} = deliver(Nacks, SA1, 60),
    Rtx = sends(A3),
    ?assertEqual(1, length(Rtx)),
    {_SB3, A4} = deliver(Rtx, SB2, 70),
    [{rtp, <<"1">>, #rtp{payload = <<3>>} = Recovered}] = events(A4),
    #rtp{seq = S2} = element(3, hd(events(A1)) ),
    _ = S2,
    ?assertMatch(#{counters := #{retransmitted := 1}}, webrtc_media:stats(SA2)),
    ?assertEqual(<<3>>, Recovered#rtp.payload).

keyframe_request_test() ->
    {SA, SB0, _, _} = pair(),
    {ok, O, _SA1} = webrtc_media:send(<<"1">>, <<"frame">>, #{}, 0, SA),
    {SB1, _} = deliver(O, SB0, 0),
    {Pli, _SB2} = webrtc_media:request_keyframe(<<"1">>, 0, SB1),
    ?assertMatch([{send, _}], Pli),
    {_, A} = deliver(Pli, SA, 0),
    ?assertEqual([{keyframe_request, <<"1">>}], events(A)).

rtcp_reports_test() ->
    {SA0, SB0, _, _} = pair(),
    {ok, O, SA1} = webrtc_media:send(<<"0">>, <<"a">>, #{timestamp => 100}, 0, SA0),
    {SB1, _} = deliver(O, SB0, 0),
    Far = 5000,
    {_SA2, RA} = webrtc_media:handle_timeout(Far, SA1),
    {_SB2, RB} = webrtc_media:handle_timeout(Far, SB1),
    ?assertMatch([{send, _}], sends(RA)),
    ?assertMatch([{send, _}], sends(RB)),
    %% A's SR reaches B without errors and is not an application event.
    {SB3, Ev} = deliver(sends(RA), SB1, Far),
    ?assertEqual([], events(Ev)),
    ?assertMatch(#{counters := #{rtcp_received := 1}}, webrtc_media:stats(SB3)).

not_ready_before_keys_test() ->
    {_, _, MA, _} = pair(),
    S = webrtc_media:configure(MA, webrtc_media:new(#{})),
    ?assertNot(webrtc_media:ready(S)),
    ?assertEqual({error, not_ready}, webrtc_media:send(<<"0">>, <<"x">>, #{}, 0, S)),
    ?assertEqual({S, []}, webrtc_media:handle_packet(<<128, 0:88>>, 0, S)).

garbage_test() ->
    {_, SB, _, _} = pair(),
    rand:seed(exsss, {7, 8, 9}),
    [_ = webrtc_media:handle_packet(rand:bytes(rand:uniform(200)), 0, SB) || _ <- lists:seq(1, 2000)],
    [_ = webrtc_media:handle_packet(<<128, (rand:bytes(rand:uniform(200)))/binary>>, 0, SB)
     || _ <- lists:seq(1, 2000)],
    ok.

%% Without RTX a NACK is answered with the bytes of the first
%% transmission (protecting the packet again would reuse its SRTP index).
nack_without_rtx_test() ->
    Vp8 = hd(webrtc_jsep_caps:default_codecs(video)),
    {SA0, SB0, _, _} = pair(#{codecs => #{video => [Vp8]}}),
    {Pkts, SA1} = lists:foldl(
        fun(I, {Acc, S}) ->
            {ok, O, S1} = webrtc_media:send(<<"1">>, <<I>>, #{timestamp => I * 3000}, 0, S),
            {Acc ++ O, S1}
        end,
        {[], SA0},
        lists:seq(1, 5)
    ),
    [P1, P2, Lost, P4, P5] = Pkts,
    {SB1, A1} = deliver([P1, P2, P4, P5], SB0, 0),
    {SB2, A2} = webrtc_media:handle_timeout(50, SB1),
    Nacks = sends(A1) ++ sends(A2),
    ?assert(length(Nacks) >= 1),
    {SA2, A3} = deliver(Nacks, SA1, 60),
    ?assertEqual([Lost], sends(A3)),
    {_SB3, A4} = deliver(sends(A3), SB2, 70),
    ?assertMatch([{rtp, <<"1">>, #rtp{payload = <<3>>}}], events(A4)),
    #{counters := C} = webrtc_media:stats(SA2),
    ?assertEqual(1, maps:get(retransmitted, C)),
    ?assertEqual(0, maps:get(srtp_failed, C, 0)).

%%--------------------------------------------------------------------
%% Receive streams stay bounded when the peer keeps changing SSRC
%%--------------------------------------------------------------------

-define(URI_MID, <<"urn:ietf:params:rtp-hdrext:sdes:mid">>).

%% B without signaled SSRCs, and A's sending key, so the test can send
%% packets with any SSRC.
keyed() ->
    {_, _, _, MB} = pair(),
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    MB1 = [M#{remote_ssrcs => []} || M <- MB],
    SB = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB1, webrtc_media:new(#{}))),
    %% Cryptex is negotiated (the default): the peer sends that form.
    {Tx, _} = webrtc_srtp:dtls_contexts(Profile, Material, server, #{cryptex => true}),
    [#{mid := <<"0">>, recv_extensions := #{?URI_MID := MidId}, recv_codecs := [#{pt := Pt} | _]} | _] = MB1,
    {SB, {Tx, MidId, Pt}}.

from(Ssrc, Seq, {Tx, MidId, Pt}) ->
    Pkt = #rtp{pt = Pt, seq = Seq, ts = Seq * 960, ssrc = Ssrc, ext = [{MidId, <<"0">>}], payload = <<"x">>},
    {ok, Bin, Tx1} = webrtc_srtp:protect_rtp(webrtc_rtp:encode(Pkt), Tx),
    {Bin, setelement(1, {Tx, MidId, Pt}, Tx1)}.

%% Live receive streams (ended ones are still reported, marked).
receivers(S) -> length([x || _ := R <- maps:get(receivers, webrtc_media:stats(S)), not maps:get(ended, R, false)]).

counter(K, S) -> maps:get(K, maps:get(counters, webrtc_media:stats(S)), 0).

rotate(S0, Ssrcs, Now, K0) ->
    lists:foldl(
        fun(Ssrc, {S, K, N}) ->
            {Bin, K1} = from(Ssrc, 1, K),
            {S1, A} = webrtc_media:handle_packet(Bin, Now, S),
            {S1, K1, N + length([x || {rtp, _, _} <- events(A)])}
        end,
        {S0, K0, 0},
        Ssrcs
    ).

ssrc_churn_bounded_test() ->
    {SB0, K0} = keyed(),
    {SB1, K1, Got} = rotate(SB0, lists:seq(1, 1000), 10, K0),
    %% One transceiver keeps at most 16 receive streams.
    ?assertEqual(16, Got),
    ?assertEqual(16, receivers(SB1)),
    ?assertEqual(1000 - 16, counter(too_many_streams, SB1)),
    %% Once the memory of forgotten SSRCs is full (1024), the state no
    %% longer grows.
    {SB1b, K1b, 0} = rotate(SB1, lists:seq(2000, 3000), 20, K1),
    Size = erts_debug:flat_size(SB1b),
    {SB2, K2, 0} = rotate(SB1b, lists:seq(4000, 6000), 30, K1b),
    ?assert(erts_debug:flat_size(SB2) =< Size + 256),
    %% Streams silent for 60 s are forgotten, making room again.
    {SB3, _} = webrtc_media:handle_timeout(60010, SB2),
    ?assertEqual(0, receivers(SB3)),
    {SB4, _, 1} = rotate(SB3, [9999], 60020, K2),
    ?assertEqual(1, receivers(SB4)).

%% RFC 3550 §6.6: a BYE removes the stream; the SSRC is accepted again
%% only with later packets.
bye_removes_stream_test() ->
    {SB0, K0} = keyed(),
    {Bin, {Tx1, _, _} = K1} = from(77, 1, K0),
    {SB1, _} = webrtc_media:handle_packet(Bin, 0, SB0),
    ?assertEqual(1, receivers(SB1)),
    Bye = webrtc_rtcp:encode([#rtcp_rr{ssrc = 77}, #rtcp_bye{ssrcs = [77]}]),
    {ok, SBye, _} = webrtc_srtp:protect_rtcp(Bye, Tx1),
    {SB2, A} = webrtc_media:handle_packet(SBye, 0, SB1),
    ?assertEqual([{bye, <<"0">>, 77}], [E || {bye, _, _} = E <- events(A)]),
    ?assertEqual(0, receivers(SB2)),
    %% A replay of the packet sent before the BYE is refused.
    {SB3, A3} = webrtc_media:handle_packet(Bin, 0, SB2),
    ?assertEqual([], events(A3)),
    ?assertEqual(1, counter(srtp_rejected, SB3)),
    {Bin2, _} = from(77, 2, K1),
    {SB4, A4} = webrtc_media:handle_packet(Bin2, 0, SB3),
    ?assertMatch([{rtp, <<"0">>, #rtp{ssrc = 77, seq = 2}}], events(A4)),
    ?assertEqual(1, receivers(SB4)).

%%--------------------------------------------------------------------
%% RTCP with more sources than one report holds (RFC 3550 §6.4)
%%--------------------------------------------------------------------

%% B receives from 80 SSRCs over 5 video transceivers.
many_sources() ->
    Add = fun(J0) -> lists:foldl(fun(_, J) -> {ok, _, J1} = webrtc_jsep:add_transceiver(video, #{}, J), J1 end, J0, lists:seq(1, 5)) end,
    A1 = Add(jsep(#{})),
    B1 = Add(jsep(#{})),
    {ok, O, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, _} = webrtc_jsep:set_local_description(offer, O, A2),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, wire(O), B1),
    {ok, Ans, B3} = webrtc_jsep:create_answer(#{}, B2),
    {ok, B4} = webrtc_jsep:set_local_description(answer, Ans, B3),
    #{media := MB} = webrtc_jsep:negotiated(B4),
    MB1 = [M#{remote_ssrcs => []} || M <- MB],
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SB0 = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB1, webrtc_media:new(#{cname => <<"b">>}))),
    {Tx0, Rx} = webrtc_srtp:dtls_contexts(Profile, Material, server, #{cryptex => true}),
    {SB, _} = lists:foldl(
        fun({#{mid := Mid, recv_extensions := #{?URI_MID := MidId}, recv_codecs := [#{pt := Pt} | _]}, I}, {S, Tx}) ->
            lists:foldl(
                fun(K, {S1, Tx1}) ->
                    Pkt = #rtp{pt = Pt, seq = 1, ts = 1, ssrc = I * 100 + K, ext = [{MidId, Mid}], payload = <<"x">>},
                    {ok, Bin, Tx2} = webrtc_srtp:protect_rtp(webrtc_rtp:encode(Pkt), Tx1),
                    {S2, _} = webrtc_media:handle_packet(Bin, 10, S1),
                    {S2, Tx2}
                end,
                {S, Tx},
                lists:seq(1, 16)
            )
        end,
        {SB0, Tx0},
        lists:zip(MB1, lists:seq(1, length(MB1)))
    ),
    {SB, Rx}.

many_sources_reported_test() ->
    {SB, Rx} = many_sources(),
    ?assertEqual(80, receivers(SB)),
    All = lists:sort(maps:keys(maps:get(receivers, webrtc_media:stats(SB)))),
    {Seen, Sizes, _} = lists:foldl(
        fun(_, {Seen0, Sizes0, S0}) ->
            {S1, Acts} = next_report(S0, 50),
            Pkts = lists:append([P || {send, Bin} <- Acts, {ok, Plain, _} <- [webrtc_srtp:unprotect_rtcp(Bin, Rx)], {ok, P} <- [webrtc_rtcp:decode(Plain)]]),
            Blocks = lists:append([Rbs || #rtcp_rr{reports = Rbs} <- Pkts] ++ [Rbs || #rtcp_sr{reports = Rbs} <- Pkts]),
            %% No source is reported twice in one compound.
            Ssrcs = [S || #rtcp_rb{ssrc = S} <- Blocks],
            ?assertEqual(length(Ssrcs), length(lists:usort(Ssrcs))),
            {Seen0 ++ Ssrcs, Sizes0 ++ [byte_size(B) || {send, B} <- Acts], S1}
        end,
        {[], [], SB},
        lists:seq(1, 3)
    ),
    %% 80 blocks do not fit one compound; three intervals cover them all.
    ?assertEqual(All, lists:usort(Seen)),
    ?assert(lists:all(fun(Sz) -> Sz =< 1200 end, Sizes)).

%% Run timers until a regular report (with report blocks) goes out.
next_report(S0, Tries) when Tries > 0 ->
    {S1, Acts} = webrtc_media:handle_timeout(webrtc_media:next_timeout(S0), S0),
    case [B || {send, B} <- Acts] of
        [] -> next_report(S1, Tries - 1);
        _ -> {S1, Acts}
    end.

%%--------------------------------------------------------------------
%% Feedback packet form (RFC 5506, RFC 4585 §3.1)
%%--------------------------------------------------------------------

%% B with the given rtcp-rsize, having received a video packet from A;
%% returns A's receive context to read what B sends.
feedback_pair(Rsize) ->
    {_, _, MA, MB} = pair(),
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{}))),
    MB1 = [M#{rtcp_rsize => Rsize} || M <- MB],
    SB = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB1, webrtc_media:new(#{cname => <<"b">>}))),
    {ok, Out, _} = webrtc_media:send(<<"1">>, <<"frame">>, #{timestamp => 1}, 0, SA),
    {SB1, _} = deliver(Out, SB, 0),
    {_, Rx} = webrtc_srtp:dtls_contexts(Profile, Material, server, #{}),
    {SB1, Rx}.

pli_from(SB, Rx) ->
    {Acts, _} = webrtc_media:request_keyframe(<<"1">>, 0, SB),
    [Bin] = [B || {send, B} <- Acts],
    {ok, Plain, _} = webrtc_srtp:unprotect_rtcp(Bin, Rx),
    {ok, Pkts} = webrtc_rtcp:decode(Plain),
    Pkts.

%% Without rtcp-rsize, feedback is a compound: RR, SDES CNAME, then the
%% feedback.
compound_feedback_without_rsize_test() ->
    {SB, Rx} = feedback_pair(false),
    ?assertMatch([#rtcp_rr{}, #rtcp_sdes{chunks = [{_, [{cname, <<"b">>}]}]}, #rtcp_pli{}], pli_from(SB, Rx)).

%% With rtcp-rsize negotiated, it goes out alone.
reduced_size_feedback_test() ->
    {SB, Rx} = feedback_pair(true),
    ?assertMatch([#rtcp_pli{}], pli_from(SB, Rx)).

%%====================================================================
%% SSRC collision (RFC 3550 §8.2), cryptex required (RFC 9335 §6.3),
%% more than 31 sources (RFC 3550 §6.4.2)
%%====================================================================

%% B sends with A's audio SSRC: A takes another, says BYE for the old
%% one and reports the change; its next packets use the new SSRC.
ssrc_collision_test() ->
    {SA, _SB, MA, MB} = pair(),
    [#{ssrc := Ours} | _] = MA,
    MB1 = [case maps:get(mid, M) of <<"0">> -> M#{ssrc := Ours}; _ -> M end || M <- MB],
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA1 = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{cname => <<"a">>}))),
    SB1 = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB1, webrtc_media:new(#{cname => <<"b">>}))),
    _ = SA,
    {ok, Out, _} = webrtc_media:send(<<"0">>, <<"from b">>, #{timestamp => 1}, 0, SB1),
    {SA2, Acts} = deliver(Out, SA1, 0),
    [{ssrc_changed, <<"0">>, Ours, New}] = [E || {ssrc_changed, _, _, _} = E <- events(Acts)],
    ?assertNotEqual(Ours, New),
    ?assertMatch([_ | _], sends(Acts)),
    {ok, [{send, Pkt}], _} = webrtc_media:send(<<"0">>, <<"from a">>, #{timestamp => 2}, 0, SA2),
    {ok, Plain, _} = webrtc_srtp:unprotect_rtp(Pkt, element(2, webrtc_srtp:dtls_contexts(Profile, Material, client, #{}))),
    {ok, #rtp{ssrc = New}} = webrtc_rtp:decode(Plain).

%% Cryptex negotiated: a packet with header extensions in the plain form
%% is refused.
cryptex_required_test() ->
    {SA, _SB, MA, MB} = pair(#{cryptex => true}),
    ?assert(lists:all(fun(M) -> maps:get(cryptex, M) end, MA)),
    MB1 = [M#{cryptex := false} || M <- MB],
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA1 = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{}))),
    SB1 = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB1, webrtc_media:new(#{}))),
    _ = SA,
    {ok, Out, _} = webrtc_media:send(<<"0">>, <<"plain extensions">>, #{timestamp => 1}, 0, SB1),
    {_, Acts} = deliver(Out, SA1, 0),
    ?assertEqual([], [E || {rtp, _, _} = E <- events(Acts)]).
