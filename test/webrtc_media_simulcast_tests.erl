%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Simulcast media (RFC 8853) with RTP stream identifiers (RFC 8852):
%% per-layer SSRCs and rid extension on send, demultiplexing by MID and
%% rid / repaired-rid on receive, NACK, RTX and PLI per layer.
-module(webrtc_media_simulcast_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").

-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).
-define(URI_RRID, <<"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>).
-define(RIDS, [<<"q">>, <<"h">>, <<"f">>]).

jsep() ->
    webrtc_jsep:new(#{
        ice_ufrag => <<"ufrag">>,
        ice_pwd => <<"passwordpasswordpassword">>,
        fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]
    }).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

%% A sends three video layers, B receives them.
negotiate() ->
    Encs = [#{rid => R} || R <- ?RIDS],
    {ok, _, A0} = webrtc_jsep:add_transceiver(video, #{direction => sendonly, send_encodings => Encs}, jsep()),
    {ok, O, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, A2} = webrtc_jsep:set_local_description(offer, O, A1),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(O), jsep()),
    {ok, Ans, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Ans, B2),
    {ok, A3} = webrtc_jsep:set_remote_description(answer, wire(Ans), A2),
    #{media := MA} = webrtc_jsep:negotiated(A3),
    #{media := MB} = webrtc_jsep:negotiated(B3),
    {MA, MB}.

pair() ->
    {MA, MB} = negotiate(),
    sessions(MA, MB).

sessions(MA, MB) ->
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{}))),
    SB = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{}))),
    {SA, SB}.

deliver([], S, _Now) ->
    {S, []};
deliver([{send, Bin} | Rest], S, Now) ->
    {S1, A} = webrtc_media:handle_packet(Bin, Now, S),
    {S2, A2} = deliver(Rest, S1, Now),
    {S2, A ++ A2}.

events(Actions) -> [E || {event, E} <- Actions].
sends(Actions) -> [A || {send, _} = A <- Actions].

send(Rid, Payload, Ts, S) ->
    {ok, Out, S1} = webrtc_media:send(<<"0">>, Payload, #{rid => Rid, timestamp => Ts}, 0, S),
    {Out, S1}.

%% Decode what A puts on the wire (same keys on both sides).
plain(Bin, Profile, Material) ->
    {_, In} = webrtc_srtp:dtls_contexts(Profile, Material, client, #{}),
    {ok, P, _} = webrtc_srtp:unprotect_rtp(Bin, In),
    {ok, Pkt} = webrtc_rtp:decode(P, #{extensions => parse}),
    Pkt.

negotiated_layers_test() ->
    {MA, MB} = negotiate(),
    [#{send_rids := Send, send_extensions := #{?URI_RID := RidId}}] = MA,
    [#{recv_rids := Recv, recv_extensions := #{?URI_RID := RidId}}] = MB,
    ?assertEqual(?RIDS, [R || #{rid := R} <- Send]),
    ?assertEqual(?RIDS, [R || #{rid := R} <- Recv]).

%% Each layer has its own SSRC and carries MID and RtpStreamId.
send_layers_test() ->
    {MA, MB} = negotiate(),
    [#{send_rids := Layers, send_extensions := Exts}] = MA,
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{}))),
    _ = MB,
    lists:foreach(
        fun(#{rid := Rid, ssrc := Ssrc}) ->
            {[{send, Bin}], _} = send(Rid, <<"x">>, 1, SA),
            #rtp{ssrc = S, ext = Ext} = plain(Bin, Profile, Material),
            ?assertEqual(Ssrc, S),
            ?assertEqual({ok, Rid}, webrtc_rtp_ext:find(maps:get(?URI_RID, Exts), Ext)),
            ?assertEqual({ok, <<"0">>}, webrtc_rtp_ext:find(maps:get(<<"urn:ietf:params:rtp-hdrext:sdes:mid">>, Exts), Ext))
        end,
        Layers
    ),
    %% A layer needs its rid; an unknown rid is not sent.
    ?assertEqual({error, not_sending}, webrtc_media:send(<<"0">>, <<"x">>, #{}, 0, SA)),
    ?assertEqual({error, not_sending}, webrtc_media:send(<<"0">>, <<"x">>, #{rid => <<"z">>}, 0, SA)).

receive_layers_test() ->
    {SA0, SB0} = pair(),
    {Out, _} = lists:foldl(
        fun(Rid, {Acc, S}) ->
            {O, S1} = send(Rid, <<"frame-", Rid/binary>>, 3000, S),
            {Acc ++ O, S1}
        end,
        {[], SA0},
        ?RIDS
    ),
    {SB1, A} = deliver(Out, SB0, 0),
    Events = events(A),
    ?assertEqual(?RIDS, [Rid || {rtp, <<"0">>, Rid, #rtp{}} <- Events]),
    ?assertEqual([<<"frame-", R/binary>> || R <- ?RIDS], [P || {rtp, _, _, #rtp{payload = P}} <- Events]),
    Ssrcs = [S || {rtp, _, _, #rtp{ssrc = S}} <- Events],
    ?assertEqual(3, length(lists:usort(Ssrcs))),
    #{receivers := Rcv} = webrtc_media:stats(SB1),
    ?assertEqual(lists:sort(?RIDS), lists:sort([R || #{rid := R} <- maps:values(Rcv)])).

%% A lost packet of one layer is NACKed on that layer's SSRC and
%% resent on its RTX stream, which names it by repaired-rid.
layer_nack_rtx_test() ->
    {SA0, SB0} = pair(),
    {Pkts, SA1} = lists:foldl(
        fun(I, {Acc, S}) ->
            {O, S1} = send(<<"h">>, <<I>>, I * 3000, S),
            {Acc ++ O, S1}
        end,
        {[], SA0},
        lists:seq(1, 5)
    ),
    [P1, P2, _Lost, P4, P5] = Pkts,
    {SB1, A1} = deliver([P1, P2, P4, P5], SB0, 0),
    ?assertEqual(4, length([E || {rtp, _, <<"h">>, _} = E <- events(A1)])),
    {SB2, A2} = webrtc_media:handle_timeout(50, SB1),
    Nacks = sends(A1) ++ sends(A2),
    ?assert(length(Nacks) >= 1),
    {SA2, A3} = deliver(Nacks, SA1, 60),
    Rtx = sends(A3),
    ?assertEqual(1, length(Rtx)),
    {SB3, A4} = deliver(Rtx, SB2, 70),
    ?assertMatch([{rtp, <<"0">>, <<"h">>, #rtp{payload = <<3>>}}], events(A4)),
    ?assertMatch(#{counters := #{retransmitted := 1}}, webrtc_media:stats(SA2)),
    ?assertMatch(#{counters := #{rtx_received := 1}}, webrtc_media:stats(SB3)).

layer_keyframe_test() ->
    {SA0, SB0} = pair(),
    {Out, SA1} = lists:foldl(
        fun(Rid, {Acc, S}) ->
            {O, S1} = send(Rid, <<"k">>, 1, S),
            {Acc ++ O, S1}
        end,
        {[], SA0},
        ?RIDS
    ),
    {SB1, _} = deliver(Out, SB0, 0),
    {Pli, SB2} = webrtc_media:request_keyframe({<<"0">>, <<"h">>}, 0, SB1),
    {_, A} = deliver(Pli, SA1, 0),
    ?assertEqual([{keyframe_request, <<"0">>, <<"h">>}], events(A)),
    %% Without a rid every layer is asked.
    {All, _} = webrtc_media:request_keyframe(<<"0">>, 0, SB2),
    {_, A2} = deliver(All, SA1, 0),
    ?assertEqual(lists:sort([{keyframe_request, <<"0">>, R} || R <- ?RIDS]), lists:sort(events(A2))),
    %% A layer never seen: nothing to ask.
    ?assertMatch({[], _}, webrtc_media:request_keyframe({<<"0">>, <<"z">>}, 0, SB2)).

%% RFC 8853 §5.2: streams with a rid that was not negotiated are not
%% accepted; streams without any rid cannot be attributed.
unknown_rid_dropped_test() ->
    {MA, [MB]} = negotiate(),
    {SA0, SB0} = sessions(MA, [MB#{recv_rids := [#{rid => <<"q">>, paused => false}]}]),
    {O1, SA1} = send(<<"q">>, <<"ok">>, 1, SA0),
    {O2, _} = send(<<"h">>, <<"no">>, 1, SA1),
    {SB1, A} = deliver(O1 ++ O2, SB0, 0),
    ?assertMatch([{rtp, <<"0">>, <<"q">>, #rtp{payload = <<"ok">>}}], events(A)),
    ?assertMatch(#{counters := #{unknown_rid := 1}}, webrtc_media:stats(SB1)).

%% The SDES RtpStreamId items of the sender's reports (RFC 8852 §4)
%% teach the receiver the SSRC of every layer before any RTP arrives.
sdes_teaches_layers_test() ->
    {SA0, SB0} = pair(),
    {_, Reports} = webrtc_media:handle_timeout(5000, SA0),
    {SB1, Ev} = deliver(sends(Reports), SB0, 5000),
    ?assertEqual([], events(Ev)),
    {Pli, _} = webrtc_media:request_keyframe({<<"0">>, <<"f">>}, 5000, SB1),
    ?assertMatch([{send, _}], Pli),
    {_, A} = deliver(Pli, SA0, 5000),
    ?assertEqual([{keyframe_request, <<"0">>, <<"f">>}], events(A)).

%%--------------------------------------------------------------------
%% webrtc_media_rid
%%--------------------------------------------------------------------

rid_state() ->
    webrtc_media_rid:configure(
        [
            #{mid => <<"v">>, recv_rids => [#{rid => R, paused => false} || R <- ?RIDS],
              recv_extensions => #{?URI_RID => 10, ?URI_RRID => 11}},
            #{mid => <<"a">>, recv_rids => [], recv_extensions => #{}}
        ],
        webrtc_media_rid:new()
    ).

classify_test() ->
    R0 = rid_state(),
    Pkt = fun(Ssrc, Ext) -> #rtp{ssrc = Ssrc, ext = Ext} end,
    ?assertMatch({plain, _}, webrtc_media_rid:classify(<<"a">>, Pkt(1, undefined), R0)),
    %% Repair before its source: cannot be bound yet.
    ?assertMatch({drop, _}, webrtc_media_rid:classify(<<"v">>, Pkt(9, [{11, <<"h">>}]), R0)),
    %% Zero padding after the value is ignored.
    {{source, <<"h">>}, R1} = webrtc_media_rid:classify(<<"v">>, Pkt(5, [{10, <<"h", 0, 0>>}]), R0),
    %% Learned: later packets need no extension.
    ?assertMatch({{source, <<"h">>}, _}, webrtc_media_rid:classify(<<"v">>, Pkt(5, undefined), R1)),
    ?assertMatch({{repair, 5}, _}, webrtc_media_rid:classify(<<"v">>, Pkt(9, [{11, <<"h">>}]), R1)),
    ?assertMatch({drop, _}, webrtc_media_rid:classify(<<"v">>, Pkt(7, [{10, <<"x">>}]), R1)),
    ?assertMatch({drop, _}, webrtc_media_rid:classify(<<"v">>, Pkt(7, [{12, <<"q">>}]), R1)),
    ?assertMatch({drop, _}, webrtc_media_rid:classify(<<"v">>, Pkt(7, {16#BEDE, <<>>}), R1)),
    ?assertEqual(<<"h">>, webrtc_media_rid:rid(5, R1)),
    ?assertEqual({ok, 5}, webrtc_media_rid:source(<<"v">>, <<"h">>, R1)),
    %% Renegotiation keeps what was learned.
    ?assertEqual(<<"h">>, webrtc_media_rid:rid(5, webrtc_media_rid:configure([], R1))).

sdes_test() ->
    R = webrtc_media_rid:sdes(
        [{1, [{cname, <<"c">>}, {mid, <<"v">>}, {rid, <<"q">>}]},
         {2, [{rid, <<"f">>}]},
         {3, [{mid, <<"v">>}, {rid, <<"zz">>}]},
         {4, [{rid, <<"h">>}]}],
        #{2 => <<"v">>},
        rid_state()
    ),
    ?assertEqual([<<"q">>, <<"f">>, undefined, undefined], [webrtc_media_rid:rid(S, R) || S <- [1, 2, 3, 4]]).

%% RFC 7728 per layer: PAUSE stops one layer, PAUSED answers it, RESUME
%% restarts it; the other layers keep flowing.
layer_pause_test() ->
    {SA0, SB0} = pair(),
    {Out, SA1} = lists:foldl(
        fun(Rid, {Acc, S}) -> {O, S1} = send(Rid, <<"x">>, 1, S), {Acc ++ O, S1} end,
        {[], SA0},
        ?RIDS
    ),
    {SB1, _} = deliver(Out, SB0, 0),
    {ok, Pause, SB2} = webrtc_media:request_pause({<<"0">>, <<"h">>}, pause, 0, SB1),
    {SA2, A1} = deliver(Pause, SA1, 0),
    ?assertEqual([{stream_paused, <<"0">>, <<"h">>}], events(A1)),
    ?assertEqual({error, paused}, webrtc_media:send(<<"0">>, <<"y">>, #{rid => <<"h">>}, 0, SA2)),
    {_, SA3} = send(<<"q">>, <<"y">>, 2, SA2),
    {SB3, A2} = deliver(sends(A1), SB2, 0),
    ?assertEqual([{remote_paused, <<"0">>, <<"h">>}], events(A2)),
    {ok, Resume, SB4} = webrtc_media:request_pause({<<"0">>, <<"h">>}, resume, 0, SB3),
    {SA4, A3} = deliver(Resume, SA3, 0),
    ?assertEqual([{stream_resumed, <<"0">>, <<"h">>}], events(A3)),
    {Again, _} = send(<<"h">>, <<"z">>, 3, SA4),
    {_, A4} = deliver(Again, SB4, 0),
    ?assertMatch([{remote_resumed, <<"0">>, <<"h">>}, {rtp, <<"0">>, <<"h">>, #rtp{payload = <<"z">>}}], events(A4)).

%% RFC 8853 §5.3: a layer the answer marks paused starts paused; the
%% receiver learns its SSRC from SDES and resumes it.
answer_paused_layer_test() ->
    {MA0, MB} = negotiate(),
    [#{send_rids := Layers} = Sec] = MA0,
    MA = [Sec#{send_rids := [L#{paused := R =:= <<"f">>} || #{rid := R} = L <- Layers]}],
    {SA0, SB0} = sessions(MA, MB),
    ?assertEqual({error, paused}, webrtc_media:send(<<"0">>, <<"y">>, #{rid => <<"f">>}, 0, SA0)),
    {_, SA1} = send(<<"q">>, <<"y">>, 1, SA0),
    ?assertEqual({error, unknown_stream}, webrtc_media:request_pause({<<"0">>, <<"f">>}, resume, 0, SB0)),
    {SA2, Report} = webrtc_media:handle_timeout(10000, SA1),
    {SB1, _} = deliver(sends(Report), SB0, 10000),
    {ok, Resume, _} = webrtc_media:request_pause({<<"0">>, <<"f">>}, resume, 10000, SB1),
    {SA3, A} = deliver(Resume, SA2, 10000),
    ?assertEqual([{stream_resumed, <<"0">>, <<"f">>}], events(A)),
    {_, _} = send(<<"f">>, <<"z">>, 2, SA3).
