%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private Media session receive path: SRTP unprotect, demultiplexing to transceivers and
%% simulcast layers, RTX, NACK generation and RTCP processing.
%% Internal module of `webrtc_media'.
%%
%% Its job in the media session is everything that arrives: `rtp_in/4'
%% (SRTP, routing by SSRC, MID, payload type and rid, RTX and FEC
%% repair, statistics, NACK, the frame buffer and the codec plugin) and
%% `rtcp_in/3' (reports, feedback, TMMBR, SR requests, BYE). What it
%% decides to send back (NACK, keyframe requests, TMMBN) goes out through
%% `webrtc_media_out'. Per-SSRC state is bounded by the limits in
%% `webrtc_media.hrl'. The receive path is drawn in docs/ARCHITECTURE.md,
%% "Inside the media session".
-module(webrtc_media_in).

-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include("webrtc_media.hrl").

-export([
    delivery/5,
    expire_idle/2,
    frame_timeouts/2,
    keyframe_feedback/2,
    nack_actions/5,
    sender_by_ssrc/2,
    rtcp_in/3,
    rtp_in/3,
    rtp_in/4
]).

-ifdef(TEST).
-export([path_rtt/2]).
-endif.

rtp_in(Bin, Now, M) ->
    rtp_in(Bin, Now, M, 0).

rtp_in(Bin, Now, M, Ecn) ->
    case webrtc_srtp:unprotect_rtp(Bin, M#media.in) of
        {ok, Plain, In} ->
            M1 = M#media{in = In},
            case webrtc_rtp:decode(Plain, #{extensions => parse}) of
                {ok, #rtp{ssrc = Ssrc, seq = Seq} = Pkt} ->
                    M1b = M1#media{cc = webrtc_cc:ccfb_arrival(Ssrc, Seq, Ecn, Now, M1#media.cc)},
                    {M2a, Acts} = route(Pkt, Now, (twcc_arrival(Pkt, Now, M1b))#media{raw = Plain}),
                    M2 = M2a#media{raw = undefined},
                    %% Header and padding bytes of a stream we receive.
                    M3 = case maps:is_key(Ssrc, M2#media.receivers) of
                             true -> webrtc_media_out:scount(in, Ssrc, header_bytes_received,
                                                             byte_size(Plain) - byte_size(Pkt#rtp.payload), M2);
                             false -> M2
                         end,
                    {keep_srtp(Ssrc, M3), Acts};
                {error, _} ->
                    {webrtc_media_out:count(dropped, M1), []}
            end;
        {error, _} ->
            {webrtc_media_out:count(srtp_rejected, M), []}
    end.

%% Transport-wide sequence numbers are recorded for every authenticated
%% packet, before demultiplexing.
twcc_arrival(#rtp{ext = Ext, ssrc = Ssrc}, Now, #media{twcc_ids = [_ | _] = Ids} = M) when is_list(Ext) ->
    Found = [S || Id <- Ids, {ok, B} <- [webrtc_rtp_ext:find(Id, Ext)], {ok, S} <- [webrtc_rtp_ext:decode_twcc_seq(B)]],
    case Found of
        [Seq | _] -> M#media{cc = webrtc_cc:arrival(Seq, Ssrc, Now, M#media.cc)};
        [] -> M
    end;
twcc_arrival(_Pkt, _Now, M) ->
    M.

%% SRTP keeps receive state only for SSRCs whose packets were accepted.
keep_srtp(Ssrc, #media{ssrc_mid = SM} = M) when is_map_key(Ssrc, SM) ->
    M;
keep_srtp(Ssrc, M) ->
    M#media{in = webrtc_srtp:forget(Ssrc, M#media.in)}.

route(#rtp{ssrc = Ssrc} = Pkt, Now, M0) ->
    %% RFC 3550 §8.2: the peer uses one of our SSRCs; ours changes.
    {M, Coll} = webrtc_media_out:ssrc_collision(Ssrc, M0),
    {M1, Acts} = route1(Pkt, Now, M),
    {M1, Coll ++ Acts}.

route1(#rtp{ssrc = Ssrc} = Pkt, Now, M) ->
    case find_mid(Pkt, M) of
        undefined ->
            {webrtc_media_out:count(unroutable, M), []};
        Mid ->
            case room_for(Ssrc, Mid, M) of
                false ->
                    {webrtc_media_out:count(too_many_streams, M), []};
                true ->
                    case {maps:find(Ssrc, M#media.rtx_ssrc), is_codec(Mid, Pkt#rtp.pt, <<"flexfec">>, M)} of
                        {_, true} -> flexfec_in(Mid, Pkt, Now, M);
                        {{ok, Primary}, _} -> rtx_in(Mid, Primary, Pkt, Now, M);
                        {error, _} -> layer_in(Mid, Pkt, Now, M)
                    end
            end
    end.

%% A new SSRC is accepted only while the transceiver and the session
%% have room for another receive stream.
room_for(Ssrc, _Mid, #media{ssrc_mid = SM}) when is_map_key(Ssrc, SM) ->
    true;
room_for(_Ssrc, Mid, #media{ssrc_mid = SM}) ->
    map_size(SM) < ?MAX_STREAMS andalso
        length([x || _ := Mi <- SM, Mi =:= Mid]) < ?MAX_MID_STREAMS.

learn(Ssrc, Mid, Now, M) ->
    M#media{ssrc_mid = (M#media.ssrc_mid)#{Ssrc => Mid}, last_seen = (M#media.last_seen)#{Ssrc => Now}}.

%% @doc Forget the receive streams silent for ?RECV_IDLE ms (RFC 3550
%% §6.3.5 times out members; this bounds the state of a peer that keeps
%% changing SSRC).
-spec expire_idle(integer(), #media{}) -> #media{}.
expire_idle(Now, #media{last_seen = Seen} = M) ->
    Idle = [S || S := T <- Seen, Now - T >= ?RECV_IDLE],
    lists:foldl(fun forget/2, M, Idle).

%% Drop all state of a receive stream and of its RTX stream. Its last
%% statistics stay among the ended streams (W3C deletes them only when
%% the receiver drops the stream), at most ?MAX_ENDED.
forget(Ssrc, #media{rtx_ssrc = Rtx} = M0) ->
    M = case maps:find(Ssrc, M0#media.receivers) of
            {ok, R} ->
                %% Its decoder ends with it (webrtc_media_codec terminate/1).
                webrtc_media:plugin_terminate(R#rcv.plugin),
                Info = (webrtc_media:receiver_info(Ssrc, R, M0))#{ended => true},
                Ended = {Ssrc, Info, maps:get({in, Ssrc}, M0#media.streams, #{})},
                M0#media{ended = lists:sublist([Ended | lists:keydelete(Ssrc, 1, M0#media.ended)], ?MAX_ENDED)};
            error ->
                M0
        end,
    Repair = [X || X := P <- Rtx, P =:= Ssrc],
    lists:foldl(
        fun(S, Acc) ->
            Acc#media{
                receivers = maps:remove(S, Acc#media.receivers),
                last_seen = maps:remove(S, Acc#media.last_seen),
                %% Its statistics go too: an ended stream is not reported.
                streams = maps:remove({in, S}, Acc#media.streams),
                ssrc_mid =
                    case maps:find(S, Acc#media.signaled) of
                        {ok, Mid} -> (Acc#media.ssrc_mid)#{S => Mid};
                        error -> maps:remove(S, Acc#media.ssrc_mid)
                    end,
                rtx_ssrc = maps:remove(S, Acc#media.rtx_ssrc),
                pause_req = maps:remove(S, Acc#media.pause_req),
                rids = webrtc_media_rid:forget(S, Acc#media.rids),
                in =
                    case Acc#media.in of
                        undefined -> undefined;
                        In -> webrtc_srtp:forget(S, In)
                    end
            }
        end,
        M,
        [Ssrc | Repair]
    ).

%% Simulcast layers are told apart by rid (RFC 8852); an RTX stream is
%% bound to its layer by repaired-rid and remembered once a packet of it
%% is accepted.
layer_in(Mid, Pkt, Now, M) ->
    case webrtc_media_rid:classify(Mid, Pkt, M#media.rids) of
        {{repair, Primary}, R} ->
            rtx_in(Mid, Primary, Pkt, Now, M#media{rids = R});
        {drop, R} ->
            {webrtc_media_out:count(unknown_rid, M#media{rids = R}), []};
        {_, R} ->
            deliver(Mid, Pkt, Now, M#media{rids = R})
    end.

find_mid(#rtp{ssrc = Ssrc, pt = Pt, ext = Ext}, M) ->
    case maps:find(Ssrc, M#media.ssrc_mid) of
        {ok, Mid} ->
            Mid;
        error ->
            case mid_from_ext(Ext, M) of
                undefined -> maps:get(Pt, M#media.pt_mid, undefined);
                Mid -> Mid
            end
    end.

mid_from_ext(Elems, M) when is_list(Elems) ->
    Found = [
        V
     || {_Mid, Id} <- maps:to_list(M#media.mid_ext), {ok, V} <- [webrtc_rtp_ext:find(Id, Elems)]
    ],
    case Found of
        [V | _] ->
            case maps:is_key(V, M#media.recv) of
                true -> V;
                false -> undefined
            end;
        [] ->
            undefined
    end;
mid_from_ext(_, _) ->
    undefined.

%% Padding-only packets (the sender probing the path) carry nothing to
%% deliver; their transport-wide arrival was already recorded.
rtx_in(_Mid, _Primary, #rtp{payload = <<>>, padding = P}, _Now, M) when P > 0 ->
    {webrtc_media_out:count(padding_received, M), []};
rtx_in(Mid, Primary, Pkt, Now, M) ->
    Sec = maps:get(Mid, M#media.recv),
    Apt = [
        binary_to_integer(A)
     || #{pt := P, name := N, fmtp := F} <- maps:get(recv_codecs, Sec),
        P =:= Pkt#rtp.pt,
        string:lowercase(N) =:= <<"rtx">>,
        {<<"apt">>, A} <- F
    ],
    case Apt of
        [OrigPt] ->
            case webrtc_rtx:decapsulate(Pkt, #{ssrc => Primary, pt => OrigPt}) of
                {ok, Orig} ->
                    M1 = learn(Pkt#rtp.ssrc, Mid, Now, M#media{rtx_ssrc = (M#media.rtx_ssrc)#{Pkt#rtp.ssrc => Primary}}),
                    M2 = webrtc_media_out:scount(in, Primary, retransmitted_packets_received, 1,
                             webrtc_media_out:scount(in, Primary, retransmitted_bytes_received, byte_size(Orig#rtp.payload), M1)),
                    deliver(Mid, Orig, Now, webrtc_media_out:count(rtx_received, webrtc_media_out:sset(in, Primary, #{rtx_ssrc => Pkt#rtp.ssrc}, M2)));
                {error, _} -> {webrtc_media_out:count(dropped, M), []}
            end;
        _ ->
            {webrtc_media_out:count(dropped, M), []}
    end.

%% RED (RFC 2198): the primary block is delivered as the packet it
%% carries; a redundant block only when the packet it repeats was lost
%% (RFC 8854 §7: audio FEC is received and used).
deliver(Mid, #rtp{pt = Pt} = Pkt, Now, M) ->
    case is_red(Mid, Pt, M) of
        true -> red_in(Mid, Pkt, Now, M);
        false -> flexfec_media(Mid, Pkt, Now, M)
    end.

is_codec(Mid, Pt, Name, M) ->
    Codecs = maps:get(recv_codecs, maps:get(Mid, M#media.recv, #{}), []),
    lists:any(fun(#{pt := P, name := N}) -> P =:= Pt andalso string:lowercase(N) =:= Name end, Codecs).

has_codec(Mid, Name, M) ->
    Codecs = maps:get(recv_codecs, maps:get(Mid, M#media.recv, #{}), []),
    lists:any(fun(#{name := N}) -> string:lowercase(N) =:= Name end, Codecs).

%% FlexFEC (RFC 8627): a source packet, its bytes as received, goes to the
%% stream's recovery when the transceiver negotiated FlexFEC.
flexfec_media(Mid, #rtp{ssrc = Ssrc, seq = Seq} = Pkt, Now, #media{raw = Raw} = M) when is_binary(Raw) ->
    case has_codec(Mid, <<"flexfec">>, M) andalso Raw of
        <<_:16, Seq:16, _:32, Ssrc:32, _/binary>> ->
            case seen(Ssrc, Seq, M) of
                true ->
                    {webrtc_media_out:count(fec_duplicate, M), []};
                false ->
                    {M1, A1} = deliver1(Mid, Pkt, Now, M),
                    {M2, A2} = fec_step(Mid, Ssrc, fun(F) -> webrtc_ulpfec:media(Seq, Raw, F) end, Now, M1),
                    {M2, A1 ++ A2}
            end;
        _ ->
            deliver1(Mid, Pkt, Now, M)
    end;
flexfec_media(Mid, Pkt, Now, M) ->
    deliver1(Mid, Pkt, Now, M).

%% A FlexFEC repair packet: the stream it protects is its CSRC (§4.2.1).
flexfec_in(Mid, #rtp{ssrc = FecSsrc, csrcs = Csrcs, payload = P}, Now, M0) ->
    M = learn(FecSsrc, Mid, Now, M0),
    case webrtc_flexfec:decode(P, length(Csrcs)) of
        {ok, #{blocks := [Block]} = F} when length(Csrcs) =:= 1 ->
            [Ssrc] = Csrcs,
            case maps:is_key(Ssrc, M#media.receivers) of
                true ->
                    M1 = webrtc_media_out:sset(in, Ssrc, #{fec_ssrc => FecSsrc}, M),
                    fec_step(Mid, Ssrc, fun(Rx) -> webrtc_ulpfec:repair({Ssrc, Block, F, byte_size(P)}, Rx) end, Now, M1);
                false ->
                    {webrtc_media_out:count(fec_unknown_source, M), []}
            end;
        {ok, _} ->
            %% Several protected SSRCs: not recovered here.
            {webrtc_media_out:count(fec_multi_source, M), []};
        {retransmission, Bin} ->
            case webrtc_rtp:decode(Bin, #{extensions => parse}) of
                {ok, #rtp{ssrc = S, seq = Sq} = Src} ->
                    case maps:is_key(S, M#media.receivers) andalso not seen(S, Sq, M) of
                        true -> deliver1(Mid, Src, Now, webrtc_media_out:count(fec_retransmission, M));
                        false -> {M, []}
                    end;
                {error, _} ->
                    {webrtc_media_out:count(dropped, M), []}
            end;
        {error, _} ->
            {webrtc_media_out:count(dropped, M), []}
    end.

is_red(Mid, Pt, M) ->
    Codecs = maps:get(recv_codecs, maps:get(Mid, M#media.recv, #{}), []),
    lists:any(fun(#{pt := P, name := N}) -> P =:= Pt andalso string:lowercase(N) =:= <<"red">> end, Codecs).

red_in(Mid, Red, Now, M0) ->
    M = webrtc_media_out:count(red_received, M0),
    Codecs0 = maps:get(recv_codecs, maps:get(Mid, M#media.recv, #{}), []),
    Ulp = [P || #{pt := P, name := N} <- Codecs0, string:lowercase(N) =:= <<"ulpfec">>],
    case {webrtc_red:decode(Red#rtp.payload), Ulp} of
        {{ok, [{P, 0, Data}]}, [P]} ->
            %% An FEC packet (RFC 8854 §5.2).
            fec_packet(Mid, Red, Data, Now, M);
        {{ok, [{P, 0, Data}]}, [_]} ->
            %% Media in RED, protected by ULPFEC.
            fec_media(Mid, Red, P, Data, Now, M);
        {Decoded, _} ->
            red_in1(Mid, Red, Decoded, Now, M)
    end.

red_in1(Mid, #rtp{ssrc = Ssrc} = Red, Decoded, Now, M) ->
    case Decoded of
        {ok, Blocks} ->
            Codecs = maps:get(recv_codecs, maps:get(Mid, M#media.recv, #{}), []),
            Known = fun(P) -> lists:any(fun(#{pt := X, name := N}) -> X =:= P andalso not webrtc_media_out:is_repair(N) end, Codecs) end,
            Recent = case maps:find(Ssrc, M#media.receivers) of {ok, #rcv{recent = Rc}} -> Rc; error -> [] end,
            {Repaired, Primary} = webrtc_red:repair(Red, Blocks, Known, Recent),
            M1 = webrtc_media_out:count(red_recovered, length(Repaired), M),
            lists:foldl(fun(P, {Acc, A}) -> {Acc1, A1} = deliver1(Mid, P, Now, Acc), {Acc1, A ++ A1} end,
                        {M1, []}, Repaired ++ Primary);
        {error, _} ->
            {webrtc_media_out:count(dropped, M), []}
    end.

%% ULPFEC (RFC 5109) inside RED: the media packet, as its sender
%% protected it (its own payload type, the RED header left out), goes
%% to the stream's recovery; the packets it recovers follow it.
fec_media(Mid, #rtp{ssrc = Ssrc, seq = Seq, padding = 0} = Red, Pt, Data, Now, #media{raw = Raw} = M)
  when is_binary(Raw) ->
    case seen(Ssrc, Seq, M) of
        true ->
            {webrtc_media_out:count(fec_duplicate, M), []};
        false ->
            {M1a, A1} = deliver1(Mid, Red#rtp{pt = Pt, payload = Data}, Now, M),
            %% The RTP payload counted as sent: the RED header too.
            M1 = webrtc_media_out:scount(in, Ssrc, bytes_received, byte_size(Red#rtp.payload) - byte_size(Data), M1a),
            %% The bytes kept are this packet's (not an RTX packet's).
            HdrLen = byte_size(Raw) - byte_size(Red#rtp.payload),
            case Raw of
                <<B0, Mk:1, _:7, Seq:16, _:32, Ssrc:32, _/binary>> when HdrLen >= 12 ->
                    <<_:16, HRest:(HdrLen - 2)/binary, _/binary>> = Raw,
                    {M2, A2} = fec_step(Mid, Ssrc,
                                        fun(F) -> webrtc_ulpfec:media(Seq, <<B0, Mk:1, Pt:7, HRest/binary, Data/binary>>, F) end,
                                        Now, M1),
                    {M2, A1 ++ A2};
                _ ->
                    {M1, A1}
            end
    end;
fec_media(Mid, Red, Pt, Data, Now, M) ->
    deliver1(Mid, Red#rtp{pt = Pt, payload = Data}, Now, M).

fec_packet(Mid, #rtp{ssrc = Ssrc, seq = Seq, ts = Ts} = Pkt, Data, Now, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, R0} ->
            %% A packet of the stream all the same: counted, not missing
            %% for NACK, no gap for the frame buffer.
            {_, Rx} = webrtc_rtp_stats:rx_packet(Seq, Ts, Now, R0#rcv.rx),
            {Nack, NackActions} = case R0#rcv.nack of
                                      undefined -> {undefined, []};
                                      N -> webrtc_nack:packet(Seq, Now, N)
                                  end,
            M1 = webrtc_media_out:scount(in, Ssrc, packets_received, 1,
                     webrtc_media_out:scount(in, Ssrc, bytes_received, byte_size(Pkt#rtp.payload),
                         M#media{receivers = (M#media.receivers)#{Ssrc := R0#rcv{rx = Rx, nack = Nack}}})),
            {A0, M2} = nack_actions(Mid, Ssrc, NackActions, Now, M1),
            {A1, M3} = frames(Mid, Ssrc, fun(Fb) -> webrtc_frame_buffer:padding(Seq, Now, Fb) end, Now, M2),
            {M4, A2} = fec_step(Mid, Ssrc, fun(F) -> webrtc_ulpfec:fec({Ssrc, Data}, F) end, Now, M3),
            {M4, A0 ++ A1 ++ A2};
        error ->
            {webrtc_media_out:count(dropped, M), []}
    end.

fec_step(Mid, Ssrc, Fun, Now, M) ->
    R = maps:get(Ssrc, M#media.receivers),
    F0 = case R#rcv.fec of undefined -> webrtc_ulpfec:new(); F -> F end,
    {Recovered, F1} = Fun(F0),
    M1 = M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{fec = F1}}},
    lists:foldl(
        fun(Bin, {MA, Acc}) ->
            case webrtc_rtp:decode(Bin, #{extensions => parse}) of
                {ok, #rtp{seq = S} = Pkt} ->
                    case seen(Ssrc, S, MA) of
                        true -> {MA, Acc};
                        false ->
                            {MB, A} = deliver1(Mid, Pkt, Now, webrtc_media_out:count(fec_recovered, MA), recovered),
                            {MB, Acc ++ A}
                    end;
                {error, _} ->
                    {MA, Acc}
            end
        end,
        {M1, []},
        Recovered
    ).

seen(Ssrc, Seq, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, #rcv{recent = Recent}} -> lists:keymember(Seq, 1, Recent);
        error -> false
    end.

deliver1(Mid, Pkt, Now, M) ->
    deliver1(Mid, Pkt, Now, M, received).

%% A packet recovered by FEC is not one received: it stays out of the
%% reception statistics and the loss the receiver reports (as in
%% libwebrtc), so the sender keeps protecting the stream.
deliver1(Mid, #rtp{ssrc = Ssrc, seq = Seq, ts = Ts} = Pkt, Now, Mx, How) ->
    {R0, M} =
        case maps:find(Ssrc, Mx#media.receivers) of
            {ok, R} -> {R, Mx};
            error -> {new_receiver(Mid, Ssrc, Pkt#rtp.pt, Mx), replaced(Mid, Ssrc, Mx)}
        end,
    Rx = case How of
             received -> element(2, webrtc_rtp_stats:rx_packet(Seq, Ts, Now, R0#rcv.rx));
             recovered -> R0#rcv.rx
         end,
    {Nack, NackActions} =
        case R0#rcv.nack of
            undefined -> {undefined, []};
            N -> webrtc_nack:packet(Seq, Now, N)
        end,
    R1 = R0#rcv{rx = Rx, nack = Nack, recent = webrtc_red:seen(Seq, Ts, R0#rcv.recent)},
    M0 = case How of
             received ->
                 webrtc_media_out:sset(in, Ssrc, #{last_packet_received => erlang:system_time(millisecond)},
                     webrtc_media_out:scount(in, Ssrc, packets_received, 1,
                         webrtc_media_out:scount(in, Ssrc, bytes_received, byte_size(Pkt#rtp.payload), M)));
             recovered ->
                 M
         end,
    M1 = webrtc_media_sync:rtp_in(Mid, Pkt, Now,
                                  audio_level(Mid, Pkt, learn(Ssrc, Mid, Now, M0#media{receivers = (M0#media.receivers)#{Ssrc => R1}}))),
    {Out, M2a} = nack_actions(Mid, Ssrc, NackActions, Now, M1),
    {M2, PauseEvents} = webrtc_media_pause:rtp(Ssrc, M2a),
    case Pkt of
        #rtp{payload = <<>>, padding = P} when P > 0, R1#rcv.frames =/= undefined ->
            %% Padding only (a bandwidth probe when RTX is not negotiated):
            %% its sequence number is no gap for the frame buffer, which
            %% tells the frames of codecs without picture IDs (AV1, H.264)
            %% apart by sequence number alone.
            {FrameOut, M3} = frames(Mid, Ssrc, fun(Fb) -> webrtc_frame_buffer:padding(Seq, Now, Fb) end, Now,
                                    webrtc_media_out:count(padding_received, M2)),
            {M3, PauseEvents ++ FrameOut ++ Out};
        #rtp{payload = <<>>, padding = P} when P > 0 ->
            %% Padding only: it counts for the stream, not for the
            %% application.
            {webrtc_media_out:count(padding_received, M2), PauseEvents ++ Out};
        _ when R1#rcv.frames =/= undefined ->
            %% Frames instead of packets (webrtc_frame_buffer).
            Opts = playout_delay(Mid, Pkt, M2),
            {FrameOut, M3} = frames(Mid, Ssrc, fun(Fb) -> webrtc_frame_buffer:push(Pkt, Now, Opts, Fb) end, Now,
                                    webrtc_media_out:count(rtp_received, M2)),
            {M3, PauseEvents ++ FrameOut ++ Out};
        _ ->
            Event =
                case webrtc_media_rid:rid(Ssrc, M2#media.rids) of
                    undefined -> {rtp, Mid, Pkt};
                    Rid -> {rtp, Mid, Rid, Pkt}
                end,
            {webrtc_media_out:count(rtp_received, M2), PauseEvents ++ [{event, Event} | Out]}
    end.

%% The RFC 6464 level of an audio packet, when negotiated: W3C
%% audioLevel (linear, 1.0 for 0 dBov), totalAudioEnergy (the level
%% squared times the packet's duration) and totalSamplesDuration.
audio_level(Mid, #rtp{ext = Ext, ssrc = Ssrc, pt = Pt, payload = P}, M) when is_list(Ext) ->
    Sec = maps:get(Mid, M#media.recv, #{}),
    case maps:get(recv_extensions, Sec, #{}) of
        #{?URI_AUDIO_LEVEL := Id} ->
            case {webrtc_rtp_ext:find(Id, Ext), duration(Pt, P, maps:get(recv_codecs, Sec, []))} of
                {{ok, B}, {ok, D}} ->
                    case webrtc_rtp_ext:decode_audio_level(B) of
                        {ok, {_, Dbov}} ->
                            L = math:pow(10, -Dbov / 20),
                            S = maps:get({in, Ssrc}, M#media.streams, #{}),
                            M#media{streams = (M#media.streams)#{{in, Ssrc} => S#{
                                audio_level => L,
                                total_audio_energy => maps:get(total_audio_energy, S, 0.0) + L * L * D,
                                total_samples_duration => maps:get(total_samples_duration, S, 0.0) + D}}};
                        _ ->
                            M
                    end;
                _ ->
                    M
            end;
        _ ->
            M
    end;
audio_level(_Mid, _Pkt, M) ->
    M.

%% Seconds of audio in a payload: Opus from its TOC byte (RFC 6716
%% §3.1), G.711 and G.722 from their size (8000 bytes a second).
duration(Pt, P, Codecs) ->
    case [string:lowercase(N) || #{pt := X, name := N} <- Codecs, X =:= Pt] of
        [<<"opus">> | _] ->
            case webrtc_rtp_opus:duration(P) of
                {ok, Samples} -> {ok, Samples / 48000};
                _ -> error
            end;
        [N | _] when N =:= <<"pcmu">>; N =:= <<"pcma">>; N =:= <<"g722">> ->
            {ok, byte_size(P) / 8000};
        _ ->
            error
    end.

%% The playout-delay extension, when negotiated and carried.
playout_delay(Mid, #rtp{ext = Ext}, M) when is_list(Ext) ->
    case maps:get(recv_extensions, maps:get(Mid, M#media.recv, #{}), #{}) of
        #{?URI_PLAYOUT_DELAY := Id} ->
            case webrtc_rtp_ext:find(Id, Ext) of
                {ok, B} ->
                    case webrtc_rtp_ext:decode_playout_delay(B) of
                        {ok, Pd} -> #{playout_delay => Pd};
                        _ -> #{}
                    end;
                _ ->
                    #{}
            end;
        _ ->
            #{}
    end;
playout_delay(_Mid, _Pkt, _M) ->
    #{}.

%% Run `Fun' on the stream's frame buffer: frames become events, key
%% frame requests feedback.
frames(Mid, Ssrc, Fun, Now, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, #rcv{frames = Fb0} = R} when Fb0 =/= undefined ->
            {Actions, Fb} = Fun(Fb0),
            M1 = M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{frames = Fb}}},
            Rid = webrtc_media_rid:rid(Ssrc, M1#media.rids),
            {Events, M1a} = lists:foldl(
                fun({frame, F0}, {Acc, MA}) ->
                        %% RFC 6051: the capture time on the sender's clock.
                        {F, MA0} = case webrtc_media_sync:ntp_time(Ssrc, maps:get(timestamp, F0), MA) of
                                       undefined -> {F0, MA};
                                       NtpUs -> {F0#{ntp_time => NtpUs},
                                                 webrtc_media_out:sset(in, Ssrc, #{playout_ntp => {NtpUs, erlang:system_time(microsecond)}}, MA)}
                                   end,
                        Ev = {event, case Rid of
                                         undefined -> {frame, Mid, F};
                                         _ -> {frame, Mid, Rid, F}
                                     end},
                        {Decoded, MB} = decode(Mid, Ssrc, F, MA0),
                        {Acc ++ [Ev | Decoded], MB};
                   ({plugin_feedback, _} = Pf, {Acc, MA}) ->
                        {Acc ++ [Pf], MA};
                   (_, Acc) ->
                        Acc
                end,
                {[], M1},
                Actions
            ),
            {PluginFb, Events1} = lists:partition(fun(E) -> element(1, E) =:= plugin_feedback end, Events),
            Fbs = lists:append([F || {plugin_feedback, F} <- PluginFb]),
            Keyframe = [request_keyframe || lists:member(keyframe_request, Fbs)],
            Loss = webrtc_media_fb:packets(Ssrc, [F || F <- Fbs, F =/= keyframe_request], M1a),
            {Sent, M1b} = webrtc_media_out:send_feedback(Loss, Now, M1a),
            frames_feedback(Actions ++ Keyframe, Ssrc, Events1 ++ Sent, Now, M1b);
        _ ->
            {[], M}
    end.

frames_feedback(Actions, Ssrc, Events, Now, M1) ->
            case lists:member(request_keyframe, Actions) of
                true ->
                    {Fb1, M2} = keyframe_feedback(Ssrc, M1),
                    {Sent, M3} = webrtc_media_out:send_feedback(Fb1, Now, M2),
                    {Events ++ Sent, M3};
                false ->
                    {Events, M1}
            end.

%% The transceiver's codec plugin decodes the frame (webrtc_media_codec):
%% its outputs become events, its statistics the stream's.
decode(Mid, Ssrc, #{codec := Name} = F, M0) ->
    Sec = maps:get(Mid, M0#media.recv, #{}),
    R = maps:get(Ssrc, M0#media.receivers),
    case {maps:get(codec_plugin, Sec, undefined), R#rcv.plugin} of
        {undefined, _} ->
            {[], M0};
        {_, {off, _}} ->
            {[], M0};
        {{Mod, Opts}, Plugin} ->
            Started =
                case Plugin of
                    {Mod, St, Name} ->
                        {ok, St, R#rcv.plugin_ref};
                    _ ->
                        %% Another codec now: the previous decoder ends.
                        webrtc_media:plugin_terminate(Plugin),
                        Codec = hd([C || #{name := N} = C <- maps:get(recv_codecs, Sec, []), N =:= Name] ++ [#{name => Name}]),
                        Ref = make_ref(),
                        case webrtc_media:plugin_init(Mod, maps:get(kind, Sec, video), Codec, Opts, {in, Ssrc, Ref}) of
                            {ok, St} -> {ok, St, Ref};
                            {error, _} = E -> E
                        end
                end,
            case Started of
                {ok, St0, Ref0} ->
                    M = set_ref(Ssrc, Ref0, M0),
                    case webrtc_media:plugin_call(fun() -> Mod:decode(F, St0) end) of
                        {ok, Outs, Stats, St1} ->
                            decoded(Mid, Ssrc, Mod, Name, Outs, Stats, St1, [], M);
                        {ok, Outs, Stats, St1, Feedback} when is_list(Feedback) ->
                            %% Loss the decoder found, to send (RFC 8834 §5.1.3, §5.1.4).
                            decoded(Mid, Ssrc, Mod, Name, Outs, Stats, St1, Feedback, M);
                        {error, _Reason, St1} ->
                            %% Recoverable: this frame is dropped, the
                            %% plugin goes on (webrtc_media_codec).
                            {[], webrtc_media:report_stream(in, Ssrc, inbound, #{framesDropped => 1},
                                                            set_plugin(Ssrc, {Mod, St1, Name}, M))};
                        {error, Reason} ->
                            webrtc_media:plugin_terminate({Mod, St0, Name}),
                            {[{event, {codec_plugin_error, Mid, Reason}}], set_plugin(Ssrc, {off, Reason}, M)}
                    end;
                {error, Reason} ->
                    {[{event, {codec_plugin_error, Mid, Reason}}], set_plugin(Ssrc, {off, Reason}, M0)}
            end
    end.

set_ref(Ssrc, Ref, M) ->
    R = maps:get(Ssrc, M#media.receivers),
    M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{plugin_ref = Ref}}}.

%% @doc What an asynchronous decoder delivers (webrtc_media_codec): its
%% outputs and statistics, or feedback for the remote encoder. Dropped
%% and counted when the instance `Ref' no longer runs on the stream.
-spec delivery(non_neg_integer(), reference(), term(), integer(), #media{}) -> {list(), #media{}}.
delivery(Ssrc, Ref, Msg, Now, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, #rcv{plugin = {Mod, St, Name}, plugin_ref = Ref, mid = Mid}} ->
            case Msg of
                {decoded, Outs, Stats} when is_list(Outs), is_map(Stats) ->
                    decoded(Mid, Ssrc, Mod, Name, Outs, Stats, St, [], M);
                {decoder_feedback, Fbs} when is_list(Fbs) ->
                    decoder_feedback(Ssrc, Fbs, Now, M);
                _ ->
                    {[], webrtc_media_out:count(codec_deliveries_rejected, M)}
            end;
        _ ->
            {[], webrtc_media_out:count(codec_deliveries_stale, M)}
    end.

%% Feedback a decoder found, as decode/2's fifth element carries it: a
%% key frame request, and the loss indications the stream negotiated.
decoder_feedback(Ssrc, Fbs, Now, M) ->
    Loss = webrtc_media_fb:packets(Ssrc, [F || F <- Fbs, F =/= keyframe_request], M),
    {Sent, M1} = webrtc_media_out:send_feedback(Loss, Now, M),
    frames_feedback([request_keyframe || lists:member(keyframe_request, Fbs)], Ssrc, Sent, Now, M1).

decoded(Mid, Ssrc, Mod, Name, Outs, Stats, St1, Feedback, M) ->
    M1 = set_plugin(Ssrc, {Mod, St1, Name}, M),
    Info = webrtc_media:plugin_info(decoder, Mod, St1),
    {[{event, {decoded, Mid, Out}} || Out <- Outs] ++ [{plugin_feedback, Feedback} || Feedback =/= []],
     webrtc_media:report_stream(in, Ssrc, inbound, maps:merge(Stats, Info), M1)}.

set_plugin(Ssrc, P, M) ->
    R = maps:get(Ssrc, M#media.receivers),
    M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{plugin = P}}}.

%% @doc Frame buffer timers.
-spec frame_timeouts(integer(), #media{}) -> {#media{}, list()}.
frame_timeouts(Now, M) ->
    Due = [{S, Mid} || S := #rcv{frames = Fb, mid = Mid} <- M#media.receivers, due(Fb, Now)],
    lists:foldl(
        fun({Ssrc, Mid}, {Acc, A}) ->
            {A1, Acc1} = frames(Mid, Ssrc, fun(Fb) -> webrtc_frame_buffer:timeout(Now, Fb) end, Now, Acc),
            {Acc1, A ++ A1}
        end,
        {M, []},
        Due
    ).

due(undefined, _Now) -> false;
due(Fb, Now) -> case webrtc_frame_buffer:next_timeout(Fb) of infinity -> false; T -> T =< Now end.

%% @doc The key frame request a stream accepts: PLI (RFC 4585 §6.3.1)
%% when negotiated, otherwise FIR (RFC 5104 §4.3.1) with the next
%% sequence number; none when neither is.
-spec keyframe_feedback(non_neg_integer(), #media{}) -> {list(), #media{}}.
keyframe_feedback(Ssrc, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, #rcv{keyframe = Kf, fir_seq = Seq} = R} ->
            case {lists:member(pli, Kf), lists:member(fir, Kf)} of
                {true, _} ->
                    {[#rtcp_pli{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = Ssrc}], M};
                {false, true} ->
                    {[#rtcp_fir{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = 0, entries = [{Ssrc, Seq}]}],
                     M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{fir_seq = (Seq + 1) band 255}}}};
                _ ->
                    {[], M}
            end;
        error ->
            {[#rtcp_pli{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = Ssrc}], M}
    end.

%% W3C: a new SSRC on the mid (and rid) of an ended stream replaces it,
%% and a recycled SSRC is a new stream: the ended statistics go.
replaced(Mid, Ssrc, M) ->
    Rid = webrtc_media_rid:rid(Ssrc, M#media.rids),
    M#media{ended = [E || {S, I, _} = E <- M#media.ended, S =/= Ssrc,
                          maps:get(mid, I) =/= Mid orelse maps:get(rid, I, undefined) =/= Rid]}.

new_receiver(Mid, Ssrc, Pt, M) ->
    Sec = maps:get(Mid, M#media.recv, #{}),
    Codecs = maps:get(recv_codecs, Sec, []),
    Rate = hd([R || #{pt := P, clock_rate := R} <- Codecs, P =:= Pt] ++ [90000]),
    Has = fun(Type, Param) ->
        lists:any(fun(#{rtcp_fb := Fb}) -> lists:member(#{type => Type, param => Param}, Fb) end, Codecs)
    end,
    Nackable = Has(<<"nack">>, undefined),
    #rcv{
        mid = Mid,
        clock_rate = Rate,
        rx = webrtc_rtp_stats:rx_new(Ssrc, #{clock_rate => Rate, time_unit => 1000}),
        nack =
            case Nackable of
                true -> webrtc_nack:new(#{});
                false -> undefined
            end,
        keyframe = [pli || Has(<<"nack">>, <<"pli">>)] ++ [fir || Has(<<"ccm">>, <<"fir">>)],
        loss_fb = webrtc_media_fb:receiver_kinds(Codecs),
        frames =
            case maps:get(frames, Sec, false) of
                false ->
                    undefined;
                FOpts ->
                    webrtc_frame_buffer:new(FOpts#{
                        kind => maps:get(kind, Sec, video),
                        clock_rate => Rate,
                        nack => Nackable,
                        codecs => [C || #{name := N} = C <- Codecs, not webrtc_media_out:is_repair(N)]
                    })
            end
    }.

nack_actions(_Mid, _Ssrc, [], _Now, M) ->
    {[], M};
nack_actions(Mid, Ssrc, Actions, Now, M0) ->
    %% Packets NACK gave up on: the frame buffer stops waiting for them.
    {FrameOut, M} =
        case [S || {give_up, Seqs} <- Actions, S <- Seqs] of
            [] -> {[], M0};
            Lost -> frames(Mid, Ssrc, fun(Fb) -> webrtc_frame_buffer:lost(Lost, Now, Fb) end, Now, M0)
        end,
    {Pkts, M1} = lists:foldl(
        fun
            ({nack, Seqs}, {Acc, MA}) ->
                {Acc ++ [#rtcp_nack{
                    sender_ssrc = MA#media.rtcp_ssrc,
                    media_ssrc = Ssrc,
                    items = webrtc_rtcp_fb:nack_items(Seqs)
                }], MA};
            (request_keyframe, {Acc, MA}) ->
                {Kf, MA1} = keyframe_feedback(Ssrc, MA),
                {Acc ++ Kf, MA1};
            ({give_up, _}, Acc) ->
                Acc
        end,
        {[], M},
        Actions
    ),
    {Out, M2} = webrtc_media_out:send_feedback(Pkts, Now, M1),
    {FrameOut ++ Out, M2}.

rtcp_in(Bin, Now, M) ->
    case webrtc_srtp:unprotect_rtcp(Bin, M#media.in) of
        {ok, Plain, In} ->
            case webrtc_rtcp:decode(Plain) of
                {ok, Pkts} ->
                    lists:foldl(
                        fun(P, {Acc, Act}) ->
                            {Acc1, A} = rtcp_packet(P, Now, Acc),
                            {Acc1, Act ++ A}
                        end,
                        {webrtc_media_out:count(rtcp_received, M#media{in = In}), []},
                        Pkts
                    );
                {error, _} ->
                    {webrtc_media_out:count(dropped, M#media{in = In}), []}
            end;
        {error, _} ->
            {webrtc_media_out:count(srtp_rejected, M), []}
    end.

%% Feedback is counted on our stream it names; feedback about another
%% SSRC only in one counter, so a peer cannot grow our state.
rtcp_packet(#rtcp_nack{media_ssrc = Ssrc, items = Items}, Now, M) ->
    case sender_by_ssrc(Ssrc, M) of
        {ok, S} -> webrtc_media_out:retransmit(S, webrtc_rtcp_fb:nack_seqs(Items), Now,
                                               webrtc_media_out:scount(out, Ssrc, nack_count, 1, M));
        error -> {webrtc_media_out:count(feedback_unknown_ssrc, M), []}
    end;
rtcp_packet(#rtcp_pli{media_ssrc = Ssrc}, _Now, M) ->
    keyframe(Ssrc, pli_count, M);
rtcp_packet(#rtcp_fir{entries = Entries}, _Now, M) ->
    lists:foldl(
        fun({Ssrc, _}, {Acc, Act}) ->
            {Acc1, A} = keyframe(Ssrc, fir_count, Acc),
            {Acc1, Act ++ A}
        end,
        {M, []},
        Entries
    );
rtcp_packet(#rtcp_sr{ssrc = Ssrc} = SR, Now, M0) ->
    {M, Coll} = webrtc_media_out:ssrc_collision(Ssrc, webrtc_media_limit:touch(Ssrc, Now, M0)),
    {M1, Acts} = sender_report(SR, Now, M),
    {M1, Coll ++ Acts};
rtcp_packet(#rtcp_sdes{chunks = Chunks}, _Now, M) ->
    {M#media{rids = webrtc_media_rid:sdes(Chunks, M#media.ssrc_mid, M#media.rids)}, []};
rtcp_packet(#rtcp_rr{ssrc = Ssrc, reports = Rbs}, Now, M0) ->
    {M, Coll} = webrtc_media_out:ssrc_collision(Ssrc, webrtc_media_limit:touch(Ssrc, Now, M0)),
    {M1, Acts} = report_blocks(Rbs, Now, M),
    {M1, Coll ++ Acts};
rtcp_packet(Other, Now, M) ->
    rtcp_packet2(Other, Now, M).

sender_report(#rtcp_sr{ssrc = Ssrc, reports = Rbs} = SR, Now, M0) ->
    case maps:find(Ssrc, M0#media.receivers) of
        {ok, R} ->
            %% The remote outbound stream (W3C RTCRemoteOutboundRtpStreamStats),
            %% for a stream we receive only.
            M = webrtc_media_out:scount(in, Ssrc, reports_received, 1, webrtc_media_out:sset(in, Ssrc, #{
                remote_packets_sent => SR#rtcp_sr.packets,
                remote_bytes_sent => SR#rtcp_sr.octets,
                remote_timestamp => webrtc_rtp_stats:ntp_to_us(SR#rtcp_sr.ntp) div 1000
            }, M0)),
            Rx = webrtc_rtp_stats:rx_sender_report(SR, Now, R#rcv.rx),
            report_blocks(Rbs, Now, webrtc_media_sync:sr_in(SR, M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{rx = Rx}}}));
        error ->
            report_blocks(Rbs, Now, webrtc_media_out:count(sr_unknown_ssrc, M0))
    end.

%% RFC 3550 §6.6: the source left; its state goes with it.
rtcp_packet2(#rtcp_bye{ssrcs = Ssrcs}, Now, M) ->
    Events = [{event, {bye, maps:get(S, M#media.ssrc_mid, undefined), S}} || S <- Ssrcs],
    %% Their TMMBR limits go too (RFC 5104 §4.2.1.2).
    {M1, Acts} = webrtc_media_limit:bye(Ssrcs, Now, M),
    {lists:foldl(fun forget/2, M1, Ssrcs), Events ++ Acts};
rtcp_packet2(#rtcp_tmmbr{sender_ssrc = From, entries = Entries}, Now, M) ->
    webrtc_media_limit:tmmbr(From, Entries, Now, webrtc_media_limit:touch(From, Now, M));
rtcp_packet2(#rtcp_srreq{} = P, Now, M) ->
    webrtc_media_sync:srreq(P, Now, M);
rtcp_packet2(P, _Now, M) when is_record(P, rtcp_sli); is_record(P, rtcp_rpsi) ->
    webrtc_media_fb:received(P, M);
rtcp_packet2(#rtcp_tmmbn{} = N, _Now, M) ->
    {webrtc_media_limit:tmmbn(N, M), []};
rtcp_packet2(#rtcp_xr{ssrc = From, blocks = Blocks}, _Now, M) ->
    {lists:foldl(fun(B, Acc) -> xr_block(From, B, Acc) end, M, Blocks), []};
rtcp_packet2(#rtcp_pause{} = P, Now, M) ->
    webrtc_media_pause:rtcp(P, Now, M);
rtcp_packet2(P, Now, M0) when is_record(P, rtcp_remb); is_record(P, rtcp_twcc); is_record(P, rtcp_ccfb) ->
    M = case P of #rtcp_ccfb{} -> webrtc_media_out:count(ccfb_received, M0); _ -> M0 end,
    {Events, Cc} = webrtc_cc:rtcp(P, Now, M#media.cc),
    {M#media{cc = Cc}, [{event, {rtcp, undefined, P}} | [{event, E} || E <- Events]]};
rtcp_packet2(_P, _Now, M) ->
    {M, []}.

%% RFC 3611 §4.4: a Receiver Reference Time to answer (at most 16
%% sources kept). §4.5: the answer to ours, whose round trip is that of
%% every stream we receive (W3C remote-outbound-rtp roundTripTime).
xr_block(From, {rrtr, Ntp}, #media{xr_rrtr = Got} = M) when map_size(Got) < 16; is_map_key(From, Got) ->
    M#media{xr_rrtr = Got#{From => {webrtc_rtp_stats:ntp_middle(Ntp), erlang:system_time(microsecond)}}};
xr_block(_From, {dlrr, Subs}, M) ->
    Ours = [M#media.rtcp_ssrc | [S || #snd{ssrc = S} <- maps:values(M#media.senders)]],
    Arrival = webrtc_rtp_stats:ntp_from_us(erlang:system_time(microsecond)),
    case [Us || {S, Lrr, D} <- Subs, lists:member(S, Ours), {ok, Us} <- [webrtc_rtp_stats:rtt(Lrr, D, Arrival)]] of
        [Us | _] ->
            Rtt = Us div 1000,
            lists:foldl(
                fun(Ssrc, Acc) ->
                    webrtc_media_out:scount(in, Ssrc, remote_rtt_measurements, 1,
                        webrtc_media_out:scount(in, Ssrc, remote_total_rtt, Rtt,
                            webrtc_media_out:sset(in, Ssrc, #{remote_rtt => Rtt}, Acc)))
                end,
                M,
                maps:keys(M#media.receivers)
            );
        [] ->
            M
    end;
xr_block(_From, _Block, M) ->
    M.

%% Report blocks about our streams feed the circuit breakers and the
%% loss-based estimate (RFC 8083, draft-ietf-rmcat-gcc §6).
report_blocks(Rbs, Now, M) ->
    Arrival = webrtc_rtp_stats:ntp_from_us(erlang:system_time(microsecond)),
    lists:foldl(
        fun(#rtcp_rb{ssrc = Ssrc, lsr = Lsr, dlsr = Dlsr} = Rb, {M1, Acts}) ->
            case sender_by_ssrc(Ssrc, M1) of
                {ok, #snd{mid = Mid}} ->
                    Rtt =
                        case webrtc_rtp_stats:rtt(Lsr, Dlsr, Arrival) of
                            {ok, Us} -> Us div 1000;
                            undefined -> undefined
                        end,
                    %% RFC 6051 §3.3: a non-zero LSR means the peer has an SR.
                    M1a = case Lsr of 0 -> M1; _ -> webrtc_media_sync:acked(Ssrc, M1) end,
                    M1b = path_rtt(Rtt, M1a),
                    {Events, Cc} = webrtc_cc:report(Mid, Rb, Rtt, Now, M1b#media.cc),
                    M2 = remote_inbound(Rb, Rtt, M1b#media{cc = Cc}),
                    {M2, Acts ++ [{event, E} || E <- Events]};
                error ->
                    {M1, Acts}
            end
        end,
        {M, []},
        Rbs
    ).

%% What the peer reports of one of our streams (W3C
%% RTCRemoteInboundRtpStreamStats); the round trip time in ms.
remote_inbound(#rtcp_rb{ssrc = Ssrc} = Rb, Rtt, M) ->
    M1 = webrtc_media_out:sset(out, Ssrc, #{
        remote_fraction_lost => Rb#rtcp_rb.fraction_lost,
        remote_packets_lost => Rb#rtcp_rb.lost,
        remote_jitter => Rb#rtcp_rb.jitter,
        remote_reports => maps:get(remote_reports, stream(out, Ssrc, M), 0) + 1
    }, M),
    case Rtt of
        undefined ->
            M1;
        _ ->
            webrtc_media_out:scount(out, Ssrc, rtt_measurements, 1,
                webrtc_media_out:scount(out, Ssrc, total_rtt, Rtt,
                    webrtc_media_out:sset(out, Ssrc, #{rtt => Rtt}, M1)))
    end.

stream(Dir, Ssrc, M) -> maps:get({Dir, Ssrc}, M#media.streams, #{}).

%% The path's RTT from a report block (RFC 3550 §6.4.1) paces the NACK
%% requests we repeat (RFC 4585 §3.4) and keeps a packet from being
%% resent twice within one RTT (RFC 4588 §5).
path_rtt(undefined, M) ->
    M;
path_rtt(Rtt, M) ->
    Rs = maps:map(fun(_, #rcv{nack = N, frames = Fb} = R) ->
                          R#rcv{nack = case N of undefined -> N; _ -> webrtc_nack:set_rtt(Rtt, N) end,
                                frames = case Fb of undefined -> Fb; _ -> webrtc_frame_buffer:set_rtt(Rtt, Fb) end}
                  end, M#media.receivers),
    Ss = maps:map(fun(_, S) -> S#snd{buffer = webrtc_nack_buffer:set_rtt(Rtt, S#snd.buffer)} end, M#media.senders),
    M#media{receivers = Rs, senders = Ss}.

keyframe(Ssrc, Counter, M0) ->
    case sender_by_ssrc(Ssrc, M0) of
        {ok, #snd{mid = Mid, rid = Rid}} ->
            M = webrtc_media_out:scount(out, Ssrc, Counter, 1, M0),
            case Rid of
                undefined -> {M, [{event, {keyframe_request, Mid}}]};
                _ -> {M, [{event, {keyframe_request, Mid, Rid}}]}
            end;
        error ->
            {webrtc_media_out:count(feedback_unknown_ssrc, M0), []}
    end.

sender_by_ssrc(Ssrc, M) ->
    case [S || S = #snd{ssrc = X} <- maps:values(M#media.senders), X =:= Ssrc] of
        [S] -> {ok, S};
        [] -> error
    end.
