%% @private Media session receive path: SRTP unprotect, demultiplexing to transceivers and
%% simulcast layers, RTX, NACK generation and RTCP processing.
%% Internal module of `webrtc_media'.
-module(webrtc_media_in).

-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include("webrtc_media.hrl").

-export([
    expire_idle/2,
    nack_actions/5,
    sender_by_ssrc/2,
    rtcp_in/3,
    rtp_in/3,
    rtp_in/4
]).

rtp_in(Bin, Now, M) ->
    rtp_in(Bin, Now, M, 0).

rtp_in(Bin, Now, M, Ecn) ->
    case webrtc_srtp:unprotect_rtp(Bin, M#media.in) of
        {ok, Plain, In} ->
            M1 = M#media{in = In},
            case webrtc_rtp:decode(Plain, #{extensions => parse}) of
                {ok, #rtp{ssrc = Ssrc, seq = Seq} = Pkt} ->
                    M1b = M1#media{cc = webrtc_cc:ccfb_arrival(Ssrc, Seq, Ecn, Now, M1#media.cc)},
                    {M2, Acts} = route(Pkt, Now, twcc_arrival(Pkt, Now, M1b)),
                    {keep_srtp(Ssrc, M2), Acts};
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
                    case maps:find(Ssrc, M#media.rtx_ssrc) of
                        {ok, Primary} -> rtx_in(Mid, Primary, Pkt, Now, M);
                        error -> layer_in(Mid, Pkt, Now, M)
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

%% Drop all state of a receive stream and of its RTX stream.
forget(Ssrc, #media{rtx_ssrc = Rtx} = M) ->
    Repair = [X || X := P <- Rtx, P =:= Ssrc],
    lists:foldl(
        fun(S, Acc) ->
            Acc#media{
                receivers = maps:remove(S, Acc#media.receivers),
                last_seen = maps:remove(S, Acc#media.last_seen),
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
                    deliver(Mid, Orig, Now, webrtc_media_out:count(rtx_received, M1));
                {error, _} -> {webrtc_media_out:count(dropped, M), []}
            end;
        _ ->
            {webrtc_media_out:count(dropped, M), []}
    end.

deliver(Mid, #rtp{ssrc = Ssrc, seq = Seq, ts = Ts} = Pkt, Now, M) ->
    R0 =
        case maps:find(Ssrc, M#media.receivers) of
            {ok, R} -> R;
            error -> new_receiver(Mid, Ssrc, Pkt#rtp.pt, M)
        end,
    {_, Rx} = webrtc_rtp_stats:rx_packet(Seq, Ts, Now, R0#rcv.rx),
    {Nack, NackActions} =
        case R0#rcv.nack of
            undefined -> {undefined, []};
            N -> webrtc_nack:packet(Seq, Now, N)
        end,
    R1 = R0#rcv{rx = Rx, nack = Nack},
    M1 = learn(Ssrc, Mid, Now, M#media{receivers = (M#media.receivers)#{Ssrc => R1}}),
    {Out, M2a} = nack_actions(Mid, Ssrc, NackActions, Now, M1),
    {M2, PauseEvents} = webrtc_media_pause:rtp(Ssrc, M2a),
    Event =
        case webrtc_media_rid:rid(Ssrc, M2#media.rids) of
            undefined -> {rtp, Mid, Pkt};
            Rid -> {rtp, Mid, Rid, Pkt}
        end,
    case Pkt of
        #rtp{payload = <<>>, padding = P} when P > 0 ->
            %% Padding only: it counts for the stream, not for the
            %% application.
            {webrtc_media_out:count(padding_received, M2), PauseEvents ++ Out};
        _ ->
            {webrtc_media_out:count(rtp_received, M2), PauseEvents ++ [{event, Event} | Out]}
    end.

new_receiver(Mid, Ssrc, Pt, M) ->
    Sec = maps:get(Mid, M#media.recv, #{}),
    Codecs = maps:get(recv_codecs, Sec, []),
    Rate = hd([R || #{pt := P, clock_rate := R} <- Codecs, P =:= Pt] ++ [90000]),
    Nackable = lists:any(
        fun(#{rtcp_fb := Fb}) -> lists:member(#{type => <<"nack">>, param => undefined}, Fb) end,
        Codecs
    ),
    #rcv{
        mid = Mid,
        clock_rate = Rate,
        rx = webrtc_rtp_stats:rx_new(Ssrc, #{clock_rate => Rate, time_unit => 1000}),
        nack =
            case Nackable of
                true -> webrtc_nack:new(#{});
                false -> undefined
            end
    }.

nack_actions(_Mid, _Ssrc, [], _Now, M) ->
    {[], M};
nack_actions(Mid, Ssrc, Actions, Now, M) ->
    Pkts = lists:flatmap(
        fun
            ({nack, Seqs}) ->
                [#rtcp_nack{
                    sender_ssrc = M#media.rtcp_ssrc,
                    media_ssrc = Ssrc,
                    items = webrtc_rtcp_fb:nack_items(Seqs)
                }];
            (request_keyframe) ->
                [#rtcp_pli{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = Ssrc}];
            ({give_up, _}) ->
                []
        end,
        Actions
    ),
    _ = Mid,
    webrtc_media_out:send_feedback(Pkts, Now, M).

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

rtcp_packet(#rtcp_nack{media_ssrc = Ssrc, items = Items}, Now, M) ->
    case sender_by_ssrc(Ssrc, M) of
        {ok, S} -> webrtc_media_out:retransmit(S, webrtc_rtcp_fb:nack_seqs(Items), Now, M);
        error -> {M, []}
    end;
rtcp_packet(#rtcp_pli{media_ssrc = Ssrc}, _Now, M) ->
    keyframe(Ssrc, M);
rtcp_packet(#rtcp_fir{entries = Entries}, _Now, M) ->
    lists:foldl(
        fun({Ssrc, _}, {Acc, Act}) ->
            {Acc1, A} = keyframe(Ssrc, Acc),
            {Acc1, Act ++ A}
        end,
        {M, []},
        Entries
    );
rtcp_packet(#rtcp_sr{ssrc = Ssrc} = SR, Now, M0) ->
    {M, Coll} = webrtc_media_out:ssrc_collision(Ssrc, M0),
    {M1, Acts} = sender_report(SR, Now, M),
    {M1, Coll ++ Acts};
rtcp_packet(#rtcp_sdes{chunks = Chunks}, _Now, M) ->
    {M#media{rids = webrtc_media_rid:sdes(Chunks, M#media.ssrc_mid, M#media.rids)}, []};
rtcp_packet(#rtcp_rr{ssrc = Ssrc, reports = Rbs}, Now, M0) ->
    {M, Coll} = webrtc_media_out:ssrc_collision(Ssrc, M0),
    {M1, Acts} = report_blocks(Rbs, Now, M),
    {M1, Coll ++ Acts};
rtcp_packet(Other, Now, M) ->
    rtcp_packet2(Other, Now, M).

sender_report(#rtcp_sr{ssrc = Ssrc, reports = Rbs} = SR, Now, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, R} ->
            Rx = webrtc_rtp_stats:rx_sender_report(SR, Now, R#rcv.rx),
            report_blocks(Rbs, Now, M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{rx = Rx}}});
        error ->
            report_blocks(Rbs, Now, M)
    end.

%% RFC 3550 §6.6: the source left; its state goes with it.
rtcp_packet2(#rtcp_bye{ssrcs = Ssrcs}, _Now, M) ->
    Events = [{event, {bye, maps:get(S, M#media.ssrc_mid, undefined), S}} || S <- Ssrcs],
    {lists:foldl(fun forget/2, M, Ssrcs), Events};
rtcp_packet2(#rtcp_pause{} = P, Now, M) ->
    webrtc_media_pause:rtcp(P, Now, M);
rtcp_packet2(P, Now, M) when is_record(P, rtcp_remb); is_record(P, rtcp_twcc); is_record(P, rtcp_ccfb) ->
    {Events, Cc} = webrtc_cc:rtcp(P, Now, M#media.cc),
    {M#media{cc = Cc}, [{event, {rtcp, undefined, P}} | [{event, E} || E <- Events]]};
rtcp_packet2(_P, _Now, M) ->
    {M, []}.

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
                    {Events, Cc} = webrtc_cc:report(Mid, Rb, Rtt, Now, M1#media.cc),
                    {M1#media{cc = Cc}, Acts ++ [{event, E} || E <- Events]};
                error ->
                    {M1, Acts}
            end
        end,
        {M, []},
        Rbs
    ).

keyframe(Ssrc, M) ->
    case sender_by_ssrc(Ssrc, M) of
        {ok, #snd{mid = Mid, rid = undefined}} -> {M, [{event, {keyframe_request, Mid}}]};
        {ok, #snd{mid = Mid, rid = Rid}} -> {M, [{event, {keyframe_request, Mid, Rid}}]};
        error -> {M, []}
    end.

sender_by_ssrc(Ssrc, M) ->
    case [S || S = #snd{ssrc = X} <- maps:values(M#media.senders), X =:= Ssrc] of
        [S] -> {ok, S};
        [] -> error
    end.
