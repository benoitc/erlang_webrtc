%% @private Media session send path: pacing, transport-wide sequence numbers, SRTP protect,
%% retransmission over RTX and RTCP reports.
%% Internal module of `webrtc_media'.
-module(webrtc_media_out).

-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include("webrtc_media.hrl").

-export([
    cc_timeouts/2,
    count/2,
    count/3,
    scount/5,
    sset/4,
    egress/3,
    mid_ext/1,
    header_ext/2,
    audio_level/2,
    nack_timeouts/2,
    pace/4,
    pick_pt/2,
    is_repair/1,
    red_pt/1,
    fec_wrap/2,
    reports/3,
    retransmit/4,
    send_feedback/3,
    send_rtcp/2,
    senders/2,
    ssrc_collision/2,
    tmin/2
]).

%% One sender per transceiver, or one per negotiated simulcast layer.
senders(#{mid := Mid, send_rids := [_ | _] = Layers} = Sec, Old) ->
    Exts = maps:get(send_extensions, Sec, #{}),
    [
        {{Mid, Rid}, (sender(Sec#{ssrc := S, rtx_ssrc := X, paused => maps:get(paused, L, false)},
                             maps:get({Mid, Rid}, Old, undefined)))#snd{
            rid = Rid,
            rid_ext = maps:get(?URI_RID, Exts, undefined),
            rrid_ext = maps:get(?URI_RRID, Exts, undefined)
        }}
     || #{rid := Rid, ssrc := S, rtx_ssrc := X} = L <- Layers
    ];
senders(#{mid := Mid} = Sec, Old) ->
    [{Mid, sender(Sec, maps:get(Mid, Old, undefined))}].

skey(#snd{mid = Mid, rid = undefined}) -> Mid;
skey(#snd{mid = Mid, rid = Rid}) -> {Mid, Rid}.

sender(#{mid := Mid, kind := K, ssrc := S, rtx_ssrc := R, send_codecs := Cs} = Sec, Old) ->
    Rtx = maps:from_list([
        {binary_to_integer(Apt), Pt}
     || #{name := N, pt := Pt, fmtp := F} <- Cs,
        string:lowercase(N) =:= <<"rtx">>,
        {<<"apt">>, Apt} <- F
    ]),
    SendExt = maps:get(send_extensions, Sec, #{}),
    MidExt = maps:get(?URI_MID, SendExt, undefined),
    AudioLevel = maps:get(?URI_AUDIO_LEVEL, SendExt, undefined),
    TwccExt = maps:get(?URI_TWCC, SendExt, undefined),
    {Pause, HoldOff} = pause(Sec, Old),
    case Old of
        #snd{} -> Old#snd{codecs = Cs, rtx = Rtx, mid_ext = MidExt, twcc_ext = TwccExt, pause = Pause, hold_off = HoldOff,
                          audio_level_ext = AudioLevel, fec_ssrc = maps:get(fec_ssrc, Sec, Old#snd.fec_ssrc)};
        undefined ->
            #snd{
                mid = Mid,
                kind = K,
                ssrc = S,
                rtx_ssrc = R,
                codecs = Cs,
                rtx = Rtx,
                mid_ext = MidExt,
                twcc_ext = TwccExt,
                seq = rand16(),
                rtx_seq = rand16(),
                tx = webrtc_rtp_stats:tx_new(),
                buffer = webrtc_nack_buffer:new(#{size => ?BUFFER_SIZE}),
                pause = Pause,
                hold_off = HoldOff,
                audio_level_ext = AudioLevel,
                fec_ssrc = maps:get(fec_ssrc, Sec, undefined),
                fec_seq = rand16()
            }
    end.

%% RFC 7728: a stream keeps its pause state across renegotiations; a
%% layer the answer marked paused (RFC 8853 §5.3) starts paused.
%% Without nowait the hold-off is 2 * RTT + T_dither_max, 500 ms while
%% no RTT is known.
pause(#{pause := #{nowait := NoWait}} = Sec, Old) ->
    HoldOff = case NoWait of true -> 0; false -> 500 end,
    case Old of
        #snd{pause = P} when P =/= undefined -> {P, HoldOff};
        _ -> {webrtc_rtp_pause:sender(maps:get(paused, Sec, false)), HoldOff}
    end;
pause(_Sec, _Old) ->
    {undefined, 0}.

pick_pt(#{pt := Pt}, #snd{codecs = Cs}) ->
    case [P || #{pt := P} <- Cs, P =:= Pt] of
        [_] -> {ok, Pt};
        [] -> error
    end;
pick_pt(#{codec := Name}, #snd{codecs = Cs}) ->
    case [P || #{pt := P, name := N} <- Cs, string:lowercase(N) =:= string:lowercase(Name)] of
        [P | _] -> {ok, P};
        [] -> error
    end;
pick_pt(_, #snd{codecs = Cs}) ->
    %% The first media codec: an offer may list RED first (RFC 2198).
    case [P || #{pt := P, name := N} <- Cs, not is_repair(N)] of
        [P | _] -> {ok, P};
        [] -> error
    end.

%% @doc Payload formats that carry other packets or their repair.
-spec is_repair(binary()) -> boolean().
is_repair(N) -> lists:member(string:lowercase(N), [<<"rtx">>, <<"red">>, <<"ulpfec">>, <<"flexfec-03">>]).

%% @doc The RED payload type negotiated for sending, if any.
-spec red_pt(#snd{}) -> {ok, 0..127} | error.
red_pt(#snd{codecs = Cs}) ->
    case [P || #{pt := P, name := N} <- Cs, string:lowercase(N) =:= <<"red">>] of
        [P | _] -> {ok, P};
        [] -> error
    end.

%% @doc ULPFEC inside RED (RFC 8854 §5.2, as libwebrtc sends it): a
%% video packet of a sender with both negotiated goes as a RED packet
%% with one block.
-spec fec_wrap(#snd{}, #rtp{}) -> #rtp{}.
fec_wrap(S, #rtp{pt = Pt, payload = P} = Pkt) ->
    case fec_pts(S) of
        {ulp, Red, _} when Pt =/= Red -> Pkt#rtp{pt = Red, payload = <<0:1, Pt:7, P/binary>>};
        _ -> Pkt
    end.

%% The video FEC of a sender: FlexFEC (RFC 8627, the SHOULD of RFC 8854
%% §5.1) on its repair stream when negotiated, otherwise ULPFEC in RED
%% when both are.
fec_pts(#snd{kind = video, codecs = Cs, fec_ssrc = FecSsrc}) ->
    Pt = fun(Name) -> [P || #{pt := P, name := N} <- Cs, string:lowercase(N) =:= Name] end,
    case {Pt(<<"flexfec">>), Pt(<<"red">>), Pt(<<"ulpfec">>)} of
        {[Flex | _], _, _} when is_integer(FecSsrc) -> {flex, Flex};
        {_, [Red | _], [Ulp | _]} -> {ulp, Red, Ulp};
        _ -> undefined
    end;
fec_pts(_) ->
    undefined.

%% The packet as ULPFEC protects it (the media payload type, no RED
%% header), and the media payload for the frame statistics.
unwrap_red(#rtp{pt = Red, payload = <<0:1, Pt:7, Inner/binary>>} = Pkt, {ulp, Red, _}) -> Pkt#rtp{pt = Pt, payload = Inner};
unwrap_red(Pkt, _) -> Pkt.

%% A video packet sent with ULPFEC joins its frame's group; the last
%% packet of the frame sends the FEC packets (RFC 5109) after it.
fec_sent(Key, Pkt, Now, M) ->
    case maps:find(Key, M#media.senders) of
        {ok, #snd{} = S} ->
            case fec_pts(S) of
                undefined ->
                    {[], M};
                Pts ->
                    Media = unwrap_red(Pkt, Pts),
                    Group = [{Media#rtp.seq, webrtc_rtp:encode(Media)} | S#snd.fec_group],
                    case Pkt#rtp.marker of
                        false ->
                            {[], M#media{senders = (M#media.senders)#{Key := S#snd{fec_group = Group}}}};
                        true ->
                            fec_packets(Key, lists:reverse(Group), Pkt#rtp.ts, Pts, Now,
                                        M#media{senders = (M#media.senders)#{Key := S#snd{fec_group = []}}})
                    end
            end;
        error ->
            {[], M}
    end.

fec_packets(Key, Group, Ts, {flex, Flex}, Now, M) ->
    S0 = maps:get(Key, M#media.senders),
    Rate = fec_rate(S0, M),
    Payloads = lists:append([webrtc_flexfec:protect(C, fec_count(length(C), Rate)) || C <- chunk(Group, 110), Rate > 0]),
    %% RFC 8627 §4.2.1: the repair stream's own SSRC and sequence, the
    %% protected SSRC as its CSRC, the time of sending at 90 kHz.
    _ = Ts,
    {Pkts, S1} = lists:mapfoldl(
        fun(P, S) ->
            Pkt = #rtp{ssrc = S#snd.fec_ssrc, pt = Flex, seq = S#snd.fec_seq, ts = (Now * 90) band 16#FFFFFFFF,
                       csrcs = [S#snd.ssrc],
                       ext = mid_ext(S), payload = P},
            {Pkt, S#snd{fec_seq = (S#snd.fec_seq + 1) band 16#FFFF}}
        end,
        S0,
        Payloads
    ),
    M1 = count(fec_sent, length(Pkts), M#media{senders = (M#media.senders)#{Key := S1}}),
    egress([{Key, P, flexfec, Now} || P <- Pkts], Now, M1);
fec_packets(Key, Group, Ts, {ulp, Red, Ulp}, Now, M) ->
    S0 = maps:get(Key, M#media.senders),
    Rate = fec_rate(S0, M),
    Chunks = chunk(Group, 48),
    Payloads = lists:append([webrtc_ulpfec:protect(C, fec_count(length(C), Rate)) || C <- Chunks, Rate > 0]),
    {Pkts, S1} = lists:mapfoldl(
        fun(P, S) ->
            Next = (S#snd.seq + 1) band 16#FFFF,
            Pkt = #rtp{ssrc = S#snd.ssrc, pt = Red, seq = S#snd.seq, ts = Ts, ext = mid_ext(S),
                       payload = <<0:1, Ulp:7, P/binary>>},
            {Pkt, S#snd{seq = Next, cycles = S#snd.cycles + case Next of 0 -> 1; _ -> 0 end}}
        end,
        S0,
        Payloads
    ),
    M1 = count(fec_sent, length(Pkts), M#media{senders = (M#media.senders)#{Key := S1}}),
    egress([{Key, P, fec, Now} || P <- Pkts], Now, M1).

%% `video_fec': a fixed rate, or with `auto' twice the fraction lost the
%% peer reports (RFC 3550 §6.4.2), at most one FEC packet for two.
fec_rate(#snd{ssrc = Ssrc}, #media{video_fec = auto, streams = St}) ->
    Lost = maps:get(remote_fraction_lost, maps:get({out, Ssrc}, St, #{}), 0) / 256,
    min(0.5, 2 * Lost);
fec_rate(_S, #media{video_fec = R}) ->
    R.

fec_count(_N, R) when R =< 0 -> 0;
fec_count(N, R) -> max(1, min(N, ceil(N * R))).

chunk([], _) -> [];
chunk(L, N) when length(L) =< N -> [L];
chunk(L, N) -> {A, B} = lists:split(N, L), [A | chunk(B, N)].

%% Queue packets in the pacer, then protect and send what it releases.
pace(Class, Items, Now, M) ->
    {Out, Cc} = lists:foldl(
        fun({K, P, R}, {Acc, C}) ->
            %% The time it was queued, for totalPacketSendDelay.
            {O, C1} = webrtc_cc:enqueue({Class, wire_size(P), {K, P, R, Now}}, Now, C),
            {Acc ++ O, C1}
        end,
        {[], M#media.cc},
        Items
    ),
    egress(Out, Now, M#media{cc = Cc}).

%% Header, payload and an allowance for extensions and the SRTP tag.
wire_size({raw, Bin}) -> byte_size(Bin);
wire_size(#rtp{payload = P, csrcs = Cs}) -> 12 + 4 * length(Cs) + byte_size(P) + 32.

%% Add the transport-wide sequence number, protect and count.
egress(Items, Now, M0) ->
    {Sends, M} = lists:foldl(
        fun(Item, {Acc, M1}) ->
            {Key, Pkt0, Rtx, Queued} = case Item of {Ki, Pi, Ri} -> {Ki, Pi, Ri, Now}; {_, _, _, _} -> Item end,
            {Twcc, Mid, Kind} =
                case maps:find(Key, M1#media.senders) of
                    {ok, #snd{twcc_ext = Id, mid = Mi, kind = K}} -> {Id, Mi, K};
                    error -> {undefined, Key, undefined}
                end,
            case webrtc_cc:halted(Mid, M1#media.cc) of
                {true, _} ->
                    %% Halted while queued in the pacer (RFC 8083 §4.5).
                    {Acc, count(circuit_breaker_dropped, M1)};
                false when element(1, Pkt0) =:= raw ->
                    %% A retransmission without RTX: the exact bytes sent
                    %% the first time, not protected again.
                    {raw, Srtp} = Pkt0,
                    <<_:16, RSeq:16, _:32, RSsrc:32, _/binary>> = Srtp,
                    Cc = webrtc_cc:sent_rtp(Mid, RSsrc, RSeq, byte_size(Srtp), Now, M1#media.cc),
                    {[out(Srtp, M1) | Acc], sent_stats(Key, Pkt0, Rtx, M1#media{cc = Cc})};
                false ->
                    Pkt = add_twcc(Twcc, webrtc_cc:twcc_seq(M1#media.cc), Pkt0),
                    Plain = webrtc_rtp:encode(Pkt),
                    case webrtc_srtp:protect_rtp(Plain, M1#media.out) of
                        {ok, Srtp, Out} ->
                            %% Circuit breakers work per transceiver: all
                            %% simulcast layers of a mid share the flow.
                            Cc0 = webrtc_cc:sent_rtp(Mid, Pkt#rtp.ssrc, Pkt#rtp.seq, byte_size(Srtp), Now, M1#media.cc),
                            Cc = case Kind of video -> webrtc_cc:video_sent(Now, Cc0); _ -> Cc0 end,
                            M2 = keep_wire(Key, Pkt, Srtp, Rtx, Now, M1#media{out = Out, cc = Cc}),
                            Ssrc = Pkt#rtp.ssrc,
                            M3 = scount(out, Ssrc, header_bytes_sent, byte_size(Plain) - byte_size(Pkt#rtp.payload),
                                        scount(out, Ssrc, total_packet_send_delay_ms, Now - Queued, M2)),
                            {Fec, M4} = case Rtx of
                                            false when Kind =:= video ->
                                                Pts = case maps:find(Key, M3#media.senders) of
                                                          {ok, Sn} -> fec_pts(Sn);
                                                          error -> undefined
                                                      end,
                                                fec_sent(Key, Pkt, Now, frame_sent(Key, unwrap_red(Pkt, Pts), Now, M3));
                                            _ ->
                                                {[], M3}
                                        end,
                            {lists:reverse(Fec, [out(Srtp, M1) | Acc]), sent_stats(Key, Pkt, Rtx, M4)};
                        {error, _} ->
                            {Acc, count(srtp_failed, M1)}
                    end
            end
        end,
        {[], M0},
        Items
    ),
    {lists:reverse(Sends), M}.

%% The frames of a video stream, by marker bit (W3C framesSent,
%% hugeFramesSent: at least 2.5 times the average frame size so far),
%% and the size of its key frames from the bitstream.
frame_sent(Key, #rtp{ssrc = Ssrc, pt = Pt, payload = P, marker = Marker}, Now, M) ->
    S = maps:get({out, Ssrc}, M#media.streams, #{}),
    Size =
        case maps:find(Key, M#media.senders) of
            {ok, #snd{codecs = Cs}} ->
                case [N || #{pt := X, name := N} <- Cs, X =:= Pt] of
                    [Name | _] -> webrtc_frame_codec:payload_size(webrtc_frame_codec:codec(video, Name), P);
                    [] -> error
                end;
            error ->
                error
        end,
    S1 = case Size of
             {ok, {W, H}} -> S#{frame_width => W, frame_height => H};
             error -> S
         end,
    Bytes = maps:get(frame_bytes, S1, 0) + byte_size(P),
    S2 =
        case Marker of
            false ->
                S1#{frame_bytes => Bytes};
            true ->
                Frames = maps:get(frames_sent, S1, 0),
                Total = maps:get(frames_bytes, S1, 0),
                Huge = Frames > 0 andalso Bytes * Frames >= 2.5 * Total,
                S1#{frame_bytes => 0, frames_sent => Frames + 1, frames_bytes => Total + Bytes,
                    huge_frames_sent => maps:get(huge_frames_sent, S1, 0) + case Huge of true -> 1; false -> 0 end,
                    frame_times => [Now | [T || T <- maps:get(frame_times, S1, []), T > Now - 1000]]}
        end,
    M#media{streams = (M#media.streams)#{{out, Ssrc} => S2}}.

%% RTP goes out ECT(0) while ECN is in use (RFC 6679, RFC 8888 §6).
out(Bin, #media{cc = Cc}) ->
    case webrtc_cc:ecn_mark(Cc) of
        true -> {send_ect, Bin};
        false -> {send, Bin}
    end.

add_twcc(undefined, _Seq, Pkt) ->
    Pkt;
add_twcc(_Id, undefined, Pkt) ->
    Pkt;
add_twcc(Id, Seq, #rtp{ext = Ext} = Pkt) ->
    Elems = [E || is_list(Ext), {I, _} = E <- Ext, I =/= Id],
    Pkt#rtp{ext = Elems ++ [{Id, webrtc_rtp_ext:twcc_seq(Seq)}]}.

%% Keep the protected bytes of a first transmission with its packet in
%% the retransmission buffer: without RTX a NACK is answered with them.
%% Protecting the packet again would reuse its SRTP index, which SRTP
%% refuses (it would reuse keystream); the same bytes reuse nothing and
%% the receiver accepts them since it never got that index.
keep_wire(_Key, _Pkt, _Srtp, true, _Now, M) ->
    M;
keep_wire(_Key, _Pkt, _Srtp, flexfec, _Now, M) ->
    %% The repair stream is not retransmitted.
    M;
keep_wire(Key, Pkt, Srtp, fec, Now, M) ->
    keep_wire(Key, Pkt, Srtp, false, Now, M);
keep_wire(Key, #rtp{seq = Seq} = Pkt, Srtp, false, Now, M) ->
    case maps:find(Key, M#media.senders) of
        {ok, S} ->
            Buf = webrtc_nack_buffer:store(Seq, {Pkt, Srtp}, Now, S#snd.buffer),
            M#media{senders = (M#media.senders)#{Key := S#snd{buffer = Buf}}};
        error ->
            M
    end.

sent_stats(Mid, Pkt, true, M) ->
    M1 =
        case maps:find(Mid, M#media.senders) of
            {ok, #snd{ssrc = Ssrc}} ->
                %% Without RTX the first transmission's protected bytes
                %% go again: the packet counts, its payload size is not
                %% known here.
                Bytes = case Pkt of #rtp{payload = P} -> byte_size(P); _ -> 0 end,
                scount(out, Ssrc, retransmitted_bytes_sent, Bytes, scount(out, Ssrc, retransmitted_packets_sent, 1, M));
            error ->
                M
        end,
    count(retransmitted, M1);
sent_stats(_Mid, _Pkt, flexfec, M) ->
    M;
sent_stats(Mid, Pkt, fec, M) ->
    sent_stats(Mid, Pkt, false, M);
sent_stats(Mid, Pkt, false, M) ->
    case maps:find(Mid, M#media.senders) of
        {ok, S} ->
            Tx = webrtc_rtp_stats:tx_packet(byte_size(Pkt#rtp.payload), S#snd.tx),
            count(rtp_sent, M#media{senders = (M#media.senders)#{Mid := S#snd{tx = Tx}}});
        error ->
            count(rtp_sent, M)
    end.

%% @doc The RFC 6464 audio level element for the `audio_level' option of
%% a send, when the extension is negotiated (in clear or encrypted,
%% RFC 6904).
audio_level(#{audio_level := {Voice, Level}}, #snd{audio_level_ext = Id}) when is_integer(Id) ->
    [{Id, webrtc_rtp_ext:audio_level(Voice, Level)}];
audio_level(_, _) ->
    undefined.

%% @doc Our identification elements, plus the audio level the packet
%% carries when it is one of ours.
header_ext(#snd{audio_level_ext = Id} = S, Ext) ->
    Level = [E || is_integer(Id), is_list(Ext), {I, _} = E <- Ext, I =:= Id],
    case mid_ext(S) of
        undefined when Level =:= [] -> undefined;
        undefined -> Level;
        Mine -> Mine ++ Level
    end.

%% RFC 9143 §9.1: carry the MID so the receiver can demultiplex before
%% it has learned our SSRC; a simulcast layer carries its RtpStreamId
%% too (RFC 8851 §4, RFC 8852 §3.1).
mid_ext(#snd{} = S) ->
    case sdes_ext(S#snd.mid_ext, S#snd.mid) ++ sdes_ext(S#snd.rid_ext, S#snd.rid) of
        [] -> undefined;
        Elems -> Elems
    end.

sdes_ext(Id, Value) when is_integer(Id), is_binary(Value) -> [{Id, webrtc_rtp_ext:sdes(Value)}];
sdes_ext(_, _) -> [].

%% A retransmission of a layer names the layer it repairs (RFC 8852
%% §3.2) instead of carrying its RtpStreamId.
rtx_ext(#snd{rid = undefined}, Ext) ->
    Ext;
rtx_ext(#snd{} = S, _Ext) ->
    case sdes_ext(S#snd.mid_ext, S#snd.mid) ++ sdes_ext(S#snd.rrid_ext, S#snd.rid) of
        [] -> undefined;
        Elems -> Elems
    end.

%% Resend NACKed packets, over RTX when negotiated (RFC 4588 §4),
%% through the pacer ahead of new video.
retransmit(#snd{} = S0, Seqs, Now, M) ->
    Key = skey(S0),
    {Found, Buf} = webrtc_nack_buffer:retransmit(Seqs, Now, S0#snd.buffer),
    {Wires, S1} = lists:mapfoldl(fun({_Seq, Entry}, S) -> resend(Entry, S) end, S0#snd{buffer = Buf}, Found),
    M1 = M#media{senders = (M#media.senders)#{Key := S1}},
    {Sends, M2} = pace(rtx, [{Key, W, true} || W <- Wires, W =/= skip], Now, M1),
    {M2, Sends}.

%% Over RTX when negotiated (a new packet on the RTX stream), else the
%% bytes of the first transmission; a packet still in the pacer has not
%% been sent and is skipped.
resend(Entry, #snd{rtx = Rtx} = S) ->
    Pkt = case Entry of {P, _} -> P; P -> P end,
    case {maps:is_key(Pkt#rtp.pt, Rtx), Entry} of
        {true, _} -> rtx_packet(Pkt, S);
        {false, {_, Srtp}} -> {{raw, Srtp}, S};
        {false, #rtp{}} -> {skip, S}
    end.

rtx_packet(#rtp{pt = Pt} = Pkt, #snd{rtx = Rtx} = S) ->
    case maps:find(Pt, Rtx) of
        {ok, RtxPt} ->
            Wire0 = webrtc_rtx:encapsulate(Pkt, #{ssrc => S#snd.rtx_ssrc, pt => RtxPt, seq => S#snd.rtx_seq}),
            Wire = Wire0#rtp{ext = rtx_ext(S, Wire0#rtp.ext)},
            {Wire, S#snd{rtx_seq = (S#snd.rtx_seq + 1) band 16#FFFF}};
        error ->
            {Pkt, S}
    end.

%%====================================================================
%% Timers: RTCP reports and NACK
%%====================================================================

tmin(infinity, B) -> B;
tmin(A, infinity) -> A;
tmin(A, B) -> min(A, B).

cc_timeouts(Now, M) ->
    {Items, Fb, Events, Cc} = webrtc_cc:handle_timeout(Now, M#media.cc),
    {Probes, Paced} = lists:partition(fun(I) -> element(1, I) =:= probe end, Items),
    {Sends, M1} = egress(Paced, Now, M#media{cc = Cc}),
    {ProbeSends, M2} = probes(Probes, Now, M1),
    {Fb, Sends ++ ProbeSends ++ [{event, E} || E <- Events], M2}.

%% Probe clusters (webrtc_cc_probe) are padding-only packets of a video
%% sender with transport-wide sequence numbers: on its RTX stream when
%% RTX is negotiated, as libwebrtc does, on the media stream otherwise.
probes([], _Now, M) ->
    {[], M};
probes(Probes, Now, M) ->
    %% With transport-cc the probes carry its sequence numbers; with RFC
    %% 8888 feedback their own RTP sequence numbers are reported.
    Ccfb = webrtc_cc:ccfb_send(M#media.cc),
    case [S || S = #snd{kind = video, twcc_ext = E} <- maps:values(M#media.senders), E =/= undefined orelse Ccfb] of
        [] ->
            {[], M};
        Senders ->
            S = hd([X || X = #snd{rtx = R} <- Senders, map_size(R) > 0] ++ Senders),
            lists:foldl(fun(P, {Acc, MAcc}) -> {Out, M1} = probe(P, S#snd.mid, skey(S), Now, MAcc), {Acc ++ Out, M1} end,
                        {[], M}, Probes)
    end.

probe({probe, Cluster, Size}, Mid, Key, Now, M) ->
    S = maps:get(Key, M#media.senders),
    Pad = max(1, min(255, Size - 32)),
    {Pkt, S1} =
        case maps:values(S#snd.rtx) of
            [RtxPt | _] ->
                {#rtp{ssrc = S#snd.rtx_ssrc, pt = RtxPt, seq = S#snd.rtx_seq, ts = S#snd.last_ts,
                      ext = rtx_ext(S, mid_ext(S)), payload = <<>>, padding = Pad},
                 S#snd{rtx_seq = (S#snd.rtx_seq + 1) band 16#FFFF}};
            [] ->
                [#{pt := Pt} | _] = S#snd.codecs,
                Next = (S#snd.seq + 1) band 16#FFFF,
                {#rtp{ssrc = S#snd.ssrc, pt = Pt, seq = S#snd.seq, ts = S#snd.last_ts, ext = mid_ext(S),
                      payload = <<>>, padding = Pad},
                 S#snd{seq = Next, cycles = S#snd.cycles + case Next of 0 -> 1; _ -> 0 end}}
        end,
    M1 = M#media{senders = (M#media.senders)#{Key := S1}},
    Wire = add_twcc(S#snd.twcc_ext, webrtc_cc:twcc_seq(M1#media.cc), Pkt),
    case webrtc_srtp:protect_rtp(webrtc_rtp:encode(Wire), M1#media.out) of
        {ok, Srtp, Out} ->
            Cc = webrtc_cc:sent_probe_rtp(Mid, Wire#rtp.ssrc, Wire#rtp.seq, byte_size(Srtp), Now, Cluster, M1#media.cc),
            {[out(Srtp, M1)], count(probe_sent, M1#media{out = Out, cc = Cc})};
        {error, _} ->
            {[], count(srtp_failed, M1)}
    end.

nack_timeouts(Now, M) ->
    maps:fold(
        fun
            (_Ssrc, #rcv{nack = undefined}, Acc) ->
                Acc;
            (Ssrc, #rcv{nack = N, mid = Mid} = R, {MAcc, AAcc}) ->
                {N1, Actions} = webrtc_nack:handle_timeout(Now, N),
                MAcc1 = MAcc#media{receivers = (MAcc#media.receivers)#{Ssrc := R#rcv{nack = N1}}},
                {Out, MAcc2} = webrtc_media_in:nack_actions(Mid, Ssrc, Actions, Now, MAcc1),
                {MAcc2, AAcc ++ Out}
        end,
        {M, []},
        M#media.receivers
    ).

%% One compound packet: SR per sender (or one RR), SDES CNAME, then
%% feedback (RFC 3550 §6.1, RFC 4585 §3.1; reduced-size not used for
%% regular reports).
%% The compound holds an SR per sent stream (or one RR), the SDES and
%% the feedback, then as many report blocks as fit in ?RTCP_BUDGET:
%% 31 in the first report, the others in RR packets that follow it
%% (RFC 3550 §6.4.2). When not every source fits, the first one reported
%% rotates so each is reported in turn; a source's interval statistics
%% only advance when it is reported.
reports(Now, Feedback, M) ->
    Ntp = webrtc_rtp_stats:ntp_from_us(erlang:system_time(microsecond)),
    Senders = maps:values(M#media.senders),
    {Reporter, Heads} =
        case Senders of
            [] ->
                {M#media.rtcp_ssrc, [#rtcp_rr{ssrc = M#media.rtcp_ssrc}]};
            [#snd{ssrc = First} | _] ->
                {First, [
                    webrtc_rtp_stats:sender_report(S#snd.ssrc, Ntp, rtp_ts_now(S, Now), S#snd.tx, [])
                 || S <- Senders
                ]}
        end,
    Cname = {cname, M#media.cname},
    Chunks =
        case Senders of
            [] -> [{M#media.rtcp_ssrc, [Cname]}];
            _ -> [{S#snd.ssrc, [Cname | layer_sdes(S)]} || S <- Senders]
        end,
    Sdes = #rtcp_sdes{chunks = Chunks},
    {Xr, M0} = xr(Reporter, Ntp, M),
    Fixed = byte_size(webrtc_rtcp:encode(Heads ++ [Sdes | Xr ++ Feedback])),
    {Picked, M1} = pick_sources(blocks_fitting(?RTCP_BUDGET - Fixed), M0),
    {Blocks, M2} = lists:foldl(
        fun(Ssrc, {Bs, Acc}) ->
            R = maps:get(Ssrc, Acc#media.receivers),
            {B, Rx} = webrtc_rtp_stats:report_block(Now, R#rcv.rx),
            {[B | Bs], Acc#media{receivers = (Acc#media.receivers)#{Ssrc := R#rcv{rx = Rx}}}}
        end,
        {[], M1},
        Picked
    ),
    {InHead, Extra} = lists:split(min(31, length(Blocks)), lists:reverse(Blocks)),
    [Head | Others] = Heads,
    Reports =
        [with_blocks(Head, InHead) | Others] ++
            [#rtcp_rr{ssrc = Reporter, reports = Bs} || Bs <- chunks(Extra, 31)],
    send_regular(Reports ++ [Sdes | Xr ++ Feedback], Now, M2).

%% RFC 3611: a Receiver Reference Time block while we receive streams
%% (their senders answer with DLRR, which gives the round trip time of
%% remote-outbound-rtp), and a DLRR block answering each one received.
xr(Reporter, Ntp, #media{receivers = Rs, xr_rrtr = Got} = M) ->
    NowUs = erlang:system_time(microsecond),
    Rrtr = [{rrtr, Ntp} || map_size(Rs) > 0],
    Dlrr = [{S, Lrr, (NowUs - At) * 65536 div 1000000} || S := {Lrr, At} <- Got],
    Blocks = Rrtr ++ [{dlrr, Dlrr} || Dlrr =/= []],
    {[#rtcp_xr{ssrc = Reporter, blocks = Blocks} || Blocks =/= []], M#media{xr_rrtr = #{}}}.

%% A regular compound: it resets the report timer.
send_regular(Pkts, Now, M) ->
    case send_rtcp(Pkts, M) of
        {[{send, B}], M1} ->
            Mark = maps:get(rtp_sent, M1#media.counters, 0),
            R = webrtc_rtcp_sched:regular_sent(Now, byte_size(B), M1#media.rtcp),
            {[{send, B}], M1#media{rtcp = R, rtp_sent_mark = Mark}};
        Other ->
            Other
    end.

%% @doc Feedback (NACK, PLI, FIR, transport-wide congestion control) to
%% send now. Without rtcp-rsize it goes in a compound with an RR and the
%% CNAME (RFC 4585 §3.1, RFC 5506 §5). It goes out while the RTCP
%% bandwidth allows and waits otherwise, at most ?MAX_PENDING_FEEDBACK
%% packets, the oldest dropped (see webrtc_rtcp_sched).
send_feedback([], _Now, M) ->
    {[], M};
send_feedback(_Pkts, _Now, #media{out = undefined} = M) ->
    {[], M};
send_feedback(Pkts, Now, #media{rtcp = R} = M0) ->
    M = lists:foldl(fun feedback_sent/2, M0, Pkts),
    Compound =
        case M#media.reduced_size of
            true -> Pkts;
            false -> [#rtcp_rr{ssrc = M#media.rtcp_ssrc}, #rtcp_sdes{chunks = [{M#media.rtcp_ssrc, [{cname, M#media.cname}]}]} | Pkts]
        end,
    %% SRTCP adds the index and the tag.
    Size = byte_size(webrtc_rtcp:encode(Compound)) + 14,
    case webrtc_rtcp_sched:feedback(Now, Size, R) of
        {now, R1} ->
            send_rtcp(Compound, M#media{rtcp = R1});
        {later, R1} ->
            Kept = lists:nthtail(max(0, length(M#media.pending_fb) + length(Pkts) - ?MAX_PENDING_FEEDBACK),
                                 M#media.pending_fb ++ Pkts),
            {[], count(feedback_delayed, M#media{rtcp = R1, pending_fb = Kept})}
    end.

%% NACK, PLI and FIR we send, per remote stream.
feedback_sent(#rtcp_nack{media_ssrc = S}, M) -> scount(in, S, nack_count, 1, M);
feedback_sent(#rtcp_pli{media_ssrc = S}, M) -> scount(in, S, pli_count, 1, M);
feedback_sent(#rtcp_fir{entries = Es}, M) -> lists:foldl(fun({S, _}, Acc) -> scount(in, S, fir_count, 1, Acc) end, M, Es);
feedback_sent(#rtcp_ccfb{}, M) -> count(ccfb_sent, M);
feedback_sent(_, M) -> M.

with_blocks(#rtcp_sr{} = SR, Bs) -> SR#rtcp_sr{reports = Bs};
with_blocks(#rtcp_rr{} = RR, Bs) -> RR#rtcp_rr{reports = Bs}.

chunks([], _N) -> [];
chunks(L, N) when length(L) =< N -> [L];
chunks(L, N) ->
    {H, T} = lists:split(N, L),
    [H | chunks(T, N)].

%% Report blocks (24 bytes) fitting in Room bytes: 31 in the first
%% report, then 8 bytes of header for every further RR packet.
blocks_fitting(Room) when Room < 24 -> 0;
blocks_fitting(Room) when Room < 31 * 24 -> Room div 24;
blocks_fitting(Room) -> 31 + extra_blocks(Room - 31 * 24).

extra_blocks(Room) when Room < 8 + 24 -> 0;
extra_blocks(Room) ->
    N = min(31, (Room - 8) div 24),
    N + extra_blocks(Room - 8 - N * 24).

pick_sources(Max, #media{receivers = Rs} = M) ->
    Ssrcs = lists:sort(maps:keys(Rs)),
    N = length(Ssrcs),
    case N =< Max of
        true ->
            {Ssrcs, M};
        false ->
            Off = M#media.rtcp_rot rem N,
            {A, B} = lists:split(Off, Ssrcs),
            {lists:sublist(B ++ A, Max), M#media{rtcp_rot = Off + Max}}
    end.

%% RFC 8852 §4: the RtpStreamId (and MID) SDES items of a layer, so the
%% receiver learns its SSRC even when no RTP flows.
layer_sdes(#snd{rid = undefined}) -> [];
layer_sdes(#snd{mid = Mid, rid = Rid}) -> [{mid, Mid}, {rid, Rid}].

%% Extrapolate the RTP timestamp to now from the last packet sent.
rtp_ts_now(#snd{last_ts_at = undefined, last_ts = Ts}, _Now) ->
    Ts;
rtp_ts_now(#snd{last_ts_at = At, last_ts = Ts, codecs = Cs}, Now) ->
    Rate =
        case Cs of
            [#{clock_rate := R} | _] -> R;
            [] -> 90000
        end,
    (Ts + ((Now - At) * Rate) div 1000) band 16#FFFFFFFF.

send_rtcp([], M) ->
    {[], M};
send_rtcp(_Pkts, #media{out = undefined} = M) ->
    {[], M};
send_rtcp(Pkts, M) ->
    case webrtc_srtp:protect_rtcp(webrtc_rtcp:encode(Pkts), M#media.out) of
        {ok, B, Out} -> {[{send, B}], count(rtcp_sent, M#media{out = Out})};
        {error, _} -> {[], M}
    end.

%% @doc RFC 3550 §8.2: the peer sends with `Ssrc', one of ours. The
%% sender using it takes a new SSRC and says BYE for the old one; our
%% receiver-only RTCP SSRC simply changes. Events:
%% `{ssrc_changed, Mid, Old, New}'.
-spec ssrc_collision(non_neg_integer(), #media{}) -> {#media{}, list()}.
ssrc_collision(Ssrc, #media{senders = Senders} = M) ->
    case [{K, F} || K := S <- Senders, F <- [ssrc, rtx_ssrc], element(field_pos(F), S) =:= Ssrc] of
        [{K, F} | _] ->
            S = maps:get(K, Senders),
            New = fresh_ssrc(M),
            S1 = setelement(field_pos(F), S, New),
            M1 = count(ssrc_collisions, M#media{senders = Senders#{K := S1}}),
            {Bye, M2} = send_rtcp([#rtcp_rr{ssrc = Ssrc}, #rtcp_sdes{chunks = [{Ssrc, [{cname, M1#media.cname}]}]},
                                   #rtcp_bye{ssrcs = [Ssrc]}], M1),
            {M2, Bye ++ [{event, {ssrc_changed, S#snd.mid, Ssrc, New}}]};
        [] when Ssrc =:= M#media.rtcp_ssrc ->
            {count(ssrc_collisions, M#media{rtcp_ssrc = fresh_ssrc(M)}), []};
        [] ->
            {M, []}
    end.

field_pos(ssrc) -> #snd.ssrc;
field_pos(rtx_ssrc) -> #snd.rtx_ssrc.

%% Distinct from every SSRC in use, ours and the peer's.
fresh_ssrc(M) ->
    <<S:32>> = crypto:strong_rand_bytes(4),
    Used = [M#media.rtcp_ssrc | [X || #snd{ssrc = A, rtx_ssrc = B} <- maps:values(M#media.senders), X <- [A, B]]] ++
        maps:keys(M#media.ssrc_mid),
    case S =:= 0 orelse lists:member(S, Used) of
        true -> fresh_ssrc(M);
        false -> S
    end.

%%====================================================================
%% Stats
%%====================================================================

count(Key, M) ->
    count(Key, 1, M).

count(Key, N, #media{counters = C} = M) ->
    M#media{counters = maps:update_with(Key, fun(V) -> V + N end, N, C)}.

%% @doc Add N to a counter of stream {Dir, Ssrc}.
-spec scount(in | out, non_neg_integer(), atom(), integer(), #media{}) -> #media{}.
scount(Dir, Ssrc, Key, N, #media{streams = Ss} = M) ->
    S = maps:get({Dir, Ssrc}, Ss, #{}),
    M#media{streams = Ss#{{Dir, Ssrc} => S#{Key => maps:get(Key, S, 0) + N}}}.

%% @doc Set values of stream {Dir, Ssrc}.
-spec sset(in | out, non_neg_integer(), map(), #media{}) -> #media{}.
sset(Dir, Ssrc, Values, #media{streams = Ss} = M) ->
    M#media{streams = Ss#{{Dir, Ssrc} => maps:merge(maps:get({Dir, Ssrc}, Ss, #{}), Values)}}.

rand16() ->
    <<S:16>> = crypto:strong_rand_bytes(2),
    S.
