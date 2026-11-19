%% @doc Media session of one BUNDLE transport, as a sans-IO engine:
%% SRTP/SRTCP protection, RTP demultiplexing to transceivers, RTCP
%% reports, NACK-based retransmission (RFC 4585, RFC 4588) and keyframe
%% requests (RFC 4585 PLI, RFC 5104 FIR).
%%
%% Media payloads are never decoded: the application sends and receives
%% RTP payloads (or whole packets when forwarding).
%%
%% This module is the API of the media session and its sans-IO entry
%% points (`new/1', `configure/2', `handle_packet/3', `handle_timeout/2',
%% `next_timeout/1'). The work is split by direction and by feature:
%% `webrtc_media_in' receives, `webrtc_media_out' sends, and
%% `webrtc_media_fb' (SLI, RPSI), `webrtc_media_limit' (TMMBR),
%% `webrtc_media_sync' (RFC 6051), `webrtc_media_rid' (simulcast
%% receive), `webrtc_media_pause' (RFC 7728) and `webrtc_media_report'
%% (statistics reported by the application) each hold one feature. They
%% share the `#media{}' record of `webrtc_media.hrl'. The two paths are
%% drawn in docs/ARCHITECTURE.md, "Inside the media session".
%%
%% Incoming RTP is matched to a transceiver (mid) in this order
%% (RFC 9143 §9.2): known SSRC, the MID header extension, then a payload
%% type used by a single m= section. In a section with negotiated
%% simulcast layers, the layer (rid) comes from the RtpStreamId and
%% RepairedRtpStreamId header extensions (RFC 8852, see
%% `webrtc_media_rid').
%%
%% Senders are keyed by mid, or by `{Mid, Rid}' for each simulcast layer
%% we send (RFC 8853); every layer has its own SSRC and RTX SSRC and
%% carries the RtpStreamId extension (RFC 8851 §4).
%%
%% Congestion control (`webrtc_cc'): when the peer accepts the
%% transport-wide-cc header extension every outgoing RTP packet carries
%% a transport-wide sequence number, and the peer's feedback (or REMB)
%% drives the bandwidth estimate and the pacer on the send path. When we
%% offered the extension, feedback is generated for incoming packets.
%% `new/1' takes the `webrtc_cc' options under `cc'.
%%
%% Actions: `{send, Datagram}', `{send_ect, Datagram}' (RTP to send
%% with ECT(0), RFC 6679, once RFC 8888 feedback validated ECN) and
%% `{event, Event}' with Event one of
%% `{rtp, Mid, #rtp{}}', `{rtp, Mid, Rid, #rtp{}}' (a simulcast layer),
%% `{keyframe_request, Mid}', `{keyframe_request, Mid, Rid}',
%% `{rtcp, Mid, Packet}' (feedback the application may act on, such as
%% REMB or TWCC), `{bye, Mid, Ssrc}', `{bandwidth_estimate, Bps}' (the
%% target bitrate for everything sent on the transport changed),
%% `{max_bitrate, Mid, Bps}' and `{max_bitrate, Mid, Rid, Bps}' (the
%% payload bit rate a TMMBR limit allows on the stream, or `infinity',
%% see `webrtc_media_limit') and
%% `{circuit_breaker, Mid, Reason}' (RFC 8083, see
%% `webrtc_circuit_breaker').
-module(webrtc_media).

-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").

-export([
    new/1,
    configure/2,
    set_srtp/5,
    clear_srtp/1,
    ready/1,
    send/5,
    send_frame/5,
    send_media/5,
    report_stats/4,
    report_stream/5,
    plugin_call/1,
    plugin_info/3,
    send_packet/4,
    resume/3,
    request_keyframe/3,
    send_loss_indication/4,
    request_max_bitrate/4,
    dscps/1,
    dscp_blocked/2,
    request_pause/4,
    set_congestion_control/3,
    handle_packet/3,
    handle_packet/4,
    handle_timeout/2,
    next_timeout/1,
    stats/1,
    receiver_info/3
]).

-export_type([state/0, sender_key/0]).

-include("webrtc_media.hrl").

-opaque state() :: #media{}.
%% A transceiver (mid) or one simulcast layer of it.

%%====================================================================
%% Setup
%%====================================================================

-spec new(map()) -> state().
new(Opts) ->
    #media{
        cname = maps:get(cname, Opts, <<"webrtc">>),
        ecn = maps:get(ecn, Opts, false),
        rtcp_ssrc = rand32(),
        video_fec = maps:get(video_fec, Opts, auto),
        cc = webrtc_cc:new(maps:get(cc, Opts, #{})),
        rtcp_opts = maps:with([report_interval], maps:get(rtcp, Opts, #{}))
    }.

%% @doc Apply the negotiated media sections (`media' of
%% `webrtc_jsep:negotiated/1'). Existing sequence numbers and statistics
%% are kept for transceivers that remain.
-spec configure([map()], state()) -> state().
configure(Sections, #media{} = M) ->
    Senders = maps:from_list(
        lists:append([
            webrtc_media_out:senders(S, M#media.senders)
         || #{direction := D} = S <- Sections, D =:= sendrecv orelse D =:= sendonly
        ])
    ),
    Recv = maps:from_list([{Mid, S} || #{mid := Mid} = S <- Sections]),
    SsrcMid = maps:from_list(
        lists:append([
            [{Ssrc, Mid} || #{ssrc := Ssrc} <- Rs] ++
                [{X, Mid} || #{rtx_ssrc := X} <- Rs, is_integer(X)] ++
                [{X, Mid} || #{fec_ssrc := X} <- Rs, is_integer(X)]
         || #{mid := Mid, remote_ssrcs := Rs} <- Sections
        ])
    ),
    RtxSsrc = maps:from_list(
        [{X, P} || #{remote_ssrcs := Rs} <- Sections, #{ssrc := P, rtx_ssrc := X} <- Rs, is_integer(X)]
    ),
    PtOwners = lists:foldl(
        fun(#{mid := Mid, recv_codecs := Cs}, Acc) ->
            lists:foldl(fun(#{pt := Pt}, A) -> maps:update_with(Pt, fun(L) -> [Mid | L] end, [Mid], A) end, Acc, Cs)
        end,
        #{},
        Sections
    ),
    PtMid = maps:from_list([{Pt, Mid} || {Pt, [Mid]} <- maps:to_list(PtOwners)]),
    MidExt = maps:from_list([
        {Mid, Id}
     || #{mid := Mid, recv_extensions := #{?URI_MID := Id}} <- Sections
    ]),
    TwccIds = lists:usort([Id || #{recv_extensions := #{?URI_TWCC := Id}} <- Sections]),
    Cc = webrtc_cc:configure(
        #{
            twcc_send => lists:any(fun(#snd{twcc_ext = E}) -> E =/= undefined end, maps:values(Senders)),
            twcc_recv => TwccIds =/= [],
            sender_ssrc => M#media.rtcp_ssrc,
            %% RFC 8888 when transport-cc is not negotiated.
            ccfb => Sections =/= [] andalso lists:all(fun(S) -> maps:get(ccfb, S, false) end, Sections),
            ecn => M#media.ecn
        },
        M#media.cc
    ),
    Cryptex = Sections =/= [] andalso lists:all(fun(S) -> maps:get(cryptex, S, false) end, Sections),
    %% One SRTP context per transport: the encrypted ids of its sections
    %% together (ids are unique within a BUNDLE group).
    SendEnc = lists:usort(lists:append([maps:get(send_encrypted, S, []) || S <- Sections])),
    RecvEnc = lists:usort(lists:append([maps:get(recv_encrypted, S, []) || S <- Sections])),
    M#media{
        cryptex = Cryptex,
        send_encrypted = SendEnc,
        recv_encrypted = RecvEnc,
        out = case M#media.out of
                  undefined -> undefined;
                  Out -> webrtc_srtp:set_encrypted_extensions(SendEnc, webrtc_srtp:set_cryptex(Cryptex, Out))
              end,
        in = case M#media.in of
                 undefined -> undefined;
                 In -> webrtc_srtp:set_encrypted_extensions(RecvEnc, webrtc_srtp:set_cryptex(Cryptex, In))
             end,
        senders = Senders,
        twcc_ids = TwccIds,
        cc = Cc,
        recv = Recv,
        %% W3C: a stopped transceiver's streams are deleted.
        ended = [E || {_, #{mid := Mi}, _} = E <- M#media.ended, is_map_key(Mi, Recv)],
        %% Learned SSRCs are kept while their stream is live.
        ssrc_mid = maps:merge(maps:with(maps:keys(M#media.last_seen), M#media.ssrc_mid), SsrcMid),
        signaled = SsrcMid,
        rtx_ssrc = RtxSsrc,
        pt_mid = PtMid,
        mid_ext = MidExt,
        reduced_size = Sections =/= [] andalso lists:all(fun(S) -> maps:get(rtcp_rsize, S, false) end, Sections),
        rids = webrtc_media_rid:configure(Sections, M#media.rids)
    }.

%% @doc Install the SRTP contexts from the DTLS-SRTP handshake.
-spec set_srtp(webrtc_srtp:profile(), binary(), client | server, integer(), state()) -> state().
set_srtp(Profile, Material, Role, Now, M) ->
    {Out0, In0} = webrtc_srtp:dtls_contexts(Profile, Material, Role, #{cryptex => M#media.cryptex}),
    Out = webrtc_srtp:set_encrypted_extensions(M#media.send_encrypted, Out0),
    In = webrtc_srtp:set_encrypted_extensions(M#media.recv_encrypted, In0),
    Rtcp = webrtc_rtcp_sched:new(Now, (M#media.rtcp_opts)#{session_bandwidth => session_bandwidth(M)}),
    M#media{out = Out, in = In, rtcp = Rtcp}.

%% @doc Forget the SRTP contexts: the DTLS association they came from is
%% gone. Sending fails with `not_ready' until `set_srtp/5'.
-spec clear_srtp(state()) -> state().
clear_srtp(M) ->
    M#media{out = undefined, in = undefined}.

-spec ready(state()) -> boolean().
ready(#media{out = O}) -> O =/= undefined.

%%====================================================================
%% Sending
%%====================================================================

%% @doc Send a payload on a transceiver. `Opts': `timestamp' (RTP
%% clock), `marker', `pt' or `codec' (name), defaulting to the first
%% negotiated codec, `rid' to send on one simulcast layer, and
%% `keyframe' when the payload belongs to one (it then carries the
%% RFC 6051 NTP time when negotiated).
-spec send(binary(), binary(), map(), integer(), state()) ->
    {ok, [{send, binary()}], state()} | {error, term()}.
send(Mid0, Payload, Opts, Now, M) ->
    Mid =
        case Opts of
            #{rid := Rid} -> {Mid0, Rid};
            _ -> Mid0
        end,
    case maps:find(Mid, M#media.senders) of
        error ->
            {error, not_sending};
        {ok, S} ->
            case webrtc_media_out:pick_pt(Opts, S) of
                {ok, Pt} ->
                    Ts = maps:get(timestamp, Opts, 0),
                    {SendPt, Body, S1} = redundancy(Opts, Pt, Ts, Payload, S),
                    Pkt = #rtp{
                        pt = SendPt,
                        marker = maps:get(marker, Opts, false),
                        ts = Ts,
                        payload = Body,
                        ext = webrtc_media_out:audio_level(Opts, S1)
                    },
                    send_hinted(Mid, Pkt, maps:with([keyframe], Opts), Now, M#media{senders = (M#media.senders)#{Mid := S1}});
                error ->
                    {error, unknown_codec}
            end
    end.

%% @doc Send an encoded frame: split into payloads by the codec's
%% payload format (VP8, VP9 with picture IDs, H.264 in Annex B, AV1
%% temporal units; one payload for audio), the marker bit on the last.
%% `Opts': `timestamp', `keyframe', `codec', `rid'.
-spec send_frame(binary(), binary(), map(), integer(), state()) ->
    {ok, [{send, binary()}], state()} | {error, term()}.
send_frame(Mid0, Frame, Opts, Now, M) when is_binary(Frame), byte_size(Frame) > 0 ->
    Key = case Opts of #{rid := Rid} -> {Mid0, Rid}; _ -> Mid0 end,
    case maps:find(Key, M#media.senders) of
        error ->
            {error, not_sending};
        {ok, #snd{kind = Kind, codecs = Cs, picture_id = Pic} = S} ->
            Named = [C || #{name := N} = C <- Cs, not webrtc_media_out:is_repair(N),
                          string:lowercase(N) =:= string:lowercase(maps:get(codec, Opts, N))],
            case Named of
                [] ->
                    {error, unknown_codec};
                [#{name := Name} | _] ->
                    Key0 = maps:get(keyframe, Opts, false),
                    Payloads = payloads(webrtc_frame_codec:codec(Kind, Name), Frame, Key0, Pic),
                    M1 = M#media{senders = (M#media.senders)#{Key := S#snd{picture_id = (Pic + 1) band 16#7FFF}}},
                    N = length(Payloads),
                    Base = maps:with([timestamp, rid, audio_level, keyframe], Opts),
                    lists:foldl(
                        fun({I, P}, {ok, Acc, MA}) ->
                                case send(Mid0, P, Base#{marker => I =:= N, codec => Name}, Now, MA) of
                                    {ok, Out, MB} -> {ok, Acc ++ Out, MB};
                                    {error, _} = E -> E
                                end;
                           (_, E) ->
                                E
                        end,
                        {ok, [], M1},
                        lists:enumerate(Payloads)
                    )
            end
    end;
send_frame(_Mid, _Frame, _Opts, _Now, _M) ->
    {error, empty_frame}.

%% Payloads of at most 1100 bytes: the RTP header, extensions and the
%% SRTP tag fit within a 1200 byte path MTU.
-define(PAYLOAD_MTU, 1100).
payloads(vp8, F, _Key, Pic) -> webrtc_rtp_vp8:packetize(F, ?PAYLOAD_MTU, #{picture_id => Pic});
payloads(vp9, F, Key, Pic) -> webrtc_rtp_vp9:packetize(F, ?PAYLOAD_MTU, #{picture_id => Pic, inter_predicted => not Key});
payloads(h264, F, _Key, _Pic) -> webrtc_rtp_h264:packetize(webrtc_rtp_h264:split_annexb(F), ?PAYLOAD_MTU);
payloads(av1, F, Key, _Pic) -> webrtc_rtp_av1:packetize(F, ?PAYLOAD_MTU, #{new_sequence => Key});
payloads(_, F, _Key, _Pic) -> [F].

%% @doc Encode raw media with the transceiver's codec plugin and send the
%% frames it returns.
-spec send_media(binary(), term(), map(), integer(), state()) ->
    {ok, [{send, binary()} | {event, term()}], state()} | {error, term()}.
send_media(Mid0, Raw, Opts, Now, M) ->
    Key = case Opts of #{rid := Rid} -> {Mid0, Rid}; _ -> Mid0 end,
    Config = maps:get(codec_plugin, maps:get(Mid0, M#media.recv, #{}), undefined),
    case {maps:find(Key, M#media.senders), Config} of
        {error, _} ->
            {error, not_sending};
        {_, undefined} ->
            {error, no_codec_plugin};
        {{ok, #snd{plugin = {off, R}}}, _} ->
            {error, {codec_plugin, R}};
        {{ok, #snd{ssrc = Ssrc, kind = Kind, codecs = Cs} = S0}, {Mod, POpts}} ->
            case plugin_start(S0#snd.plugin, Mod, Kind, [C || #{name := N} = C <- Cs, not webrtc_media_out:is_repair(N)], POpts) of
                {ok, {Mod, PSt}} ->
                    case plugin_call(fun() -> Mod:encode(Raw, PSt) end) of
                        {ok, Frames, Stats, PSt1} ->
                            M1 = M#media{senders = (M#media.senders)#{Key := S0#snd{plugin = {Mod, PSt1}}}},
                            M2 = report_stream(out, Ssrc, outbound, maps:merge(Stats, plugin_info(encoder, Mod, PSt1)), M1),
                            lists:foldl(
                                fun(#{data := D} = F, {ok, Acc, MA}) ->
                                        case send_frame(Mid0, D, maps:merge(maps:with([rid], Opts), maps:with([timestamp, keyframe], F)), Now, MA) of
                                            {ok, Out, MB} -> {ok, Acc ++ Out, MB};
                                            {error, _} = E -> E
                                        end;
                                   (_, E) ->
                                        E
                                end,
                                {ok, [], M2},
                                Frames
                            );
                        {error, R} ->
                            plugin_off(Key, Mid0, R, M)
                    end;
                {error, R} ->
                    plugin_off(Key, Mid0, R, M)
            end
    end.

plugin_off(Key, Mid, R, M) ->
    S = maps:get(Key, M#media.senders),
    {ok, [{event, {codec_plugin_error, Mid, R}}], M#media{senders = (M#media.senders)#{Key := S#snd{plugin = {off, R}}}}}.

plugin_start({Mod, _} = P, Mod, _Kind, _Codecs, _Opts) ->
    {ok, P};
plugin_start(_, Mod, Kind, [Codec | _], Opts) ->
    case plugin_call(fun() -> Mod:init(Kind, Codec, Opts) end) of
        {ok, St} -> {ok, {Mod, St}};
        {error, R} -> {error, R}
    end;
plugin_start(_, _Mod, _Kind, [], _Opts) ->
    {error, no_codec}.

%% @doc Run a plugin callback: a raise becomes an error.
-spec plugin_call(fun(() -> term())) -> term().
plugin_call(F) ->
    try F() of
        {ok, _} = R -> R;
        {ok, _, _, _} = R -> R;
        {ok, _, _, _, _} = R -> R;
        {error, _} = E -> E;
        Other -> {error, {bad_return, Other}}
    catch
        C:R:St -> {error, {C, R, St}}
    end.

%% @doc decoderImplementation or encoderImplementation and the power
%% efficiency member from the plugin's info/1.
-spec plugin_info(encoder | decoder, module(), term()) -> map().
plugin_info(Role, Mod, St) ->
    case plugin_call(fun() -> {ok, Mod:info(St)} end) of
        {ok, #{} = I} ->
            {Impl, Power} = case Role of
                                encoder -> {encoderImplementation, powerEfficientEncoder};
                                decoder -> {decoderImplementation, powerEfficientDecoder}
                            end,
            maps:from_list([{Impl, V} || {implementation, V} <- maps:to_list(I)] ++
                           [{Power, V} || {power_efficient, V} <- maps:to_list(I)]);
        _ ->
            #{}
    end.

%% @doc W3C members reported for a transceiver's streams (`inbound',
%% `outbound'), its media source or its audio playout (see
%% webrtc_media_report). Returns the members dropped.
-spec report_stats(binary(), webrtc_media_report:dir(), map(), state()) -> {[{term(), term()}], state()}.
report_stats(Mid, inbound, Report, M) ->
    Ssrcs = [S || S := #rcv{mid = X} <- M#media.receivers, X =:= Mid],
    report_streams(in, inbound, Ssrcs, Report, M);
report_stats(Mid, outbound, Report, M) ->
    Ssrcs = [S || #snd{mid = X, ssrc = S} <- maps:values(M#media.senders), X =:= Mid],
    report_streams(out, outbound, Ssrcs, Report, M);
report_stats(Mid, source, Report, M) ->
    {Kept, Bad} = webrtc_media_report:merge(source, Report, maps:get(Mid, M#media.sources, #{})),
    {Bad, M#media{sources = (M#media.sources)#{Mid => Kept}}};
report_stats(Mid, playout, Report, M) ->
    {Kept, Bad} = webrtc_media_report:merge(playout, Report, maps:get(Mid, M#media.playouts, #{})),
    {Bad, M#media{playouts = (M#media.playouts)#{Mid => Kept}}}.

report_streams(_Dir, _Kind, [], Report, M) ->
    {_, Bad} = webrtc_media_report:merge(inbound, Report, #{}),
    {Bad ++ [{no_stream, Report}], M};
report_streams(Dir, Kind, Ssrcs, Report, M) ->
    lists:foldl(fun(Ssrc, {_, MA}) ->
                    {Bad, MB} = report_stream1(Dir, Ssrc, Kind, Report, MA),
                    {Bad, MB}
                end, {[], M}, Ssrcs).

%% @doc Merge reported members into one stream's.
-spec report_stream(in | out, non_neg_integer(), webrtc_media_report:dir(), map(), #media{}) -> #media{}.
report_stream(Dir, Ssrc, Kind, Report, M) ->
    element(2, report_stream1(Dir, Ssrc, Kind, Report, M)).

report_stream1(Dir, Ssrc, Kind, Report, M) ->
    S = maps:get({Dir, Ssrc}, M#media.streams, #{}),
    {Kept, Bad} = webrtc_media_report:merge(Kind, Report, maps:get(reported, S, #{})),
    M1 = case Bad of [] -> M; _ -> webrtc_media_out:count(media_stats_rejected, length(Bad), M) end,
    {Bad, M1#media{streams = (M1#media.streams)#{{Dir, Ssrc} => S#{reported => Kept}}}}.

%% With `red => true' and RED negotiated, the payload goes in a RED
%% packet with the previous one as its redundant block (RFC 2198, RFC
%% 8854 §4.1), so a single loss is repaired at the receiver without a
%% round trip.
redundancy(#{red := true}, Pt, Ts, Payload, S) ->
    case webrtc_media_out:red_pt(S) of
        {ok, Red} ->
            Prev = [{P, (Ts - T) band 16#FFFFFFFF, D} || {P, T, D} <- [S#snd.red_prev], P =:= Pt],
            {Red, webrtc_red:encode(Prev, {Pt, Payload}), S#snd{red_prev = {Pt, Ts, Payload}}};
        error ->
            {Pt, Payload, S}
    end;
redundancy(_, Pt, _Ts, Payload, S) ->
    {Pt, Payload, S}.

%% @doc Send an RTP packet on a transceiver, or on one of its simulcast
%% layers with `{Mid, Rid}'. The SSRC and sequence number are ours;
%% payload type, timestamp, marker and payload come from the packet
%% (forwarding rewrites only what identifies the stream). The packet goes
%% through the pacer: the returned datagrams are those that may leave
%% now, the others are returned by `handle_timeout/2'.
-spec send_packet(sender_key(), #rtp{}, integer(), state()) ->
    {ok, [{send, binary()}], state()} | {error, term()}.
send_packet(_Mid, _Pkt, _Now, #media{out = undefined}) ->
    {error, not_ready};
send_packet(Mid, #rtp{} = Pkt0, Now, M) ->
    send_hinted(Mid, Pkt0, #{}, Now, M).

%% `Hints': `keyframe', when the packet belongs to one.
send_hinted(_Mid, _Pkt, _Hints, _Now, #media{out = undefined}) ->
    {error, not_ready};
send_hinted(Mid, #rtp{} = Pkt0, Hints, Now, M) ->
    case maps:find(Mid, M#media.senders) of
        error ->
            {error, not_sending};
        {ok, #snd{mid = TMid} = S} ->
            case {webrtc_cc:halted(TMid, M#media.cc), webrtc_media_pause:is_paused(S)} of
                {{true, Reason}, _} -> {error, {circuit_breaker, Reason}};
                {false, true} -> {error, paused};
                {false, false} -> send_packet(Mid, Pkt0, Hints, Now, M)
            end
    end.

send_packet(Mid, Pkt00, Hints, Now, M0) ->
    %% RFC 6051: the NTP time of the packet when it is due.
    {Sync, M} = webrtc_media_sync:sender_ext(Mid, Hints#{ts => Pkt00#rtp.ts}, M0),
    S = maps:get(Mid, M#media.senders),
    %% With ULPFEC negotiated, video goes in RED (RFC 8854 §5.2).
    Pkt0 = webrtc_media_out:fec_wrap(S, Pkt00),
    Ext = case {webrtc_media_out:header_ext(S, Pkt0#rtp.ext), Sync} of
              {E, []} -> E;
              {undefined, _} -> Sync;
              {E, _} -> E ++ Sync
          end,
    Pkt = Pkt0#rtp{ssrc = S#snd.ssrc, seq = S#snd.seq, csrcs = Pkt0#rtp.csrcs, ext = Ext},
    Next = (S#snd.seq + 1) band 16#FFFF,
    S1 = S#snd{
        seq = Next,
        cycles = S#snd.cycles + case Next of 0 -> 1; _ -> 0 end,
        last_ts = Pkt#rtp.ts,
        last_ts_at = Now,
        key_ts = case maps:get(keyframe, Hints, false) of
                     true -> Pkt#rtp.ts;
                     false -> S#snd.key_ts
                 end,
        buffer = webrtc_nack_buffer:store(Pkt#rtp.seq, Pkt, Now, S#snd.buffer)
    },
    M1 = M#media{senders = (M#media.senders)#{Mid := S1}},
    {Sends, M2} = webrtc_media_out:pace(S#snd.kind, [{Mid, Pkt, false}], Now, M1),
    {ok, Sends, M2}.

%% @doc Restart the streams of a transceiver halted by a circuit breaker
%% (RFC 8083 §4.5), once its hold time has passed.
-spec resume(binary(), integer(), state()) -> {ok, state()} | {error, term()}.
resume(Mid, Now, M) ->
    case webrtc_cc:resume(Mid, Now, M#media.cc) of
        {ok, Cc} -> {ok, M#media{cc = Cc}};
        {error, _} = E -> E
    end.

%% @doc Ask the remote sender of a transceiver for a keyframe, on every
%% stream of the mid or on one simulcast layer with `{Mid, Rid}': PLI
%% when negotiated, otherwise FIR.
-spec request_keyframe(sender_key(), integer(), state()) -> {[{send, binary()}], state()}.
request_keyframe({Mid, Rid}, Now, M) ->
    keyframe_requests([S || {ok, S} <- [webrtc_media_rid:source(Mid, Rid, M#media.rids)]], Now, M);
request_keyframe(Mid, Now, M) ->
    keyframe_requests([S || {S, #rcv{mid = Mi}} <- maps:to_list(M#media.receivers), Mi =:= Mid], Now, M).

keyframe_requests(Ssrcs, Now, M0) ->
    {Pkts, M} = lists:foldl(fun(S, {Acc, MA}) ->
                                {P, MA1} = webrtc_media_in:keyframe_feedback(S, MA),
                                {Acc ++ P, MA1}
                            end, {[], M0}, Ssrcs),
    webrtc_media_out:send_feedback(Pkts, Now, M).

%% @doc Ask the senders of a transceiver to keep their streams under
%% `Bps' (RTP headers and payload) with TMMBR (RFC 5104 §4.2.1), or to
%% lift our limit with `infinity'. Repeated with the regular reports
%% until each sender answers with a TMMBN.
-spec request_max_bitrate(binary(), pos_integer() | infinity, integer(), state()) ->
    {ok, [{send, binary()}], state()} | {error, not_negotiated}.
request_max_bitrate(Mid, Bps, Now, M) ->
    webrtc_media_limit:request(Mid, Bps, Now, M).

%% @doc The DSCPs the media flows use (RFC 8837), none at the default
%% priority.
-spec dscps(state()) -> [1..63].
dscps(M) ->
    webrtc_media_out:dscps(M).

%% @doc `Dscp' does not get through (RFC 8835 §4.2): the flows using it
%% go unmarked.
-spec dscp_blocked(1..63, state()) -> state().
dscp_blocked(Dscp, M) ->
    M#media{dscp_off = lists:usort([Dscp | M#media.dscp_off])}.

%% @doc Send a slice loss or reference picture selection indication to
%% the senders of a transceiver, or of one simulcast layer with
%% `{Mid, Rid}' (RFC 4585 §6.3.2, §6.3.3), when it was negotiated.
-spec send_loss_indication(sender_key(), webrtc_media_fb:indication(), integer(), state()) ->
    {ok, [{send, binary()}], state()} | {error, not_negotiated}.
send_loss_indication(Key, Fb, Now, M) ->
    webrtc_media_fb:send(Key, Fb, Now, M).

%% @doc Ask the remote sender of a transceiver, or of one simulcast
%% layer with `{Mid, Rid}', to pause or resume its stream (RFC 7728).
-spec request_pause(sender_key(), pause | resume, integer(), state()) ->
    {ok, [{send, binary()}], state()} | {error, term()}.
request_pause(Key, Type, Now, M) ->
    webrtc_media_pause:request(Key, Type, Now, M).

%% @doc Change the congestion control options at run time (see
%% `webrtc_cc:set_options/3'): `pacing', `pacing_factor',
%% `min_bitrate', `max_bitrate'.
-spec set_congestion_control(map(), integer(), state()) -> {list(), state()}.
set_congestion_control(Opts, Now, M) ->
    {Items, Events, Cc} = webrtc_cc:set_options(Opts, Now, M#media.cc),
    {Sends, M1} = webrtc_media_out:egress(Items, Now, M#media{cc = Cc}),
    {Sends ++ [{event, E} || E <- Events], M1}.

%%====================================================================
%% Receiving
%%====================================================================

-spec handle_packet(binary(), integer(), state()) -> {state(), list()}.
handle_packet(_Bin, _Now, #media{in = undefined} = M) ->
    {M, []};
handle_packet(Bin, Now, M) ->
    handle_packet(Bin, Now, M, 0).

%% @doc The same with the ECN codepoint the datagram arrived with (0
%% not-ECT, 1 ECT(1), 2 ECT(0), 3 CE), for RFC 8888 feedback.
-spec handle_packet(binary(), integer(), state(), 0..3) -> {state(), list()}.
handle_packet(_Bin, _Now, #media{in = undefined} = M, _Ecn) ->
    {M, []};
handle_packet(Bin, Now, M, Ecn) ->
    case webrtc_rtp:classify(Bin) of
        rtp -> webrtc_media_in:rtp_in(Bin, Now, M, Ecn);
        rtcp -> webrtc_media_in:rtcp_in(Bin, Now, M);
        unknown -> {webrtc_media_out:count(dropped, M), []}
    end.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#media{rtcp = Rtcp, receivers = Rs, cc = Cc} = M) ->
    R =
        case Rtcp of
            undefined -> infinity;
            _ -> webrtc_rtcp_sched:next_timeout(Rtcp)
        end,
    lists:foldl(
        fun(#rcv{nack = N, frames = Fb}, Acc) ->
            Acc1 = case N of undefined -> Acc; _ -> webrtc_media_out:tmin(webrtc_nack:next_timeout(N), Acc) end,
            case Fb of undefined -> Acc1; _ -> webrtc_media_out:tmin(webrtc_frame_buffer:next_timeout(Fb), Acc1) end
        end,
        webrtc_media_out:tmin(webrtc_media_out:tmin(webrtc_media_out:tmin(R, webrtc_cc:next_timeout(Cc)),
                                                     webrtc_media_pause:next_timeout(M)),
                              webrtc_media_limit:next_timeout(M)),
        maps:values(Rs)
    ).

-spec handle_timeout(integer(), state()) -> {state(), list()}.
handle_timeout(Now, #media{out = undefined} = M) ->
    _ = Now,
    {M, []};
handle_timeout(Now, M0) ->
    {Fb, A0, M1} = webrtc_media_out:cc_timeouts(Now, M0),
    {M2b, A1a} = webrtc_media_out:nack_timeouts(Now, M1),
    {M2, A1b} = webrtc_media_in:frame_timeouts(Now, M2b),
    A1 = A1a ++ A1b,
    {PauseFb, PauseEvents0, M2c} = webrtc_media_pause:timeouts(Now, M2),
    %% TMMBR hold-offs, silent owners and limited streams.
    {Limited, LimitActs, M2d} = webrtc_media_limit:timeouts(Now, M2c),
    {LimitSends, M2a} = webrtc_media_out:enqueue(Limited, Now, M2d),
    PauseEvents = PauseEvents0 ++ LimitActs ++ LimitSends,
    M3 = rtcp_session(Now, M2a),
    Pending = M3#media.pending_fb ++ Fb ++ PauseFb,
    case webrtc_rtcp_sched:expire(Now, M3#media.rtcp) of
        {send, R} ->
            %% Waiting and due feedback joins the regular compound, with
            %% the PAUSED repeats (RFC 7728 §6.2).
            M4 = webrtc_media_in:expire_idle(Now, M3#media{rtcp = R, pending_fb = []}),
            {Repeats, M4a} = webrtc_media_pause:report(M4),
            Fb2 = webrtc_media_limit:repeats(M4a) ++ webrtc_media_sync:requests(Now, M4a),
            {A2, M5} = webrtc_media_out:reports(Now, Pending ++ Repeats ++ Fb2, M4a),
            {M5, A0 ++ A1 ++ PauseEvents ++ A2};
        {wait, R} ->
            {A2, M4} = webrtc_media_out:send_feedback(Pending, Now, M3#media{rtcp = R, pending_fb = []}),
            {M4, A0 ++ A1 ++ PauseEvents ++ A2}
    end.

%% The RTCP bandwidth follows the send estimate (both directions are
%% counted alike) and the membership follows the streams (RFC 3550
%% §6.2, §6.3.3).
rtcp_session(Now, #media{rtcp = R0} = M) ->
    Sent = maps:get(rtp_sent, M#media.counters, 0),
    WeSent = Sent > M#media.rtp_sent_mark,
    Local = max(1, map_size(M#media.senders)),
    Remote = map_size(M#media.receivers),
    Senders = Remote + case WeSent of true -> Local; false -> 0 end,
    R1 = webrtc_rtcp_sched:set_session_bandwidth(session_bandwidth(M), R0),
    M#media{rtcp = webrtc_rtcp_sched:set_membership(Now, Local + max(1, Remote), Senders, WeSent, R1)}.

session_bandwidth(#media{cc = Cc}) ->
    2 * webrtc_cc:target(Cc).

-spec stats(state()) -> map().
stats(#media{} = M) ->
    #{
        counters => M#media.counters,
        congestion_control => webrtc_cc:stats(M#media.cc),
        senders => maps:map(
            fun(Key, S) ->
                (webrtc_rtp_stats:tx_info(S#snd.tx))#{
                    ssrc => S#snd.ssrc,
                    %% The RTX stream, when RTX is negotiated.
                    rtx_ssrc => case map_size(S#snd.rtx) of 0 -> undefined; _ -> S#snd.rtx_ssrc end,
                    encoding_index => encoding_index(Key, M)
                }
            end,
            M#media.senders
        ),
        sources => M#media.sources,
        playouts => M#media.playouts,
        %% Ended streams too, until W3C deletes them.
        receivers => maps:merge(maps:from_list([{S, I} || {S, I, _} <- M#media.ended]),
                                maps:map(fun(Ssrc, R) -> receiver_info(Ssrc, R, M) end, M#media.receivers)),
        streams => maps:merge(maps:from_list([{{in, S}, E} || {S, _, E} <- M#media.ended]), M#media.streams)
    }.

%% @doc What the statistics show of a receive stream.
-spec receiver_info(non_neg_integer(), #rcv{}, #media{}) -> map().
receiver_info(Ssrc, R, M) ->
    Info = (webrtc_rtp_stats:rx_info(R#rcv.rx))#{mid => R#rcv.mid, rid => webrtc_media_rid:rid(Ssrc, M#media.rids)},
    Info1 = case R#rcv.fec of
                undefined -> Info;
                F -> Info#{fec => webrtc_ulpfec:stats(F)}
            end,
    case R#rcv.frames of
        undefined -> Info1;
        Fb -> Info1#{frames => webrtc_frame_buffer:stats(Fb)}
    end.

%% The place of a simulcast layer in the section's send encodings
%% (W3C encodingIndex), 0 for a single stream.
encoding_index({Mid, Rid}, M) ->
    Rids = [R || #{rid := R} <- maps:get(send_rids, maps:get(Mid, M#media.recv, #{}), [])],
    case lists:search(fun({_, R}) -> R =:= Rid end, lists:enumerate(0, Rids)) of
        {value, {I, _}} -> I;
        false -> undefined
    end;
encoding_index(_Mid, _M) ->
    0.

rand32() ->
    <<S:32>> = crypto:strong_rand_bytes(4),
    S.

