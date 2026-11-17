%% @doc Media session of one BUNDLE transport, as a sans-IO engine:
%% SRTP/SRTCP protection, RTP demultiplexing to transceivers, RTCP
%% reports, NACK-based retransmission (RFC 4585, RFC 4588) and keyframe
%% requests (RFC 4585 PLI, RFC 5104 FIR).
%%
%% Media payloads are never decoded: the application sends and receives
%% RTP payloads (or whole packets when forwarding).
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
%% target bitrate for everything sent on the transport changed) and
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
    send_packet/4,
    resume/3,
    request_keyframe/3,
    request_pause/4,
    set_congestion_control/3,
    handle_packet/3,
    handle_packet/4,
    handle_timeout/2,
    next_timeout/1,
    stats/1
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
                [{X, Mid} || #{rtx_ssrc := X} <- Rs, is_integer(X)]
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
%% negotiated codec, and `rid' to send on one simulcast layer.
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
                    send_packet(Mid, Pkt, Now, M#media{senders = (M#media.senders)#{Mid := S1}});
                error ->
                    {error, unknown_codec}
            end
    end.

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
    case maps:find(Mid, M#media.senders) of
        error ->
            {error, not_sending};
        {ok, #snd{mid = TMid} = S} ->
            case {webrtc_cc:halted(TMid, M#media.cc), webrtc_media_pause:is_paused(S)} of
                {{true, Reason}, _} -> {error, {circuit_breaker, Reason}};
                {false, true} -> {error, paused};
                {false, false} -> send_packet(Mid, S, Pkt0, Now, M)
            end
    end.

send_packet(Mid, S, Pkt0, Now, M) ->
    Pkt = Pkt0#rtp{ssrc = S#snd.ssrc, seq = S#snd.seq, csrcs = Pkt0#rtp.csrcs,
                   ext = webrtc_media_out:header_ext(S, Pkt0#rtp.ext)},
    Next = (S#snd.seq + 1) band 16#FFFF,
    S1 = S#snd{
        seq = Next,
        cycles = S#snd.cycles + case Next of 0 -> 1; _ -> 0 end,
        last_ts = Pkt#rtp.ts,
        last_ts_at = Now,
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
        webrtc_media_out:tmin(webrtc_media_out:tmin(R, webrtc_cc:next_timeout(Cc)), webrtc_media_pause:next_timeout(M)),
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
    {PauseFb, PauseEvents, M2a} = webrtc_media_pause:timeouts(Now, M2),
    M3 = rtcp_session(Now, M2a),
    Pending = M3#media.pending_fb ++ Fb ++ PauseFb,
    case webrtc_rtcp_sched:expire(Now, M3#media.rtcp) of
        {send, R} ->
            %% Waiting and due feedback joins the regular compound, with
            %% the PAUSED repeats (RFC 7728 §6.2).
            M4 = webrtc_media_in:expire_idle(Now, M3#media{rtcp = R, pending_fb = []}),
            {Repeats, M4a} = webrtc_media_pause:report(M4),
            {A2, M5} = webrtc_media_out:reports(Now, Pending ++ Repeats, M4a),
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
        receivers => maps:map(
            fun(Ssrc, R) ->
                Info = (webrtc_rtp_stats:rx_info(R#rcv.rx))#{mid => R#rcv.mid, rid => webrtc_media_rid:rid(Ssrc, M#media.rids)},
                case R#rcv.frames of
                    undefined -> Info;
                    Fb -> Info#{frames => webrtc_frame_buffer:stats(Fb)}
                end
            end,
            M#media.receivers
        ),
        streams => M#media.streams
    }.

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

