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
%% Actions: `{send, Datagram}' and `{event, Event}' with Event one of
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
    ready/1,
    send/5,
    send_packet/4,
    request_keyframe/3,
    set_congestion_control/3,
    handle_packet/3,
    handle_timeout/2,
    next_timeout/1,
    stats/1
]).

-export_type([state/0, sender_key/0]).

-define(URI_MID, <<"urn:ietf:params:rtp-hdrext:sdes:mid">>).
-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).
-define(URI_RRID, <<"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>).
-define(URI_TWCC, <<"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>).
-define(RTCP_INTERVAL, 1000).
-define(BUFFER_SIZE, 512).

-record(snd, {
    mid :: binary(),
    kind :: audio | video,
    ssrc :: non_neg_integer(),
    rtx_ssrc :: non_neg_integer(),
    codecs :: [map()],
    %% Negotiated rtx payload type per primary payload type.
    rtx :: #{0..127 => 0..127},
    mid_ext :: undefined | pos_integer(),
    twcc_ext :: undefined | pos_integer(),
    seq :: 0..65535,
    rtx_seq :: 0..65535,
    last_ts = 0 :: non_neg_integer(),
    last_ts_at :: undefined | integer(),
    tx :: term(),
    buffer :: term(),
    %% Simulcast layer (RFC 8853) and the RtpStreamId and
    %% RepairedRtpStreamId extension ids (RFC 8852).
    rid :: undefined | binary(),
    rid_ext :: undefined | pos_integer(),
    rrid_ext :: undefined | pos_integer()
}).

-record(rcv, {
    mid :: binary(),
    clock_rate :: pos_integer(),
    rx :: term(),
    nack :: undefined | term()
}).

-record(media, {
    cname :: binary(),
    rtcp_ssrc :: non_neg_integer(),
    out :: undefined | term(),
    in :: undefined | term(),
    senders = #{} :: #{sender_key() => #snd{}},
    %% Incoming streams by SSRC.
    receivers = #{} :: #{non_neg_integer() => #rcv{}},
    %% Demultiplexing tables, rebuilt on every negotiation.
    ssrc_mid = #{} :: #{non_neg_integer() => binary()},
    rtx_ssrc = #{} :: #{non_neg_integer() => non_neg_integer()},
    pt_mid = #{} :: #{0..127 => binary()},
    mid_ext = #{} :: #{binary() => pos_integer()},
    recv = #{} :: #{binary() => map()},
    rids = webrtc_media_rid:new() :: webrtc_media_rid:state(),
    %% Transport-wide-cc extension ids we accept on incoming packets.
    twcc_ids = [] :: [pos_integer()],
    cc :: webrtc_cc:state(),
    rtcp_at = infinity :: integer() | infinity,
    counters = #{} :: map()
}).

-opaque state() :: #media{}.
%% A transceiver (mid) or one simulcast layer of it.
-type sender_key() :: binary() | {binary(), binary()}.

%%====================================================================
%% Setup
%%====================================================================

-spec new(map()) -> state().
new(Opts) ->
    #media{
        cname = maps:get(cname, Opts, <<"webrtc">>),
        rtcp_ssrc = rand32(),
        cc = webrtc_cc:new(maps:get(cc, Opts, #{}))
    }.

%% @doc Apply the negotiated media sections (`media' of
%% `webrtc_jsep:negotiated/1'). Existing sequence numbers and statistics
%% are kept for transceivers that remain.
-spec configure([map()], state()) -> state().
configure(Sections, #media{} = M) ->
    Senders = maps:from_list(
        lists:append([
            senders(S, M#media.senders)
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
            sender_ssrc => M#media.rtcp_ssrc
        },
        M#media.cc
    ),
    M#media{
        senders = Senders,
        twcc_ids = TwccIds,
        cc = Cc,
        recv = Recv,
        ssrc_mid = maps:merge(M#media.ssrc_mid, SsrcMid),
        rtx_ssrc = RtxSsrc,
        pt_mid = PtMid,
        mid_ext = MidExt,
        rids = webrtc_media_rid:configure(Sections, M#media.rids)
    }.

%% One sender per transceiver, or one per negotiated simulcast layer.
senders(#{mid := Mid, send_rids := [_ | _] = Layers} = Sec, Old) ->
    Exts = maps:get(send_extensions, Sec, #{}),
    [
        {{Mid, Rid}, (sender(Sec#{ssrc := S, rtx_ssrc := X}, maps:get({Mid, Rid}, Old, undefined)))#snd{
            rid = Rid,
            rid_ext = maps:get(?URI_RID, Exts, undefined),
            rrid_ext = maps:get(?URI_RRID, Exts, undefined)
        }}
     || #{rid := Rid, ssrc := S, rtx_ssrc := X} <- Layers
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
    TwccExt = maps:get(?URI_TWCC, SendExt, undefined),
    case Old of
        #snd{} -> Old#snd{codecs = Cs, rtx = Rtx, mid_ext = MidExt, twcc_ext = TwccExt};
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
                buffer = webrtc_nack_buffer:new(#{size => ?BUFFER_SIZE})
            }
    end.

%% @doc Install the SRTP contexts from the DTLS-SRTP handshake.
-spec set_srtp(webrtc_srtp:profile(), binary(), client | server, integer(), state()) -> state().
set_srtp(Profile, Material, Role, Now, M) ->
    {Out, In} = webrtc_srtp:dtls_contexts(Profile, Material, Role, #{}),
    M#media{out = Out, in = In, rtcp_at = Now + ?RTCP_INTERVAL}.

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
            case pick_pt(Opts, S) of
                {ok, Pt} ->
                    Pkt = #rtp{
                        pt = Pt,
                        marker = maps:get(marker, Opts, false),
                        ts = maps:get(timestamp, Opts, 0),
                        payload = Payload
                    },
                    send_packet(Mid, Pkt, Now, M);
                error ->
                    {error, unknown_codec}
            end
    end.

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
pick_pt(_, #snd{codecs = [#{pt := P} | _]}) ->
    {ok, P};
pick_pt(_, _) ->
    error.

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
        {ok, S} ->
            Pkt = Pkt0#rtp{ssrc = S#snd.ssrc, seq = S#snd.seq, csrcs = Pkt0#rtp.csrcs, ext = mid_ext(S)},
            S1 = S#snd{
                seq = (S#snd.seq + 1) band 16#FFFF,
                last_ts = Pkt#rtp.ts,
                last_ts_at = Now,
                buffer = webrtc_nack_buffer:store(Pkt#rtp.seq, Pkt, Now, S#snd.buffer)
            },
            M1 = M#media{senders = (M#media.senders)#{Mid := S1}},
            {Sends, M2} = pace(S#snd.kind, [{Mid, Pkt, false}], Now, M1),
            {ok, Sends, M2}
    end.

%% Queue packets in the pacer, then protect and send what it releases.
pace(Class, Items, Now, M) ->
    {Out, Cc} = lists:foldl(
        fun({_, P, _} = Item, {Acc, C}) ->
            {O, C1} = webrtc_cc:enqueue({Class, wire_size(P), Item}, Now, C),
            {Acc ++ O, C1}
        end,
        {[], M#media.cc},
        Items
    ),
    egress(Out, Now, M#media{cc = Cc}).

%% Header, payload and an allowance for extensions and the SRTP tag.
wire_size(#rtp{payload = P, csrcs = Cs}) -> 12 + 4 * length(Cs) + byte_size(P) + 32.

%% Add the transport-wide sequence number, protect and count.
egress(Items, Now, M0) ->
    {Sends, M} = lists:foldl(
        fun({Mid, Pkt0, Rtx}, {Acc, M1}) ->
            Twcc =
                case maps:find(Mid, M1#media.senders) of
                    {ok, #snd{twcc_ext = Id}} -> Id;
                    error -> undefined
                end,
            Pkt = add_twcc(Twcc, webrtc_cc:twcc_seq(M1#media.cc), Pkt0),
            case webrtc_srtp:protect_rtp(webrtc_rtp:encode(Pkt), M1#media.out) of
                {ok, Srtp, Out} ->
                    Cc = webrtc_cc:sent(Mid, byte_size(Srtp), Now, M1#media.cc),
                    {[{send, Srtp} | Acc], sent_stats(Mid, Pkt, Rtx, M1#media{out = Out, cc = Cc})};
                {error, _} ->
                    {Acc, count(srtp_failed, M1)}
            end
        end,
        {[], M0},
        Items
    ),
    {lists:reverse(Sends), M}.

add_twcc(undefined, _Seq, Pkt) ->
    Pkt;
add_twcc(_Id, undefined, Pkt) ->
    Pkt;
add_twcc(Id, Seq, #rtp{ext = Ext} = Pkt) ->
    Elems = [E || is_list(Ext), {I, _} = E <- Ext, I =/= Id],
    Pkt#rtp{ext = Elems ++ [{Id, webrtc_rtp_ext:twcc_seq(Seq)}]}.

sent_stats(_Mid, _Pkt, true, M) ->
    count(retransmitted, M);
sent_stats(Mid, Pkt, false, M) ->
    case maps:find(Mid, M#media.senders) of
        {ok, S} ->
            Tx = webrtc_rtp_stats:tx_packet(byte_size(Pkt#rtp.payload), S#snd.tx),
            count(rtp_sent, M#media{senders = (M#media.senders)#{Mid := S#snd{tx = Tx}}});
        error ->
            count(rtp_sent, M)
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

%% @doc Ask the remote sender of a transceiver for a keyframe (PLI), on
%% every stream of the mid or on one simulcast layer with `{Mid, Rid}'.
-spec request_keyframe(sender_key(), integer(), state()) -> {[{send, binary()}], state()}.
request_keyframe({Mid, Rid}, _Now, M) ->
    Ssrcs = [S || {ok, S} <- [webrtc_media_rid:source(Mid, Rid, M#media.rids)]],
    Pkts = [#rtcp_pli{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = S} || S <- Ssrcs],
    send_rtcp(Pkts, M);
request_keyframe(Mid, _Now, M) ->
    Ssrcs = [S || {S, #rcv{mid = Mi}} <- maps:to_list(M#media.receivers), Mi =:= Mid],
    Pkts = [#rtcp_pli{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = S} || S <- Ssrcs],
    send_rtcp(Pkts, M).

%% @doc Change the congestion control options at run time (see
%% `webrtc_cc:set_options/3'): `pacing', `pacing_factor',
%% `min_bitrate', `max_bitrate'.
-spec set_congestion_control(map(), integer(), state()) -> {list(), state()}.
set_congestion_control(Opts, Now, M) ->
    {Items, Events, Cc} = webrtc_cc:set_options(Opts, Now, M#media.cc),
    {Sends, M1} = egress(Items, Now, M#media{cc = Cc}),
    {Sends ++ [{event, E} || E <- Events], M1}.

%%====================================================================
%% Receiving
%%====================================================================

-spec handle_packet(binary(), integer(), state()) -> {state(), list()}.
handle_packet(_Bin, _Now, #media{in = undefined} = M) ->
    {M, []};
handle_packet(Bin, Now, M) ->
    case webrtc_rtp:classify(Bin) of
        rtp -> rtp_in(Bin, Now, M);
        rtcp -> rtcp_in(Bin, Now, M);
        unknown -> {count(dropped, M), []}
    end.

rtp_in(Bin, Now, M) ->
    case webrtc_srtp:unprotect_rtp(Bin, M#media.in) of
        {ok, Plain, In} ->
            M1 = M#media{in = In},
            case webrtc_rtp:decode(Plain, #{extensions => parse}) of
                {ok, Pkt} -> route(Pkt, Now, twcc_arrival(Pkt, Now, M1));
                {error, _} -> {count(dropped, M1), []}
            end;
        {error, _} ->
            {count(srtp_rejected, M), []}
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

route(#rtp{ssrc = Ssrc} = Pkt, Now, M) ->
    case find_mid(Pkt, M) of
        undefined ->
            {count(unroutable, M), []};
        Mid ->
            M1 = M#media{ssrc_mid = (M#media.ssrc_mid)#{Ssrc => Mid}},
            case maps:find(Ssrc, M1#media.rtx_ssrc) of
                {ok, Primary} -> rtx_in(Mid, Primary, Pkt, Now, M1);
                error -> layer_in(Mid, Pkt, Now, M1)
            end
    end.

%% Simulcast layers are told apart by rid (RFC 8852); an RTX stream is
%% bound to its layer by repaired-rid and remembered.
layer_in(Mid, #rtp{ssrc = Ssrc} = Pkt, Now, M) ->
    case webrtc_media_rid:classify(Mid, Pkt, M#media.rids) of
        {{repair, Primary}, R} ->
            M1 = M#media{rids = R, rtx_ssrc = (M#media.rtx_ssrc)#{Ssrc => Primary}},
            rtx_in(Mid, Primary, Pkt, Now, M1);
        {drop, R} ->
            {count(unknown_rid, M#media{rids = R}), []};
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
                {ok, Orig} -> deliver(Mid, Orig, Now, count(rtx_received, M));
                {error, _} -> {count(dropped, M), []}
            end;
        _ ->
            {count(dropped, M), []}
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
    M1 = M#media{receivers = (M#media.receivers)#{Ssrc => R1}},
    {Out, M2} = nack_actions(Mid, Ssrc, NackActions, M1),
    Event =
        case webrtc_media_rid:rid(Ssrc, M2#media.rids) of
            undefined -> {rtp, Mid, Pkt};
            Rid -> {rtp, Mid, Rid, Pkt}
        end,
    {count(rtp_received, M2), [{event, Event} | Out]}.

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

nack_actions(_Mid, _Ssrc, [], M) ->
    {[], M};
nack_actions(Mid, Ssrc, Actions, M) ->
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
    send_rtcp(Pkts, M).

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
                        {count(rtcp_received, M#media{in = In}), []},
                        Pkts
                    );
                {error, _} ->
                    {count(dropped, M#media{in = In}), []}
            end;
        {error, _} ->
            {count(srtp_rejected, M), []}
    end.

rtcp_packet(#rtcp_nack{media_ssrc = Ssrc, items = Items}, Now, M) ->
    case sender_by_ssrc(Ssrc, M) of
        {ok, S} -> retransmit(S, webrtc_rtcp_fb:nack_seqs(Items), Now, M);
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
rtcp_packet(#rtcp_sr{ssrc = Ssrc, reports = Rbs} = SR, Now, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, R} ->
            Rx = webrtc_rtp_stats:rx_sender_report(SR, Now, R#rcv.rx),
            report_blocks(Rbs, Now, M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{rx = Rx}}});
        error ->
            report_blocks(Rbs, Now, M)
    end;
rtcp_packet(#rtcp_sdes{chunks = Chunks}, _Now, M) ->
    {M#media{rids = webrtc_media_rid:sdes(Chunks, M#media.ssrc_mid, M#media.rids)}, []};
rtcp_packet(#rtcp_rr{reports = Rbs}, Now, M) ->
    report_blocks(Rbs, Now, M);
rtcp_packet(#rtcp_bye{ssrcs = Ssrcs}, _Now, M) ->
    {M, [{event, {bye, maps:get(S, M#media.ssrc_mid, undefined), S}} || S <- Ssrcs]};
rtcp_packet(P, Now, M) when is_record(P, rtcp_remb); is_record(P, rtcp_twcc) ->
    {Events, Cc} = webrtc_cc:rtcp(P, Now, M#media.cc),
    {M#media{cc = Cc}, [{event, {rtcp, undefined, P}} | [{event, E} || E <- Events]]};
rtcp_packet(_P, _Now, M) ->
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

%% Resend NACKed packets, over RTX when negotiated (RFC 4588 §4),
%% through the pacer ahead of new video.
retransmit(#snd{} = S0, Seqs, Now, M) ->
    Key = skey(S0),
    {Found, Buf} = webrtc_nack_buffer:retransmit(Seqs, Now, S0#snd.buffer),
    {Wires, S1} = lists:mapfoldl(fun({_Seq, Pkt}, S) -> rtx_packet(Pkt, S) end, S0#snd{buffer = Buf}, Found),
    M1 = M#media{senders = (M#media.senders)#{Key := S1}},
    {Sends, M2} = pace(rtx, [{Key, W, true} || W <- Wires], Now, M1),
    {M2, Sends}.

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

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#media{rtcp_at = R, receivers = Rs, cc = Cc}) ->
    lists:foldl(
        fun
            (#rcv{nack = undefined}, Acc) -> Acc;
            (#rcv{nack = N}, Acc) -> tmin(webrtc_nack:next_timeout(N), Acc)
        end,
        tmin(R, webrtc_cc:next_timeout(Cc)),
        maps:values(Rs)
    ).

tmin(infinity, B) -> B;
tmin(A, infinity) -> A;
tmin(A, B) -> min(A, B).

-spec handle_timeout(integer(), state()) -> {state(), list()}.
handle_timeout(Now, #media{out = undefined} = M) ->
    _ = Now,
    {M, []};
handle_timeout(Now, M0) ->
    {Fb, A0, M1} = cc_timeouts(Now, M0),
    {M2, A1} = nack_timeouts(Now, M1),
    case M2#media.rtcp_at =/= infinity andalso Now >= M2#media.rtcp_at of
        true ->
            %% Transport-wide feedback due now joins the compound report.
            {A2, M3} = reports(Now, Fb, M2),
            %% RFC 3550 §6.3.5: randomize in [0.5, 1.5] of the interval.
            Next = Now + round(?RTCP_INTERVAL * (0.5 + rand:uniform())),
            {M3#media{rtcp_at = Next}, A0 ++ A1 ++ A2};
        false ->
            {A2, M3} = send_rtcp(Fb, M2),
            {M3, A0 ++ A1 ++ A2}
    end.

cc_timeouts(Now, M) ->
    {Items, Fb, Events, Cc} = webrtc_cc:handle_timeout(Now, M#media.cc),
    {Sends, M1} = egress(Items, Now, M#media{cc = Cc}),
    {Fb, Sends ++ [{event, E} || E <- Events], M1}.

nack_timeouts(Now, M) ->
    maps:fold(
        fun
            (_Ssrc, #rcv{nack = undefined}, Acc) ->
                Acc;
            (Ssrc, #rcv{nack = N, mid = Mid} = R, {MAcc, AAcc}) ->
                {N1, Actions} = webrtc_nack:handle_timeout(Now, N),
                MAcc1 = MAcc#media{receivers = (MAcc#media.receivers)#{Ssrc := R#rcv{nack = N1}}},
                {Out, MAcc2} = nack_actions(Mid, Ssrc, Actions, MAcc1),
                {MAcc2, AAcc ++ Out}
        end,
        {M, []},
        M#media.receivers
    ).

%% One compound packet: SR per sender (or one RR), SDES CNAME, then
%% feedback (RFC 3550 §6.1, RFC 4585 §3.1; reduced-size not used for
%% regular reports).
reports(Now, Feedback, M) ->
    {Blocks, Rcvs} = maps:fold(
        fun(Ssrc, R, {Bs, Acc}) ->
            {B, Rx} = webrtc_rtp_stats:report_block(Now, R#rcv.rx),
            {[B | Bs], Acc#{Ssrc => R#rcv{rx = Rx}}}
        end,
        {[], #{}},
        M#media.receivers
    ),
    M1 = M#media{receivers = Rcvs},
    Ntp = webrtc_rtp_stats:ntp_from_us(erlang:system_time(microsecond)),
    Senders = maps:values(M1#media.senders),
    Reports =
        case Senders of
            [] ->
                [#rtcp_rr{ssrc = M1#media.rtcp_ssrc, reports = lists:sublist(Blocks, 31)}];
            _ ->
                [
                    webrtc_rtp_stats:sender_report(
                        S#snd.ssrc, Ntp, rtp_ts_now(S, Now), S#snd.tx, lists:sublist(Blocks, 31)
                    )
                 || S <- Senders
                ]
        end,
    Cname = {cname, M1#media.cname},
    Chunks =
        case Senders of
            [] -> [{M1#media.rtcp_ssrc, [Cname]}];
            _ -> [{S#snd.ssrc, [Cname | layer_sdes(S)]} || S <- Senders]
        end,
    Sdes = #rtcp_sdes{chunks = Chunks},
    send_rtcp(Reports ++ [Sdes | Feedback], M1).

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

%%====================================================================
%% Stats
%%====================================================================

-spec stats(state()) -> map().
stats(#media{} = M) ->
    #{
        counters => M#media.counters,
        congestion_control => webrtc_cc:stats(M#media.cc),
        senders => maps:map(
            fun(_Mid, S) -> (webrtc_rtp_stats:tx_info(S#snd.tx))#{ssrc => S#snd.ssrc} end,
            M#media.senders
        ),
        receivers => maps:map(
            fun(Ssrc, R) ->
                (webrtc_rtp_stats:rx_info(R#rcv.rx))#{mid => R#rcv.mid, rid => webrtc_media_rid:rid(Ssrc, M#media.rids)}
            end,
            M#media.receivers
        )
    }.

count(Key, M) ->
    count(Key, 1, M).

count(Key, N, #media{counters = C} = M) ->
    M#media{counters = maps:update_with(Key, fun(V) -> V + N end, N, C)}.

rand32() ->
    <<S:32>> = crypto:strong_rand_bytes(4),
    S.

rand16() ->
    <<S:16>> = crypto:strong_rand_bytes(2),
    S.
