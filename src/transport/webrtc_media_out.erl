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
    egress/3,
    mid_ext/1,
    nack_timeouts/2,
    pace/4,
    pick_pt/2,
    reports/3,
    retransmit/4,
    send_rtcp/2,
    senders/2,
    tmin/2
]).

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
        fun({Key, Pkt0, Rtx}, {Acc, M1}) ->
            {Twcc, Mid} =
                case maps:find(Key, M1#media.senders) of
                    {ok, #snd{twcc_ext = Id, mid = Mi}} -> {Id, Mi};
                    error -> {undefined, Key}
                end,
            case webrtc_cc:halted(Mid, M1#media.cc) of
                {true, _} ->
                    %% Halted while queued in the pacer (RFC 8083 §4.5).
                    {Acc, count(circuit_breaker_dropped, M1)};
                false ->
                    Pkt = add_twcc(Twcc, webrtc_cc:twcc_seq(M1#media.cc), Pkt0),
                    case webrtc_srtp:protect_rtp(webrtc_rtp:encode(Pkt), M1#media.out) of
                        {ok, Srtp, Out} ->
                            %% Circuit breakers work per transceiver: all
                            %% simulcast layers of a mid share the flow.
                            Cc = webrtc_cc:sent(Mid, byte_size(Srtp), Now, M1#media.cc),
                            {[{send, Srtp} | Acc], sent_stats(Key, Pkt, Rtx, M1#media{out = Out, cc = Cc})};
                        {error, _} ->
                            {Acc, count(srtp_failed, M1)}
                    end
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

tmin(infinity, B) -> B;
tmin(A, infinity) -> A;
tmin(A, B) -> min(A, B).

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
                {Out, MAcc2} = webrtc_media_in:nack_actions(Mid, Ssrc, Actions, MAcc1),
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

count(Key, M) ->
    count(Key, 1, M).

count(Key, N, #media{counters = C} = M) ->
    M#media{counters = maps:update_with(Key, fun(V) -> V + N end, N, C)}.

rand16() ->
    <<S:16>> = crypto:strong_rand_bytes(2),
    S.
