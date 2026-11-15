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
    send_feedback/3,
    send_rtcp/2,
    senders/2,
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
    TwccExt = maps:get(?URI_TWCC, SendExt, undefined),
    {Pause, HoldOff} = pause(Sec, Old),
    case Old of
        #snd{} -> Old#snd{codecs = Cs, rtx = Rtx, mid_ext = MidExt, twcc_ext = TwccExt, pause = Pause, hold_off = HoldOff};
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
                hold_off = HoldOff
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
wire_size({raw, Bin}) -> byte_size(Bin);
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
                false when element(1, Pkt0) =:= raw ->
                    %% A retransmission without RTX: the exact bytes sent
                    %% the first time, not protected again.
                    {raw, Srtp} = Pkt0,
                    Cc = webrtc_cc:sent(Mid, byte_size(Srtp), Now, M1#media.cc),
                    {[{send, Srtp} | Acc], sent_stats(Key, Pkt0, Rtx, M1#media{cc = Cc})};
                false ->
                    Pkt = add_twcc(Twcc, webrtc_cc:twcc_seq(M1#media.cc), Pkt0),
                    case webrtc_srtp:protect_rtp(webrtc_rtp:encode(Pkt), M1#media.out) of
                        {ok, Srtp, Out} ->
                            %% Circuit breakers work per transceiver: all
                            %% simulcast layers of a mid share the flow.
                            Cc = webrtc_cc:sent(Mid, byte_size(Srtp), Now, M1#media.cc),
                            M2 = keep_wire(Key, Pkt, Srtp, Rtx, Now, M1#media{out = Out, cc = Cc}),
                            {[{send, Srtp} | Acc], sent_stats(Key, Pkt, Rtx, M2)};
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

%% Keep the protected bytes of a first transmission with its packet in
%% the retransmission buffer: without RTX a NACK is answered with them.
%% Protecting the packet again would reuse its SRTP index, which SRTP
%% refuses (it would reuse keystream); the same bytes reuse nothing and
%% the receiver accepts them since it never got that index.
keep_wire(_Key, _Pkt, _Srtp, true, _Now, M) ->
    M;
keep_wire(Key, #rtp{seq = Seq} = Pkt, Srtp, false, Now, M) ->
    case maps:find(Key, M#media.senders) of
        {ok, S} ->
            Buf = webrtc_nack_buffer:store(Seq, {Pkt, Srtp}, Now, S#snd.buffer),
            M#media{senders = (M#media.senders)#{Key := S#snd{buffer = Buf}}};
        error ->
            M
    end.

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
    Fixed = byte_size(webrtc_rtcp:encode(Heads ++ [Sdes | Feedback])),
    {Picked, M1} = pick_sources(blocks_fitting(?RTCP_BUDGET - Fixed), M),
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
    send_regular(Reports ++ [Sdes | Feedback], Now, M2).

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
send_feedback(Pkts, Now, #media{rtcp = R} = M) ->
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
