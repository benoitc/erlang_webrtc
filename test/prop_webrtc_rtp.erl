%% PropEr properties for the RTP / RTCP codecs: encode/decode round
%% trips for RTP, header extensions and every RTCP packet type, and
%% decoders that never crash on arbitrary or mutated input.
-module(prop_webrtc_rtp).
-include_lib("proper/include/proper.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").

-export([
    prop_rtp_roundtrip/0,
    prop_rtp_parsed_ext_roundtrip/0,
    prop_ext_roundtrip/0,
    prop_rtcp_roundtrip/0,
    prop_twcc_roundtrip/0,
    prop_twcc_arrivals/0,
    prop_nack_items/0,
    prop_seq_unwrap/0,
    prop_rtp_decode_never_crashes/0,
    prop_rtp_mutation_never_crashes/0,
    prop_rtcp_decode_never_crashes/0,
    prop_rtcp_mutation_never_crashes/0,
    prop_payload_helpers_never_crash/0
]).

%%====================================================================
%% Generators
%%====================================================================

u(Bits) -> integer(0, (1 bsl Bits) - 1).

words(Max) -> ?LET(N, integer(0, Max), binary(N * 4)).

bin(Max) -> ?LET(N, integer(0, Max), binary(N)).

bin(Min, Max) -> ?LET(N, integer(Min, Max), binary(N)).

rtp(ExtGen) ->
    ?LET(
        {Pad, M, PT, Seq, Ts, Ssrc, Csrcs, Ext, Payload},
        {
            oneof([0, integer(1, 255)]),
            boolean(),
            u(7),
            u(16),
            u(32),
            u(32),
            ?LET(N, integer(0, 15), vector(N, u(32))),
            ExtGen,
            bin(300)
        },
        #rtp{
            padding = Pad,
            marker = M,
            pt = PT,
            seq = Seq,
            ts = Ts,
            ssrc = Ssrc,
            csrcs = Csrcs,
            ext = Ext,
            payload = Payload
        }
    ).

raw_ext() -> oneof([undefined, {u(16), words(20)}]).

one_byte_elems() -> list({integer(1, 14), bin(1, 16)}).

two_byte_elems() -> list({integer(1, 255), bin(40)}).

elems() -> oneof([one_byte_elems(), two_byte_elems()]).

rb() ->
    ?LET(
        {S, F, L, E, J, Lsr, Dlsr},
        {u(32), u(8), integer(-16#800000, 16#7FFFFF), u(32), u(32), u(32), u(32)},
        #rtcp_rb{ssrc = S, fraction_lost = F, lost = L, ext_seq = E, jitter = J, lsr = Lsr, dlsr = Dlsr}
    ).

rbs() -> ?LET(N, integer(0, 4), vector(N, rb())).

sdes_item() ->
    oneof([
        {oneof([cname, name, email, phone, loc, tool, note, mid, rid, repaired_rid]), bin(255)},
        {oneof([9, 10, 11, 14, integer(16, 255)]), bin(255)},
        ?LET({P, V}, {bin(100), bin(100)}, {{priv, P}, V})
    ]).

bitrate(MantBits) -> ?LET({E, M}, {integer(0, 40), u(MantBits)}, M bsl E).

twcc_status() -> oneof([not_received, integer(0, 255), integer(-32768, 32767)]).

twcc(MaxLen) ->
    ?LET(
        {S, M, Base, Ref, Fb, Statuses},
        {u(32), u(32), u(16), integer(-16#800000, 16#7FFFFF), u(8), ?LET(N, integer(0, MaxLen), vector(N, twcc_status()))},
        #rtcp_twcc{
            sender_ssrc = S,
            media_ssrc = M,
            base_seq = Base,
            ref_time = Ref,
            fb_count = Fb,
            packets = lists:zip(
                [(Base + I) band 16#FFFF || I <- lists:seq(0, length(Statuses) - 1)], Statuses
            )
        }
    ).

ccfb_metric() -> oneof([not_received, {u(2), u(13)}]).

xr_block() ->
    oneof([
        {rrtr, u(64)},
        {dlrr, list({u(32), u(32), u(32)})},
        {oneof([1, 2, 3, 6, 7, integer(8, 255)]), u(8), words(4)}
    ]).

rtpfb_raw_fmt() -> oneof([0, 2, 5, 6, 7, 8, 9, 10, 12, 13, 14, 16, 31]).
psfb_raw_fmt() -> oneof([0, 3, 5, 6, 7, 8, 14, 16, 31]).

rtcp_packet() ->
    oneof([
        ?LET(
            {S, Ntp, Ts, P, O, R, E},
            {u(32), u(64), u(32), u(32), u(32), rbs(), words(3)},
            #rtcp_sr{ssrc = S, ntp = Ntp, rtp_ts = Ts, packets = P, octets = O, reports = R, ext = E}
        ),
        ?LET({S, R, E}, {u(32), rbs(), words(3)}, #rtcp_rr{ssrc = S, reports = R, ext = E}),
        ?LET(C, list({u(32), list(sdes_item())}), #rtcp_sdes{chunks = lists:sublist(C, 31)}),
        ?LET(
            {Ss, R},
            {list(u(32)), oneof([undefined, bin(255)])},
            #rtcp_bye{ssrcs = lists:sublist(Ss, 31), reason = R}
        ),
        ?LET(
            {Sub, S, N, D},
            {u(5), u(32), binary(4), words(8)},
            #rtcp_app{subtype = Sub, ssrc = S, name = N, data = D}
        ),
        ?LET(
            {S, M, I},
            {u(32), u(32), non_empty(list({u(16), u(16)}))},
            #rtcp_nack{sender_ssrc = S, media_ssrc = M, items = I}
        ),
        ?LET(
            {S, M, E},
            {u(32), u(32), list({u(32), bitrate(17), u(9)})},
            #rtcp_tmmbr{sender_ssrc = S, media_ssrc = M, entries = E}
        ),
        ?LET(
            {S, M, E},
            {u(32), u(32), list({u(32), bitrate(17), u(9)})},
            #rtcp_tmmbn{sender_ssrc = S, media_ssrc = M, entries = E}
        ),
        twcc(60),
        ?LET(
            {S, Reports, Ts},
            {u(32), list({u(32), u(16), ?LET(N, integer(0, 30), vector(N, ccfb_metric()))}), u(32)},
            #rtcp_ccfb{sender_ssrc = S, reports = Reports, timestamp = Ts}
        ),
        ?LET({S, M}, {u(32), u(32)}, #rtcp_pli{sender_ssrc = S, media_ssrc = M}),
        ?LET(
            {S, M, E},
            {u(32), u(32), non_empty(list({u(13), u(13), u(6)}))},
            #rtcp_sli{sender_ssrc = S, media_ssrc = M, entries = E}
        ),
        ?LET(
            {S, M, E},
            {u(32), u(32), non_empty(list({u(32), u(8)}))},
            #rtcp_fir{sender_ssrc = S, media_ssrc = M, entries = E}
        ),
        ?LET(
            {S, M, B, Ss},
            {u(32), u(32), bitrate(18), list(u(32))},
            #rtcp_remb{sender_ssrc = S, media_ssrc = M, bitrate = B, ssrcs = Ss}
        ),
        ?LET({S, B}, {u(32), list(xr_block())}, #rtcp_xr{ssrc = S, blocks = B}),
        ?LET(
            {PT, C, B},
            {oneof([192, 193, 194, 195, 196, 197, 198, 199, integer(208, 223)]), u(5), words(6)},
            #rtcp_raw{pt = PT, count = C, body = B}
        ),
        ?LET(
            {F, S, M, B},
            {rtpfb_raw_fmt(), u(32), u(32), words(4)},
            #rtcp_raw{pt = 205, count = F, body = <<S:32, M:32, B/binary>>}
        ),
        ?LET(
            {F, S, M, B},
            {psfb_raw_fmt(), u(32), u(32), words(4)},
            #rtcp_raw{pt = 206, count = F, body = <<S:32, M:32, B/binary>>}
        )
    ]).

%% Encoded valid packets with one byte replaced.
mutated(Gen) ->
    ?LET(
        {Bin, Pos, Byte},
        {Gen, nat(), u(8)},
        case byte_size(Bin) of
            0 ->
                Bin;
            Size ->
                P = Pos rem Size,
                <<H:P/binary, _, T/binary>> = Bin,
                <<H/binary, Byte, T/binary>>
        end
    ).

rtcp_bin() -> ?LET(Ps, non_empty(list(rtcp_packet())), webrtc_rtcp:encode(Ps)).

%%====================================================================
%% Round trips
%%====================================================================

prop_rtp_roundtrip() ->
    ?FORALL(P, rtp(raw_ext()), webrtc_rtp:decode(webrtc_rtp:encode(P)) =:= {ok, P}).

prop_rtp_parsed_ext_roundtrip() ->
    ?FORALL(
        P,
        rtp(elems()),
        webrtc_rtp:decode(webrtc_rtp:encode(P), #{extensions => parse}) =:= {ok, P}
    ).

prop_ext_roundtrip() ->
    ?FORALL(
        {Elems, Form},
        oneof([{one_byte_elems(), oneof([auto, one_byte, two_byte])}, {two_byte_elems(), two_byte}]),
        begin
            {Profile, Data} = webrtc_rtp_ext:encode(Elems, #{form => Form}),
            byte_size(Data) rem 4 =:= 0 andalso webrtc_rtp_ext:decode(Profile, Data) =:= {ok, Elems}
        end
    ).

prop_rtcp_roundtrip() ->
    ?FORALL(
        Ps,
        non_empty(list(rtcp_packet())),
        webrtc_rtcp:decode(webrtc_rtcp:encode(Ps)) =:= {ok, Ps}
    ).

prop_twcc_roundtrip() ->
    ?FORALL(T, twcc(3000), webrtc_rtcp:decode(webrtc_rtcp:encode(T)) =:= {ok, [T]}).

%% Rebuilt arrival times are within half a 250 us tick of the originals,
%% including gaps that need a new feedback message and negative deltas.
prop_twcc_arrivals() ->
    ?FORALL(
        {Base, Start, Steps},
        {
            u(16),
            integer(1000000, 1 bsl 38),
            list({integer(1, 3), oneof([integer(-5000, 200000), integer(8200000, 9000000)])})
        },
        begin
            {Arrivals, _, _} = lists:foldl(
                fun({Gap, Dt}, {Acc, Seq, T}) ->
                    {[{Seq band 16#FFFF, T + Dt} | Acc], Seq + Gap, T + Dt}
                end,
                {[], Base, Start},
                Steps
            ),
            In = lists:reverse(Arrivals),
            Msgs = webrtc_rtcp_twcc:from_arrivals(1, 2, 0, In),
            Out = [{S, A} || M <- Msgs, {S, A} <- webrtc_rtcp_twcc:arrivals(M), A =/= not_received],
            length(Out) =:= length(In) andalso
                lists:all(fun({{S, A}, {S, B}}) -> abs(A - B) =< 125 end, lists:zip(In, Out)) andalso
                lists:all(
                    fun(M) -> webrtc_rtcp:decode(webrtc_rtcp:encode(M)) =:= {ok, [M]} end, Msgs
                )
        end
    ).

prop_nack_items() ->
    ?FORALL(
        {Base, Offsets},
        {u(16), non_empty(list(integer(0, 2000)))},
        begin
            Seqs = [(Base + O) band 16#FFFF || O <- [0 | Offsets]],
            Items = webrtc_rtcp_fb:nack_items(Seqs),
            lists:sort(webrtc_rtcp_fb:nack_seqs(Items)) =:= lists:usort(Seqs)
        end
    ).

prop_seq_unwrap() ->
    ?FORALL(
        {Last, D},
        {integer(-1000000, 1000000), integer(-32768, 32767)},
        webrtc_rtp_seq:seq_unwrap((Last + D) band 16#FFFF, Last) =:= Last + D andalso
            webrtc_rtp_seq:seq_diff((Last + D) band 16#FFFF, Last band 16#FFFF) =:= D
    ).

%%====================================================================
%% Robustness
%%====================================================================

rtp_total(Bin) ->
    is_result(webrtc_rtp:decode(Bin)) andalso
        is_result(webrtc_rtp:decode(Bin, #{extensions => parse})) andalso
        is_result(webrtc_rtp:peek(Bin)) andalso
        is_result(webrtc_rtp:header_size(Bin)) andalso
        is_result(webrtc_rtp:rewrite(Bin, #{seq => 1})) andalso
        lists:member(webrtc_rtp:classify(Bin), [rtp, rtcp, unknown]).

is_result({ok, _}) -> true;
is_result({error, _}) -> true;
is_result(_) -> false.

prop_rtp_decode_never_crashes() ->
    ?FORALL(
        Bin, oneof([binary(), ?LET({F, B}, {u(6), binary()}, <<2:2, F:6, B/binary>>)]), rtp_total(Bin)
    ).

prop_rtp_mutation_never_crashes() ->
    ?FORALL(
        Bin,
        mutated(?LET(P, rtp(oneof([raw_ext(), elems()])), webrtc_rtp:encode(P))),
        rtp_total(Bin)
    ).

rtcp_total(Bin) ->
    is_result(webrtc_rtcp:decode(Bin)) andalso is_result(webrtc_rtcp:decode(Bin, #{mode => compound})).

prop_rtcp_decode_never_crashes() ->
    ?FORALL(
        Bin,
        oneof([binary(), ?LET({T, B}, {oneof([200, 201, 202, 203, 204, 205, 206, 207]), binary()}, rtcp_header(T, B))]),
        rtcp_total(Bin)
    ).

%% A well-formed header (any count/FMT) followed by random words.
rtcp_header(PT, B) ->
    Words = byte_size(B) div 4,
    Body = binary:part(B, 0, Words * 4),
    <<2:2, 0:1, (Words rem 32):5, PT, Words:16, Body/binary>>.

prop_rtcp_mutation_never_crashes() ->
    ?FORALL(Bin, mutated(rtcp_bin()), rtcp_total(Bin)).

prop_payload_helpers_never_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            _ = webrtc_rtp_vp8:parse(Bin),
            _ = webrtc_rtp_vp8:rewrite(Bin, #{picture_id => 5, tl0picidx => 6}),
            _ = webrtc_rtp_h264:depacketize(Bin),
            _ = webrtc_rtp_h264:depacketizer_push(0, Bin, webrtc_rtp_h264:depacketizer_new()),
            _ = webrtc_rtp_vp9:parse(Bin),
            _ = webrtc_rtp_av1:aggregation_header(Bin),
            _ = webrtc_rtp_opus:duration(Bin),
            is_boolean(webrtc_rtp_vp8:is_keyframe(Bin)) andalso
                is_boolean(webrtc_rtp_h264:is_keyframe(Bin)) andalso
                is_boolean(webrtc_rtp_vp9:is_keyframe(Bin)) andalso
                is_boolean(webrtc_rtp_av1:is_keyframe(Bin))
        end
    ).
