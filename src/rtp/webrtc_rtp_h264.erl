%% @doc H.264 RTP payload format (RFC 6184): packetization-mode 1
%% (non-interleaved: single NAL unit packets, STAP-A and FU-A) and
%% packetization-mode 2 (interleaved: STAP-B, MTAP16, MTAP24, FU-A and
%% FU-B with decoding order numbers).
%%
%% `packetize/2' turns the NAL units of one access unit into RTP
%% payloads of at most `Mtu' bytes: consecutive small NAL units are
%% aggregated into STAP-A packets (§5.7.1), NAL units larger than the
%% MTU are fragmented into FU-A packets (§5.8), others are sent as
%% single NAL unit packets (§5.6). The caller sets the marker bit on the
%% last payload of the access unit.
%%
%% `depacketize/1' returns the NAL units of one payload, or a fragment
%% for FU-A. `depacketizer_new/0' and `depacketizer_push/3' reassemble
%% FU-A fragments across packets, dropping a fragmented NAL unit when a
%% sequence number is missing.
%%
%% `depacketize/1' rejects the interleaved types with
%% `{error, {unsupported, Type}}'; use the interleaved functions for
%% them:
%%
%% <ul>
%% <li>`packetize_interleaved/3' packs NAL units in decoding order,
%%     numbered from a DON, into STAP-B packets and FU-B / FU-A
%%     fragments (§5.7.1, §5.8, §6.4);</li>
%% <li>`mtap/2' builds one MTAP16 or MTAP24 packet (§5.7.2);</li>
%% <li>`depacketize_interleaved/1' reads one interleaved payload;</li>
%% <li>`deinterleaver_new/1', `deinterleaver_push/3' and
%%     `deinterleaver_flush/1' reassemble fragments and give the NAL
%%     units back in decoding order (§7.2), holding
%%     sprop-interleaving-depth + 1 VCL NAL units.</li>
%% </ul>
%%
%% `split_annexb/1' extracts NAL units from an Annex B byte stream.
%% Nothing here decodes video; key frame detection looks for an IDR
%% slice (NAL type 5).
-module(webrtc_rtp_h264).

-export([
    nal_type/1,
    split_annexb/1,
    packetize/2,
    depacketize/1,
    depacketizer_new/0,
    depacketizer_push/3,
    nal_types/1,
    is_keyframe/1,
    packetize_interleaved/3,
    mtap/2,
    depacketize_interleaved/1,
    deinterleaver_new/1,
    deinterleaver_push/3,
    deinterleaver_flush/1
]).

-export_type([depacketizer/0, fragment/0, deinterleaver/0, unit/0]).

-define(STAP_A, 24).
-define(STAP_B, 25).
-define(MTAP16, 26).
-define(MTAP24, 27).
-define(FU_A, 28).
-define(FU_B, 29).
-define(IDR, 5).

-type fragment() :: {fragment, start | middle | 'end', NalHeader :: byte(), Data :: binary()}.

-record(depack, {
    %% Expected next seq and the NAL being reassembled.
    next = undefined :: undefined | 0..65535,
    buf = undefined :: undefined | iodata()
}).

-opaque depacketizer() :: #depack{}.

%% A NAL unit of an interleaved payload with its decoding order number
%% and, in an MTAP, its timestamp offset.
-type unit() :: #{nal := binary(), don := 0..65535, ts_offset := non_neg_integer()}.

-record(deint, {
    %% sprop-interleaving-depth + 1 (§7.2).
    n :: pos_integer(),
    %% DON of the last NAL unit given back (PDON), none yet.
    pdon = undefined :: undefined | 0..65535,
    %% Buffered units, and the FU-B / FU-A reassembly in progress.
    buf = [] :: [{0..65535, binary()}],
    next = undefined :: undefined | 0..65535,
    frag = undefined :: undefined | {0..65535, iodata()}
}).

-opaque deinterleaver() :: #deint{}.

%% @doc NAL unit type of a NAL unit or payload (low 5 bits of byte 0).
-spec nal_type(binary()) -> 0..31.
nal_type(<<_:3, T:5, _/binary>>) -> T.

%% @doc Split an Annex B byte stream on 3 and 4 byte start codes.
%% Bytes before the first start code are ignored.
-spec split_annexb(binary()) -> [binary()].
split_annexb(Bin) ->
    Starts = [{P + L, P} || {P, L} <- binary:matches(Bin, <<0, 0, 1>>)],
    split_at(Bin, Starts).

split_at(_Bin, []) ->
    [];
split_at(Bin, [{From, _} | Rest]) ->
    To =
        case Rest of
            [] -> byte_size(Bin);
            [{_, Next} | _] -> Next
        end,
    Nal = trim_zeros(binary:part(Bin, From, To - From)),
    case Nal of
        <<>> -> split_at(Bin, Rest);
        _ -> [Nal | split_at(Bin, Rest)]
    end.

%% A zero before the next 3-byte start code belongs to a 4-byte start
%% code (trailing_zero_8bits), not to the NAL unit.
trim_zeros(<<>>) ->
    <<>>;
trim_zeros(B) ->
    case binary:last(B) of
        0 -> trim_zeros(binary:part(B, 0, byte_size(B) - 1));
        _ -> B
    end.

%%====================================================================
%% Packetization
%%====================================================================

-spec packetize([binary()], pos_integer()) -> [binary()].
packetize(Nals, Mtu) when is_integer(Mtu), Mtu > 2 ->
    pack([N || N <- Nals, byte_size(N) > 0], Mtu).

pack([], _) ->
    [];
pack([Nal | Rest], Mtu) when byte_size(Nal) > Mtu ->
    fu_a(Nal, Mtu) ++ pack(Rest, Mtu);
pack([Nal | Rest], Mtu) ->
    case stap(Rest, Mtu, [Nal], 1 + 2 + byte_size(Nal)) of
        {[_], _} -> [Nal | pack(Rest, Mtu)];
        {Group, Rest1} -> [stap_a(Group) | pack(Rest1, Mtu)]
    end.

stap([Nal | Rest], Mtu, Acc, Size) when Size + 2 + byte_size(Nal) =< Mtu ->
    stap(Rest, Mtu, [Nal | Acc], Size + 2 + byte_size(Nal));
stap(Rest, _, Acc, _) ->
    {lists:reverse(Acc), Rest}.

%% §5.7.1: F is the OR of the aggregated F bits, NRI the maximum.
stap_a(Nals) ->
    F = lists:foldl(fun(<<Fb:1, _:7, _/binary>>, A) -> A bor Fb end, 0, Nals),
    Nri = lists:max([N || <<_:1, N:2, _:5, _/binary>> <- Nals]),
    iolist_to_binary([<<F:1, Nri:2, ?STAP_A:5>> | [[<<(byte_size(N)):16>>, N] || N <- Nals]]).

fu_a(<<F:1, Nri:2, Type:5, Data/binary>>, Mtu) ->
    Max = Mtu - 2,
    Ind = <<F:1, Nri:2, ?FU_A:5>>,
    fragments(Data, Max, Ind, Type, 1).

fragments(Data, Max, Ind, Type, S) when byte_size(Data) =< Max ->
    [<<Ind/binary, S:1, 1:1, 0:1, Type:5, Data/binary>>];
fragments(Data, Max, Ind, Type, S) ->
    <<C:Max/binary, Rest/binary>> = Data,
    [<<Ind/binary, S:1, 0:1, 0:1, Type:5, C/binary>> | fragments(Rest, Max, Ind, Type, 0)].

%%====================================================================
%% Depacketization
%%====================================================================

%% @doc NAL units carried by one payload, or a FU-A fragment.
-spec depacketize(binary()) -> {ok, [binary()]} | fragment() | {error, term()}.
depacketize(<<>>) ->
    {error, empty};
depacketize(<<_F:1, _Nri:2, ?STAP_A:5, Rest/binary>>) ->
    stap_units(Rest, []);
depacketize(<<F:1, Nri:2, ?FU_A:5, S:1, E:1, _R:1, Type:5, Data/binary>>) ->
    Hdr = (F bsl 7) bor (Nri bsl 5) bor Type,
    case {S, E} of
        {1, 1} -> {error, bad_fu_a};
        {1, 0} -> {fragment, start, Hdr, Data};
        {0, 0} -> {fragment, middle, Hdr, Data};
        {0, 1} -> {fragment, 'end', Hdr, Data}
    end;
depacketize(<<_:3, ?FU_A:5, _/binary>>) ->
    {error, truncated};
depacketize(<<_:3, T:5, _/binary>>) when
    T =:= ?STAP_B; T =:= ?MTAP16; T =:= ?MTAP24; T =:= ?FU_B
->
    {error, {unsupported, T}};
depacketize(<<_:3, T:5, _/binary>> = Nal) when T >= 1, T =< 23 ->
    {ok, [Nal]};
depacketize(<<_:3, T:5, _/binary>>) ->
    {error, {bad_nal_type, T}}.

stap_units(<<>>, []) ->
    {error, empty_stap_a};
stap_units(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
stap_units(<<Size:16, Nal:Size/binary, Rest/binary>>, Acc) when Size > 0 ->
    stap_units(Rest, [Nal | Acc]);
stap_units(_, _) ->
    {error, truncated}.

-spec depacketizer_new() -> depacketizer().
depacketizer_new() ->
    #depack{}.

%% @doc Push one payload with its RTP sequence number. Returns the
%% complete NAL units it yields. A malformed payload, or a fragment that
%% does not continue the NAL unit being reassembled, drops that NAL unit.
-spec depacketizer_push(0..65535, binary(), depacketizer()) ->
    {ok, [binary()], depacketizer()} | {error, term(), depacketizer()}.
depacketizer_push(Seq, Payload, #depack{next = Next, buf = Buf}) ->
    InOrder = Next =:= Seq,
    St = #depack{next = (Seq + 1) band 16#FFFF},
    case depacketize(Payload) of
        {ok, Nals} ->
            {ok, Nals, St};
        {fragment, start, Hdr, Data} ->
            {ok, [], St#depack{buf = [Hdr, Data]}};
        {fragment, middle, _, Data} when InOrder, Buf =/= undefined ->
            {ok, [], St#depack{buf = [Buf, Data]}};
        {fragment, 'end', _, Data} when InOrder, Buf =/= undefined ->
            {ok, [iolist_to_binary([Buf, Data])], St};
        {fragment, _, _, _} ->
            {error, lost_fragment, St};
        {error, R} ->
            {error, R, St}
    end.

%%====================================================================
%% Interleaved mode (packetization-mode 2)
%%====================================================================

%% @doc Packetize NAL units given in decoding order, the first with
%% decoding order number `Don'. Small units are aggregated in STAP-B
%% packets (a unit alone too: single NAL unit packets are not allowed in
%% this mode, §6.4); larger ones become an FU-B then FU-A fragments.
%% Returns the payloads and the DON of the next NAL unit.
-spec packetize_interleaved([binary()], pos_integer(), 0..65535) -> {[binary()], 0..65535}.
packetize_interleaved(Nals, Mtu, Don) when is_integer(Mtu), Mtu > 5 ->
    pack_b([N || N <- Nals, byte_size(N) > 0], Mtu, Don, []).

pack_b([], _Mtu, Don, Acc) ->
    {lists:reverse(Acc), Don};
pack_b([Nal | Rest], Mtu, Don, Acc) when 1 + 2 + 2 + byte_size(Nal) > Mtu ->
    pack_b(Rest, Mtu, next_don(Don), lists:reverse(fu_b(Nal, Mtu, Don), Acc));
pack_b([Nal | Rest], Mtu, Don, Acc) ->
    {Group, Rest1} = stap(Rest, Mtu, [Nal], 1 + 2 + 2 + byte_size(Nal)),
    pack_b(Rest1, Mtu, (Don + length(Group)) band 16#FFFF, [stap_b(Group, Don) | Acc]).

stap_b(Nals, Don) ->
    iolist_to_binary([aggregate_header(Nals, ?STAP_B), <<Don:16>> | [[<<(byte_size(N)):16>>, N] || N <- Nals]]).

%% §5.7: F is the OR of the aggregated F bits, NRI the maximum.
aggregate_header(Nals, Type) ->
    F = lists:foldl(fun(<<Fb:1, _:7, _/binary>>, A) -> A bor Fb end, 0, Nals),
    Nri = lists:max([N || <<_:1, N:2, _:5, _/binary>> <- Nals]),
    <<F:1, Nri:2, Type:5>>.

%% §5.8: the first fragment is an FU-B carrying the DON, the others
%% FU-A.
fu_b(<<F:1, Nri:2, Type:5, Data/binary>>, Mtu, Don) ->
    %% At least one byte is left for the end fragment: S and E are
    %% never both set.
    First = min(Mtu - 4, byte_size(Data) - 1),
    <<C:First/binary, Rest/binary>> = Data,
    [<<F:1, Nri:2, ?FU_B:5, 1:1, 0:1, 0:1, Type:5, Don:16, C/binary>>
     | fragments(Rest, Mtu - 2, <<F:1, Nri:2, ?FU_A:5>>, Type, 0)].

next_don(Don) -> (Don + 1) band 16#FFFF.

%% @doc One MTAP16 (`16') or MTAP24 (`24') payload (§5.7.2) from units
%% in transmission order with their DON and their timestamp offset from
%% the packet's RTP timestamp. DONB is the smallest DON in decoding
%% order; every DON must lie within 255 of it and the offsets within 16
%% or 24 bits.
-spec mtap([{binary(), 0..65535, non_neg_integer()}], 16 | 24) -> {ok, binary()} | {error, term()}.
mtap([_ | _] = Units, Bits) when Bits =:= 16; Bits =:= 24 ->
    Dons = [D || {_, D, _} <- Units],
    Donb = hd(lists:sort(fun(A, B) -> don_diff(A, B) >= 0 end, Dons)),
    Ok = lists:all(
        fun({N, D, Off}) ->
            byte_size(N) > 0 andalso ((D - Donb) band 16#FFFF) =< 255 andalso Off >= 0 andalso Off < (1 bsl Bits)
        end,
        Units
    ),
    case Ok of
        false ->
            {error, badarg};
        true ->
            Type = case Bits of 16 -> ?MTAP16; 24 -> ?MTAP24 end,
            {ok, iolist_to_binary([
                aggregate_header([N || {N, _, _} <- Units], Type),
                <<Donb:16>>
                | [[<<(byte_size(N)):16, ((D - Donb) band 16#FFFF):8, Off:Bits>>, N] || {N, D, Off} <- Units]
            ])}
    end;
mtap(_, _) ->
    {error, badarg}.

%% @doc The NAL units of one interleaved payload with their DON, or a
%% fragment: the FU-B start carries the DON, the FU-A fragments that
%% follow continue it. STAP-A and single NAL unit packets are not
%% allowed in this mode (§6.4).
-spec depacketize_interleaved(binary()) ->
    {ok, [unit()]}
    | {fragment, start, byte(), 0..65535, binary()}
    | {fragment, middle | 'end', byte(), binary()}
    | {error, term()}.
depacketize_interleaved(<<_:3, ?STAP_B:5, Don:16, Rest/binary>>) ->
    case stap_units(Rest, []) of
        {ok, Nals} ->
            {ok, [#{nal => N, don => (Don + I) band 16#FFFF, ts_offset => 0} || {I, N} <- lists:enumerate(0, Nals)]};
        {error, _} = E ->
            E
    end;
depacketize_interleaved(<<_:3, T:5, Donb:16, Rest/binary>>) when T =:= ?MTAP16; T =:= ?MTAP24 ->
    Bits = case T of ?MTAP16 -> 16; ?MTAP24 -> 24 end,
    mtap_units(Rest, Donb, Bits, []);
depacketize_interleaved(<<F:1, Nri:2, ?FU_B:5, 1:1, 0:1, _R:1, Type:5, Don:16, Data/binary>>) ->
    {fragment, start, (F bsl 7) bor (Nri bsl 5) bor Type, Don, Data};
depacketize_interleaved(<<_:3, ?FU_B:5, _/binary>>) ->
    {error, bad_fu_b};
depacketize_interleaved(<<_:3, ?FU_A:5, 1:1, _/bitstring>>) ->
    %% A fragmented NAL unit starts with an FU-B in this mode.
    {error, bad_fu_a};
depacketize_interleaved(<<_:3, ?FU_A:5, _/binary>> = P) ->
    depacketize(P);
depacketize_interleaved(<<>>) ->
    {error, empty};
depacketize_interleaved(<<_:3, T:5, _/binary>>) ->
    {error, {not_interleaved, T}}.

mtap_units(<<>>, _Donb, _Bits, []) ->
    {error, empty_mtap};
mtap_units(<<>>, _Donb, _Bits, Acc) ->
    {ok, lists:reverse(Acc)};
mtap_units(Bin, Donb, Bits, Acc) ->
    case Bin of
        <<Size:16, Dond:8, Off:Bits, Nal:Size/binary, Rest/binary>> when Size > 0 ->
            mtap_units(Rest, Donb, Bits, [#{nal => Nal, don => (Donb + Dond) band 16#FFFF, ts_offset => Off} | Acc]);
        _ ->
            {error, truncated}
    end.

%% @doc A de-interleaving buffer for sprop-interleaving-depth `Depth'
%% (§7.2; 0 when not signaled).
-spec deinterleaver_new(non_neg_integer()) -> deinterleaver().
deinterleaver_new(Depth) when is_integer(Depth), Depth >= 0 ->
    #deint{n = Depth + 1}.

%% @doc Push one payload with its RTP sequence number. Returns the NAL
%% units that leave the buffer, in decoding order. A malformed payload
%% or a lost fragment drops what it carried.
-spec deinterleaver_push(0..65535, binary(), deinterleaver()) ->
    {ok, [binary()], deinterleaver()} | {error, term(), deinterleaver()}.
deinterleaver_push(Seq, Payload, #deint{next = Next, frag = Frag} = D0) ->
    InOrder = Next =:= Seq,
    D = D0#deint{next = (Seq + 1) band 16#FFFF},
    case depacketize_interleaved(Payload) of
        {ok, Units} ->
            release(add(D, [{Don, N} || #{don := Don, nal := N} <- Units]));
        {fragment, start, Hdr, Don, Data} ->
            {ok, [], D#deint{frag = {Don, [Hdr, Data]}}};
        {fragment, middle, _, Data} when InOrder, Frag =/= undefined ->
            {Don, Buf} = Frag,
            {ok, [], D#deint{frag = {Don, [Buf, Data]}}};
        {fragment, 'end', _, Data} when InOrder, Frag =/= undefined ->
            {Don, Buf} = Frag,
            release(add(D#deint{frag = undefined}, [{Don, iolist_to_binary([Buf, Data])}]));
        {fragment, _, _, _} ->
            {error, lost_fragment, D#deint{frag = undefined}};
        {error, R} ->
            {error, R, D}
    end.

add(D, Units) -> D#deint{buf = D#deint.buf ++ Units}.

%% While N or more VCL NAL units wait, give back the one closest in
%% decoding order after PDON (§7.2).
release(D) ->
    release(D, []).

release(#deint{n = N, buf = Buf} = D, Out) ->
    case length([x || {_, Nal} <- Buf, vcl(Nal)]) >= N of
        true ->
            {Unit, D1} = take_next(D),
            release(D1, [Unit | Out]);
        false ->
            {ok, lists:reverse(Out), D}
    end.

%% @doc Everything left, in decoding order (end of the stream).
-spec deinterleaver_flush(deinterleaver()) -> {[binary()], deinterleaver()}.
deinterleaver_flush(#deint{buf = []} = D) ->
    {[], D};
deinterleaver_flush(D) ->
    {Unit, D1} = take_next(D),
    {More, D2} = deinterleaver_flush(D1),
    {[Unit | More], D2}.

%% The first unit given back is the earliest buffered in decoding order.
take_next(#deint{pdon = P, buf = Buf} = D) ->
    Before = case P of
                 undefined -> fun({A, _}, {B, _}) -> don_diff(A, B) >= 0 end;
                 _ -> fun({A, _}, {B, _}) -> distance(P, A) =< distance(P, B) end
             end,
    [{Don, Nal} = First | _] = lists:sort(Before, Buf),
    {Nal, D#deint{pdon = Don, buf = lists:delete(First, Buf)}}.

%% DON distance from PDON (§7.2).
distance(P, Don) when Don > P -> Don - P;
distance(P, Don) -> 65535 - P + Don + 1.

%% don_diff(m, n) of §5.5: positive when n follows m in decoding order.
don_diff(M, N) when M =:= N -> 0;
don_diff(M, N) when M < N, N - M < 32768 -> N - M;
don_diff(M, N) when M > N, M - N >= 32768 -> 65536 - M + N;
don_diff(M, N) when M < N -> -(M + 65536 - N);
don_diff(M, N) -> -(M - N).

vcl(<<_:3, T:5, _/binary>>) -> T >= 1 andalso T =< 5.

%%====================================================================
%% Key frames
%%====================================================================

%% @doc NAL unit types present in a payload. For FU-A only the start
%% fragment reports its type.
-spec nal_types(binary()) -> [0..31].
nal_types(Payload) ->
    case depacketize(Payload) of
        {ok, Nals} -> [nal_type(N) || N <- Nals];
        {fragment, start, Hdr, _} -> [Hdr band 31];
        _ -> []
    end.

%% @doc True when the payload carries (the start of) an IDR slice.
-spec is_keyframe(binary()) -> boolean().
is_keyframe(Payload) ->
    lists:member(?IDR, nal_types(Payload)).
