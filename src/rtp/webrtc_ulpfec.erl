%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc ULPFEC (RFC 5109): generic forward error correction of RTP
%% packets by XOR, as WebRTC sends it inside video RED (RFC 8854 §5.2).
%%
%% An FEC payload is the FEC header (§7.3: E, L, the P, X, CC, M and PT
%% bits, SN base, TS and length recovery fields), one level 0 header
%% (§7.4: protection length and a 16 or 48 bit mask) and the XOR of the
%% protected packets past their 12 byte RTP header. Only level 0 is
%% generated, with the protection length of the longest packet, so a
%% single missing packet is recovered whole.
%%
%% `protect/2' makes FEC payloads for packets of one SSRC; the packets
%% are the bytes protected, as sent before RED encapsulation. The
%% receiver keeps the last packets and FEC payloads (`new/0', `media/3',
%% `fec/2'): an FEC payload with exactly one of its packets missing gives
%% that packet back.
-module(webrtc_ulpfec).

-export([protect/2, decode/1, new/0, media/3, fec/2, repair/2, stats/1]).

-export_type([receiver/0]).

%% FlexFEC masks reach 110 packets back (RFC 8627 §4.2.2.1).
-define(MEDIA_KEPT, 160).
-define(FEC_KEPT, 32).

%%====================================================================
%% Generation
%%====================================================================

%% @doc `K' FEC payloads protecting `Packets' (`[{Seq, Bin}]', in
%% sequence order, at most 48), packet `I' in payload `I rem K': an
%% interleaved mask, so a burst of up to `K' losses is recovered.
-spec protect([{0..65535, binary()}], pos_integer()) -> [binary()].
protect([], _K) ->
    [];
protect(Packets, K) when length(Packets) =< 48, K >= 1 ->
    Indexed = lists:enumerate(0, Packets),
    Groups = [[P || {I, P} <- Indexed, I rem K =:= J] || J <- lists:seq(0, min(K, length(Packets)) - 1)],
    [payload(G) || G <- Groups, G =/= []].

payload([{Base, _} | _] = Group) ->
    Offsets = [(S - Base) band 16#FFFF || {S, _} <- Group],
    Long = lists:max(Offsets) >= 16,
    Bins = [B || {_, B} <- Group],
    ProtLen = lists:max([byte_size(B) - 12 || B <- Bins]),
    {B0, B1, Ts, Len, Data} = lists:foldl(
        fun(<<X0, X1, _:16, XTs:32, _:32, Rest/binary>> = B, {A0, A1, ATs, ALen, AData}) ->
            {A0 bxor X0, A1 bxor X1, ATs bxor XTs, ALen bxor (byte_size(B) - 12), bytes_xor(AData, pad(Rest, ProtLen))}
        end,
        {0, 0, 0, 0, binary:copy(<<0>>, ProtLen)},
        Bins
    ),
    MaskBits = case Long of true -> 48; false -> 16 end,
    Mask = lists:foldl(fun(O, M) -> M bor (1 bsl (MaskBits - 1 - O)) end, 0, Offsets),
    L = case Long of true -> 1; false -> 0 end,
    %% E = 0; the P, X and CC bits, then M and PT, recovered from their XOR.
    <<0:1, L:1, (B0 band 16#3F):6, B1, Base:16, Ts:32, Len:16, ProtLen:16, Mask:MaskBits, Data/binary>>.

pad(B, N) when byte_size(B) >= N -> binary:part(B, 0, N);
pad(B, N) -> <<B/binary, 0:((N - byte_size(B)) * 8)>>.

bytes_xor(A, B) ->
    crypto:exor(A, B).

%%====================================================================
%% Parsing
%%====================================================================

%% @doc Parse an FEC payload: SN base, the protected offsets and the
%% recovery fields.
-spec decode(binary()) -> {ok, map()} | {error, term()}.
decode(<<0:1, L:1, PXCC:6, MPT, Base:16, Ts:32, Len:16, Rest/binary>>) ->
    Bits = case L of 1 -> 48; 0 -> 16 end,
    case Rest of
        <<ProtLen:16, Mask:Bits, Data:ProtLen/binary, _/binary>> ->
            Offsets = [O || O <- lists:seq(0, Bits - 1), Mask band (1 bsl (Bits - 1 - O)) =/= 0],
            case Offsets of
                [] -> {error, empty_mask};
                _ -> {ok, #{base => Base, offsets => Offsets, bits0 => PXCC, bits1 => MPT, ts => Ts, length => Len,
                            data => Data}}
            end;
        _ ->
            {error, truncated}
    end;
decode(<<1:1, _/bits>>) ->
    {error, extension};
decode(_) ->
    {error, truncated}.

%%====================================================================
%% Recovery
%%====================================================================

-record(rx, {
    %% Packets received or recovered, by extended sequence number.
    media = #{} :: #{integer() => binary()},
    fec = [] :: [{[integer()], map(), binary()}],
    last :: undefined | integer(),
    stats = #{fec_packets_received => 0, fec_bytes_received => 0, fec_packets_discarded => 0,
              packets_recovered => 0} :: map()
}).

-opaque receiver() :: #rx{}.

-spec new() -> receiver().
new() ->
    #rx{}.

%% @doc A media packet received (its bytes as protected). Returns the
%% packets it lets FEC recover.
-spec media(0..65535, binary(), receiver()) -> {[binary()], receiver()}.
media(Seq, Bin, #rx{} = St0) ->
    {Ext, St} = unwrap(Seq, St0),
    recover(keep(St#rx{media = (St#rx.media)#{Ext => Bin}})).

%% @doc An FEC payload received, with the SSRC of the packet that
%% carried it: the SSRC of the packets it recovers.
-spec fec({non_neg_integer(), binary()}, receiver()) -> {[binary()], receiver()}.
fec({Ssrc, Payload}, #rx{stats = S} = St0) ->
    St1 = St0#rx{stats = S#{fec_packets_received := maps:get(fec_packets_received, S) + 1,
                            fec_bytes_received := maps:get(fec_bytes_received, S) + byte_size(Payload)}},
    case decode(Payload) of
        {ok, #{base := Base, offsets := Offs} = F} ->
            add(Ssrc, Base, Offs, F, St1);
        {error, _} ->
            {[], discard(1, St1)}
    end.

%% @doc A repair packet already read (FlexFEC, RFC 8627, see
%% webrtc_flexfec): SN base and offsets of the packets of `Ssrc' it
%% protects, the recovery fields and the repair payload, and its size.
-spec repair({non_neg_integer(), {0..65535, [non_neg_integer()]}, map(), non_neg_integer()}, receiver()) ->
    {[binary()], receiver()}.
repair({Ssrc, {Base, Offs}, F, Size}, #rx{stats = S} = St0) ->
    St1 = St0#rx{stats = S#{fec_packets_received := maps:get(fec_packets_received, S) + 1,
                            fec_bytes_received := maps:get(fec_bytes_received, S) + Size}},
    add(Ssrc, Base, Offs, F, St1).

add(Ssrc, Base, Offs, F, St1) ->
    {ExtBase, St2} = unwrap(Base, St1),
    Seqs = [ExtBase + O || O <- Offs],
    recover(keep(St2#rx{fec = [{Seqs, F, <<Ssrc:32>>} | St2#rx.fec]})).

-spec stats(receiver()) -> map().
stats(#rx{stats = S}) ->
    S.

%% Recover what can be: an FEC payload missing one packet gives it; a
%% payload with none missing is done.
recover(St) ->
    recover(St, []).

recover(#rx{fec = Fecs, media = Media} = St, Acc) ->
    Missing = fun({Seqs, _, _}) -> [S || S <- Seqs, not maps:is_key(S, Media)] end,
    case lists:partition(fun(F) -> Missing(F) =:= [] end, Fecs) of
        {Done, Rest} when Done =/= [] ->
            recover(discard(length(Done), St#rx{fec = Rest}), Acc);
        {[], _} ->
            case [{F, M} || F <- Fecs, [M] <- [Missing(F)]] of
                [] ->
                    {lists:reverse(Acc), St};
                [{{Seqs, F, Ssrc} = Entry, Seq} | _] ->
                    Others = [maps:get(S, Media) || S <- Seqs, S =/= Seq],
                    case rebuild(Seq band 16#FFFF, Ssrc, F, Others) of
                        {ok, Bin} ->
                            S0 = St#rx.stats,
                            St1 = St#rx{media = Media#{Seq => Bin}, fec = Fecs -- [Entry],
                                        stats = S0#{packets_recovered := maps:get(packets_recovered, S0) + 1}},
                            recover(St1, [Bin | Acc]);
                        error ->
                            recover(discard(1, St#rx{fec = Fecs -- [Entry]}), Acc)
                    end
            end
    end.

%% §8: the missing packet from the FEC payload and the other packets.
rebuild(Seq, <<Ssrc:32>>, #{bits0 := P0, bits1 := P1, ts := Ts0, length := L0, data := D0}, Others) ->
    ProtLen = byte_size(D0),
    {B0, B1, Ts, Len, Data} = lists:foldl(
        fun(<<X0, X1, _:16, XTs:32, _:32, Rest/binary>> = B, {A0, A1, ATs, ALen, AData}) ->
                {A0 bxor X0, A1 bxor X1, ATs bxor XTs, ALen bxor (byte_size(B) - 12), bytes_xor(AData, pad(Rest, ProtLen))};
           (_, Acc) ->
                Acc
        end,
        {P0, P1, Ts0, L0, D0},
        Others
    ),
    case Len =< ProtLen of
        true -> {ok, <<2:2, (B0 band 16#3F):6, B1, Seq:16, Ts:32, Ssrc:32, (binary:part(Data, 0, Len))/binary>>};
        false -> error
    end.

discard(N, #rx{stats = S} = St) ->
    St#rx{stats = S#{fec_packets_discarded := maps:get(fec_packets_discarded, S) + N}}.

unwrap(Seq, #rx{last = Last} = St) ->
    Ext = webrtc_rtp_seq:seq_unwrap(Seq, Last),
    {Ext, St#rx{last = case Last of undefined -> Ext; _ -> max(Ext, Last) end}}.

%% Bounded: the last ?MEDIA_KEPT sequence numbers and ?FEC_KEPT payloads.
keep(#rx{media = Media, fec = Fecs, last = Last} = St) ->
    Floor = Last - ?MEDIA_KEPT,
    {Kept, Old} = lists:split(min(length(Fecs), ?FEC_KEPT), Fecs),
    Stale = [F || {Seqs, _, _} = F <- Kept, lists:min(Seqs) < Floor],
    discard(length(Old) + length(Stale),
            St#rx{media = maps:filter(fun(S, _) -> S >= Floor end, Media), fec = Kept -- Stale}).
