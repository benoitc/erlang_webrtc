%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc FlexFEC (RFC 8627): parity FEC repair packets on their own RTP
%% stream, protecting the packets of a source stream named in the repair
%% packet's CSRC list (§4.2.1).
%%
%% The FEC header (§4.2.2) starts with R and F, then the P, X, CC, M and
%% PT recovery fields, the length recovery and the TS recovery fields.
%% With R = 0 and F = 0 an SN base and a flexible mask of 15, 46 or 110
%% bits follow for each protected SSRC (§4.2.2.1: k = 1, another mask
%% block follows; k = 0, the last); with F = 1 an SN base and L columns
%% and D rows (§4.2.2.2); with R = 1 the packet is a retransmission of a
%% source packet (§4.2.2.3). The repair payload is the XOR of everything
%% after the 12 byte RTP header of each source packet (§6.2).
%%
%% `protect/2' builds flexible mask repair payloads. `decode/2' reads a
%% repair payload for the given CSRC count; the recovery itself is the
%% same XOR as ULPFEC's and is done by `webrtc_ulpfec'.
-module(webrtc_flexfec).

-export([protect/2, decode/2]).

%% @doc `K' repair payloads protecting `Packets' (`[{Seq, Bin}]', one
%% SSRC, in sequence order, at most 110), packet `I' in payload `I rem
%% K'.
-spec protect([{0..65535, binary()}], pos_integer()) -> [binary()].
protect([], _K) ->
    [];
protect(Packets, K) when length(Packets) =< 110, K >= 1 ->
    Indexed = lists:enumerate(0, Packets),
    Groups = [[P || {I, P} <- Indexed, I rem K =:= J] || J <- lists:seq(0, min(K, length(Packets)) - 1)],
    [payload(G) || G <- Groups, G =/= []].

payload([{Base, _} | _] = Group) ->
    Offsets = [(S - Base) band 16#FFFF || {S, _} <- Group],
    Bins = [B || {_, B} <- Group],
    Len = lists:max([byte_size(B) - 12 || B <- Bins]),
    {B0, B1, LenX, Ts, Data} = lists:foldl(
        fun(<<X0, X1, _:16, XTs:32, _:32, Rest/binary>> = B, {A0, A1, AL, ATs, AData}) ->
            {A0 bxor X0, A1 bxor X1, AL bxor (byte_size(B) - 12), ATs bxor XTs, crypto:exor(AData, pad(Rest, Len))}
        end,
        {0, 0, 0, 0, binary:copy(<<0>>, Len)},
        Bins
    ),
    <<0:1, 0:1, (B0 band 16#3F):6, B1, LenX:16, Ts:32, Base:16, (mask(Offsets))/bits, Data/binary>>.

%% The mask blocks for the largest offset: 15, 46 or 110 bits.
mask(Offsets) ->
    Max = lists:max(Offsets),
    Bits = if Max < 15 -> 15; Max < 46 -> 46; true -> 110 end,
    M = lists:foldl(fun(O, A) -> A bor (1 bsl (Bits - 1 - O)) end, 0, Offsets),
    case Bits of
        15 -> <<0:1, M:15>>;
        46 -> <<1:1, (M bsr 31):15, 0:1, (M band 16#7FFFFFFF):31>>;
        110 -> <<1:1, (M bsr 95):15, 1:1, ((M bsr 64) band 16#7FFFFFFF):31, (M band 16#FFFFFFFFFFFFFFFF):64>>
    end.

pad(B, N) when byte_size(B) >= N -> binary:part(B, 0, N);
pad(B, N) -> <<B/binary, 0:((N - byte_size(B)) * 8)>>.

%% @doc Read a repair payload whose RTP header has `Count' CSRCs (the
%% protected SSRCs). A parity repair gives, per protected SSRC in CSRC
%% order, `{Base, Offsets}', and the recovery fields; a retransmission
%% gives the source packet.
-spec decode(binary(), non_neg_integer()) ->
    {ok, #{blocks := [{0..65535, [non_neg_integer()]}], atom() => term()}} | {retransmission, binary()} | {error, term()}.
decode(<<1:1, 0:1, Rest/bits>>, _Count) when bit_size(Rest) >= 94 ->
    %% §4.2.2.3: the source packet, the version bits replaced by R and F.
    {retransmission, <<2:2, Rest/bits>>};
decode(<<1:1, 1:1, _/bits>>, _Count) ->
    {error, reserved};
decode(<<0:1, F:1, PXCC:6, MPT, Len:16, Ts:32, Rest/binary>>, Count) when Count >= 1 ->
    %% The length recovery is the XOR of the source lengths, not that of
    %% the repair payload.
    case blocks(F, Count, Rest, []) of
        {ok, Blocks, Data} ->
            {ok, #{blocks => Blocks, bits0 => PXCC, bits1 => MPT, ts => Ts, length => Len, data => Data}};
        {error, _} = E ->
            E
    end;
decode(_, _) ->
    {error, truncated}.

blocks(_F, 0, Rest, Acc) ->
    {ok, lists:reverse(Acc), Rest};
%% Flexible mask.
blocks(0, N, <<Base:16, 0:1, M:15, Rest/binary>>, Acc) ->
    blocks(0, N - 1, Rest, [{Base, offsets(M, 15)} | Acc]);
blocks(0, N, <<Base:16, 1:1, M0:15, 0:1, M1:31, Rest/binary>>, Acc) ->
    blocks(0, N - 1, Rest, [{Base, offsets((M0 bsl 31) bor M1, 46)} | Acc]);
blocks(0, N, <<Base:16, 1:1, M0:15, 1:1, M1:31, M2:64, Rest/binary>>, Acc) ->
    blocks(0, N - 1, Rest, [{Base, offsets((M0 bsl 95) bor (M1 bsl 64) bor M2, 110)} | Acc]);
%% Fixed L columns and D rows (§4.2.2.2, Figure 14).
blocks(1, _N, <<_:16, 0, 0, _/binary>>, _Acc) ->
    {error, reserved};
blocks(1, N, <<Base:16, L, D, Rest/binary>>, Acc) when L > 0 ->
    Offs = case D =< 1 of
               true -> lists:seq(0, L - 1);
               false -> [I * L || I <- lists:seq(0, D - 1)]
           end,
    blocks(1, N - 1, Rest, [{Base, Offs} | Acc]);
blocks(_, _, _, _) ->
    {error, truncated}.

offsets(M, Bits) ->
    [O || O <- lists:seq(0, Bits - 1), M band (1 bsl (Bits - 1 - O)) =/= 0].
