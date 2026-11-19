%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc SCTP packet and chunk codec (RFC 9260 §3, RFC 3758, RFC 4820,
%% RFC 6525, RFC 8260, RFC 9653).
%%
%% This module is pure: it turns binaries into `#sctp_packet{}' records
%% and chunk terms and back. Parameters and error causes inside chunks are
%% handled by `webrtc_sctp_param'. The association logic lives elsewhere.
%%
%% Packets: `decode/1' parses the 12 byte common header and the chunks.
%% It does not verify the checksum; the `checksum' field holds the wire
%% value read as `<<Crc:32/little>>', which equals
%% `webrtc_sctp_crc32c:crc32c/1' of the packet (checksum zeroed) when the
%% packet is intact. Use `checksum_ok/2' to verify it. `encode/2' writes
%% the CRC32c, or 0 with `#{checksum => zero}' (RFC 9653).
%%
%% Chunk terms, `chunk()':
%% <ul>
%% <li>`#sctp_data{}': DATA (type 0) when `idata' is false, I-DATA (type
%% 64) when true. For DATA `mid' is the 16-bit SSN and `fsn' is 0. For
%% I-DATA the last header word is the PPID when `beginning' is set (`fsn'
%% is then 0) and the FSN otherwise (`ppid' is then 0 after decode).</li>
%% <li>`#sctp_init{}': INIT (`ack' false, type 1) or INIT ACK (type 2).</li>
%% <li>`#sctp_sack{}': gaps as `{Start, End}' offsets, dups as TSNs, in
%% wire order.</li>
%% <li>`{heartbeat, Info}', `{heartbeat_ack, Info}': `Info' is the value of
%% the Heartbeat Info parameter.</li>
%% <li>`{abort, T, [cause()]}', `{op_error, [cause()]}' (ERROR chunk),
%% `{shutdown, CumTsn}', `shutdown_ack', `{cookie_echo, Cookie}',
%% `cookie_ack', `{shutdown_complete, T}'.</li>
%% <li>`{forward_tsn, NewCumTsn, [{Sid, Ssn}]}' (RFC 3758),
%% `{i_forward_tsn, NewCumTsn, [{Sid, Unordered, Mid}]}' (RFC 8260).</li>
%% <li>`{reconfig, [reconf_param()]}' (RFC 6525), `{pad, NBytes}' (RFC 4820).</li>
%% <li>`{unknown_chunk, Type, Flags, Value}' for any other type; it encodes
%% back to the original chunk.</li>
%% </ul>
%%
%% Decoding is strict (RFC 9260 §3.2) and never raises. Error reasons:
%% <ul>
%% <li>`too_short': the packet is shorter than the 12 byte header.</li>
%% <li>`trailing_bytes': 1 to 3 bytes left after a chunk and its padding,
%% or a partial padding after the last chunk.</li>
%% <li>`{bad_chunk, Type}': a chunk length below 4 or past the end of the
%% packet, a fixed-size chunk with the wrong length, a SACK whose length
%% does not match its counts, a HEARTBEAT without Heartbeat Info, an
%% empty RE-CONFIG, or bytes left inside a chunk that do not form a
%% parameter or cause.</li>
%% <li>`{bad_param, Type}', `{bad_cause, Code}': a malformed parameter or
%% error cause inside a chunk (see `webrtc_sctp_param').</li>
%% </ul>
%%
%% Flags of chunks other than DATA, I-DATA, ABORT and SHUTDOWN COMPLETE
%% are ignored on decode and written as 0. Chunks are padded with zero
%% bytes; the padding of the last parameter or cause inside a chunk is not
%% counted in the chunk length on encode, and both forms are accepted on
%% decode.
-module(webrtc_sctp_chunk).

-include("webrtc_sctp.hrl").

-export([
    decode/1,
    encode/1,
    encode/2,
    checksum_ok/2,
    decode_chunks/1,
    encode_chunk/1,
    chunk_size/1,
    unrecognized_chunk_action/1
]).

-export_type([
    chunk/0,
    data_chunk/0,
    init_chunk/0,
    sack_chunk/0,
    packet/0,
    encode_opts/0,
    error_reason/0
]).

-type u16() :: 0..16#FFFF.
-type u32() :: 0..16#FFFFFFFF.

-type data_chunk() :: #sctp_data{}.
-type init_chunk() :: #sctp_init{}.
-type sack_chunk() :: #sctp_sack{}.
-type packet() :: #sctp_packet{}.

-type chunk() ::
    data_chunk()
    | init_chunk()
    | sack_chunk()
    | {heartbeat, Info :: binary()}
    | {heartbeat_ack, Info :: binary()}
    | {abort, T :: boolean(), [webrtc_sctp_param:cause()]}
    | {shutdown, CumTsn :: u32()}
    | shutdown_ack
    | cookie_ack
    | {op_error, [webrtc_sctp_param:cause()]}
    | {cookie_echo, Cookie :: binary()}
    | {shutdown_complete, T :: boolean()}
    | {forward_tsn, NewCumTsn :: u32(), [{Sid :: u16(), Ssn :: u16()}]}
    | {i_forward_tsn, NewCumTsn :: u32(), [{Sid :: u16(), Unordered :: boolean(), Mid :: u32()}]}
    | {reconfig, [webrtc_sctp_param:reconf_param(), ...]}
    | {pad, NBytes :: non_neg_integer()}
    | {unknown_chunk, Type :: 0..255, Flags :: 0..255, Value :: binary()}.

-type encode_opts() :: #{checksum => crc32c | zero}.

-type error_reason() ::
    too_short
    | trailing_bytes
    | {bad_chunk, 0..255}
    | webrtc_sctp_param:error_reason().

-define(HEARTBEAT_INFO, 1).
-define(MAX_VALUE, 65531).

%% DATA / I-DATA flags.
-define(F_E, 16#01).
-define(F_B, 16#02).
-define(F_U, 16#04).
-define(F_I, 16#08).

%%====================================================================
%% Packets
%%====================================================================

%% @doc Decode a packet. The checksum is not verified.
-spec decode(binary()) -> {ok, packet()} | {error, error_reason()}.
decode(<<Src:16, Dst:16, Vtag:32, Csum:32/little, Rest/binary>>) ->
    case decode_chunks(Rest) of
        {ok, Chunks} ->
            {ok, #sctp_packet{
                src_port = Src,
                dst_port = Dst,
                vtag = Vtag,
                checksum = Csum,
                chunks = Chunks
            }};
        {error, _} = Error ->
            Error
    end;
decode(Bin) when is_binary(Bin) ->
    {error, too_short}.

%% @doc Encode a packet with a CRC32c checksum.
-spec encode(packet()) -> binary().
encode(Packet) ->
    encode(Packet, #{checksum => crc32c}).

%% @doc Encode a packet. `#{checksum => zero}' writes a zero checksum
%% (RFC 9653); the default is `crc32c'. The `checksum' field of the record
%% is ignored.
-spec encode(packet(), encode_opts()) -> binary().
encode(#sctp_packet{src_port = Src, dst_port = Dst, vtag = Vtag, chunks = Chunks}, Opts) ->
    Head = <<Src:16, Dst:16, Vtag:32>>,
    Body = [chunk_iodata(C) || C <- Chunks],
    Csum =
        case maps:get(checksum, Opts, crc32c) of
            crc32c -> webrtc_sctp_crc32c:crc32c([Head, <<0:32>>, Body]);
            zero -> 0
        end,
    iolist_to_binary([Head, <<Csum:32/little>>, Body]).

%% @doc Verify the checksum of a packet: true when the CRC32c is correct,
%% or when `AcceptZero' is true and the wire checksum is 0 (RFC 9653).
%% False for binaries shorter than 12 bytes.
-spec checksum_ok(binary(), AcceptZero :: boolean()) -> boolean().
checksum_ok(<<Head:8/binary, Csum:32/little, Rest/binary>>, AcceptZero) ->
    (AcceptZero andalso Csum =:= 0) orelse
        webrtc_sctp_crc32c:crc32c([Head, <<0:32>>, Rest]) =:= Csum;
checksum_ok(Bin, _AcceptZero) when is_binary(Bin) ->
    false.

%%====================================================================
%% Chunks
%%====================================================================

%% @doc Decode the chunk area of a packet (the bytes after the 12 byte
%% common header).
-spec decode_chunks(binary()) -> {ok, [chunk()]} | {error, error_reason()}.
decode_chunks(Bin) when is_binary(Bin) ->
    decode_chunks(Bin, []).

decode_chunks(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_chunks(<<Type, Flags, Len:16, Rest/binary>>, Acc) when
    Len >= 4, Len - 4 =< byte_size(Rest)
->
    VLen = Len - 4,
    <<Value:VLen/binary, Rest1/binary>> = Rest,
    case chunk(Type, Flags, Value) of
        {ok, Chunk} ->
            Pad = (4 - Len rem 4) rem 4,
            case Rest1 of
                <<_:Pad/binary, Rest2/binary>> ->
                    decode_chunks(Rest2, [Chunk | Acc]);
                <<>> ->
                    %% Missing padding after the last chunk.
                    {ok, lists:reverse([Chunk | Acc])};
                _ ->
                    {error, trailing_bytes}
            end;
        {error, trailing_bytes} ->
            {error, {bad_chunk, Type}};
        {error, _} = Error ->
            Error
    end;
decode_chunks(<<Type, _/binary>> = Bin, _Acc) when byte_size(Bin) >= 4 ->
    {error, {bad_chunk, Type}};
decode_chunks(_Bin, _Acc) ->
    {error, trailing_bytes}.

%% @doc Encode one chunk, padded with zero bytes to a multiple of 4.
-spec encode_chunk(chunk()) -> binary().
encode_chunk(Chunk) ->
    iolist_to_binary(chunk_iodata(Chunk)).

%% @doc Encoded size of a chunk including its padding. Constant time for
%% DATA and I-DATA chunks.
-spec chunk_size(chunk()) -> pos_integer().
chunk_size(#sctp_data{idata = false, data = Data}) ->
    ?SCTP_DATA_HEADER_SIZE + padded(byte_size(Data));
chunk_size(#sctp_data{idata = true, data = Data}) ->
    ?SCTP_IDATA_HEADER_SIZE + padded(byte_size(Data));
chunk_size(Chunk) ->
    byte_size(encode_chunk(Chunk)).

%% @doc What to do with a chunk type this endpoint does not understand
%% (RFC 9260 §3.2, the upper two bits of the type): `00' stop processing
%% the packet, `01' stop and report, `10' skip the chunk, `11' skip and
%% report.
-spec unrecognized_chunk_action(0..255) -> {stop | skip, Report :: boolean()}.
unrecognized_chunk_action(Type) when is_integer(Type), Type >= 0, Type =< 255 ->
    case Type bsr 6 of
        0 -> {stop, false};
        1 -> {stop, true};
        2 -> {skip, false};
        3 -> {skip, true}
    end.

%%====================================================================
%% Chunk decoders
%%====================================================================

chunk(?SCTP_DATA, F, <<Tsn:32, Sid:16, Ssn:16, Ppid:32, Data/binary>>) ->
    {ok, data_flags(F, #sctp_data{tsn = Tsn, sid = Sid, mid = Ssn, ppid = Ppid, data = Data})};
chunk(?SCTP_IDATA, F, <<Tsn:32, Sid:16, _:16, Mid:32, X:32, Data/binary>>) ->
    D0 = data_flags(F, #sctp_data{idata = true, tsn = Tsn, sid = Sid, mid = Mid, data = Data}),
    case D0#sctp_data.beginning of
        true -> {ok, D0#sctp_data{ppid = X}};
        false -> {ok, D0#sctp_data{fsn = X}}
    end;
chunk(T, _F, <<Tag:32, Rwnd:32, Os:16, Mis:16, Tsn:32, P/binary>>) when
    T =:= ?SCTP_INIT; T =:= ?SCTP_INIT_ACK
->
    case webrtc_sctp_param:decode_params(P) of
        {ok, Params} ->
            {ok, #sctp_init{
                ack = T =:= ?SCTP_INIT_ACK,
                tag = Tag,
                a_rwnd = Rwnd,
                os = Os,
                mis = Mis,
                tsn = Tsn,
                params = Params
            }};
        {error, _} = Error ->
            Error
    end;
chunk(?SCTP_SACK, _F, <<Cum:32, Rwnd:32, NG:16, ND:16, Rest/binary>>) when
    byte_size(Rest) =:= 4 * (NG + ND)
->
    GLen = 4 * NG,
    <<Gaps:GLen/binary, Dups/binary>> = Rest,
    {ok, #sctp_sack{
        cum_tsn = Cum,
        a_rwnd = Rwnd,
        gaps = [{S, E} || <<S:16, E:16>> <= Gaps],
        dups = [D || <<D:32>> <= Dups]
    }};
chunk(T, _F, V) when T =:= ?SCTP_HEARTBEAT; T =:= ?SCTP_HEARTBEAT_ACK ->
    case webrtc_sctp_param:decode_params(V) of
        {ok, Params} ->
            case [I || {unknown_param, ?HEARTBEAT_INFO, I} <- Params] of
                [Info | _] when T =:= ?SCTP_HEARTBEAT -> {ok, {heartbeat, Info}};
                [Info | _] -> {ok, {heartbeat_ack, Info}};
                [] -> {error, {bad_chunk, T}}
            end;
        {error, _} = Error ->
            Error
    end;
chunk(?SCTP_ABORT, F, V) ->
    case webrtc_sctp_param:decode_causes(V) of
        {ok, Causes} -> {ok, {abort, F band 1 =:= 1, Causes}};
        {error, _} = Error -> Error
    end;
chunk(?SCTP_SHUTDOWN, _F, <<Cum:32>>) ->
    {ok, {shutdown, Cum}};
chunk(?SCTP_SHUTDOWN_ACK, _F, <<>>) ->
    {ok, shutdown_ack};
chunk(?SCTP_ERROR, _F, V) ->
    case webrtc_sctp_param:decode_causes(V) of
        {ok, Causes} -> {ok, {op_error, Causes}};
        {error, _} = Error -> Error
    end;
chunk(?SCTP_COOKIE_ECHO, _F, V) ->
    {ok, {cookie_echo, V}};
chunk(?SCTP_COOKIE_ACK, _F, <<>>) ->
    {ok, cookie_ack};
chunk(?SCTP_SHUTDOWN_COMPLETE, F, <<>>) ->
    {ok, {shutdown_complete, F band 1 =:= 1}};
chunk(?SCTP_FORWARD_TSN, _F, <<Cum:32, Rest/binary>>) when byte_size(Rest) rem 4 =:= 0 ->
    {ok, {forward_tsn, Cum, [{Sid, Ssn} || <<Sid:16, Ssn:16>> <= Rest]}};
chunk(?SCTP_IFORWARD_TSN, _F, <<Cum:32, Rest/binary>>) when byte_size(Rest) rem 8 =:= 0 ->
    {ok, {i_forward_tsn, Cum, [{Sid, U =:= 1, Mid} || <<Sid:16, _:15, U:1, Mid:32>> <= Rest]}};
chunk(?SCTP_RECONFIG, _F, V) ->
    case webrtc_sctp_param:decode_reconf_params(V) of
        {ok, [_ | _] = Params} -> {ok, {reconfig, Params}};
        {ok, []} -> {error, {bad_chunk, ?SCTP_RECONFIG}};
        {error, _} = Error -> Error
    end;
chunk(?SCTP_PAD, _F, V) ->
    {ok, {pad, byte_size(V)}};
chunk(T, _F, _V) when
    T =:= ?SCTP_DATA;
    T =:= ?SCTP_IDATA;
    T =:= ?SCTP_INIT;
    T =:= ?SCTP_INIT_ACK;
    T =:= ?SCTP_SACK;
    T =:= ?SCTP_SHUTDOWN;
    T =:= ?SCTP_SHUTDOWN_ACK;
    T =:= ?SCTP_COOKIE_ACK;
    T =:= ?SCTP_SHUTDOWN_COMPLETE;
    T =:= ?SCTP_FORWARD_TSN;
    T =:= ?SCTP_IFORWARD_TSN
->
    {error, {bad_chunk, T}};
chunk(T, F, V) ->
    {ok, {unknown_chunk, T, F, V}}.

data_flags(F, D) ->
    D#sctp_data{
        ending = F band ?F_E =/= 0,
        beginning = F band ?F_B =/= 0,
        unordered = F band ?F_U =/= 0,
        immediate = F band ?F_I =/= 0
    }.

%%====================================================================
%% Chunk encoders
%%====================================================================

%% Padded iodata of one chunk.
chunk_iodata(#sctp_data{idata = false, mid = Ssn} = D) when Ssn =< 16#FFFF ->
    #sctp_data{tsn = Tsn, sid = Sid, ppid = Ppid, data = Data} = D,
    Head = <<(u32(Tsn)):32, (u16(Sid)):16, Ssn:16, (u32(Ppid)):32>>,
    data_iodata(?SCTP_DATA, flags(D), Head, Data);
chunk_iodata(#sctp_data{idata = true} = D) ->
    #sctp_data{tsn = Tsn, sid = Sid, mid = Mid, ppid = Ppid, fsn = Fsn, data = Data} = D,
    X =
        case D#sctp_data.beginning of
            true -> Ppid;
            false -> Fsn
        end,
    Head = <<(u32(Tsn)):32, (u16(Sid)):16, 0:16, (u32(Mid)):32, (u32(X)):32>>,
    data_iodata(?SCTP_IDATA, flags(D), Head, Data);
chunk_iodata(#sctp_init{ack = Ack} = I) ->
    #sctp_init{tag = Tag, a_rwnd = Rwnd, os = Os, mis = Mis, tsn = Tsn, params = Ps} = I,
    Type =
        case Ack of
            false -> ?SCTP_INIT;
            true -> ?SCTP_INIT_ACK
        end,
    Head =
        <<(u32(Tag)):32, (u32(Rwnd)):32, (u16(Os)):16, (u16(Mis)):16, (u32(Tsn)):32>>,
    tlv(Type, 0, [Head | tlv_list([webrtc_sctp_param:encode_param(P) || P <- Ps])]);
chunk_iodata(#sctp_sack{cum_tsn = Cum, a_rwnd = Rwnd, gaps = Gaps, dups = Dups}) ->
    tlv(?SCTP_SACK, 0, [
        <<(u32(Cum)):32, (u32(Rwnd)):32, (u16(length(Gaps))):16, (u16(length(Dups))):16>>,
        <<<<(u16(S)):16, (u16(E)):16>> || {S, E} <- Gaps>>,
        <<<<(u32(D)):32>> || D <- Dups>>
    ]);
chunk_iodata({heartbeat, Info}) ->
    heartbeat(?SCTP_HEARTBEAT, Info);
chunk_iodata({heartbeat_ack, Info}) ->
    heartbeat(?SCTP_HEARTBEAT_ACK, Info);
chunk_iodata({abort, T, Causes}) ->
    tlv(?SCTP_ABORT, t_flag(T), causes(Causes));
chunk_iodata({shutdown, Cum}) ->
    tlv(?SCTP_SHUTDOWN, 0, <<(u32(Cum)):32>>);
chunk_iodata(shutdown_ack) ->
    tlv(?SCTP_SHUTDOWN_ACK, 0, <<>>);
chunk_iodata({op_error, Causes}) ->
    tlv(?SCTP_ERROR, 0, causes(Causes));
chunk_iodata({cookie_echo, Cookie}) when is_binary(Cookie) ->
    tlv(?SCTP_COOKIE_ECHO, 0, Cookie);
chunk_iodata(cookie_ack) ->
    tlv(?SCTP_COOKIE_ACK, 0, <<>>);
chunk_iodata({shutdown_complete, T}) ->
    tlv(?SCTP_SHUTDOWN_COMPLETE, t_flag(T), <<>>);
chunk_iodata({forward_tsn, Cum, Streams}) ->
    tlv(?SCTP_FORWARD_TSN, 0, [
        <<(u32(Cum)):32>> | [<<(u16(Sid)):16, (u16(Ssn)):16>> || {Sid, Ssn} <- Streams]
    ]);
chunk_iodata({i_forward_tsn, Cum, Streams}) ->
    tlv(?SCTP_IFORWARD_TSN, 0, [
        <<(u32(Cum)):32>>
        | [<<(u16(Sid)):16, 0:15, (u_bit(U)):1, (u32(Mid)):32>> || {Sid, U, Mid} <- Streams]
    ]);
chunk_iodata({reconfig, [_ | _] = Params}) ->
    tlv(
        ?SCTP_RECONFIG,
        0,
        tlv_list([webrtc_sctp_param:encode_reconf_params([P]) || P <- Params])
    );
chunk_iodata({pad, N}) when is_integer(N), N >= 0 ->
    tlv(?SCTP_PAD, 0, binary:copy(<<0>>, N));
chunk_iodata({unknown_chunk, Type, Flags, Value}) when is_binary(Value) ->
    tlv(Type, Flags, Value).

data_iodata(Type, Flags, Head, Data) ->
    Len = byte_size(Head) + 4 + byte_size(Data),
    true = Len =< 16#FFFF,
    [<<Type, Flags, Len:16>>, Head, Data | padding(Len)].

heartbeat(Type, Info) when is_binary(Info), byte_size(Info) =< ?MAX_VALUE ->
    Param = <<?HEARTBEAT_INFO:16, (byte_size(Info) + 4):16, Info/binary>>,
    tlv(Type, 0, Param).

causes(Causes) ->
    tlv_list([webrtc_sctp_param:encode_causes([C]) || C <- Causes]).

%% Padded TLVs inside a chunk: the padding of the last one is left out of
%% the chunk length and written as chunk padding.
tlv_list([]) ->
    [];
tlv_list([Last]) ->
    <<_:16, Len:16, _/binary>> = Last,
    [binary:part(Last, 0, Len)];
tlv_list([H | T]) ->
    [H | tlv_list(T)].

%% Chunk header, value and padding.
tlv(Type, Flags, Value) ->
    Len = iolist_size(Value) + 4,
    true = Len =< 16#FFFF,
    [<<(u8(Type)), (u8(Flags)), Len:16>>, Value | padding(Len)].

padding(Len) ->
    case Len rem 4 of
        0 -> [];
        R -> [<<0:((4 - R) * 8)>>]
    end.

padded(N) ->
    (N + 3) band (bnot 3).

flags(#sctp_data{ending = E, beginning = B, unordered = U, immediate = I}) ->
    bit(E, ?F_E) bor bit(B, ?F_B) bor bit(U, ?F_U) bor bit(I, ?F_I).

bit(true, V) -> V;
bit(false, _V) -> 0.

t_flag(true) -> 1;
t_flag(false) -> 0.

u_bit(true) -> 1;
u_bit(false) -> 0.

u8(X) when is_integer(X), X >= 0, X =< 255 -> X.
u16(X) when is_integer(X), X >= 0, X =< 16#FFFF -> X.
u32(X) when is_integer(X), X >= 0, X =< 16#FFFFFFFF -> X.
