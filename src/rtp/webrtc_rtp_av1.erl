%% @doc AV1 RTP payload format (AOMedia "RTP Payload Format for AV1"
%% v1.0.0 §4.4 to §4.5): aggregation header, key frame detection,
%% depacketization, packetization and the frame size of a sequence
%% header.
%%
%% The aggregation header is `Z Y W(2) N' followed by three reserved
%% bits. N = 1 marks the first packet of a coded video sequence, which
%% starts with a key frame and a sequence header; it is the signal used
%% here for key frame detection.
%%
%% `depacketize/1' joins the OBU elements of a temporal unit's payloads,
%% fragments included, into the low overhead bitstream format (AV1
%% §5.2): a temporal delimiter, then every OBU with its size field.
%% `packetize/3' does the reverse, dropping temporal delimiters and tile
%% lists as §5 asks.
-module(webrtc_rtp_av1).

-export([aggregation_header/1, is_keyframe/1, depacketize/1, packetize/3, frame_size/1, payload_size/1, obus/1]).

-export_type([aggregation_header/0]).

-define(OBU_SEQUENCE_HEADER, 1).
-define(OBU_TEMPORAL_DELIMITER, 2).
-define(OBU_TILE_LIST, 8).
-define(OBU_PADDING, 15).

-type aggregation_header() :: #{
    continuation := boolean(),
    continues := boolean(),
    obu_count := 0..3,
    new_sequence := boolean()
}.

%% @doc Parse the aggregation header. `continuation' (Z): the first OBU
%% element continues one from the previous packet; `continues' (Y): the
%% last OBU element continues in the next packet; `obu_count' (W): the
%% number of OBU elements, 0 when each element carries a length field.
-spec aggregation_header(binary()) -> {ok, aggregation_header()} | {error, truncated}.
aggregation_header(<<Z:1, Y:1, W:2, N:1, _:3, _/binary>>) ->
    {ok, #{continuation => Z =:= 1, continues => Y =:= 1, obu_count => W, new_sequence => N =:= 1}};
aggregation_header(_) ->
    {error, truncated}.

-spec is_keyframe(binary()) -> boolean().
is_keyframe(Payload) ->
    case aggregation_header(Payload) of
        {ok, #{new_sequence := true, continuation := false}} -> true;
        _ -> false
    end.

%%====================================================================
%% Depacketization
%%====================================================================

%% @doc The temporal unit carried by the payloads of one frame, in
%% order. An element that continues a missing one, or a last element
%% left unfinished, fails the frame.
-spec depacketize([binary()]) -> {ok, binary()} | {error, term()}.
depacketize(Payloads) ->
    try
        case elements(Payloads, undefined, []) of
            {ok, Obus} ->
                Out = [obu_out(O) || O <- Obus],
                {ok, iolist_to_binary([<<0:1, ?OBU_TEMPORAL_DELIMITER:4, 0:1, 1:1, 0:1, 0>> | [O || O <- Out, O =/= <<>>]])};
            {error, _} = E ->
                E
        end
    catch
        throw:R -> {error, R}
    end.

elements([], undefined, Acc) ->
    {ok, lists:reverse(Acc)};
elements([], _Partial, _Acc) ->
    {error, unfinished_obu};
elements([<<Z:1, Y:1, W:2, _N:1, _:3, Rest/binary>> | More], Partial, Acc) ->
    Elems = split(W, Rest),
    Elems =/= [] orelse throw(empty_packet),
    {First, Others} =
        case {Z, Partial} of
            {1, undefined} -> throw(lost_fragment);
            {1, _} -> {[[Partial, hd(Elems)]], tl(Elems)};
            {0, undefined} -> {[], Elems};
            {0, _} -> throw(unfinished_obu)
        end,
    All = First ++ Others,
    case Y of
        1 ->
            {Done, [Last]} = lists:split(length(All) - 1, All),
            elements(More, Last, lists:reverse([iolist_to_binary(D) || D <- Done], Acc));
        0 ->
            elements(More, undefined, lists:reverse([iolist_to_binary(D) || D <- All], Acc))
    end;
elements([_ | _], _, _) ->
    {error, truncated}.

%% W = 0: every element has a leb128 length; otherwise the first W - 1
%% have one and the last takes the rest of the packet.
split(0, <<>>) ->
    [];
split(0, Bin) ->
    {Len, Rest} = leb128(Bin),
    byte_size(Rest) >= Len orelse throw(truncated),
    <<E:Len/binary, Rest1/binary>> = Rest,
    [E | split(0, Rest1)];
split(1, Bin) ->
    [Bin];
split(W, Bin) ->
    {Len, Rest} = leb128(Bin),
    byte_size(Rest) >= Len orelse throw(truncated),
    <<E:Len/binary, Rest1/binary>> = Rest,
    [E | split(W - 1, Rest1)].

%% An OBU with its size field (obu_has_size_field = 1); temporal
%% delimiters, tile lists and padding are left out.
obu_out(<<>>) ->
    throw(empty_obu);
obu_out(<<_F:1, Type:4, _/bits>>) when Type =:= ?OBU_TEMPORAL_DELIMITER; Type =:= ?OBU_TILE_LIST; Type =:= ?OBU_PADDING ->
    <<>>;
obu_out(Obu) ->
    {Hdr, Payload} = obu(Obu),
    <<F:1, Type:4, X:1, _S:1, R:1, Ext/binary>> = Hdr,
    [<<F:1, Type:4, X:1, 1:1, R:1>>, Ext, leb128_encode(byte_size(Payload)), Payload].

%% Header (with its extension byte) and payload of an OBU, whether it
%% has a size field or not.
obu(<<_:5, X:1, S:1, _:1, _/binary>> = Obu) ->
    HdrLen = 1 + X,
    byte_size(Obu) >= HdrLen orelse throw(truncated),
    <<Hdr:HdrLen/binary, Rest/binary>> = Obu,
    case S of
        0 ->
            {Hdr, Rest};
        1 ->
            {Len, Rest1} = leb128(Rest),
            byte_size(Rest1) >= Len orelse throw(truncated),
            <<P:Len/binary, _/binary>> = Rest1,
            {Hdr, P}
    end.

%% @doc The OBUs of a low overhead bitstream, as `{Type, Payload}'.
-spec obus(binary()) -> {ok, [{0..15, binary()}]} | {error, term()}.
obus(Bin) ->
    try {ok, obus1(Bin)} catch throw:R -> {error, R} end.

obus1(<<>>) ->
    [];
obus1(<<_F:1, Type:4, X:1, 1:1, _:1, Rest/binary>>) ->
    <<_:X/unit:8, Rest1/binary>> = ensure(X, Rest),
    {Len, Rest2} = leb128(Rest1),
    byte_size(Rest2) >= Len orelse throw(truncated),
    <<P:Len/binary, Rest3/binary>> = Rest2,
    [{Type, P} | obus1(Rest3)];
obus1(_) ->
    throw(no_size_field).

ensure(N, Bin) when byte_size(Bin) >= N -> Bin;
ensure(_, _) -> throw(truncated).

%% leb128 (AV1 §4.10.5): at most 8 bytes.
leb128(Bin) -> leb128(Bin, 0, 0).

leb128(<<1:1, V:7, Rest/binary>>, Shift, Acc) when Shift < 56 -> leb128(Rest, Shift + 7, Acc bor (V bsl Shift));
leb128(<<0:1, V:7, Rest/binary>>, Shift, Acc) -> {Acc bor (V bsl Shift), Rest};
leb128(_, _, _) -> throw(truncated).

leb128_encode(V) when V < 128 -> <<V>>;
leb128_encode(V) -> <<1:1, (V band 127):7, (leb128_encode(V bsr 7))/binary>>.

%%====================================================================
%% Packetization
%%====================================================================

%% @doc Split a temporal unit in the low overhead bitstream format into
%% payloads of at most `Mtu' bytes. Every OBU element has a length field
%% (W = 0) and no size field of its own; elements longer than a packet
%% continue in the next one (Y, then Z). `new_sequence': the unit starts
%% a coded video sequence (N = 1 on the first payload). The caller sets
%% the RTP marker bit on the last payload.
-spec packetize(binary(), pos_integer(), #{new_sequence => boolean()}) -> [binary()].
packetize(Tu, Mtu, Opts) when Mtu > 4 ->
    {ok, Obus} = obus(Tu),
    Elems = [<<0:1, T:4, 0:1, 0:1, 0:1, P/binary>> || {T, P} <- Obus,
             T =/= ?OBU_TEMPORAL_DELIMITER, T =/= ?OBU_TILE_LIST],
    N = case maps:get(new_sequence, Opts, false) of true -> 1; false -> 0 end,
    fill(Elems, Mtu, N, 0, []).

%% Z: this packet starts with the rest of an element; Acc: the elements
%% of the packet being filled, with their length fields.
fill([], _Mtu, N, Z, Acc) ->
    [packet(Z, 0, N, Acc)];
fill([E | Rest], Mtu, N, Z, Acc) ->
    Room = Mtu - 1 - iolist_size(Acc),
    Need = byte_size(leb128_encode(byte_size(E))) + byte_size(E),
    if
        Need =< Room ->
            fill(Rest, Mtu, N, Z, Acc ++ [leb128_encode(byte_size(E)), E]);
        Room > 2 ->
            %% What fits in this packet, the rest in the next.
            Len = fit(Room),
            <<Part:Len/binary, More/binary>> = E,
            [packet(Z, 1, N, Acc ++ [leb128_encode(Len), Part]) | fill([More | Rest], Mtu, 0, 1, [])];
        Acc =:= [] ->
            error(badarg);
        true ->
            [packet(Z, 0, N, Acc) | fill([E | Rest], Mtu, 0, 0, [])]
    end.

%% The longest part whose length field and bytes fit in Room.
fit(Room) ->
    fit(Room - 1, Room).

fit(Len, Room) ->
    case byte_size(leb128_encode(Len)) + Len =< Room of
        true -> Len;
        false -> fit(Len - 1, Room)
    end.

packet(Z, Y, N, Elems) ->
    iolist_to_binary([<<Z:1, Y:1, 0:2, N:1, 0:3>> | Elems]).

%%====================================================================
%% Sequence header
%%====================================================================

%% @doc Maximum frame width and height from the sequence header of a
%% temporal unit (AV1 §5.5): the frame size when frames do not override
%% it.
-spec frame_size(binary()) -> {ok, {pos_integer(), pos_integer()}} | error.
frame_size(Tu) ->
    case obus(Tu) of
        {ok, Obus} ->
            case [P || {?OBU_SEQUENCE_HEADER, P} <- Obus] of
                [Seq | _] -> sequence_size(Seq);
                [] -> error
            end;
        _ ->
            error
    end.

%% @doc The frame size of a sequence header among the whole OBU
%% elements of one payload.
-spec payload_size(binary()) -> {ok, {pos_integer(), pos_integer()}} | error.
payload_size(<<Z:1, Y:1, W:2, _:4, Rest/binary>>) ->
    try split(W, Rest) of
        Elems ->
            Whole = case Y of 1 -> lists:droplast(Elems); 0 -> Elems end,
            Seqs = [E || E <- case Z of 1 -> tl_or_empty(Whole); 0 -> Whole end,
                         <<_:1, ?OBU_SEQUENCE_HEADER:4, _:3, _/binary>> <- [E]],
            case Seqs of
                [S | _] -> {_, Payload} = obu(S), sequence_size(Payload);
                [] -> error
            end
    catch
        throw:_ -> error
    end;
payload_size(_) ->
    error.

tl_or_empty([]) -> [];
tl_or_empty([_ | T]) -> T.

sequence_size(Seq) ->
    try
        <<_Profile:3, _Still:1, Reduced:1, R0/bits>> = Seq,
        R1 =
            case Reduced of
                1 -> skip(5, R0);
                0 -> operating_points(R0)
            end,
        <<Wb:4, Hb:4, R2/bits>> = R1,
        <<W:(Wb + 1), H:(Hb + 1), _/bits>> = R2,
        {ok, {W + 1, H + 1}}
    catch
        error:_ -> error;
        throw:_ -> error
    end.

operating_points(<<Timing:1, R0/bits>>) ->
    {Model, BufLen, R1} =
        case Timing of
            1 ->
                <<_Units:32, _Scale:32, Equal:1, T0/bits>> = R0,
                T1 = case Equal of 1 -> uvlc(T0); 0 -> T0 end,
                case T1 of
                    <<1:1, BufMinus1:5, _:32, _:5, _:5, T2/bits>> -> {1, BufMinus1 + 1, T2};
                    <<0:1, T2/bits>> -> {0, 0, T2}
                end;
            0 ->
                {0, 0, R0}
        end,
    %% operating_points_cnt_minus_1: 5 bits, at most 32 points.
    <<Initial:1, Count:5, R2/bits>> = R1,
    lists:foldl(fun(_, Acc) -> operating_point(Model, BufLen, Initial, Acc) end, R2, lists:seq(0, Count)).

operating_point(Model, BufLen, Initial, Bits0) ->
    <<_Idc:12, Level:5, Bits1/bits>> = Bits0,
    Bits2 = case Level > 7 of true -> skip(1, Bits1); false -> Bits1 end,
    Bits3 =
        case {Model, Bits2} of
            {1, <<1:1, B/bits>>} -> skip(2 * BufLen + 1, B);
            {1, <<0:1, B/bits>>} -> B;
            {0, B} -> B
        end,
    case {Initial, Bits3} of
        {1, <<1:1, B4/bits>>} -> skip(4, B4);
        {1, <<0:1, B4/bits>>} -> B4;
        {0, B4} -> B4
    end.

uvlc(Bits) -> uvlc(Bits, 0).

uvlc(<<0:1, R/bits>>, N) when N < 32 -> uvlc(R, N + 1);
uvlc(<<1:1, R/bits>>, N) when N < 32 -> skip(N, R);
uvlc(_, _) -> throw(bad_uvlc).

skip(N, Bits) ->
    <<_:N, R/bits>> = Bits,
    R.
