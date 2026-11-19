%% @doc VP8 RTP payload descriptor (RFC 7741 §4.2) without decoding
%% media.
%%
%% `parse/1' reads the payload descriptor; `is_keyframe/1' checks the
%% inverse key frame bit of the VP8 payload header (§4.3), present in
%% the first packet of a frame (S = 1, PID = 0). `rewrite/2' patches the
%% picture ID and TL0PICIDX in place, keeping the 7 or 15 bit picture ID
%% width of the packet, which is what a forwarding unit needs to keep
%% these fields continuous when it switches between simulcast layers.
%% `packetize/3' splits an encoded frame into payloads; `frame_size/1'
%% reads the size of a key frame.
-module(webrtc_rtp_vp8).

-export([parse/1, is_keyframe/1, rewrite/2, packetize/3, frame_size/1]).

-export_type([descriptor/0]).

-type descriptor() :: #{
    non_reference := boolean(),
    start := boolean(),
    partition := 0..7,
    picture_id := undefined | {7 | 15, non_neg_integer()},
    tl0picidx := undefined | 0..255,
    tid := undefined | 0..3,
    layer_sync := undefined | boolean(),
    keyidx := undefined | 0..31,
    size := pos_integer()
}.

%% @doc Parse the payload descriptor. Returns the descriptor and the VP8
%% payload that follows it.
-spec parse(binary()) -> {ok, descriptor(), binary()} | {error, truncated}.
parse(<<X:1, _R:1, N:1, S:1, _R2:1, Pid:3, Rest/binary>>) ->
    D0 = #{
        non_reference => N =:= 1,
        start => S =:= 1,
        partition => Pid,
        picture_id => undefined,
        tl0picidx => undefined,
        tid => undefined,
        layer_sync => undefined,
        keyidx => undefined,
        size => 1
    },
    case X of
        0 -> {ok, D0, Rest};
        1 -> extended(Rest, D0)
    end;
parse(_) ->
    {error, truncated}.

extended(<<I:1, L:1, T:1, K:1, _:4, Rest0/binary>>, D0) ->
    case picture_id(I, Rest0) of
        {ok, PicId, IBytes, Rest1} ->
            case {L, Rest1} of
                {1, <<Tl0, Rest2/binary>>} ->
                    tk(T, K, Rest2, D0#{picture_id => PicId, tl0picidx => Tl0}, 2 + IBytes + 1);
                {0, _} ->
                    tk(T, K, Rest1, D0#{picture_id => PicId}, 2 + IBytes);
                _ ->
                    {error, truncated}
            end;
        error ->
            {error, truncated}
    end;
extended(_, _) ->
    {error, truncated}.

picture_id(0, Rest) -> {ok, undefined, 0, Rest};
picture_id(1, <<1:1, V:15, Rest/binary>>) -> {ok, {15, V}, 2, Rest};
picture_id(1, <<0:1, V:7, Rest/binary>>) -> {ok, {7, V}, 1, Rest};
picture_id(1, _) -> error.

tk(0, 0, Rest, D, Size) ->
    {ok, D#{size => Size}, Rest};
tk(T, K, <<Tid:2, Y:1, KeyIdx:5, Rest/binary>>, D, Size) ->
    D1 =
        case T of
            1 -> D#{tid => Tid, layer_sync => Y =:= 1};
            0 -> D
        end,
    D2 =
        case K of
            1 -> D1#{keyidx => KeyIdx};
            0 -> D1
        end,
    {ok, D2#{size => Size + 1}, Rest};
tk(_, _, _, _, _) ->
    {error, truncated}.

%% @doc True when the payload starts a key frame: S = 1, partition 0 and
%% the P bit of the VP8 payload header is 0 (RFC 7741 §4.3).
-spec is_keyframe(binary()) -> boolean().
is_keyframe(Payload) ->
    case parse(Payload) of
        {ok, #{start := true, partition := 0}, <<_:7, 0:1, _/binary>>} -> true;
        _ -> false
    end.

%% @doc Width and height of a key frame, from the start of its VP8 data
%% (the payload of its first packet after the descriptor): the 3 byte
%% frame tag, the start code 9d 01 2a, then the 14 bit width and height
%% (RFC 6386 §9.1).
-spec frame_size(binary()) -> {ok, {pos_integer(), pos_integer()}} | error.
frame_size(<<_:7, 0:1, _:16, 16#9d, 16#01, 16#2a, W:16/little, H:16/little, _/binary>>)
  when W band 16#3FFF > 0, H band 16#3FFF > 0 ->
    {ok, {W band 16#3FFF, H band 16#3FFF}};
frame_size(_) ->
    error.

%% @doc Rewrite `picture_id' and / or `tl0picidx' in a payload. The new
%% picture ID is truncated to the width used by the packet. Fails when a
%% field to rewrite is not present.
-spec rewrite(binary(), #{picture_id => non_neg_integer(), tl0picidx => 0..255}) ->
    {ok, binary()} | {error, truncated | {absent, picture_id | tl0picidx}}.
rewrite(Payload, Changes) ->
    case parse(Payload) of
        {ok, D, _} -> rewrite(Payload, D, Changes);
        Err -> Err
    end.

rewrite(Payload, #{picture_id := PicId, tl0picidx := Tl0}, Changes) ->
    case {maps:find(picture_id, Changes), PicId, maps:find(tl0picidx, Changes), Tl0} of
        {{ok, _}, undefined, _, _} ->
            {error, {absent, picture_id}};
        {_, _, {ok, _}, undefined} ->
            {error, {absent, tl0picidx}};
        {NewPic, _, NewTl0, _} ->
            P1 = set_picture_id(Payload, PicId, NewPic),
            {ok, set_tl0(P1, PicId, NewTl0)}
    end.

set_picture_id(P, _, error) ->
    P;
set_picture_id(<<H:2/binary, _:16, Rest/binary>>, {15, _}, {ok, V}) ->
    <<H/binary, 1:1, (V band 16#7FFF):15, Rest/binary>>;
set_picture_id(<<H:2/binary, _:8, Rest/binary>>, {7, _}, {ok, V}) ->
    <<H/binary, 0:1, (V band 16#7F):7, Rest/binary>>.

set_tl0(P, _, error) ->
    P;
set_tl0(P, PicId, {ok, V}) when is_integer(V), V >= 0, V =< 255 ->
    Off =
        case PicId of
            undefined -> 2;
            {7, _} -> 3;
            {15, _} -> 4
        end,
    <<H:Off/binary, _, Rest/binary>> = P,
    <<H/binary, V, Rest/binary>>.

%% @doc Split an encoded VP8 frame into RTP payloads of at most `Mtu'
%% bytes, each with a payload descriptor. Options: `picture_id' (15-bit),
%% `tl0picidx', `tid' and `layer_sync' (the temporal layer and the Y
%% bit), `non_reference'. The first payload has S = 1; the caller sets
%% the RTP marker bit on the last one.
-spec packetize(binary(), pos_integer(), #{
    picture_id => 0..16#7FFF, tl0picidx => 0..255, tid => 0..3, layer_sync => boolean(),
    non_reference => boolean()
}) -> [binary()].
packetize(Frame, Mtu, Opts) when is_binary(Frame), byte_size(Frame) > 0 ->
    Ext = maps:is_key(picture_id, Opts) orelse maps:is_key(tl0picidx, Opts) orelse maps:is_key(tid, Opts),
    N =
        case maps:get(non_reference, Opts, false) of
            true -> 1;
            false -> 0
        end,
    Tail = ext_bytes(Ext, Opts),
    HdrSize = 1 + byte_size(Tail),
    Max = Mtu - HdrSize,
    Max > 0 orelse error(badarg),
    chunks(Frame, Max, fun(S) -> <<(bool(Ext)):1, 0:1, N:1, S:1, 0:1, 0:3, Tail/binary>> end, 1).

ext_bytes(false, _) ->
    <<>>;
ext_bytes(true, Opts) ->
    I = maps:is_key(picture_id, Opts),
    L = maps:is_key(tl0picidx, Opts),
    Tb = maps:is_key(tid, Opts),
    Pic =
        case Opts of
            #{picture_id := V} -> <<1:1, V:15>>;
            _ -> <<>>
        end,
    Tl0 =
        case Opts of
            #{tl0picidx := T} -> <<T>>;
            _ -> <<>>
        end,
    Tk =
        case Opts of
            #{tid := Tid} -> <<Tid:2, (bool(maps:get(layer_sync, Opts, false))):1, 0:5>>;
            _ -> <<>>
        end,
    <<(bool(I)):1, (bool(L)):1, (bool(Tb)):1, 0:5, Pic/binary, Tl0/binary, Tk/binary>>.

chunks(Bin, Max, Hdr, S) when byte_size(Bin) =< Max ->
    [<<(Hdr(S))/binary, Bin/binary>>];
chunks(Bin, Max, Hdr, S) ->
    <<C:Max/binary, Rest/binary>> = Bin,
    [<<(Hdr(S))/binary, C/binary>> | chunks(Rest, Max, Hdr, 0)].

bool(true) -> 1;
bool(false) -> 0.
