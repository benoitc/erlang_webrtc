%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc VP9 RTP payload format (RFC 9628): payload descriptor, key frame
%% detection, frame size and packetization.
%%
%% A payload starts a key frame of the base layer when the frame does not
%% use inter-picture prediction (P = 0), it is the first packet of the
%% frame (B = 1) and, when layer indices are present, the spatial layer
%% is 0.
%%
%% `parse/1' reads the descriptor (§4.2): picture ID, layer indices,
%% the reference indices of flexible mode and the scalability structure.
%% `parse_payload/1' also returns the VP9 data after it. `frame_size/1'
%% reads the size of a key frame from its uncompressed header.
%% `packetize/3' splits one layer frame into payloads.
-module(webrtc_rtp_vp9).

-export([parse/1, parse_payload/1, is_keyframe/1, frame_size/1, packetize/3]).

-export_type([descriptor/0]).

-type descriptor() :: #{
    inter_predicted := boolean(),
    flexible := boolean(),
    start := boolean(),
    'end' := boolean(),
    picture_id := undefined | {7 | 15, non_neg_integer()},
    tid := undefined | 0..7,
    sid := undefined | 0..7,
    tl0picidx := undefined | 0..255,
    switching_up := undefined | boolean(),
    inter_layer := undefined | boolean(),
    %% P_DIFF of each reference picture (flexible mode).
    refs := [1..127],
    %% Width and height of each spatial layer, from the scalability
    %% structure when it has them.
    layer_sizes := undefined | [{0..65535, 0..65535}],
    not_reference := boolean()
}.

%% @doc Parse the descriptor.
-spec parse(binary()) -> {ok, descriptor()} | {error, truncated}.
parse(Payload) ->
    case parse_payload(Payload) of
        {ok, D, _} -> {ok, D};
        Err -> Err
    end.

%% @doc Parse the descriptor; also return the VP9 data that follows it.
-spec parse_payload(binary()) -> {ok, descriptor(), binary()} | {error, truncated}.
parse_payload(<<I:1, P:1, L:1, F:1, B:1, E:1, V:1, Z:1, Rest0/binary>>) ->
    D0 = #{
        inter_predicted => P =:= 1,
        flexible => F =:= 1,
        start => B =:= 1,
        'end' => E =:= 1,
        picture_id => undefined,
        tid => undefined,
        sid => undefined,
        tl0picidx => undefined,
        switching_up => undefined,
        inter_layer => undefined,
        refs => [],
        layer_sizes => undefined,
        not_reference => Z =:= 1
    },
    maybe
        {ok, Pic, Rest1} ?= picture_id(I, Rest0),
        {ok, D1, Rest2} ?= layers(L, F, Rest1, D0#{picture_id => Pic}),
        {ok, Refs, Rest3} ?= refs(F =:= 1 andalso P =:= 1 andalso Pic =/= undefined, Rest2, []),
        {ok, Sizes, Rest4} ?= ss(V, Rest3),
        {ok, D1#{refs => Refs, layer_sizes => Sizes}, Rest4}
    else
        _ -> {error, truncated}
    end;
parse_payload(_) ->
    {error, truncated}.

picture_id(0, Rest) -> {ok, undefined, Rest};
picture_id(1, <<1:1, V:15, Rest/binary>>) -> {ok, {15, V}, Rest};
picture_id(1, <<0:1, V:7, Rest/binary>>) -> {ok, {7, V}, Rest};
picture_id(1, _) -> error.

layers(0, _, Rest, D) ->
    {ok, D, Rest};
layers(1, 1, <<Tid:3, U:1, Sid:3, Dl:1, Rest/binary>>, D) ->
    {ok, D#{tid => Tid, sid => Sid, switching_up => U =:= 1, inter_layer => Dl =:= 1}, Rest};
layers(1, 0, <<Tid:3, U:1, Sid:3, Dl:1, Tl0, Rest/binary>>, D) ->
    {ok, D#{tid => Tid, sid => Sid, switching_up => U =:= 1, inter_layer => Dl =:= 1, tl0picidx => Tl0}, Rest};
layers(1, _, _, _) ->
    error.

%% Up to three P_DIFF, each followed by N: another one follows.
refs(false, Rest, []) ->
    {ok, [], Rest};
refs(true, <<Diff:7, N:1, Rest/binary>>, Acc) when length(Acc) < 3, Diff > 0 ->
    case N of
        1 -> refs(true, Rest, [Diff | Acc]);
        0 -> {ok, lists:reverse([Diff | Acc]), Rest}
    end;
refs(true, _, _) ->
    error.

%% Scalability structure (§4.2.1): N_S, Y and G, the layer sizes when
%% Y = 1, then the picture group description when G = 1.
ss(0, Rest) ->
    {ok, undefined, Rest};
ss(1, <<Ns:3, Y:1, G:1, _:3, Rest0/binary>>) ->
    maybe
        {ok, Sizes, Rest1} ?= sizes(Y, Ns + 1, Rest0, []),
        {ok, Rest2} ?= groups(G, Rest1),
        {ok, Sizes, Rest2}
    end;
ss(1, _) ->
    error.

sizes(0, _, Rest, []) -> {ok, undefined, Rest};
sizes(1, 0, Rest, Acc) -> {ok, lists:reverse(Acc), Rest};
sizes(1, N, <<W:16, H:16, Rest/binary>>, Acc) -> sizes(1, N - 1, Rest, [{W, H} | Acc]);
sizes(_, _, _, _) -> error.

groups(0, Rest) -> {ok, Rest};
groups(1, <<Ng, Rest/binary>>) -> group(Ng, Rest);
groups(1, _) -> error.

group(0, Rest) ->
    {ok, Rest};
group(N, <<_Tid:3, _U:1, R:2, _:2, Rest/binary>>) when byte_size(Rest) >= R ->
    <<_:R/binary, Rest1/binary>> = Rest,
    group(N - 1, Rest1);
group(_, _) ->
    error.

-spec is_keyframe(binary()) -> boolean().
is_keyframe(Payload) ->
    case parse(Payload) of
        {ok, #{inter_predicted := false, start := true, sid := Sid}} ->
            Sid =:= undefined orelse Sid =:= 0;
        _ ->
            false
    end.

%% @doc Width and height of a key frame from its uncompressed header
%% (VP9 bitstream specification §6.2): frame marker, profile, frame
%% type, the sync code 49 83 42, the color config, then the frame size.
-spec frame_size(binary()) -> {ok, {pos_integer(), pos_integer()}} | error.
frame_size(<<2:2, Lo:1, Hi:1, Rest0/bits>>) ->
    Profile = (Hi bsl 1) bor Lo,
    Rest1 =
        case {Profile, Rest0} of
            {3, <<_:1, R/bits>>} -> R;
            _ -> Rest0
        end,
    case Rest1 of
        <<0:1, 0:1, _Show:1, _ErrorRes:1, 16#49, 16#83, 16#42, Rest2/bits>> ->
            case color_config(Profile, Rest2) of
                <<W:16, H:16, _/bits>> -> {ok, {W + 1, H + 1}};
                _ -> error
            end;
        _ ->
            error
    end;
frame_size(_) ->
    error.

color_config(Profile, Bits0) ->
    Bits1 =
        case Bits0 of
            <<_:1, B/bits>> when Profile >= 2 -> B;
            _ -> Bits0
        end,
    Sub = Profile =:= 1 orelse Profile =:= 3,
    case Bits1 of
        %% CS_RGB: full range, 4:4:4 in profiles 1 and 3.
        <<7:3, R/bits>> when Sub -> skip(1, R);
        <<7:3, R/bits>> -> R;
        <<_:3, _Range:1, R/bits>> when Sub -> skip(3, R);
        <<_:3, _Range:1, R/bits>> -> R;
        _ -> <<>>
    end.

skip(N, Bits) ->
    case Bits of
        <<_:N, R/bits>> -> R;
        _ -> <<>>
    end.

%% @doc Split one layer frame into RTP payloads of at most `Mtu' bytes,
%% each with a descriptor. Options: `picture_id' (15 bit),
%% `inter_predicted' (default true), `tid', `sid', `tl0picidx' (layer
%% indices in non-flexible mode), `flexible' with `refs' (P_DIFF list),
%% `switching_up', `inter_layer', `not_reference', and `layer_sizes', a
%% scalability structure with the size of each spatial layer, sent in
%% the first payload. B is set on the first payload and E on the last;
%% the caller sets the RTP marker bit on the last payload of the picture.
-spec packetize(binary(), pos_integer(), map()) -> [binary()].
packetize(Frame, Mtu, Opts) when is_binary(Frame), byte_size(Frame) > 0 ->
    Flexible = maps:get(flexible, Opts, false),
    P = maps:get(inter_predicted, Opts, true),
    Pic =
        case Opts of
            #{picture_id := V} -> <<1:1, V:15>>;
            _ -> <<>>
        end,
    HasLayers = maps:is_key(tid, Opts) orelse maps:is_key(sid, Opts),
    Layers =
        case HasLayers of
            false ->
                <<>>;
            true ->
                L = <<(maps:get(tid, Opts, 0)):3, (bool(maps:get(switching_up, Opts, false))):1,
                      (maps:get(sid, Opts, 0)):3, (bool(maps:get(inter_layer, Opts, false))):1>>,
                case Flexible of
                    true -> L;
                    false -> <<L/binary, (maps:get(tl0picidx, Opts, 0))>>
                end
        end,
    Refs =
        case {Flexible, P, maps:get(refs, Opts, [])} of
            {true, true, Rs} when Rs =/= [], Pic =/= <<>> ->
                N = length(Rs),
                << <<D:7, (bool(I < N)):1>> || {I, D} <- lists:enumerate(Rs) >>;
            _ ->
                <<>>
        end,
    Ss =
        case Opts of
            #{layer_sizes := Sizes} when Sizes =/= [] ->
                <<(length(Sizes) - 1):3, 1:1, 0:1, 0:3, << <<W:16, H:16>> || {W, H} <- Sizes >>/binary>>;
            _ ->
                <<>>
        end,
    Common = <<Pic/binary, Layers/binary, Refs/binary>>,
    NotRef = bool(maps:get(not_reference, Opts, false)),
    Hdr = fun(B, E, Vb) ->
        Tail = case Vb of 1 -> Ss; 0 -> <<>> end,
        <<(bool(Pic =/= <<>>)):1, (bool(P)):1, (bool(HasLayers)):1, (bool(Flexible)):1, B:1, E:1, Vb:1,
          NotRef:1, Common/binary, Tail/binary>>
    end,
    V0 = bool(Ss =/= <<>>),
    First = Mtu - byte_size(Hdr(1, 0, V0)),
    Next = Mtu - byte_size(Hdr(0, 0, 0)),
    (First > 0 andalso Next > 0) orelse error(badarg),
    chunks(Frame, First, Next, Hdr, V0, 1).

chunks(Bin, Max, _Next, Hdr, V, B) when byte_size(Bin) =< Max ->
    [<<(Hdr(B, 1, V))/binary, Bin/binary>>];
chunks(Bin, Max, Next, Hdr, V, B) ->
    <<C:Max/binary, Rest/binary>> = Bin,
    [<<(Hdr(B, 0, V))/binary, C/binary>> | chunks(Rest, Next, Next, Hdr, 0, 0)].

bool(true) -> 1;
bool(false) -> 0.
