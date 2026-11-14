%% @doc VP9 RTP payload descriptor (RFC 9628 §4.2), key frame detection
%% only.
%%
%% A payload starts a key frame of the base layer when the frame does not
%% use inter-picture prediction (P = 0), it is the first packet of the
%% frame (B = 1) and, when layer indices are present, the spatial layer
%% is 0.
-module(webrtc_rtp_vp9).

-export([parse/1, is_keyframe/1]).

-export_type([descriptor/0]).

-type descriptor() :: #{
    inter_predicted := boolean(),
    flexible := boolean(),
    start := boolean(),
    'end' := boolean(),
    picture_id := undefined | {7 | 15, non_neg_integer()},
    tid := undefined | 0..7,
    sid := undefined | 0..7,
    tl0picidx := undefined | 0..255
}.

%% @doc Parse the first byte, the picture ID and the layer indices.
%% The reference indices and the scalability structure are not parsed.
-spec parse(binary()) -> {ok, descriptor()} | {error, truncated}.
parse(<<I:1, P:1, L:1, F:1, B:1, E:1, _V:1, _Z:1, Rest0/binary>>) ->
    D0 = #{
        inter_predicted => P =:= 1,
        flexible => F =:= 1,
        start => B =:= 1,
        'end' => E =:= 1,
        picture_id => undefined,
        tid => undefined,
        sid => undefined,
        tl0picidx => undefined
    },
    case picture_id(I, Rest0) of
        {ok, Pic, Rest1} -> layers(L, F, Rest1, D0#{picture_id => Pic});
        error -> {error, truncated}
    end;
parse(_) ->
    {error, truncated}.

picture_id(0, Rest) -> {ok, undefined, Rest};
picture_id(1, <<1:1, V:15, Rest/binary>>) -> {ok, {15, V}, Rest};
picture_id(1, <<0:1, V:7, Rest/binary>>) -> {ok, {7, V}, Rest};
picture_id(1, _) -> error.

layers(0, _, _, D) ->
    {ok, D};
layers(1, 1, <<Tid:3, _U:1, Sid:3, _D:1, _/binary>>, D) ->
    {ok, D#{tid => Tid, sid => Sid}};
layers(1, 0, <<Tid:3, _U:1, Sid:3, _D:1, Tl0, _/binary>>, D) ->
    {ok, D#{tid => Tid, sid => Sid, tl0picidx => Tl0}};
layers(1, _, _, _) ->
    {error, truncated}.

-spec is_keyframe(binary()) -> boolean().
is_keyframe(Payload) ->
    case parse(Payload) of
        {ok, #{inter_predicted := false, start := true, sid := Sid}} ->
            Sid =:= undefined orelse Sid =:= 0;
        _ ->
            false
    end.
