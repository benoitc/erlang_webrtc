%% @private What the frame buffer needs from each payload format: per
%% packet, whether it starts a frame, whether the frame is a key frame
%% and the references it carries; per frame, the joined data and the
%% picture size. Internal module of `webrtc_frame_buffer'.
-module(webrtc_frame_codec).

-export([codec/2, packet/2, track/4, assemble/4]).

-export_type([codec/0, info/0]).

-type codec() :: vp8 | vp9 | h264 | av1 | audio | video.

%% `start': the packet starts a frame (`unknown' when the format does
%% not say, `probable' when it does only if no earlier packet of the
%% frame is missing); `pid', `tid', `tl0', `sync': picture ID, temporal layer,
%% TL0PICIDX and layer sync of VP8 and of VP9 in non-flexible mode;
%% `refs': picture IDs referenced in VP9 flexible mode.
-type info() :: #{
    start := boolean() | probable | unknown,
    keyframe := boolean(),
    pid => undefined | {7 | 15, non_neg_integer()},
    tid => undefined | non_neg_integer(),
    tl0 => undefined | 0..255,
    sync => boolean(),
    flexible => boolean(),
    refs => [non_neg_integer()],
    sizes => undefined | [{non_neg_integer(), non_neg_integer()}]
}.

%% @doc The format of a codec name, by media kind.
-spec codec(audio | video, binary()) -> codec().
codec(audio, _) ->
    audio;
codec(video, Name) ->
    case string:lowercase(Name) of
        <<"vp8">> -> vp8;
        <<"vp9">> -> vp9;
        <<"h264">> -> h264;
        <<"av1">> -> av1;
        _ -> video
    end.

%% @doc What one payload says about its frame.
-spec packet(codec(), binary()) -> info().
packet(audio, _) ->
    #{start => true, keyframe => false};
packet(vp8, P) ->
    case webrtc_rtp_vp8:parse(P) of
        {ok, #{start := S, partition := Part, picture_id := Pid, tid := Tid, tl0picidx := Tl0, layer_sync := Y}, Data} ->
            Start = S andalso Part =:= 0,
            Key = Start andalso case Data of <<_:7, 0:1, _/binary>> -> true; _ -> false end,
            #{start => Start, keyframe => Key, pid => Pid, tid => Tid, tl0 => Tl0, sync => Y =:= true};
        _ ->
            #{start => unknown, keyframe => false}
    end;
packet(vp9, P) ->
    case webrtc_rtp_vp9:parse(P) of
        {ok, #{start := B, sid := Sid, inter_layer := D, inter_predicted := Inter, picture_id := Pid,
               tid := Tid, tl0picidx := Tl0, switching_up := U, flexible := F, refs := Refs,
               layer_sizes := Sizes}} ->
            %% The first layer frame of the picture: B on the lowest
            %% spatial layer, or on one that does not use a lower one.
            Start = B andalso (Sid =:= undefined orelse Sid =:= 0 orelse D =:= false),
            #{start => Start, keyframe => Start andalso not Inter, pid => Pid, tid => Tid, tl0 => Tl0,
              sync => U =:= true, flexible => F, refs => [pid_sub(Pid, R) || R <- Refs], sizes => Sizes};
        _ ->
            #{start => unknown, keyframe => false}
    end;
packet(h264, P) ->
    #{start => h264_start(P), keyframe => webrtc_rtp_h264:is_keyframe(P)};
packet(av1, P) ->
    case webrtc_rtp_av1:is_keyframe(P) of
        true -> #{start => true, keyframe => true};
        false -> #{start => unknown, keyframe => false}
    end;
packet(video, _) ->
    #{start => unknown, keyframe => false}.

%% ITU-T H.264 §7.4.1.2.3: an access unit starts with an access unit
%% delimiter, a sequence parameter set or SEI, all before the first
%% slice, or with the slice holding macroblock 0 (first_mb_in_slice,
%% ue(v), is 0 when its first bit is 1). A picture parameter set may sit
%% between slices, so it says nothing. Packets before it with more of
%% these may be late or lost: the start is only probable.
h264_start(<<_:3, 24:5, Size:16, Nal:Size/binary, _/binary>>) -> h264_nal_start(Nal);
h264_start(<<_:3, 28:5, 1:1, _:2, Type:5, Rest/binary>>) -> h264_nal_start(<<0:3, Type:5, Rest/binary>>);
h264_start(<<_:3, 28:5, _/binary>>) -> unknown;
h264_start(Nal) -> h264_nal_start(Nal).

h264_nal_start(<<_:3, T:5, _/binary>>) when T =:= 6; T =:= 7; T =:= 9 -> probable;
h264_nal_start(<<_:3, T:5, 1:1, _/bits>>) when T =:= 1; T =:= 5 -> probable;
h264_nal_start(_) -> unknown.

%% @doc Keep what packet `Seq' (extended) carries for later frames: the
%% H.264 sequence and picture parameter sets of the highest sequence
%% number, whatever becomes of its frame.
-spec track(codec(), integer(), binary(), map()) -> map().
track(h264, Seq, P, St) ->
    case webrtc_rtp_h264:depacketize(P) of
        {ok, Nals} ->
            lists:foldl(fun(N, Acc) ->
                            case webrtc_rtp_h264:nal_type(N) of
                                7 -> keep(sps, Seq, N, Acc);
                                8 -> keep(pps, Seq, N, Acc);
                                _ -> Acc
                            end
                        end, St, Nals);
        _ ->
            St
    end;
track(_, _, _, St) ->
    St.

keep(K, Seq, N, St) ->
    case maps:get(K, St, undefined) of
        {S, _} when S > Seq -> St;
        _ -> St#{K => {Seq, N}}
    end.

%% The parameter set of a packet before `First'.
before(K, First, St) ->
    case maps:get(K, St, undefined) of
        {S, N} when S < First -> N;
        _ -> undefined
    end.

pid_sub({Bits, V}, D) -> (V - D) band ((1 bsl Bits) - 1).

%% @doc The frame carried by the payloads of one frame, in sequence
%% order, the first with extended sequence number `First', with its
%% picture size when the frame tells it. `State' keeps what spans
%% frames: the H.264 parameter sets.
-spec assemble(codec(), [{0..65535, binary()}], integer(), map()) ->
    {ok, binary(), undefined | {pos_integer(), pos_integer()}, map()} | {error, term(), map()}.
assemble(vp8, Pkts, _First, St) ->
    Datas = [D || {_, P} <- Pkts, {ok, _, D} <- [webrtc_rtp_vp8:parse(P)]],
    case length(Datas) =:= length(Pkts) of
        true ->
            Data = iolist_to_binary(Datas),
            Size = case webrtc_rtp_vp8:frame_size(Data) of {ok, S} -> S; error -> undefined end,
            {ok, Data, Size, St};
        false ->
            {error, bad_descriptor, St}
    end;
assemble(vp9, Pkts, _First, St) ->
    Parsed = [{D, Data} || {_, P} <- Pkts, {ok, D, Data} <- [webrtc_rtp_vp9:parse_payload(P)]],
    case length(Parsed) =:= length(Pkts) of
        true ->
            Data = iolist_to_binary([X || {_, X} <- Parsed]),
            %% The scalability structure gives the size of each spatial
            %% layer: the picture is the size of the highest one.
            Size =
                case [S || {#{layer_sizes := [_ | _] = S}, _} <- Parsed] of
                    [Sizes | _] -> lists:last(Sizes);
                    [] -> case webrtc_rtp_vp9:frame_size(Data) of {ok, S} -> S; error -> undefined end
                end,
            {ok, Data, Size, St};
        false ->
            {error, bad_descriptor, St}
    end;
assemble(h264, Pkts, First, St) ->
    case h264_nals(Pkts, webrtc_rtp_h264:depacketizer_new(), []) of
        {ok, Nals0} ->
            Types = [webrtc_rtp_h264:nal_type(N) || N <- Nals0],
            Sps = last([N || N <- Nals0, webrtc_rtp_h264:nal_type(N) =:= 7], before(sps, First, St)),
            Pps = last([N || N <- Nals0, webrtc_rtp_h264:nal_type(N) =:= 8], before(pps, First, St)),
            %% RFC 6184 §8.4: parameter sets may come in an earlier frame;
            %% a decoder needs them before an IDR, so one without them
            %% cannot be decoded.
            Idr = lists:member(5, Types),
            case Idr andalso (Sps =:= undefined orelse Pps =:= undefined) of
                true ->
                    {error, missing_parameter_sets, St};
                false ->
                    Nals = case Idr of
                               true -> [Sps || not lists:member(7, Types)] ++ [Pps || not lists:member(8, Types)] ++ Nals0;
                               false -> Nals0
                           end,
                    Size =
                        case Sps of
                            undefined -> undefined;
                            S -> case webrtc_rtp_h264:sps_size(S) of {ok, WH} -> WH; error -> undefined end
                        end,
                    {ok, iolist_to_binary([[<<0, 0, 0, 1>>, N] || N <- Nals]), Size, St}
            end;
        {error, R} ->
            {error, R, St}
    end;
assemble(av1, Pkts, _First, St) ->
    case webrtc_rtp_av1:depacketize([P || {_, P} <- Pkts]) of
        {ok, Tu} ->
            Size = case webrtc_rtp_av1:frame_size(Tu) of {ok, S} -> S; error -> undefined end,
            {ok, Tu, Size, St};
        {error, R} ->
            {error, R, St}
    end;
assemble(_, Pkts, _First, St) ->
    {ok, iolist_to_binary([P || {_, P} <- Pkts]), undefined, St}.

h264_nals([], _D, Acc) ->
    {ok, lists:append(lists:reverse(Acc))};
h264_nals([{Seq, P} | Rest], D, Acc) ->
    case webrtc_rtp_h264:depacketizer_push(Seq, P, D) of
        {ok, Nals, D1} -> h264_nals(Rest, D1, [Nals | Acc]);
        {error, R, _} -> {error, R}
    end.

last([], Default) -> Default;
last(L, _) -> lists:last(L).
