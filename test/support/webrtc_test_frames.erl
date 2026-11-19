%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Encoded video for the frame buffer tests: the files of
%% test/corpora/frames (made by ffmpeg, see its README), cut into
%% frames, packetized with our packetizers and run through a buffer.
-module(webrtc_test_frames).

-include("webrtc_rtp.hrl").

-export([frames/1, packets/2, packets/3, run/2, ivf/1, name/1, write_ivf/4]).

-define(PT, 96).

dir() -> filename:join([filename:dirname(?FILE), "..", "corpora", "frames"]).

name(vp8) -> <<"VP8">>;
name(vp9) -> <<"VP9">>;
name(h264) -> <<"H264">>;
name(av1) -> <<"AV1">>.

%% [#{key, data, expect}]: what goes to the packetizer and what the
%% buffer must give back.
frames(h264) ->
    {ok, Bin} = file:read_file(filename:join(dir(), "h264.h264")),
    [#{key => lists:member(5, [webrtc_rtp_h264:nal_type(N) || N <- Au]), data => Au,
       expect => iolist_to_binary([[<<0, 0, 0, 1>>, N] || N <- Au])}
     || Au <- access_units(webrtc_rtp_h264:split_annexb(Bin))];
frames(Codec) ->
    File = atom_to_list(Codec) ++ ".ivf",
    [#{key => key(Codec, F), data => F, expect => F} || F <- ivf(filename:join(dir(), File))].

key(vp8, <<_:7, P:1, _/binary>>) -> P =:= 0;
key(vp9, F) -> webrtc_rtp_vp9:frame_size(F) =/= error;
key(av1, F) -> {ok, Obus} = webrtc_rtp_av1:obus(F), lists:keymember(1, 1, Obus).

%% IVF: 32 byte header, then per frame a 4 byte size and an 8 byte
%% timestamp, little endian.
ivf(File) ->
    {ok, <<"DKIF", _:28/binary, Rest/binary>>} = file:read_file(File),
    ivf_frames(Rest).

ivf_frames(<<Size:32/little, _Pts:64/little, F:Size/binary, Rest/binary>>) -> [F | ivf_frames(Rest)];
ivf_frames(<<>>) -> [].

write_ivf(File, Fourcc, {W, H}, Frames) ->
    Hdr = <<"DKIF", 0:16/little, 32:16/little, Fourcc:4/binary, W:16/little, H:16/little,
            30:32/little, 1:32/little, (length(Frames)):32/little, 0:32>>,
    Body = [[<<(byte_size(F)):32/little, I:64/little>>, F] || {I, F} <- lists:enumerate(0, Frames)],
    ok = file:write_file(File, [Hdr | Body]).

%% ITU-T H.264 §7.4.1.2.3: a new access unit at a delimiter, SPS or SEI,
%% or at a slice with first_mb_in_slice 0, once the current one has a
%% slice.
access_units(Nals) ->
    {Aus, Cur, _} = lists:foldl(
        fun(N, {Aus, Cur, Slice}) ->
            T = webrtc_rtp_h264:nal_type(N),
            First = case N of <<_:8, 1:1, _/bits>> -> true; _ -> false end,
            New = Slice andalso (lists:member(T, [6, 7, 9]) orelse ((T =:= 1 orelse T =:= 5) andalso First)),
            IsSlice = T =:= 1 orelse T =:= 5,
            case New of
                true -> {[lists:reverse(Cur) | Aus], [N], IsSlice};
                false -> {Aus, [N | Cur], Slice orelse IsSlice}
            end
        end,
        {[], [], false},
        Nals
    ),
    lists:reverse([lists:reverse(Cur) | Aus]).

%% RTP packets of the frames, 3000 ticks apart.
packets(Codec, Frames) ->
    packets(Codec, Frames, #{}).

packets(Codec, Frames, Opts) ->
    Mtu = maps:get(mtu, Opts, 300),
    Extra = maps:get(extra, Opts, fun(_I) -> #{} end),
    {Pkts, _} = lists:mapfoldl(
        fun({I, #{key := Key, data := D}}, Seq) ->
            Payloads = payloads(Codec, D, Key, I, Mtu, Extra(I)),
            N = length(Payloads),
            Rtps = [#rtp{pt = ?PT, seq = (Seq + J - 1) band 16#FFFF, ts = (maps:get(ts0, Opts, 1000) + I * 3000) band 16#FFFFFFFF,
                         ssrc = 1, marker = J =:= N, payload = P}
                    || {J, P} <- lists:enumerate(Payloads)],
            {{I, Rtps}, Seq + N}
        end,
        maps:get(seq0, Opts, 100),
        lists:enumerate(0, Frames)
    ),
    Pkts.

payloads(vp8, D, _Key, I, Mtu, Extra) ->
    webrtc_rtp_vp8:packetize(D, Mtu, maps:merge(#{picture_id => I band 16#7FFF}, Extra));
payloads(vp9, D, Key, I, Mtu, Extra) ->
    webrtc_rtp_vp9:packetize(D, Mtu, maps:merge(#{picture_id => I band 16#7FFF, inter_predicted => not Key}, Extra));
payloads(h264, Nals, _Key, _I, Mtu, _Extra) ->
    webrtc_rtp_h264:packetize(Nals, Mtu);
payloads(av1, D, Key, _I, Mtu, _Extra) ->
    webrtc_rtp_av1:packetize(D, Mtu, #{new_sequence => Key}).

%% Push `[{At, #rtp{}}]' in order, run the timers when due, then let
%% everything out. Returns the frames with the time they left, the number of key
%% frame requests and the statistics.
run(Arrivals, Opts) ->
    Fb0 = webrtc_frame_buffer:new(maps:merge(#{kind => video, clock_rate => 90000}, Opts)),
    {Out, Fb1} = lists:foldl(
        fun({At, Rtp}, {Acc, Fb}) ->
            {A0, FbT} = timers(At, Fb),
            {A1, Fb2} = case Rtp of
                            {lost, Seqs} -> webrtc_frame_buffer:lost(Seqs, At, FbT);
                            _ -> webrtc_frame_buffer:push(Rtp, At, #{}, FbT)
                        end,
            {Acc ++ A0 ++ [{At, X} || X <- A1], Fb2}
        end,
        {[], Fb0},
        Arrivals
    ),
    End = case Arrivals of [] -> 0; _ -> element(1, lists:last(Arrivals)) + 20000 end,
    {A, Fb3} = timers(End, Fb1),
    All = Out ++ A,
    {[{T, F} || {T, {frame, F}} <- All], length([x || {_, request_keyframe} <- All]), webrtc_frame_buffer:stats(Fb3)}.

timers(Now, Fb) ->
    case webrtc_frame_buffer:next_timeout(Fb) of
        T when is_integer(T), T =< Now ->
            {A, Fb1} = webrtc_frame_buffer:timeout(T, Fb),
            {A1, Fb2} = timers(Now, Fb1),
            {[{T, X} || X <- A] ++ A1, Fb2};
        _ ->
            {[], Fb}
    end.
