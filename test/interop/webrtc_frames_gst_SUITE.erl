%% Frame assembly (webrtc_frame_buffer) against packetizers written apart
%% from ours: GStreamer encodes and packetizes VP8, VP9, H.264 and AV1
%% (rtpvp8pay, rtpvp9pay, rtph264pay, rtpav1pay) over plain RTP on UDP,
%% our buffer puts the frames together, and ffmpeg decodes them. Each
%% codec is skipped, saying why, when its elements are missing.
-module(webrtc_frames_gst_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([in_order/1, reordered_and_lost/1]).

-define(PT, 96).
-define(FRAMES, 90).
-define(W, 320).
-define(H, 240).

all() -> [{group, vp8}, {group, vp9}, {group, h264}, {group, av1}].

groups() -> [{C, [], [in_order, reordered_and_lost]} || C <- [vp8, vp9, h264, av1]].

init_per_suite(Config) ->
    case {os:find_executable("gst-launch-1.0"), os:find_executable("ffprobe")} of
        {false, _} -> {skip, "GStreamer not installed (gst-launch-1.0)"};
        {_, false} -> {skip, "ffmpeg not installed (ffprobe)"};
        _ -> Config
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(Codec, Config) ->
    {Enc, Pay} = pipeline(Codec),
    Elements = [E || S <- string:split(Enc ++ " ! " ++ Pay, " ! ", all), E <- [hd(string:split(S, " "))],
                     string:find(E, "/") =:= nomatch],
    case [E || E <- Elements, not element_exists(E)] of
        [] -> [{codec, Codec} | Config];
        Missing -> {skip, "GStreamer elements missing: " ++ string:join(Missing, ", ")}
    end.

end_per_group(_, _Config) ->
    ok.

element_exists(E) ->
    string:find(os:cmd("gst-inspect-1.0 " ++ E ++ " 2>&1"), "Factory Details") =/= nomatch.

%% A key frame every 30 frames, so that a loss is repaired by the next one
%% (plain RTP: no PLI reaches GStreamer).
pipeline(vp8) ->
    {"vp8enc deadline=1 keyframe-max-dist=30 target-bitrate=400000",
     "rtpvp8pay picture-id-mode=15-bit mtu=600 pt=96"};
pipeline(vp9) ->
    {"vp9enc deadline=1 keyframe-max-dist=30 target-bitrate=400000",
     "rtpvp9pay picture-id-mode=15-bit mtu=600 pt=96"};
pipeline(h264) ->
    {"x264enc tune=zerolatency key-int-max=30 bitrate=400 ! video/x-h264,profile=constrained-baseline",
     "rtph264pay config-interval=-1 mtu=600 pt=96"};
pipeline(av1) ->
    {"av1enc usage-profile=realtime cpu-used=8 keyframe-max-dist=30 target-bitrate=400 ! av1parse",
     "rtpav1pay mtu=600 pt=96"}.

%%====================================================================
%% Cases
%%====================================================================

%% Every frame GStreamer sent comes out, and ffmpeg decodes each of them
%% at the size it was encoded, with the same key frames.
in_order(Config) ->
    Codec = ?config(codec, Config),
    Pkts = capture(Codec),
    Sent = length(lists:usort([Ts || {_, #rtp{ts = Ts}} <- Pkts])),
    ?assert(Sent >= ?FRAMES - 1),
    {Frames, _} = assemble(Codec, Pkts),
    ?assertEqual(Sent, length(Frames)),
    ?assert(lists:all(fun(#{width := W, height := H}) -> {W, H} =:= {?W, ?H} end, Frames)),
    decode(Config, Codec, "in_order", Frames).

%% Packets reordered by up to 30 ms and one in 40 lost: what comes out
%% still decodes without an error, the frames after each loss wait for
%% the next key frame (one in 30 frames), and a key frame is asked for.
reordered_and_lost(Config) ->
    Codec = ?config(codec, Config),
    Pkts = capture(Codec),
    rand:seed(exsss, {7, 7, 7}),
    Impaired = lists:keysort(1, [{T + rand:uniform(30), P} || {I, {T, P}} <- lists:enumerate(Pkts), I rem 40 =/= 7]),
    {Frames, Requests} = assemble(Codec, Impaired),
    Sent = length(lists:usort([Ts || {_, #rtp{ts = Ts}} <- Pkts])),
    ct:log("~p: ~b of ~b frames out, ~b key frame requests", [Codec, length(Frames), Sent, Requests]),
    ?assert(length(Frames) < Sent),
    ?assert(length(Frames) >= 10),
    ?assert(Requests >= 1),
    decode(Config, Codec, "lossy", Frames).

%%====================================================================
%% Helpers
%%====================================================================

%% The packets of `videotestsrc ! enc ! pay ! udpsink', with the time
%% they arrived (ms from the first).
capture(Codec) ->
    {Enc, Pay} = pipeline(Codec),
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {recbuf, 4 bsl 20}]),
    {ok, Port} = inet:port(Sock),
    Cmd = lists:flatten(io_lib:format(
        "gst-launch-1.0 -q videotestsrc num-buffers=~b pattern=ball is-live=true ! "
        "video/x-raw,format=I420,width=~b,height=~b,framerate=30/1 ! ~s ! ~s ! udpsink host=127.0.0.1 port=~b",
        [?FRAMES, ?W, ?H, Enc, Pay, Port])),
    P = open_port({spawn, Cmd}, [exit_status]),
    T0 = erlang:monotonic_time(millisecond),
    Pkts = recv(Sock, T0, []),
    gen_udp:close(Sock),
    receive {P, {exit_status, _}} -> ok after 5000 -> ok end,
    ?assert(length(Pkts) > ?FRAMES),
    Pkts.

recv(Sock, T0, Acc) ->
    case gen_udp:recv(Sock, 0, 3000) of
        {ok, {_, _, Bin}} ->
            {ok, Pkt} = webrtc_rtp:decode(Bin),
            recv(Sock, T0, [{erlang:monotonic_time(millisecond) - T0, Pkt} | Acc]);
        {error, timeout} ->
            lists:reverse(Acc)
    end.

assemble(Codec, Pkts) ->
    {Out, Requests, Stats} = webrtc_test_frames:run(Pkts, #{codecs => [#{pt => ?PT, name => webrtc_test_frames:name(Codec)}]}),
    ct:log("~p", [Stats]),
    {[F || {_, F} <- Out], Requests}.

%% Write the frames to a file ffmpeg reads (IVF, or an H.264 Annex B
%% stream), decode it and compare.
decode(Config, Codec, Name, Frames) ->
    Dir = ?config(priv_dir, Config),
    File = filename:join(Dir, Name ++ "." ++ atom_to_list(Codec)),
    case Codec of
        h264 -> ok = file:write_file(File, [D || #{data := D} <- Frames]);
        _ -> webrtc_test_frames:write_ivf(File, fourcc(Codec), {?W, ?H}, [D || #{data := D} <- Frames])
    end,
    Fmt = case Codec of h264 -> "-f h264 "; _ -> "-f ivf " end,
    Errors = os:cmd("ffmpeg -hide_banner -v error " ++ Fmt ++ "-i " ++ File ++ " -f null - 2>&1"),
    ct:log("ffmpeg: ~s", [Errors]),
    ?assertEqual("", string:trim(Errors)),
    Probe = os:cmd("ffprobe -v error " ++ Fmt ++ "-show_frames -show_entries frame=key_frame,width,height -of csv=p=0 " ++ File),
    Decoded = [string:split(L, ",", all) || L <- string:split(string:trim(Probe), "\n", all), L =/= ""],
    ?assertEqual(length(Frames), length(Decoded)),
    ?assertEqual([case K of true -> "1"; false -> "0" end || #{keyframe := K} <- Frames], [K || [_, K | _] <- reorder(Decoded)]),
    ?assert(lists:all(fun(D) -> lists:member(integer_to_list(?W), D) andalso lists:member(integer_to_list(?H), D) end,
                      Decoded)).

%% ffprobe prints the fields in its own order: key_frame first.
reorder(Rows) -> [[x, K] || [K | _] <- Rows].

fourcc(vp8) -> <<"VP80">>;
fourcc(vp9) -> <<"VP90">>;
fourcc(av1) -> <<"AV01">>.
