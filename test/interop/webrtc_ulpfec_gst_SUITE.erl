%% ULPFEC (RFC 5109) in RED (RFC 2198) against GStreamer's rtpulpfecenc
%% and rtpredenc, an implementation independent of libwebrtc, over plain
%% RTP on UDP: VP8 packets protected by GStreamer, some dropped, rebuilt
%% by our decoder byte for byte, and the frames decoded by ffmpeg.
-module(webrtc_ulpfec_gst_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([gst_fec_recovers_losses/1, gst_fec_multipacket/1]).

-define(VP8, 96).
-define(RED, 116).
-define(ULPFEC, 118).

all() -> [gst_fec_recovers_losses, gst_fec_multipacket].

init_per_suite(Config) ->
    Elements = ["videotestsrc", "vp8enc", "rtpvp8pay", "rtpulpfecenc", "rtpredenc"],
    case {os:find_executable("gst-launch-1.0"), os:find_executable("ffprobe")} of
        {false, _} -> {skip, "GStreamer not installed (gst-launch-1.0)"};
        {_, false} -> {skip, "ffmpeg not installed (ffprobe)"};
        _ ->
            case [E || E <- Elements, not element_exists(E)] of
                [] -> Config;
                Missing -> {skip, "GStreamer elements missing: " ++ string:join(Missing, ", ")}
            end
    end.

end_per_suite(_Config) ->
    ok.

element_exists(E) ->
    string:find(os:cmd("gst-inspect-1.0 " ++ E ++ " 2>&1"), "Factory Details") =/= nomatch.

%% One FEC packet per media packet (100%): every media packet dropped
%% alone comes back exactly.
gst_fec_recovers_losses(Config) ->
    run(Config, "percentage=100", fun(I) -> I rem 5 =:= 2 end).

%% multipacket: an FEC packet protects several media packets.
gst_fec_multipacket(Config) ->
    run(Config, "percentage=50 multipacket=true", fun(I) -> I rem 9 =:= 4 end).

run(Config, FecOpts, Drop) ->
    Pkts = capture(io_lib:format(
        "videotestsrc num-buffers=60 pattern=ball ! video/x-raw,format=I420,width=320,height=240,framerate=30/1 ! "
        "vp8enc deadline=1 keyframe-max-dist=30 target-bitrate=300000 ! rtpvp8pay picture-id-mode=15-bit mtu=600 pt=~b ! "
        "rtpulpfecenc pt=~b ~s ! rtpredenc pt=~b allow-no-red-blocks=true", [?VP8, ?ULPFEC, FecOpts, ?RED])),
    %% Every packet in RED with one block: VP8 or ULPFEC.
    Split = [{P, block(P)} || P <- Pkts],
    Media = [{P, B} || {P, {?VP8, _} = B} <- Split],
    Fecs = [{P, B} || {P, {?ULPFEC, _} = B} <- Split],
    ct:log("~b media packets, ~b FEC packets", [length(Media), length(Fecs)]),
    ?assert(length(Fecs) > 0),
    Lost = [P || {I, {P, _}} <- lists:enumerate(Media), Drop(I)],
    {Recovered, Rx} = lists:foldl(
        fun({#rtp{seq = S, ssrc = Ssrc} = P, {Pt, Data}}, {Acc, R}) ->
            case {Pt, lists:member(P, Lost)} of
                {?VP8, true} -> {Acc, R};
                {?VP8, false} -> {A, R1} = webrtc_ulpfec:media(S, protected(P, Data), R), {Acc ++ A, R1};
                {?ULPFEC, _} -> {A, R1} = webrtc_ulpfec:fec({Ssrc, Data}, R), {Acc ++ A, R1}
            end
        end,
        {[], webrtc_ulpfec:new()},
        Split
    ),
    Stats = webrtc_ulpfec:stats(Rx),
    ct:log("lost ~b, recovered ~b, ~p", [length(Lost), length(Recovered), Stats]),
    %% What we rebuilt is what GStreamer sent, byte for byte.
    Expected = [protected(P, D) || #rtp{} = P <- Lost, {_, {_, D}} <- [lists:keyfind(P, 1, Split)]],
    ?assertEqual([], Recovered -- Expected),
    %% Every lost packet that an FEC packet covers as its only missing one
    %% comes back (GStreamer's masks decide which those are).
    LostSeqs = [S || #rtp{seq = S} <- Lost],
    Covered = lists:usort([S || {_, {?ULPFEC, D}} <- Fecs, {ok, #{base := B, offsets := Os}} <- [webrtc_ulpfec:decode(D)],
                                Seqs <- [[(B + O) band 16#FFFF || O <- Os]],
                                [S] <- [[X || X <- Seqs, lists:member(X, LostSeqs)]]]),
    Got = lists:usort([S || B <- Recovered, {ok, #rtp{seq = S}} <- [webrtc_rtp:decode(B)]]),
    ct:log("covered alone ~p, recovered ~p", [Covered, Got]),
    ?assert(Covered =/= []),
    ?assertEqual([], Covered -- Got),
    %% The frames, received and recovered, decode.
    Back = [R || B <- Recovered, {ok, R} <- [webrtc_rtp:decode(B)]],
    Kept = [P#rtp{pt = ?VP8, payload = D} || {P, {?VP8, D}} <- Media, not lists:member(P, Lost)],
    Arrivals = [{I, P} || {I, P} <- lists:enumerate(lists:keysort(#rtp.seq, Kept ++ Back))],
    {Out, _, _} = webrtc_test_frames:run(Arrivals, #{codecs => [#{pt => ?VP8, name => <<"VP8">>}]}),
    Frames = [D || {_, #{data := D}} <- Out],
    ct:log("~b frames out", [length(Frames)]),
    ?assert(length(Frames) >= 20),
    File = filename:join(?config(priv_dir, Config), "fec.ivf"),
    webrtc_test_frames:write_ivf(File, <<"VP80">>, {320, 240}, Frames),
    ?assertEqual("", string:trim(os:cmd("ffmpeg -hide_banner -v error -f ivf -i " ++ File ++ " -f null - 2>&1"))).

block(#rtp{payload = P}) ->
    {ok, [{Pt, 0, D}]} = webrtc_red:decode(P),
    {Pt, D}.

%% The packet as ULPFEC protects it: the media payload type, no RED
%% header (GStreamer protects before rtpredenc, as libwebrtc).
protected(#rtp{} = P, Data) ->
    webrtc_rtp:encode(P#rtp{pt = ?VP8, payload = Data}).

capture(Source) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {recbuf, 4 bsl 20}]),
    {ok, Port} = inet:port(Sock),
    Cmd = lists:flatten(io_lib:format("gst-launch-1.0 -q ~s ! udpsink host=127.0.0.1 port=~b", [Source, Port])),
    P = open_port({spawn, Cmd}, [exit_status]),
    Pkts = recv(Sock, []),
    gen_udp:close(Sock),
    receive {P, {exit_status, _}} -> ok after 5000 -> ok end,
    Pkts.

recv(Sock, Acc) ->
    case gen_udp:recv(Sock, 0, 3000) of
        {ok, {_, _, Bin}} -> {ok, Pkt} = webrtc_rtp:decode(Bin), recv(Sock, [Pkt | Acc]);
        {error, timeout} -> lists:reverse(Acc)
    end.
