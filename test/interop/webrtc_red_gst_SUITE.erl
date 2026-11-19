%% RED (RFC 2198) against GStreamer's rtpredenc and rtpreddec, an
%% implementation independent of libwebrtc, over plain RTP on UDP: RED is
%% an RTP payload format, so no WebRTC layer is needed around it.
%% Chromium checks the negotiation (webrtc_pc_interop_SUITE).
-module(webrtc_red_gst_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([gst_red_distance_1/1, gst_red_distance_2/1, gst_decodes_our_red/1]).

-define(RED, 63).
-define(OPUS, 111).

all() -> [gst_red_distance_1, gst_red_distance_2, gst_decodes_our_red].

init_per_suite(Config) ->
    Elements = ["rtpredenc", "rtpreddec", "opusenc", "opusdec", "rtpopuspay", "rtpopusdepay", "audiotestsrc"],
    case os:find_executable("gst-launch-1.0") of
        false ->
            {skip, "GStreamer not installed (gst-launch-1.0)"};
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

%%====================================================================
%% GStreamer encodes, we decode and repair
%%====================================================================

gst_red_distance_1(_Config) -> gst_encodes(1).

gst_red_distance_2(_Config) -> gst_encodes(2).

gst_encodes(Distance) ->
    Pkts = capture(io_lib:format("audiotestsrc num-buffers=60 ! opusenc frame-size=20 ! rtpopuspay pt=~b ! "
                                 "rtpredenc pt=~b distance=~b allow-no-red-blocks=true", [?OPUS, ?RED, Distance]), 60),
    %% Every redundant block repeats an earlier primary: same payload
    %% type and payload, at the packet its offset points to.
    Primaries = maps:from_list([{Ts, primary(P)} || #rtp{ts = Ts} = P <- Pkts]),
    Checked = lists:append([[begin
                                 ?assertEqual({ok, {Pt, D}}, {ok, maps:get((Ts - O) band 16#FFFFFFFF, Primaries)}),
                                 1
                             end || {Pt, O, D} <- redundant(P), maps:is_key((Ts - O) band 16#FFFFFFFF, Primaries)]
                            || #rtp{ts = Ts} = P <- Pkts]),
    ?assert(length(Checked) >= 50),
    %% Every third packet lost: our receiver gets each back from the
    %% packet `Distance' later.
    Kept = [P || {I, P} <- lists:enumerate(Pkts), I rem 3 =/= 0],
    {Delivered, _} = lists:foldl(
        fun(#rtp{} = P, {Acc, H}) ->
            {ok, Blocks} = webrtc_red:decode(P#rtp.payload),
            {Repaired, Primary} = webrtc_red:repair(P, Blocks, fun(Pt) -> Pt =:= ?OPUS end, H),
            Out = Repaired ++ Primary,
            {Acc ++ Out, lists:foldl(fun(#rtp{seq = S, ts = T}, H1) -> webrtc_red:seen(S, T, H1) end, H, Out)}
        end,
        {[], []},
        Kept
    ),
    All = [{S, Ts, primary(P)} || #rtp{seq = S, ts = Ts} = P <- Pkts],
    Got = lists:sort([{S, Ts, {Pt, D}} || #rtp{seq = S, ts = Ts, pt = Pt, payload = D} <- Delivered]),
    %% The last `Distance' packets have no later packet to repair them;
    %% the first two are before a packet duration is known.
    Expected = [E || {I, E} <- lists:enumerate(All), I =< length(All) - Distance, I > 2],
    ?assertEqual([], Expected -- Got),
    ct:log("distance ~b: ~b of ~b packets delivered after losing ~b", [Distance, length(Got), length(All),
                                                                       length(All) - length(Kept)]).

primary(#rtp{payload = B}) ->
    {ok, Blocks} = webrtc_red:decode(B),
    {Pt, 0, D} = lists:last(Blocks),
    {Pt, D}.

redundant(#rtp{payload = B}) ->
    {ok, Blocks} = webrtc_red:decode(B),
    lists:droplast(Blocks).

%%====================================================================
%% We encode, GStreamer decodes
%%====================================================================

%% Opus from GStreamer, put in RED by us, every third packet lost: with
%% the previous packet repeated, rtpreddec and opusdec decode as much
%% audio as with no loss, and more than without redundancy.
gst_decodes_our_red(Config) ->
    Opus = capture(io_lib:format("audiotestsrc num-buffers=60 ! opusenc frame-size=20 ! rtpopuspay pt=~b", [?OPUS]), 60),
    Dir = ?config(priv_dir, Config),
    Full = decoded_bytes(Dir, "full", red_stream(Opus, 1), fun(_) -> true end),
    Lossy = decoded_bytes(Dir, "lossy", red_stream(Opus, 0), fun(I) -> I rem 3 =/= 0 end),
    Repaired = decoded_bytes(Dir, "repaired", red_stream(Opus, 1), fun(I) -> I rem 3 =/= 0 end),
    ct:log("decoded bytes: all sent ~b, a third lost ~b, a third lost with RED ~b", [Full, Lossy, Repaired]),
    ?assert(Full > 0),
    ?assert(Lossy < Full),
    %% The last packet lost has no later one to repair it.
    ?assert(Repaired >= Full - Full div 60).

%% RED packets with `Distance' previous payloads (0: primary only).
red_stream(Opus, Distance) ->
    {Out, _} = lists:mapfoldl(
        fun(#rtp{ts = Ts, payload = D} = P, Prev) ->
            Red = [{?OPUS, (Ts - T) band 16#FFFFFFFF, PD} || {T, PD} <- lists:sublist(Prev, Distance)],
            {P#rtp{pt = ?RED, payload = webrtc_red:encode(lists:reverse(Red), {?OPUS, D})}, [{Ts, D} | Prev]}
        end,
        [],
        Opus
    ),
    Out.

decoded_bytes(Dir, Name, Pkts, Send) ->
    File = filename:join(Dir, Name ++ ".raw"),
    {ok, Sock} = gen_udp:open(0, [binary]),
    Port = free_port(),
    %% The caps describe what rtpopusdepay gets once rtpreddec took the
    %% Opus packets out.
    Caps = io_lib:format("application/x-rtp,media=audio,clock-rate=48000,encoding-name=OPUS,payload=~b", [?OPUS]),
    Cmd = lists:flatten(io_lib:format(
        "gst-launch-1.0 -q -e udpsrc port=~b caps=\"~s\" ! rtpreddec pt=~b ! rtpopusdepay ! opusdec plc=false ! "
        "filesink location=~s", [Port, Caps, ?RED, File])),
    P = open_port({spawn, Cmd}, [exit_status]),
    timer:sleep(1000),
    [ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, webrtc_rtp:encode(Pkt)) || {I, Pkt} <- lists:enumerate(Pkts), Send(I)],
    timer:sleep(1000),
    {os_pid, Os} = erlang:port_info(P, os_pid),
    _ = os:cmd("kill -INT " ++ integer_to_list(Os)),
    receive {P, {exit_status, _}} -> ok after 10000 -> ok end,
    gen_udp:close(Sock),
    filelib:file_size(File).

%%====================================================================
%% Helpers
%%====================================================================

%% Run `Source ! udpsink' and decode the first N RTP packets it sends.
capture(Source, N) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    {ok, Port} = inet:port(Sock),
    Cmd = lists:flatten(io_lib:format("gst-launch-1.0 -q ~s ! udpsink host=127.0.0.1 port=~b", [Source, Port])),
    P = open_port({spawn, Cmd}, [exit_status]),
    Pkts = recv(Sock, N, []),
    gen_udp:close(Sock),
    receive {P, {exit_status, _}} -> ok after 5000 -> ok end,
    Pkts.

recv(_Sock, 0, Acc) ->
    lists:reverse(Acc);
recv(Sock, N, Acc) ->
    case gen_udp:recv(Sock, 0, 10000) of
        {ok, {_, _, Bin}} ->
            {ok, Pkt} = webrtc_rtp:decode(Bin),
            recv(Sock, N - 1, [Pkt | Acc]);
        {error, timeout} ->
            lists:reverse(Acc)
    end.

free_port() ->
    {ok, S} = gen_udp:open(0),
    {ok, P} = inet:port(S),
    gen_udp:close(S),
    P.
