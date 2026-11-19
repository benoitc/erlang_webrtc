%% Receive a browser's camera as frames: the page sends a video track
%% and opens a data channel; Erlang counts the frames it gets and tells
%% the page once a second over the channel.
%%
%%   1> c(browser_video).
%%   2> browser_video:start(8080).
%%   then open http://localhost:8080/ and allow the camera
-module(browser_video).

-export([start/1, stop/0, do/1, session/1]).

-include_lib("inets/include/httpd.hrl").

%% Serve the page and the /offer endpoint on localhost.
start(Port) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(webrtc),
    Dir = filename:dirname(code:which(?MODULE)),
    inets:start(httpd, [{port, Port}, {bind_address, {127, 0, 0, 1}}, {server_name, "localhost"},
                        {server_root, Dir}, {document_root, Dir}, {modules, [?MODULE]}]).

stop() ->
    [inets:stop(httpd, P) || {httpd, P} <- inets:services()],
    ok.

%% httpd callback: GET / gives the page, POST /offer an answer.
do(#mod{method = "GET", request_uri = "/"}) ->
    {ok, Page} = file:read_file(filename:join(filename:dirname(code:which(?MODULE)), "index.html")),
    reply("text/html", Page);
do(#mod{method = "POST", request_uri = "/offer", entity_body = Body}) ->
    Self = self(),
    Pid = spawn(fun() -> session({Self, list_to_binary(Body)}) end),
    receive
        {answer, Pid, Answer} ->
            reply("application/sdp", Answer)
    after 10000 ->
        exit(Pid, kill),
        {proceed, [{response, {500, "no answer"}}]}
    end;
do(_) ->
    {proceed, [{response, {404, "not found"}}]}.

reply(Type, Body) ->
    Head = [{code, 200}, {content_type, Type}, {content_length, integer_to_list(byte_size(Body))}],
    {proceed, [{response, {response, Head, binary_to_list(Body)}}]}.

%% `frames => true' applies to the transceiver the offer creates: we get
%% `{frame, Mid, Frame}' events, whole encoded frames, instead of RTP
%% packets.
session({From, Offer}) ->
    {ok, Pc} = webrtc:new_peer_connection(#{frames => true}),
    ok = webrtc:set_remote_description(Pc, offer, Offer),
    {ok, Answer} = webrtc:create_answer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, answer, Answer),
    receive {webrtc, Pc, {ice_gathering_state, complete}} -> ok after 5000 -> ok end,
    From ! {answer, self(), webrtc:local_description(Pc)},
    {ok, _} = timer:send_interval(1000, report),
    loop(Pc, #{channel => undefined, frames => 0, keyframes => 0, width => 0, height => 0}).

loop(Pc, S) ->
    receive
        {webrtc, Pc, {frame, _Mid, Frame}} ->
            loop(Pc, count(Frame, S));
        {webrtc, Pc, {datachannel_open, Id, _Label, _Protocol, _Opts}} ->
            loop(Pc, S#{channel := Id});
        report when is_integer(map_get(channel, S)) ->
            #{channel := Id, frames := N, keyframes := K, width := W, height := H} = S,
            Text = io_lib:format("frames: ~b keyframes: ~b width: ~b height: ~b", [N, K, W, H]),
            _ = webrtc:send_data(Pc, Id, text, Text),
            loop(Pc, S);
        report ->
            loop(Pc, S);
        {webrtc, Pc, {connection_state, St}} when St =:= closed; St =:= failed ->
            webrtc:close(Pc);
        {webrtc, Pc, _} ->
            loop(Pc, S)
    end.

count(#{keyframe := Key} = Frame, #{frames := N, keyframes := K} = S) ->
    S1 = S#{frames := N + 1, keyframes := K + case Key of true -> 1; false -> 0 end},
    %% Only key frames carry the picture size; keep the last one.
    case Frame of
        #{width := W, height := H} when is_integer(W) -> S1#{width := W, height := H};
        _ -> S1
    end.
