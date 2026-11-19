%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% A data channel between a browser and Erlang, with HTTP as the
%% signaling channel: the page posts its offer, with every candidate in
%% it, and gets the answer back. See docs/guides/data-channels.md.
%%
%%   1> c(browser_datachannel).
%%   2> browser_datachannel:start(8080).
%%   then open http://localhost:8080/
-module(browser_datachannel).

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
    %% One process per browser owns its peer connection and gets its
    %% events; it hands the answer back here.
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

%% Answer the offer, wait for our candidates, then run the channel.
session({From, Offer}) ->
    {ok, Pc} = webrtc:new_peer_connection(#{}),
    ok = webrtc:set_remote_description(Pc, offer, Offer),
    {ok, Answer} = webrtc:create_answer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, answer, Answer),
    receive {webrtc, Pc, {ice_gathering_state, complete}} -> ok after 5000 -> ok end,
    %% The local description now carries every candidate gathered.
    From ! {answer, self(), webrtc:local_description(Pc)},
    loop(Pc).

loop(Pc) ->
    receive
        {webrtc, Pc, {datachannel_open, Id, Label, _Protocol, _Opts}} ->
            ok = webrtc:send_data(Pc, Id, text, <<"hello from Erlang on ", Label/binary>>),
            loop(Pc);
        {webrtc, Pc, {channel_message, Id, text, Text}} ->
            ok = webrtc:send_data(Pc, Id, text, <<"echo: ", Text/binary>>),
            loop(Pc);
        {webrtc, Pc, {channel_message, Id, binary, Bin}} ->
            ok = webrtc:send_data(Pc, Id, binary, Bin),
            loop(Pc);
        {webrtc, Pc, {connection_state, S}} when S =:= closed; S =:= failed ->
            webrtc:close(Pc);
        {webrtc, Pc, _} ->
            loop(Pc)
    end.
