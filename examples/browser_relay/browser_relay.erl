%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Relay a browser's camera to another browser: one page sends its
%% video, another receives it, and Erlang forwards every RTP packet from
%% the first peer connection to the second without decoding it.
%%
%%   1> c(browser_relay).
%%   2> browser_relay:start(8080).
%%   then open http://localhost:8080/?role=send and
%%   http://localhost:8080/?role=receive, in either order
-module(browser_relay).

-export([start/1, stop/0, do/1]).

-include_lib("inets/include/httpd.hrl").

%% Serve the page, and start the relay process that holds both peer
%% connections.
start(Port) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(webrtc),
    true = register(?MODULE, spawn(fun() -> relay(#{}) end)),
    Dir = filename:dirname(code:which(?MODULE)),
    inets:start(httpd, [{port, Port}, {bind_address, {127, 0, 0, 1}}, {server_name, "localhost"},
                        {server_root, Dir}, {document_root, Dir}, {modules, [?MODULE]}]).

stop() ->
    [inets:stop(httpd, P) || {httpd, P} <- inets:services()],
    case whereis(?MODULE) of
        undefined -> ok;
        Relay -> exit(Relay, kill), ok
    end.

%% httpd callback: GET / gives the page (both roles), POST /send and
%% POST /receive take that role's offer and return the answer.
do(#mod{method = "GET", request_uri = "/?" ++ _} = Mod) ->
    do(Mod#mod{request_uri = "/"});
do(#mod{method = "GET", request_uri = "/"}) ->
    {ok, Page} = file:read_file(filename:join(filename:dirname(code:which(?MODULE)), "index.html")),
    reply("text/html", Page);
do(#mod{method = "POST", request_uri = Uri, entity_body = Body}) when Uri =:= "/send"; Uri =:= "/receive" ->
    Role = case Uri of "/send" -> sender; "/receive" -> receiver end,
    ?MODULE ! {offer, Role, list_to_binary(Body), self()},
    receive
        {answer, Answer} -> reply("application/sdp", Answer)
    after 10000 ->
        {proceed, [{response, {500, "no answer"}}]}
    end;
do(_) ->
    {proceed, [{response, {404, "not found"}}]}.

reply(Type, Body) ->
    Head = [{code, 200}, {content_type, Type}, {content_length, integer_to_list(byte_size(Body))}],
    {proceed, [{response, {response, Head, binary_to_list(Body)}}]}.

%% `Peers' maps `sender' and `receiver' to `{Pc, Mid}', the peer
%% connection of that page and the mid of its video transceiver. A page
%% that comes back replaces the previous one of its role.
relay(Peers) ->
    receive
        {offer, Role, Offer, From} ->
            case Peers of
                #{Role := {Old, _}} -> webrtc:close(Old);
                _ -> ok
            end,
            {Pc, Mid, Answer} = answer(Role, Offer),
            From ! {answer, Answer},
            relay(Peers#{Role => {Pc, Mid}});
        %% Every packet the sender sends goes to the receiver, if there
        %% is one. SSRC and sequence numbers are rewritten for it.
        {webrtc, In, {rtp, _Mid, Pkt}} ->
            case Peers of
                #{sender := {In, _}, receiver := {Out, Mid}} -> _ = webrtc:send_rtp_packet(Out, Mid, Pkt);
                _ -> ok
            end,
            relay(Peers);
        %% The receiver can only decode from a keyframe: ask the sender
        %% for one when the receiver connects or when it asks for one.
        {webrtc, Out, Event} when Event =:= {connection_state, connected};
                                  element(1, Event) =:= keyframe_request ->
            case Peers of
                #{receiver := {Out, _}, sender := {In, Mid}} -> _ = webrtc:request_keyframe(In, Mid);
                _ -> ok
            end,
            relay(Peers);
        {webrtc, _, _} ->
            relay(Peers)
    end.

%% Answer a page's offer, wait for our candidates and return the local
%% description, which now carries them. Each page offers one video
%% transceiver; the one the offer creates here only receives, so turn
%% it to sendonly for the receiving page.
answer(Role, Offer) ->
    {ok, Pc} = webrtc:new_peer_connection(#{}),
    ok = webrtc:set_remote_description(Pc, offer, Offer),
    [#{id := Id, mid := Mid}] = webrtc:transceivers(Pc),
    case Role of
        receiver -> ok = webrtc:set_direction(Pc, Id, sendonly);
        sender -> ok
    end,
    {ok, Answer} = webrtc:create_answer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, answer, Answer),
    receive {webrtc, Pc, {ice_gathering_state, complete}} -> ok after 5000 -> ok end,
    {Pc, Mid, webrtc:local_description(Pc)}.
