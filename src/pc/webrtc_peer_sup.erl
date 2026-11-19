%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private The supervision subtree of one peer connection: the peer
%% connection process, significant, and its transports, added by it
%% with `start_transport/2'. When the peer connection ends, however it
%% ends, the subtree shuts down and takes the transports with it
%% (`auto_shutdown => any_significant'). Nothing is restarted: a peer
%% connection's JSEP and DTLS state cannot be rebuilt.
-module(webrtc_peer_sup).
-behaviour(supervisor).

-export([start_link/1, start_transport/2, init/1]).

%% @doc Start the subtree; returns `{ok, Sup, PeerConnection}'.
-spec start_link(map() | fun(() -> map())) -> {ok, pid(), pid()} | {error, term()}.
start_link(Args) when is_function(Args, 0) ->
    start_link(Args());
start_link(Args) ->
    case supervisor:start_link(?MODULE, Args) of
        {ok, Sup} ->
            [Pc] = [P || {pc, P, _, _} <- supervisor:which_children(Sup), is_pid(P)],
            {ok, Sup, Pc};
        {error, _} = E ->
            E
    end.

%% @doc Start a transport under the subtree of `Sup'.
-spec start_transport(pid(), map()) -> {ok, pid()} | {error, term()}.
start_transport(Sup, Opts) ->
    supervisor:start_child(Sup, #{
        id => {transport, make_ref()},
        %% A fun: the options hold the certificate and credentials, and
        %% supervisor reports print start arguments.
        start => {webrtc_transport, start_link, [fun() -> Opts end]},
        restart => temporary,
        shutdown => 5000
    }).

init(Args) ->
    Opts = Args#{peer_sup => self()},
    Pc = #{
        id => pc,
        start => {webrtc_pc, start_link, [fun() -> Opts end]},
        restart => temporary,
        significant => true,
        shutdown => 5000
    },
    {ok, {#{strategy => one_for_all, intensity => 0, period => 1, auto_shutdown => any_significant}, [Pc]}}.
