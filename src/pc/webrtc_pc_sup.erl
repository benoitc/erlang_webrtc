%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private Dynamic supervisor of the peer connections. Each child is
%% the subtree of one peer connection (`webrtc_peer_sup'), temporary: a
%% crash of one peer connection does not affect the others and is not
%% restarted.
-module(webrtc_pc_sup).
-behaviour(supervisor).
-export([start_link/0, start_child/1, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @doc Start a peer connection; returns its pid.
-spec start_child(map()) -> {ok, pid()} | {error, term()}.
start_child(Args) ->
    Spec = #{
        id => make_ref(),
        %% A fun keeps the options (certificate, credentials) out of
        %% supervisor reports.
        start => {webrtc_peer_sup, start_link, [fun() -> Args end]},
        restart => temporary,
        type => supervisor,
        shutdown => infinity
    },
    case supervisor:start_child(?MODULE, Spec) of
        {ok, _Sup, Pc} -> {ok, Pc};
        {ok, _Sup} -> {error, no_peer_connection};
        {error, {E, _Child}} -> {error, E};
        {error, _} = E -> E
    end.

init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 100, period => 1}, []}}.
