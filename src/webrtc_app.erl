%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private
-module(webrtc_app).
-behaviour(application).
-export([start/2, stop/1]).

start(_Type, _Args) ->
    webrtc_sup:start_link().

stop(_State) ->
    ok.
