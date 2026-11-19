%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% A logger handler for the tests: every log event, formatted as the
%% default handler would print it, goes to a process as {log, Text}.
-module(webrtc_test_log).

-export([capture/1, release/1, log/2]).

%% @doc Send every formatted event to the calling process.
capture(Id) ->
    ok = logger:add_handler(Id, ?MODULE, #{config => #{pid => self()}, level => all,
                                           formatter => {logger_formatter, #{single_line => false, depth => unlimited,
                                                                              chars_limit => unlimited}}}).

release(Id) ->
    logger:remove_handler(Id).

log(Event, #{config := #{pid := Pid}, formatter := {Mod, FConfig}}) ->
    Pid ! {log, unicode:characters_to_binary(Mod:format(Event, FConfig))}.
