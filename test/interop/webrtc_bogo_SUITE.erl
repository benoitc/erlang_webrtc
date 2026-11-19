%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% BoringSSL's DTLS tests (BoGo) against our DTLS engine, through the shim
%% in interop/bogo. Every DTLS test of the runner that is not disabled in
%% interop/bogo/config.json must pass; tests needing features the shim
%% does not implement are reported as unimplemented, never as passes.
%% Skipped when the BoringSSL checkout (`make -C interop bogo`) or Go is
%% missing.
-module(webrtc_bogo_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([dtls/1]).

all() -> [dtls].

%% The project root: the application is built in _build/<profile>/lib/webrtc.
root() ->
    lists:foldl(fun(_, D) -> filename:dirname(D) end, code:lib_dir(webrtc), [1, 2, 3, 4]).

bogo_dir() -> filename:join([root(), "interop", "bogo"]).

runner_dir() -> filename:join([bogo_dir(), "boringssl", "ssl", "test", "runner"]).

init_per_suite(Config) ->
    Shim = filename:join([bogo_dir(), "ebin", "webrtc_bogo_shim.beam"]),
    case {filelib:is_dir(runner_dir()), filelib:is_file(Shim), os:find_executable("go")} of
        {false, _, _} -> {skip, "BoringSSL checkout missing (make -C interop bogo)"};
        {_, false, _} -> {skip, "shim not built (make -C interop bogo)"};
        {_, _, false} -> {skip, "Go not installed"};
        _ -> Config
    end.

end_per_suite(_Config) ->
    ok.

dtls(Config) ->
    Json = filename:join(?config(priv_dir, Config), "bogo.json"),
    Bogo = filename:absname(bogo_dir()),
    Cmd = lists:flatten(io_lib:format(
        "cd ~s && WEBRTC_EBIN=~s go test -shim-path ~s -shim-config ~s -test '*DTLS*' "
        "-allow-unimplemented -loose-errors -pipe -json-output ~s 2>&1",
        [runner_dir(), filename:join(code:lib_dir(webrtc), "ebin"), filename:join(Bogo, "bogo_shim"),
         filename:join(Bogo, "config.json"), Json])),
    ct:log("~s", [Cmd]),
    Out = run(Cmd, 1800000),
    ct:log("~s", [Out]),
    {ok, Bin} = file:read_file(Json),
    #{<<"tests">> := Tests} = json:decode(Bin),
    Count = fun(R) -> length([N || N := #{<<"actual">> := A} <- Tests, A =:= R]) end,
    ct:log("passed ~b, failed ~b, unimplemented or disabled ~b", [Count(<<"PASS">>), Count(<<"FAIL">>), Count(<<"SKIP">>)]),
    case lists:sort([N || N := #{<<"actual">> := <<"FAIL">>} <- Tests]) of
        [] -> {comment, io_lib:format("~b DTLS tests passed", [Count(<<"PASS">>)])};
        Failed -> ct:fail({failed, Failed})
    end.

%% The runner's output, with a deadline.
run(Cmd, Timeout) ->
    Port = open_port({spawn_executable, "/bin/sh"}, [{args, ["-c", Cmd]}, stream, exit_status, binary, stderr_to_stdout]),
    collect(Port, [], erlang:monotonic_time(millisecond) + Timeout).

collect(Port, Acc, Deadline) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {Port, {data, D}} -> collect(Port, [D | Acc], Deadline);
        {Port, {exit_status, _}} -> iolist_to_binary(lists:reverse(Acc))
    after Left ->
        try port_close(Port) catch _:_ -> ok end,
        ct:fail(runner_timeout)
    end.
