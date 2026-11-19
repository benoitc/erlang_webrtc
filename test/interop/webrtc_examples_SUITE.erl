%% The examples of docs/guides run as written: examples/browser_datachannel
%% serves its page, a headless browser loads it, and the data channel
%% must carry the greeting and the echo both ways.
-module(webrtc_examples_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([browser_datachannel/1]).

all() -> [{group, chromium}, {group, firefox}].

groups() -> [{B, [], [browser_datachannel]} || B <- [chromium, firefox]].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Root = root(),
    Script = filename:join([Root, "interop", "browser", "open_page.js"]),
    case os:find_executable("node") =/= false andalso
             filelib:is_dir(filename:join([Root, "interop", "browser", "node_modules", "playwright"])) of
        true -> [{root, Root}, {script, Script} | Config];
        false -> {skip, "playwright missing: run npm ci in interop/browser"}
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(firefox, Config) ->
    case os:type() of
        {unix, darwin} -> {skip, "Playwright's Firefox does not start from a terminal on macOS"};
        _ -> [{browser, firefox} | Config]
    end;
init_per_group(B, Config) ->
    [{browser, B} | Config].

end_per_group(_, _Config) ->
    ok.

%% The page posts its offer, Erlang answers, the browser sends "hello
%% from the browser" and gets it echoed after Erlang's greeting.
browser_datachannel(Config) ->
    Dir = ?config(priv_dir, Config),
    Src = filename:join([?config(root, Config), "examples", "browser_datachannel"]),
    %% Built and run from its own directory, as the guide does.
    [{ok, _} = file:copy(filename:join(Src, F), filename:join(Dir, F)) || F <- ["browser_datachannel.erl", "index.html"]],
    {ok, browser_datachannel} = compile:file(filename:join(Dir, "browser_datachannel.erl"), [{outdir, Dir}]),
    true = code:add_patha(Dir),
    code:purge(browser_datachannel),
    {module, _} = code:load_file(browser_datachannel),
    Port = free_port(),
    {ok, _} = browser_datachannel:start(Port),
    try
        Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/",
        Cmd = lists:flatten(io_lib:format("node ~s ~s ~s 'echo: hello from the browser'",
                                          [?config(script, Config), ?config(browser, Config), Url])),
        P = open_port({spawn, Cmd}, [exit_status, binary, stderr_to_stdout]),
        {Status, Out} = collect(P, <<>>),
        ct:log("~s", [Out]),
        ?assertEqual(0, Status),
        ?assertMatch({_, _}, binary:match(Out, <<"erlang: hello from Erlang on chat">>)),
        ?assertMatch({_, _}, binary:match(Out, <<"erlang: echo: hello from the browser">>))
    after
        browser_datachannel:stop()
    end.

collect(P, Acc) ->
    receive
        {P, {data, D}} -> collect(P, <<Acc/binary, D/binary>>);
        {P, {exit_status, S}} -> {S, Acc}
    after 60000 ->
        {timeout, Acc}
    end.

free_port() ->
    {ok, S} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, P} = inet:port(S),
    gen_tcp:close(S),
    P.

root() ->
    {ok, Cwd} = file:get_cwd(),
    up(Cwd).

up("/") -> error(no_project_root);
up(Dir) ->
    case filelib:is_dir(filename:join(Dir, "examples")) andalso filelib:is_regular(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> up(filename:dirname(Dir))
    end.
