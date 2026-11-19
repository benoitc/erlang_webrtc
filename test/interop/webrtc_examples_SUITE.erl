%% The examples of docs/guides run as written: each one under examples/
%% serves its page, a headless browser with a fake camera loads it, and
%% the page must show what the guide says it shows.
-module(webrtc_examples_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([browser_datachannel/1, browser_video/1, browser_relay/1]).

all() -> [{group, chromium}, {group, firefox}].

groups() -> [{B, [], [browser_datachannel, browser_video, browser_relay]} || B <- [chromium, firefox]].

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
    Url = start_example(browser_datachannel, Config),
    try
        Out = open_pages(Config, [Url], "echo: hello from the browser"),
        ?assertMatch({_, _}, binary:match(Out, <<"erlang: hello from Erlang on chat">>)),
        ?assertMatch({_, _}, binary:match(Out, <<"erlang: echo: hello from the browser">>))
    after
        browser_datachannel:stop()
    end.

%% The page sends its camera; Erlang counts the frames and reports them
%% over the data channel, the size once a key frame came.
browser_video(Config) ->
    Url = start_example(browser_video, Config),
    try
        Out = open_pages(Config, [Url], "height: 480"),
        {match, [N, K]} = re:run(Out, "frames: ([0-9]+) keyframes: ([0-9]+) width: 640 height: 480",
                                 [{capture, all_but_first, list}]),
        ?assert(list_to_integer(N) > 0),
        ?assert(list_to_integer(K) > 0)
    after
        browser_video:stop()
    end.

%% One page sends its camera, the other gets it through Erlang, which
%% forwards the RTP packets. The receiving page opens first; the relay
%% works in either order.
browser_relay(Config) ->
    Url = start_example(browser_relay, Config),
    try
        %% The sender may start below the size it captures while its
        %% bandwidth estimate grows: any size shows the relay works.
        Out = open_pages(Config, [Url ++ "?role=receive", Url ++ "?role=send"], "receiving: "),
        ?assertMatch({match, _}, re:run(Out, "\\[1\\] receiving: [1-9][0-9]*x[1-9][0-9]*"))
    after
        browser_relay:stop()
    end.

%% Built and run from its own directory, as the guide does. Returns the
%% URL of its page.
start_example(Mod, Config) ->
    Dir = ?config(priv_dir, Config),
    Src = filename:join([?config(root, Config), "examples", atom_to_list(Mod)]),
    Erl = atom_to_list(Mod) ++ ".erl",
    [{ok, _} = file:copy(filename:join(Src, F), filename:join(Dir, F)) || F <- [Erl, "index.html"]],
    {ok, Mod} = compile:file(filename:join(Dir, Erl), [{outdir, Dir}]),
    true = code:add_patha(Dir),
    code:purge(Mod),
    {module, _} = code:load_file(Mod),
    Port = free_port(),
    {ok, _} = Mod:start(Port),
    "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/".

%% Open the pages in one headless browser until one logs Expect.
open_pages(Config, Urls, Expect) ->
    Cmd = lists:flatten(io_lib:format("node ~s ~s ~s '~s'",
                                      [?config(script, Config), ?config(browser, Config),
                                       lists:join(" ", ["'" ++ U ++ "'" || U <- Urls]), Expect])),
    P = open_port({spawn, Cmd}, [exit_status, binary, stderr_to_stdout]),
    {Status, Out} = collect(P, <<>>),
    ct:log("~s", [Out]),
    ?assertEqual(0, Status),
    Out.

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
