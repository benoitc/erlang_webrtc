%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Every process and table row a peer connection creates ends with it,
%% however it ends: close, owner exit, kill. A stuck application
%% function or a hanging connect does not keep anything alive.
-module(webrtc_lifecycle_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([
    close_ends_helpers/1,
    killed_peer_rows_removed/1,
    slow_signaling_bounded/1,
    connect_workers_end/1,
    owner_death/1,
    killed_transport/1,
    application_restart/1,
    stuck_codec_plugin/1,
    plugins_end_with_close/1,
    abandoned_connections/1,
    short_lived_pairs/1,
    scheduler_stress/1,
    other_node/1
]).

-export([init/3, decode/2, encode/2, info/1]).

-define(S, webrtc_test_signal).

all() ->
    [close_ends_helpers, killed_peer_rows_removed, slow_signaling_bounded, connect_workers_end,
     owner_death, killed_transport, application_restart, stuck_codec_plugin, plugins_end_with_close, abandoned_connections,
     short_lived_pairs, scheduler_stress, other_node].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Config.

end_per_suite(_) -> ok.

init_per_testcase(_, Config) -> ?S:flush(), Config.
end_per_testcase(_, _) -> ?S:flush(), ok.

%% The processes linked to a process, its supervisor aside.
linked(Pid) ->
    {links, L} = process_info(Pid, links),
    Parent = case process_info(Pid, parent) of {parent, P} -> P; _ -> undefined end,
    [P || P <- L, is_pid(P), P =/= Parent, P =/= whereis(webrtc_pc_sup)].

%% The transports of a peer connection and its signaling helper.
owned(Pc) ->
    lists:usort([T || {_, T} <- rows(Pc)] ++ linked(Pc)).

wait_dead(Pids, Ms) ->
    Deadline = erlang:monotonic_time(millisecond) + Ms,
    wait_dead1(Pids, Deadline).

wait_dead1(Pids, Deadline) ->
    case [P || P <- Pids, is_process_alive(P)] of
        [] -> ok;
        Alive ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> {alive, Alive};
                false -> timer:sleep(20), wait_dead1(Alive, Deadline)
            end
    end.

rows(Pc) ->
    ets:lookup(webrtc_transports, Pc) ++ ets:match_object(webrtc_transports, {{Pc, '_'}, '_'}).

wait_until(F, Ms) when Ms =< 0 -> F();
wait_until(F, Ms) ->
    case F() of
        true -> true;
        false -> timer:sleep(20), wait_until(F, Ms - 20)
    end.

%% close/1: the transport and the signaling helper end too.
close_ends_helpers(_Config) ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, signaling => fun(_, _) -> ok end}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"c">>, #{}),
    ?S:connect(A, B),
    Linked = owned(A),
    ?assert(length(Linked) >= 2),
    ok = webrtc:close(A),
    ok = webrtc:close(B),
    ?assertEqual(ok, wait_dead(Linked, 6000)),
    ?assertEqual([], rows(A)).

%% kill: terminate does not run, the registry still removes the rows of
%% every transport (unbundled: one per section).
killed_peer_rows_removed(_Config) ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, bundle => false}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    ok = webrtc:create_data_channel(A, <<"k">>, #{}),
    ?S:connect(A, B),
    ?assert(length(rows(A)) >= 2),
    Linked = owned(A),
    exit(A, kill),
    ?assert(wait_until(fun() -> rows(A) =:= [] end, 2000)),
    ?assertEqual(ok, wait_dead(Linked, 6000)),
    %% The API answers closed, not with a dead pid.
    ?assertEqual({error, closed}, webrtc:send_data(A, 0, text, <<"x">>)),
    webrtc:close(B).

%% A signaling function that never returns: the candidates queue for
%% its helper, at most 64, and close still ends it.
slow_signaling_bounded(_Config) ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, signaling => fun(_, _) -> timer:sleep(infinity) end}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"s">>, #{}),
    ?S:connect(A, B),
    [T | _] = [T || {_, T} <- rows(A)],
    [Helper] = linked(A),
    %% B restarts ICE; A answers through its helper, which blocks in the
    %% function. Candidates from the transport keep coming.
    ok = webrtc:restart_ice(B),
    {ok, Offer} = webrtc:create_offer(B, #{}),
    ok = webrtc:set_local_description(B, offer, Offer),
    ok = webrtc:set_remote_description(A, offer, Offer),
    ?assert(wait_until(fun() -> process_info(Helper, current_function) =:= {current_function, {timer, sleep, 1}} end, 2000)),
    Cand = <<"candidate:1 1 udp 2130706431 127.0.0.1 9 typ host">>,
    [A ! {webrtc_transport, T, {local_candidate, Cand}} || _ <- lists:seq(1, 500)],
    timer:sleep(300),
    {message_queue_len, N} = process_info(Helper, message_queue_len),
    ct:log("helper queue ~b, at ~p", [N, process_info(Helper, current_function)]),
    ?assert(N =< 64),
    ok = webrtc:close(A),
    ?assertEqual(ok, wait_dead([Helper], 6000)),
    webrtc:close(B).

%% A TURN server over TCP that never answers: its connect worker is
%% linked to the transport and ends with it, on close and on kill.
%% The TURN server is a local socket that accepts the TCP connection and
%% never answers the TLS handshake, so the worker is still running when
%% the transport ends, wherever the test runs.
connect_workers_end(_Config) ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}, {backlog, 16}]),
    {ok, Port} = inet:port(L),
    Url = iolist_to_binary(["turns:127.0.0.1:", integer_to_list(Port), "?transport=tcp"]),
    Turn = [#{urls => [Url], username => <<"u">>, credential => <<"p">>}],
    lists:foreach(
        fun(How) ->
            {ok, A} = webrtc:new_peer_connection(#{loopback => true, ice_servers => Turn}),
            ok = webrtc:create_data_channel(A, <<"w">>, #{}),
            {ok, Offer} = webrtc:create_offer(A, #{}),
            ok = webrtc:set_local_description(A, offer, Offer),
            [{_, T}] = ets:lookup(webrtc_transports, A),
            ?assert(wait_until(fun() -> length(linked(T)) >= 1 end, 2000)),
            Workers = linked(T),
            ct:log("~p: workers ~p", [How, Workers]),
            case How of
                close -> ok = webrtc:close(A);
                kill -> exit(T, kill)
            end,
            ?assertEqual(ok, wait_dead(Workers ++ [T], 6000)),
            try webrtc:close(A) catch exit:_ -> ok end
        end,
        [close, kill]
    ),
    gen_tcp:close(L).

%%====================================================================
%% Back to the baseline
%%====================================================================

%% Processes, ports, registry rows and ticket table entries of the node.
baseline() ->
    #{processes => erlang:system_info(process_count), ports => erlang:system_info(port_count),
      transports => ets:info(webrtc_transports, size), memory => erlang:memory(total)}.

%% Wait until the counts come back to `Base' (a few processes of slack
%% for the test framework), and report what is left.
back_to(Base, Ms) ->
    Ok = fun() ->
             Now = baseline(),
             maps:get(processes, Now) =< maps:get(processes, Base) + 5 andalso
                 maps:get(ports, Now) =< maps:get(ports, Base) andalso
                 maps:get(transports, Now) =< maps:get(transports, Base)
         end,
    case wait_until(Ok, Ms) of
        true -> ok;
        false -> {left, baseline(), Base}
    end.

pair() ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"p">>, #{}),
    ?S:connect(A, B),
    {A, B}.

%% The owner exits: its peer connections end, and all they started.
owner_death(_Config) ->
    Base = baseline(),
    Self = self(),
    Owner = spawn(fun() -> {A, B} = pair(), Self ! {pair, A, B}, receive stop -> ok end end),
    {A, B} = receive {pair, PA, PB} -> {PA, PB} end,
    Owned = owned(A) ++ owned(B),
    Owner ! stop,
    ?assertEqual(ok, wait_dead([A, B | Owned], 6000)),
    ?assertEqual(ok, back_to(Base, 6000)).

%% A transport killed: the peer connection reports failed and ends with
%% its subtree.
killed_transport(_Config) ->
    Base = baseline(),
    {A, B} = pair(),
    [{_, T}] = ets:lookup(webrtc_transports, A),
    exit(T, kill),
    {ok, _} = ?S:wait(A, fun({connection_state, failed}) -> true; (_) -> false end, 5000),
    ?assertEqual(ok, wait_dead([A], 6000)),
    webrtc:close(B),
    ?assertEqual(ok, back_to(Base, 6000)).

%% The application stops with connections open: nothing of them is
%% left, and it starts again.
application_restart(_Config) ->
    Base = baseline(),
    Pairs = [pair() || _ <- lists:seq(1, 5)],
    Pcs = lists:append([[A, B] || {A, B} <- Pairs]),
    ok = application:stop(webrtc),
    ?assertEqual(ok, wait_dead(Pcs, 6000)),
    {ok, _} = application:ensure_all_started(webrtc),
    {A, B} = pair(),
    webrtc:close(A),
    webrtc:close(B),
    ?assertEqual(ok, back_to(Base#{transports => 0}, 6000)).

%% A codec plugin stuck in decode/2 blocks its transport; close still
%% ends everything (the transport is killed after 5 s).
stuck_codec_plugin(_Config) ->
    Base = baseline(),
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, frames => true, codec_plugins => #{audio => {?MODULE, stuck}}}),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    ?S:connect(A, B),
    [ok = webrtc:send_rtp(A, <<"0">>, <<16#F8, 16#FF, 16#FE>>, #{timestamp => N * 960, marker => true}) || N <- lists:seq(1, 10)],
    timer:sleep(500),
    {Us, ok} = timer:tc(fun() -> webrtc:close(B) end),
    ct:log("close took ~b ms", [Us div 1000]),
    ?assert(Us < 8000000),
    webrtc:close(A),
    ?assertEqual(ok, back_to(Base, 8000)).

%% close/1 ends the codec plugins of both sides: the encoder and the
%% decoder each get terminate/1 once.
plugins_end_with_close(_Config) ->
    Base = baseline(),
    Me = self(),
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, frames => true,
                                           codec_plugins => #{video => {webrtc_test_codec, #{notify => Me}}}}),
    {ok, _} = webrtc:add_transceiver(A, video, #{frames => true, codec_plugin => {webrtc_test_codec, #{notify => Me}}}),
    ?S:connect(A, B),
    [#{data := D} | _] = webrtc_test_frames:frames(vp8),
    [ok = webrtc:send_media(A, <<"0">>, {frame, D, I =:= 0, I * 3000}) || I <- lists:seq(0, 4)],
    {ok, _} = ?S:wait(B, fun({decoded, <<"0">>, _}) -> true; (_) -> false end, 5000),
    webrtc:close(A),
    webrtc:close(B),
    Ends = fun Loop(N) -> receive {codec_terminate, _} -> Loop(N + 1) after 1000 -> N end end,
    ?assertEqual(2, Ends(0)),
    ?assertEqual(ok, back_to(Base, 8000)).

%% A codec plugin whose decode never returns.
init(_Kind, _Codec, stuck) -> {ok, stuck}.
decode(_Frame, _St) -> timer:sleep(infinity).
encode(_Raw, St) -> {ok, [], #{}, St}.
info(_) -> #{implementation => <<"stuck">>}.

%% Connections abandoned half way, before ICE connects.
abandoned_connections(_Config) ->
    Base = baseline(),
    lists:foreach(
        fun(_) ->
            {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
            {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
            ok = webrtc:create_data_channel(A, <<"a">>, #{}),
            {ok, Offer} = webrtc:create_offer(A, #{}),
            ok = webrtc:set_local_description(A, offer, Offer),
            ok = webrtc:set_remote_description(B, offer, Offer),
            {ok, Answer} = webrtc:create_answer(B, #{}),
            ok = webrtc:set_local_description(B, answer, Answer),
            ok = webrtc:close(B),
            ok = webrtc:set_remote_description(A, answer, Answer),
            ok = webrtc:close(A)
        end,
        lists:seq(1, 200)
    ),
    ?S:flush(),
    ?assertEqual(ok, back_to(Base, 10000)).

%% Many short connected pairs (LIFECYCLE_PAIRS, 200 by default): the
%% node comes back to where it was, memory within 20 MB.
short_lived_pairs(_Config) ->
    N = list_to_integer(os:getenv("LIFECYCLE_PAIRS", "200")),
    Base = baseline(),
    lists:foreach(fun(_) -> {A, B} = pair(), webrtc:close(A), webrtc:close(B), ?S:flush() end, lists:seq(1, N)),
    ?assertEqual(ok, back_to(Base, 10000)),
    erlang:garbage_collect(),
    Grown = erlang:memory(total) - maps:get(memory, Base),
    ct:log("~b pairs, memory ~+b bytes", [N, Grown]),
    ?assert(Grown < 20 * 1024 * 1024).

%% 40 processes connecting pairs at once, first on a single scheduler,
%% then on all of them: every pair connects and closes, nothing waits on
%% anything else, the node comes back to its baseline.
scheduler_stress(_Config) ->
    Base = baseline(),
    Online = erlang:system_info(schedulers_online),
    try
        lists:foreach(
            fun(Schedulers) ->
                _ = erlang:system_flag(schedulers_online, Schedulers),
                Self = self(),
                Workers = [spawn_link(fun() ->
                                          [begin {A, B} = pair(), webrtc:close(A), webrtc:close(B) end || _ <- lists:seq(1, 3)],
                                          ?S:flush(),
                                          Self ! {done, self()}
                                      end) || _ <- lists:seq(1, 40)],
                [receive {done, W} -> ok after 120000 -> ct:fail({stuck, W, Schedulers}) end || W <- Workers]
            end,
            [1, Online]
        )
    after
        erlang:system_flag(schedulers_online, Online)
    end,
    ?assertEqual(ok, back_to(Base, 15000)).

%% The API from another node: data, statistics, and an owner there whose
%% node goes away closes the peer connection.
other_node(_Config) ->
    %% Long names on the loopback address: a short host name may not
    %% resolve on the test host.
    Started = node() =:= nonode@nohost,
    %% Distribution needs epmd, which a CI runner does not start.
    _ = Started andalso epmd(),
    case not Started orelse net_kernel:start('lifecycle_main@127.0.0.1', #{name_domain => longnames}) of
        {error, R} ->
            {skip, {no_distribution, R}};
        _ when Started ->
            try other_node1() after net_kernel:stop() end;
        _ ->
            other_node1()
    end.

epmd() ->
    case os:find_executable("epmd") of
        false -> false;
        Epmd -> os:cmd(Epmd ++ " -daemon"), true
    end.

other_node1() ->
    begin
            Paths = lists:append([["-pa", P] || P <- code:get_path()]),
            {ok, Peer, Node} = peer:start_link(#{name => peer:random_name(), host => "127.0.0.1", longnames => true,
                                                 args => Paths, wait_boot => 30000}),
            try
                {A, B} = pair(),
                {ok, {datachannel_open, Id, _, _, _}} =
                    ?S:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 5000),
                ok = erpc:call(Node, webrtc, send_data, [A, Id, text, <<"from another node">>]),
                {ok, _} = ?S:wait(B, fun({channel_message, _, text, <<"from another node">>}) -> true; (_) -> false end, 5000),
                #{} = erpc:call(Node, webrtc, get_stats, [A]),
                Owner = erpc:call(Node, erlang, spawn, [timer, sleep, [infinity]]),
                ok = webrtc:controlling_process(A, Owner),
                Owned = owned(A),
                peer:stop(Peer),
                ?assertEqual(ok, wait_dead([A | Owned], 6000)),
                webrtc:close(B)
            catch
                C:E:St ->
                    try peer:stop(Peer) catch _:_ -> ok end,
                    erlang:raise(C, E, St)
            end
    end.
