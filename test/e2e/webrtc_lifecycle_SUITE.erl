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
    connect_workers_end/1
]).

-define(S, webrtc_test_signal).

all() ->
    [close_ends_helpers, killed_peer_rows_removed, slow_signaling_bounded, connect_workers_end].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Config.

end_per_suite(_) -> ok.

init_per_testcase(_, Config) -> ?S:flush(), Config.
end_per_testcase(_, _) -> ?S:flush(), ok.

%% The processes linked to a peer connection: its transports and its
%% signaling helper.
linked(Pc) ->
    {links, L} = process_info(Pc, links),
    Sups = [whereis(webrtc_pc_sup)],
    [P || P <- L, is_pid(P), not lists:member(P, Sups)].

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
    Linked = linked(A),
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
    Linked = linked(A),
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
    [Helper] = linked(A) -- [T],
    %% The restart offer blocks the helper in the function; candidates
    %% from the transport keep coming.
    ok = webrtc:restart_ice(A),
    Cand = <<"candidate:1 1 udp 2130706431 127.0.0.1 9 typ host">>,
    [A ! {webrtc_transport, T, {local_candidate, Cand}} || _ <- lists:seq(1, 500)],
    timer:sleep(300),
    {message_queue_len, N} = process_info(Helper, message_queue_len),
    ct:log("helper queue ~b", [N]),
    ?assert(N =< 64),
    ok = webrtc:close(A),
    ?assertEqual(ok, wait_dead([Helper], 6000)),
    webrtc:close(B).

%% A TURN server over TCP that never answers: its connect worker is
%% linked to the transport and ends with it, on close and on kill.
connect_workers_end(_Config) ->
    Turn = [#{urls => [<<"turn:10.255.255.1:3478?transport=tcp">>], username => <<"u">>, credential => <<"p">>}],
    lists:foreach(
        fun(How) ->
            {ok, A} = webrtc:new_peer_connection(#{loopback => true, ice_servers => Turn}),
            ok = webrtc:create_data_channel(A, <<"w">>, #{}),
            {ok, Offer} = webrtc:create_offer(A, #{}),
            ok = webrtc:set_local_description(A, offer, Offer),
            [{_, T}] = ets:lookup(webrtc_transports, A),
            ?assert(wait_until(fun() -> length(linked(T)) >= 2 end, 2000)),
            Workers = linked(T) -- [A],
            ct:log("~p: workers ~p", [How, Workers]),
            case How of
                close -> ok = webrtc:close(A);
                kill -> exit(T, kill)
            end,
            ?assertEqual(ok, wait_dead(Workers ++ [T], 6000)),
            try webrtc:close(A) catch exit:_ -> ok end
        end,
        [close, kill]
    ).
