%% Security and robustness of a live peer connection: traffic from
%% addresses ICE did not validate, replayed datagrams, floods, teardown
%% during traffic and resource cleanup.
-module(webrtc_security_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([
    no_secrets_in_crash_logs/1,
    spoofed_traffic_dropped/1,
    unauthenticated_stun_flood/1,
    garbage_flood/1,
    replayed_datagrams_dropped/1,
    teardown_during_traffic/1,
    resources_released_on_close/1,
    owner_exit_closes/1,
    stuck_transport_killed_on_close/1,
    turn_allocation_deleted_on_close/1,
    nothing_sent_after_peer_close/1,
    no_state_in_caller/1
]).

-define(S, webrtc_test_signal).

all() ->
    [
        spoofed_traffic_dropped,
        unauthenticated_stun_flood,
        garbage_flood,
        replayed_datagrams_dropped,
        teardown_during_traffic,
        resources_released_on_close,
        owner_exit_closes,
        stuck_transport_killed_on_close,
        turn_allocation_deleted_on_close,
        nothing_sent_after_peer_close,
        no_state_in_caller,
        no_secrets_in_crash_logs
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Config.

end_per_suite(_) -> ok.

init_per_testcase(_, Config) -> ?S:flush(), Config.
end_per_testcase(_, _) -> ?S:flush(), ok.

connected_pair(Opts) ->
    {ok, A} = webrtc:new_peer_connection(Opts#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    ok = webrtc:create_data_channel(A, <<"s">>, #{}),
    ?S:connect(A, B),
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 10000),
    {ok, _} = ?S:wait(B, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 10000),
    {A, B, Id}.

address(Pc) ->
    #{transport := #{addresses := [Addr | _]}} = webrtc:get_stats(Pc),
    Addr.

rogue() ->
    {ok, S} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    S.

still_works(A, B, Id) ->
    Msg = crypto:strong_rand_bytes(16),
    ok = webrtc:send_data(A, Id, binary, Msg),
    {ok, _} = ?S:wait(B, fun({channel_message, _, binary, D}) -> D =:= Msg; (_) -> false end, 10000),
    ok = webrtc:send_rtp(A, <<"0">>, Msg, #{timestamp => 1}),
    {ok, _} = ?S:wait(B, fun({rtp, _, #rtp{payload = P}}) -> P =:= Msg; (_) -> false end, 10000),
    ok.

no_rtp_events(B) ->
    receive
        {webrtc, B, {rtp, _, _} = E} -> ct:fail({unexpected, E});
        {webrtc, B, {channel_message, _, _, _} = E} -> ct:fail({unexpected, E})
    after 500 -> ok
    end.

%% RFC 8445 §12.2, RFC 8826 §4.2: DTLS and SRTP from an address that is
%% not a validated candidate pair are dropped before any parsing.
spoofed_traffic_dropped(_Config) ->
    {A, B, Id} = connected_pair(#{}),
    {IP, Port} = address(B),
    R = rogue(),
    [ok = gen_udp:send(R, IP, Port, <<128, 111, N:16, 0:64, (crypto:strong_rand_bytes(40))/binary>>)
     || N <- lists:seq(1, 500)],
    [ok = gen_udp:send(R, IP, Port, <<23, 16#FEFD:16, 0:16, N:48, 40:16, (crypto:strong_rand_bytes(40))/binary>>)
     || N <- lists:seq(1, 500)],
    no_rtp_events(B),
    #{transport := #{media := #{counters := C}}} = webrtc:get_stats(B),
    ?assertEqual(0, maps:get(srtp_rejected, C, 0)),
    still_works(A, B, Id),
    gen_udp:close(R),
    webrtc:close(A),
    webrtc:close(B).

%% Binding requests with wrong credentials are answered with errors or
%% dropped; they create no state and do not disturb the session.
unauthenticated_stun_flood(_Config) ->
    {A, B, Id} = connected_pair(#{}),
    {IP, Port} = address(B),
    R = rogue(),
    T = webrtc_transport_of(B),
    Before = proc_memory(T),
    lists:foreach(
        fun(_) ->
            Req = webrtc_stun:request(binding, [{username, <<"nobody:here">>}, {priority, 1}, {ice_controlling, 1}]),
            Bin = webrtc_stun:encode(Req, #{integrity => {sha1, <<"wrong-password-wrong!!">>}, fingerprint => true}),
            ok = gen_udp:send(R, IP, Port, Bin)
        end,
        lists:seq(1, 5000)
    ),
    timer:sleep(500),
    After = proc_memory(T),
    ct:log("transport memory before ~p after ~p", [Before, After]),
    ?assert(After < Before + 2000000),
    still_works(A, B, Id),
    gen_udp:close(R),
    webrtc:close(A),
    webrtc:close(B).

garbage_flood(_Config) ->
    {A, B, Id} = connected_pair(#{}),
    {IP, Port} = address(B),
    R = rogue(),
    rand:seed(exsss, {11, 12, 13}),
    [ok = gen_udp:send(R, IP, Port, rand:bytes(rand:uniform(1400))) || _ <- lists:seq(1, 10000)],
    timer:sleep(500),
    ?assert(is_process_alive(B)),
    still_works(A, B, Id),
    gen_udp:close(R),
    webrtc:close(A),
    webrtc:close(B).

%% Every datagram A sends is replayed 300 ms later. DTLS (RFC 6347
%% §4.1.2.6), SRTP (RFC 3711 §3.3.2) and SCTP TSN tracking must make
%% each message and packet arrive exactly once.
replayed_datagrams_dropped(_Config) ->
    Replay = {fun(_Dest, Bin, S) -> {[{0, Bin}, {300, Bin}], S} end, undefined},
    {A, B, Id} = connected_pair(#{outbound_filter => Replay}),
    [ok = webrtc:send_data(A, Id, binary, <<I:32>>) || I <- lists:seq(1, 50)],
    [ok = webrtc:send_rtp(A, <<"0">>, <<I:32>>, #{timestamp => I}) || I <- lists:seq(1, 50)],
    timer:sleep(1500),
    {Msgs, Rtp} = drain(B, [], []),
    ?assertEqual([<<I:32>> || I <- lists:seq(1, 50)], lists:reverse(Msgs)),
    ?assertEqual(50, length(Rtp)),
    ?assertEqual(50, length(lists:usort(Rtp))),
    #{transport := #{media := #{counters := C}}} = webrtc:get_stats(B),
    ct:log("receiver counters: ~p", [C]),
    ?assert(maps:get(srtp_rejected, C, 0) >= 50),
    webrtc:close(A),
    webrtc:close(B).

drain(B, Msgs, Rtp) ->
    receive
        {webrtc, B, {channel_message, _, binary, D}} -> drain(B, [D | Msgs], Rtp);
        {webrtc, B, {rtp, _, #rtp{payload = P}}} -> drain(B, Msgs, [P | Rtp])
    after 0 ->
        {Msgs, Rtp}
    end.

teardown_during_traffic(_Config) ->
    {A, B, Id} = connected_pair(#{}),
    Sender = spawn(fun() -> flood(A, Id, 0) end),
    timer:sleep(300),
    ok = webrtc:close(B),
    timer:sleep(300),
    ok = webrtc:close(A),
    exit(Sender, kill),
    ?assertNot(is_process_alive(A)),
    ?assertNot(is_process_alive(B)).

flood(A, Id, N) ->
    _ = webrtc:send_data(A, Id, binary, <<N:32, 0:8000>>),
    _ = webrtc:send_rtp(A, <<"0">>, <<N:32>>, #{timestamp => N}),
    flood(A, Id, N + 1).

resources_released_on_close(_Config) ->
    Ports0 = length(erlang:ports()),
    Procs0 = length(processes()),
    Pairs = [connected_pair(#{}) || _ <- lists:seq(1, 5)],
    [begin webrtc:close(A), webrtc:close(B) end || {A, B, _} <- Pairs],
    timer:sleep(500),
    %% Ports of earlier cases may still be closing: a leak only adds.
    ?assert(length(erlang:ports()) =< Ports0),
    ?assert(length(processes()) =< Procs0 + 2),
    ?assertEqual([], supervisor:which_children(webrtc_pc_sup)).

owner_exit_closes(_Config) ->
    Self = self(),
    Owner = spawn(fun() ->
        {ok, Pc} = webrtc:new_peer_connection(#{loopback => true}),
        Self ! {pc, Pc},
        receive stop -> ok end
    end),
    Pc = receive {pc, P} -> P end,
    Ref = monitor(process, Pc),
    Owner ! stop,
    receive {'DOWN', Ref, process, Pc, _} -> ok after 5000 -> ct:fail(pc_not_closed) end.

webrtc_transport_of(Pc) ->
    {ok, T} = gen_server:call(Pc, transport_pid),
    T.

proc_memory(P) ->
    {memory, M} = process_info(P, memory),
    M.

%% A transport stuck in a callback (here a blocking outbound filter)
%% cannot outlive its peer connection: close kills it and its sockets are
%% released.
stuck_transport_killed_on_close(_Config) ->
    Block = atomics:new(1, []),
    Filter = {fun(_Dest, Bin, S) ->
                  case atomics:get(Block, 1) of
                      1 -> receive never -> ok end;
                      0 -> ok
                  end,
                  {[{0, Bin}], S}
              end, undefined},
    {A, B, Id} = connected_pair(#{outbound_filter => Filter}),
    T = webrtc_transport_of(A),
    {links, Links} = process_info(T, links),
    Ports = [P || P <- Links, is_port(P)],
    ?assertNotEqual([], Ports),
    Ref = monitor(process, T),
    atomics:put(Block, 1, 1),
    %% The next datagram A sends blocks its transport forever.
    _ = spawn(fun() -> webrtc:send_data(A, Id, text, <<"x">>) end),
    timer:sleep(300),
    {Time, ok} = timer:tc(fun() -> webrtc:close(A) end),
    ct:log("close took ~p ms", [Time div 1000]),
    receive {'DOWN', Ref, process, T, _} -> ok after 1000 -> ct:fail(transport_survived) end,
    webrtc:close(B),
    %% The sockets of the killed transport are released.
    ?assertEqual([], [P || P <- Ports, erlang:port_info(P) =/= undefined]).

%% RFC 8656 §8: closing deletes the TURN allocation (Refresh with a zero
%% lifetime) instead of leaving it until it expires.
turn_allocation_deleted_on_close(_Config) ->
    {Turn, Addr} = webrtc_test_turn_udp:start(#{users => #{<<"u">> => <<"p">>}}),
    {ok, A} = webrtc:new_peer_connection(#{
        loopback => true,
        turn_servers => [#{address => Addr, username => <<"u">>, password => <<"p">>}]
    }),
    ok = webrtc:create_data_channel(A, <<"t">>, #{}),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    {ok, _} = ?S:wait(A, fun({ice_candidate, C, _}) when is_binary(C) ->
                                 binary:match(C, <<"typ relay">>) =/= nomatch;
                            (_) -> false end, 5000),
    ?assertEqual(1, webrtc_test_turn_udp:allocations(Turn)),
    ok = webrtc:close(A),
    timer:sleep(300),
    ?assertEqual(0, webrtc_test_turn_udp:allocations(Turn)),
    webrtc_test_turn_udp:stop(Turn).

%% After the peer's close_notify the transport is finished: media and
%% data calls fail and no datagram leaves (no SRTP on old keys, no
%% consent checks, no RTCP).
nothing_sent_after_peer_close(_Config) ->
    Count = atomics:new(1, []),
    Counter = {fun(_Dest, Bin, S) -> atomics:add(Count, 1, 1), {[{0, Bin}], S} end, undefined},
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, outbound_filter => Counter}),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    ok = webrtc:create_data_channel(A, <<"c">>, #{}),
    ?S:connect(A, B),
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(B, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 10000),
    ok = webrtc:close(A),
    {ok, _} = ?S:wait(B, fun({connection_state, closed}) -> true; (_) -> false end, 5000),
    timer:sleep(200),
    After = atomics:get(Count, 1),
    ?assertEqual({error, closed}, webrtc:send_rtp(B, <<"0">>, <<"x">>, #{timestamp => 1})),
    ?assertEqual({error, closed}, webrtc:send_data(B, Id, text, <<"x">>)),
    timer:sleep(6000),
    ?assertEqual(After, atomics:get(Count, 1)),
    webrtc:close(B).

%% Using many peer connections from one process leaves nothing in its
%% dictionary, and closed connections leave no transport rows behind.
no_state_in_caller(_Config) ->
    Dict0 = get(),
    Pcs = [
        begin
            {ok, Pc} = webrtc:new_peer_connection(#{loopback => true}),
            {ok, _} = webrtc:add_transceiver(Pc, audio, #{}),
            {ok, Offer} = webrtc:create_offer(Pc, #{}),
            ok = webrtc:set_local_description(Pc, offer, Offer),
            [{Pc, _}] = ets:lookup(webrtc_transports, Pc),
            %% Not connected: the transport answers, nothing is cached.
            {error, _} = webrtc:send_rtp(Pc, <<"0">>, <<"x">>, #{timestamp => 1}),
            ok = webrtc:close(Pc),
            {error, closed} = webrtc:send_rtp(Pc, <<"0">>, <<"x">>, #{timestamp => 1}),
            Pc
        end
     || _ <- lists:seq(1, 100)
    ],
    ?assertEqual(Dict0, get()),
    ?assertEqual([], [P || P <- Pcs, ets:lookup(webrtc_transports, P) =/= []]).

%% A crashing peer connection or transport, and sys:get_status/1, show
%% neither the DTLS private key nor the ICE and TURN credentials.
no_secrets_in_crash_logs(_Config) ->
    Turn = <<"turn-credential-0d9c2e">>,
    Cert = webrtc_dtls_cert:generate(),
    %% One pair whose transport crashes, one whose peer connection does:
    %% neither call races the other process's end.
    {A1, B1, T1, Pwds1} = secret_pair(Cert, Turn),
    {A2, B2, T2, Pwds2} = secret_pair(Cert, Turn),
    #{key := Key} = Cert,
    KeyDer = public_key:der_encode('ECPrivateKey', Key),
    Secrets = Pwds1 ++ Pwds2 ++ [Turn, <<"ECPrivateKey">>, base64:encode(KeyDer),
                                 iolist_to_binary(io_lib:format("~w", [binary:part(KeyDer, 7, 16)]))],
    Status = iolist_to_binary(io_lib:format("~p~n~p", [sys:get_status(A1), sys:get_status(T1)])),
    ok = webrtc_test_log:capture(secrets),
    try
        process_flag(trap_exit, true),
        %% An unknown call: function_clause with the state as argument.
        Crash = fun(P, M) -> try gen_server:call(P, M) catch exit:_ -> ok end end,
        Crash(T1, {bogus, hd(Pwds1)}),
        Crash(A2, {bogus, hd(Pwds2)}),
        Logs = collect_logs(<<>>, 3000),
        ct:log("~s", [Logs]),
        ?assertNotEqual(<<>>, Logs),
        [?assertEqual(nomatch, binary:match(Logs, S), S) || S <- Secrets],
        [?assertEqual(nomatch, binary:match(Status, S), S) || S <- Secrets],
        _ = T2
    after
        webrtc_test_log:release(secrets),
        [webrtc:close(P) || P <- [A1, B1, A2, B2]]
    end.

%% A connected pair: A with the certificate and a TURN credential; its
%% transport and local and remote ICE passwords.
secret_pair(Cert, Turn) ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, certificate => Cert,
                                           ice_servers => [#{urls => [<<"turn:127.0.0.1:9?transport=udp">>],
                                                             username => <<"u">>, credential => Turn}]}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"x">>, #{}),
    ?S:connect(A, B),
    {match, [LocalPwd]} = re:run(webrtc:local_description(A), <<"a=ice-pwd:(\\S+)">>, [{capture, all_but_first, binary}]),
    {match, [RemotePwd]} = re:run(webrtc:remote_description(A), <<"a=ice-pwd:(\\S+)">>, [{capture, all_but_first, binary}]),
    [{A, T}] = ets:lookup(webrtc_transports, A),
    {A, B, T, [LocalPwd, RemotePwd]}.

collect_logs(Acc, Wait) ->
    receive
        {log, L} -> collect_logs(<<Acc/binary, L/binary>>, 500)
    after Wait ->
        Acc
    end.
