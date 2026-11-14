%% Multi-agent ICE scenarios over the in-memory network
%% (webrtc_ice_net): host, server-reflexive, peer-reflexive and relayed
%% paths through simulated NATs, lite agents, role conflicts, trickle,
%% loss, authentication failures, restart, consent and network changes.
-module(webrtc_ice_net_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_ice.hrl").

-define(NET, webrtc_ice_net).
-define(AG, webrtc_ice_agent).

-define(A4, {10, 0, 0, 1}).
-define(B4, {10, 0, 1, 1}).
-define(A6, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}).
-define(B6, {16#2001, 16#db8, 0, 1, 0, 0, 0, 1}).
-define(STUN, {{198, 51, 100, 1}, 3478}).
-define(TURN, {{198, 51, 100, 2}, 3478}).
-define(NAT_A, {203, 0, 113, 1}).
-define(NAT_B, {203, 0, 113, 2}).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

base_opts(Seed) ->
    #{seed => Seed}.

%% Two agents `a' and `b' with the given sockets and NATs, linked with
%% trickle signaling, both gathering.
pair_net(NetOpts, {OptsA, SocksA, NatA}, {OptsB, SocksB, NatB}) ->
    N0 = ?NET:new(NetOpts),
    N1 = ?NET:add_stun_server(N0, ?STUN),
    N2 = ?NET:add_turn_server(N1, ?TURN, maps:get(turn, NetOpts, #{})),
    N3 = add_nats(N2, maps:get(nats, NetOpts, [])),
    N4 = ?NET:add_agent(N3, a, maps:merge(base_opts({1, 2, 3}), OptsA), SocksA, NatA),
    N5 = ?NET:add_agent(N4, b, maps:merge(base_opts({4, 5, 6}), OptsB), SocksB, NatB),
    N6 = ?NET:link(N5, {a, b}, maps:get(auto, NetOpts, true)),
    ?NET:gather(?NET:gather(N6, a), b).

add_nats(N, Nats) ->
    lists:foldl(fun({Name, Type, IP}, Acc) -> ?NET:add_nat(Acc, Name, Type, IP) end, N, Nats).

host_pair(OptsA, OptsB) ->
    pair_net(#{}, {OptsA#{role => controlling}, [{sa, {?A4, 5000}}], none},
             {OptsB#{role => controlled}, [{sb, {?B4, 6000}}], none}).

state(N, Name) -> ?AG:connection_state(?NET:agent(N, Name)).

both(St) -> fun(N) -> state(N, a) =:= St andalso state(N, b) =:= St end.

completed(N) -> (both(completed))(N).

run_ok(N, Pred, Until) ->
    {Res, N1} = ?NET:run_until(N, Pred, ?NET:now(N) + Until),
    ?assertEqual(ok, Res),
    N1.

selected(N, Name) ->
    {L, R} = ?AG:selected_pair(?NET:agent(N, Name)),
    {L#ice_cand.type, R#ice_cand.type, webrtc_ice_candidate:transport_address(L),
     webrtc_ice_candidate:transport_address(R)}.

events(N, Name, Tag) ->
    [E || {_, E} <- ?NET:events(N, Name), element(1, E) =:= Tag].

state_events(N, Name) ->
    [St || {connection_state, St} <- events(N, Name, connection_state)].

%% Selected pairs of both sides agree when there is no NAT.
assert_symmetric(N) ->
    {_, _, AL, AR} = selected(N, a),
    {_, _, BL, BR} = selected(N, b),
    ?assertEqual({AL, AR}, {BR, BL}).

exchange(N0) ->
    N1 = ?NET:send_data(N0, a, <<128, "from a">>),
    N2 = ?NET:send_data(N1, b, <<128, "from b">>),
    {_, N3} = ?NET:run(N2, ?NET:now(N2) + 1000),
    N3.

received(N, Name) ->
    [D || {_, _, D} <- ?NET:app_data(N, Name)].

%%--------------------------------------------------------------------
%% Host to host
%%--------------------------------------------------------------------

host_host_test() ->
    N = run_ok(host_pair(#{}, #{}), fun completed/1, 10000),
    assert_symmetric(N),
    ?assertMatch({host, host, {?A4, 5000}, {?B4, 6000}}, selected(N, a)),
    ?assertEqual([checking, connected, completed], state_events(N, a)),
    ?assertEqual([checking, connected, completed], state_events(N, b)),
    ?assertEqual([{gathering_state, gathering}, {gathering_state, complete}],
                 events(N, a, gathering_state)),
    N1 = exchange(N),
    ?assertEqual([<<128, "from b">>], received(N1, a)),
    ?assertEqual([<<128, "from a">>], received(N1, b)),
    ?assertEqual(controlling, ?AG:role(?NET:agent(N1, a))),
    ?assertEqual(controlled, ?AG:role(?NET:agent(N1, b))).

host_host_stats_test() ->
    N = run_ok(host_pair(#{}, #{}), fun completed/1, 10000),
    #{pairs := Pairs, state := completed} = ?AG:stats(?NET:agent(N, a)),
    [Sel] = [P || #{selected := true} = P <- Pairs],
    ?assertMatch(#{valid := true, nominated := true, state := succeeded}, Sel),
    ?assert(maps:get(requests_sent, Sel) >= 2),
    ?assert(maps:get(responses_received, Sel) >= 2),
    ?assertEqual(20, maps:get(rtt, Sel)).

%%--------------------------------------------------------------------
%% Lite
%%--------------------------------------------------------------------

full_lite_test() ->
    N0 = pair_net(#{}, {#{remote_lite => true}, [{sa, {?A4, 5000}}], none},
                  {#{lite => true}, [{sb, {?B4, 6000}}], none}),
    N = run_ok(N0, fun completed/1, 10000),
    assert_symmetric(N),
    Lite = ?NET:agent(N, b),
    ?assertEqual(controlled, ?AG:role(Lite)),
    ?assertEqual(controlling, ?AG:role(?NET:agent(N, a))),
    #{counters := C, pairs := Pairs} = ?AG:stats(Lite),
    %% A lite agent never sends checks.
    ?assertEqual(0, maps:get(checks_sent, C, 0)),
    ?assertEqual(0, lists:sum([maps:get(requests_sent, P) || P <- Pairs])),
    %% Lite agents gather host candidates only.
    ?assertEqual([host], lists:usort([T || #ice_cand{type = T} <- ?AG:local_candidates(Lite)])),
    N1 = exchange(N),
    ?assertEqual([<<128, "from a">>], received(N1, b)),
    ?assertEqual([<<128, "from b">>], received(N1, a)).

lite_forced_controlled_test() ->
    A = ?AG:new(#{lite => true, role => controlling}),
    ?assertEqual(controlled, ?AG:role(A)),
    ?assertEqual(controlling, ?AG:role(?AG:new(#{remote_lite => true, role => controlled}))).

%% The lite agent keeps consent from the full peer's checks; when the
%% peer goes silent consent expires on the lite side too.
lite_consent_expiry_test() ->
    N0 = pair_net(#{}, {#{remote_lite => true}, [{sa, {?A4, 5000}}], none},
                  {#{lite => true}, [{sb, {?B4, 6000}}], none}),
    N1 = run_ok(N0, fun completed/1, 10000),
    N2 = ?NET:set_filter(N1, fun(_, {IP, _}, _, _) when IP =:= ?A4 -> drop; (_, _, _, _) -> pass end),
    N3 = run_ok(N2, fun(N) -> state(N, b) =:= failed end, 40000),
    ?assertMatch([{consent_lost, _, _}], events(N3, b, consent_lost)),
    ?assertEqual({error, consent_lost}, ?AG:send(<<128>>, ?NET:now(N3), ?NET:agent(N3, b))).

%%--------------------------------------------------------------------
%% Roles
%%--------------------------------------------------------------------

both_controlling_test() ->
    roles_conflict(controlling).

both_controlled_test() ->
    roles_conflict(controlled).

roles_conflict(Role) ->
    N0 = pair_net(#{}, {#{role => Role, tiebreaker => 10}, [{sa, {?A4, 5000}}], none},
                  {#{role => Role, tiebreaker => 20}, [{sb, {?B4, 6000}}], none}),
    N = run_ok(N0, fun completed/1, 10000),
    assert_symmetric(N),
    Roles = lists:sort([?AG:role(?NET:agent(N, X)) || X <- [a, b]]),
    ?assertEqual([controlled, controlling], Roles),
    Changes = events(N, a, role_change) ++ events(N, b, role_change),
    ?assert(length(Changes) >= 1).

%%--------------------------------------------------------------------
%% Trickle
%%--------------------------------------------------------------------

%% `b' learns `a''s candidates at once, `a' gets `b''s three seconds
%% later: `a' first sees `b' as peer-reflexive from its checks, then the
%% signaled candidate replaces it.
late_candidates_test() ->
    N0 = pair_net(#{auto => false}, {#{}, [{sa, {?A4, 5000}}], none},
                  {#{role => controlled}, [{sb, {?B4, 6000}}], none}),
    Now = ?NET:now(N0),
    N1 = lists:foldl(
        fun(C, N) -> ?NET:call(N, b, fun(Ag) -> ?AG:add_remote_candidate(C, Now, Ag) end) end,
        N0,
        ?AG:local_candidates(?NET:agent(N0, a))
    ),
    N2 = run_ok(N1, fun(N) -> ?AG:remote_candidates(?NET:agent(N, a)) =/= [] end, 3000),
    [#ice_cand{type = prflx}] = ?AG:remote_candidates(?NET:agent(N2, a)),
    {_, N3} = ?NET:run(N2, Now + 3000),
    BCands = ?AG:local_candidates(?NET:agent(N3, b)),
    N4 = lists:foldl(
        fun(C, N) -> ?NET:call(N, a, fun(Ag) -> ?AG:add_remote_candidate(C, ?NET:now(N), Ag) end) end,
        N3,
        BCands
    ),
    N5 = ?NET:call(N4, a, fun(Ag) -> ?AG:end_of_candidates(?NET:now(N4), Ag) end),
    N6 = run_ok(N5, fun completed/1, 10000),
    [#ice_cand{type = host, priority = P}] = ?AG:remote_candidates(?NET:agent(N6, a)),
    ?assertEqual([P], [C#ice_cand.priority || C <- BCands]),
    assert_symmetric(N6).

candidates_after_eoc_ignored_test() ->
    A0 = ?AG:new(#{}),
    {A1, _} = ?AG:set_remote_credentials(<<"abcd">>, <<"0123456789012345678901">>, 0, A0),
    {A2, _} = ?AG:end_of_candidates(0, A1),
    {A3, _} = ?AG:add_remote_candidate(<<"candidate:1 1 udp 1 10.0.0.9 9 typ host">>, 0, A2),
    ?assertEqual([], ?AG:remote_candidates(A3)),
    ?assertEqual({error, bad_candidate}, ?AG:add_remote_candidate(<<"junk">>, 0, A0)).

old_generation_candidate_ignored_test() ->
    A0 = ?AG:new(#{}),
    {A1, _} = ?AG:set_remote_credentials(<<"abcd">>, <<"0123456789012345678901">>, 0, A0),
    {A2, _} = ?AG:add_remote_candidate(<<"candidate:1 1 udp 1 10.0.0.9 9 typ host ufrag zzzz">>, 0, A1),
    ?assertEqual([], ?AG:remote_candidates(A2)),
    {A3, _} = ?AG:add_remote_candidate(<<"candidate:1 1 udp 1 10.0.0.9 9 typ host ufrag abcd">>, 0, A2),
    ?assertMatch([_], ?AG:remote_candidates(A3)).

%%--------------------------------------------------------------------
%% NATs, STUN and TURN
%%--------------------------------------------------------------------

nat_pair(TypeA, TypeB, Extra) ->
    Turn = #{turn_servers => [#{address => ?TURN, username => <<"user">>, password => <<"pass">>}]},
    Stun = #{stun_servers => [?STUN]},
    Opts = maps:merge(maps:merge(Stun, Turn), Extra),
    pair_net(#{nats => [{na, TypeA, ?NAT_A}, {nb, TypeB, ?NAT_B}]},
             {Opts#{role => controlling}, [{sa, {?A4, 5000}}], na},
             {Opts#{role => controlled}, [{sb, {?B4, 6000}}], nb}).

types(N, Name) ->
    lists:usort([T || #ice_cand{type = T} <- ?AG:local_candidates(?NET:agent(N, Name))]).

full_cone_test() ->
    N = run_ok(nat_pair(full_cone, full_cone, #{}), fun completed/1, 20000),
    ?assertEqual([host, relay, srflx], types(N, a)),
    {_, RT, _, {RIP, _}} = selected(N, a),
    %% The best working pair goes through the NATs, not the relay.
    ?assertNotEqual(relay, RT),
    ?assertEqual(?NAT_B, RIP),
    %% Checks only leave from bases: a reflexive local candidate is
    %% replaced by its base (RFC 8445 §6.1.2.4) and only appears in valid
    %% pairs built from a mapped address.
    #{pairs := Pairs} = ?AG:stats(?NET:agent(N, a)),
    ?assertEqual([host, relay], lists:usort([T || #{requests_sent := R, local := #ice_cand{type = T}} = P0 <- Pairs, R > 0, not maps:get(valid, P0)])),
    ?assert(lists:member(srflx, [T || #{valid := true, local := #ice_cand{type = T}} <- Pairs])),
    N1 = exchange(N),
    ?assertEqual([<<128, "from a">>], received(N1, b)).

%% A TURN server out of allocations still yields a server-reflexive
%% candidate through a Binding request (RFC 8445 §5.1.1.2).
turn_quota_srflx_fallback_test() ->
    Opts = #{turn_servers => [#{address => ?TURN, username => <<"user">>, password => <<"pass">>}]},
    N0 = pair_net(#{nats => [{na, full_cone, ?NAT_A}], turn => #{max_allocations => 0}},
                  {Opts, [{sa, {?A4, 5000}}], na}, {#{role => controlled}, [{sb, {?B4, 6000}}], none}),
    N = run_ok(N0, fun(X) -> ?AG:gathering_state(?NET:agent(X, a)) =:= complete end, 5000),
    ?assertEqual([host, srflx], types(N, a)),
    ?assertMatch([{turn_error, ?TURN, {error, 486}}], events(N, a, turn_error)).

turn_allocation_lost_test() ->
    N0 = run_ok(nat_pair(full_cone, full_cone, #{}), fun completed/1, 20000),
    %% The TURN server becomes unreachable from `a': the refresh fails
    %% and the relayed candidate goes away; the direct path stays up.
    {TIP, _} = ?TURN,
    N1 = ?NET:set_filter(N0, fun(_, {IP, _}, {D, _}, _) when IP =:= ?NAT_A, D =:= TIP -> drop; (_, _, _, _) -> pass end),
    N2 = run_ok(N1, fun(N) -> events(N, a, turn_error) =/= [] end, 700000),
    ?assertMatch([{turn_error, ?TURN, {allocation_lost, _}}], events(N2, a, turn_error)),
    ?assertMatch([{local_candidate_removed, #ice_cand{type = relay}}], events(N2, a, local_candidate_removed)),
    ?assertEqual([host, srflx], types(N2, a)),
    ?assertEqual(completed, state(N2, a)).

close_deletes_allocations_test() ->
    N0 = run_ok(nat_pair(full_cone, full_cone, #{}), fun completed/1, 20000),
    TurnIP = element(1, ?TURN),
    ?assertEqual(2, map_size(webrtc_test_turn_server:allocations(?NET:server(N0, TurnIP)))),
    N1 = ?NET:call(N0, a, fun(A) -> ?AG:close(?NET:now(N0), A) end),
    {_, N2} = ?NET:run(N1, ?NET:now(N1) + 1000),
    ?assertEqual(1, map_size(webrtc_test_turn_server:allocations(?NET:server(N2, TurnIP)))),
    ?assertEqual(closed, state(N2, a)),
    ?assertEqual(infinity, ?AG:next_timeout(?NET:agent(N2, a))),
    ?assertEqual({error, closed}, ?AG:send(<<1>>, ?NET:now(N2), ?NET:agent(N2, a))).

port_restricted_test() ->
    N = run_ok(nat_pair(port_restricted, port_restricted, #{}), fun completed/1, 20000),
    {LT, RT, _, _} = selected(N, a),
    ?assertNotEqual(relay, LT),
    ?assertNotEqual(relay, RT),
    N1 = exchange(N),
    ?assertEqual([<<128, "from b">>], received(N1, a)).

restricted_test() ->
    N = run_ok(nat_pair(restricted, port_restricted, #{}), fun completed/1, 20000),
    N1 = exchange(N),
    ?assertEqual([<<128, "from a">>], received(N1, b)).

symmetric_needs_relay_test() ->
    N = run_ok(nat_pair(symmetric, symmetric, #{}), fun completed/1, 30000),
    {LA, RA, _, _} = selected(N, a),
    {LB, RB, _, _} = selected(N, b),
    ?assert(lists:member(relay, [LA, RA, LB, RB])),
    N1 = exchange(N),
    ?assertEqual([<<128, "from a">>], [D || {_, _, D} <- ?NET:app_data(N1, b)]),
    ?assertEqual([<<128, "from b">>], [D || {_, _, D} <- ?NET:app_data(N1, a)]),
    %% The relay path is bound to a TURN channel once selected.
    Log = webrtc_test_turn_server:log(?NET:server(N1, element(1, ?TURN))),
    ?assert(lists:keymember(channel_bind, 1, Log)).

symmetric_without_turn_fails_test() ->
    N0 = pair_net(#{nats => [{na, symmetric, ?NAT_A}, {nb, symmetric, ?NAT_B}]},
                  {#{stun_servers => [?STUN]}, [{sa, {?A4, 5000}}], na},
                  {#{stun_servers => [?STUN], role => controlled}, [{sb, {?B4, 6000}}], nb}),
    N = run_ok(N0, both(failed), 120000),
    %% Not before the PAC timer (RFC 8863).
    [{T, _} | _] = [E || {_, {connection_state, failed}} = E <- ?NET:events(N, a)],
    ?assert(T >= 1000 + 39500).

srflx_candidate_test() ->
    N = run_ok(nat_pair(full_cone, full_cone, #{}), fun completed/1, 20000),
    [S] = [C || #ice_cand{type = srflx} = C <- ?AG:local_candidates(?NET:agent(N, a))],
    ?assertEqual(?NAT_A, S#ice_cand.address),
    ?assertEqual({?A4, 5000}, {S#ice_cand.related_address, S#ice_cand.related_port}),
    [R] = [C || #ice_cand{type = relay} = C <- ?AG:local_candidates(?NET:agent(N, a))],
    ?assertEqual(element(1, ?TURN), R#ice_cand.address),
    ?assertEqual(?NAT_A, R#ice_cand.related_address).

%%--------------------------------------------------------------------
%% Address families
%%--------------------------------------------------------------------

ipv6_only_test() ->
    N0 = pair_net(#{}, {#{}, [{sa, {?A6, 5000}}], none}, {#{role => controlled}, [{sb, {?B6, 6000}}], none}),
    N = run_ok(N0, fun completed/1, 10000),
    ?assertMatch({host, host, {?A6, 5000}, {?B6, 6000}}, selected(N, a)).

dual_stack_test() ->
    N0 = pair_net(#{}, {#{}, [{sa4, {?A4, 5000}}, {sa6, {?A6, 5000}}], none},
                  {#{role => controlled}, [{sb4, {?B4, 6000}}, {sb6, {?B6, 6000}}], none}),
    N = run_ok(N0, fun completed/1, 10000),
    %% RFC 8421: IPv6 is preferred.
    ?assertMatch({host, host, {?A6, 5000}, {?B6, 6000}}, selected(N, a)),
    #{pairs := Pairs} = ?AG:stats(?NET:agent(N, a)),
    %% Only same-family pairs are formed.
    ?assert(lists:all(
        fun(#{local := L, remote := R}) ->
            webrtc_ice_candidate:family(L#ice_cand.address) =:= webrtc_ice_candidate:family(R#ice_cand.address)
        end,
        Pairs
    )),
    ?assertEqual(2, length(Pairs)).

family_mismatch_fails_test() ->
    N0 = pair_net(#{}, {#{}, [{sa, {?A4, 5000}}], none}, {#{role => controlled}, [{sb, {?B6, 6000}}], none}),
    N = run_ok(N0, both(failed), 60000),
    ?assert(?NET:now(N) >= 1000 + 39500).

%%--------------------------------------------------------------------
%% Loss
%%--------------------------------------------------------------------

%% 30% loss on every packet, including checks and their
%% retransmissions: every seed still completes.
lossy_checks_test() ->
    Lost = [lossy(Seed) || Seed <- lists:seq(1, 20)],
    ?assert(lists:sum(Lost) > 20).

lossy(Seed) ->
    N0 = pair_net(#{loss => 0.3, seed => Seed},
                  {#{}, [{sa, {?A4, 5000}}], none}, {#{role => controlled}, [{sb, {?B4, 6000}}], none}),
    N = run_ok(N0, fun completed/1, 40000),
    assert_symmetric(N),
    maps:get(lost, ?NET:stats(N)).

%%--------------------------------------------------------------------
%% Failure
%%--------------------------------------------------------------------

no_working_pair_fails_test() ->
    N0 = host_pair(#{}, #{}),
    N1 = ?NET:set_filter(N0, fun(_, {IP, _}, _, _) when IP =:= ?A4; IP =:= ?B4 -> drop; (_, _, _, _) -> pass end),
    {timeout, N2} = ?NET:run_until(N1, both(failed), 1000 + 39000),
    ?assertEqual(checking, state(N2, a)),
    N3 = run_ok(N2, both(failed), 10000),
    ?assertEqual([checking, failed], state_events(N3, a)),
    ?assertEqual({error, no_valid_pair}, ?AG:send(<<128>>, ?NET:now(N3), ?NET:agent(N3, a))).

%% Without end-of-candidates the agent waits for the eoc timer.
no_eoc_waits_test() ->
    N0 = pair_net(#{auto => false}, {#{eoc_timeout => 60000}, [{sa, {?A4, 5000}}], none},
                  {#{role => controlled}, [{sb, {?B4, 6000}}], none}),
    N1 = ?NET:set_filter(N0, fun(_, _, _, _) -> drop end),
    {timeout, N2} = ?NET:run_until(N1, fun(N) -> state(N, a) =:= failed end, 1000 + 59000),
    N3 = run_ok(N2, fun(N) -> state(N, a) =:= failed end, 5000),
    ?assert(?NET:now(N3) >= 61000).

%%--------------------------------------------------------------------
%% Consent freshness
%%--------------------------------------------------------------------

consent_loss_test() ->
    N0 = run_ok(host_pair(#{}, #{}), fun completed/1, 10000),
    T0 = ?NET:now(N0),
    %% Consent keeps the session up while the peer answers.
    {_, N1} = ?NET:run(N0, T0 + 60000),
    ?assertEqual(completed, state(N1, a)),
    #{counters := #{consent_sent := Sent}} = ?AG:stats(?NET:agent(N1, a)),
    %% One request every 4 to 6 seconds.
    ?assert(Sent >= 10 andalso Sent =< 15),
    %% The peer goes silent.
    T1 = ?NET:now(N1),
    N2 = ?NET:set_filter(N1, fun(_, {IP, _}, _, _) when IP =:= ?B4 -> drop; (_, _, _, _) -> pass end),
    N3 = run_ok(N2, fun(N) -> state(N, a) =:= failed end, 40000),
    [{TLost, {consent_lost, #ice_cand{}, #ice_cand{}}}] =
        [E || {_, {consent_lost, _, _}} = E <- ?NET:events(N3, a)],
    ?assert(TLost - T1 =< 30000 andalso TLost - T1 >= 24000),
    ?assertEqual([checking, connected, completed, disconnected, failed], state_events(N3, a)),
    ?assertEqual({error, consent_lost}, ?AG:send(<<128>>, ?NET:now(N3), ?NET:agent(N3, a))),
    %% No more consent requests after expiry.
    #{counters := #{consent_sent := S1}} = ?AG:stats(?NET:agent(N3, a)),
    {_, N4} = ?NET:run(N3, ?NET:now(N3) + 20000),
    ?assertMatch(#{counters := #{consent_sent := S1}}, ?AG:stats(?NET:agent(N4, a))).

consent_disabled_keepalive_test() ->
    N0 = run_ok(host_pair(#{consent => false}, #{consent => false}), fun completed/1, 10000),
    {_, N1} = ?NET:run(N0, ?NET:now(N0) + 61000),
    #{counters := C} = ?AG:stats(?NET:agent(N1, a)),
    ?assertEqual(0, maps:get(consent_sent, C, 0)),
    ?assert(maps:get(keepalives_sent, C) >= 4),
    ?assertEqual(completed, state(N1, a)).

%%--------------------------------------------------------------------
%% ICE restart
%%--------------------------------------------------------------------

resignal(N0) ->
    N1 = ?NET:link(N0, {a, b}, true),
    lists:foldl(
        fun({From, To}, N) ->
            lists:foldl(
                fun(C, Acc) -> ?NET:call(Acc, To, fun(A) -> ?AG:add_remote_candidate(C, ?NET:now(Acc), A) end) end,
                N,
                ?AG:local_candidates(?NET:agent(N, From))
            )
        end,
        N1,
        [{a, b}, {b, a}]
    ).

restart_test() ->
    N0 = run_ok(host_pair(#{}, #{}), fun completed/1, 10000),
    {_, _, AL0, AR0} = selected(N0, a),
    Old = ?AG:local_credentials(?NET:agent(N0, a)),
    Now = ?NET:now(N0),
    N1 = ?NET:call(N0, a, fun(A) -> ?AG:restart(Now, A) end),
    N2 = ?NET:call(N1, b, fun(A) -> ?AG:restart(Now, A) end),
    ?assertNotEqual(Old, ?AG:local_credentials(?NET:agent(N2, a))),
    %% Data still flows on the old pair while the new session starts.
    N3 = exchange(N2),
    ?assertEqual([<<128, "from b">>], received(N3, a)),
    N4 = resignal(N3),
    N5 = run_ok(N4, fun(N) -> length(events(N, a, selected_pair)) =:= 2 andalso completed(N) end, 10000),
    {_, _, AL1, AR1} = selected(N5, a),
    ?assertEqual({AL0, AR0}, {AL1, AR1}),
    N6 = exchange(N5),
    ?assertEqual([<<128, "from b">>, <<128, "from b">>], received(N6, a)),
    {_, N7} = ?NET:run(N6, ?NET:now(N6) + 40000),
    ?assertEqual(completed, state(N7, a)),
    ?assertEqual(completed, state(N7, b)).

restart_requires_new_credentials_test() ->
    A0 = ?AG:new(#{}),
    {A1, _} = ?AG:set_remote_credentials(<<"abcd">>, <<"0123456789012345678901">>, 0, A0),
    ?assertError(restart_required, ?AG:set_remote_credentials(<<"efgh">>, <<"0123456789012345678901">>, 0, A1)),
    {A2, _} = ?AG:restart(#{ufrag => <<"wxyz">>, pwd => <<"abcdefghijklmnopqrstuv">>}, 0, A1),
    ?assertEqual({<<"wxyz">>, <<"abcdefghijklmnopqrstuv">>}, ?AG:local_credentials(A2)),
    ?assertEqual(undefined, ?AG:remote_credentials(A2)),
    ?assertError({badarg, bad_credentials}, ?AG:restart(#{ufrag => <<"a">>}, 0, A1)).

%%--------------------------------------------------------------------
%% Network change
%%--------------------------------------------------------------------

remove_host_test() ->
    N0 = pair_net(#{}, {#{}, [{sa1, {?A4, 5000}}, {sa2, {{10, 0, 0, 2}, 5001}}], none},
                  {#{role => controlled}, [{sb, {?B4, 6000}}], none}),
    N1 = run_ok(N0, fun completed/1, 10000),
    {host, host, {?A4, 5000}, _} = selected(N1, a),
    Now = ?NET:now(N1),
    N2 = ?NET:call(N1, a, fun(A) -> ?AG:remove_host(sa1, Now, A) end),
    ?assertMatch([{local_candidate_removed, #ice_cand{address = ?A4}}], events(N2, a, local_candidate_removed)),
    ?assertEqual(failed, state(N2, a)),
    ?assertEqual(undefined, ?AG:selected_pair(?NET:agent(N2, a))),
    ?assertNot(?AG:is_valid_remote(sa1, {?B4, 6000}, ?NET:agent(N2, a))),
    %% An ICE restart recovers on the remaining interface.
    N3 = ?NET:call(N2, a, fun(A) -> ?AG:restart(Now, A) end),
    N4 = ?NET:call(N3, b, fun(A) -> ?AG:restart(Now, A) end),
    N5 = run_ok(resignal(N4), fun completed/1, 10000),
    ?assertMatch({host, host, {{10, 0, 0, 2}, 5001}, _}, selected(N5, a)).
