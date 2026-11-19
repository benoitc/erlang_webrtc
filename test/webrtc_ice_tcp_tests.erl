%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% ICE-TCP (RFC 6544) between two agents with only TCP host candidates.
%% The test plays the owners: it opens the connections the agents ask
%% for, accepts them on the other side and carries the framed packets.
-module(webrtc_ice_tcp_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_ice.hrl").

-define(AG, webrtc_ice_agent).
-define(LA, {{10, 0, 0, 1}, 7000}).
-define(LB, {{10, 0, 0, 2}, 8000}).

agent(Name, Role) ->
    {U, P} = creds(Name),
    ?AG:new(#{ufrag => U, pwd => P, role => Role, seed => {1, 2, 3}}).

creds(a) -> {<<"aaaa">>, <<"apassword0123456789012">>};
creds(b) -> {<<"bbbb">>, <<"bpassword0123456789012">>}.

other(a) -> b;
other(b) -> a.

listen(a) -> ?LA;
listen(b) -> ?LB.

%% World: agents, links between connection refs, events, time.
world() ->
    W0 = #{a => agent(a, controlling), b => agent(b, controlled), links => #{}, events => [], next => 1, now => 0,
           refuse => false},
    W1 = lists:foldl(
        fun(N, W) ->
            {A1, Acts} = ?AG:tcp_listeners([{{listen, N}, listen(N)}], 0, maps:get(N, W)),
            {A2, Acts2} = ?AG:gather([], 0, A1),
            route(N, Acts ++ Acts2, W#{N => A2})
        end,
        W0,
        [a, b]
    ),
    {UA, PA} = creds(a),
    {UB, PB} = creds(b),
    W2 = call(a, fun(A) -> ?AG:set_remote_credentials(UB, PB, 0, A) end, W1),
    W3 = call(b, fun(B) -> ?AG:set_remote_credentials(UA, PA, 0, B) end, W2),
    %% Trickle every local candidate to the other side.
    lists:foldl(
        fun(N, W) ->
            lists:foldl(
                fun(C, WA) -> call(other(N), fun(Ag) -> ?AG:add_remote_candidate(C, 0, Ag) end, WA) end,
                W,
                ?AG:local_candidates(maps:get(N, W))
            )
        end,
        W3,
        [a, b]
    ).

call(N, F, W) ->
    {A1, Acts} = F(maps:get(N, W)),
    route(N, Acts, W#{N => A1}).

route(N, Acts, W) ->
    lists:foldl(fun(Act, WA) -> act(N, Act, WA) end, W, Acts).

act(N, {event, E}, W) ->
    W#{events => maps:get(events, W) ++ [{N, E}]};
act(N, {connect, Ref, #{transport := ice_tcp, local := LIP, remote := Remote}}, #{refuse := true} = W) ->
    _ = {LIP, Remote},
    call(N, fun(A) -> ?AG:stream_down(Ref, econnrefused, maps:get(now, W), A) end, W);
act(N, {connect, Ref, #{transport := ice_tcp, local := LIP, remote := Remote}}, W) ->
    %% The peer accepts on its listener; the connection comes from an
    %% ephemeral port of the active side.
    Peer = other(N),
    Remote = listen(Peer),
    I = maps:get(next, W),
    From = {LIP, 50000 + I},
    PeerRef = {tcp, 1000 + I},
    Links = (maps:get(links, W))#{{N, Ref} => {Peer, PeerRef, Remote}, {Peer, PeerRef} => {N, Ref, From}},
    W1 = W#{links => Links, next => I + 1},
    W2 = call(Peer, fun(A) -> ?AG:tcp_accepted(PeerRef, {listen, Peer}, From, maps:get(now, W1), A) end, W1),
    call(N, fun(A) -> ?AG:stream_up(Ref, maps:get(now, W2), A) end, W2);
act(N, {send, {tcp, _} = Ref, _Dest, Bin}, W) ->
    case maps:find({N, Ref}, maps:get(links, W)) of
        {ok, {Peer, PeerRef, _}} ->
            %% The source seen by the peer is our end of the connection.
            {_, _, Src} = maps:get({Peer, PeerRef}, maps:get(links, W)),
            call(Peer, fun(A) -> ?AG:handle_packet(PeerRef, Src, Bin, maps:get(now, W), A) end, W);
        error ->
            W
    end;
act(_N, _Other, W) ->
    W.

run(W, Until) ->
    Next = min(?AG:next_timeout(maps:get(a, W)), ?AG:next_timeout(maps:get(b, W))),
    case Next of
        T when T =< Until ->
            Now = max(maps:get(now, W), T),
            W1 = W#{now => Now},
            W2 = call(a, fun(A) -> ?AG:handle_timeout(Now, A) end, W1),
            run(call(b, fun(B) -> ?AG:handle_timeout(Now, B) end, W2), Until);
        _ ->
            W#{now => Until}
    end.

state(N, W) -> ?AG:connection_state(maps:get(N, W)).

%% RFC 6544 §4.2, §6.2: TCP host candidates, active and passive, below UDP.
candidates_test() ->
    W = world(),
    Cands = ?AG:local_candidates(maps:get(a, W)),
    ?assertEqual([active, passive], lists:sort([T || #ice_cand{transport = tcp, tcptype = T} <- Cands])),
    [Active] = [C || #ice_cand{tcptype = active} = C <- Cands],
    ?assertEqual(9, Active#ice_cand.port),
    ?assertMatch(<<_/binary>>, webrtc_ice_candidate:to_sdp(Active)),
    ?assertNotEqual(nomatch, binary:match(webrtc_ice_candidate:to_sdp(Active), <<"tcptype active">>)),
    UdpHost = webrtc_ice_candidate:priority(host, webrtc_ice_candidate:local_preference(0, 0), 1),
    ?assert(lists:all(fun(#ice_cand{priority = P}) -> P < UdpHost end, Cands)).

%% ICE completes over TCP and data flows both ways on the selected pair.
connectivity_test() ->
    W = run(world(), 20000),
    ?assertEqual({completed, completed}, {state(a, W), state(b, W)}),
    {LA, RA} = ?AG:selected_pair(maps:get(a, W)),
    ?assertEqual({tcp, tcp}, {LA#ice_cand.transport, RA#ice_cand.transport}),
    ?assertEqual(lists:sort([active, passive]), lists:sort([LA#ice_cand.tcptype, peer_type(W)])),
    %% Data leaves on the selected pair's connection, and the peer
    %% accepts it from that connection only (RFC 8445 §12.2).
    {ok, _, [{send, {tcp, _} = Ref, _, <<128, "from a">>}]} = ?AG:send(<<128, "from a">>, maps:get(now, W), maps:get(a, W)),
    {Peer, PeerRef, Src} = maps:get({a, Ref}, maps:get(links, W)),
    {_, _, ASrc} = maps:get({Peer, PeerRef}, maps:get(links, W)),
    _ = Src,
    ?assert(?AG:is_valid_remote(PeerRef, ASrc, maps:get(b, W))),
    ?assertNot(?AG:is_valid_remote({tcp, 9999}, ASrc, maps:get(b, W))),
    {ok, _, [{send, PeerRef, _, <<128, "from b">>}]} = ?AG:send(<<128, "from b">>, maps:get(now, W), maps:get(b, W)).

peer_type(W) ->
    {LB, _} = ?AG:selected_pair(maps:get(b, W)),
    LB#ice_cand.tcptype.

%% A connection that cannot be opened fails its pair; nothing connects.
refused_connection_test() ->
    W = run((world())#{refuse => true}, 50000),
    ?assertNotEqual(completed, state(a, W)),
    #{pairs := Pairs} = ?AG:stats(maps:get(a, W)),
    ?assert(lists:all(fun(#{state := St}) -> St =:= failed end, Pairs)).
