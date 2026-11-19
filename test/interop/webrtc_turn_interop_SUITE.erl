%% Relayed connectivity through an independent TURN server (pion/turn,
%% interop/turn). A filter drops every datagram that is not addressed to
%% the TURN server, so the only working candidate pairs are relayed
%% (RFC 8445 relay candidates, RFC 8656 allocations, permissions and
%% channels).
-module(webrtc_turn_interop_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_ice.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([relay_only_datachannel/1, relay_only_media/1, wrong_credentials_no_relay/1, one_side_relayed/1,
         relayed_spoofing_dropped/1, relayed_over_tcp/1, relayed_over_tls/1, untrusted_tls_no_relay/1,
         relayed_by_uri_udp/1, relayed_by_uri_tcp/1, relayed_by_uri_tls/1,
         srv_fallback_tcp/1, srv_fallback_tls/1]).

-define(S, webrtc_test_signal).

all() -> [relay_only_datachannel, relay_only_media, wrong_credentials_no_relay, one_side_relayed,
          relayed_spoofing_dropped, relayed_over_tcp, relayed_over_tls, untrusted_tls_no_relay,
          relayed_by_uri_udp, relayed_by_uri_tcp, relayed_by_uri_tls,
          srv_fallback_tcp, srv_fallback_tls].

init_per_suite(Config) ->
    Bin = filename:join([root(), "interop", "turn", "bin", "turn-server"]),
    case filelib:is_regular(Bin) of
        false ->
            {skip, "TURN server not built: cd interop/turn && go build -o bin/turn-server ."};
        true ->
            {ok, _} = application:ensure_all_started(webrtc),
            %% init_per_suite runs in a short-lived process; the server
            %% exits when its stdin closes, so a holder owns the port.
            Self = self(),
            Ca = filename:join(?config(priv_dir, Config), "turn-ca.pem"),
            Holder = spawn(fun() -> hold(Bin, Ca, Self) end),
            receive
                {turn_ready, Holder, Addrs} ->
                    {ok, Pem} = file:read_file(Ca),
                    [{'Certificate', Der, _}] = public_key:pem_decode(Pem),
                    [{turn_holder, Holder}, {turn, addr(maps:get(udp, Addrs))}, {turn_tcp, addr(maps:get(tcp, Addrs))},
                     {turn_tls, addr(maps:get(tls, Addrs))}, {turn_ca, Der} | Config]
            after 10000 ->
                exit(Holder, kill),
                {skip, "TURN server did not start"}
            end
    end.

hold(Bin, Ca, Parent) ->
    Port = open_port({spawn_executable, Bin},
                     [{args, ["-listen", "127.0.0.1:0", "-user", "alice=wonderland",
                              "-tcp", "127.0.0.1:0", "-tls", "127.0.0.1:0", "-tls-ca", Ca]},
                      {line, 256}, binary, use_stdio, exit_status]),
    Parent ! {turn_ready, self(), listening(Port, #{})},
    receive
        stop -> port_close(Port)
    end.

%% The stream listeners come first, the UDP one last.
listening(Port, Acc) ->
    receive
        {Port, {data, {eol, <<"listening-tcp ", A/binary>>}}} -> listening(Port, Acc#{tcp => A});
        {Port, {data, {eol, <<"listening-tls ", A/binary>>}}} -> listening(Port, Acc#{tls => A});
        {Port, {data, {eol, <<"listening ", A/binary>>}}} -> Acc#{udp => A}
    end.

addr(A) ->
    [Host, P] = string:split(A, ":", trailing),
    {ok, IP} = inet:parse_address(binary_to_list(Host)),
    {IP, binary_to_integer(P)}.

end_per_suite(Config) ->
    case ?config(turn_holder, Config) of
        undefined -> ok;
        H -> H ! stop, ok
    end.

init_per_testcase(_, Config) -> ?S:flush(), Config.
end_per_testcase(_, _) -> ?S:flush(), ok.

root() ->
    {ok, Cwd} = file:get_cwd(),
    up(Cwd).

up("/") -> error(no_root);
up(D) ->
    case filelib:is_regular(filename:join(D, "rebar.config")) of
        true -> D;
        false -> up(filename:dirname(D))
    end.

relayed_pc(Config, Password) ->
    Turn = ?config(turn, Config),
    {ok, Pc} = webrtc:new_peer_connection(#{
        loopback => true,
        turn_servers => [#{address => Turn, username => <<"alice">>, password => Password}],
        outbound_filter => webrtc_impair:filter(#{only_to => [Turn]})
    }),
    Pc.

%% Connect, logging both sides' ICE and DTLS state when it fails.
connect(A, B) ->
    try
        ?S:connect(A, B, 30000)
    catch
        C:R:Stk ->
            [begin
                 ct:pal("~p stats: ~p", [N, webrtc:get_stats(P)]),
                 {ok, T} = gen_server:call(P, transport_pid),
                 ct:pal("~p transport state: ~P", [N, sys:get_state(T), 80])
             end || {N, P} <- [{a, A}, {b, B}]],
            erlang:raise(C, R, Stk)
    end.

%% Data may flow before nomination (RFC 8445 §12.1): wait for it.
%% RFC 8656 §3.1: TURN over TCP and TLS. A reaches the server over the
%% stream only (no UDP leaves A at all), so the data channel must go
%% through the relay.
relayed_over_tcp(Config) ->
    stream_relay(Config, tcp, ?config(turn_tcp, Config), []).

relayed_over_tls(Config) ->
    stream_relay(Config, tls, ?config(turn_tls, Config), [{cacerts, [?config(turn_ca, Config)]}]).

stream_relay(_Config, Transport, Addr, Tls) ->
    {ok, A} = webrtc:new_peer_connection(#{
        loopback => true,
        turn_servers => [#{address => Addr, username => <<"alice">>, password => <<"wonderland">>,
                           transport => Transport, tls_options => Tls}],
        outbound_filter => webrtc_impair:filter(#{only_to => []})
    }),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"s">>, #{}),
    connect(A, B),
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 15000),
    ok = webrtc:send_data(A, Id, text, <<"over ", (atom_to_binary(Transport))/binary>>),
    {ok, _} = ?S:wait(B, fun({channel_message, _, text, <<"over ", _/binary>>}) -> true; (_) -> false end, 15000),
    ?assertMatch([{relay, _}], selected_types(A)),
    webrtc:close(A),
    webrtc:close(B).

%% The server given by URI and host name (RFC 7065), resolved when the
%% peer connection starts; for turns the certificate is checked against
%% the name.
relayed_by_uri_udp(Config) ->
    %% UDP from A only to the server.
    Turn = ?config(turn, Config),
    uri_relay(by_uri(<<"turn">>, Turn, <<"?transport=udp">>), #{}, [Turn]).

relayed_by_uri_tcp(Config) ->
    uri_relay(by_uri(<<"turn">>, ?config(turn_tcp, Config), <<"?transport=tcp">>), #{}, []).

relayed_by_uri_tls(Config) ->
    uri_relay(by_uri(<<"turns">>, ?config(turn_tls, Config), <<>>), #{tls_options => [{cacerts, [?config(turn_ca, Config)]}]},
              []).

by_uri(Scheme, {_, Port}, Query) ->
    <<Scheme/binary, ":localhost:", (integer_to_binary(Port))/binary, Query/binary>>.

%% RFC 5928 §3: the first SRV target refuses the connection (a port
%% nobody listens on), the second is the Pion server: the relay comes
%% from it. Over UDP the same fallback follows the 39.5 s transaction
%% timeout; webrtc_ice_agent_tests:turn_udp_fallback_test covers it.
srv_fallback_tcp(Config) ->
    srv_relay(<<"turn:localhost?transport=tcp">>, "_turn._tcp.localhost", dead_port(tcp), ?config(turn_tcp, Config), #{}, []).

srv_fallback_tls(Config) ->
    srv_relay(<<"turns:localhost">>, "_turns._tcp.localhost", dead_port(tcp), ?config(turn_tls, Config),
              #{tls_options => [{cacerts, [?config(turn_ca, Config)]}]}, []).

dead_port(tcp) ->
    {ok, L} = gen_tcp:listen(0, []), {ok, P} = inet:port(L), gen_tcp:close(L), P.

srv_relay(Url, Srv, DeadPort, {_, LivePort}, Extra, OnlyTo) ->
    Dns = fun
        (srv, Name) when Name =:= Srv -> {ok, [{10, 0, DeadPort, "dead.localhost"}, {20, 0, LivePort, "live.localhost"}]};
        (srv, _) -> {ok, []};
        (inet, N) when N =:= "dead.localhost"; N =:= "live.localhost" -> {ok, [{127, 0, 0, 1}]};
        (_, _) -> {error, nxdomain}
    end,
    {ok, A} = webrtc:new_peer_connection(#{
        loopback => true,
        ice_resolver => Dns,
        ice_servers => [maps:merge(#{urls => [Url], username => <<"alice">>, credential => <<"wonderland">>}, Extra)],
        outbound_filter => webrtc_impair:filter(#{only_to => OnlyTo})
    }),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"f">>, #{}),
    connect(A, B),
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 60000),
    ok = webrtc:send_data(A, Id, text, Url),
    {ok, _} = ?S:wait(B, fun({channel_message, _, text, U}) -> U =:= Url; (_) -> false end, 15000),
    ?assertMatch([{relay, _}], selected_types(A)),
    webrtc:close(A),
    webrtc:close(B).

uri_relay(Url, Extra, OnlyTo) ->
    {ok, A} = webrtc:new_peer_connection(#{
        loopback => true,
        ice_servers => [maps:merge(#{urls => [Url], username => <<"alice">>, credential => <<"wonderland">>}, Extra)],
        outbound_filter => webrtc_impair:filter(#{only_to => OnlyTo})
    }),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"u">>, #{}),
    connect(A, B),
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 15000),
    ok = webrtc:send_data(A, Id, text, Url),
    {ok, _} = ?S:wait(B, fun({channel_message, _, text, U}) -> U =:= Url; (_) -> false end, 15000),
    ?assertMatch([{relay, _}], selected_types(A)),
    webrtc:close(A),
    webrtc:close(B).

%% A certificate that does not verify gives no relayed candidate, and
%% the failure is reported.
untrusted_tls_no_relay(Config) ->
    {ok, A} = webrtc:new_peer_connection(#{
        loopback => true,
        turn_servers => [#{address => ?config(turn_tls, Config), username => <<"alice">>, password => <<"wonderland">>,
                           transport => tls, tls_options => [{cacerts, []}]}]
    }),
    ok = webrtc:create_data_channel(A, <<"s">>, #{}),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    {ok, _} = ?S:wait(A, fun({ice_gathering_state, complete}) -> true; (_) -> false end, 15000),
    ?assertEqual([], [C || {webrtc, P, {ice_candidate, C, _}} <- flush_all(), P =:= A, is_binary(C),
                           binary:match(C, <<"typ relay">>) =/= nomatch]),
    webrtc:close(A).

flush_all() ->
    receive M -> [M | flush_all()] after 0 -> [] end.

selected_types(Pc) ->
    [{L#ice_cand.type, R#ice_cand.type} || {L, R} <- selected(Pc, 50)].

selected(Pc, Tries) ->
    #{transport := #{ice := #{pairs := Pairs}}} = webrtc:get_stats(Pc),
    case [{L, R} || #{selected := true, local := #ice_cand{} = L, remote := #ice_cand{} = R} <- Pairs] of
        [] when Tries > 0 -> timer:sleep(100), selected(Pc, Tries - 1);
        Sel -> Sel
    end.

relay_only_datachannel(Config) ->
    A = relayed_pc(Config, <<"wonderland">>),
    B = relayed_pc(Config, <<"wonderland">>),
    ok = webrtc:create_data_channel(A, <<"r">>, #{}),
    ?S:connect(A, B, 30000),
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 15000),
    ok = webrtc:send_data(A, Id, text, <<"through the relay">>),
    {ok, _} = ?S:wait(B, fun({channel_message, _, text, <<"through the relay">>}) -> true; (_) -> false end, 15000),
    Types = selected_types(A),
    ct:log("selected pair types: ~p", [Types]),
    ?assert(lists:any(fun({L, _}) -> L =:= relay end, Types) orelse
            lists:any(fun({_, R}) -> R =:= relay end, Types)),
    webrtc:close(A),
    webrtc:close(B).

relay_only_media(Config) ->
    A = relayed_pc(Config, <<"wonderland">>),
    B = relayed_pc(Config, <<"wonderland">>),
    {ok, _} = webrtc:add_transceiver(A, video, #{}),
    {ok, _} = webrtc:add_transceiver(B, video, #{}),
    ?S:connect(A, B, 30000),
    [ok = webrtc:send_rtp(A, <<"0">>, <<I:32>>, #{timestamp => I}) || I <- lists:seq(1, 100)],
    {ok, _} = ?S:wait(B, fun({rtp, _, #rtp{payload = <<100:32>>}}) -> true; (_) -> false end, 15000),
    webrtc:close(A),
    webrtc:close(B).

%% A 401 for bad credentials leaves no relay candidate; with direct
%% traffic blocked the connection cannot be established.
wrong_credentials_no_relay(Config) ->
    A = relayed_pc(Config, <<"wrong">>),
    B = relayed_pc(Config, <<"wrong">>),
    ok = webrtc:create_data_channel(A, <<"x">>, #{}),
    _ = ?S:negotiate(A, B),
    ?assertMatch({error, _}, ?S:wait_connected([A, B], 8000)),
    webrtc:close(A),
    webrtc:close(B).

%% Only A is behind the firewall: A's relay candidate pairs with B's host
%% candidate.
one_side_relayed(Config) ->
    A = relayed_pc(Config, <<"wonderland">>),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"h">>, #{}),
    connect(A, B),
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 15000),
    ok = webrtc:send_data(A, Id, text, <<"half relayed">>),
    {ok, _} = ?S:wait(B, fun({channel_message, _, text, <<"half relayed">>}) -> true; (_) -> false end, 15000),
    TA = selected_types(A),
    ct:log("A pairs: ~p, B pairs: ~p", [TA, selected_types(B)]),
    ?assert(lists:any(fun({L, _}) -> L =:= relay end, TA)),
    webrtc:close(A),
    webrtc:close(B).

%% TURN permissions cover a whole IP (RFC 8656 §9): another port of a
%% permitted host reaches the relay. Only the validated pair may reach
%% DTLS and SRTP.
relayed_spoofing_dropped(Config) ->
    A = relayed_pc(Config, <<"wonderland">>),
    B = relayed_pc(Config, <<"wonderland">>),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    ?S:connect(A, B, 30000),
    [Relay | _] = [{L#ice_cand.address, L#ice_cand.port} || {#ice_cand{type = relay} = L, _} <- selected(A, 50)],
    {ok, Rogue} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {IP, Port} = Relay,
    [ok = gen_udp:send(Rogue, IP, Port, <<128, 111, N:16, 0:64, (crypto:strong_rand_bytes(40))/binary>>)
     || N <- lists:seq(1, 200)],
    [ok = gen_udp:send(Rogue, IP, Port, <<23, 16#FEFD:16, 0:16, N:48, 40:16, (crypto:strong_rand_bytes(40))/binary>>)
     || N <- lists:seq(1, 200)],
    timer:sleep(500),
    #{transport := #{media := #{counters := C}}} = webrtc:get_stats(A),
    ct:log("A media counters: ~p", [C]),
    ?assertEqual(0, maps:get(srtp_rejected, C, 0)),
    ok = webrtc:send_rtp(B, <<"0">>, <<"real">>, #{timestamp => 1}),
    {ok, _} = ?S:wait(A, fun({rtp, _, #rtp{payload = <<"real">>}}) -> true; (_) -> false end, 10000),
    gen_udp:close(Rogue),
    webrtc:close(A),
    webrtc:close(B).
