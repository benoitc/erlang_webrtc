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
-export([relay_only_datachannel/1, relay_only_media/1, wrong_credentials_no_relay/1, one_side_relayed/1]).

-define(S, webrtc_test_signal).

all() -> [relay_only_datachannel, relay_only_media, wrong_credentials_no_relay, one_side_relayed].

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
            Holder = spawn(fun() -> hold(Bin, Self) end),
            receive
                {turn_ready, Holder, Addr} ->
                    [Host, P] = string:split(Addr, ":", trailing),
                    {ok, IP} = inet:parse_address(binary_to_list(Host)),
                    [{turn_holder, Holder}, {turn, {IP, binary_to_integer(P)}} | Config]
            after 10000 ->
                exit(Holder, kill),
                {skip, "TURN server did not start"}
            end
    end.

hold(Bin, Parent) ->
    Port = open_port({spawn_executable, Bin},
                     [{args, ["-listen", "127.0.0.1:0", "-user", "alice=wonderland"]},
                      {line, 256}, binary, use_stdio, exit_status]),
    receive
        {Port, {data, {eol, <<"listening ", Addr/binary>>}}} -> Parent ! {turn_ready, self(), Addr}
    end,
    receive
        stop -> port_close(Port)
    end.

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

selected_types(Pc) ->
    #{transport := #{ice := #{pairs := Pairs}}} = webrtc:get_stats(Pc),
    [{L#ice_cand.type, R#ice_cand.type}
     || #{selected := true, local := #ice_cand{} = L, remote := #ice_cand{} = R} <- Pairs].

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
    ?S:connect(A, B, 30000),
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 15000),
    ok = webrtc:send_data(A, Id, text, <<"half relayed">>),
    {ok, _} = ?S:wait(B, fun({channel_message, _, text, <<"half relayed">>}) -> true; (_) -> false end, 15000),
    TA = selected_types(A),
    ct:log("A pairs: ~p, B pairs: ~p", [TA, selected_types(B)]),
    ?assert(lists:any(fun({L, _}) -> L =:= relay end, TA)),
    webrtc:close(A),
    webrtc:close(B).
