%% @doc Test helper: a fake mDNS responder on a loopback port. It answers
%% A queries for the names it knows by legacy unicast (RFC 6762 §6.7),
%% the way the system responder answers one-shot queries.
-module(webrtc_test_mdns).

-export([start/1, stop/1, free_port/0, multicast_works/0]).

%% @doc Start a responder for `#{Name => IP | [IP]}'. Returns `{Pid, Port}';
%% resolvers use `#{group => {{127,0,0,1}, Port}}'.
start(Names) ->
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, S} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}, {active, true}]),
        {ok, Port} = inet:port(S),
        Parent ! {self(), {port, Port}},
        loop(S, Names)
    end),
    receive {Pid, {port, Port}} -> {Pid, Port} after 2000 -> error(fake_mdns_start) end.

stop({Pid, _}) ->
    Pid ! stop,
    ok.

loop(S, Names) ->
    receive
        {udp, S, IP, P, Bin} ->
            _ = case webrtc_mdns_msg:decode(Bin) of
                {ok, #{qr := false, id := Id, questions := [#{name := N, type := a}]}} when is_map_key(N, Names) ->
                    Ans = [{N, Addr, 10, false} || Addr <- lists:flatten([maps:get(N, Names)])],
                    gen_udp:send(S, IP, P, webrtc_mdns_msg:encode_response(Id, [{N, a}], Ans, []));
                _ ->
                    ok
            end,
            loop(S, Names);
        stop ->
            gen_udp:close(S)
    end.

free_port() ->
    {ok, S} = gen_udp:open(0, [{ip, {127, 0, 0, 1}}]),
    {ok, P} = inet:port(S),
    ok = gen_udp:close(S),
    P.

%% @doc Whether IPv4 multicast to 224.0.0.251:5353 works on this host: a
%% query sent to the group comes back on a socket joined to it.
-spec multicast_works() -> ok | {skip, string()}.
multicast_works() ->
    Opts = [binary, {active, true}, {reuseaddr, true}, {reuseport, true},
        {add_membership, {{224, 0, 0, 251}, {0, 0, 0, 0}}}],
    case gen_udp:open(5353, Opts) of
        {ok, M} ->
            {ok, Q} = gen_udp:open(0, [binary, {active, false}, {multicast_loop, true}]),
            Probe = webrtc_mdns_msg:encode_query(16#5A5A, [{<<"webrtc-multicast-probe.local">>, a, false}]),
            Sent = gen_udp:send(Q, {224, 0, 0, 251}, 5353, Probe),
            R = receive
                {udp, M, _, _, Probe} -> ok
            after 2000 -> {skip, "multicast to 224.0.0.251:5353 does not loop back on this host"}
            end,
            gen_udp:close(Q),
            gen_udp:close(M),
            case Sent of
                ok -> R;
                {error, E} -> {skip, lists:flatten(io_lib:format("cannot send to 224.0.0.251: ~p", [E]))}
            end;
        {error, E} ->
            {skip, lists:flatten(io_lib:format("cannot bind the mDNS port 5353: ~p", [E]))}
    end.
