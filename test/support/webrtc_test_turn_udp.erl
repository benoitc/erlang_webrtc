%% @doc Test helper: the in-memory TURN server engine
%% (`webrtc_test_turn_server') on a real UDP socket. Only the client
%% side is served on the socket; relayed traffic to peers is dropped,
%% which is enough to observe allocations.
-module(webrtc_test_turn_udp).
-export([start/1, allocations/1, stop/1]).

start(Opts) ->
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, S} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}, {active, true}]),
        {ok, Port} = inet:port(S),
        Addr = {{127, 0, 0, 1}, Port},
        Srv = webrtc_test_turn_server:new(maps:merge(#{address => Addr}, Opts)),
        Parent ! {turn_udp, self(), Addr},
        loop(S, Addr, Srv)
    end),
    receive {turn_udp, Pid, Addr} -> {Pid, Addr} end.

allocations(Pid) ->
    Pid ! {allocations, self()},
    receive {allocations, Pid, N} -> N after 2000 -> error(timeout) end.

stop(Pid) ->
    Pid ! stop,
    ok.

loop(S, Addr, Srv) ->
    receive
        {udp, S, IP, Port, Bin} ->
            {Srv1, Out} = webrtc_test_turn_server:handle({IP, Port}, Addr, Bin, now_ms(), Srv),
            _ = [gen_udp:send(S, DIP, DPort, B) || {send, From, {DIP, DPort}, B} <- Out, From =:= Addr],
            loop(S, Addr, Srv1);
        {allocations, From} ->
            From ! {allocations, self(), map_size(webrtc_test_turn_server:allocations(Srv))},
            loop(S, Addr, Srv);
        stop ->
            gen_udp:close(S)
    end.

now_ms() -> erlang:monotonic_time(millisecond).
