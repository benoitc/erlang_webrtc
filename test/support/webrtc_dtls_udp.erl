%% @doc Test helper: run a webrtc_dtls engine over a real gen_udp socket
%% in the calling process.
-module(webrtc_dtls_udp).
-export([open/0, run/4, send/3]).

open() ->
    {ok, S} = gen_udp:open(0, [binary, {active, true}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(S),
    {S, Port}.

%% Drive the engine until Stop(Events) is true or Timeout ms pass.
%% Peer is {IP, Port} or undefined (learned from the first datagram).
%% Option `out' rewrites each outgoing datagram (an attacker on path).
run(Sock, Peer, St0, Opts) ->
    put(webrtc_dtls_udp_out, maps:get(out, Opts, fun(D) -> D end)),
    Stop = maps:get(stop, Opts),
    Deadline = now_ms() + maps:get(timeout, Opts, 10000),
    {St1, A} =
        case maps:get(start, Opts, false) of
            true -> webrtc_dtls:start(now_ms(), St0);
            false -> {St0, []}
        end,
    {Peer1, Ev} = exec(A, Sock, Peer, []),
    loop(Sock, Peer1, St1, Ev, Stop, Deadline).

loop(Sock, Peer, St, Ev, Stop, Deadline) ->
    case Stop(Ev) of
        true ->
            {ok, St, Peer, Ev};
        false ->
            Now = now_ms(),
            Wait = max(0, min(Deadline, timeout_of(St)) - Now),
            case Now >= Deadline of
                true ->
                    {timeout, St, Peer, Ev};
                false ->
                    receive
                        {udp, Sock, IP, Port, Data} ->
                            P = case Peer of undefined -> {IP, Port}; _ -> Peer end,
                            {St1, A} = webrtc_dtls:handle_packet(Data, now_ms(), St),
                            {P1, Ev1} = exec(A, Sock, P, Ev),
                            loop(Sock, P1, St1, Ev1, Stop, Deadline)
                    after Wait ->
                        {St1, A} = webrtc_dtls:handle_timeout(now_ms(), St),
                        {P1, Ev1} = exec(A, Sock, Peer, Ev),
                        loop(Sock, P1, St1, Ev1, Stop, Deadline)
                    end
            end
    end.

send(Sock, Peer, Actions) ->
    exec(Actions, Sock, Peer, []).

exec([], _Sock, Peer, Ev) ->
    {Peer, Ev};
exec([{send, D} | Rest], Sock, {IP, Port} = Peer, Ev) ->
    Out =
        case get(webrtc_dtls_udp_out) of
            undefined -> D;
            F -> F(D)
        end,
    ok = gen_udp:send(Sock, IP, Port, Out),
    exec(Rest, Sock, Peer, Ev);
exec([{event, E} | Rest], Sock, Peer, Ev) ->
    exec(Rest, Sock, Peer, Ev ++ [E]).

timeout_of(St) ->
    case webrtc_dtls:next_timeout(St) of
        infinity -> now_ms() + 100;
        T -> T
    end.

now_ms() -> erlang:monotonic_time(millisecond).
