%% RFC 8837 §5 Table 1, and the TOS byte the operating system puts on
%% the wire for it (read back with recvtos / recvtclass, independently
%% of our code).
-module(webrtc_dscp_tests).
-include_lib("eunit/include/eunit.hrl").

-define(D, webrtc_dscp).

table_test_() ->
    Rows = [
        %% {Kind, Priority, Interactive, Important, Dscp}
        {audio, very_low, true, true, 1}, {audio, low, true, true, 0},
        {audio, medium, true, true, 46}, {audio, high, true, false, 46},
        {video, very_low, true, true, 1}, {video, low, true, true, 0},
        {video, medium, true, true, 36}, {video, medium, true, false, 38},
        {video, high, true, true, 34}, {video, high, true, false, 36},
        {video, medium, false, true, 28}, {video, medium, false, false, 30},
        {video, high, false, true, 26}, {video, high, false, false, 28},
        {data, very_low, true, true, 1}, {data, low, true, true, 0},
        {data, medium, true, true, 10}, {data, high, true, true, 18}
    ],
    [?_assertEqual(D, ?D:dscp(K, P, I, Imp)) || {K, P, I, Imp, D} <- Rows].

class_test() ->
    ?assertEqual([very_low, very_low, low, low, medium, high, high],
                 [?D:class(P) || P <- [0, 128, 256, 511, 512, 1024, 65535]]).

tos_test() ->
    ?assertEqual(184, ?D:tos(46, 0)),
    ?assertEqual(186, ?D:tos(46, 2)),
    ?assertEqual(136, ?D:tos(34, 0)).

%% What the sending path puts in the IP header reaches the receiver.
wire_test_() ->
    [{atom_to_list(F), fun() -> wire(F) end} || F <- [inet, inet6], family_works(F)].

family_works(F) ->
    case gen_udp:open(0, [F, {ip, loopback(F)}]) of
        {ok, S} -> gen_udp:close(S), true;
        _ -> false
    end.

loopback(inet) -> {127, 0, 0, 1};
loopback(inet6) -> {0, 0, 0, 0, 0, 0, 0, 1}.

wire(F) ->
    Ip = loopback(F),
    Opt = case F of inet -> recvtos; inet6 -> recvtclass end,
    {ok, R} = gen_udp:open(0, [F, binary, {ip, Ip}, {active, false}, {Opt, true}]),
    {ok, Port} = inet:port(R),
    {ok, S} = gen_udp:open(0, [F, binary, {ip, Ip}]),
    Tos = [?D:tos(46, 0), ?D:tos(34, 2), ?D:tos(18, 0), ?D:tos(1, 0)],
    [ok = webrtc_transport_net:udp_send(S, {Ip, Port}, <<T>>, T) || T <- Tos],
    Got = [begin
               {ok, {_, _, Anc, <<T>>}} = gen_udp:recv(R, 0, 2000),
               {T, proplists:get_value(case F of inet -> tos; inet6 -> tclass end, Anc)}
           end || _ <- Tos],
    gen_udp:close(S),
    gen_udp:close(R),
    [?assertEqual(T, Seen) || {T, Seen} <- Got].
