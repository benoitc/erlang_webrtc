%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% The mDNS resolver process against a fake responder on loopback ports
%% (the group address and port are configurable for tests), and the
%% responder for our own names (draft-ietf-mmusic-mdns-ice-candidates §3.1).
-module(webrtc_mdns_tests).
-include_lib("eunit/include/eunit.hrl").

-define(MSG, webrtc_mdns_msg).
-define(RS, webrtc_mdns_responder).
-define(LO, {127, 0, 0, 1}).
-define(NAME, <<"9b2f6c1e-3d4a-4e5f-8a7b-0c1d2e3f4a5b.local">>).

free_port() ->
    {ok, S} = gen_udp:open(0, [{ip, ?LO}]),
    {ok, P} = inet:port(S),
    ok = gen_udp:close(S),
    P.

%% A responder for ?NAME on `Port'. Modes: `legacy' answers every query
%% by unicast to its source (RFC 6762 §6.7); `multicast' ignores QU
%% questions and sends answers to the "group" listener port with ID 0,
%% as Chromium does; `spoof' answers with another name; `silent'.
fake(Mode, Port, ListenPort) ->
    Parent = self(),
    Pid = spawn_link(fun() ->
        {ok, S} = gen_udp:open(Port, [binary, {ip, ?LO}, {active, true}]),
        Parent ! {fake, self(), ready},
        fake_loop(Mode, S, ListenPort, Parent)
    end),
    receive {fake, Pid, ready} -> Pid end.

fake_loop(Mode, S, LP, Parent) ->
    receive
        {udp, S, IP, P, Bin} ->
            {ok, #{id := Id, questions := [#{name := N, type := T, unicast := U}]}} = ?MSG:decode(Bin),
            Parent ! {fake_query, T, U},
            Ans = [{N, {127, 0, 0, 1}, 10, false} || T =:= a],
            case Mode of
                legacy when N =:= ?NAME, Ans =/= [] ->
                    gen_udp:send(S, IP, P, ?MSG:encode_response(Id, [{N, T}], Ans, []));
                multicast when N =:= ?NAME, Ans =/= [], not U ->
                    gen_udp:send(S, ?LO, LP, ?MSG:encode_response(0, [], Ans, []));
                spoof when Ans =/= [] ->
                    gen_udp:send(S, IP, P, ?MSG:encode_response(Id, [{N, T}], [{<<"x.local">>, ?LO, 10, false}], []));
                _ ->
                    ok
            end,
            fake_loop(Mode, S, LP, Parent);
        stop ->
            gen_udp:close(S)
    end.

start(Mode) ->
    GP = free_port(),
    LP = free_port(),
    F = fake(Mode, GP, LP),
    {ok, M} = webrtc_mdns:start(#{group => {?LO, GP}, listen => {?LO, LP}, schedule => [100, 100, 200]}),
    {M, F}.

stop({M, F}) ->
    ok = webrtc_mdns:stop(M),
    F ! stop,
    flush().

flush() ->
    receive _ -> flush() after 0 -> ok end.

result(Ref) ->
    receive {webrtc_mdns, Ref, R} -> R after 3000 -> no_result end.

process_test_() ->
    {foreach, fun() -> ok end, fun(_) -> flush() end, [
        fun legacy_unicast/0,
        fun multicast_answer_after_qm/0,
        fun no_answer_times_out/0,
        fun spoofed_answer_ignored/0,
        fun fqdn_lookup/0,
        fun bad_name/0,
        fun owner_exit_stops_resolver/0,
        fun responder_answers_queries/0,
        fun ipv6_only_answer/0,
        fun responder_answers_ipv6/0
    ]}.

legacy_unicast() ->
    {M, _} = Ctx = start(legacy),
    T0 = erlang:monotonic_time(millisecond),
    ?assertEqual({ok, [{127, 0, 0, 1}]}, result(webrtc_mdns:resolve(M, ?NAME))),
    ?assert(erlang:monotonic_time(millisecond) - T0 < 100),
    %% The first queries ask for unicast answers (QU).
    receive {fake_query, a, U} -> ?assert(U) after 1000 -> error(no_query) end,
    %% Served from the cache, no new query.
    flush(),
    ?assertEqual({ok, [{127, 0, 0, 1}]}, result(webrtc_mdns:resolve(M, ?NAME))),
    receive {fake_query, _, _} -> error(not_cached) after 200 -> ok end,
    stop(Ctx).

multicast_answer_after_qm() ->
    {M, _} = Ctx = start(multicast),
    ?assertEqual({ok, [{127, 0, 0, 1}]}, result(webrtc_mdns:resolve(M, ?NAME))),
    stop(Ctx).

no_answer_times_out() ->
    {M, _} = Ctx = start(silent),
    T0 = erlang:monotonic_time(millisecond),
    ?assertEqual({error, timeout}, result(webrtc_mdns:resolve(M, ?NAME))),
    %% Attempts at 0, 100 and 200 ms, failure at 400 ms.
    ?assert(erlang:monotonic_time(millisecond) - T0 >= 400),
    ?assertEqual(6, length([x || {fake_query, _, _} <- drain()])),
    stop(Ctx).

drain() ->
    receive M -> [M | drain()] after 0 -> [] end.

spoofed_answer_ignored() ->
    {M, _} = Ctx = start(spoof),
    ?assertEqual({error, timeout}, result(webrtc_mdns:resolve(M, ?NAME))),
    stop(Ctx).

fqdn_lookup() ->
    {M, _} = Ctx = start(silent),
    {ok, IPs} = result(webrtc_mdns:resolve(M, <<"localhost">>)),
    ?assert(lists:member({127, 0, 0, 1}, IPs) orelse lists:member({0, 0, 0, 0, 0, 0, 0, 1}, IPs)),
    ?assertMatch({error, _}, result(webrtc_mdns:resolve(M, <<"does-not-exist.invalid">>))),
    stop(Ctx).

bad_name() ->
    {M, _} = Ctx = start(silent),
    ?assertEqual({error, bad_name}, result(webrtc_mdns:resolve(M, <<"a..local">>))),
    stop(Ctx).

owner_exit_stops_resolver() ->
    Self = self(),
    Owner = spawn(fun() ->
        {ok, M} = webrtc_mdns:start(#{group => {?LO, free_port()}, listen => false}),
        Self ! {resolver, M},
        receive stop -> ok end
    end),
    M = receive {resolver, R} -> R end,
    Mon = monitor(process, M),
    Owner ! stop,
    receive {'DOWN', Mon, process, M, _} -> ok after 2000 -> error(resolver_alive) end.

responder_answers_queries() ->
    GP = free_port(),
    LP = free_port(),
    {ok, G} = gen_udp:open(GP, [binary, {ip, ?LO}, {active, true}]),
    {ok, M} = webrtc_mdns:start(#{group => {?LO, GP}, listen => {?LO, LP}}),
    {ok, Name} = webrtc_mdns:register_name(M, {192, 0, 2, 10}),
    %% A new name is announced on the group (draft §3.1.1, RFC 6762 §8.3).
    receive
        {udp, G, _, LP, Ann} ->
            ?assertMatch({ok, #{qr := true, answers := [#{name := Name, data := {192, 0, 2, 10}, ttl := 120}]}},
                         ?MSG:decode(Ann))
    after 2000 -> error(no_announcement)
    end,
    ?assertMatch({match, _}, re:run(Name, "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.local$")),
    ?assertEqual({ok, Name}, webrtc_mdns:register_name(M, {192, 0, 2, 10})),
    receive {udp, G, _, _, _} -> error(announced_twice) after 200 -> ok end,
    %% A legacy one-shot query from an ephemeral port: unicast reply,
    %% ID and question repeated, TTL 10 (RFC 6762 §6.7).
    {ok, Q} = gen_udp:open(0, [binary, {ip, ?LO}, {active, true}]),
    ok = gen_udp:send(Q, ?LO, LP, ?MSG:encode_query(77, [{Name, a, false}])),
    receive
        {udp, Q, _, LP, Bin} ->
            {ok, R} = ?MSG:decode(Bin),
            ?assertMatch(#{id := 77, qr := true, aa := true, questions := [#{name := Name}]}, R),
            ?assertMatch([#{name := Name, data := {192, 0, 2, 10}, ttl := 10, cache_flush := false}], maps:get(answers, R))
    after 2000 -> error(no_reply)
    end,
    %% A query from the mDNS port is answered on the group.
    ok = gen_udp:send(G, ?LO, LP, ?MSG:encode_query(0, [{Name, a, false}])),
    receive
        {udp, G, _, LP, Bin2} ->
            {ok, R2} = ?MSG:decode(Bin2),
            ?assertMatch([#{name := Name, ttl := 120, cache_flush := true}], maps:get(answers, R2))
    after 2000 -> error(no_group_reply)
    end,
    ok = webrtc_mdns:stop(M),
    %% Stopping sends a goodbye (TTL 0, RFC 6762 §10.1).
    receive
        {udp, G, _, LP, Bye} -> ?assertMatch({ok, #{answers := [#{ttl := 0}]}}, ?MSG:decode(Bye))
    after 2000 -> error(no_goodbye)
    end,
    gen_udp:close(Q),
    gen_udp:close(G).

-define(LO6, {0, 0, 0, 0, 0, 0, 0, 1}).

free_port6() ->
    {ok, S} = gen_udp:open(0, [inet6, {ip, ?LO6}]),
    {ok, P} = inet:port(S),
    ok = gen_udp:close(S),
    P.

%% RFC 6762 §20: a responder reachable over IPv6 only. The IPv4 group
%% stays silent; the answer comes back over the IPv6 query socket.
ipv6_only_answer() ->
    G6 = free_port6(),
    {ok, F} = gen_udp:open(G6, [binary, inet6, {ip, ?LO6}, {active, true}]),
    {ok, M} = webrtc_mdns:start(#{group => {?LO, free_port()}, listen => false, group6 => {?LO6, G6},
                                  listen6 => false, schedule => [100, 100]}),
    Ref = webrtc_mdns:resolve(M, ?NAME),
    receive
        {udp, F, IP, P, Q} ->
            {ok, #{id := Id, questions := [#{name := ?NAME, type := a}]}} = ?MSG:decode(Q),
            ok = gen_udp:send(F, IP, P, ?MSG:encode_response(Id, [{?NAME, a}], [{?NAME, {127, 0, 0, 1}, 10, false}], []))
    after 2000 -> error(no_ipv6_query)
    end,
    ?assertEqual({ok, [{127, 0, 0, 1}]}, result(Ref)),
    ok = webrtc_mdns:stop(M),
    gen_udp:close(F).

%% Our names are announced on the IPv6 group too, and an IPv6 query is
%% answered there, with NSEC for the family the name lacks.
responder_answers_ipv6() ->
    G6 = free_port6(),
    L6 = free_port6(),
    {ok, G} = gen_udp:open(G6, [binary, inet6, {ip, ?LO6}, {active, true}]),
    {ok, M} = webrtc_mdns:start(#{group => {?LO, free_port()}, listen => false, group6 => {?LO6, G6},
                                  listen6 => {?LO6, L6}}),
    {ok, Name} = webrtc_mdns:register_name(M, {192, 0, 2, 10}),
    receive {udp, G, _, L6, Ann} -> ?assertMatch({ok, #{answers := [#{name := Name}]}}, ?MSG:decode(Ann))
    after 2000 -> error(no_ipv6_announcement)
    end,
    ok = gen_udp:send(G, ?LO6, L6, ?MSG:encode_query(0, [{Name, aaaa, false}])),
    receive {udp, G, _, L6, R} -> ?assertMatch({ok, #{answers := [#{type := nsec}]}}, ?MSG:decode(R))
    after 2000 -> error(no_ipv6_reply)
    end,
    ok = webrtc_mdns:stop(M),
    gen_udp:close(G).

%% RFC 6762 §11: sources of either family against networks of both.
from_link_test() ->
    Nets = [{{10, 0, 0, 0}, {255, 0, 0, 0}}, {{16#2001, 16#db8, 0, 0, 0, 0, 0, 0}, {16#ffff, 16#ffff, 16#ffff, 16#ffff, 0, 0, 0, 0}}],
    ?assert(webrtc_mdns:from_link({{10, 1, 2, 3}, 5353}, Nets)),
    ?assertNot(webrtc_mdns:from_link({{203, 0, 113, 9}, 5353}, Nets)),
    ?assert(webrtc_mdns:from_link({{16#2001, 16#db8, 0, 0, 1, 2, 3, 4}, 5353}, Nets)),
    ?assertNot(webrtc_mdns:from_link({{16#2001, 16#db9, 0, 0, 1, 2, 3, 4}, 5353}, Nets)),
    %% Link-local IPv6 is on the link.
    ?assert(webrtc_mdns:from_link({{16#fe80, 0, 0, 0, 1, 2, 3, 4}, 5353}, Nets)).

%%--------------------------------------------------------------------
%% Responder, sans-IO
%%--------------------------------------------------------------------

-define(SRC, {{10, 0, 0, 5}, 5353}).

responder() ->
    {ok, Name, R} = ?RS:register({10, 0, 0, 1}, ?RS:new(#{})),
    {Name, R}.

decode_out(Out) -> [{D, element(2, ?MSG:decode(B))} || {D, B} <- Out].

responder_qm_qu_legacy_test() ->
    {Name, R} = responder(),
    {_, Out1} = ?RS:handle_query(?SRC, 5353, ?MSG:encode_query(0, [{Name, a, false}]), 0, R),
    ?assertMatch([{group, #{answers := [#{data := {10, 0, 0, 1}}]}}], decode_out(Out1)),
    {_, Out2} = ?RS:handle_query(?SRC, 5353, ?MSG:encode_query(0, [{Name, a, true}]), 0, R),
    ?assertMatch([{?SRC, #{answers := [_]}}], decode_out(Out2)),
    Legacy = {{10, 0, 0, 5}, 40000},
    {_, Out3} = ?RS:handle_query(Legacy, 5353, ?MSG:encode_query(5, [{Name, any, false}]), 0, R),
    ?assertMatch([{Legacy, #{id := 5, questions := [_], answers := [#{ttl := 10}]}}], decode_out(Out3)).

responder_rate_limit_test() ->
    {Name, R0} = responder(),
    Q = ?MSG:encode_query(0, [{Name, a, false}]),
    {R1, [_]} = ?RS:handle_query(?SRC, 5353, Q, 0, R0),
    %% At most one multicast per second per record (RFC 6762 §6).
    {R2, []} = ?RS:handle_query(?SRC, 5353, Q, 500, R1),
    ?assertMatch({_, [_]}, ?RS:handle_query(?SRC, 5353, Q, 1000, R2)).

responder_ignores_test() ->
    {Name, R} = responder(),
    Ignored = [
        %% other name, a response, garbage
        ?MSG:encode_query(0, [{<<"other.local">>, a, false}]),
        ?MSG:encode_response(0, [], [{Name, {10, 0, 0, 1}, 120, true}], []),
        <<1, 2, 3>>
    ],
    [?assertMatch({_, []}, ?RS:handle_query(?SRC, 5353, B, 0, R)) || B <- Ignored],
    ?assertMatch({_, []}, ?RS:handle_query(?SRC, 5353, ?MSG:encode_query(0, [{Name, a, false}]), 0, ?RS:new(#{}))).

%% RFC 6762 §6.1: a question for the family the name does not have is
%% answered with an NSEC record listing the one it has.
responder_nsec_test() ->
    {Name, R} = responder(),
    {_, Out} = ?RS:handle_query(?SRC, 5353, ?MSG:encode_query(0, [{Name, aaaa, false}]), 0, R),
    [{group, #{answers := [#{name := Name, type := nsec, ttl := 120, data := Rdata}]}}] = decode_out(Out),
    %% Next domain name is the name itself, then window 0 with bit 1 (A).
    {ok, Labels} = ?MSG:name_labels(Name),
    NameWire = iolist_to_binary([[<<(byte_size(L))>>, L] || L <- Labels] ++ [<<0>>]),
    ?assertEqual(<<NameWire/binary, 0, 1, 16#40>>, Rdata),
    {ok, N6, R6} = ?RS:register({16#fe80, 0, 0, 0, 0, 0, 0, 1}, ?RS:new(#{})),
    {_, Out6} = ?RS:handle_query(?SRC, 5353, ?MSG:encode_query(0, [{N6, a, false}]), 0, R6),
    %% AAAA is type 28: window 0, 4 octets, bit 28.
    [{group, #{answers := [#{type := nsec, data := Rdata6}]}}] = decode_out(Out6),
    ?assertEqual(<<0, 4, 0, 0, 0, 16#08>>, binary:part(Rdata6, byte_size(Rdata6), -6)).

responder_known_answer_test() ->
    {Name, R} = responder(),
    %% A query listing our record with enough TTL left (RFC 6762 §7.1).
    Q = ?MSG:encode_query(0, [{Name, a, false}]),
    <<H:6/binary, 0:16, _:32, Body/binary>> = Q,
    {ok, KA} = ?MSG:decode(?MSG:encode_response(0, [], [{Name, {10, 0, 0, 1}, 100, true}], [])),
    [_] = maps:get(answers, KA),
    <<_:12/binary, KARecord/binary>> = ?MSG:encode_response(0, [], [{Name, {10, 0, 0, 1}, 100, true}], []),
    WithKnown = <<H/binary, 1:16, 0:16, 0:16, Body/binary, KARecord/binary>>,
    ?assertMatch({_, []}, ?RS:handle_query(?SRC, 5353, WithKnown, 0, R)).

responder_bounded_test() ->
    R0 = ?RS:new(#{max_names => 2}),
    {ok, _, R1} = ?RS:register({10, 0, 0, 1}, R0),
    {ok, _, R2} = ?RS:register({10, 0, 0, 2}, R1),
    ?assertEqual({error, too_many_names}, ?RS:register({10, 0, 0, 3}, R2)),
    ?assertEqual(2, map_size(?RS:names(R2))),
    ?assertMatch([_], ?RS:goodbye(R2)),
    ?assertEqual([], ?RS:goodbye(R0)).
