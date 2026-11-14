%% Tests for ICE candidate priorities, foundations, pairing rules and
%% the RFC 8839 candidate attribute.
-module(webrtc_ice_candidate_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_ice.hrl").

-define(C, webrtc_ice_candidate).

priority_test_() ->
    [
        %% Well known values: host / srflx / relay with local preference 65535.
        ?_assertEqual(2130706431, ?C:priority(host, 65535, 1)),
        ?_assertEqual(2130706430, ?C:priority(host, 65535, 2)),
        ?_assertEqual(1694498815, ?C:priority(srflx, 65535, 1)),
        ?_assertEqual(1862270975, ?C:priority(prflx, 65535, 1)),
        ?_assertEqual(16777215, ?C:priority(relay, 65535, 1)),
        ?_assertEqual(255, ?C:priority(relay, 0, 1)),
        ?_assertEqual(0, ?C:priority(relay, 0, 256)),
        ?_assertError(function_clause, ?C:priority(host, 70000, 1)),
        ?_assertError(function_clause, ?C:priority(host, 1, 0)),
        %% RFC 8421 §5 example: host IPv6 with local preference 60000.
        ?_assertEqual(2129289471, ?C:priority(host, 60000, 1))
    ].

type_order_test() ->
    [H, P, S, R] = [?C:type_preference(T) || T <- [host, prflx, srflx, relay]],
    ?assert(H > P andalso P > S andalso S > R).

pair_priority_test_() ->
    [
        ?_assertEqual((5 bsl 32) + 20 + 1, ?C:pair_priority(10, 5)),
        ?_assertEqual((5 bsl 32) + 20, ?C:pair_priority(5, 10)),
        ?_assertEqual((7 bsl 32) + 14, ?C:pair_priority(7, 7)),
        %% Both agents compute the same value for the same pair.
        ?_assertEqual(?C:pair_priority(100, 3, controlling), ?C:pair_priority(3, 100, controlled)),
        ?_assertEqual(?C:pair_priority(3, 100, controlling), ?C:pair_priority(100, 3, controlled)),
        %% 64-bit range for the largest candidate priorities.
        ?_assertEqual(
            ((16#7FFFFFFF) bsl 32) + 2 * 16#7FFFFFFF,
            ?C:pair_priority(16#7FFFFFFF, 16#7FFFFFFF)
        ),
        ?_assert(?C:pair_priority(16#7FFFFFFF, 16#7FFFFFFF) < (1 bsl 64))
    ].

local_preferences_test() ->
    V4 = [{10, 0, 0, N} || N <- [1, 2]],
    V6 = [{16#2001, 16#db8, 0, 0, 0, 0, 0, N} || N <- lists:seq(1, 6)],
    Prefs = ?C:local_preferences(V4 ++ V6),
    Families = [?C:family(IP) || {IP, _} <- Prefs],
    %% RFC 8421 §4: head start of (2 + 6) / 2 = 4 IPv6 addresses.
    ?assertEqual([ipv6, ipv6, ipv6, ipv6, ipv4, ipv6, ipv4, ipv6], Families),
    Values = [P || {_, P} <- Prefs],
    ?assertEqual(lists:reverse(lists:usort(Values)), Values),
    ?assertEqual(65535, hd(Values)),
    %% Order within a family is preserved.
    ?assertEqual(V4, [IP || {IP, _} <- Prefs, ?C:family(IP) =:= ipv4]),
    ?assertEqual(V6, [IP || {IP, _} <- Prefs, ?C:family(IP) =:= ipv6]).

local_preferences_single_family_test() ->
    IPs = [{10, 0, 0, 1}, {10, 0, 0, 2}],
    ?assertEqual([{{10, 0, 0, 1}, 65535}, {{10, 0, 0, 2}, 65527}], ?C:local_preferences(IPs)),
    ?assertEqual([], ?C:local_preferences([])).

local_preference_unique_per_server_test() ->
    Values = [?C:local_preference(R, I) || R <- lists:seq(0, 20), I <- lists:seq(0, 7)],
    ?assertEqual(length(Values), length(lists:usort(Values))).

foundation_test() ->
    F = ?C:foundation(srflx, {10, 0, 0, 1}, {1, 2, 3, 4}, udp),
    ?assertEqual(F, ?C:foundation(srflx, {10, 0, 0, 1}, {1, 2, 3, 4}, udp)),
    Others = [
        ?C:foundation(host, {10, 0, 0, 1}, {1, 2, 3, 4}, udp),
        ?C:foundation(srflx, {10, 0, 0, 2}, {1, 2, 3, 4}, udp),
        ?C:foundation(srflx, {10, 0, 0, 1}, {1, 2, 3, 5}, udp),
        ?C:foundation(srflx, {10, 0, 0, 1}, {1, 2, 3, 4}, tcp)
    ],
    ?assertEqual(5, length(lists:usort([F | Others]))),
    ?assert(byte_size(F) =< 32).

cand(Type, Addr, Port, Base, Prio) ->
    #ice_cand{foundation = <<"1">>, priority = Prio, address = Addr, port = Port, type = Type, base = Base}.

redundant_test() ->
    Host = cand(host, {1, 2, 3, 4}, 5000, {{1, 2, 3, 4}, 5000}, 2000),
    %% Not behind a NAT: the server-reflexive candidate equals the host.
    Srflx = cand(srflx, {1, 2, 3, 4}, 5000, {{1, 2, 3, 4}, 5000}, 1000),
    Other = cand(srflx, {9, 9, 9, 9}, 5000, {{1, 2, 3, 4}, 5000}, 1000),
    %% Same address, different base: not redundant.
    Host2 = cand(host, {1, 2, 3, 4}, 5000, {{1, 2, 3, 4}, 6000}, 1500),
    ?assertEqual([Host, Host2, Other], ?C:eliminate_redundant([Srflx, Host, Other, Host2])),
    ?assert(?C:is_redundant(Srflx, [Host])),
    ?assertNot(?C:is_redundant(Other, [Host])).

can_pair_test_() ->
    V4 = cand(host, {10, 0, 0, 1}, 1, undefined, 1),
    V6 = cand(host, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 1, undefined, 1),
    LL = cand(host, {16#fe80, 0, 0, 0, 0, 0, 0, 1}, 1, undefined, 1),
    [
        ?_assert(?C:can_pair(V4, V4)),
        ?_assertNot(?C:can_pair(V4, V6)),
        ?_assert(?C:can_pair(V6, V6)),
        ?_assertNot(?C:can_pair(LL, V6)),
        ?_assertNot(?C:can_pair(V6, LL)),
        ?_assert(?C:can_pair(LL, LL)),
        ?_assertNot(?C:can_pair(V4, V4#ice_cand{component = 2})),
        ?_assertNot(?C:can_pair(V4, V4#ice_cand{transport = tcp})),
        ?_assert(?C:is_link_local({169, 254, 1, 1}))
    ].

sdp_roundtrip_test_() ->
    Host = #ice_cand{foundation = <<"1">>, priority = 2130706431, address = {192, 0, 2, 1},
                     port = 5000, type = host},
    Srflx = Host#ice_cand{foundation = <<"abc+/">>, type = srflx, address = {198, 51, 100, 7},
                          priority = 1694498815, related_address = {192, 0, 2, 1}, related_port = 5000,
                          extensions = [{<<"generation">>, <<"0">>}, {<<"ufrag">>, <<"8hhY">>}]},
    V6 = Host#ice_cand{address = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, component = 2},
    Tcp = Host#ice_cand{transport = tcp, tcptype = passive, port = 9},
    [?_assertEqual({ok, C}, ?C:from_sdp(?C:to_sdp(C))) || C <- [Host, Srflx, V6, Tcp]] ++
        [?_assertEqual(<<"candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host">>, ?C:to_sdp(Host))].

sdp_parse_test_() ->
    [
        %% RFC 8838 §9 example.
        ?_assertMatch(
            {ok, #ice_cand{foundation = <<"1">>, component = 1, transport = udp, priority = 2130706431,
                           address = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, port = 5000, type = host,
                           extensions = [{<<"ufrag">>, <<"8hhY">>}]}},
            ?C:from_sdp(<<"a=candidate:1 1 UDP 2130706431 2001:db8::1 5000 typ host ufrag 8hhY">>)
        ),
        ?_assertMatch({ok, #ice_cand{type = relay, related_address = {1, 2, 3, 4}, related_port = 9}},
                      ?C:from_sdp("candidate:2 1 udp 16777215 5.6.7.8 7000 typ relay raddr 1.2.3.4 rport 9")),
        ?_assertMatch({ok, #ice_cand{type = prflx}}, ?C:from_sdp(<<"3 1 udp 1 1.1.1.1 1 typ prflx">>)),
        ?_assertEqual({error, {fqdn, <<"abc.local">>}},
                      ?C:from_sdp(<<"candidate:1 1 udp 1 abc.local 1 typ host">>)),
        ?_assertEqual({error, bad_candidate}, ?C:from_sdp(<<"candidate:1 1 udp 1 1.1.1.1 1">>)),
        ?_assertEqual({error, bad_candidate}, ?C:from_sdp(<<>>)),
        ?_assertMatch({error, {bad_integer, _}}, ?C:from_sdp(<<"1 0 udp 1 1.1.1.1 1 typ host">>)),
        ?_assertMatch({error, {bad_integer, _}}, ?C:from_sdp(<<"1 1 udp 0 1.1.1.1 1 typ host">>)),
        ?_assertMatch({error, {bad_integer, _}}, ?C:from_sdp(<<"1 1 udp 1 1.1.1.1 70000 typ host">>)),
        ?_assertMatch({error, {unsupported_transport, _}}, ?C:from_sdp(<<"1 1 sctp 1 1.1.1.1 1 typ host">>)),
        ?_assertMatch({error, {bad_type, _}}, ?C:from_sdp(<<"1 1 udp 1 1.1.1.1 1 typ cool">>)),
        ?_assertEqual({error, bad_foundation}, ?C:from_sdp(<<"f-1 1 udp 1 1.1.1.1 1 typ host">>)),
        ?_assertEqual({error, bad_extension}, ?C:from_sdp(<<"1 1 udp 1 1.1.1.1 1 typ host generation">>))
    ].

credentials_test_() ->
    [
        ?_assert(?C:valid_ufrag(<<"abcd">>)),
        ?_assertNot(?C:valid_ufrag(<<"abc">>)),
        ?_assertNot(?C:valid_ufrag(<<"ab:d">>)),
        ?_assertNot(?C:valid_ufrag(binary:copy(<<"a">>, 257))),
        ?_assert(?C:valid_pwd(<<"aaaaaaaaaaaaaaaaaaaa+/">>)),
        ?_assertNot(?C:valid_pwd(<<"aaaaaaaaaaaaaaaaaaaaa">>)),
        ?_assertNot(?C:valid_pwd(not_a_binary)),
        ?_assert(lists:all(fun(_) -> ?C:valid_ufrag(?C:random_ufrag()) end, lists:seq(1, 50))),
        ?_assert(lists:all(fun(_) -> ?C:valid_pwd(?C:random_pwd()) end, lists:seq(1, 50))),
        ?_assertNotEqual(?C:random_pwd(), ?C:random_pwd())
    ].
