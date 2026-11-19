%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for the standalone candidate codec (RFC 8839 §5.1, RFC 6544).
-module(webrtc_sdp_candidate_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_sdp.hrl").

-define(C, webrtc_sdp_candidate).

chrome_srflx() ->
    <<"842163049 1 udp 1677729535 198.51.100.7 46154 typ srflx raddr 10.0.0.5 rport 46154 "
      "generation 0 ufrag EsAw network-id 1 network-cost 10">>.

forms_test() ->
    V = chrome_srflx(),
    {ok, C} = ?C:parse(V),
    ?assertEqual({ok, C}, ?C:parse(<<"candidate:", V/binary>>)),
    ?assertEqual({ok, C}, ?C:parse(<<"a=candidate:", V/binary>>)),
    ?assertEqual(V, ?C:encode(C)),
    ?assertEqual(<<"candidate:", V/binary>>, ?C:encode_attr(C)).

fields_test() ->
    {ok, C} = ?C:parse(chrome_srflx()),
    ?assertEqual(
        #sdp_candidate{
            foundation = <<"842163049">>,
            component = 1,
            transport = <<"udp">>,
            priority = 1677729535,
            address = {198, 51, 100, 7},
            port = 46154,
            type = srflx,
            raddr = {10, 0, 0, 5},
            rport = 46154,
            extensions = [
                {<<"generation">>, <<"0">>},
                {<<"ufrag">>, <<"EsAw">>},
                {<<"network-id">>, <<"1">>},
                {<<"network-cost">>, <<"10">>}
            ]
        },
        C
    ),
    ?assertEqual({ok, <<"1">>}, ?C:extension(<<"network-id">>, C)),
    ?assertEqual(error, ?C:extension(<<"tcptype">>, C)).

roundtrip_test_() ->
    Samples = [
        <<"0 1 UDP 2122252543 192.168.1.2 54321 typ host">>,
        <<"2 1 TCP 2105524479 192.168.1.2 9 typ host tcptype active">>,
        <<"3 1 tcp 1518280447 192.168.1.2 50000 typ host tcptype so generation 0">>,
        <<"4 1 udp 2122262783 2001:db8::1 56143 typ host generation 0 network-id 2">>,
        <<"5 1 udp 2122194687 0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0.local 54401 typ host generation 0">>,
        <<"6 1 udp 1686052607 198.51.100.7 54400 typ srflx raddr 0.0.0.0 rport 0">>,
        <<"7 2 udp 41885438 203.0.113.5 61002 typ relay raddr 198.51.100.7 rport 54400">>,
        <<"8 1 udp 1845501695 198.51.100.7 54400 typ prflx">>,
        <<"a+/Z 1 udp 1 192.0.2.1 1 typ host">>,
        <<"9 1 udp 100 192.0.2.1 3478 typ relay rport 1">>,
        <<"10 256 udp 2147483647 ::1 65535 typ host">>
    ],
    [
        {binary_to_list(S), fun() ->
            {ok, C} = ?C:parse(S),
            ?assertEqual(S, ?C:encode(C))
        end}
     || S <- Samples
    ].

unknown_type_and_transport_test() ->
    {ok, C} = ?C:parse(<<"1 1 sctp 5 192.0.2.1 5000 typ future x y">>),
    ?assertEqual(<<"sctp">>, C#sdp_candidate.transport),
    ?assertEqual(<<"future">>, C#sdp_candidate.type),
    ?assertEqual([{<<"x">>, <<"y">>}], C#sdp_candidate.extensions).

mdns_test() ->
    {ok, C} = ?C:parse(<<"1 1 udp 5 abcd.LOCAL 5000 typ host">>),
    ?assert(?C:is_mdns(C)),
    {ok, H} = ?C:parse(<<"1 1 udp 5 turn.example.com 5000 typ host">>),
    ?assertNot(?C:is_mdns(H)),
    ?assertEqual(<<"turn.example.com">>, H#sdp_candidate.address).

errors_test_() ->
    Cases = [
        {<<"">>, missing_fields},
        {<<"1 1 udp 1 192.0.2.1 1">>, missing_fields},
        {<<"1 1 udp 1 192.0.2.1 1 typ">>, missing_fields},
        {<<"1  1 udp 1 192.0.2.1 1 typ host">>, bad_spacing},
        {<<"1 1 udp 1 192.0.2.1 1 typ host ">>, bad_spacing},
        {<<"1 1 udp 1 192.0.2.1 1 host x">>, missing_fields},
        {<<"1 0 udp 1 192.0.2.1 1 typ host">>, component},
        {<<"1 257 udp 1 192.0.2.1 1 typ host">>, component},
        {<<"1 0001 udp 1 192.0.2.1 1 typ host">>, component},
        {<<"1 x udp 1 192.0.2.1 1 typ host">>, component},
        {<<"1 1 udp 0 192.0.2.1 1 typ host">>, priority},
        {<<"1 1 udp 2147483648 192.0.2.1 1 typ host">>, priority},
        {<<"1 1 udp -1 192.0.2.1 1 typ host">>, priority},
        {<<"1 1 udp 1 192.0.2.1 65536 typ host">>, port},
        {<<"1 1 udp 1 192.0.2.1 x typ host">>, port},
        {<<"1 1 u(p 1 192.0.2.1 1 typ host">>, transport},
        {<<"1 1 udp 1 192.0.2.256 1 typ host">>, address},
        {<<"1 1 udp 1 2001:db8::zz 1 typ host">>, address},
        {<<"1 1 udp 1 fe80::1%eth0 1 typ host">>, address},
        {<<"1 1 udp 1 a_b.local 1 typ host">>, address},
        {<<"1 1 udp 1 abc 1 typ host">>, address},
        {<<"1 1 udp 1 192.0.2.1 1 typ ho(st">>, type},
        {<<"1-2 1 udp 1 192.0.2.1 1 typ host">>, foundation},
        {<<"123456789012345678901234567890123 1 udp 1 192.0.2.1 1 typ host">>, foundation},
        {<<"1 1 udp 1 192.0.2.1 1 typ srflx raddr x_y rport 1">>, raddr},
        {<<"1 1 udp 1 192.0.2.1 1 typ srflx raddr 10.0.0.1 rport 99999">>, rport},
        {<<"1 1 udp 1 192.0.2.1 1 typ host generation 0 raddr 10.0.0.1">>, misplaced_raddr},
        {<<"1 1 udp 1 192.0.2.1 1 typ host generation 0 rport 1">>, misplaced_rport},
        {<<"1 1 udp 1 192.0.2.1 1 typ host generation">>, odd_extension},
        {<<"1 1 tcp 1 192.0.2.1 9 typ host tcptype both">>, tcptype},
        {<<"1 1 tcp 1 192.0.2.1 9 typ host tcptype active tcptype so">>, duplicate_tcptype},
        {<<"1 1 udp 1 192.0.2.1 1 typ host gen\x7f 0">>, extension_name}
    ],
    [
        {binary_to_list(V), fun() -> ?assertEqual({error, Why}, ?C:parse(V)) end}
     || {V, Why} <- Cases
    ].

encode_validation_test() ->
    {ok, C} = ?C:parse(chrome_srflx()),
    ?assertError({invalid_sdp, _}, ?C:encode(C#sdp_candidate{component = 0})),
    ?assertError({invalid_sdp, _}, ?C:encode(C#sdp_candidate{priority = 0})),
    ?assertError({invalid_sdp, _}, ?C:encode(C#sdp_candidate{foundation = <<"a b">>})),
    ?assertError({invalid_sdp, _}, ?C:encode(C#sdp_candidate{extensions = [{<<"x">>, <<"a b">>}]})),
    ?assertError({invalid_sdp, _}, ?C:encode(C#sdp_candidate{address = <<"x\r\n">>})),
    ?assertError({invalid_sdp, _}, ?C:encode(C#sdp_candidate{port = 70000})).

%% inet:ntoa/1 writes a zone for link-local IPv6 addresses; the SDP
%% form has none and parses back to the same address.
link_local_ipv6_test() ->
    {ok, C} = webrtc_sdp_candidate:parse(<<"candidate:a 1 udp 1 fe80::1 9 typ host">>),
    Addr = {16#fe80, 1, 0, 0, 0, 0, 0, 0},
    Bin = webrtc_sdp_candidate:encode(C#sdp_candidate{address = Addr}),
    ?assertEqual(nomatch, binary:match(Bin, <<"%">>)),
    ?assertMatch({ok, #sdp_candidate{address = Addr}}, webrtc_sdp_candidate:parse(Bin)).
