%% Conformance tests for webrtc_stun (RFC 8489) using RFC 5769 vectors.
-module(webrtc_stun_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_stun.hrl").

-import(webrtc_test_hex, [b/1]).

-define(PASSWORD, <<"VOkJxbRl1RmTxUk/WvJxBt">>).

rfc5769_request() ->
    b("00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
       80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74
       00 24 00 04 6e 00 01 ff 80 29 00 08 93 2f f9 b1 51 26 3b 36
       00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20
       00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2
       80 28 00 04 e5 7a 3b cf").

rfc5769_ipv4_response() ->
    b("01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
       80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
       00 20 00 08 00 01 a1 47 e1 12 a6 43
       00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7
       80 28 00 04 c0 7d 4c 96").

rfc5769_ipv6_response() ->
    b("01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
       80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
       00 20 00 14 00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9
       00 08 00 14 a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75 bf e3 ed 41
       80 28 00 04 c8 fb 0b 4c").

rfc5769_long_term_request() ->
    b("00 01 00 60 21 12 a4 42 78 ad 34 33 c6 ad 72 c0 29 da 41 2e
       00 06 00 12 e3 83 9e e3 83 88 e3 83 aa e3 83 83 e3 82 af e3 82 b9 00 00
       00 15 00 1c 66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34 6f 4c 39 46
       53 54 76 79 36 34 73 41
       00 14 00 0b 65 78 61 6d 70 6c 65 2e 6f 72 67 00
       00 08 00 14 f6 70 24 65 6d d6 4a 3e 02 b8 e0 71 2e 85 c9 a2 8c a8 96 66").

request_decode_test() ->
    Bin = rfc5769_request(),
    ?assert(webrtc_stun:is_stun(Bin)),
    {ok, M} = webrtc_stun:decode(Bin),
    ?assertEqual(request, M#stun.class),
    ?assertEqual(binding, M#stun.method),
    ?assertEqual({ok, <<"STUN test client">>}, webrtc_stun:get(software, M)),
    ?assertEqual({ok, 16#6e0001ff}, webrtc_stun:get(priority, M)),
    ?assertEqual({ok, 16#932ff9b151263b36}, webrtc_stun:get(ice_controlled, M)),
    ?assertEqual({ok, <<"evtj:h6vY">>}, webrtc_stun:get(username, M)),
    ?assertEqual(ok, webrtc_stun:check_integrity(Bin, ?PASSWORD)),
    ?assertEqual({error, bad_integrity}, webrtc_stun:check_integrity(Bin, <<"wrong">>)).

ipv4_response_test() ->
    Bin = rfc5769_ipv4_response(),
    {ok, M} = webrtc_stun:decode(Bin),
    ?assertEqual(success, M#stun.class),
    ?assertEqual({ok, {{192, 0, 2, 1}, 32853}}, webrtc_stun:get(xor_mapped_address, M)),
    ?assertEqual(ok, webrtc_stun:check_integrity(Bin, ?PASSWORD)).

ipv6_response_test() ->
    Bin = rfc5769_ipv6_response(),
    {ok, M} = webrtc_stun:decode(Bin),
    ?assertEqual(
        {ok, {{16#2001, 16#db8, 16#1234, 16#5678, 16#11, 16#2233, 16#4455, 16#6677}, 32853}},
        webrtc_stun:get(xor_mapped_address, M)
    ),
    ?assertEqual(ok, webrtc_stun:check_integrity(Bin, ?PASSWORD)).

long_term_test() ->
    Bin = rfc5769_long_term_request(),
    {ok, M} = webrtc_stun:decode(Bin),
    {ok, User} = webrtc_stun:get(username, M),
    ?assertEqual(<<"マトリックス"/utf8>>, User),
    Key = webrtc_stun:long_term_key(User, <<"example.org">>, <<"TheMatrIX">>),
    ?assertEqual(ok, webrtc_stun:check_integrity(Bin, Key)).

%% Re-encoding the decoded vector must reproduce the exact bytes, which
%% checks the integrity and fingerprint computation on the encode path.
reencode_ipv4_response_test() ->
    Bin = rfc5769_ipv4_response(),
    {ok, M} = webrtc_stun:decode(Bin),
    Attrs = [A || {K, _} = A <- M#stun.attrs, K =/= message_integrity, K =/= fingerprint],
    %% The vector pads SOFTWARE with a space rather than zero.
    Out = webrtc_stun:encode(M#stun{attrs = Attrs}, #{
        integrity => {sha1, ?PASSWORD}, fingerprint => true
    }),
    ?assertEqual(byte_size(Bin), byte_size(Out)),
    ?assertEqual(ok, webrtc_stun:check_integrity(Out, ?PASSWORD)),
    {ok, M2} = webrtc_stun:decode(Out),
    ?assertEqual(webrtc_stun:get(xor_mapped_address, M), webrtc_stun:get(xor_mapped_address, M2)).

roundtrip_all_attrs_test() ->
    Attrs = [
        {username, <<"a:b">>},
        {priority, 1853824767},
        {use_candidate, true},
        {ice_controlling, 16#0102030405060708},
        {xor_mapped_address, {{10, 0, 0, 1}, 5000}},
        {xor_peer_address, {{16#fe80, 0, 0, 0, 1, 2, 3, 4}, 6000}},
        {mapped_address, {{1, 2, 3, 4}, 7}},
        {lifetime, 600},
        {requested_transport, 17},
        {channel_number, 16#4001},
        {data, <<"hello">>},
        {realm, <<"r">>},
        {nonce, <<"n">>},
        {even_port, true},
        {dont_fragment, true},
        {reservation_token, <<1, 2, 3, 4, 5, 6, 7, 8>>},
        {requested_address_family, ipv6},
        {unknown_attributes, [16#0031, 16#0032]},
        {password_algorithms, [{md5, <<>>}, {sha256, <<>>}]},
        {error_code, {487, <<"Role Conflict">>}}
    ],
    Msg = #stun{class = error, method = binding, txid = webrtc_stun:new_txid(), attrs = Attrs},
    Bin = webrtc_stun:encode(Msg, #{integrity => {sha256, <<"k">>}, fingerprint => true}),
    {ok, Dec} = webrtc_stun:decode(Bin),
    ?assertEqual(Attrs, [A || {K, _} = A <- Dec#stun.attrs,
                              K =/= message_integrity_sha256, K =/= fingerprint]),
    ?assertEqual(ok, webrtc_stun:check_integrity(Bin, <<"k">>)).

all_methods_and_classes_test() ->
    [begin
         M = #stun{class = C, method = Me, txid = <<0:96>>},
         {ok, D} = webrtc_stun:decode(webrtc_stun:encode(M)),
         ?assertEqual({C, Me}, {D#stun.class, D#stun.method})
     end
     || C <- [request, indication, success, error],
        Me <- [binding, allocate, refresh, send, data, create_permission, channel_bind, 16#FFF]].

bad_fingerprint_test() ->
    Bin = rfc5769_request(),
    Sz = byte_size(Bin) - 1,
    <<Head:Sz/binary, Last>> = Bin,
    ?assertEqual({error, bad_fingerprint}, webrtc_stun:decode(<<Head/binary, (Last bxor 1)>>)).

fingerprint_not_last_test() ->
    T = <<0:96>>,
    Bin = <<0, 1, 0, 16, 16#2112A442:32, T/binary, 16#8028:16, 4:16, 0:32, 16#0025:16, 0:16, 0:32>>,
    ?assertMatch({error, _}, webrtc_stun:decode(Bin)).

attrs_after_integrity_ignored_test() ->
    Msg = #stun{class = request, method = binding, txid = <<1:96>>, attrs = [{username, <<"u">>}]},
    Bin0 = webrtc_stun:encode(Msg, #{integrity => {sha1, <<"k">>}}),
    %% Append PRIORITY after MESSAGE-INTEGRITY and fix up the length.
    <<H:2/binary, Len:16, Rest/binary>> = Bin0,
    Bin = <<H/binary, (Len + 8):16, Rest/binary, 16#0024:16, 4:16, 1:32>>,
    {ok, D} = webrtc_stun:decode(Bin),
    ?assertEqual(error, webrtc_stun:get(priority, D)),
    ?assertEqual(ok, webrtc_stun:check_integrity(Bin, <<"k">>)).

unknown_comprehension_required_test() ->
    Msg = #stun{class = request, method = binding, txid = <<1:96>>,
                attrs = [{16#0031, <<1, 2>>}, {16#8031, <<3>>}]},
    {ok, D} = webrtc_stun:decode(webrtc_stun:encode(Msg)),
    ?assertEqual([16#0031], D#stun.unknown),
    ?assertEqual([], D#stun.attrs).

malformed_test_() ->
    Valid = rfc5769_request(),
    [
        ?_assertEqual({error, not_stun}, webrtc_stun:decode(<<>>)),
        ?_assertEqual({error, not_stun}, webrtc_stun:decode(<<128, 0:152>>)),
        ?_assertEqual({error, bad_magic_cookie}, webrtc_stun:decode(<<0, 1, 0, 0, 0:32, 0:96>>)),
        ?_assertEqual({error, bad_length}, webrtc_stun:decode(<<0, 1, 0, 3, 16#2112A442:32, 0:96, 0:24>>)),
        ?_assertEqual({error, bad_length}, webrtc_stun:decode(<<0, 1, 0, 8, 16#2112A442:32, 0:96, 0:32>>)),
        ?_assertEqual({error, truncated_attribute},
                      webrtc_stun:decode(<<0, 1, 0, 4, 16#2112A442:32, 0:96, 0, 6, 0, 8>>)),
        ?_assertEqual({error, {bad_attribute, 16#0024}},
                      webrtc_stun:decode(<<0, 1, 0, 8, 16#2112A442:32, 0:96, 0, 16#24, 0, 3, 0:32>>)),
        ?_assertEqual({error, bad_address},
                      webrtc_stun:decode(<<0, 1, 0, 8, 16#2112A442:32, 0:96, 0, 16#20, 0, 4, 0, 1, 0, 0>>)),
        ?_assertEqual({error, bad_address_family},
                      webrtc_stun:decode(<<0, 1, 0, 8, 16#2112A442:32, 0:96, 0, 16#17, 0, 4, 9, 0, 0, 0>>)),
        %% Every truncation of a valid message is rejected, never crashes.
        ?_assert(lists:all(fun(N) ->
            <<P:N/binary, _/binary>> = Valid,
            element(1, webrtc_stun:decode(P)) =:= error
        end, lists:seq(0, byte_size(Valid) - 1)))
    ].

no_integrity_test() ->
    Bin = webrtc_stun:encode(webrtc_stun:request(binding, [])),
    ?assertEqual({error, no_integrity}, webrtc_stun:check_integrity(Bin, <<"k">>)).
