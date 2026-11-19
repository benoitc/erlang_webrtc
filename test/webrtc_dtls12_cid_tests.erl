%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% DTLS 1.2 connection IDs (RFC 9146): the record format, the hello
%% negotiation and records carrying the peer's CID.
-module(webrtc_dtls12_cid_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("webrtc/src/dtls/webrtc_dtls.hrl").

-define(R, webrtc_dtls_record).

v12(Opts) -> Opts#{versions => ['dtlsv1.2']}.

fp(#{der := D}) -> webrtc_dtls_cert:fingerprint(sha256, D).

pair(COpts, SOpts) ->
    C = webrtc_dtls_cert:generate(),
    S = webrtc_dtls_cert:generate(),
    {webrtc_dtls:new(maps:merge(#{role => client, cert => C, remote_fingerprints => [fp(S)]}, COpts)),
     webrtc_dtls:new(maps:merge(#{role => server, cert => S, remote_fingerprints => [fp(C)]}, SOpts))}.

established(COpts, SOpts) ->
    {C, S} = pair(COpts, SOpts),
    #{c := Cs, s := Ss, ev := #{c := CE, s := SE}} = webrtc_dtls_sim:run(C, S),
    ?assertMatch([_], webrtc_dtls_sim:connected(CE)),
    ?assertMatch([_], webrtc_dtls_sim:connected(SE)),
    {Cs, Ss}.

data(From, To, Msg) ->
    {ok, From1, [{send, D}]} = webrtc_dtls:send(Msg, From),
    {To1, A} = webrtc_dtls:handle_packet(D, 100, To),
    ?assertEqual([{event, {data, Msg}}], A),
    {From1, To1, D}.

%% The CID of a datagram's first record: `none' for the plain format.
record_cid(<<25, _:10/binary, Rest/binary>>, Len) -> binary:part(Rest, 0, Len);
record_cid(<<_, _/binary>>, _Len) -> none.

cipher(C) -> ?R:new_cipher(element(2, webrtc_dtls_crypto:suite(C)), crypto:strong_rand_bytes(key_len(C)), iv(C)).
key_len(16#C02B) -> 16; key_len(16#C02C) -> 32; key_len(16#CCA9) -> 32.
iv(16#CCA9) -> crypto:strong_rand_bytes(12);
iv(_) -> crypto:strong_rand_bytes(4).

%%====================================================================
%% Record format (RFC 9146 §4, §5)
%%====================================================================

record_round_trip_test_() ->
    [fun() ->
         K = cipher(Suite),
         Rec = ?R:protect(application_data, 16#FEFD, 1, 7, <<"hello">>, K, <<"abcdefgh">>),
         <<25, 16#FEFD:16, 1:16, 7:48, "abcdefgh", Len:16, Body/binary>> = Rec,
         ?assertEqual(Len, byte_size(Body)),
         [R] = ?R:decode(Rec, 8),
         ?assertMatch(#{type := tls12_cid, cid := <<"abcdefgh">>}, R),
         ?assertEqual({ok, application_data, <<"hello">>}, ?R:open(R, K)),
         ?assertEqual(byte_size(Rec) - 5, ?R:overhead(K, <<"abcdefgh">>))
     end || Suite <- [16#C02B, 16#C02C, 16#CCA9]].

%% The CID is authenticated, and a record with it does not parse without
%% the CID length.
tampered_cid_test() ->
    K = cipher(16#C02B),
    <<H:11/binary, _:4/binary, Rest/binary>> = ?R:protect(handshake, 16#FEFD, 1, 0, <<"x">>, K, <<"abcd">>),
    [R] = ?R:decode(<<H/binary, "abce", Rest/binary>>, 4),
    ?assertEqual({error, bad_record_mac}, ?R:open(R, K)),
    ?assertEqual([], ?R:decode(<<H/binary, "abcd", Rest/binary>>)).

%% No CID or an empty one: the plain format.
plain_without_cid_test() ->
    K = cipher(16#C02B),
    ?assertEqual(?R:protect(alert, 16#FEFD, 1, 3, <<1, 0>>, K),
                 ?R:protect(alert, 16#FEFD, 1, 3, <<1, 0>>, K, <<>>)).

%%====================================================================
%% Handshake (RFC 9146 §3)
%%====================================================================

%% Both sides want one: each sends the other's CID once keys are in use.
negotiated_test() ->
    {C, S} = established(v12(#{connection_id => <<"client-cid">>}), v12(#{connection_id => <<"srv">>})),
    ?assertMatch(#{version := 'dtlsv1.2', connection_id := true}, webrtc_dtls:info(C)),
    ?assertMatch(#{connection_id := true}, webrtc_dtls:info(S)),
    {C1, S1, D1} = data(C, S, <<"to server">>),
    ?assertEqual(<<"srv">>, record_cid(D1, 3)),
    {_, _, D2} = data(S1, C1, <<"to client">>),
    ?assertEqual(<<"client-cid">>, record_cid(D2, 10)).

%% The server does not want one: plain records both ways.
refused_test() ->
    {C, S} = established(v12(#{connection_id => true}), v12(#{})),
    ?assertMatch(#{connection_id := false}, webrtc_dtls:info(C)),
    {C1, S1, D1} = data(C, S, <<"x">>),
    ?assertEqual(none, record_cid(D1, 8)),
    {_, _, D2} = data(S1, C1, <<"y">>),
    ?assertEqual(none, record_cid(D2, 8)).

%% A zero-length CID: the client sends with the server's CID but asks
%% for plain records itself.
zero_length_test() ->
    {C, S} = established(v12(#{connection_id => <<>>}), v12(#{connection_id => <<"srv1">>})),
    {C1, S1, D1} = data(C, S, <<"x">>),
    ?assertEqual(<<"srv1">>, record_cid(D1, 4)),
    {_, _, D2} = data(S1, C1, <<"y">>),
    ?assertEqual(none, record_cid(D2, 4)).

%% A client offering DTLS 1.3 and 1.2 with a CID against a DTLS 1.2
%% server that echoes the extension (it aborted with
%% unsolicited_extension before).
both_versions_offered_test() ->
    {C, S} = established(#{connection_id => <<"cccc">>}, v12(#{connection_id => <<"ssss">>})),
    ?assertMatch(#{version := 'dtlsv1.2', connection_id := true}, webrtc_dtls:info(C)),
    {_, _, D} = data(C, S, <<"x">>),
    ?assertEqual(<<"ssss">>, record_cid(D, 4)).

%% A record with a CID we do not receive on is dropped.
unknown_cid_dropped_test() ->
    {C, S} = established(v12(#{connection_id => <<"cccc">>}), v12(#{connection_id => <<"ssss">>})),
    {ok, _, [{send, <<H:11/binary, _:4/binary, Rest/binary>>}]} = webrtc_dtls:send(<<"x">>, S),
    ?assertEqual({C, []}, webrtc_dtls:handle_packet(<<H/binary, "zzzz", Rest/binary>>, 100, C)).

%% Handshake records with a long CID still fit the MTU.
mtu_with_cid_test() ->
    Cid = binary:copy(<<"c">>, 32),
    {C, S} = pair(v12(#{connection_id => Cid, mtu => 300}), v12(#{connection_id => Cid, mtu => 300})),
    #{ev := #{c := CE}} = W = webrtc_dtls_sim:run(C, S),
    ?assertMatch([_], webrtc_dtls_sim:connected(CE)),
    Sizes = [byte_size(D) || {_, D, _} <- webrtc_dtls_sim:sent(W, c) ++ webrtc_dtls_sim:sent(W, s)],
    ?assert(lists:all(fun(N) -> N =< 300 end, Sizes)).
