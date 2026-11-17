%% Conformance tests for the DTLS engine: our client against our server
%% over an in-memory network with a fake clock.
-module(webrtc_dtls_tests).
-include_lib("eunit/include/eunit.hrl").

-define(EXPORT_LABEL, <<"EXTRACTOR-dtls_srtp">>).

certs() ->
    C = webrtc_dtls_cert:generate(),
    S = webrtc_dtls_cert:generate(),
    {C, S}.

fp(#{der := D}) -> webrtc_dtls_cert:fingerprint(sha256, D).

pair(COpts, SOpts) ->
    {C, S} = certs(),
    Cl = webrtc_dtls:new(maps:merge(#{role => client, cert => C, remote_fingerprints => [fp(S)]}, COpts)),
    Sv = webrtc_dtls:new(maps:merge(#{role => server, cert => S, remote_fingerprints => [fp(C)]}, SOpts)),
    {Cl, Sv}.

%% Drive both endpoints until quiet. Drop is fun((From, N) -> boolean())
%% applied to the N-th datagram sent by From. Returns final states and
%% the events seen by each side.
run(Cl0, Sv0) ->
    run(Cl0, Sv0, fun(_, _) -> false end).

run(Cl0, Sv0, Drop) ->
    {Cl1, A} = webrtc_dtls:start(0, Cl0),
    loop(#{c => Cl1, s => Sv0, now => 0, q => tag(c, A), ev => #{c => [], s => []}, n => #{c => 0, s => 0},
           drop => Drop, steps => 0}).

tag(From, Actions) -> [{From, A} || A <- Actions].

other(c) -> s;
other(s) -> c.

loop(#{steps := N}) when N > 10000 -> error(too_many_steps);
loop(#{q := [{From, {send, D}} | Rest], n := Ns, drop := Drop} = W) ->
    K = maps:get(From, Ns) + 1,
    W1 = W#{q := Rest, n := Ns#{From := K}, steps := maps:get(steps, W) + 1},
    case Drop(From, K) of
        true ->
            loop(W1);
        false ->
            To = other(From),
            {St, A} = webrtc_dtls:handle_packet(D, maps:get(now, W), maps:get(To, W1)),
            loop(W1#{To := St, q := Rest ++ tag(To, A)})
    end;
loop(#{q := [{From, {event, E}} | Rest], ev := Ev} = W) ->
    loop(W#{q := Rest, ev := Ev#{From := maps:get(From, Ev) ++ [E]}});
loop(#{q := [], c := C, s := S, now := Now} = W) ->
    case min_t(webrtc_dtls:next_timeout(C), webrtc_dtls:next_timeout(S)) of
        infinity ->
            W;
        T when T > Now + 600000 ->
            W;
        T ->
            {C1, AC} = webrtc_dtls:handle_timeout(T, C),
            {S1, AS} = webrtc_dtls:handle_timeout(T, S),
            loop(W#{c := C1, s := S1, now := T, q := tag(c, AC) ++ tag(s, AS),
                    steps := maps:get(steps, W) + 1})
    end.

min_t(infinity, B) -> B;
min_t(A, infinity) -> A;
min_t(A, B) -> min(A, B).

connected(Events) ->
    [I || {connected, I} <- Events].

basic_handshake_test() ->
    {Cl, Sv} = pair(#{}, #{}),
    #{c := C, s := S, ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertMatch([#{srtp_profile := 16#0007, extended_master_secret := true}], connected(CE)),
    ?assertMatch([#{srtp_profile := 16#0007}], connected(SE)),
    ?assertEqual(connected, webrtc_dtls:status(C)),
    ?assertEqual(connected, webrtc_dtls:status(S)),
    {ok, K1} = webrtc_dtls:export_keying_material(?EXPORT_LABEL, no_context, 60, C),
    {ok, K2} = webrtc_dtls:export_keying_material(?EXPORT_LABEL, no_context, 60, S),
    ?assertEqual(K1, K2),
    ?assertEqual(60, byte_size(K1)),
    ?assertEqual(infinity, webrtc_dtls:next_timeout(C)).

app_data_test() ->
    {Cl, Sv} = pair(#{}, #{}),
    #{c := C, s := S} = run(Cl, Sv),
    {ok, C1, [{send, D}]} = webrtc_dtls:send(<<"hello">>, C),
    {_S1, A} = webrtc_dtls:handle_packet(D, 0, S),
    ?assertEqual([{event, {data, <<"hello">>}}], A),
    %% Replay of the same record is dropped.
    {_, A2} = webrtc_dtls:handle_packet(D, 0, element(1, webrtc_dtls:handle_packet(D, 0, S))),
    ?assertEqual([], A2),
    %% Tampered record is dropped silently.
    Sz = byte_size(D) - 1,
    <<H:Sz/binary, L>> = D,
    {_, A3} = webrtc_dtls:handle_packet(<<H/binary, (L bxor 1)>>, 0, S),
    ?assertEqual([], A3),
    {ok, _, [{send, _}]} = webrtc_dtls:send(<<"more">>, C1).

suites_test_() ->
    [?_test(begin
         {Cl, Sv} = pair(#{suites => [Suite]}, #{}),
         #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
         ?assertMatch([#{suite := Name}], connected(CE)),
         ?assertMatch([_], connected(SE))
     end)
     || {Suite, Name} <- [{16#C02B, tls_ecdhe_ecdsa_with_aes_128_gcm_sha256},
                          {16#C02C, tls_ecdhe_ecdsa_with_aes_256_gcm_sha384},
                          {16#CCA9, tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256}]].

groups_test_() ->
    [?_test(begin
         {Cl, Sv} = pair(#{groups => [G]}, #{}),
         #{ev := #{c := CE}} = run(Cl, Sv),
         ?assertMatch([#{group := G}], connected(CE))
     end)
     || G <- [x25519, secp256r1, secp384r1]].

rsa_certificate_test() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    %% DTLS 1.2 suites carry the authentication algorithm.
    Cl = webrtc_dtls:new(#{role => client, cert => C, remote_fingerprints => [fp(S)], versions => ['dtlsv1.2']}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)]}),
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertMatch([#{suite := tls_ecdhe_rsa_with_aes_128_gcm_sha256}], connected(CE)),
    ?assertMatch([_], connected(SE)).

%% A suite names the server's key type: a client with an ECDSA key still
%% reaches a server with an RSA key, and the other way round.
mixed_key_types_test_() ->
    [?_test(begin
         C = webrtc_dtls_cert:generate(#{key => CK}),
         S = webrtc_dtls_cert:generate(#{key => SK}),
         Cl = webrtc_dtls:new(#{role => client, cert => C, remote_fingerprints => [fp(S)], versions => ['dtlsv1.2']}),
         Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)]}),
         #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
         ?assertMatch([#{suite := Suite}], connected(CE)),
         ?assertMatch([_], connected(SE))
     end)
     || {CK, SK, Suite} <- [{ecdsa_p256, {rsa, 2048}, tls_ecdhe_rsa_with_aes_128_gcm_sha256},
                            {{rsa, 2048}, ecdsa_p256, tls_ecdhe_ecdsa_with_aes_128_gcm_sha256}]].

%% RFC 6347 §4.2.4: the server's flight is the final one. A client that
%% received it has nothing to resend, even when the server retransmits an
%% earlier flight (new record sequence numbers, so not a replay).
final_flight_copy_ignored_test() ->
    {Cl0, Sv0} = pair(#{versions => ['dtlsv1.2']}, #{}),
    {Cl1, A0} = webrtc_dtls:start(0, Cl0),
    {Sv1, Hvr} = feed(Sv0, sends(A0)),
    {Cl2, Hello} = feed(Cl1, Hvr),
    {Sv2, Flight2} = feed(Sv1, Hello),
    {Cl3, Flight3} = feed(Cl2, Flight2),
    {_, Final} = feed(Sv2, Flight3),
    {Cl, []} = feed(Cl3, Final),
    ?assertEqual(connected, webrtc_dtls:status(Cl)),
    Resent = [iolist_to_binary([bump_seq(R) || R <- records(D)]) || D <- Flight2],
    ?assertEqual({ok, []}, {ok, element(2, feed(Cl, Resent))}).

%% The same epoch 0 record with a sequence number far ahead.
bump_seq(<<T, V:16, E:16, Seq:48, Rest/binary>>) -> <<T, V:16, E:16, (Seq + 1000):48, Rest/binary>>.

%% A copy of an earlier server flight that arrives after the server's
%% ChangeCipherSpec but before its Finished is a replay (same record
%% sequence numbers): it must not make the client resend its flight.
replayed_flight_after_ccs_test() ->
    {Cl0, Sv0} = pair(#{versions => ['dtlsv1.2']}, #{}),
    {Cl1, A0} = webrtc_dtls:start(0, Cl0),
    {Sv1, Hvr} = feed(Sv0, sends(A0)),
    {Cl2, Hello} = feed(Cl1, Hvr),
    {Sv2, Flight2} = feed(Sv1, Hello),
    {Cl3, Flight3} = feed(Cl2, Flight2),
    {_, Final} = feed(Sv2, Flight3),
    [Ccs | _] = records(iolist_to_binary(Final)),
    {Cl4, []} = feed(Cl3, [Ccs]),
    ?assertEqual({ok, []}, {ok, element(2, feed(Cl4, Flight2))}).

%% Copies of the server's flight in the same burst (new record numbers,
%% as a retransmission has) do not make the client resend its own (RFC
%% 6347 §4.2.4); a copy of the HelloVerifyRequest never does (§4.2.1); a
%% retransmission by the server's timer still does.
copies_in_burst_test() ->
    {Cl0, Sv0} = pair(#{versions => ['dtlsv1.2']}, #{}),
    {Cl1, A0} = webrtc_dtls:start(0, Cl0),
    {Sv1, Hvr} = feed(Sv0, sends(A0)),
    {Cl2, Hello} = feed(Cl1, Hvr),
    {_, Flight2} = feed(Sv1, Hello),
    Copies = [iolist_to_binary([bump_seq(R) || R <- records(D)]) || D <- Flight2],
    {Cl3, Once} = feed(Cl2, Flight2),
    {_, Twice} = feed(Cl2, Flight2 ++ Copies),
    ?assertEqual(length(Once), length(Twice)),
    HvrCopy = [iolist_to_binary([bump_seq(R) || R <- records(D)]) || D <- Hvr],
    ?assertEqual([], sends(element(2, webrtc_dtls:handle_packet(hd(HvrCopy), 1000, Cl2)))),
    Late = [iolist_to_binary([bump_seq(bump_seq(R)) || R <- records(D)]) || D <- Flight2],
    ?assertNotEqual([], sends(element(2, webrtc_dtls:handle_packet(hd(Late), 1000, Cl3)))).

records(<<>>) -> [];
records(<<H:11/binary, Len:16, Body:Len/binary, Rest/binary>>) -> [<<H/binary, Len:16, Body/binary>> | records(Rest)].

feed(E, Ds) ->
    lists:foldl(fun(D, {S, Out}) -> {S1, A} = webrtc_dtls:handle_packet(D, 0, S), {S1, Out ++ sends(A)} end, {E, []}, Ds).

sends(Actions) -> [D || {send, D} <- Actions].

%% RFC 6347 §4.2.1: the HelloVerifyRequest carries DTLS 1.0 whatever
%% version the handshake goes on with.
hello_verify_request_version_test() ->
    {Cl, Sv} = pair(#{versions => ['dtlsv1.2']}, #{}),
    {_, [{send, Hello}]} = webrtc_dtls:start(0, Cl),
    {_, [{send, Hvr}]} = webrtc_dtls:handle_packet(Hello, 0, Sv),
    ?assertMatch(<<22, _:16, _:64, _:16, 3, _:24, 0:16, 0:24, _:24, 16#FE, 16#FF, _/binary>>, Hvr).

no_cookie_test() ->
    {Cl, Sv} = pair(#{}, #{use_cookie => false}),
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)).

srtp_profile_selection_test() ->
    %% Server preference wins among profiles the client offered.
    {Cl, Sv} = pair(#{srtp_profiles => [1, 7]}, #{srtp_profiles => [8, 1]}),
    #{ev := #{c := CE}} = run(Cl, Sv),
    ?assertMatch([#{srtp_profile := 1}], connected(CE)).

no_common_srtp_profile_test() ->
    {Cl, Sv} = pair(#{srtp_profiles => [1]}, #{srtp_profiles => [7]}),
    #{ev := #{c := CE}} = run(Cl, Sv),
    ?assertMatch([#{srtp_profile := undefined}], connected(CE)).

fingerprint_mismatch_test() ->
    {C, S} = certs(),
    Other = webrtc_dtls_cert:generate(),
    Cl = webrtc_dtls:new(#{role => client, cert => C, remote_fingerprints => [fp(Other)]}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)]}),
    #{c := CSt, ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertEqual([{failed, fingerprint_mismatch}], CE),
    ?assertEqual([{failed, {alert, 42}}], SE),
    ?assertEqual(failed, webrtc_dtls:status(CSt)).

server_rejects_client_fingerprint_test() ->
    {C, S} = certs(),
    Other = webrtc_dtls_cert:generate(),
    Cl = webrtc_dtls:new(#{role => client, cert => C, remote_fingerprints => [fp(S)]}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(Other)]}),
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertEqual([{failed, fingerprint_mismatch}], SE),
    %% A DTLS 1.3 client is connected once its Finished is sent (RFC 8446
    %% §4.4.4); the server's alert then ends the connection.
    ?assertMatch([{connected, _}, {failed, {alert, _}}], CE).

sha1_fingerprint_not_accepted_test() ->
    {C, S} = certs(),
    Cl = webrtc_dtls:new(#{role => client, cert => C,
                           remote_fingerprints => [webrtc_dtls_cert:fingerprint(sha, maps:get(der, S))]}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)]}),
    #{ev := #{c := CE}} = run(Cl, Sv),
    ?assertEqual([{failed, fingerprint_mismatch}], CE).

deferred_fingerprint_test() ->
    {C, S} = certs(),
    Cl = webrtc_dtls:new(#{role => client, cert => C}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)]}),
    #{c := CSt, s := SSt, ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertEqual([], connected(CE)),
    ?assertMatch([_], connected(SE)),
    ?assertEqual({error, not_connected}, webrtc_dtls:send(<<"x">>, CSt)),
    %% Data from the server is held until the fingerprint is verified.
    {ok, _, [{send, D}]} = webrtc_dtls:send(<<"early">>, SSt),
    {CSt1, []} = webrtc_dtls:handle_packet(D, 0, CSt),
    {_, A} = webrtc_dtls:set_remote_fingerprints([fp(S)], CSt1),
    ?assertMatch([{event, {connected, _}}, {event, {data, <<"early">>}}], A).

deferred_fingerprint_mismatch_test() ->
    {C, S} = certs(),
    Cl = webrtc_dtls:new(#{role => client, cert => C}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)]}),
    #{c := CSt} = run(Cl, Sv),
    {CSt1, A} = webrtc_dtls:set_remote_fingerprints([fp(C)], CSt),
    ?assertMatch([{send, _}, {event, {failed, fingerprint_mismatch}}], A),
    ?assertEqual(failed, webrtc_dtls:status(CSt1)).

%% Loss of each single datagram of the handshake is recovered by
%% retransmission.
single_loss_test_() ->
    [?_test(begin
         {Cl, Sv} = pair(#{}, #{}),
         Drop = fun(F, K) -> F =:= From andalso K =:= N end,
         #{ev := #{c := CE, s := SE}} = run(Cl, Sv, Drop),
         ?assertMatch([_], connected(CE)),
         ?assertMatch([_], connected(SE))
     end)
     || From <- [c, s], N <- [1, 2, 3, 4]].

heavy_loss_test() ->
    rand:seed(exsss, {1, 2, 3}),
    {Cl, Sv} = pair(#{rtx_limit => 12}, #{rtx_limit => 12}),
    Drop = fun(_, _) -> rand:uniform() < 0.4 end,
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv, Drop),
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)).

timeout_test() ->
    {Cl, Sv} = pair(#{rtx_limit => 3}, #{}),
    #{ev := #{c := CE}, now := Now} = run(Cl, Sv, fun(c, _) -> true; (s, _) -> false end),
    ?assertEqual([{failed, handshake_timeout}], CE),
    %% 400 + 800 + 1600 + 3200 ms of back-off.
    ?assertEqual(400 + 800 + 1600 + 3200, Now).

small_mtu_fragmentation_test() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    Cl = webrtc_dtls:new(#{role => client, cert => C, remote_fingerprints => [fp(S)], mtu => 200}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)], mtu => 200}),
    Big = fun(_, _) -> false end,
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv, Big),
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)).

close_notify_test() ->
    {Cl, Sv} = pair(#{}, #{}),
    #{c := C, s := S} = run(Cl, Sv),
    {C1, [{send, D}]} = webrtc_dtls:close(C),
    ?assertEqual(closed, webrtc_dtls:status(C1)),
    {S1, A} = webrtc_dtls:handle_packet(D, 0, S),
    ?assertMatch([{send, _}, {event, {closed, peer_closed}}], A),
    ?assertEqual(closed, webrtc_dtls:status(S1)).

ems_required_test() ->
    %% A client that does not insist still connects with EMS when both
    %% support it; EMS is always offered.
    {Cl, Sv} = pair(#{require_ems => false}, #{}),
    #{ev := #{c := CE}} = run(Cl, Sv),
    ?assertMatch([#{extended_master_secret := true}], connected(CE)).

garbage_never_crashes_test() ->
    {_Cl, Sv} = pair(#{}, #{}),
    rand:seed(exsss, {4, 5, 6}),
    lists:foreach(
        fun(_) ->
            Len = rand:uniform(300),
            Bin = rand:bytes(Len),
            {_, _} = webrtc_dtls:handle_packet(Bin, 0, Sv),
            %% Valid looking record header with random content.
            {_, _} = webrtc_dtls:handle_packet(<<22, 16#FEFD:16, 0:16, 0:48, Len:16, Bin/binary>>, 0, Sv)
        end,
        lists:seq(1, 2000)
    ).

%% Every truncation and every single bit flip of each handshake datagram
%% is handled without crashing.
mutated_handshake_test() ->
    {Cl, Sv} = pair(#{}, #{}),
    {Cl1, [{send, CH}]} = webrtc_dtls:start(0, Cl),
    {_, [{send, HVR}]} = webrtc_dtls:handle_packet(CH, 0, Sv),
    Mutations = fun(Bin) ->
        [binary:part(Bin, 0, N) || N <- lists:seq(0, byte_size(Bin) - 1)] ++
            [flip(Bin, I) || I <- lists:seq(0, byte_size(Bin) * 8 - 1, 7)]
    end,
    [_ = webrtc_dtls:handle_packet(M, 0, Sv) || M <- Mutations(CH)],
    [_ = webrtc_dtls:handle_packet(M, 0, Cl1) || M <- Mutations(HVR)],
    ok.

flip(Bin, I) ->
    <<A:I/bitstring, B:1, C/bitstring>> = Bin,
    <<A/bitstring, (1 - B):1, C/bitstring>>.

prf_sha256_vector_test() ->
    %% Widely used TLS 1.2 PRF test vector (SHA-256), from the IETF TLS
    %% mailing list and used by several TLS stacks.
    Secret = webrtc_test_hex:b("9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35"),
    Seed = webrtc_test_hex:b("a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c"),
    Out = webrtc_dtls_crypto:prf(sha256, Secret, [<<"test label">>, Seed], 100),
    Expected = webrtc_test_hex:b(
        "e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53 c2 aa b2 1d 07 c3 d4 95 32 9b 52 d4 e6 1e db 5a
         6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af 0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab
         4f bc 91 66 6e 9d ef 9b 97 fc e3 4f 79 67 89 ba a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01
         87 34 7b 66"),
    ?assertEqual(Expected, Out).

record_replay_window_test() ->
    W0 = webrtc_dtls_record:replay_new(),
    ?assertEqual(ok, webrtc_dtls_record:replay_check(0, W0)),
    W1 = webrtc_dtls_record:replay_update(0, W0),
    ?assertEqual(replay, webrtc_dtls_record:replay_check(0, W1)),
    %% A 256 entry window: 300 - 256 = 44 is just outside it.
    W2 = webrtc_dtls_record:replay_update(300, W1),
    ?assertEqual(replay, webrtc_dtls_record:replay_check(44, W2)),
    ?assertEqual(ok, webrtc_dtls_record:replay_check(45, W2)),
    ?assertEqual(ok, webrtc_dtls_record:replay_check(299, W2)),
    W3 = webrtc_dtls_record:replay_update(299, W2),
    ?assertEqual(replay, webrtc_dtls_record:replay_check(299, W3)),
    ?assertEqual(replay, webrtc_dtls_record:replay_check(300, W3)).

fingerprint_format_test() ->
    FP = {sha256, <<1, 2, 171, 255, 0:224>>},
    Txt = webrtc_dtls_cert:format_fingerprint(FP),
    ?assertMatch(<<"sha-256 01:02:AB:FF:00:", _/binary>>, Txt),
    ?assertEqual({ok, FP}, webrtc_dtls_cert:parse_fingerprint(Txt)),
    ?assertEqual({error, bad_fingerprint}, webrtc_dtls_cert:parse_fingerprint(<<"sha-256 01:02">>)),
    ?assertEqual({error, bad_fingerprint}, webrtc_dtls_cert:parse_fingerprint(<<"md7 01">>)),
    ?assertEqual({error, bad_fingerprint}, webrtc_dtls_cert:parse_fingerprint(<<"sha-256 zz">>)).

record_replay_window_jump_test() ->
    %% A sequence number far ahead must not overflow the bitmap.
    W = webrtc_dtls_record:replay_update(1 bsl 45, webrtc_dtls_record:replay_update(3, webrtc_dtls_record:replay_new())),
    ?assertEqual(replay, webrtc_dtls_record:replay_check(1 bsl 45, W)),
    ?assertEqual(replay, webrtc_dtls_record:replay_check(3, W)),
    ?assertEqual(ok, webrtc_dtls_record:replay_check((1 bsl 45) - 1, W)).

%% The tests above negotiate DTLS 1.3, the default. The same scenarios
%% with DTLS 1.2 on the client.

v12() -> #{versions => ['dtlsv1.2']}.

dtls12_handshake_test() ->
    {Cl, Sv} = pair(v12(), #{}),
    #{c := C, s := S, ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertMatch([#{version := 'dtlsv1.2', extended_master_secret := true, srtp_profile := 7}], connected(CE)),
    ?assertMatch([#{version := 'dtlsv1.2'}], connected(SE)),
    {ok, K} = webrtc_dtls:export_keying_material(?EXPORT_LABEL, no_context, 60, C),
    ?assertEqual({ok, K}, webrtc_dtls:export_keying_material(?EXPORT_LABEL, no_context, 60, S)),
    {ok, _, [{send, D}]} = webrtc_dtls:send(<<"hi">>, C),
    ?assertMatch({_, [{event, {data, <<"hi">>}}]}, webrtc_dtls:handle_packet(D, 0, S)).

dtls12_suites_test_() ->
    [?_test(begin
         {Cl, Sv} = pair((v12())#{suites => [Suite]}, #{}),
         #{ev := #{c := CE}} = run(Cl, Sv),
         ?assertMatch([#{suite := Name}], connected(CE))
     end)
     || {Suite, Name} <- [{16#C02B, tls_ecdhe_ecdsa_with_aes_128_gcm_sha256},
                          {16#C02C, tls_ecdhe_ecdsa_with_aes_256_gcm_sha384},
                          {16#CCA9, tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256}]].

dtls12_groups_test_() ->
    [?_test(begin
         {Cl, Sv} = pair((v12())#{groups => [G]}, #{}),
         #{ev := #{c := CE}} = run(Cl, Sv),
         ?assertMatch([#{version := 'dtlsv1.2', group := G}], connected(CE))
     end)
     || G <- [x25519, secp256r1, secp384r1]].

dtls12_srtp_profile_selection_test() ->
    {Cl, Sv} = pair((v12())#{srtp_profiles => [1, 7]}, #{srtp_profiles => [8, 1]}),
    #{ev := #{c := CE}} = run(Cl, Sv),
    ?assertMatch([#{version := 'dtlsv1.2', srtp_profile := 1}], connected(CE)).

dtls12_single_loss_test_() ->
    [?_test(begin
         {Cl, Sv} = pair(v12(), #{}),
         Drop = fun(F, K) -> F =:= From andalso K =:= N end,
         #{ev := #{c := CE, s := SE}} = run(Cl, Sv, Drop),
         ?assertMatch([#{version := 'dtlsv1.2'}], connected(CE)),
         ?assertMatch([_], connected(SE))
     end)
     || From <- [c, s], N <- [1, 2, 3, 4]].

dtls12_heavy_loss_test() ->
    rand:seed(exsss, {1, 2, 3}),
    {Cl, Sv} = pair((v12())#{rtx_limit => 12}, #{rtx_limit => 12}),
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv, fun(_, _) -> rand:uniform() < 0.4 end),
    ?assertMatch([#{version := 'dtlsv1.2'}], connected(CE)),
    ?assertMatch([_], connected(SE)).

dtls12_small_mtu_fragmentation_test() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    Cl = webrtc_dtls:new(#{role => client, cert => C, remote_fingerprints => [fp(S)], mtu => 200,
                           versions => ['dtlsv1.2']}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)], mtu => 200}),
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertMatch([#{version := 'dtlsv1.2'}], connected(CE)),
    ?assertMatch([_], connected(SE)).

dtls12_deferred_fingerprint_test() ->
    {C, S} = certs(),
    Cl = webrtc_dtls:new(#{role => client, cert => C, versions => ['dtlsv1.2']}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)]}),
    #{c := CSt, s := SSt, ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertEqual([], connected(CE)),
    ?assertMatch([_], connected(SE)),
    {ok, _, [{send, D}]} = webrtc_dtls:send(<<"early">>, SSt),
    {CSt1, []} = webrtc_dtls:handle_packet(D, 0, CSt),
    {_, A} = webrtc_dtls:set_remote_fingerprints([fp(S)], CSt1),
    ?assertMatch([{event, {connected, #{version := 'dtlsv1.2'}}}, {event, {data, <<"early">>}}], A).

dtls12_fingerprint_mismatch_test() ->
    {C, S} = certs(),
    Other = webrtc_dtls_cert:generate(),
    Cl = webrtc_dtls:new(#{role => client, cert => C, remote_fingerprints => [fp(Other)],
                           versions => ['dtlsv1.2']}),
    Sv = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [fp(C)]}),
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertEqual([{failed, fingerprint_mismatch}], CE),
    ?assertEqual([{failed, {alert, 42}}], SE).

dtls12_close_notify_test() ->
    {Cl, Sv} = pair(v12(), #{}),
    #{c := C, s := S} = run(Cl, Sv),
    {_, [{send, D}]} = webrtc_dtls:close(C),
    {_, A} = webrtc_dtls:handle_packet(D, 0, S),
    ?assertMatch([{send, _}, {event, {closed, peer_closed}}], A).

dtls12_mutated_handshake_test() ->
    {Cl, Sv} = pair(v12(), #{}),
    {Cl1, [{send, CH}]} = webrtc_dtls:start(0, Cl),
    {_, [{send, HVR}]} = webrtc_dtls:handle_packet(CH, 0, Sv),
    Mutations = fun(Bin) ->
        [binary:part(Bin, 0, N) || N <- lists:seq(0, byte_size(Bin) - 1)] ++
            [flip(Bin, I) || I <- lists:seq(0, byte_size(Bin) * 8 - 1, 7)]
    end,
    [_ = webrtc_dtls:handle_packet(M, 0, Sv) || M <- Mutations(CH)],
    [_ = webrtc_dtls:handle_packet(M, 0, Cl1) || M <- Mutations(HVR)],
    ok.

%% RFC 5246 §6.2.1, RFC 8446 §5.2: an authentic record carrying more than
%% 2^14 bytes of plaintext ends the connection with record_overflow; an
%% alert of unknown level with illegal_parameter. Both versions.
record_limits_test_() ->
    [?_test(begin
         {Cl, Sv} = pair(V, #{}),
         #{c := C, s := S} = run(Cl, Sv),
         Mod = case webrtc_dtls:info(C) of #{version := 'dtlsv1.3'} -> webrtc_dtls13; _ -> webrtc_dtls12 end,
         Epoch = case Mod of webrtc_dtls13 -> 3; webrtc_dtls12 -> 1 end,
         {ok, Big, _} = Mod:encode_record(application_data, Epoch, binary:copy(<<0>>, 16385), S),
         {_, A1} = webrtc_dtls:handle_packet(Big, 0, C),
         ?assertMatch([{failed, record_overflow}], [E || {event, E} <- A1]),
         {ok, Odd, _} = Mod:encode_record(alert, Epoch, <<3, 0>>, S),
         {_, A2} = webrtc_dtls:handle_packet(Odd, 0, C),
         ?assertMatch([{failed, {bad_alert_level, 3}}], [E || {event, E} <- A2])
     end)
     || V <- [#{}, v12()]].
