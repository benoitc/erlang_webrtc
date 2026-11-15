%% Conformance tests for DTLS 1.3 (RFC 9147): our client against our
%% server over an in-memory network with a fake clock, plus unit tests
%% of the key schedule (RFC 8448 vectors), record layer, ACK codec and
%% stateless cookie.
-module(webrtc_dtls13_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("webrtc/src/dtls/webrtc_dtls.hrl").

-define(LABEL, <<"EXTRACTOR-dtls_srtp">>).
-define(T13, <<"tls13 ">>).

fp(#{der := D}) -> webrtc_dtls_cert:fingerprint(sha256, D).

pair(COpts, SOpts) ->
    pair(webrtc_dtls_cert:generate(), webrtc_dtls_cert:generate(), COpts, SOpts).

pair(C, S, COpts, SOpts) ->
    {
        webrtc_dtls:new(maps:merge(#{role => client, cert => C, remote_fingerprints => [fp(S)]}, COpts)),
        webrtc_dtls:new(maps:merge(#{role => server, cert => S, remote_fingerprints => [fp(C)]}, SOpts))
    }.

run(C, S) -> webrtc_dtls_sim:run(C, S).
run(C, S, F) -> webrtc_dtls_sim:run(C, S, F).
connected(E) -> webrtc_dtls_sim:connected(E).
drop(From, N) -> fun(F, K, D) -> case F =:= From andalso K =:= N of true -> []; false -> [D] end end.

established(COpts, SOpts) ->
    {C, S} = pair(COpts, SOpts),
    W = run(C, S),
    #{c := Cs, s := Ss, ev := #{c := CE, s := SE}} = W,
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)),
    {Cs, Ss, W}.

%% Epoch bits of the first record of a protected datagram.
epoch_bits(<<H, _/binary>>) when H band 16#E0 =:= 16#20 -> H band 3.

data(From, To, Msg, Now) ->
    {ok, From1, [{send, D}]} = webrtc_dtls:send(Msg, From),
    {To1, A} = webrtc_dtls:handle_packet(D, Now, To),
    ?assertEqual([{event, {data, Msg}}], A),
    {From1, To1, D}.

first_server_hello(W) ->
    [{_, D, _} | _] = webrtc_dtls_sim:sent(W, s),
    [#{format := plain, fragment := F} | _] = webrtc_dtls13_record:split(D),
    {ok, [#{type := server_hello, data := Body} | _]} = webrtc_dtls_msg:decode_fragment(F),
    {ok, M} = webrtc_dtls_msg:decode_body(server_hello, Body),
    M.

%%====================================================================
%% Handshake
%%====================================================================

handshake_test() ->
    {C, S, W} = established(#{}, #{}),
    #{ev := #{c := CE, s := SE}} = W,
    [CI] = connected(CE),
    [SI] = connected(SE),
    ?assertMatch(
        #{version := 'dtlsv1.3', suite := tls_aes_128_gcm_sha256, group := x25519, srtp_profile := 7, verified := true},
        CI
    ),
    ?assertMatch(#{version := 'dtlsv1.3', role := server, srtp_profile := 7}, SI),
    {ok, K1} = webrtc_dtls:export_keying_material(?LABEL, no_context, 60, C),
    {ok, K2} = webrtc_dtls:export_keying_material(?LABEL, no_context, 60, S),
    ?assertEqual(K1, K2),
    ?assertEqual(60, byte_size(K1)),
    %% TLS 1.3 does not distinguish an empty context from no context.
    ?assertEqual({ok, K1}, webrtc_dtls:export_keying_material(?LABEL, <<>>, 60, S)),
    {ok, K3} = webrtc_dtls:export_keying_material(?LABEL, <<"ctx">>, 60, S),
    ?assertNotEqual(K1, K3),
    ?assertEqual(infinity, webrtc_dtls:next_timeout(C)),
    ?assertEqual(infinity, webrtc_dtls:next_timeout(S)),
    {C1, S1, D} = data(C, S, <<"hello">>, 0),
    ?assertEqual(3, epoch_bits(D)),
    {_, _, _} = data(S1, C1, <<"world">>, 0).

suites_test_() ->
    [
        ?_test(begin
            {C, S, #{ev := #{c := CE}}} = established(#{suites => [Id]}, #{}),
            ?assertMatch([#{suite := Name}], connected(CE)),
            {ok, K} = webrtc_dtls:export_keying_material(?LABEL, no_context, 30, C),
            ?assertEqual({ok, K}, webrtc_dtls:export_keying_material(?LABEL, no_context, 30, S)),
            {C1, S1, _} = data(C, S, <<"a">>, 0),
            data(S1, C1, <<"b">>, 0)
        end)
     || {Id, Name} <- [
            {16#1301, tls_aes_128_gcm_sha256}, {16#1302, tls_aes_256_gcm_sha384}, {16#1303, tls_chacha20_poly1305_sha256}
        ]
    ].

server_suite_preference_test() ->
    {_, _, #{ev := #{c := CE}}} = established(#{}, #{suites => [16#1303, 16#1301]}),
    ?assertMatch([#{suite := tls_chacha20_poly1305_sha256}], connected(CE)).

groups_test_() ->
    [
        ?_test(begin
            {_, _, #{ev := #{c := CE, s := SE}}} = established(#{groups => [G]}, #{}),
            ?assertMatch([#{group := G}], connected(CE)),
            ?assertMatch([#{group := G}], connected(SE))
        end)
     || G <- [x25519, secp256r1, secp384r1]
    ].

rsa_certificate_test() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    {Cl, Sv} = pair(C, S, #{}, #{}),
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertMatch([#{version := 'dtlsv1.3'}], connected(CE)),
    ?assertMatch([_], connected(SE)).

mixed_certificate_test() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(),
    {Cl, Sv} = pair(C, S, #{}, #{}),
    #{ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertMatch([#{version := 'dtlsv1.3'}], connected(CE)),
    ?assertMatch([_], connected(SE)).

srtp_profile_selection_test() ->
    {_, _, #{ev := #{c := CE}}} = established(#{srtp_profiles => [1, 7]}, #{srtp_profiles => [8, 1]}),
    ?assertMatch([#{srtp_profile := 1}], connected(CE)).

no_common_srtp_profile_test() ->
    {_, _, #{ev := #{c := CE}}} = established(#{srtp_profiles => [1]}, #{srtp_profiles => [7]}),
    ?assertMatch([#{srtp_profile := undefined}], connected(CE)).

no_srtp_test() ->
    {_, _, #{ev := #{c := CE}}} = established(#{srtp_profiles => []}, #{}),
    ?assertMatch([#{srtp_profile := undefined}], connected(CE)).

close_notify_test() ->
    {C, S, _} = established(#{}, #{}),
    {C1, [{send, D}]} = webrtc_dtls:close(C),
    ?assertEqual(closed, webrtc_dtls:status(C1)),
    {S1, A} = webrtc_dtls:handle_packet(D, 0, S),
    ?assertMatch([{send, _}, {event, {closed, peer_closed}}], A),
    ?assertEqual(closed, webrtc_dtls:status(S1)).

%%====================================================================
%% HelloRetryRequest and the stateless cookie (RFC 9147 §5.1)
%%====================================================================

hrr_cookie_test() ->
    {C, S} = pair(#{}, #{}),
    W = run(C, S),
    #{ev := #{c := CE, s := SE}} = W,
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)),
    %% The default server asks for a cookie with a HelloRetryRequest.
    ?assertMatch(#{random := <<16#CF21AD74:32, _/binary>>}, first_server_hello(W)).

no_cookie_test() ->
    {C, S} = pair(#{}, #{use_cookie => false}),
    W = run(C, S),
    #{ev := #{c := CE}} = W,
    ?assertMatch([_], connected(CE)),
    #{random := R} = first_server_hello(W),
    ?assertNotEqual(webrtc_dtls13_keys:hrr_random(), R).

hrr_key_share_test() ->
    %% The client's key share is for a group the server does not accept:
    %% the HelloRetryRequest selects another group.
    {C, S} = pair(#{groups => [secp384r1, x25519]}, #{groups => [x25519], use_cookie => false}),
    W = run(C, S),
    #{ev := #{c := CE, s := SE}} = W,
    ?assertMatch([#{group := x25519}], connected(CE)),
    ?assertMatch([_], connected(SE)),
    ?assertMatch(#{random := <<16#CF21AD74:32, _/binary>>}, first_server_hello(W)).

no_common_group_test() ->
    {C, S} = pair(#{groups => [secp384r1]}, #{groups => [x25519]}),
    #{ev := #{c := CE, s := SE}} = run(C, S),
    ?assertEqual([{failed, no_common_group}], SE),
    ?assertEqual([{failed, {alert, 40}}], CE).

hrr_stateless_test() ->
    {C, S} = pair(#{}, #{}),
    {C1, [{send, CH1}]} = webrtc_dtls:start(0, C),
    {S1, [{send, HRR}]} = webrtc_dtls:handle_packet(CH1, 0, S),
    %% Nothing is kept after the HelloRetryRequest.
    ?assertEqual(wait_client_hello, webrtc_dtls:status(S1)),
    ?assertEqual(infinity, webrtc_dtls:next_timeout(S1)),
    ?assertMatch(#{version := undefined}, webrtc_dtls:info(S1)),
    {_C2, [{send, CH2}]} = webrtc_dtls:handle_packet(HRR, 0, C1),
    %% Another server instance has another cookie secret.
    {_, Other} = pair(#{}, #{}),
    {_, A1} = webrtc_dtls:handle_packet(CH2, 0, Other),
    ?assertMatch([{send, _}, {event, {failed, bad_cookie}}], A1),
    %% An expired cookie is refused.
    {_, A2} = webrtc_dtls:handle_packet(CH2, 61000, S1),
    ?assertMatch([{send, _}, {event, {failed, bad_cookie}}], A2),
    %% A valid one is accepted.
    {S2, A3} = webrtc_dtls:handle_packet(CH2, 100, S1),
    ?assertMatch([{send, _} | _], A3),
    ?assertEqual(wait_client_cert, webrtc_dtls:status(S2)).

cookie_test() ->
    {_, S} = pair(#{}, #{}),
    Hash = crypto:strong_rand_bytes(32),
    Cookie = webrtc_dtls13_server:make_cookie(16#1301, {true, x25519}, Hash, 5000, S),
    ?assertEqual({ok, {16#1301, {true, x25519}, Hash}}, webrtc_dtls13_server:open_cookie(Cookie, 6000, S)),
    ?assertEqual(error, webrtc_dtls13_server:open_cookie(Cookie, 5000 + 61000, S)),
    ?assertEqual(error, webrtc_dtls13_server:open_cookie(Cookie, 0, S)),
    Sz = byte_size(Cookie) - 1,
    <<Head:Sz/binary, Last>> = Cookie,
    ?assertEqual(error, webrtc_dtls13_server:open_cookie(<<Head/binary, (Last bxor 1)>>, 6000, S)),
    <<First, Tail/binary>> = Cookie,
    ?assertEqual(error, webrtc_dtls13_server:open_cookie(<<(First bxor 1), Tail/binary>>, 6000, S)),
    ?assertEqual(error, webrtc_dtls13_server:open_cookie(<<1, 2, 3>>, 6000, S)).

%%====================================================================
%% Loss, retransmission, ACK (RFC 9147 §5.8, §7)
%%====================================================================

single_loss_test_() ->
    [
        ?_test(begin
            {C, S} = pair(#{}, #{}),
            #{ev := #{c := CE, s := SE}} = run(C, S, drop(From, N)),
            ?assertMatch([_], connected(CE)),
            ?assertMatch([_], connected(SE))
        end)
     || From <- [c, s], N <- lists:seq(1, 6)
    ].

heavy_loss_test_() ->
    [
        ?_test(begin
            rand:seed(exsss, {Seed, 2, 3}),
            {C, S} = pair(#{rtx_limit => 14}, #{rtx_limit => 14}),
            Drop = fun(_, _, D) ->
                case rand:uniform() < 0.4 of
                    true -> [];
                    false -> [D]
                end
            end,
            #{ev := #{c := CE, s := SE}} = run(C, S, Drop),
            ?assertMatch([_], connected(CE)),
            ?assertMatch([_], connected(SE))
        end)
     || Seed <- lists:seq(1, 8)
    ].

duplication_and_reordering_test() ->
    rand:seed(exsss, {7, 7, 7}),
    {C, S} = pair(#{}, #{}),
    F = fun(_, _, D) ->
        case rand:uniform(3) of
            1 -> [D, D];
            _ -> [D]
        end
    end,
    #{ev := #{c := CE, s := SE}} = run(C, S, F),
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)).

timeout_test() ->
    {C, S} = pair(#{rtx_limit => 3}, #{}),
    #{ev := #{c := CE}, now := Now} = run(C, S, fun(c, _, _) -> []; (s, _, D) -> [D] end),
    ?assertEqual([{failed, handshake_timeout}], CE),
    ?assertEqual(400 + 800 + 1600 + 3200, Now).

small_mtu_test() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    {Cl, Sv} = pair(C, S, #{mtu => 200}, #{mtu => 200}),
    W = run(Cl, Sv),
    #{ev := #{c := CE, s := SE}} = W,
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)),
    Sizes = [byte_size(D) || From <- [c, s], {_, D, _} <- webrtc_dtls_sim:sent(W, From)],
    ?assert(lists:max(Sizes) =< 200),
    ?assert(length(Sizes) > 10).

small_mtu_loss_test_() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    [
        ?_test(begin
            {Cl, Sv} = pair(C, S, #{mtu => 250}, #{mtu => 250}),
            #{ev := #{c := CE, s := SE}} = run(Cl, Sv, drop(From, N)),
            ?assertMatch([_], connected(CE)),
            ?assertMatch([_], connected(SE))
        end)
     || From <- [c, s], N <- lists:seq(1, 12, 2)
    ].

%% The server acknowledges the client's final flight in epoch 3; the
%% client only reports the connection once that ACK arrived.
ack_final_flight_test() ->
    {_, _, W} = established(#{}, #{}),
    [{_, Ack, _} | _] = lists:reverse(webrtc_dtls_sim:sent(W, s)),
    ?assertEqual(3, epoch_bits(Ack)),
    %% Header, inner type, tag and a non-empty record number list.
    ?assert(byte_size(Ack) > 5 + 2 + 16 + 1 + 16).

lost_ack_test() ->
    {_, _, W0} = established(#{}, #{}),
    AckN = length(webrtc_dtls_sim:sent(W0, s)),
    ClientN = length(webrtc_dtls_sim:sent(W0, c)),
    {C, S} = pair(#{}, #{}),
    W = run(C, S, drop(s, AckN)),
    #{ev := #{c := CE, s := SE}} = W,
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)),
    %% The client retransmitted its final flight and got a new ACK.
    ?assert(length(webrtc_dtls_sim:sent(W, c)) > ClientN),
    ?assert(length(webrtc_dtls_sim:sent(W, s)) > AckN).

no_ack_no_connection_test() ->
    {_, _, W0} = established(#{}, #{}),
    AckN = length(webrtc_dtls_sim:sent(W0, s)),
    {C, S} = pair(#{rtx_limit => 3}, #{}),
    F = fun(s, N, _) when N >= AckN -> []; (_, _, D) -> [D] end,
    #{ev := #{c := CE, s := SE}} = run(C, S, F),
    ?assertEqual([{failed, handshake_timeout}], CE),
    ?assertMatch([_], connected(SE)).

%% A partial flight is acknowledged after a quarter of the timeout and
%% the sender only retransmits what is missing.
partial_flight_ack_test() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    {Cl0, Sv0} = pair(C, S, #{mtu => 300}, #{mtu => 300, use_cookie => false}),
    W0 = run(Cl0, Sv0),
    Full = length(webrtc_dtls_sim:sent(W0, s)) - 1,
    {Cl, Sv} = pair(C, S, #{mtu => 300}, #{mtu => 300, use_cookie => false}),
    W = run(Cl, Sv, drop(s, 3)),
    #{ev := #{c := CE, s := SE}, now := Now} = W,
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)),
    %% Recovered from the client's ACK before the server's 400 ms timer.
    ?assert(Now < 400),
    Sent = length(webrtc_dtls_sim:sent(W, s)) - 1,
    ?assert(Sent < Full + 3).

%%====================================================================
%% Records: replay, reconstruction, tampering
%%====================================================================

replay_test() ->
    {C, S, _} = established(#{}, #{}),
    {ok, _, [{send, D}]} = webrtc_dtls:send(<<"once">>, C),
    {S1, [{event, {data, <<"once">>}}]} = webrtc_dtls:handle_packet(D, 0, S),
    ?assertEqual({S1, []}, webrtc_dtls:handle_packet(D, 0, S1)),
    Sz = byte_size(D) - 1,
    <<H:Sz/binary, L>> = D,
    {_, A} = webrtc_dtls:handle_packet(<<H/binary, (L bxor 1)>>, 0, S),
    ?assertEqual([], A),
    %% A flipped (encrypted) sequence number byte fails deprotection.
    <<B0, B1, B2, Rest/binary>> = D,
    {_, A2} = webrtc_dtls:handle_packet(<<B0, B1, (B2 bxor 16#80), Rest/binary>>, 0, S),
    ?assertEqual([], A2).

reordering_test() ->
    {C, S, _} = established(#{}, #{}),
    {Ds, _} = lists:mapfoldl(
        fun(I, Cx) ->
            {ok, Cx1, [{send, D}]} = webrtc_dtls:send(<<I:32>>, Cx),
            {D, Cx1}
        end,
        C,
        lists:seq(1, 50)
    ),
    Shuffled = [D || {_, D} <- lists:sort([{rand:uniform(), D} || D <- Ds])],
    {_, Got} = lists:foldl(
        fun(D, {Sx, Acc}) ->
            {Sx1, A} = webrtc_dtls:handle_packet(D, 0, Sx),
            {Sx1, Acc ++ [I || {event, {data, <<I:32>>}} <- A]}
        end,
        {S, []},
        Shuffled
    ),
    ?assertEqual(lists:seq(1, 50), lists:sort(Got)).

%% The 16-bit wire sequence number wraps: records on both sides of the
%% boundary, delivered out of order, are reconstructed (§4.2.2).
sequence_wrap_test_() ->
    {timeout, 120, fun() ->
        {C, S, _} = established(#{}, #{}),
        Burn = fun(0, Cx, _) -> Cx; (N, Cx, F) -> {ok, Cx1, _} = webrtc_dtls:send(<<"x">>, Cx), F(N - 1, Cx1, F) end,
        %% Sequence numbers start after the handshake records of epoch 3
        %% (none from the client), so this lands just below 65536.
        C1 = Burn(65530, C, Burn),
        {Ds, _} = lists:mapfoldl(
            fun(I, Cx) ->
                {ok, Cx1, [{send, D}]} = webrtc_dtls:send(<<I:32>>, Cx),
                {D, Cx1}
            end,
            C1,
            lists:seq(1, 12)
        ),
        [D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11, D12] = Ds,
        Order = [D1, D3, D2, D8, D4, D5, D7, D6, D9, D12, D10, D11],
        {_, Got} = lists:foldl(
            fun(D, {Sx, Acc}) ->
                {Sx1, A} = webrtc_dtls:handle_packet(D, 0, Sx),
                {Sx1, Acc ++ [I || {event, {data, <<I:32>>}} <- A]}
            end,
            {S, []},
            Order
        ),
        ?assertEqual([1, 3, 2, 8, 4, 5, 7, 6, 9, 12, 10, 11], Got)
    end}.

reconstruct_test() ->
    R = fun webrtc_dtls13_record:reconstruct/3,
    ?assertEqual(0, R(0, 16, 0)),
    ?assertEqual(5, R(5, 16, 0)),
    ?assertEqual(16#FFF0, R(16#FFF0, 16, 3)),
    ?assertEqual(16#10000, R(0, 16, 16#FFFF)),
    ?assertEqual(16#FFFF, R(16#FFFF, 16, 16#10000)),
    ?assertEqual(16#10001, R(1, 16, 16#10000)),
    ?assertEqual(16#2FFFE, R(16#FFFE, 16, 16#30005)),
    ?assertEqual(257, R(1, 8, 255)),
    ?assertEqual(254, R(254, 8, 256)),
    ?assertEqual(16#1FF, R(16#FF, 8, 16#200)),
    ?assertEqual(16#200, R(0, 8, 16#1FF)),
    %% Halfway is resolved towards the lower candidate.
    ?assertEqual(16#80, R(16#80, 8, 16#100)).

select_epoch_test() ->
    S = fun webrtc_dtls13_record:select_epoch/2,
    ?assertEqual({ok, 2}, S(2, [0, 2])),
    ?assertEqual({ok, 3}, S(3, [0, 2, 3])),
    ?assertEqual({ok, 4}, S(0, [3, 4])),
    ?assertEqual({ok, 6}, S(2, [2, 5, 6])),
    ?assertEqual(error, S(1, [2, 3])),
    %% Epoch 0 never uses the unified header.
    ?assertEqual(error, S(0, [0])).

record_roundtrip_test_() ->
    [
        ?_test(begin
            {ok, Suite} = webrtc_dtls13_keys:suite(Id),
            Keys = webrtc_dtls13_keys:traffic_keys(<<"dtls13">>, Suite, crypto:strong_rand_bytes(32)),
            lists:foreach(
                fun(Seq) ->
                    Plain = crypto:strong_rand_bytes(rand:uniform(100) - 1),
                    Rec = webrtc_dtls13_record:protect(application_data, 3, Seq, Plain, Keys),
                    ?assertEqual(2#00101111, binary:first(Rec)),
                    [R] = webrtc_dtls13_record:split(Rec),
                    ?assertEqual({ok, Seq, application_data, Plain}, webrtc_dtls13_record:open(R, Keys, Seq)),
                    %% Wrong keys fail.
                    Other = webrtc_dtls13_keys:traffic_keys(<<"dtls13">>, Suite, crypto:strong_rand_bytes(32)),
                    ?assertEqual(error, webrtc_dtls13_record:open(R, Other, Seq))
                end,
                [0, 1, 255, 256, 65535, 65536, 1 bsl 40]
            )
        end)
     || Id <- webrtc_dtls13_keys:supported_suites()
    ].

split_test() ->
    {ok, Suite} = webrtc_dtls13_keys:suite(16#1301),
    Keys = webrtc_dtls13_keys:traffic_keys(<<"dtls13">>, Suite, crypto:strong_rand_bytes(32)),
    P = webrtc_dtls_record:encode(handshake, 16#FEFD, 0, 7, <<1, 2, 3>>),
    E = webrtc_dtls13_record:protect(handshake, 2, 9, <<"abc">>, Keys),
    ?assertMatch(
        [#{format := plain, seq := 7, fragment := <<1, 2, 3>>}, #{format := unified, epoch_bits := 2}, #{format := plain}],
        webrtc_dtls13_record:split(<<P/binary, E/binary, P/binary>>)
    ),
    %% A record without length runs to the end of the datagram.
    <<H, S:16, _L:16, Body/binary>> = E,
    NoLen = <<(H band 2#11111011), S:16, Body/binary>>,
    ?assertMatch([#{format := plain}, #{format := unified, length := undefined}], webrtc_dtls13_record:split(<<P/binary, NoLen/binary>>)),
    %% Connection IDs are not negotiated: parsing stops.
    ?assertEqual([], webrtc_dtls13_record:split(<<(H bor 16#10), S:16, Body/binary>>)),
    %% Too short ciphertext is dropped.
    ?assertEqual([], webrtc_dtls13_record:split(<<16#2E, 1, 2, 0, 3, 1, 2, 3>>)),
    ?assertEqual([], webrtc_dtls13_record:split(<<64, 1, 2, 3>>)).

%% Erratum 8108: an ACK may not cover records of a later epoch than its
%% own.
ack_for_later_epoch_test() ->
    {C, S, _} = established(#{}, #{}),
    Body = webrtc_dtls13_record:encode_ack([{4, 0}]),
    {ok, Rec, _} = webrtc_dtls13:encode_record(ack, 3, Body, C),
    {S1, A} = webrtc_dtls:handle_packet(Rec, 0, S),
    ?assertMatch([{send, _}, {event, {failed, ack_for_later_epoch}}], A),
    ?assertEqual(failed, webrtc_dtls:status(S1)).

%% Unknown record numbers in an ACK are ignored.
ack_unknown_records_test() ->
    {C, S, _} = established(#{}, #{}),
    Body = webrtc_dtls13_record:encode_ack([{2, 99}, {3, 7}]),
    {ok, Rec, C1} = webrtc_dtls13:encode_record(ack, 3, Body, C),
    {S1, []} = webrtc_dtls:handle_packet(Rec, 0, S),
    data(C1, S1, <<"fine">>, 0).

%% Unauthenticated alerts are ignored once handshake keys exist.
plaintext_alert_ignored_test() ->
    {C, S, _} = established(#{}, #{}),
    Alert = webrtc_dtls_record:encode(alert, 16#FEFD, 0, 1000, <<2, 40>>),
    {S1, []} = webrtc_dtls:handle_packet(Alert, 0, S),
    {C1, []} = webrtc_dtls:handle_packet(Alert, 0, C),
    data(C1, S1, <<"alive">>, 0).

ack_codec_test() ->
    Recs = [{2, 5}, {0, 1}, {3, 1 bsl 40}],
    Bin = webrtc_dtls13_record:encode_ack(Recs),
    ?assertEqual({ok, lists:sort(Recs)}, webrtc_dtls13_record:decode_ack(Bin)),
    ?assertEqual({ok, []}, webrtc_dtls13_record:decode_ack(<<0:16>>)),
    ?assertEqual(error, webrtc_dtls13_record:decode_ack(<<0:16, 1>>)),
    ?assertEqual(error, webrtc_dtls13_record:decode_ack(<<15:16, 0:120>>)).

%%====================================================================
%% KeyUpdate (RFC 9147 §8)
%%====================================================================

key_update_test() ->
    {C, S, W} = established(#{}, #{}),
    {ok, C1, A} = webrtc_dtls:key_update(0, C),
    ?assertMatch([{send, _}], A),
    ?assertEqual({error, pending}, webrtc_dtls:key_update(0, C1)),
    #{c := C2, s := S2, ev := Ev} = webrtc_dtls_sim:deliver(W#{c := C1, s := S}, c, A),
    ?assertEqual(maps:get(ev, W), Ev),
    ?assertEqual(infinity, webrtc_dtls:next_timeout(C2)),
    ?assertEqual(infinity, webrtc_dtls:next_timeout(S2)),
    %% Both sides moved to epoch 4 (the peer was asked to update too).
    {C3, S3, D1} = data(C2, S2, <<"after">>, 0),
    ?assertEqual(0, epoch_bits(D1)),
    {_, _, D2} = data(S3, C3, <<"reply">>, 0),
    ?assertEqual(0, epoch_bits(D2)),
    %% Exported keys do not change.
    ?assertEqual(
        webrtc_dtls:export_keying_material(?LABEL, no_context, 60, C),
        webrtc_dtls:export_keying_material(?LABEL, no_context, 60, C3)
    ).

many_key_updates_test() ->
    {C0, S0, W} = established(#{}, #{}),
    {C, S} = lists:foldl(
        fun(I, {Cx, Sx}) ->
            {Cx1, Sx1} =
                case I rem 2 of
                    0 ->
                        {ok, Cy, A} = webrtc_dtls:key_update(0, Cx),
                        #{c := Cz, s := Sz} = webrtc_dtls_sim:deliver(W#{c := Cy, s := Sx}, c, A),
                        {Cz, Sz};
                    1 ->
                        {ok, Sy, A} = webrtc_dtls:key_update(0, Sx),
                        #{c := Cz, s := Sz} = webrtc_dtls_sim:deliver(W#{c := Cx, s := Sy}, s, A),
                        {Cz, Sz}
                end,
            {Cx2, Sx2, D} = data(Cx1, Sx1, <<I>>, 0),
            ?assertEqual((3 + I) band 3, epoch_bits(D)),
            {Sx3, Cx3, _} = data(Sx2, Cx2, <<I>>, 0),
            {Cx3, Sx3}
        end,
        {C0, S0},
        lists:seq(1, 9)
    ),
    data(C, S, <<"end">>, 0).

key_update_lost_ack_test() ->
    {C, S, W} = established(#{}, #{}),
    Base = maps:get(s, maps:get(n, W)),
    {ok, C1, A} = webrtc_dtls:key_update(0, C),
    Drop = fun(s, N, _) when N =:= Base + 1 -> []; (_, _, D) -> [D] end,
    W1 = webrtc_dtls_sim:deliver(W#{c := C1, s := S, filter := Drop}, c, A),
    #{c := C2, s := S2} = W1,
    ?assertEqual(infinity, webrtc_dtls:next_timeout(C2)),
    {C3, S3, D} = data(C2, S2, <<"x">>, 0),
    ?assertEqual(0, epoch_bits(D)),
    {_, _, _} = data(S3, C3, <<"y">>, 0).

automatic_key_update_test() ->
    {C0, S0, W} = established(#{rekey_records => 5}, #{}),
    {C1, Acts} = lists:foldl(
        fun(I, {Cx, Acc}) ->
            {ok, Cx1, A} = webrtc_dtls:send(<<I>>, Cx),
            {Cx1, Acc ++ A}
        end,
        {C0, []},
        lists:seq(1, 8)
    ),
    %% A KeyUpdate was added after the fifth record.
    ?assert(length(Acts) > 8),
    #{c := C2, s := S2, ev := #{s := SE}} = webrtc_dtls_sim:deliver(W#{c := C1, s := S0}, c, Acts),
    ?assertEqual([<<I>> || I <- lists:seq(1, 8)], [B || {data, B} <- SE]),
    {_, _, D} = data(C2, S2, <<"z">>, 0),
    ?assertEqual(0, epoch_bits(D)).

key_update_errors_test() ->
    {C, _} = pair(#{}, #{}),
    ?assertEqual({error, not_connected}, webrtc_dtls:key_update(0, C)),
    {C12, _, _} = established(#{versions => ['dtlsv1.2']}, #{}),
    ?assertEqual({error, not_supported}, webrtc_dtls:key_update(0, C12)).

%%====================================================================
%% Version negotiation and downgrade protection
%%====================================================================

fallback_to_12_server_test() ->
    {C, S, #{ev := #{c := CE, s := SE}}} = established(#{}, #{versions => ['dtlsv1.2']}),
    ?assertMatch([#{version := 'dtlsv1.2', extended_master_secret := true}], connected(CE)),
    ?assertMatch([#{version := 'dtlsv1.2'}], connected(SE)),
    {ok, K} = webrtc_dtls:export_keying_material(?LABEL, no_context, 60, C),
    ?assertEqual({ok, K}, webrtc_dtls:export_keying_material(?LABEL, no_context, 60, S)),
    data(C, S, <<"12">>, 0).

fallback_to_12_client_test() ->
    {C, S, #{ev := #{c := CE, s := SE}}} = established(#{versions => ['dtlsv1.2']}, #{}),
    ?assertMatch([#{version := 'dtlsv1.2'}], connected(CE)),
    ?assertMatch([#{version := 'dtlsv1.2'}], connected(SE)),
    data(S, C, <<"12">>, 0).

fallback_without_13_suites_test() ->
    {_, _, #{ev := #{c := CE}}} = established(#{suites => [16#C02B]}, #{}),
    ?assertMatch([#{version := 'dtlsv1.2', suite := tls_ecdhe_ecdsa_with_aes_128_gcm_sha256}], connected(CE)).

%% A server without DTLS 1.3 suites does not support DTLS 1.3: it
%% negotiates DTLS 1.2 without the downgrade sentinel.
server_without_13_suites_test() ->
    {_, _, #{ev := #{c := CE}}} = established(#{}, #{suites => [16#C02B]}),
    ?assertMatch([#{version := 'dtlsv1.2'}], connected(CE)).

%% Encrypted records of the server flight arrive before its ServerHello:
%% they are buffered and processed once the handshake keys exist.
records_before_server_hello_test() ->
    C = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    S = webrtc_dtls_cert:generate(#{key => {rsa, 2048}}),
    {Cl, Sv} = pair(C, S, #{mtu => 300}, #{mtu => 300, use_cookie => false}),
    Self = self(),
    F = fun
        (s, 1, D) -> Self ! {held, D}, [];
        (s, 2, D) -> receive {held, H} -> [D, H] end;
        (_, _, D) -> [D]
    end,
    #{ev := #{c := CE, s := SE}, now := Now} = run(Cl, Sv, F),
    ?assertMatch([_], connected(CE)),
    ?assertMatch([_], connected(SE)),
    %% No timer fired: nothing was lost or retransmitted.
    ?assertEqual(0, Now).

no_common_version_test_() ->
    [
        ?_test(begin
            {C, S} = pair(#{versions => ['dtlsv1.3']}, #{versions => ['dtlsv1.2']}),
            #{ev := #{c := CE, s := SE}} = run(C, S),
            ?assertEqual([{failed, no_common_version}], SE),
            ?assertEqual([{failed, {alert, 70}}], CE)
        end),
        ?_test(begin
            {C, S} = pair(#{versions => ['dtlsv1.2']}, #{versions => ['dtlsv1.3']}),
            #{ev := #{c := CE, s := SE}} = run(C, S),
            ?assertEqual([{failed, no_common_version}], SE),
            ?assertEqual([{failed, {alert, 70}}], CE)
        end)
    ].

only_13_test() ->
    {_, _, #{ev := #{c := CE}}} = established(#{versions => ['dtlsv1.3']}, #{versions => ['dtlsv1.3']}),
    ?assertMatch([#{version := 'dtlsv1.3'}], connected(CE)).

%% An attacker removes supported_versions from the ClientHello: the
%% server falls back to DTLS 1.2 and marks its random, the client
%% detects the downgrade (RFC 8446 §4.1.3).
downgrade_detection_test() ->
    {C, S} = pair(#{}, #{use_cookie => false}),
    #{ev := #{c := CE, s := SE}} = run(C, S, fun strip_versions/3),
    ?assertEqual([{failed, downgrade_detected}], CE),
    ?assertEqual([{failed, {alert, 47}}], SE).

%% Without DTLS 1.3 on the client the sentinel is ignored.
downgrade_sentinel_ignored_by_12_client_test() ->
    {_, _, W} = established(#{versions => ['dtlsv1.2']}, #{use_cookie => false}),
    #{random := R} = first_server_hello(W),
    ?assertEqual(<<"DOWNGRD", 1>>, binary:part(R, 24, 8)).

%% Rewrite the first handshake message of a plaintext record with F.
rewrite_hello(Type, F, <<22, V:16, E:16, Seq:48, Len:16, Rest/binary>>) ->
    <<Frag:Len/binary, Tail/binary>> = Rest,
    {ok, [#{data := Body, seq := MS} | _]} = webrtc_dtls_msg:decode_fragment(Frag),
    {ok, M} = webrtc_dtls_msg:decode_body(Type, Body),
    F1 = webrtc_dtls_msg:full(Type, MS, webrtc_dtls_msg:encode_body(Type, F(M))),
    <<22, V:16, E:16, Seq:48, (byte_size(F1)):16, F1/binary, Tail/binary>>.

%% RFC 9147 §5.3: a DTLS 1.3 ClientHello has an empty legacy_cookie.
legacy_cookie_test() ->
    {C, S} = pair(#{}, #{use_cookie => false}),
    F = fun
        (c, 1, D) -> [rewrite_hello(client_hello, fun(M) -> M#{cookie => <<1, 2, 3>>} end, D)];
        (_, _, D) -> [D]
    end,
    #{ev := #{c := CE, s := SE}} = run(C, S, F),
    ?assertEqual([{failed, legacy_cookie_not_empty}], SE),
    ?assertEqual([{failed, {alert, 47}}], CE).

%% Erratum 8066: the client rejects a non-empty legacy_session_id_echo.
session_id_echo_test() ->
    {C, S} = pair(#{}, #{use_cookie => false}),
    F = fun
        (s, 1, D) -> [rewrite_hello(server_hello, fun(M) -> M#{session_id => <<7>>} end, D)];
        (_, _, D) -> [D]
    end,
    #{ev := #{c := CE}} = run(C, S, F),
    ?assertEqual([{failed, bad_session_id_echo}], CE).

strip_versions(c, 1, <<22, V:16, E:16, Seq:48, _Len:16, Frag/binary>>) ->
    {ok, [#{data := Body, seq := MS}]} = webrtc_dtls_msg:decode_fragment(Frag),
    {ok, #{extensions := Exts} = M} = webrtc_dtls_msg:decode_body(client_hello, Body),
    Exts1 = [X || {T, _} = X <- Exts, T =/= 43, T =/= 51],
    Body1 = webrtc_dtls_msg:encode_body(client_hello, M#{extensions => Exts1}),
    F1 = webrtc_dtls_msg:full(client_hello, MS, Body1),
    [<<22, V:16, E:16, Seq:48, (byte_size(F1)):16, F1/binary>>];
strip_versions(_, _, D) ->
    [D].

%%====================================================================
%% Fingerprints (same semantics as DTLS 1.2)
%%====================================================================

fingerprint_mismatch_test() ->
    {C, S} = pair(#{remote_fingerprints => [fp(webrtc_dtls_cert:generate())]}, #{}),
    #{c := CSt, ev := #{c := CE, s := SE}} = run(C, S),
    ?assertEqual([{failed, fingerprint_mismatch}], CE),
    ?assertEqual([{failed, {alert, 42}}], SE),
    ?assertEqual(failed, webrtc_dtls:status(CSt)).

server_rejects_client_fingerprint_test() ->
    {C, S} = pair(#{}, #{remote_fingerprints => [fp(webrtc_dtls_cert:generate())]}),
    #{ev := #{c := CE, s := SE}} = run(C, S),
    ?assertEqual([{failed, fingerprint_mismatch}], SE),
    ?assertEqual([], connected(CE)),
    ?assertEqual([{failed, {alert, 42}}], CE).

deferred_fingerprint_client_test() ->
    Cc = webrtc_dtls_cert:generate(),
    Sc = webrtc_dtls_cert:generate(),
    Cl = webrtc_dtls:new(#{role => client, cert => Cc}),
    Sv = webrtc_dtls:new(#{role => server, cert => Sc, remote_fingerprints => [fp(Cc)]}),
    #{c := CSt, s := SSt, ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertEqual([], connected(CE)),
    ?assertMatch([_], connected(SE)),
    ?assertEqual({error, not_connected}, webrtc_dtls:send(<<"x">>, CSt)),
    ?assertEqual({error, not_connected}, webrtc_dtls:export_keying_material(?LABEL, no_context, 60, CSt)),
    {ok, _, [{send, D}]} = webrtc_dtls:send(<<"early">>, SSt),
    {CSt1, []} = webrtc_dtls:handle_packet(D, 0, CSt),
    {CSt2, A} = webrtc_dtls:set_remote_fingerprints([fp(Sc)], CSt1),
    ?assertMatch([{event, {connected, #{version := 'dtlsv1.3'}}}, {event, {data, <<"early">>}}], A),
    ?assertEqual(
        webrtc_dtls:export_keying_material(?LABEL, no_context, 60, SSt),
        webrtc_dtls:export_keying_material(?LABEL, no_context, 60, CSt2)
    ).

deferred_fingerprint_server_test() ->
    Cc = webrtc_dtls_cert:generate(),
    Sc = webrtc_dtls_cert:generate(),
    Cl = webrtc_dtls:new(#{role => client, cert => Cc, remote_fingerprints => [fp(Sc)]}),
    Sv = webrtc_dtls:new(#{role => server, cert => Sc}),
    #{c := CSt, s := SSt, ev := #{c := CE, s := SE}} = run(Cl, Sv),
    ?assertMatch([_], connected(CE)),
    ?assertEqual([], connected(SE)),
    {ok, _, [{send, D}]} = webrtc_dtls:send(<<"early">>, CSt),
    {SSt1, []} = webrtc_dtls:handle_packet(D, 0, SSt),
    {_, A} = webrtc_dtls:set_remote_fingerprints([fp(Cc)], SSt1),
    ?assertMatch([{event, {connected, _}}, {event, {data, <<"early">>}}], A).

deferred_fingerprint_mismatch_test() ->
    Cc = webrtc_dtls_cert:generate(),
    Sc = webrtc_dtls_cert:generate(),
    Cl = webrtc_dtls:new(#{role => client, cert => Cc}),
    Sv = webrtc_dtls:new(#{role => server, cert => Sc, remote_fingerprints => [fp(Cc)]}),
    #{c := CSt} = run(Cl, Sv),
    {CSt1, A} = webrtc_dtls:set_remote_fingerprints([fp(Cc)], CSt),
    ?assertMatch([{send, _}, {event, {failed, fingerprint_mismatch}}], A),
    ?assertEqual(failed, webrtc_dtls:status(CSt1)).

sha1_fingerprint_not_accepted_test() ->
    Cc = webrtc_dtls_cert:generate(),
    Sc = webrtc_dtls_cert:generate(),
    Cl = webrtc_dtls:new(#{
        role => client, cert => Cc, remote_fingerprints => [webrtc_dtls_cert:fingerprint(sha, maps:get(der, Sc))]
    }),
    Sv = webrtc_dtls:new(#{role => server, cert => Sc, remote_fingerprints => [fp(Cc)]}),
    #{ev := #{c := CE}} = run(Cl, Sv),
    ?assertEqual([{failed, fingerprint_mismatch}], CE).

%%====================================================================
%% Malformed input never crashes the engine
%%====================================================================

garbage_test() ->
    rand:seed(exsss, {4, 5, 6}),
    {C, S, _} = established(#{}, #{}),
    {Cf, Sf} = pair(#{}, #{}),
    {Cw, _} = webrtc_dtls:start(0, Cf),
    Targets = [C, S, Sf, Cw],
    lists:foreach(
        fun(_) ->
            Len = rand:uniform(300),
            Bin = rand:bytes(Len),
            H = 16#20 + rand:uniform(32) - 1,
            [
                begin
                    {_, _} = webrtc_dtls:handle_packet(Bin, 0, T),
                    {_, _} = webrtc_dtls:handle_packet(<<H, Bin/binary>>, 0, T),
                    {_, _} = webrtc_dtls:handle_packet(<<(H bor 4), 0:16, Len:16, Bin/binary>>, 0, T),
                    {_, _} = webrtc_dtls:handle_packet(<<22, 16#FEFD:16, 0:16, 0:48, Len:16, Bin/binary>>, 0, T),
                    {_, _} = webrtc_dtls:handle_packet(<<26, 16#FEFD:16, 0:16, 0:48, Len:16, Bin/binary>>, 0, T)
                end
             || T <- Targets
            ]
        end,
        lists:seq(1, 1000)
    ),
    %% The established connection is unaffected.
    data(C, S, <<"still">>, 0).

%% Every truncation and every seventh bit flip of each handshake
%% datagram, fed to the receiver in the state it had at that point.
mutated_handshake_test_() ->
    {timeout, 120, fun mutated_handshake/0}.

mutated_handshake() ->
    {C0, S0} = pair(#{}, #{}),
    {C1, [{send, CH1}]} = webrtc_dtls:start(0, C0),
    {S1, [{send, HRR}]} = webrtc_dtls:handle_packet(CH1, 0, S0),
    {C2, [{send, CH2}]} = webrtc_dtls:handle_packet(HRR, 0, C1),
    {S2, SA} = webrtc_dtls:handle_packet(CH2, 0, S1),
    ServerFlight = [D || {send, D} <- SA],
    {C3, CA} = feed(ServerFlight, C2),
    ClientFlight = [D || {send, D} <- CA],
    {_S3, _} = feed(ClientFlight, S2),
    Cases = [{CH1, S0}, {HRR, C1}, {CH2, S1}] ++ [{D, C2} || D <- ServerFlight] ++ [{D, S2} || D <- ClientFlight],
    lists:foreach(
        fun({D, St}) ->
            [_ = webrtc_dtls:handle_packet(M, 0, St) || M <- mutations(D)]
        end,
        Cases
    ),
    ?assertEqual(wait_ack, webrtc_dtls:status(C3)).

feed(Ds, St) ->
    lists:foldl(fun(D, {S, A}) -> {S1, A1} = webrtc_dtls:handle_packet(D, 0, S), {S1, A ++ A1} end, {St, []}, Ds).

mutations(Bin) ->
    [binary:part(Bin, 0, N) || N <- lists:seq(0, byte_size(Bin) - 1)] ++
        [flip(Bin, I) || I <- lists:seq(0, byte_size(Bin) * 8 - 1, 7)].

flip(Bin, I) ->
    <<A:I/bitstring, B:1, C/bitstring>> = Bin,
    <<A/bitstring, (1 - B):1, C/bitstring>>.

%%====================================================================
%% Key schedule: RFC 8448 §3 (TLS 1.3 labels, "tls13 " prefix)
%%====================================================================

h(S) -> webrtc_test_hex:b(S).

rfc8448_key_schedule_test() ->
    ClientPriv = h("49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05"),
    ServerPub = h("c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f"),
    CH = h(
        "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 "
        "02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 "
        "00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 "
        "26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 "
        "1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 "
        "05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01"
    ),
    SH = h(
        "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e "
        "d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 "
        "56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04"
    ),
    Shared = crypto:compute_key(ecdh, ServerPub, ClientPriv, x25519),
    ?assertEqual(h("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d"), Shared),
    ?assertEqual(
        h("33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"),
        webrtc_dtls13_keys:early_secret(?T13, sha256)
    ),
    HS = webrtc_dtls13_keys:handshake_secret(?T13, sha256, Shared),
    ?assertEqual(h("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"), HS),
    TH = crypto:hash(sha256, [CH, SH]),
    ?assertEqual(h("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8"), TH),
    CHS = webrtc_dtls13_keys:derive_secret(?T13, sha256, HS, <<"c hs traffic">>, TH),
    SHS = webrtc_dtls13_keys:derive_secret(?T13, sha256, HS, <<"s hs traffic">>, TH),
    ?assertEqual(h("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"), CHS),
    ?assertEqual(h("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"), SHS),
    {ok, Suite} = webrtc_dtls13_keys:suite(16#1301),
    #{key := K, iv := IV} = webrtc_dtls13_keys:traffic_keys(?T13, Suite, SHS),
    ?assertEqual(h("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc"), K),
    ?assertEqual(h("5d 31 3e b2 67 12 76 ee 13 00 0b 30"), IV),
    ?assertEqual(
        h("00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8"),
        webrtc_dtls13_keys:expand_label(?T13, sha256, SHS, <<"finished">>, <<>>, 32)
    ),
    MS = webrtc_dtls13_keys:master_secret(?T13, sha256, HS),
    ?assertEqual(h("18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19"), MS),
    TH2 = h("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13"),
    ?assertEqual(
        h("9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5"),
        webrtc_dtls13_keys:derive_secret(?T13, sha256, MS, <<"c ap traffic">>, TH2)
    ),
    ?assertEqual(
        h("a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43"),
        webrtc_dtls13_keys:derive_secret(?T13, sha256, MS, <<"s ap traffic">>, TH2)
    ),
    ?assertEqual(
        h("fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50"),
        webrtc_dtls13_keys:derive_secret(?T13, sha256, MS, <<"exp master">>, TH2)
    ).

dtls13_label_prefix_test() ->
    %% RFC 9147 §5.9: "dtls13" without a trailing space gives different
    %% keys from TLS 1.3.
    S = crypto:strong_rand_bytes(32),
    ?assertNotEqual(
        webrtc_dtls13_keys:expand_label(?T13, sha256, S, <<"key">>, <<>>, 16),
        webrtc_dtls13_keys:expand_label(<<"dtls13">>, sha256, S, <<"key">>, <<>>, 16)
    ),
    Info = <<16:16, 9, "dtls13key", 0>>,
    ?assertEqual(
        webrtc_dtls13_keys:expand(sha256, S, Info, 16),
        webrtc_dtls13_keys:expand_label(<<"dtls13">>, sha256, S, <<"key">>, <<>>, 16)
    ).

hkdf_rfc5869_test() ->
    %% RFC 5869 A.1.
    IKM = binary:copy(<<16#0b>>, 22),
    Salt = h("00 01 02 03 04 05 06 07 08 09 0a 0b 0c"),
    Info = h("f0 f1 f2 f3 f4 f5 f6 f7 f8 f9"),
    PRK = webrtc_dtls13_keys:extract(sha256, Salt, IKM),
    ?assertEqual(h("07 77 09 36 2c 2e 32 df 0d dc 3f 0d c4 7b ba 63 90 b6 c7 3b b5 0f 9c 31 22 ec 84 4a d7 c2 b3 e5"), PRK),
    ?assertEqual(
        h(
            "3c b2 5f 25 fa ac d5 7a 90 43 4f 64 d0 36 2f 2a 2d 2d 0a 90 cf 1a 5a 4c 5d b0 2d 56 ec c4 c5 bf "
            "34 00 72 08 d5 b8 87 18 58 65"
        ),
        webrtc_dtls13_keys:expand(sha256, PRK, Info, 42)
    ).

%%====================================================================
%% Connection ID (RFC 9147 §9, RFC 9146)
%%====================================================================

%% The CID of a protected record, as the peer sees it.
record_cid(<<H, Rest/binary>>, Len) when H band 16#10 =/= 0 ->
    <<Cid:Len/binary, _/binary>> = Rest,
    Cid;
record_cid(<<_, _/binary>>, _Len) ->
    none.

%% Both sides want CIDs: each sends the other's, the C bit set, and
%% application data still flows.
connection_id_test() ->
    {C, S, _} = established(#{connection_id => <<"client-cid">>}, #{connection_id => <<"srv">>}),
    {C1, S1, D1} = data(C, S, <<"to server">>, 100),
    ?assertEqual(<<"srv">>, record_cid(D1, 3)),
    {_, _, D2} = data(S1, C1, <<"to client">>, 100),
    ?assertEqual(<<"client-cid">>, record_cid(D2, 10)).

%% The server does not want one: no CID in either direction.
connection_id_refused_test() ->
    {C, S, W} = established(#{connection_id => true}, #{}),
    ?assertEqual(false, lists:keymember(54, 1, maps:get(extensions, first_server_hello(W)))),
    {C1, S1, D1} = data(C, S, <<"x">>, 100),
    ?assertEqual(none, record_cid(D1, 8)),
    {_, _, D2} = data(S1, C1, <<"y">>, 100),
    ?assertEqual(none, record_cid(D2, 8)).

%% A record with a CID we never offered is rejected.
unexpected_cid_record_test() ->
    {C, _, _} = established(#{connection_id => <<"abcd">>}, #{connection_id => <<"efgh">>}),
    {ok, _, [{send, D}]} = webrtc_dtls:send(<<"x">>, C),
    {_, Plain, _} = established(#{}, #{}),
    ?assertMatch({_, []}, webrtc_dtls:handle_packet(D, 100, Plain)).

%% A post-handshake message from `From', as it goes on the wire.
post_handshake(Type, Body, Now, From) ->
    {_, F1} = webrtc_dtls:queue_handshake(Type, Body, false, From),
    F2 = webrtc_dtls13:flush(Now, F1),
    {F2#dtls{out = []}, [D || {send, D} <- lists:reverse(F2#dtls.out)]}.

%% NewConnectionId for immediate use switches the CID of the records
%% the receiver sends; without negotiated CIDs it is unexpected.
new_connection_id_test() ->
    {C, S, _} = established(#{connection_id => <<"cc">>}, #{connection_id => <<"ss">>}),
    Body = <<4:16, 3, "new", 0>>,
    {_, [D]} = post_handshake(new_connection_id, Body, 100, S),
    {C1, _} = webrtc_dtls:handle_packet(D, 100, C),
    {ok, _, [{send, Out}]} = webrtc_dtls:send(<<"x">>, C1),
    ?assertEqual(<<"new">>, record_cid(Out, 3)),
    {C2, S2, _} = established(#{}, #{}),
    {_, [D2]} = post_handshake(new_connection_id, Body, 100, S2),
    {C3, Acts} = webrtc_dtls:handle_packet(D2, 100, C2),
    ?assertEqual(failed, C3#dtls.state),
    ?assertMatch([_ | _], [A || {send, _} = A <- Acts]).
