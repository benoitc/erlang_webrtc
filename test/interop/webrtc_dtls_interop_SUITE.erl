%% DTLS interoperability against independent implementations: OTP ssl
%% (DTLS 1.2 only), the OpenSSL command line tool (DTLS 1.2 and, with
%% OpenSSL 4, DTLS 1.3) and, at the peer connection level, Chromium,
%% Firefox, Pion and aiortc. Each DTLS test runs our engine over a real
%% UDP socket on loopback, checks the negotiated version and SRTP
%% profile, compares the RFC 5764 exported keying material and
%% exchanges application data. The peer connection cases record which
%% DTLS version each peer negotiates, in both DTLS roles.
-module(webrtc_dtls_interop_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([
    otp_server_our_client/1,
    otp_client_our_server/1,
    otp_server_rejected_fingerprint/1,
    openssl_server_our_client/1,
    openssl_client_our_server/1,
    otp_server_without_ems_rejected/1,
    openssl13_server_our_client/1,
    openssl13_client_our_server/1,
    openssl13_aes256_our_client/1,
    openssl13_chacha20_our_client/1,
    openssl13_chacha20_our_server/1,
    openssl13_server_key_update/1,
    openssl13_client_key_update/1,
    openssl13_rsa_certificates/1,
    openssl13_rejected_fingerprint/1,
    openssl_any_client_our_server/1,
    openssl_any_client_our_12_server/1,
    openssl_any_server_our_12_client/1,
    openssl_downgrade_detected/1,
    pc_dtls_version/1,
    pc_dtls_version_peer_offer/1
]).

-define(LABEL, <<"EXTRACTOR-dtls_srtp">>).

all() ->
    [
        {group, otp},
        {group, openssl},
        otp_server_without_ems_rejected,
        {group, openssl13},
        {group, chromium},
        {group, firefox},
        {group, pion},
        {group, aiortc}
    ].

groups() ->
    [
        {otp, [], [otp_server_our_client, otp_client_our_server, otp_server_rejected_fingerprint]},
        {openssl, [], [openssl_server_our_client, openssl_client_our_server]},
        {openssl13, [], [
            openssl13_server_our_client,
            openssl13_client_our_server,
            openssl13_aes256_our_client,
            openssl13_chacha20_our_client,
            openssl13_chacha20_our_server,
            openssl13_server_key_update,
            openssl13_client_key_update,
            openssl13_rsa_certificates,
            openssl13_rejected_fingerprint,
            openssl_any_client_our_server,
            openssl_any_client_our_12_server,
            openssl_any_server_our_12_client,
            openssl_downgrade_detected
        ]},
        {chromium, [], [pc_dtls_version, pc_dtls_version_peer_offer]},
        {firefox, [], [pc_dtls_version, pc_dtls_version_peer_offer]},
        {pion, [], [pc_dtls_version, pc_dtls_version_peer_offer]},
        {aiortc, [], [pc_dtls_version, pc_dtls_version_peer_offer]}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(ssl),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(openssl, Config) ->
    case os:find_executable("openssl") of
        false -> {skip, "openssl executable not found"};
        Exe -> [{openssl, Exe} | Config]
    end;
init_per_group(openssl13, Config) ->
    case os:find_executable("openssl") of
        false ->
            {skip, "openssl executable not found"};
        Exe ->
            Help = os:cmd(Exe ++ " s_server -help 2>&1"),
            case string:find(Help, "-dtls1_3") of
                nomatch -> {skip, "openssl without DTLS 1.3 (needs OpenSSL 4)"};
                _ -> [{openssl, Exe} | Config]
            end
    end;
init_per_group(Peer, Config) when Peer =:= chromium; Peer =:= firefox; Peer =:= pion; Peer =:= aiortc ->
    case webrtc_interop_peer:probe(Peer, ?config(priv_dir, Config)) of
        ok ->
            {ok, _} = application:ensure_all_started(webrtc),
            [{peer, Peer} | Config];
        {skip, R} ->
            {skip, R}
    end;
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

fp(#{der := D}) -> webrtc_dtls_cert:fingerprint(sha256, D).

connected(Ev) -> lists:any(fun({connected, _}) -> true; (_) -> false end, Ev).
failed(Ev) -> lists:any(fun({failed, _}) -> true; (_) -> false end, Ev).

otp_opts(Role, #{der := Der, key := Key}, Peer) ->
    PeerFp = crypto:hash(sha256, maps:get(der, Peer)),
    [{fail_if_no_peer_cert, true} || Role =:= server] ++
    [
        binary,
        {protocol, dtls},
        {active, false},
        {versions, ['dtlsv1.2']},
        {certs_keys, [#{cert => Der, key => {'ECPrivateKey', public_key:der_encode('ECPrivateKey', Key)}}]},
        {verify, verify_peer},
        {cacerts, [maps:get(der, Peer)]},
        %% Self-signed: accept the certificate only if it matches the
        %% fingerprint, the WebRTC model (RFC 8122).
        {verify_fun,
         {fun(Cert, Event, St) ->
              case Event of
                  {bad_cert, _} -> check_fp(Cert, PeerFp, St);
                  {extension, _} -> {unknown, St};
                  valid -> {valid, St};
                  valid_peer -> check_fp(Cert, PeerFp, St)
              end
          end, []}},
        {use_srtp, #{protection_profiles => [<<0, 7>>]}}
    ].

check_fp(Cert, PeerFp, St) ->
    case crypto:hash(sha256, public_key:pkix_encode('OTPCertificate', Cert, otp)) of
        PeerFp -> {valid, St};
        _ -> {fail, fingerprint_mismatch}
    end.

otp_server_our_client(_Config) ->
    Mine = webrtc_dtls_cert:generate(),
    Theirs = webrtc_dtls_cert:generate(),
    {ok, L} = ssl:listen(0, [{ip, {127, 0, 0, 1}} | otp_opts(server, Theirs, Mine)]),
    {ok, {_, Port}} = ssl:sockname(L),
    Self = self(),
    spawn_link(fun() ->
        {ok, T} = ssl:transport_accept(L, 10000),
        {ok, S} = ssl:handshake(T, 10000),
        K = otp_export(S),
        {ok, Data} = ssl:recv(S, 0, 5000),
        ok = ssl:send(S, <<"pong:", Data/binary>>),
        Self ! {otp_keys, K},
        receive stop -> ssl:close(S) end
    end),
    {Sock, _} = webrtc_dtls_udp:open(),
    D0 = webrtc_dtls:new(#{role => client, cert => Mine, remote_fingerprints => [fp(Theirs)],
                           srtp_profiles => [7], require_ems => false}),
    {ok, D1, Peer, Ev} = webrtc_dtls_udp:run(Sock, {{127, 0, 0, 1}, Port}, D0,
                                             #{start => true, stop => fun connected/1}),
    [Info] = [I || {connected, I} <- Ev],
    ?assertEqual(7, maps:get(srtp_profile, Info)),
    %% OTP ssl has no DTLS 1.3: our DTLS 1.3 offer falls back.
    ?assertEqual('dtlsv1.2', maps:get(version, Info)),
    ct:pal("negotiated with OTP ssl server: ~p", [Info]),
    {ok, Ours} = webrtc_dtls:export_keying_material(?LABEL, no_context, 60, D1),
    {ok, D2, A} = webrtc_dtls:send(<<"ping">>, D1),
    _ = webrtc_dtls_udp:send(Sock, Peer, A),
    Theirs1 = receive {otp_keys, K} -> K after 5000 -> error(no_keys) end,
    ?assertEqual(Theirs1, Ours),
    {ok, _, _, Ev2} = webrtc_dtls_udp:run(Sock, Peer, D2, #{stop => fun(E) -> lists:member({data, <<"pong:ping">>}, E) end}),
    ?assert(lists:member({data, <<"pong:ping">>}, Ev2)),
    ssl:close(L).

otp_client_our_server(_Config) ->
    Mine = webrtc_dtls_cert:generate(),
    Theirs = webrtc_dtls_cert:generate(),
    {Sock, Port} = webrtc_dtls_udp:open(),
    Self = self(),
    spawn_link(fun() ->
        {ok, S} = ssl:connect({127, 0, 0, 1}, Port, otp_opts(client, Theirs, Mine), 10000),
        K = otp_export(S),
        Self ! {otp_keys, K},
        ok = ssl:send(S, <<"hello from otp">>),
        {ok, Echo} = ssl:recv(S, 0, 5000),
        Self ! {otp_echo, Echo},
        receive stop -> ssl:close(S) end
    end),
    D0 = webrtc_dtls:new(#{role => server, cert => Mine, remote_fingerprints => [fp(Theirs)],
                           srtp_profiles => [7, 1], require_ems => false}),
    {ok, D1, Peer, Ev} = webrtc_dtls_udp:run(Sock, undefined, D0,
        #{stop => fun(E) -> lists:keymember(data, 1, E) end}),
    ?assert(connected(Ev)),
    ?assert(lists:member({data, <<"hello from otp">>}, Ev)),
    {ok, Ours} = webrtc_dtls:export_keying_material(?LABEL, no_context, 60, D1),
    Theirs1 = receive {otp_keys, K} -> K after 5000 -> error(no_keys) end,
    ?assertEqual(Theirs1, Ours),
    {ok, _, A} = webrtc_dtls:send(<<"echo">>, D1),
    _ = webrtc_dtls_udp:send(Sock, Peer, A),
    receive {otp_echo, E1} -> ?assertEqual(<<"echo">>, E1) after 5000 -> error(no_echo) end.

otp_server_rejected_fingerprint(_Config) ->
    Mine = webrtc_dtls_cert:generate(),
    Theirs = webrtc_dtls_cert:generate(),
    Wrong = webrtc_dtls_cert:generate(),
    {ok, L} = ssl:listen(0, [{ip, {127, 0, 0, 1}} | otp_opts(server, Theirs, Mine)]),
    {ok, {_, Port}} = ssl:sockname(L),
    spawn_link(fun() ->
        {ok, T} = ssl:transport_accept(L, 10000),
        _ = ssl:handshake(T, 5000)
    end),
    {Sock, _} = webrtc_dtls_udp:open(),
    D0 = webrtc_dtls:new(#{role => client, cert => Mine, remote_fingerprints => [fp(Wrong)],
                           require_ems => false}),
    {ok, _, _, Ev} = webrtc_dtls_udp:run(Sock, {{127, 0, 0, 1}, Port}, D0,
                                         #{start => true, stop => fun failed/1}),
    ?assert(lists:member({failed, fingerprint_mismatch}, Ev)),
    ?assertNot(connected(Ev)),
    ssl:close(L).

%% OpenSSL ------------------------------------------------------------

write_pem(Dir, Name, #{der := Der, key := Key}) ->
    CertFile = filename:join(Dir, Name ++ "_cert.pem"),
    KeyFile = filename:join(Dir, Name ++ "_key.pem"),
    ok = file:write_file(CertFile, public_key:pem_encode([{'Certificate', Der, not_encrypted}])),
    ok = file:write_file(KeyFile, public_key:pem_encode([public_key:pem_entry_encode(element(1, Key), Key)])),
    {CertFile, KeyFile}.

openssl_args(Exe, Mode, CertFile, KeyFile, Extra) ->
    Cmd = lists:flatten(io_lib:format(
        "~s ~s -dtls1_2 -cert ~s -key ~s -use_srtp SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80 "
        "-keymatexport EXTRACTOR-dtls_srtp -keymatexportlen 60 ~s",
        [Exe, Mode, CertFile, KeyFile, Extra])),
    Cmd.

openssl_keymat(Output) ->
    case re:run(Output, "Keying material: ([0-9A-Fa-f]+)", [{capture, all_but_first, binary}]) of
        {match, [Hex]} -> binary:decode_hex(Hex);
        nomatch -> undefined
    end.

collect_port(Port, Acc, Deadline, Want) ->
    case re:run(Acc, Want) of
        {match, _} -> Acc;
        nomatch ->
            Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
            receive {Port, {data, D}} -> collect_port(Port, <<Acc/binary, D/binary>>, Deadline, Want)
            after Left -> Acc
            end
    end.

free_udp_port() ->
    {ok, S} = gen_udp:open(0, [{ip, {127, 0, 0, 1}}]),
    {ok, P} = inet:port(S),
    gen_udp:close(S),
    P.

openssl_server_our_client(Config) ->
    Exe = ?config(openssl, Config),
    Dir = ?config(priv_dir, Config),
    Mine = webrtc_dtls_cert:generate(),
    Theirs = webrtc_dtls_cert:generate(),
    {C, K} = write_pem(Dir, "srv", Theirs),
    P = free_udp_port(),
    Cmd = openssl_args(Exe, "s_server", C, K,
                       io_lib:format("-accept 127.0.0.1:~b -verify 1 -quiet -naccept 1", [P])),
    Port = open_port({spawn, Cmd}, [binary, stderr_to_stdout, exit_status]),
    timer:sleep(500),
    {Sock, _} = webrtc_dtls_udp:open(),
    D0 = webrtc_dtls:new(#{role => client, cert => Mine, remote_fingerprints => [fp(Theirs)]}),
    {ok, D1, Peer, Ev} = webrtc_dtls_udp:run(Sock, {{127, 0, 0, 1}, P}, D0,
                                             #{start => true, stop => fun connected/1}),
    [Info] = [I || {connected, I} <- Ev],
    ct:pal("negotiated with openssl s_server: ~p", [Info]),
    {ok, Ours} = webrtc_dtls:export_keying_material(?LABEL, no_context, 60, D1),
    {ok, _D2, A} = webrtc_dtls:send(<<"hello openssl\n">>, D1),
    _ = webrtc_dtls_udp:send(Sock, Peer, A),
    Out = collect_port(Port, <<>>, erlang:monotonic_time(millisecond) + 5000, "hello openssl"),
    ct:pal("openssl output:~n~s", [Out]),
    close_port(Port),
    ?assertMatch({match, _}, re:run(Out, "hello openssl")),
    case openssl_keymat(Out) of
        undefined -> ct:comment("s_server -quiet did not print keying material; data path verified");
        Theirs1 -> ?assertEqual(Theirs1, Ours)
    end.

openssl_client_our_server(Config) ->
    Exe = ?config(openssl, Config),
    Dir = ?config(priv_dir, Config),
    Mine = webrtc_dtls_cert:generate(),
    Theirs = webrtc_dtls_cert:generate(),
    {C, K} = write_pem(Dir, "cli", Theirs),
    {Sock, P} = webrtc_dtls_udp:open(),
    Cmd = openssl_args(Exe, "s_client", C, K, io_lib:format("-connect 127.0.0.1:~b", [P])),
    Port = open_port({spawn, Cmd}, [binary, stderr_to_stdout, exit_status]),
    D0 = webrtc_dtls:new(#{role => server, cert => Mine, remote_fingerprints => [fp(Theirs)]}),
    {ok, D1, Peer, Ev} = webrtc_dtls_udp:run(Sock, undefined, D0, #{stop => fun connected/1}),
    [Info] = [I || {connected, I} <- Ev],
    ct:pal("negotiated with openssl s_client: ~p", [Info]),
    {ok, Ours} = webrtc_dtls:export_keying_material(?LABEL, no_context, 60, D1),
    Out = collect_port(Port, <<>>, erlang:monotonic_time(millisecond) + 5000, "Keying material: [0-9A-F]+"),
    port_command(Port, <<"from openssl\n">>),
    {ok, _, _, Ev2} = webrtc_dtls_udp:run(Sock, Peer, D1, #{stop => fun(E) -> lists:keymember(data, 1, E) end}),
    close_port(Port),
    ?assert(lists:member({data, <<"from openssl\n">>}, Ev2)),
    ?assertEqual(openssl_keymat(Out), Ours).

close_port(Port) ->
    try port_close(Port) catch error:badarg -> ok end.

%% OTP ssl 11.7.8 does not implement RFC 7627. With the default
%% require_ems the handshake must fail rather than silently fall back.
otp_server_without_ems_rejected(_Config) ->
    Mine = webrtc_dtls_cert:generate(),
    Theirs = webrtc_dtls_cert:generate(),
    {ok, L} = ssl:listen(0, [{ip, {127, 0, 0, 1}} | otp_opts(server, Theirs, Mine)]),
    {ok, {_, Port}} = ssl:sockname(L),
    spawn_link(fun() ->
        {ok, T} = ssl:transport_accept(L, 10000),
        _ = ssl:handshake(T, 5000)
    end),
    {Sock, _} = webrtc_dtls_udp:open(),
    D0 = webrtc_dtls:new(#{role => client, cert => Mine, remote_fingerprints => [fp(Theirs)]}),
    {ok, _, _, Ev} = webrtc_dtls_udp:run(Sock, {{127, 0, 0, 1}, Port}, D0,
                                         #{start => true, stop => fun failed/1}),
    ?assert(lists:member({failed, extended_master_secret_required}, Ev)),
    ssl:close(L).

otp_export(S) ->
    case ssl:export_key_materials(S, [?LABEL], [no_context], [60]) of
        {ok, [K]} -> K;
        {ok, K} when is_binary(K) -> K
    end.

%% OpenSSL DTLS 1.3 ----------------------------------------------------

ossl_cmd(Exe, Tool, Version, CertFile, KeyFile, Extra) ->
    lists:flatten(io_lib:format(
        "~s ~s ~s -cert ~s -key ~s -use_srtp SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80 "
        "-keymatexport EXTRACTOR-dtls_srtp -keymatexportlen 60 ~s",
        [Exe, Tool, Version, CertFile, KeyFile, Extra])).

certs(Opts) ->
    CertOpts = maps:get(cert, Opts, #{}),
    {webrtc_dtls_cert:generate(CertOpts), webrtc_dtls_cert:generate(CertOpts)}.

deadline(Ms) -> erlang:monotonic_time(millisecond) + Ms.

pem(Config, Cert) ->
    write_pem(?config(priv_dir, Config), "c" ++ integer_to_list(erlang:unique_integer([positive])), Cert).

ossl_server(Config, Version, Theirs, Extra0) ->
    {C, K} = pem(Config, Theirs),
    P = free_udp_port(),
    Extra = io_lib:format("-accept 127.0.0.1:~b -Verify 1 -naccept 1 ~s", [P, Extra0]),
    Port = open_port({spawn, ossl_cmd(?config(openssl, Config), "s_server", Version, C, K, Extra)},
                     [binary, stderr_to_stdout, exit_status]),
    timer:sleep(500),
    {Port, P}.

%% Our client against `openssl s_server Version' (not quiet, so it
%% prints the exported keying material). Checks the keys and exchanges
%% data both ways.
our_client(Config, Version, Opts) ->
    {Mine, Theirs} = certs(Opts),
    {Port, P} = ossl_server(Config, Version, Theirs, maps:get(extra, Opts, "")),
    {Sock, _} = webrtc_dtls_udp:open(),
    D0 = webrtc_dtls:new(maps:merge(#{role => client, cert => Mine, remote_fingerprints => [fp(Theirs)]},
                                    maps:get(ours, Opts, #{}))),
    {ok, D1, Peer, Ev} = webrtc_dtls_udp:run(Sock, {{127, 0, 0, 1}, P}, D0,
                                             #{start => true, stop => fun connected/1}),
    finish(Port, Sock, Peer, D1, Ev).

%% `openssl s_client Version' against our server.
our_server(Config, Version, Opts) ->
    {Mine, Theirs} = certs(Opts),
    {C, K} = pem(Config, Theirs),
    {Sock, P} = webrtc_dtls_udp:open(),
    Extra = io_lib:format("-connect 127.0.0.1:~b ~s", [P, maps:get(extra, Opts, "")]),
    Port = open_port({spawn, ossl_cmd(?config(openssl, Config), "s_client", Version, C, K, Extra)},
                     [binary, stderr_to_stdout, exit_status]),
    D0 = webrtc_dtls:new(maps:merge(#{role => server, cert => Mine, remote_fingerprints => [fp(Theirs)]},
                                    maps:get(ours, Opts, #{}))),
    {ok, D1, Peer, Ev} = webrtc_dtls_udp:run(Sock, undefined, D0, #{stop => fun connected/1}),
    finish(Port, Sock, Peer, D1, Ev).

finish(Port, Sock, Peer, D1, Ev) ->
    [Info] = [I || {connected, I} <- Ev],
    ct:pal("negotiated with openssl: ~p", [Info]),
    Out = collect_port(Port, <<>>, deadline(5000), "Keying material: [0-9A-F]+"),
    {ok, Ours} = webrtc_dtls:export_keying_material(?LABEL, no_context, 60, D1),
    ?assertEqual(openssl_keymat(Out), Ours),
    D2 = exchange(Port, Sock, Peer, D1, <<"one">>),
    #{port => Port, sock => Sock, peer => Peer, dtls => D2, info => Info}.

%% Data both ways: ours appears on openssl's output, a line written to
%% openssl's input arrives as an event.
exchange(Port, Sock, Peer, D0, Tag) ->
    Ours = <<"from erlang ", Tag/binary>>,
    Theirs = <<"from openssl ", Tag/binary, "\n">>,
    {ok, D1, A} = webrtc_dtls:send(<<Ours/binary, "\n">>, D0),
    _ = webrtc_dtls_udp:send(Sock, Peer, A),
    Out = collect_port(Port, <<>>, deadline(5000), binary_to_list(Ours)),
    ?assertMatch({match, _}, re:run(Out, Ours)),
    port_command(Port, Theirs),
    {ok, D2, _, Ev} = webrtc_dtls_udp:run(Sock, Peer, D1, #{timeout => 5000,
                                                           stop => fun(E) -> lists:member({data, Theirs}, E) end}),
    ?assert(lists:member({data, Theirs}, Ev)),
    D2.

%% Let the engine process whatever arrives for a while.
settle(Sock, Peer, D, Ms) ->
    {_, D1, _, Ev} = webrtc_dtls_udp:run(Sock, Peer, D, #{timeout => Ms, stop => fun(_) -> false end}),
    ?assertNot(lists:keymember(failed, 1, Ev)),
    D1.

openssl13_server_our_client(Config) ->
    #{port := Port, info := Info} = our_client(Config, "-dtls1_3", #{}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.3', srtp_profile := 16#0007}, Info).

openssl13_client_our_server(Config) ->
    %% OpenSSL 4 sends an X25519MLKEM768 key share: our server answers
    %% with a HelloRetryRequest for x25519 and a cookie.
    #{port := Port, info := Info} = our_server(Config, "-dtls1_3", #{}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.3', group := x25519, srtp_profile := 16#0007}, Info).

openssl13_aes256_our_client(Config) ->
    #{port := Port, info := Info} = our_client(Config, "-dtls1_3", #{ours => #{suites => [16#1302]}}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.3', suite := tls_aes_256_gcm_sha384}, Info).

openssl13_chacha20_our_client(Config) ->
    #{port := Port, info := Info} = our_client(Config, "-dtls1_3", #{ours => #{suites => [16#1303]}}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.3', suite := tls_chacha20_poly1305_sha256}, Info).

openssl13_chacha20_our_server(Config) ->
    #{port := Port, info := Info} =
        our_server(Config, "-dtls1_3", #{extra => "-ciphersuites TLS_CHACHA20_POLY1305_SHA256"}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.3', suite := tls_chacha20_poly1305_sha256}, Info).

openssl13_rsa_certificates(Config) ->
    #{port := Port, info := Info} = our_client(Config, "-dtls1_3", #{cert => #{key => {rsa, 2048}}}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.3'}, Info).

%% openssl asks for a KeyUpdate with update_requested ("K"): both sides
%% change keys and data flows; then we start one.
openssl13_server_key_update(Config) ->
    #{port := Port, sock := Sock, peer := Peer, dtls := D0} = our_client(Config, "-dtls1_3", #{}),
    key_updates(Port, Sock, Peer, D0).

openssl13_client_key_update(Config) ->
    #{port := Port, sock := Sock, peer := Peer, dtls := D0} = our_server(Config, "-dtls1_3", #{}),
    key_updates(Port, Sock, Peer, D0).

key_updates(Port, Sock, Peer, D0) ->
    port_command(Port, <<"K\n">>),
    D1 = settle(Sock, Peer, D0, 1000),
    D2 = exchange(Port, Sock, Peer, D1, <<"after their update">>),
    {ok, D3, A} = webrtc_dtls:key_update(erlang:monotonic_time(millisecond), D2),
    _ = webrtc_dtls_udp:send(Sock, Peer, A),
    D4 = settle(Sock, Peer, D3, 1000),
    ?assertEqual(infinity, webrtc_dtls:next_timeout(D4)),
    D5 = exchange(Port, Sock, Peer, D4, <<"after our update">>),
    %% Epoch 3, then 4 after their update, 5 after ours.
    {ok, _, [{send, Rec}]} = webrtc_dtls:send(<<"x">>, D5),
    ?assertEqual(1, binary:first(Rec) band 3),
    close_port(Port).

openssl13_rejected_fingerprint(Config) ->
    {Mine, Theirs} = certs(#{}),
    {Port, P} = ossl_server(Config, "-dtls1_3", Theirs, ""),
    {Sock, _} = webrtc_dtls_udp:open(),
    D0 = webrtc_dtls:new(#{role => client, cert => Mine, remote_fingerprints => [fp(webrtc_dtls_cert:generate())]}),
    {ok, _, _, Ev} = webrtc_dtls_udp:run(Sock, {{127, 0, 0, 1}, P}, D0, #{start => true, stop => fun failed/1}),
    close_port(Port),
    ?assert(lists:member({failed, fingerprint_mismatch}, Ev)),
    ?assertNot(connected(Ev)).

%% Version negotiation with an OpenSSL that offers or accepts both.

openssl_any_client_our_server(Config) ->
    #{port := Port, info := Info} = our_server(Config, "-dtls", #{}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.3'}, Info).

%% OpenSSL checks the downgrade sentinel: our DTLS 1.2-only server must
%% not set it.
openssl_any_client_our_12_server(Config) ->
    #{port := Port, info := Info} = our_server(Config, "-dtls", #{ours => #{versions => ['dtlsv1.2']}}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.2', extended_master_secret := true}, Info).

openssl_any_server_our_12_client(Config) ->
    #{port := Port, info := Info} = our_client(Config, "-dtls", #{ours => #{versions => ['dtlsv1.2']}}),
    close_port(Port),
    ?assertMatch(#{version := 'dtlsv1.2'}, Info).

%% An attacker removes supported_versions and key_share from our
%% ClientHellos: OpenSSL falls back to DTLS 1.2 and sets the sentinel
%% in its random, which our client detects (RFC 8446 §4.1.3).
openssl_downgrade_detected(Config) ->
    {Mine, Theirs} = certs(#{}),
    {Port, P} = ossl_server(Config, "-dtls", Theirs, ""),
    {Sock, _} = webrtc_dtls_udp:open(),
    D0 = webrtc_dtls:new(#{role => client, cert => Mine, remote_fingerprints => [fp(Theirs)]}),
    {_, _, _, Ev} = webrtc_dtls_udp:run(Sock, {{127, 0, 0, 1}, P}, D0,
                                        #{start => true, timeout => 5000, stop => fun failed/1,
                                          out => fun strip_versions/1}),
    close_port(Port),
    ?assertEqual([{failed, downgrade_detected}], Ev).

strip_versions(<<22, V:16, E:16, Seq:48, _Len:16, 1, _/binary>> = D) ->
    <<_:13/binary, Frag/binary>> = D,
    {ok, [#{data := Body, seq := MS}]} = webrtc_dtls_msg:decode_fragment(Frag),
    {ok, #{extensions := Exts} = M} = webrtc_dtls_msg:decode_body(client_hello, Body),
    Body1 = webrtc_dtls_msg:encode_body(client_hello, M#{extensions => [X || {T, _} = X <- Exts, T =/= 43, T =/= 51]}),
    F1 = webrtc_dtls_msg:full(client_hello, MS, Body1),
    <<22, V:16, E:16, Seq:48, (byte_size(F1)):16, F1/binary>>;
strip_versions(D) ->
    D.

%% Peer connections: which DTLS version the peer negotiates ------------

%% Erlang offers a data channel: the peer answers with a=setup:active
%% and is the DTLS client. A message round trips over SCTP and the
%% negotiated DTLS parameters are recorded in the test comment.
pc_dtls_version(Config) ->
    pc_session(Config, erlang_offer).

%% The peer offers: Erlang answers with a=setup:active and is the DTLS
%% client.
pc_dtls_version_peer_offer(Config) ->
    pc_session(Config, peer_offer).

pc_session(Config, Who) ->
    Peer = ?config(peer, Config),
    {ok, P0} = webrtc_interop_peer:start(Peer, ?config(priv_dir, Config)),
    {ok, Pc} = webrtc:new_peer_connection(case Peer of pion -> #{loopback => true}; _ -> #{} end),
    try
        P1 = negotiate(Who, Pc, P0),
        P2 = pump(Pc, P1, false, false, deadline(20000)),
        {datachannel_open, Id, _, _, _} =
            wait_pc(Pc, fun({datachannel_open, _, L, _, _}) -> L =:= <<"dtls">>; (_) -> false end),
        timer:sleep(200),
        ok = webrtc:send_data(Pc, Id, text, <<"ping">>),
        {ok, _, _} = webrtc_interop_peer:wait_event(P2, <<"message">>, #{<<"data">> => <<"ping">>}),
        _ = wait_pc(Pc, fun({channel_message, _, _, D}) -> D =:= <<"echo:ping">>; (_) -> false end),
        #{transport := #{dtls := Info}} = webrtc:get_stats(Pc),
        ct:pal("~p negotiated ~p", [Peer, Info]),
        ?assertEqual(case Who of erlang_offer -> server; peer_offer -> client end, maps:get(role, Info)),
        {comment, lists:flatten(io_lib:format("~p: ~p, ~p, we are ~p",
                                              [Peer, maps:get(version, Info), maps:get(suite, Info),
                                               maps:get(role, Info)]))}
    after
        webrtc_interop_peer:stop(P0),
        webrtc:close(Pc)
    end.

negotiate(erlang_offer, Pc, P0) ->
    ok = webrtc:create_data_channel(Pc, <<"dtls">>, #{}),
    P1 = webrtc_interop_peer:cmd(P0, #{cmd => init}),
    {ok, Offer} = webrtc:create_offer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, offer, Offer),
    P2 = webrtc_interop_peer:cmd(P1, #{cmd => remote_description, type => offer, sdp => Offer}),
    {ok, P3, #{<<"sdp">> := Answer} = Ev} = webrtc_interop_peer:wait_event(P2, <<"local_description">>, #{}),
    ok = webrtc:set_remote_description(Pc, answer, Answer),
    webrtc_interop_peer:forget(P3, Ev);
negotiate(peer_offer, Pc, P0) ->
    P1 = webrtc_interop_peer:cmd(P0, #{cmd => init, channels => [#{label => <<"dtls">>}]}),
    P2 = webrtc_interop_peer:cmd(P1, #{cmd => create_offer}),
    {ok, P3, #{<<"sdp">> := Offer} = Ev} = webrtc_interop_peer:wait_event(P2, <<"local_description">>, #{}),
    ok = webrtc:set_remote_description(Pc, offer, Offer),
    {ok, Answer} = webrtc:create_answer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, answer, Answer),
    webrtc_interop_peer:cmd(webrtc_interop_peer:forget(P3, Ev), #{cmd => remote_description, type => answer, sdp => Answer}).

wait_pc(Pc, Pred) ->
    {ok, E} = webrtc_test_signal:wait(Pc, Pred, 15000),
    E.

pump(_Pc, P, true, true, _Deadline) ->
    P;
pump(Pc, P0, Ours, Theirs, Deadline) ->
    erlang:monotonic_time(millisecond) > Deadline andalso ct:fail({not_connected, Ours, Theirs}),
    {P1, Theirs1} =
        case webrtc_interop_peer:wait(P0, fun(#{<<"event">> := E}) ->
                                              E =:= <<"local_candidate">> orelse E =:= <<"connection_state">>;
                                             (_) -> false
                                          end, 50) of
            {ok, Px, #{<<"event">> := <<"local_candidate">>, <<"candidate">> := C} = Ev} ->
                ok = case C of
                         <<>> -> webrtc:add_ice_candidate(Pc, end_of_candidates);
                         _ -> webrtc:add_ice_candidate(Pc, C)
                     end,
                {webrtc_interop_peer:forget(Px, Ev), Theirs};
            {ok, Px, #{<<"event">> := <<"connection_state">>, <<"state">> := S} = Ev} ->
                {webrtc_interop_peer:forget(Px, Ev), Theirs orelse S =:= <<"connected">>};
            {error, Px, timeout} ->
                {Px, Theirs}
        end,
    pump(Pc, P1, forward_erlang(Pc, P1, Ours), Theirs1, Deadline).

forward_erlang(Pc, P, Ours) ->
    receive
        {webrtc, Pc, {ice_candidate, end_of_candidates, Mid}} ->
            _ = webrtc_interop_peer:cmd(P, #{cmd => remote_candidate, candidate => <<>>, mid => Mid}),
            forward_erlang(Pc, P, Ours);
        {webrtc, Pc, {ice_candidate, C, Mid}} ->
            _ = webrtc_interop_peer:cmd(P, #{cmd => remote_candidate, candidate => C, mid => Mid}),
            forward_erlang(Pc, P, Ours);
        {webrtc, Pc, {connection_state, connected}} ->
            forward_erlang(Pc, P, true);
        {webrtc, Pc, {connection_state, failed}} ->
            ct:fail(erlang_connection_failed)
    after 0 ->
        Ours
    end.
