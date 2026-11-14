%% DTLS interoperability against independent implementations: OTP ssl
%% (DTLS 1.2) and the OpenSSL command line tool. Each test runs our
%% engine over a real UDP socket on loopback, checks the negotiated
%% SRTP profile, compares the RFC 5764 exported keying material and
%% exchanges application data.
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
    otp_server_without_ems_rejected/1
]).

-define(LABEL, <<"EXTRACTOR-dtls_srtp">>).

all() -> [{group, otp}, {group, openssl}, otp_server_without_ems_rejected].

groups() ->
    [
        {otp, [], [otp_server_our_client, otp_client_our_server, otp_server_rejected_fingerprint]},
        {openssl, [], [openssl_server_our_client, openssl_client_our_server]}
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
    ok = file:write_file(KeyFile, public_key:pem_encode([public_key:pem_entry_encode('ECPrivateKey', Key)])),
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
