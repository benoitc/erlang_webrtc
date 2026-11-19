%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% A DTLS 1.2 server takes the client's ChangeCipherSpec only after the
%% CertificateVerify (RFC 5246 §7.4.8), found by DTLS-Fuzzer: before,
%% an early CCS made the server read the CertificateVerify encrypted.
-module(webrtc_dtls12_ccs_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("webrtc/src/dtls/webrtc_dtls.hrl").

-define(CERT, 11).
-define(CKE, 16).
-define(CV, 15).

%% The client's second flight, one record per handshake message, with
%% the client state that sent it and the server waiting for it.
flight() ->
    C = webrtc_dtls_cert:generate(),
    S = webrtc_dtls_cert:generate(),
    Fp = fun(#{der := D}) -> webrtc_dtls_cert:fingerprint(sha256, D) end,
    Cl0 = webrtc_dtls:new(#{role => client, cert => C, remote_fingerprints => [Fp(S)], versions => ['dtlsv1.2']}),
    Sv0 = webrtc_dtls:new(#{role => server, cert => S, remote_fingerprints => [Fp(C)]}),
    {Cl1, A0} = webrtc_dtls:start(0, Cl0),
    {Sv1, Hvr} = feed(Sv0, [D || {send, D} <- A0]),
    {Cl2, Hello} = feed(Cl1, Hvr),
    {Sv2, Flight2} = feed(Sv1, Hello),
    {Cl3, Flight3} = feed(Cl2, Flight2),
    Recs = lists:append([webrtc_dtls_record:decode(D) || D <- Flight3]),
    Msgs = lists:append([split(F) || #{epoch := 0, type := handshake, fragment := F} <- Recs]),
    Plain = maps:from_list([{T, M} || <<T, _/binary>> = M <- Msgs]),
    [Ccs] = [R || #{type := change_cipher_spec} = R <- Recs],
    [Fin] = [R || #{epoch := 1} = R <- Recs],
    {Cl3, Sv2, Plain, encode(Ccs), encode(Fin)}.

%% Reordering on the network still completes the handshake.
ccs_before_certificate_verify_test() ->
    {_, Sv, M, Ccs, Fin} = flight(),
    {Sv1, Out} = feed(Sv, [plain(?CERT, M, 10), plain(?CKE, M, 11), Ccs, Fin, plain(?CV, M, 12)]),
    ?assertNotEqual([], Out),
    ?assertEqual(connected, webrtc_dtls:status(Sv1)).

%% A CertificateVerify sent after the CCS, in epoch 1, is never read.
encrypted_certificate_verify_test() ->
    {Cl, Sv, M, Ccs, Fin} = flight(),
    W = maps:get(1, Cl#dtls.write_ciphers),
    Cv = webrtc_dtls_record:protect(handshake, ?DTLS12, 1, 50, maps:get(?CV, M), W),
    {Sv1, Out} = feed(Sv, [plain(?CERT, M, 10), plain(?CKE, M, 11), Ccs, Cv, Fin]),
    ?assertEqual([], Out),
    ?assertNotEqual(connected, webrtc_dtls:status(Sv1)),
    ?assertEqual(0, Sv1#dtls.read_epoch).

split(<<T, Len:24, H:8/binary, Body:Len/binary, Rest/binary>>) -> [<<T, Len:24, H/binary, Body/binary>> | split(Rest)];
split(<<>>) -> [].

plain(Type, M, Seq) -> webrtc_dtls_record:encode(handshake, ?DTLS12, 0, Seq, maps:get(Type, M)).

encode(#{type := T, epoch := E, seq := Seq, fragment := F}) -> webrtc_dtls_record:encode(T, ?DTLS12, E, Seq, F).

feed(E, Ds) ->
    lists:foldl(
        fun(D, {S, Out}) ->
            {S1, A} = webrtc_dtls:handle_packet(D, 0, S),
            {S1, Out ++ [X || {send, X} <- A]}
        end,
        {E, []},
        Ds
    ).
