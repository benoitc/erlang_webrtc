%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Conformance tests for webrtc_srtp: RFC 7714 §16 and §17 vectors,
%% round trips for every profile, ROC handling (RFC 3711 §3.3.1),
%% replay protection, authentication failures and malformed input.
-module(webrtc_srtp_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

-import(webrtc_test_hex, [b/1]).

-define(PROFILES, [
    srtp_aes128_cm_hmac_sha1_80,
    srtp_aes128_cm_hmac_sha1_32,
    srtp_aead_aes_128_gcm,
    srtp_aead_aes_256_gcm
]).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% Sender and receiver contexts sharing one random master key.
pair(Profile) -> pair(Profile, #{}).

pair(Profile, Opts) ->
    #{master_key_len := KL, master_salt_len := SL} = webrtc_srtp_profile:params(Profile),
    K = crypto:strong_rand_bytes(KL),
    S = crypto:strong_rand_bytes(SL),
    {webrtc_srtp:new(Profile, K, S, Opts), webrtc_srtp:new(Profile, K, S, Opts)}.

rtp(Seq) -> rtp(Seq, 16#CAFEBABE, <<"payload of the packet">>).

rtp(Seq, SSRC, Payload) ->
    <<16#80, 96, Seq:16, (Seq * 960):32, SSRC:32, Payload/binary>>.

%% SR with one report block followed by an SDES.
rtcp(SSRC) ->
    <<16#81, 200, 12:16, SSRC:32, 1:64, 2:32, 3:32, 4:32, 5:32, 6:32, 7:32, 8:32, 9:32, 10:32,
        16#81, 202, 2:16, SSRC:32, 1, 2, $a, $b, 0, 0, 0, 0>>.

protect_all(Packets, Tx) ->
    {Out, Tx1} = lists:mapfoldl(
        fun(P, T) ->
            {ok, S, T1} = webrtc_srtp:protect_rtp(P, T),
            {S, T1}
        end,
        Tx,
        Packets
    ),
    {Out, Tx1}.

unprotect_all(Packets, Rx) ->
    lists:mapfoldl(
        fun(P, R) ->
            case webrtc_srtp:unprotect_rtp(P, R) of
                {ok, Plain, R1} -> {{ok, Plain}, R1};
                {error, _} = E -> {E, R}
            end
        end,
        Rx,
        Packets
    ).

%%--------------------------------------------------------------------
%% RFC 7714 §16 (SRTP AES-GCM)
%%--------------------------------------------------------------------

gcm_key128() -> list_to_binary(lists:seq(0, 15)).
gcm_key256() -> list_to_binary(lists:seq(0, 31)).
gcm_salt() -> b("51756964 2070726f 2071756f").

gcm_ctx(Profile, Key, Opts) ->
    Keys = #{
        rtp_key => Key,
        rtp_salt => gcm_salt(),
        rtp_auth_key => <<>>,
        rtcp_key => Key,
        rtcp_salt => gcm_salt(),
        rtcp_auth_key => <<>>
    },
    webrtc_srtp:from_session_keys(Profile, Keys, Opts).

rfc7714_rtp() ->
    b(
        "8040f17b 8041f8d3 5501a0b2 47616c6c\n"
        "         69612065 7374206f 6d6e6973 20646976\n"
        "         69736120 696e2070 61727465 73207472\n"
        "         6573"
    ).

rfc7714_16_1_srtp() ->
    b(
        "8040f17b 8041f8d3 5501a0b2 f24de3a3\n"
        "         fb34de6c acba861c 9d7e4bca be633bd5\n"
        "         0d294e6f 42a5f47a 51c7d19b 36de3adf\n"
        "         8833899d 7f27beb1 6a9152cf 765ee439\n"
        "         0cce"
    ).

rfc7714_16_2_srtp() ->
    b(
        "8040f17b 8041f8d3 5501a0b2 32b1de78\n"
        "         a822fe12 ef9f78fa 332e33aa b1801238\n"
        "         9a58e2f3 b50b2a02 76ffae0f 1ba63799\n"
        "         b87b7aa3 db36dfff d6b0f9bb 7878d7a7\n"
        "         6c13"
    ).

rfc7714_16_1_encrypt_test() ->
    Ctx = gcm_ctx(srtp_aead_aes_128_gcm, gcm_key128(), #{}),
    {ok, Out, _} = webrtc_srtp:protect_rtp(rfc7714_rtp(), Ctx),
    ?assertEqual(rfc7714_16_1_srtp(), Out).

rfc7714_16_1_decrypt_test() ->
    Ctx = gcm_ctx(srtp_aead_aes_128_gcm, gcm_key128(), #{}),
    {ok, Out, _} = webrtc_srtp:unprotect_rtp(rfc7714_16_1_srtp(), Ctx),
    ?assertEqual(rfc7714_rtp(), Out).

rfc7714_16_2_encrypt_test() ->
    Ctx = gcm_ctx(srtp_aead_aes_256_gcm, gcm_key256(), #{}),
    {ok, Out, _} = webrtc_srtp:protect_rtp(rfc7714_rtp(), Ctx),
    ?assertEqual(rfc7714_16_2_srtp(), Out).

rfc7714_16_2_decrypt_test() ->
    Ctx = gcm_ctx(srtp_aead_aes_256_gcm, gcm_key256(), #{}),
    {ok, Out, _} = webrtc_srtp:unprotect_rtp(rfc7714_16_2_srtp(), Ctx),
    ?assertEqual(rfc7714_rtp(), Out).

%% The GCM tag covers the header: flipping a header bit or using the
%% other key size fails.
rfc7714_16_tampered_test() ->
    Ctx = gcm_ctx(srtp_aead_aes_128_gcm, gcm_key128(), #{}),
    <<H, Rest/binary>> = rfc7714_16_1_srtp(),
    ?assertEqual(
        {error, auth_failed}, webrtc_srtp:unprotect_rtp(<<(H bxor 16#01), Rest/binary>>, Ctx)
    ),
    Ctx256 = gcm_ctx(srtp_aead_aes_256_gcm, gcm_key256(), #{}),
    ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtp(rfc7714_16_1_srtp(), Ctx256)).

%%--------------------------------------------------------------------
%% RFC 7714 §17 (SRTCP AES-GCM), SRTCP index 0x5d4
%%--------------------------------------------------------------------

rfc7714_rtcp() ->
    b(
        "81c8000d 4d617273 4e545031 4e545032\n"
        "         52545020 0000042a 0000e930 4c756e61\n"
        "         deadbeef deadbeef deadbeef deadbeef\n"
        "         deadbeef"
    ).

rfc7714_17_1_srtcp() ->
    b(
        "81c8000d 4d617273 63e94885 dcdab67c\n"
        "         a727d766 2f6b7e99 7ff5c0f7 6c06f32d\n"
        "         c676a5f1 730d6fda 4ce09b46 86303ded\n"
        "         0bb9275b c84aa458 96cf4d2f c5abf872\n"
        "         45d9eade 800005d4"
    ).

rfc7714_17_2_srtcp() ->
    b(
        "81c8000d 4d617273 d50ae4d1 f5ce5d30\n"
        "         4ba297e4 7d470c28 2c3ece5d bffe0a50\n"
        "         a2eaa5c1 110555be 8415f658 c61de047\n"
        "         6f1b6fad 1d1eb30c 4446839f 57ff6f6c\n"
        "         b26ac3be 800005d4"
    ).

rfc7714_17_3_srtcp() ->
    b(
        "81c8000d 4d617273 4e545031 4e545032\n"
        "         52545020 0000042a 0000e930 4c756e61\n"
        "         deadbeef deadbeef deadbeef deadbeef\n"
        "         deadbeef 841dd968 3dd78ec9 2ae58790\n"
        "         125f62b3 000005d4"
    ).

rfc7714_17_4_srtcp() ->
    b(
        "81c8000d 4d617273 4e545031 4e545032\n"
        "         52545020 0000042a 0000e930 4c756e61\n"
        "         deadbeef deadbeef deadbeef deadbeef\n"
        "         deadbeef 91db4afb feee5a97 8fab4393\n"
        "         ed2615fe 000005d4"
    ).

rtcp_vector_ssrc() -> 16#4d617273.

rfc7714_17_1_test() ->
    Ctx0 = gcm_ctx(srtp_aead_aes_128_gcm, gcm_key128(), #{}),
    Ctx = webrtc_srtp:set_rtcp_index(rtcp_vector_ssrc(), 16#5d4, Ctx0),
    {ok, Out, _} = webrtc_srtp:protect_rtcp(rfc7714_rtcp(), Ctx),
    ?assertEqual(rfc7714_17_1_srtcp(), Out),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtcp(Out, Ctx0)),
    {ok, Plain, _} = webrtc_srtp:unprotect_rtcp(rfc7714_17_1_srtcp(), Ctx0),
    ?assertEqual(rfc7714_rtcp(), Plain).

rfc7714_17_2_test() ->
    Ctx0 = gcm_ctx(srtp_aead_aes_256_gcm, gcm_key256(), #{}),
    {ok, Plain, _} = webrtc_srtp:unprotect_rtcp(rfc7714_17_2_srtcp(), Ctx0),
    ?assertEqual(rfc7714_rtcp(), Plain),
    Ctx = webrtc_srtp:set_rtcp_index(rtcp_vector_ssrc(), 16#5d4, Ctx0),
    ?assertMatch({ok, _, _}, webrtc_srtp:protect_rtcp(rfc7714_rtcp(), Ctx)),
    {ok, Out, _} = webrtc_srtp:protect_rtcp(rfc7714_rtcp(), Ctx),
    ?assertEqual(rfc7714_17_2_srtcp(), Out).

%% Tagging only: E flag 0, the whole RTCP packet is associated data.
rfc7714_17_3_test() ->
    Ctx0 = gcm_ctx(srtp_aead_aes_128_gcm, gcm_key128(), #{encrypt_rtcp => false}),
    Ctx = webrtc_srtp:set_rtcp_index(rtcp_vector_ssrc(), 16#5d4, Ctx0),
    {ok, Out, _} = webrtc_srtp:protect_rtcp(rfc7714_rtcp(), Ctx),
    ?assertEqual(rfc7714_17_3_srtcp(), Out),
    {ok, Plain, _} = webrtc_srtp:unprotect_rtcp(rfc7714_17_3_srtcp(), Ctx0),
    ?assertEqual(rfc7714_rtcp(), Plain).

rfc7714_17_4_test() ->
    Ctx0 = gcm_ctx(srtp_aead_aes_256_gcm, gcm_key256(), #{encrypt_rtcp => false}),
    {ok, Plain, _} = webrtc_srtp:unprotect_rtcp(rfc7714_17_4_srtcp(), Ctx0),
    ?assertEqual(rfc7714_rtcp(), Plain),
    Ctx = webrtc_srtp:set_rtcp_index(rtcp_vector_ssrc(), 16#5d4, Ctx0),
    {ok, Out, _} = webrtc_srtp:protect_rtcp(rfc7714_rtcp(), Ctx),
    ?assertEqual(rfc7714_17_4_srtcp(), Out).

%% Clearing the E flag of an encrypted packet (or setting it on a tagged
%% one) must fail authentication: the flag is in the AAD.
rfc7714_17_eflag_test() ->
    Ctx = gcm_ctx(srtp_aead_aes_128_gcm, gcm_key128(), #{}),
    Bin = rfc7714_17_1_srtcp(),
    N = byte_size(Bin) - 4,
    <<Head:N/binary, _:1, Idx:31>> = Bin,
    ?assertEqual(
        {error, auth_failed}, webrtc_srtp:unprotect_rtcp(<<Head/binary, 0:1, Idx:31>>, Ctx)
    ),
    Bin3 = rfc7714_17_3_srtcp(),
    <<Head3:N/binary, _:1, Idx3:31>> = Bin3,
    ?assertEqual(
        {error, auth_failed}, webrtc_srtp:unprotect_rtcp(<<Head3/binary, 1:1, Idx3:31>>, Ctx)
    ).

%%--------------------------------------------------------------------
%% libsrtp reference vectors (test/srtp_driver.c). Full packets keyed
%% through the KDF, so they cross-check key derivation, IV formation,
%% HMAC input (ROC appended) and the 96-bit GCM salt layout against an
%% independent implementation used by browsers.
%%--------------------------------------------------------------------

libsrtp_rtp_plain() ->
    b("800f1234 decafbad cafebabe abababab abababab abababab abababab").

libsrtp_cm_ctx() ->
    webrtc_srtp:new(
        srtp_aes128_cm_hmac_sha1_80,
        b("e1f97a0d3e018be0d64fa32c06de4139"),
        b("0ec675ad498afeebb6960b3aabe6"),
        #{}
    ).

libsrtp_aes_cm_rtp_test() ->
    Want = b(
        "800f1234 decafbad cafebabe 4e55dc4c e79978d8 8ca4d215 949d2402\n"
        "         b78d6acc 99ea179b 8dbb"
    ),
    {ok, Out, _} = webrtc_srtp:protect_rtp(libsrtp_rtp_plain(), libsrtp_cm_ctx()),
    ?assertEqual(Want, Out),
    {ok, Plain, _} = webrtc_srtp:unprotect_rtp(Want, libsrtp_cm_ctx()),
    ?assertEqual(libsrtp_rtp_plain(), Plain).

%% libsrtp sends this one with SRTCP index 1.
libsrtp_aes_cm_rtcp_test() ->
    Plain = b("81c8000b cafebabe abababab abababab abababab abababab"),
    Want = b(
        "81c8000b cafebabe 7128035b e487b9bd bef89041 f977a5a8 80000001\n"
        "         993e08cd 54d6c123 0798"
    ),
    Ctx = webrtc_srtp:set_rtcp_index(16#cafebabe, 1, libsrtp_cm_ctx()),
    {ok, Out, _} = webrtc_srtp:protect_rtcp(Plain, Ctx),
    ?assertEqual(Want, Out),
    {ok, Dec, _} = webrtc_srtp:unprotect_rtcp(Want, libsrtp_cm_ctx()),
    ?assertEqual(Plain, Dec).

libsrtp_aes_gcm_rtp_test() ->
    Ctx = webrtc_srtp:new(
        srtp_aead_aes_128_gcm,
        b("000102030405060708090a0b0c0d0e0f"),
        b("a0a1a2a3a4a5a6a7a8a9aaab"),
        #{}
    ),
    Want = b(
        "800f1234 decafbad cafebabe c5002ede 04cfdd2e b91159e0 880aa06e\n"
        "         d2976826 f796b201 df3131a1 27e8a392"
    ),
    {ok, Out, _} = webrtc_srtp:protect_rtp(libsrtp_rtp_plain(), Ctx),
    ?assertEqual(Want, Out),
    {ok, Plain, _} = webrtc_srtp:unprotect_rtp(Want, Ctx),
    ?assertEqual(libsrtp_rtp_plain(), Plain).

%%--------------------------------------------------------------------
%% Round trips
%%--------------------------------------------------------------------

roundtrip_rtp_test_() ->
    [{atom_to_list(P), fun() -> roundtrip_rtp(P) end} || P <- ?PROFILES].

roundtrip_rtp(Profile) ->
    {Tx, Rx} = pair(Profile),
    Packets = [
        rtp(1),
        %% empty payload
        rtp(2, 1, <<>>),
        %% CSRCs
        <<16#83, 96, 3:16, 0:32, 7:32, 1:32, 2:32, 3:32, "csrc payload">>,
        %% one-byte header extension (RFC 8285), 2 words
        <<16#90, 96, 4:16, 0:32, 7:32, 16#BEDE:16, 2:16, 16#10, 1, 16#22, 2, 3, 0, 0, 0, "ext">>,
        %% CSRCs, extension and padding bit
        <<16#B1, 96, 5:16, 0:32, 7:32, 9:32, 16#1000:16, 1:16, 0:32, "pad", 0, 0, 0, 4>>,
        rtp(6, 7, crypto:strong_rand_bytes(1200))
    ],
    {Out, _} = protect_all(Packets, Tx),
    {Res, _} = unprotect_all(Out, Rx),
    ?assertEqual([{ok, P} || P <- Packets], Res),
    #{rtp_tag_len := TL} = webrtc_srtp_profile:params(Profile),
    lists:foreach(
        fun({P, S}) ->
            ?assertEqual(byte_size(P) + TL, byte_size(S)),
            HL = hdr_len(P),
            %% Header (CSRC list and extension included) is sent in the clear.
            ?assertEqual(binary:part(P, 0, HL), binary:part(S, 0, HL)),
            case byte_size(P) - HL of
                0 -> ok;
                PL -> ?assertNotEqual(binary:part(P, HL, PL), binary:part(S, HL, PL))
            end
        end,
        lists:zip(Packets, Out)
    ).

hdr_len(<<_:3, X:1, CC:4, _:11/binary, _/binary>> = P) ->
    Base = 12 + CC * 4,
    case X of
        0 ->
            Base;
        1 ->
            <<_:Base/binary, _:16, W:16, _/binary>> = P,
            Base + 4 + W * 4
    end.

roundtrip_rtcp_test_() ->
    [
        {atom_to_list(P) ++ " E=" ++ atom_to_list(Enc), fun() -> roundtrip_rtcp(P, Enc) end}
     || P <- ?PROFILES, Enc <- [true, false]
    ].

roundtrip_rtcp(Profile, Encrypt) ->
    {Tx, Rx} = pair(Profile, #{encrypt_rtcp => Encrypt}),
    Pkt = rtcp(16#11223344),
    {ok, S1, Tx1} = webrtc_srtp:protect_rtcp(Pkt, Tx),
    {ok, S2, _} = webrtc_srtp:protect_rtcp(Pkt, Tx1),
    ?assertNotEqual(S1, S2),
    #{rtcp_tag_len := TL} = webrtc_srtp_profile:params(Profile),
    ?assertEqual(byte_size(Pkt) + 4 + TL, byte_size(S1)),
    ?assertEqual(binary:part(Pkt, 0, 8), binary:part(S1, 0, 8)),
    Body = binary:part(Pkt, 8, byte_size(Pkt) - 8),
    case Encrypt of
        true -> ?assertNotEqual(Body, binary:part(S1, 8, byte_size(Body)));
        false -> ?assertEqual(Body, binary:part(S1, 8, byte_size(Body)))
    end,
    {ok, P1, Rx1} = webrtc_srtp:unprotect_rtcp(S1, Rx),
    {ok, P2, _} = webrtc_srtp:unprotect_rtcp(S2, Rx1),
    ?assertEqual({Pkt, Pkt}, {P1, P2}).

%% The SRTCP index starts at 0 and increments per packet (RFC 3711 §3.4).
srtcp_index_sequence_test() ->
    {Tx, _} = pair(srtp_aes128_cm_hmac_sha1_80),
    Pkt = rtcp(5),
    {Idx, _} = lists:mapfoldl(
        fun(_, T) ->
            {ok, S, T1} = webrtc_srtp:protect_rtcp(Pkt, T),
            Off = byte_size(S) - 14,
            <<_:Off/binary, 1:1, I:31, _:10/binary>> = S,
            {I, T1}
        end,
        Tx,
        lists:seq(1, 5)
    ),
    ?assertEqual([0, 1, 2, 3, 4], Idx).

%% SRTP_AES128_CM_HMAC_SHA1_32 uses a 32-bit tag for SRTP and an 80-bit
%% tag for SRTCP (RFC 5764 §4.1.2).
sha1_32_tag_lengths_test() ->
    {Tx, _} = pair(srtp_aes128_cm_hmac_sha1_32),
    P = rtp(1),
    {ok, S, Tx1} = webrtc_srtp:protect_rtp(P, Tx),
    ?assertEqual(byte_size(P) + 4, byte_size(S)),
    R = rtcp(1),
    {ok, SR, _} = webrtc_srtp:protect_rtcp(R, Tx1),
    ?assertEqual(byte_size(R) + 14, byte_size(SR)).

dtls_contexts_test() ->
    P = srtp_aead_aes_128_gcm,
    Mat = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(P)),
    {CTx, CRx} = webrtc_srtp:dtls_contexts(P, Mat, client, #{}),
    {STx, SRx} = webrtc_srtp:dtls_contexts(P, Mat, server, #{}),
    {ok, A, _} = webrtc_srtp:protect_rtp(rtp(1), CTx),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(A, SRx)),
    ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtp(A, CRx)),
    {ok, B, _} = webrtc_srtp:protect_rtp(rtp(1), STx),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(B, CRx)),
    ?assertNotEqual(A, B).

independent_ssrcs_test() ->
    {Tx, Rx} = pair(srtp_aes128_cm_hmac_sha1_80),
    Pkts = [rtp(10, 1, <<"a">>), rtp(10, 2, <<"a">>), rtp(11, 1, <<"b">>)],
    {Out, _} = protect_all(Pkts, Tx),
    ?assertNotEqual(lists:nth(1, Out), lists:nth(2, Out)),
    {Res, _} = unprotect_all(Out, Rx),
    ?assertEqual([{ok, P} || P <- Pkts], Res).

%%--------------------------------------------------------------------
%% ROC and index estimation (RFC 3711 §3.3.1, Appendix A)
%%--------------------------------------------------------------------

estimate_index_test() ->
    E = fun webrtc_srtp:estimate_index/3,
    ?assertEqual({0, 101}, E(101, 0, 100)),
    ?assertEqual({0, 99}, E(99, 0, 100)),
    %% s_l < 2^15: SEQ - s_l > 2^15 means the previous roll.
    ?assertEqual({4, 4 * 65536 + 65000}, E(65000, 5, 100)),
    ?assertEqual({5, 5 * 65536 + 32868}, E(32868, 5, 100)),
    ?assertEqual({4, 4 * 65536 + 32869}, E(32869, 5, 100)),
    %% s_l >= 2^15: s_l - 2^15 > SEQ means the next roll.
    ?assertEqual({6, 6 * 65536 + 5}, E(5, 5, 65530)),
    ?assertEqual({5, 5 * 65536 + 32762}, E(32762, 5, 65530)),
    ?assertEqual({6, 6 * 65536 + 32761}, E(32761, 5, 65530)),
    ?assertEqual({5, 5 * 65536 + 65535}, E(65535, 5, 32768)),
    ?assertEqual({5, 5 * 65536}, E(0, 5, 32768)),
    %% Before the start of the stream.
    ?assertEqual({-1, -65536 + 65000}, E(65000, 0, 10)).

rollover_test_() ->
    [{atom_to_list(P), fun() -> rollover(P) end} || P <- ?PROFILES].

rollover(Profile) ->
    {Tx, Rx} = pair(Profile),
    Seqs = lists:seq(65530, 65535) ++ lists:seq(0, 5),
    Pkts = [rtp(S) || S <- Seqs],
    {Out, Tx1} = protect_all(Pkts, Tx),
    ?assertEqual({ok, 1}, webrtc_srtp:roc(tx, 16#CAFEBABE, Tx1)),
    {Res, Rx1} = unprotect_all(Out, Rx),
    ?assertEqual([{ok, P} || P <- Pkts], Res),
    ?assertEqual({ok, 1}, webrtc_srtp:roc(rx, 16#CAFEBABE, Rx1)),
    %% The ROC is part of the IV and the MAC: seq 0 with ROC 1 differs
    %% from seq 0 with ROC 0.
    {ok, Fresh, _} = webrtc_srtp:protect_rtp(rtp(0), Tx),
    ?assertNotEqual(Fresh, lists:nth(7, Out)),
    ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtp(lists:nth(7, Out), Rx)).

reorder_near_rollover_test_() ->
    [{atom_to_list(P), fun() -> reorder_near_rollover(P) end} || P <- ?PROFILES].

reorder_near_rollover(Profile) ->
    {Tx, Rx} = pair(Profile),
    Seqs = [65532, 65533, 65534, 65535, 0, 1, 2, 3],
    {Out, _} = protect_all([rtp(S) || S <- Seqs], Tx),
    M = maps:from_list(lists:zip(Seqs, Out)),
    Order = [65532, 65534, 0, 65533, 2, 65535, 1, 3],
    {Res, Rx1} = unprotect_all([maps:get(S, M) || S <- Order], Rx),
    ?assertEqual([{ok, rtp(S)} || S <- Order], Res),
    ?assertEqual({ok, 1}, webrtc_srtp:roc(rx, 16#CAFEBABE, Rx1)),
    %% A late packet from before the roll after the receiver rolled.
    ?assertEqual({error, replay}, webrtc_srtp:unprotect_rtp(maps:get(65535, M), Rx1)).

%% Reordering on the sender side (packets handed to protect out of
%% order around the wrap) keeps the right ROC.
sender_reorder_near_rollover_test() ->
    {Tx, Rx} = pair(srtp_aes128_cm_hmac_sha1_80),
    Order = [65534, 0, 65535, 1],
    {Out, _} = protect_all([rtp(S) || S <- Order], Tx),
    {Res, _} = unprotect_all(Out, Rx),
    ?assertEqual([{ok, rtp(S)} || S <- Order], Res).

multiple_rollovers_test() ->
    {Tx, Rx} = pair(srtp_aead_aes_128_gcm),
    %% Steps of 30000 cross the wrap several times without ambiguity.
    Seqs = [(N * 30000) rem 65536 || N <- lists:seq(0, 12)],
    {Out, Tx1} = protect_all([rtp(S) || S <- Seqs], Tx),
    {Res, Rx1} = unprotect_all(Out, Rx),
    ?assert(lists:all(fun(R) -> element(1, R) =:= ok end, Res)),
    ?assertEqual({ok, 5}, webrtc_srtp:roc(tx, 16#CAFEBABE, Tx1)),
    ?assertEqual({ok, 5}, webrtc_srtp:roc(rx, 16#CAFEBABE, Rx1)).

%% A receiver joining with a signaled ROC (RFC 3711 §3.3.1).
set_roc_test() ->
    {Tx0, Rx0} = pair(srtp_aes128_cm_hmac_sha1_80),
    Tx = webrtc_srtp:set_roc(tx, 16#CAFEBABE, 7, Tx0),
    {ok, S, _} = webrtc_srtp:protect_rtp(rtp(100), Tx),
    ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtp(S, Rx0)),
    Rx = webrtc_srtp:set_roc(rx, 16#CAFEBABE, 7, Rx0),
    {ok, P, Rx1} = webrtc_srtp:unprotect_rtp(S, Rx),
    ?assertEqual(rtp(100), P),
    ?assertEqual({ok, 7}, webrtc_srtp:roc(rx, 16#CAFEBABE, Rx1)),
    ?assertEqual(error, webrtc_srtp:roc(rx, 1, Rx1)).

%%--------------------------------------------------------------------
%% Key lifetime (RFC 3711 §9.2, RFC 7714 §10)
%%--------------------------------------------------------------------

srtp_key_exhausted_test_() ->
    [{atom_to_list(P), fun() -> srtp_key_exhausted(P) end} || P <- ?PROFILES].

srtp_key_exhausted(Profile) ->
    {Tx0, Rx0} = pair(Profile),
    Tx = webrtc_srtp:set_roc(tx, 16#CAFEBABE, 16#FFFFFFFF, Tx0),
    %% Index 2^48 - 1 is the last one.
    {ok, S, Tx1} = webrtc_srtp:protect_rtp(rtp(65535), Tx),
    ?assertEqual({error, key_exhausted}, webrtc_srtp:protect_rtp(rtp(0), Tx1)),
    Rx = webrtc_srtp:set_roc(rx, 16#CAFEBABE, 16#FFFFFFFF, Rx0),
    {ok, _, Rx1} = webrtc_srtp:unprotect_rtp(S, Rx),
    %% The next roll would need index 2^48: refused before authentication.
    Next = <<16#80, 96, 0:16, 0:32, 16#CAFEBABE:32, 0:(20 * 8)>>,
    ?assertEqual({error, key_exhausted}, webrtc_srtp:unprotect_rtp(Next, Rx1)).

srtcp_key_exhausted_test_() ->
    [{atom_to_list(P), fun() -> srtcp_key_exhausted(P) end} || P <- ?PROFILES].

srtcp_key_exhausted(Profile) ->
    {Tx0, Rx} = pair(Profile),
    Tx = webrtc_srtp:set_rtcp_index(1, 16#7FFFFFFF, Tx0),
    {ok, S, Tx1} = webrtc_srtp:protect_rtcp(rtcp(1), Tx),
    ?assertEqual({error, key_exhausted}, webrtc_srtp:protect_rtcp(rtcp(1), Tx1)),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtcp(S, Rx)).

%%--------------------------------------------------------------------
%% Replay protection (RFC 3711 §3.3.2)
%%--------------------------------------------------------------------

rtp_replay_test_() ->
    [{atom_to_list(P), fun() -> rtp_replay(P) end} || P <- ?PROFILES].

rtp_replay(Profile) ->
    {Tx, Rx} = pair(Profile, #{replay_window => 64}),
    {Out, _} = protect_all([rtp(S) || S <- lists:seq(1, 100)], Tx),
    [P1 | _] = Out,
    {ok, _, Rx1} = webrtc_srtp:unprotect_rtp(P1, Rx),
    ?assertEqual({error, replay}, webrtc_srtp:unprotect_rtp(P1, Rx1)),
    Last = lists:last(Out),
    {ok, _, Rx2} = webrtc_srtp:unprotect_rtp(Last, Rx1),
    %% seq 37 is 63 behind 100: inside the window. seq 36 is not.
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(lists:nth(37, Out), Rx2)),
    ?assertEqual({error, too_old}, webrtc_srtp:unprotect_rtp(lists:nth(36, Out), Rx2)),
    ?assertEqual({error, replay}, webrtc_srtp:unprotect_rtp(Last, Rx2)).

default_window_is_1024_test() ->
    {Tx, Rx} = pair(srtp_aes128_cm_hmac_sha1_80),
    {Out, _} = protect_all([rtp(S) || S <- lists:seq(1, 1100)], Tx),
    {ok, _, Rx1} = webrtc_srtp:unprotect_rtp(lists:last(Out), Rx),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(lists:nth(1100 - 1023, Out), Rx1)),
    ?assertEqual({error, too_old}, webrtc_srtp:unprotect_rtp(lists:nth(1100 - 1024, Out), Rx1)).

%% Protecting the same sequence number twice would reuse an IV.
sender_refuses_index_reuse_test_() ->
    [
        {atom_to_list(P), fun() ->
            {Tx, _} = pair(P),
            {ok, _, Tx1} = webrtc_srtp:protect_rtp(rtp(5), Tx),
            ?assertEqual({error, replay}, webrtc_srtp:protect_rtp(rtp(5), Tx1))
        end}
     || P <- ?PROFILES
    ].

rtcp_replay_test_() ->
    [{atom_to_list(P), fun() -> rtcp_replay(P) end} || P <- ?PROFILES].

rtcp_replay(Profile) ->
    {Tx, Rx} = pair(Profile),
    {Out, _} = lists:mapfoldl(
        fun(_, T) ->
            {ok, S, T1} = webrtc_srtp:protect_rtcp(rtcp(9), T),
            {S, T1}
        end,
        Tx,
        lists:seq(0, 199)
    ),
    {ok, _, Rx1} = webrtc_srtp:unprotect_rtcp(hd(Out), Rx),
    ?assertEqual({error, replay}, webrtc_srtp:unprotect_rtcp(hd(Out), Rx1)),
    {ok, _, Rx2} = webrtc_srtp:unprotect_rtcp(lists:last(Out), Rx1),
    %% Default SRTCP window 128: index 199 - 127 is in, 199 - 128 is out.
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtcp(lists:nth(73, Out), Rx2)),
    ?assertEqual({error, too_old}, webrtc_srtp:unprotect_rtcp(lists:nth(72, Out), Rx2)).

%% A forged packet must not move the replay window or create state.
forged_does_not_move_window_test() ->
    {Tx, Rx} = pair(srtp_aes128_cm_hmac_sha1_80),
    {ok, Good, _} = webrtc_srtp:protect_rtp(rtp(10), Tx),
    {Attacker, _} = pair(srtp_aes128_cm_hmac_sha1_80),
    {ok, Forged, _} = webrtc_srtp:protect_rtp(rtp(5000), Attacker),
    ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtp(Forged, Rx)),
    ?assertEqual(error, webrtc_srtp:roc(rx, 16#CAFEBABE, Rx)),
    {ok, _, Rx1} = webrtc_srtp:unprotect_rtp(Good, Rx),
    ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtp(Forged, Rx1)),
    %% The window did not move to 5000: seq 11 is still accepted.
    {ok, Next, _} = webrtc_srtp:protect_rtp(
        rtp(11), element(3, webrtc_srtp:protect_rtp(rtp(10), Tx))
    ),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(Next, Rx1)).

%%--------------------------------------------------------------------
%% Authentication failures
%%--------------------------------------------------------------------

%% Flipping any bit of any octet of a protected packet is rejected.
tamper_rtp_test_() ->
    [{atom_to_list(P), fun() -> tamper(P, rtp) end} || P <- ?PROFILES].

tamper_rtcp_test_() ->
    [{atom_to_list(P), fun() -> tamper(P, rtcp) end} || P <- ?PROFILES].

tamper(Profile, Kind) ->
    {Tx, Rx} = pair(Profile),
    {Prot, Unprot, Pkt} =
        case Kind of
            rtp ->
                {
                    fun webrtc_srtp:protect_rtp/2,
                    fun webrtc_srtp:unprotect_rtp/2,
                    <<16#91, 96, 1:16, 0:32, 7:32, 9:32, 16#BEDE:16, 1:16, 16#10, 1, 0, 0, "data">>
                };
            rtcp ->
                {fun webrtc_srtp:protect_rtcp/2, fun webrtc_srtp:unprotect_rtcp/2, rtcp(3)}
        end,
    {ok, S, _} = Prot(Pkt, Tx),
    ?assertMatch({ok, Pkt, _}, Unprot(S, Rx)),
    Bad = [
        {Pos, Bit}
     || Pos <- lists:seq(0, byte_size(S) - 1),
        Bit <- [0, 3, 7],
        not is_error(Unprot(flip(S, Pos, Bit), Rx))
    ],
    ?assertEqual([], Bad).

flip(Bin, Pos, Bit) ->
    <<A:Pos/binary, B, C/binary>> = Bin,
    <<A/binary, (B bxor (1 bsl Bit)), C/binary>>.

is_error({error, _}) -> true;
is_error(_) -> false.

wrong_key_test_() ->
    [
        {atom_to_list(P), fun() ->
            {Tx, _} = pair(P),
            {_, Rx} = pair(P),
            {ok, S, _} = webrtc_srtp:protect_rtp(rtp(1), Tx),
            ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtp(S, Rx)),
            {ok, R, _} = webrtc_srtp:protect_rtcp(rtcp(1), Tx),
            ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtcp(R, Rx))
        end}
     || P <- ?PROFILES
    ].

%% Same master key, but RTP keys must not authenticate RTCP and the
%% reverse (distinct labels, RFC 3711 §4.3.2).
rtp_rtcp_keys_separate_test() ->
    {Tx, Rx} = pair(srtp_aes128_cm_hmac_sha1_80),
    {ok, S, _} = webrtc_srtp:protect_rtp(rtp(1), Tx),
    ?assertMatch({error, _}, webrtc_srtp:unprotect_rtcp(S, Rx)).

%%--------------------------------------------------------------------
%% Malformed input
%%--------------------------------------------------------------------

truncated_test_() ->
    [{atom_to_list(P), fun() -> truncated(P) end} || P <- ?PROFILES].

truncated(Profile) ->
    {Tx, Rx} = pair(Profile),
    Rtp = <<16#91, 96, 1:16, 0:32, 7:32, 9:32, 16#BEDE:16, 1:16, 16#10, 1, 0, 0, "data">>,
    {ok, S, _} = webrtc_srtp:protect_rtp(Rtp, Tx),
    {ok, R, _} = webrtc_srtp:protect_rtcp(rtcp(1), Tx),
    Check = fun(Fun, Bin) ->
        [
            N
         || N <- lists:seq(0, byte_size(Bin) - 1),
            not is_error(Fun(binary:part(Bin, 0, N), Rx))
        ]
    end,
    ?assertEqual([], Check(fun webrtc_srtp:unprotect_rtp/2, S)),
    ?assertEqual([], Check(fun webrtc_srtp:unprotect_rtcp/2, R)),
    %% Truncated plaintext on the protect side.
    ?assertEqual([], [
        N
     || N <- lists:seq(0, hdr_len(Rtp) - 1),
        not is_error(webrtc_srtp:protect_rtp(binary:part(Rtp, 0, N), Tx))
    ]),
    ?assertEqual([], [
        N
     || N <- lists:seq(0, 7),
        not is_error(webrtc_srtp:protect_rtcp(binary:part(rtcp(1), 0, N), Tx))
    ]).

malformed_test_() ->
    {Tx, Rx} = pair(srtp_aes128_cm_hmac_sha1_80),
    [
        ?_assertEqual({error, malformed}, webrtc_srtp:unprotect_rtp(<<>>, Rx)),
        %% Version 1
        ?_assertEqual({error, malformed}, webrtc_srtp:unprotect_rtp(<<16#40, 0:(31 * 8)>>, Rx)),
        ?_assertEqual({error, malformed}, webrtc_srtp:protect_rtp(<<16#40, 0:(31 * 8)>>, Tx)),
        %% CC = 15 but no room for the CSRCs
        ?_assertEqual({error, malformed}, webrtc_srtp:unprotect_rtp(<<16#8F, 0:(31 * 8)>>, Rx)),
        %% Extension length past the end
        ?_assertEqual(
            {error, malformed},
            webrtc_srtp:protect_rtp(<<16#90, 0, 0:16, 0:64, 0:16, 100:16, 0:32>>, Tx)
        ),
        ?_assertEqual({error, malformed}, webrtc_srtp:unprotect_rtcp(<<16#40, 0:(40 * 8)>>, Rx)),
        ?_assertEqual({error, malformed}, webrtc_srtp:protect_rtcp(<<16#81, 200, 0, 1>>, Tx)),
        ?_assertEqual({error, malformed}, webrtc_srtp:unprotect_rtp(not_a_binary, Rx)),
        ?_assertEqual({error, malformed}, webrtc_srtp:unprotect_rtcp(not_a_binary, Rx))
    ].

%% AES-CM must not produce more than 2^16 keystream blocks per IV
%% (RFC 3711 §4.1.1): larger payloads are refused, the limit itself works.
cm_keystream_limit_test() ->
    {Tx, Rx} = pair(srtp_aes128_cm_hmac_sha1_80),
    Max = 1 bsl 20,
    ?assertEqual({error, malformed}, webrtc_srtp:protect_rtp(rtp(1, 1, <<0:((Max + 1) * 8)>>), Tx)),
    {ok, S, _} = webrtc_srtp:protect_rtp(rtp(1, 1, <<0:(Max * 8)>>), Tx),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(S, Rx)),
    ?assertEqual(
        {error, malformed}, webrtc_srtp:protect_rtcp(<<(rtcp(1))/binary, 0:(Max * 8)>>, Tx)
    ).

bad_options_test() ->
    K = <<0:128>>,
    S = <<0:112>>,
    P = srtp_aes128_cm_hmac_sha1_80,
    ?assertError({badarg, {replay_window, 10}}, webrtc_srtp:new(P, K, S, #{replay_window => 10})),
    ?assertError(
        {badarg, {rtcp_replay_window, x}}, webrtc_srtp:new(P, K, S, #{rtcp_replay_window => x})
    ),
    ?assertError({badarg, {encrypt_rtcp, 1}}, webrtc_srtp:new(P, K, S, #{encrypt_rtcp => 1})),
    ?assertError(badarg, webrtc_srtp:new(P, <<0:120>>, S, #{})),
    ?assertError(
        {unsupported_profile, srtp_null_hmac_sha1_80},
        webrtc_srtp:new(srtp_null_hmac_sha1_80, K, S, #{})
    ).

%%--------------------------------------------------------------------
%% forget/2: bounded receive state without a replay window
%%--------------------------------------------------------------------

%% A forgotten SSRC loses its state; its earlier packets stay refused
%% and later ones are accepted, also across a rollover.
forget_test() ->
    {Tx0, Rx0} = pair(srtp_aes128_cm_hmac_sha1_80),
    Seqs = lists:seq(65530, 65535) ++ lists:seq(0, 4),
    {Ps, Tx1} = protect_all([rtp(S) || S <- Seqs], Tx0),
    {Res, Rx1} = unprotect_all(Ps, Rx0),
    ?assert(lists:all(fun({ok, _}) -> true; (_) -> false end, Res)),
    {ok, Rtcp, _} = webrtc_srtp:protect_rtcp(rtcp(16#CAFEBABE), Tx1),
    {ok, _, Rx2} = webrtc_srtp:unprotect_rtcp(Rtcp, Rx1),
    Rx3 = webrtc_srtp:forget(16#CAFEBABE, Rx2),
    ?assertEqual(error, webrtc_srtp:roc(rx, 16#CAFEBABE, Rx3)),
    ?assert(erts_debug:flat_size(Rx3) < erts_debug:flat_size(Rx2)),
    %% Replays of packets sent before are refused.
    [?assertMatch({error, _}, webrtc_srtp:unprotect_rtp(P, Rx3)) || P <- Ps],
    ?assertEqual({error, replay}, webrtc_srtp:unprotect_rtcp(Rtcp, Rx3)),
    %% The stream continues where it was, after the rollover.
    {[Next], _} = protect_all([rtp(5)], Tx1),
    {ok, _, Rx4} = webrtc_srtp:unprotect_rtp(Next, Rx3),
    ?assertEqual({ok, 1}, webrtc_srtp:roc(rx, 16#CAFEBABE, Rx4)).

%% The memory of forgotten SSRCs is bounded: the oldest are dropped.
forget_bounded_test() ->
    {Tx, Rx0} = pair(srtp_aes128_cm_hmac_sha1_80),
    Ssrcs = lists:seq(1, 1100),
    Rx1 = lists:foldl(
        fun(Ssrc, R) ->
            {ok, P, _} = webrtc_srtp:protect_rtp(rtp(1, Ssrc, <<"x">>), Tx),
            {ok, _, R1} = webrtc_srtp:unprotect_rtp(P, R),
            webrtc_srtp:forget(Ssrc, R1)
        end,
        Rx0,
        Ssrcs
    ),
    Size = erts_debug:flat_size(Rx1),
    Rx2 = lists:foldl(
        fun(Ssrc, R) ->
            {ok, P, _} = webrtc_srtp:protect_rtp(rtp(1, Ssrc, <<"x">>), Tx),
            {ok, _, R1} = webrtc_srtp:unprotect_rtp(P, R),
            webrtc_srtp:forget(Ssrc, R1)
        end,
        Rx1,
        lists:seq(5000, 5500)
    ),
    ?assert(erts_debug:flat_size(Rx2) =< Size + 64),
    %% A recent one is still protected against replay.
    {ok, Recent, _} = webrtc_srtp:protect_rtp(rtp(1, 5500, <<"x">>), Tx),
    ?assertEqual({error, replay}, webrtc_srtp:unprotect_rtp(Recent, Rx2)).

%% Receive state is created for at most 512 SSRCs.
rx_streams_bounded_test() ->
    {Tx, Rx0} = pair(srtp_aes128_cm_hmac_sha1_80),
    Rx1 = lists:foldl(
        fun(Ssrc, R) ->
            {ok, P, _} = webrtc_srtp:protect_rtp(rtp(1, Ssrc, <<"x">>), Tx),
            {ok, _, R1} = webrtc_srtp:unprotect_rtp(P, R),
            R1
        end,
        Rx0,
        lists:seq(1, 512)
    ),
    {ok, New, _} = webrtc_srtp:protect_rtp(rtp(1, 999, <<"x">>), Tx),
    ?assertEqual({error, too_many_streams}, webrtc_srtp:unprotect_rtp(New, Rx1)),
    {ok, Known, _} = webrtc_srtp:protect_rtp(rtp(2, 7, <<"x">>), Tx),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(Known, Rx1)),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(New, webrtc_srtp:forget(7, Rx1))).

%% RFC 9335 §6.3: once cryptex is negotiated, a packet with header
%% extensions in the plain form is refused; without extensions it is
%% fine, and the cryptex form is accepted.
cryptex_required_test() ->
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    {Plain, _} = webrtc_srtp:dtls_contexts(Profile, Material, server, #{}),
    {Cx, _} = webrtc_srtp:dtls_contexts(Profile, Material, server, #{cryptex => true}),
    {_, Rx0} = webrtc_srtp:dtls_contexts(Profile, Material, client, #{}),
    Rx = webrtc_srtp:set_cryptex(true, Rx0),
    WithExt = webrtc_rtp:encode(#rtp{pt = 111, seq = 1, ts = 1, ssrc = 5, ext = [{1, <<"0">>}], payload = <<"a">>}),
    NoExt = webrtc_rtp:encode(#rtp{pt = 111, seq = 2, ts = 2, ssrc = 5, payload = <<"b">>}),
    {ok, P1, _} = webrtc_srtp:protect_rtp(WithExt, Plain),
    ?assertEqual({error, cryptex_required}, webrtc_srtp:unprotect_rtp(P1, Rx)),
    {ok, P2, _} = webrtc_srtp:protect_rtp(NoExt, Plain),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(P2, Rx)),
    {ok, P3, _} = webrtc_srtp:protect_rtp(WithExt, Cx),
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(P3, Rx)).
