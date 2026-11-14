%% Conformance tests for webrtc_srtp_kdf and webrtc_srtp_profile:
%% RFC 3711 Appendix B.2 (AES-CM keystream), B.3 (key derivation) and
%% the RFC 5764 §4.2 keying material layout.
-module(webrtc_srtp_kdf_tests).
-include_lib("eunit/include/eunit.hrl").

-import(webrtc_test_hex, [b/1]).

%%--------------------------------------------------------------------
%% RFC 3711 B.3
%%--------------------------------------------------------------------

b3_master_key() -> b("E1F97A0D3E018BE0D64FA32C06DE4139").
b3_master_salt() -> b("0EC675AD498AFEEBB6960B3AABE6").

b3_cipher_key_test() ->
    ?assertEqual(
        b("C61E7A93744F39EE10734AFE3FF7A087"),
        webrtc_srtp_kdf:derive(16#00, b3_master_key(), b3_master_salt(), 16)
    ).

b3_cipher_salt_test() ->
    ?assertEqual(
        b("30CBBC08863D8C85D49DB34A9AE1"),
        webrtc_srtp_kdf:derive(16#02, b3_master_key(), b3_master_salt(), 14)
    ).

b3_auth_key_test() ->
    Expected = b(
        "CEBE321F6FF7716B6FD4AB49AF256A15\n"
        "         6D38BAA48F0A0ACF3C34E2359E6CDBCE\n"
        "         E049646C43D9327AD175578EF7227098\n"
        "         6371C10C9A369AC2F94A8C5FBCDDDC25\n"
        "         6D6E919A48B610EF17C2041E47403576\n"
        "         6B68642C59BBFC2F34DB60DBDFB2"
    ),
    ?assertEqual(94, byte_size(Expected)),
    ?assertEqual(Expected, webrtc_srtp_kdf:derive(16#01, b3_master_key(), b3_master_salt(), 94)).

%% PRF input block formation shown in B.3 (x * 2^16).
b3_prf_input_test() ->
    X = b("0EC675AD498AFEEBB6960B3AABE6"),
    ?assertEqual(
        b("C61E7A93744F39EE10734AFE3FF7A087"),
        webrtc_srtp_kdf:prf(b3_master_key(), X, 16)
    ).

session_keys_cm_test() ->
    K = webrtc_srtp_kdf:session_keys(
        srtp_aes128_cm_hmac_sha1_80, b3_master_key(), b3_master_salt()
    ),
    ?assertEqual(b("C61E7A93744F39EE10734AFE3FF7A087"), maps:get(rtp_key, K)),
    ?assertEqual(b("30CBBC08863D8C85D49DB34A9AE1"), maps:get(rtp_salt, K)),
    <<A20:20/binary, _/binary>> = webrtc_srtp_kdf:derive(1, b3_master_key(), b3_master_salt(), 94),
    ?assertEqual(A20, maps:get(rtp_auth_key, K)),
    %% SRTCP keys use labels 3, 4, 5 (RFC 3711 §4.3.2).
    ?assertEqual(
        webrtc_srtp_kdf:derive(3, b3_master_key(), b3_master_salt(), 16), maps:get(rtcp_key, K)
    ),
    ?assertEqual(
        webrtc_srtp_kdf:derive(4, b3_master_key(), b3_master_salt(), 20), maps:get(rtcp_auth_key, K)
    ),
    ?assertEqual(
        webrtc_srtp_kdf:derive(5, b3_master_key(), b3_master_salt(), 14), maps:get(rtcp_salt, K)
    ),
    ?assertNotEqual(maps:get(rtp_key, K), maps:get(rtcp_key, K)).

session_keys_gcm_test() ->
    MK = list_to_binary(lists:seq(0, 31)),
    MS = b("517569642070726f2071756f"),
    K = webrtc_srtp_kdf:session_keys(srtp_aead_aes_256_gcm, MK, MS),
    ?assertEqual(32, byte_size(maps:get(rtp_key, K))),
    ?assertEqual(12, byte_size(maps:get(rtp_salt, K))),
    ?assertEqual(<<>>, maps:get(rtp_auth_key, K)),
    %% 96-bit salts are extended with two zero octets (libsrtp layout).
    ?assertEqual(
        webrtc_srtp_kdf:prf(MK, <<MS/binary, 0, 0>>, 32),
        maps:get(rtp_key, K)
    ).

session_keys_bad_length_test() ->
    ?assertError(badarg, webrtc_srtp_kdf:session_keys(srtp_aead_aes_128_gcm, <<0:128>>, <<0:112>>)),
    ?assertError(
        badarg, webrtc_srtp_kdf:session_keys(srtp_aes128_cm_hmac_sha1_80, <<0:256>>, <<0:112>>)
    ).

%%--------------------------------------------------------------------
%% RFC 3711 B.2
%%--------------------------------------------------------------------

b2_key() -> b("2B7E151628AED2A6ABF7158809CF4F3C").

b2_first() ->
    b(
        "E03EAD0935C95E80E166B16DD92B4EB4\n"
        "         D23513162B02D0F72A43A2FE4A5F97AB\n"
        "         41E95B3BB0A2E8DD477901E4FCA894C0"
    ).

b2_last() ->
    b(
        "EC8CDF7398607CB0F2D21675EA9EA1E4\n"
        "         362B7C3C6773516318A077D7FC5073AE\n"
        "         6A2CC3787889374FBEB4C81B17BA6C44"
    ).

b2_keystream_test() ->
    IV = b("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000"),
    Len = 1044512,
    KS = webrtc_srtp_kdf:keystream(b2_key(), IV, Len),
    ?assertEqual(Len, byte_size(KS)),
    ?assertEqual(65282, Len div 16),
    <<First:48/binary, _/binary>> = KS,
    ?assertEqual(b2_first(), First),
    ?assertEqual(b2_last(), binary:part(KS, Len - 48, 48)).

%% Same vector through the SRTP packet path: SSRC 0, ROC 0, SEQ 0 and an
%% all-zero payload give the raw keystream as ciphertext, which checks
%% the RFC 3711 §4.1.1 IV formation.
b2_through_protect_test() ->
    Keys = #{
        rtp_key => b2_key(),
        rtp_salt => b("F0F1F2F3F4F5F6F7F8F9FAFBFCFD"),
        rtp_auth_key => <<0:160>>,
        rtcp_key => b2_key(),
        rtcp_salt => b("F0F1F2F3F4F5F6F7F8F9FAFBFCFD"),
        rtcp_auth_key => <<0:160>>
    },
    Ctx = webrtc_srtp:from_session_keys(srtp_aes128_cm_hmac_sha1_80, Keys, #{}),
    Len = 1044512,
    Hdr = <<16#80, 0, 0:16, 0:32, 0:32>>,
    {ok, Out, _} = webrtc_srtp:protect_rtp(<<Hdr/binary, 0:(Len * 8)>>, Ctx),
    ?assertEqual(12 + Len + 10, byte_size(Out)),
    <<Hdr:12/binary, KS:Len/binary, _Tag:10/binary>> = Out,
    ?assertEqual(b2_first(), binary:part(KS, 0, 48)),
    ?assertEqual(b2_last(), binary:part(KS, Len - 48, 48)).

%%--------------------------------------------------------------------
%% Profiles and RFC 5764 §4.2 keying material
%%--------------------------------------------------------------------

profile_ids_test() ->
    [
        begin
            Id = webrtc_srtp:profile_id(P),
            ?assertEqual({ok, P}, webrtc_srtp:profile_from_id(Id)),
            ?assertEqual({ok, P}, webrtc_srtp:profile_from_id(<<Id:16>>))
        end
     || P <- webrtc_srtp:supported_profiles()
    ],
    ?assertEqual(16#0001, webrtc_srtp:profile_id(srtp_aes128_cm_hmac_sha1_80)),
    ?assertEqual(16#0002, webrtc_srtp:profile_id(srtp_aes128_cm_hmac_sha1_32)),
    ?assertEqual(16#0007, webrtc_srtp:profile_id(srtp_aead_aes_128_gcm)),
    ?assertEqual(16#0008, webrtc_srtp:profile_id(srtp_aead_aes_256_gcm)).

%% NULL cipher profiles must not be offered or accepted (RFC 8827 §6.5).
null_profiles_rejected_test() ->
    ?assertEqual({error, unsupported_profile}, webrtc_srtp:profile_from_id(16#0005)),
    ?assertEqual({error, unsupported_profile}, webrtc_srtp:profile_from_id(16#0006)),
    ?assertEqual({error, unsupported_profile}, webrtc_srtp:profile_from_id(16#0003)),
    ?assertEqual({error, unsupported_profile}, webrtc_srtp:profile_from_id(<<0, 0>>)).

aead_preferred_test() ->
    [First | _] = webrtc_srtp:supported_profiles(),
    ?assertEqual(gcm, maps:get(transform, webrtc_srtp_profile:params(First))).

key_material_length_test() ->
    ?assertEqual(60, webrtc_srtp:key_material_length(srtp_aes128_cm_hmac_sha1_80)),
    ?assertEqual(60, webrtc_srtp:key_material_length(srtp_aes128_cm_hmac_sha1_32)),
    ?assertEqual(56, webrtc_srtp:key_material_length(srtp_aead_aes_128_gcm)),
    ?assertEqual(88, webrtc_srtp:key_material_length(srtp_aead_aes_256_gcm)),
    ?assertEqual(<<"EXTRACTOR-dtls_srtp">>, webrtc_srtp:exporter_label()).

split_layout_test() ->
    %% client_key | server_key | client_salt | server_salt
    CK = binary:copy(<<1>>, 16),
    SK = binary:copy(<<2>>, 16),
    CS = binary:copy(<<3>>, 14),
    SS = binary:copy(<<4>>, 14),
    Bin = <<CK/binary, SK/binary, CS/binary, SS/binary>>,
    ?assertEqual(
        {CK, CS, SK, SS}, webrtc_srtp:split_dtls_keying_material(srtp_aes128_cm_hmac_sha1_80, Bin)
    ),
    G = <<
        (binary:copy(<<1>>, 32))/binary,
        (binary:copy(<<2>>, 32))/binary,
        (binary:copy(<<3>>, 12))/binary,
        (binary:copy(<<4>>, 12))/binary
    >>,
    {GCK, GCS, GSK, GSS} = webrtc_srtp:split_dtls_keying_material(srtp_aead_aes_256_gcm, G),
    ?assertEqual({32, 12, 32, 12}, {byte_size(GCK), byte_size(GCS), byte_size(GSK), byte_size(GSS)}),
    ?assertEqual(
        {<<1>>, <<3>>, <<2>>, <<4>>},
        {
            binary:part(GCK, 0, 1),
            binary:part(GCS, 0, 1),
            binary:part(GSK, 0, 1),
            binary:part(GSS, 0, 1)
        }
    ),
    ?assertError(badarg, webrtc_srtp:split_dtls_keying_material(srtp_aead_aes_128_gcm, Bin)).
