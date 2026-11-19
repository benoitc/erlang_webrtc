%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc SRTP key derivation (RFC 3711 §4.3) with the AES-CM PRF
%% (RFC 3711 §4.3.3, RFC 6188 §7 for AES-256 master keys).
%%
%% The key derivation rate is always 0 (RFC 5764 §4.1.2, RFC 7714 §11),
%% so `index DIV kdr' is 0 and each session key is derived exactly once,
%% when the context is created.
%%
%% Master salts shorter than 112 bits (the 96-bit AES-GCM salt of
%% RFC 7714) are extended with trailing zero octets before the XOR with
%% the key id. This is the layout used by libsrtp and therefore by
%% browsers; see docs/compliance/srtp.md (SRTP-KDF-4).
-module(webrtc_srtp_kdf).

-export([derive/4, prf/3, keystream/3, session_keys/3]).

-export_type([session_keys/0]).

-define(LABEL_RTP_ENC, 16#00).
-define(LABEL_RTP_AUTH, 16#01).
-define(LABEL_RTP_SALT, 16#02).
-define(LABEL_RTCP_ENC, 16#03).
-define(LABEL_RTCP_AUTH, 16#04).
-define(LABEL_RTCP_SALT, 16#05).
%% RFC 6904 §3.3: header extension encryption key and salt.
-define(LABEL_RTP_HDR_ENC, 16#06).
-define(LABEL_RTP_HDR_SALT, 16#07).
%% The header keystream is AES-CM for every profile (RFC 6904 §4,
%% RFC 7714 §8.3), so its salt has the AES-CM length, as libsrtp uses.
-define(HDR_SALT_LEN, 14).

-type session_keys() :: #{
    rtp_key := binary(),
    rtp_salt := binary(),
    rtp_auth_key := binary(),
    rtcp_key := binary(),
    rtcp_salt := binary(),
    rtcp_auth_key := binary(),
    rtp_hdr_key := binary(),
    rtp_hdr_salt := binary()
}.

%% @doc Derive all session keys of a profile from a master key and salt.
%% For AEAD profiles the authentication keys are empty binaries.
-spec session_keys(webrtc_srtp_profile:profile(), binary(), binary()) -> session_keys().
session_keys(Profile, MasterKey, MasterSalt) ->
    #{master_key_len := KL, master_salt_len := SL, auth_key_len := AL} =
        webrtc_srtp_profile:params(Profile),
    case {byte_size(MasterKey), byte_size(MasterSalt)} of
        {KL, SL} -> ok;
        _ -> erlang:error(badarg, [Profile, MasterKey, MasterSalt])
    end,
    D = fun(Label, Len) -> derive(Label, MasterKey, MasterSalt, Len) end,
    #{
        rtp_key => D(?LABEL_RTP_ENC, KL),
        rtp_salt => D(?LABEL_RTP_SALT, SL),
        rtp_auth_key => D(?LABEL_RTP_AUTH, AL),
        rtcp_key => D(?LABEL_RTCP_ENC, KL),
        rtcp_salt => D(?LABEL_RTCP_SALT, SL),
        rtcp_auth_key => D(?LABEL_RTCP_AUTH, AL),
        rtp_hdr_key => D(?LABEL_RTP_HDR_ENC, KL),
        rtp_hdr_salt => D(?LABEL_RTP_HDR_SALT, ?HDR_SALT_LEN)
    }.

%% @doc Derive `Len' octets for `Label' with kdr = 0 (RFC 3711 §4.3.1):
%% x = (Label || 0^48) XOR master_salt, then PRF_n(k_master, x).
-spec derive(0..255, binary(), binary(), non_neg_integer()) -> binary().
derive(_Label, _MasterKey, _MasterSalt, 0) ->
    <<>>;
derive(Label, MasterKey, MasterSalt, Len) when byte_size(MasterSalt) =< 14 ->
    Pad = (14 - byte_size(MasterSalt)) * 8,
    <<S:112>> = <<MasterSalt/binary, 0:Pad>>,
    %% key_id = label || r (r = 0, 48 bits), right aligned in 112 bits.
    X = S bxor (Label bsl 48),
    prf(MasterKey, <<X:112>>, Len).

%% @doc AES-CM PRF (RFC 3711 §4.3.3): AES counter mode keyed with the
%% master key, IV = x * 2^16, output truncated to `Len' octets.
-spec prf(binary(), <<_:112>>, non_neg_integer()) -> binary().
prf(MasterKey, <<X:112>>, Len) ->
    keystream(MasterKey, <<X:112, 0:16>>, Len).

%% @doc `Len' octets of AES counter mode keystream starting at block `IV'
%% (RFC 3711 §4.1.1).
-spec keystream(binary(), <<_:128>>, non_neg_integer()) -> binary().
keystream(Key, IV, Len) ->
    crypto:crypto_one_time(ctr_cipher(Key), Key, IV, <<0:(Len * 8)>>, true).

ctr_cipher(K) when byte_size(K) =:= 16 -> aes_128_ctr;
ctr_cipher(K) when byte_size(K) =:= 24 -> aes_192_ctr;
ctr_cipher(K) when byte_size(K) =:= 32 -> aes_256_ctr.
