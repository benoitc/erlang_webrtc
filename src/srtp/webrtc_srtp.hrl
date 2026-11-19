%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Private records shared by the SRTP modules. Not part of the public API.

%% Session keys and transform parameters for one direction of SRTP or
%% SRTCP, derived once when the context is created.
-record(srtp_keys, {
    %% cm: AES counter mode + HMAC-SHA1 (RFC 3711).
    %% gcm: AES-GCM AEAD (RFC 7714).
    transform :: cm | gcm,
    %% Cipher name given to the crypto application.
    cipher :: aes_128_ctr | aes_128_gcm | aes_256_gcm,
    enc_key :: binary(),
    %% CM: session salt already multiplied by 2^16 (128-bit value).
    %% GCM: 96-bit session salt.
    salt :: non_neg_integer(),
    %% HMAC-SHA1 session key, CM only.
    auth_key :: binary() | undefined,
    %% Authentication tag length in octets (CM: 10 or 4, GCM: 16).
    tag_len :: pos_integer(),
    %% GCM only: precomputed AEAD states (key schedule reused per packet).
    enc_state :: term(),
    dec_state :: term()
}).
