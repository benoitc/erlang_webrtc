%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Cryptographic building blocks for DTLS 1.2: cipher suite table,
%% TLS 1.2 PRF (RFC 5246 §5), master secret including the extended
%% master secret (RFC 7627), key block, Finished, exporters (RFC 5705),
%% ECDHE and handshake signatures.
-module(webrtc_dtls_crypto).

-include_lib("public_key/include/public_key.hrl").

-export([
    suite/1,
    supported_suites/0,
    prf/4,
    master_secret/4,
    extended_master_secret/3,
    key_block/4,
    finished/4,
    export/5,
    generate_ecdhe/1,
    ecdhe_shared/3,
    group_id/1,
    group_name/1,
    sign/3,
    verify/4,
    sig_scheme_id/1,
    sig_scheme_name/1,
    signature_schemes/0,
    scheme_for_key/1
]).

-export_type([suite/0, group/0, sig_scheme/0]).

-type group() :: x25519 | secp256r1 | secp384r1.
-type sig_scheme() ::
    ecdsa_secp256r1_sha256
    | ecdsa_secp384r1_sha384
    | rsa_pss_rsae_sha256
    | rsa_pkcs1_sha256
    | ed25519.
-type suite() :: #{
    id := 0..16#FFFF,
    name := atom(),
    auth := ecdsa | rsa,
    cipher := aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    key_len := pos_integer(),
    iv_len := pos_integer(),
    explicit_nonce := 0 | 8,
    prf := sha256 | sha384
}.

%%====================================================================
%% Cipher suites
%%====================================================================

%% @doc Cipher suites in order of preference. RFC 8827 §6.5 requires
%% TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256. Only AEAD suites with
%% forward secrecy are offered (RFC 9325 §4.2).
-spec supported_suites() -> [0..16#FFFF].
supported_suites() ->
    [16#C02B, 16#C02C, 16#CCA9, 16#C02F, 16#C030, 16#CCA8].

-spec suite(0..16#FFFF) -> {ok, suite()} | error.
suite(16#C02B) ->
    {ok, gcm(16#C02B, tls_ecdhe_ecdsa_with_aes_128_gcm_sha256, ecdsa, aes_128_gcm, 16, sha256)};
suite(16#C02C) ->
    {ok, gcm(16#C02C, tls_ecdhe_ecdsa_with_aes_256_gcm_sha384, ecdsa, aes_256_gcm, 32, sha384)};
suite(16#C02F) ->
    {ok, gcm(16#C02F, tls_ecdhe_rsa_with_aes_128_gcm_sha256, rsa, aes_128_gcm, 16, sha256)};
suite(16#C030) ->
    {ok, gcm(16#C030, tls_ecdhe_rsa_with_aes_256_gcm_sha384, rsa, aes_256_gcm, 32, sha384)};
suite(16#CCA9) ->
    {ok, chacha(16#CCA9, tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256, ecdsa)};
suite(16#CCA8) ->
    {ok, chacha(16#CCA8, tls_ecdhe_rsa_with_chacha20_poly1305_sha256, rsa)};
suite(_) ->
    error.

gcm(Id, Name, Auth, Cipher, KeyLen, Prf) ->
    #{
        id => Id,
        name => Name,
        auth => Auth,
        cipher => Cipher,
        key_len => KeyLen,
        iv_len => 4,
        explicit_nonce => 8,
        prf => Prf
    }.

%% RFC 7905: 12-byte IV, nonce = IV xor seq, no explicit nonce.
chacha(Id, Name, Auth) ->
    #{
        id => Id,
        name => Name,
        auth => Auth,
        cipher => chacha20_poly1305,
        key_len => 32,
        iv_len => 12,
        explicit_nonce => 0,
        prf => sha256
    }.

%%====================================================================
%% PRF and key schedule (RFC 5246 §5, §6.3, §8.1; RFC 7627 §4)
%%====================================================================

-spec prf(sha256 | sha384, binary(), iodata(), non_neg_integer()) -> binary().
prf(Hash, Secret, LabelSeed, Len) ->
    Seed = iolist_to_binary(LabelSeed),
    p_hash(Hash, Secret, Seed, Seed, Len, []).

p_hash(_Hash, _Secret, _Seed, _A, Len, Acc) when Len =< 0 ->
    Out = iolist_to_binary(lists:reverse(Acc)),
    Out;
p_hash(Hash, Secret, Seed, A0, Len, Acc) ->
    A1 = crypto:mac(hmac, Hash, Secret, A0),
    Block = crypto:mac(hmac, Hash, Secret, [A1, Seed]),
    case Len >= byte_size(Block) of
        true ->
            p_hash(Hash, Secret, Seed, A1, Len - byte_size(Block), [Block | Acc]);
        false ->
            <<Part:Len/binary, _/binary>> = Block,
            p_hash(Hash, Secret, Seed, A1, 0, [Part | Acc])
    end.

-spec master_secret(sha256 | sha384, binary(), binary(), binary()) -> binary().
master_secret(Hash, PreMaster, ClientRandom, ServerRandom) ->
    prf(Hash, PreMaster, [<<"master secret">>, ClientRandom, ServerRandom], 48).

%% @doc RFC 7627 §4: the session hash covers the handshake up to and
%% including ClientKeyExchange.
-spec extended_master_secret(sha256 | sha384, binary(), binary()) -> binary().
extended_master_secret(Hash, PreMaster, SessionHash) ->
    prf(Hash, PreMaster, [<<"extended master secret">>, SessionHash], 48).

%% @doc Returns `{ClientKey, ServerKey, ClientIV, ServerIV}' for an AEAD
%% suite (no MAC keys).
-spec key_block(suite(), binary(), binary(), binary()) ->
    {binary(), binary(), binary(), binary()}.
key_block(#{key_len := KL, iv_len := IL, prf := Hash}, Master, ClientRandom, ServerRandom) ->
    Len = 2 * (KL + IL),
    <<CK:KL/binary, SK:KL/binary, CIV:IL/binary, SIV:IL/binary>> =
        prf(Hash, Master, [<<"key expansion">>, ServerRandom, ClientRandom], Len),
    {CK, SK, CIV, SIV}.

-spec finished(sha256 | sha384, client | server, binary(), binary()) -> binary().
finished(Hash, Role, Master, TranscriptHash) ->
    Label =
        case Role of
            client -> <<"client finished">>;
            server -> <<"server finished">>
        end,
    prf(Hash, Master, [Label, TranscriptHash], 12).

%% @doc Keying material exporter (RFC 5705 §4). DTLS-SRTP uses the label
%% "EXTRACTOR-dtls_srtp" with no context (RFC 5764 §4.2).
-spec export(sha256 | sha384, binary(), {binary(), binary()}, binary(), binary() | no_context) ->
    fun((non_neg_integer()) -> binary()).
export(Hash, Master, {ClientRandom, ServerRandom}, Label, Context) ->
    Seed =
        case Context of
            no_context -> [Label, ClientRandom, ServerRandom];
            C -> [Label, ClientRandom, ServerRandom, <<(byte_size(C)):16>>, C]
        end,
    fun(Len) -> prf(Hash, Master, Seed, Len) end.

%%====================================================================
%% ECDHE (RFC 8422)
%%====================================================================

-spec group_id(group()) -> 0..16#FFFF.
group_id(secp256r1) -> 23;
group_id(secp384r1) -> 24;
group_id(x25519) -> 29.

-spec group_name(0..16#FFFF) -> group() | unknown.
group_name(23) -> secp256r1;
group_name(24) -> secp384r1;
group_name(29) -> x25519;
group_name(_) -> unknown.

-spec generate_ecdhe(group()) -> {Public :: binary(), Private :: binary()}.
generate_ecdhe(Group) ->
    crypto:generate_key(ecdh, Group).

%% @doc Compute the ECDHE shared secret. Invalid points are rejected; an
%% all-zero X25519 result is rejected as required by RFC 8422 §5.11 and
%% RFC 7748 §6.1.
-spec ecdhe_shared(group(), binary(), binary()) -> {ok, binary()} | {error, bad_point}.
ecdhe_shared(Group, PeerPub, Priv) ->
    Valid =
        case Group of
            x25519 -> byte_size(PeerPub) =:= 32;
            secp256r1 -> byte_size(PeerPub) =:= 65 andalso binary:first(PeerPub) =:= 4;
            secp384r1 -> byte_size(PeerPub) =:= 97 andalso binary:first(PeerPub) =:= 4
        end,
    case Valid of
        false ->
            {error, bad_point};
        true ->
            try crypto:compute_key(ecdh, PeerPub, Priv, Group) of
                Shared ->
                    case Group =:= x25519 andalso Shared =:= <<0:256>> of
                        true -> {error, bad_point};
                        false -> {ok, Shared}
                    end
            catch
                _:_ -> {error, bad_point}
            end
    end.

%%====================================================================
%% Signatures (RFC 5246 §7.4.1.4.1, RFC 8446 §4.2.3 code points)
%%====================================================================

-spec signature_schemes() -> [sig_scheme()].
signature_schemes() ->
    [
        ecdsa_secp256r1_sha256,
        ecdsa_secp384r1_sha384,
        ed25519,
        rsa_pss_rsae_sha256,
        rsa_pkcs1_sha256
    ].

-spec sig_scheme_id(sig_scheme()) -> 0..16#FFFF.
sig_scheme_id(rsa_pkcs1_sha256) -> 16#0401;
sig_scheme_id(ecdsa_secp256r1_sha256) -> 16#0403;
sig_scheme_id(ecdsa_secp384r1_sha384) -> 16#0503;
sig_scheme_id(rsa_pss_rsae_sha256) -> 16#0804;
sig_scheme_id(ed25519) -> 16#0807.

-spec sig_scheme_name(0..16#FFFF) -> sig_scheme() | unknown.
sig_scheme_name(16#0401) -> rsa_pkcs1_sha256;
sig_scheme_name(16#0403) -> ecdsa_secp256r1_sha256;
sig_scheme_name(16#0503) -> ecdsa_secp384r1_sha384;
sig_scheme_name(16#0804) -> rsa_pss_rsae_sha256;
sig_scheme_name(16#0807) -> ed25519;
sig_scheme_name(_) -> unknown.

%% @doc Signature scheme to use with our own private key, chosen among
%% the schemes the peer accepts.
-spec scheme_for_key(public_key:private_key()) -> [sig_scheme()].
scheme_for_key(#'ECPrivateKey'{parameters = {namedCurve, ?'secp256r1'}}) ->
    [ecdsa_secp256r1_sha256];
scheme_for_key(#'ECPrivateKey'{parameters = {namedCurve, ?'secp384r1'}}) ->
    [ecdsa_secp384r1_sha384];
scheme_for_key(#'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'}}) ->
    [ed25519];
scheme_for_key(#'RSAPrivateKey'{}) ->
    [rsa_pss_rsae_sha256, rsa_pkcs1_sha256].

-spec sign(sig_scheme(), iodata(), public_key:private_key()) -> binary().
sign(Scheme, Data, Key) ->
    Bin = iolist_to_binary(Data),
    case Scheme of
        ecdsa_secp256r1_sha256 -> public_key:sign(Bin, sha256, Key);
        ecdsa_secp384r1_sha384 -> public_key:sign(Bin, sha384, Key);
        ed25519 -> public_key:sign(Bin, none, Key);
        rsa_pkcs1_sha256 -> public_key:sign(Bin, sha256, Key);
        rsa_pss_rsae_sha256 -> public_key:sign(Bin, sha256, Key, pss_opts())
    end.

%% @doc Verify a handshake signature with the peer's certificate key.
%% The scheme must match the key type.
-spec verify(sig_scheme(), iodata(), binary(), {ecdsa | rsa | eddsa, term()}) -> boolean().
verify(Scheme, Data, Sig, {Type, Key}) ->
    Bin = iolist_to_binary(Data),
    try
        case {Scheme, Type} of
            {ecdsa_secp256r1_sha256, ecdsa} -> public_key:verify(Bin, sha256, Sig, Key);
            {ecdsa_secp384r1_sha384, ecdsa} -> public_key:verify(Bin, sha384, Sig, Key);
            {ed25519, eddsa} -> public_key:verify(Bin, none, Sig, Key);
            {rsa_pkcs1_sha256, rsa} -> public_key:verify(Bin, sha256, Sig, Key);
            {rsa_pss_rsae_sha256, rsa} -> public_key:verify(Bin, sha256, Sig, Key, pss_opts());
            _ -> false
        end
    catch
        _:_ -> false
    end.

pss_opts() ->
    [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}, {rsa_mgf1_md, sha256}].
