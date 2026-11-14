%% @doc DTLS 1.3 key schedule (RFC 8446 §7, RFC 9147 §5.9): HKDF
%% (RFC 5869), HKDF-Expand-Label with the "dtls13" label prefix,
%% handshake and application traffic secrets, traffic keys including
%% the record number encryption key (RFC 9147 §4.2.3), Finished,
%% KeyUpdate and the exporter (RFC 8446 §7.5), and the TLS 1.3 cipher
%% suite table.
%%
%% Every function that expands a label takes the label prefix so the
%% same code can be checked against the TLS 1.3 traces of RFC 8448,
%% which use "tls13 ". The HKDF and HKDF-Expand-Label code follows
%% `quic_hkdf' from erlang_quic (Copyright (c) 2024-2026 Benoit
%% Chesneau, Apache License 2.0), adapted to a variable label prefix.
-module(webrtc_dtls13_keys).

-export([
    prefix/0,
    suite/1,
    supported_suites/0,
    extract/3,
    expand/4,
    expand_label/6,
    derive_secret/5,
    early_secret/2,
    handshake_secret/3,
    master_secret/3,
    traffic_keys/3,
    finished/4,
    next_secret/3,
    exporter/6,
    hash_len/1,
    empty_hash/1,
    cv_content/2,
    hrr_random/0,
    downgrade12/0,
    downgrade10/0
]).

-export_type([suite/0, keys/0]).

-type hash() :: sha256 | sha384.
-type suite() :: #{
    id := 0..16#FFFF,
    name := atom(),
    cipher := aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    hash := hash(),
    key_len := pos_integer()
}.
-type keys() :: #{
    cipher := aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    key := binary(),
    iv := binary(),
    sn_key := binary(),
    secret := binary(),
    hash := hash()
}.

%% @doc RFC 9147 §5.9: DTLS 1.3 uses "dtls13" (no trailing space).
-spec prefix() -> binary().
prefix() -> <<"dtls13">>.

%%====================================================================
%% Cipher suites (RFC 8446 §B.4)
%%====================================================================

%% @doc TLS 1.3 suites in preference order. RFC 8446 §9.1 requires
%% TLS_AES_128_GCM_SHA256.
-spec supported_suites() -> [0..16#FFFF].
supported_suites() ->
    [16#1301, 16#1302, 16#1303].

-spec suite(0..16#FFFF) -> {ok, suite()} | error.
suite(16#1301) ->
    {ok, #{id => 16#1301, name => tls_aes_128_gcm_sha256, cipher => aes_128_gcm, hash => sha256, key_len => 16}};
suite(16#1302) ->
    {ok, #{id => 16#1302, name => tls_aes_256_gcm_sha384, cipher => aes_256_gcm, hash => sha384, key_len => 32}};
suite(16#1303) ->
    {ok, #{
        id => 16#1303, name => tls_chacha20_poly1305_sha256, cipher => chacha20_poly1305, hash => sha256, key_len => 32
    }};
suite(_) ->
    error.

-spec hash_len(hash()) -> pos_integer().
hash_len(sha256) -> 32;
hash_len(sha384) -> 48.

-spec empty_hash(hash()) -> binary().
empty_hash(Hash) -> crypto:hash(Hash, <<>>).

%%====================================================================
%% HKDF (RFC 5869) and HKDF-Expand-Label (RFC 8446 §7.1)
%%====================================================================

-spec extract(hash(), binary(), binary()) -> binary().
extract(Hash, <<>>, IKM) ->
    crypto:mac(hmac, Hash, binary:copy(<<0>>, hash_len(Hash)), IKM);
extract(Hash, Salt, IKM) ->
    crypto:mac(hmac, Hash, Salt, IKM).

-spec expand(hash(), binary(), binary(), non_neg_integer()) -> binary().
expand(Hash, PRK, Info, Len) ->
    HL = hash_len(Hash),
    true = Len =< 255 * HL,
    N = (Len + HL - 1) div HL,
    Out = expand_loop(Hash, PRK, Info, N, 1, <<>>, <<>>),
    binary:part(Out, 0, Len).

expand_loop(_Hash, _PRK, _Info, N, I, _Prev, Acc) when I > N ->
    Acc;
expand_loop(Hash, PRK, Info, N, I, Prev, Acc) ->
    T = crypto:mac(hmac, Hash, PRK, <<Prev/binary, Info/binary, I>>),
    expand_loop(Hash, PRK, Info, N, I + 1, T, <<Acc/binary, T/binary>>).

%% @doc HKDF-Expand-Label(Secret, Label, Context, Length) with the given
%% label prefix.
-spec expand_label(binary(), hash(), binary(), binary(), binary(), non_neg_integer()) -> binary().
expand_label(Prefix, Hash, Secret, Label, Context, Len) ->
    Full = <<Prefix/binary, Label/binary>>,
    Info = <<Len:16, (byte_size(Full)), Full/binary, (byte_size(Context)), Context/binary>>,
    expand(Hash, Secret, Info, Len).

%% @doc Derive-Secret(Secret, Label, Messages), given the transcript
%% hash of Messages.
-spec derive_secret(binary(), hash(), binary(), binary(), binary()) -> binary().
derive_secret(Prefix, Hash, Secret, Label, TranscriptHash) ->
    expand_label(Prefix, Hash, Secret, Label, TranscriptHash, hash_len(Hash)).

%%====================================================================
%% Key schedule (RFC 8446 §7.1), no PSK
%%====================================================================

-spec early_secret(binary(), hash()) -> binary().
early_secret(_Prefix, Hash) ->
    extract(Hash, <<>>, binary:copy(<<0>>, hash_len(Hash))).

-spec handshake_secret(binary(), hash(), binary()) -> binary().
handshake_secret(Prefix, Hash, Shared) ->
    Early = early_secret(Prefix, Hash),
    Derived = derive_secret(Prefix, Hash, Early, <<"derived">>, empty_hash(Hash)),
    extract(Hash, Derived, Shared).

-spec master_secret(binary(), hash(), binary()) -> binary().
master_secret(Prefix, Hash, HandshakeSecret) ->
    Derived = derive_secret(Prefix, Hash, HandshakeSecret, <<"derived">>, empty_hash(Hash)),
    extract(Hash, Derived, binary:copy(<<0>>, hash_len(Hash))).

%% @doc Traffic keys of RFC 8446 §7.3 plus the record number key of
%% RFC 9147 §4.2.3.
-spec traffic_keys(binary(), suite(), binary()) -> keys().
traffic_keys(Prefix, #{cipher := C, hash := H, key_len := KL}, Secret) ->
    #{
        cipher => C,
        key => expand_label(Prefix, H, Secret, <<"key">>, <<>>, KL),
        iv => expand_label(Prefix, H, Secret, <<"iv">>, <<>>, 12),
        sn_key => expand_label(Prefix, H, Secret, <<"sn">>, <<>>, KL),
        secret => Secret,
        hash => H
    }.

%% @doc Finished verify_data (RFC 8446 §4.4.4).
-spec finished(binary(), hash(), binary(), binary()) -> binary().
finished(Prefix, Hash, BaseKey, TranscriptHash) ->
    Key = expand_label(Prefix, Hash, BaseKey, <<"finished">>, <<>>, hash_len(Hash)),
    crypto:mac(hmac, Hash, Key, TranscriptHash).

%% @doc application_traffic_secret_N+1 (RFC 8446 §7.2).
-spec next_secret(binary(), hash(), binary()) -> binary().
next_secret(Prefix, Hash, Secret) ->
    expand_label(Prefix, Hash, Secret, <<"traffic upd">>, <<>>, hash_len(Hash)).

%% @doc TLS-Exporter (RFC 8446 §7.5). In TLS 1.3 an absent context and
%% an empty context give the same output.
-spec exporter(binary(), hash(), binary(), binary(), binary() | no_context, non_neg_integer()) -> binary().
exporter(Prefix, Hash, ExporterSecret, Label, Context, Len) ->
    Ctx =
        case Context of
            no_context -> <<>>;
            C -> C
        end,
    Secret = derive_secret(Prefix, Hash, ExporterSecret, Label, empty_hash(Hash)),
    expand_label(Prefix, Hash, Secret, <<"exporter">>, crypto:hash(Hash, Ctx), Len).

%% @doc Content covered by CertificateVerify (RFC 8446 §4.4.3).
-spec cv_content(client | server, binary()) -> binary().
cv_content(Role, TranscriptHash) ->
    Ctx =
        case Role of
            server -> <<"TLS 1.3, server CertificateVerify">>;
            client -> <<"TLS 1.3, client CertificateVerify">>
        end,
    <<(binary:copy(<<16#20>>, 64))/binary, Ctx/binary, 0, TranscriptHash/binary>>.

%% @doc ServerHello.random of a HelloRetryRequest (RFC 8446 §4.1.3).
-spec hrr_random() -> binary().
hrr_random() ->
    <<16#CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C:256>>.

%% @doc Downgrade sentinels (RFC 8446 §4.1.3, RFC 9147 §5.3): last 8
%% bytes of ServerHello.random when a 1.3 server negotiates DTLS 1.2 or
%% DTLS 1.0.
-spec downgrade12() -> binary().
downgrade12() -> <<"DOWNGRD", 1>>.

-spec downgrade10() -> binary().
downgrade10() -> <<"DOWNGRD", 0>>.
