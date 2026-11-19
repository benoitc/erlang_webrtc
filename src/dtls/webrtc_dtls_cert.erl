%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Certificates for DTLS in WebRTC.
%%
%% WebRTC endpoints use self-signed certificates whose identity is the
%% fingerprint carried in SDP (RFC 8122, RFC 8827 §6.5). This module
%% generates such certificates, computes and formats fingerprints, and
%% extracts the public key used to check handshake signatures.
-module(webrtc_dtls_cert).

-include_lib("public_key/include/public_key.hrl").

-export([
    generate/0,
    generate/1,
    fingerprint/2,
    format_fingerprint/1,
    parse_fingerprint/1,
    matches/2,
    public_key/1
]).

-export_type([cert/0, fingerprint/0, hash/0]).

-type hash() :: sha | sha224 | sha256 | sha384 | sha512.
-type fingerprint() :: {hash(), binary()}.
-type cert() :: #{der := binary(), key := public_key:private_key()}.

%% @doc Generate an ECDSA P-256 self-signed certificate (the algorithm
%% browsers use by default).
-spec generate() -> cert().
generate() ->
    generate(#{}).

%% @doc Options: `key' is `ecdsa_p256' (default) or `{rsa, Bits}';
%% `common_name' (binary); `days' of validity (default 30).
-spec generate(map()) -> cert().
generate(Opts) ->
    {Key, SPKI, SigAlg} =
        case maps:get(key, Opts, ecdsa_p256) of
            ecdsa_p256 ->
                K = public_key:generate_key({namedCurve, ?'secp256r1'}),
                #'ECPrivateKey'{publicKey = Pub} = K,
                {K,
                    #'OTPSubjectPublicKeyInfo'{
                        algorithm = #'PublicKeyAlgorithm'{
                            algorithm = ?'id-ecPublicKey',
                            parameters = {namedCurve, ?'secp256r1'}
                        },
                        subjectPublicKey = #'ECPoint'{point = Pub}
                    },
                    #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256'}};
            {rsa, Bits} ->
                K = public_key:generate_key({rsa, Bits, 65537}),
                #'RSAPrivateKey'{modulus = N, publicExponent = E} = K,
                {K,
                    #'OTPSubjectPublicKeyInfo'{
                        algorithm = #'PublicKeyAlgorithm'{
                            algorithm = ?'rsaEncryption', parameters = 'NULL'
                        },
                        subjectPublicKey = #'RSAPublicKey'{modulus = N, publicExponent = E}
                    },
                    #'SignatureAlgorithm'{
                        algorithm = ?'sha256WithRSAEncryption'
                    }}
        end,
    CN = maps:get(common_name, Opts, <<"WebRTC">>),
    Name =
        {rdnSequence, [
            [#'AttributeTypeAndValue'{type = ?'id-at-commonName', value = {utf8String, CN}}]
        ]},
    Days = maps:get(days, Opts, 30),
    Now = erlang:system_time(second),
    %% Backdate by a day to tolerate clock skew between peers.
    Validity = #'Validity'{
        notBefore = utc_time(Now - 86400),
        notAfter = utc_time(Now + Days * 86400)
    },
    <<Serial:63, _:1>> = crypto:strong_rand_bytes(8),
    TBS = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = Serial + 1,
        signature = SigAlg,
        issuer = Name,
        validity = Validity,
        subject = Name,
        subjectPublicKeyInfo = SPKI
    },
    #{der => public_key:pkix_sign(TBS, Key), key => Key}.

utc_time(Secs) ->
    {{Y, Mo, D}, {H, Mi, S}} = calendar:system_time_to_universal_time(Secs, second),
    Str = io_lib:format("~2..0w~2..0w~2..0w~2..0w~2..0w~2..0wZ", [Y rem 100, Mo, D, H, Mi, S]),
    {utcTime, lists:flatten(Str)}.

%% @doc Fingerprint of a DER certificate (RFC 8122 §5).
-spec fingerprint(hash(), binary()) -> fingerprint().
fingerprint(Hash, Der) ->
    {Hash, crypto:hash(Hash, Der)}.

%% @doc Format as in SDP: `sha-256 AB:CD:...'.
-spec format_fingerprint(fingerprint()) -> binary().
format_fingerprint({Hash, Bin}) ->
    Hex = lists:join($:, [io_lib:format("~2.16.0B", [B]) || <<B>> <= Bin]),
    iolist_to_binary([hash_name(Hash), $\s, Hex]).

%% @doc Parse the value of an `a=fingerprint' attribute.
-spec parse_fingerprint(binary()) -> {ok, fingerprint()} | {error, bad_fingerprint}.
parse_fingerprint(Value) ->
    case binary:split(string:trim(Value), <<" ">>) of
        [HashName, Hex] ->
            try
                Hash = hash_atom(string:lowercase(HashName)),
                Bytes = <<<<(binary_to_integer(H, 16))>> || H <- binary:split(Hex, <<":">>, [global])>>,
                case byte_size(Bytes) =:= hash_size(Hash) of
                    true -> {ok, {Hash, Bytes}};
                    false -> {error, bad_fingerprint}
                end
            catch
                _:_ -> {error, bad_fingerprint}
            end;
        _ ->
            {error, bad_fingerprint}
    end.

%% @doc True when the DER certificate matches one of the fingerprints.
%% RFC 8122 §5: a match with any fingerprint whose hash is supported is
%% sufficient. SHA-1 and SHA-224 fingerprints are ignored: they are not
%% strong enough to bind the certificate. Comparison is constant time.
-spec matches(binary(), [fingerprint()]) -> boolean().
matches(Der, Fingerprints) ->
    lists:any(
        fun
            ({Hash, _}) when Hash =:= sha; Hash =:= sha224 ->
                false;
            ({Hash, Expected}) ->
            Actual = crypto:hash(Hash, Der),
            byte_size(Actual) =:= byte_size(Expected) andalso crypto:hash_equals(Actual, Expected)
        end,
        Fingerprints
    ).

%% @doc Public key of a DER certificate, in the form accepted by
%% `public_key:verify/4'.
-spec public_key(binary()) ->
    {ok, {ecdsa, term()} | {rsa, #'RSAPublicKey'{}} | {eddsa, term()}} | {error, term()}.
public_key(Der) ->
    try public_key:pkix_decode_cert(Der, otp) of
        #'OTPCertificate'{tbsCertificate = TBS} ->
            #'OTPSubjectPublicKeyInfo'{algorithm = Alg, subjectPublicKey = PK} =
                TBS#'OTPTBSCertificate'.subjectPublicKeyInfo,
            case {Alg, PK} of
                {#'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey', parameters = Params},
                    #'ECPoint'{} = Pt} ->
                    {ok, {ecdsa, {Pt, Params}}};
                {_, #'RSAPublicKey'{} = RSA} ->
                    {ok, {rsa, RSA}};
                {#'PublicKeyAlgorithm'{algorithm = ?'id-Ed25519'}, #'ECPoint'{} = Pt} ->
                    {ok, {eddsa, {Pt, {namedCurve, ?'id-Ed25519'}}}};
                _ ->
                    {error, unsupported_public_key}
            end
    catch
        _:_ -> {error, bad_certificate}
    end.

hash_name(sha) -> <<"sha-1">>;
hash_name(sha224) -> <<"sha-224">>;
hash_name(sha256) -> <<"sha-256">>;
hash_name(sha384) -> <<"sha-384">>;
hash_name(sha512) -> <<"sha-512">>.

hash_atom(<<"sha-1">>) -> sha;
hash_atom(<<"sha-224">>) -> sha224;
hash_atom(<<"sha-256">>) -> sha256;
hash_atom(<<"sha-384">>) -> sha384;
hash_atom(<<"sha-512">>) -> sha512.

hash_size(sha) -> 20;
hash_size(sha224) -> 28;
hash_size(sha256) -> 32;
hash_size(sha384) -> 48;
hash_size(sha512) -> 64.
