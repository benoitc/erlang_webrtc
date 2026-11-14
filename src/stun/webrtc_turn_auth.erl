%% @private
%% @doc Long-term credential helpers for the TURN client (RFC 8489
%% §9.2): request attributes, the nonce cookie and its security
%% feature bits (§9.2.1), PASSWORD-ALGORITHMS selection (§9.2.5), the
%% HMAC key (§9.2.2, §18.5.1) and the integrity rule for responses.
-module(webrtc_turn_auth).

-include("webrtc_stun.hrl").

-export([attrs/5, authentic/3, pick_algorithm/2, nonce_features/1, integrity/4]).

-define(NONCE_COOKIE, "obMatJos2").

%% @doc Attributes of an authenticated request: USERNAME, REALM, NONCE
%% and, when the server offered them, PASSWORD-ALGORITHMS (echoed) and
%% PASSWORD-ALGORITHM. Nothing before the first challenge (§9.2.3.1).
-spec attrs(binary(), binary() | undefined, binary() | undefined, list() | undefined,
            {atom(), binary()} | undefined) -> [webrtc_stun:attr()].
attrs(_U, undefined, _N, _Algs, _Alg) ->
    [];
attrs(U, R, N, Algs, Alg) ->
    [{username, U}, {realm, R}, {nonce, N}] ++
        case Algs of
            undefined -> [];
            _ -> [{password_algorithms, Algs}, {password_algorithm, Alg}]
        end.

%% @doc 401 and 438 are accepted without integrity (they carry the new
%% realm and nonce); every other response to an authenticated request
%% must verify. A 400 without integrity is discarded (§9.2.5).
-spec authentic(#stun{}, binary(), webrtc_stun:integrity()) -> boolean().
authentic(M, Bin, I) ->
    Code =
        case {M#stun.class, webrtc_stun:get(error_code, M)} of
            {error, {ok, {C, _}}} -> C;
            {error, error} -> 0;
            {_, _} -> 200
        end,
    HasMI = webrtc_stun:has_integrity(M),
    if
        Code =:= 401; Code =:= 438 -> true;
        I =:= undefined, Code =:= 400 -> HasMI;
        I =:= undefined -> true;
        true -> HasMI andalso webrtc_stun:check_integrity(Bin, element(2, I)) =:= ok
    end.

%% @doc Choose the password algorithm after a 401: the first supported
%% entry of PASSWORD-ALGORITHMS, `undefined' (MD5, MESSAGE-INTEGRITY)
%% when none was offered. A nonce cookie announcing password algorithms
%% without the attribute, or username anonymity (USERHASH, not
%% supported), stops the retry.
-spec pick_algorithm(binary(), list() | undefined) -> {ok, {atom(), binary()} | undefined} | {error, term()}.
pick_algorithm(Nonce, Algs) ->
    Features = nonce_features(Nonce),
    if
        Features band 16#800000 =/= 0, Algs =:= undefined ->
            {error, {unsupported, missing_password_algorithms}};
        Features band 16#400000 =/= 0 ->
            {error, {unsupported, userhash}};
        Algs =:= undefined ->
            {ok, undefined};
        true ->
            case [A || {Name, _} = A <- Algs, Name =:= md5 orelse Name =:= sha256] of
                [First | _] -> {ok, First};
                [] -> {error, {unsupported, password_algorithms}}
            end
    end.

%% @doc The 24 STUN security feature bits of a nonce starting with the
%% nonce cookie, 0 otherwise. Bit 0 (most significant) is "password
%% algorithms", bit 1 "username anonymity".
-spec nonce_features(binary()) -> 0..16#FFFFFF.
nonce_features(<<?NONCE_COOKIE, B64:4/binary, _/binary>>) ->
    try base64:decode(B64) of
        <<F:24>> -> F;
        _ -> 0
    catch
        error:_ -> 0
    end;
nonce_features(_) ->
    0.

%% @doc Integrity to use: MESSAGE-INTEGRITY with the MD5 key, or
%% MESSAGE-INTEGRITY-SHA256 only once PASSWORD-ALGORITHMS was offered
%% (§9.2.5), with the key of the chosen algorithm.
-spec integrity(binary(), binary(), binary(), {atom(), binary()} | undefined) -> webrtc_stun:integrity().
integrity(U, R, P, undefined) ->
    {sha1, webrtc_stun:long_term_key(md5, U, R, P)};
integrity(U, R, P, {md5, _}) ->
    {sha256, webrtc_stun:long_term_key(md5, U, R, P)};
integrity(U, R, P, {sha256, _}) ->
    {sha256, webrtc_stun:long_term_key(sha256, U, R, P)}.
