%% @doc STUN message codec (RFC 8489), with the ICE (RFC 8445 §16.1)
%% and TURN (RFC 8656 §18) attributes.
%%
%% This module is pure: it encodes and decodes binaries and verifies
%% MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256 and FINGERPRINT. It has no
%% notion of transactions or retransmission (see `webrtc_stun_tx').
-module(webrtc_stun).

-include("webrtc_stun.hrl").

-export([
    encode/1,
    encode/2,
    decode/1,
    is_stun/1,
    check_integrity/2,
    has_integrity/1,
    new_txid/0,
    request/2,
    indication/2,
    success/2,
    error_response/3,
    get/2,
    get/3,
    long_term_key/3,
    long_term_key/4,
    error_reason/1
]).

-export_type([class/0, method/0, attr/0, attr_name/0, integrity/0, address/0]).

-type class() :: request | indication | success | error.
-type method() ::
    binding
    | allocate
    | refresh
    | send
    | data
    | create_permission
    | channel_bind
    | non_neg_integer().
-type address() :: {inet:ip_address(), inet:port_number()}.
-type attr_name() :: atom() | non_neg_integer().
-type attr() :: {attr_name(), term()}.
-type integrity() ::
    undefined
    | {sha1, Key :: binary()}
    | {sha256, Key :: binary()}.
-type encode_opts() :: #{
    integrity => integrity(),
    fingerprint => boolean()
}.

%% Attribute types (RFC 8489 §18.3, RFC 8445 §16.1, RFC 8656 §18).
-define(A_MAPPED_ADDRESS, 16#0001).
-define(A_USERNAME, 16#0006).
-define(A_MESSAGE_INTEGRITY, 16#0008).
-define(A_ERROR_CODE, 16#0009).
-define(A_UNKNOWN_ATTRIBUTES, 16#000A).
-define(A_CHANNEL_NUMBER, 16#000C).
-define(A_LIFETIME, 16#000D).
-define(A_XOR_PEER_ADDRESS, 16#0012).
-define(A_DATA, 16#0013).
-define(A_REALM, 16#0014).
-define(A_NONCE, 16#0015).
-define(A_XOR_RELAYED_ADDRESS, 16#0016).
-define(A_REQUESTED_ADDRESS_FAMILY, 16#0017).
-define(A_EVEN_PORT, 16#0018).
-define(A_REQUESTED_TRANSPORT, 16#0019).
-define(A_DONT_FRAGMENT, 16#001A).
-define(A_MESSAGE_INTEGRITY_SHA256, 16#001C).
-define(A_PASSWORD_ALGORITHM, 16#001D).
-define(A_USERHASH, 16#001E).
-define(A_XOR_MAPPED_ADDRESS, 16#0020).
-define(A_RESERVATION_TOKEN, 16#0022).
-define(A_PRIORITY, 16#0024).
-define(A_USE_CANDIDATE, 16#0025).
-define(A_ADDITIONAL_ADDRESS_FAMILY, 16#8000).
-define(A_ADDRESS_ERROR_CODE, 16#8001).
-define(A_PASSWORD_ALGORITHMS, 16#8002).
-define(A_ALTERNATE_DOMAIN, 16#8003).
-define(A_ICMP, 16#8004).
-define(A_SOFTWARE, 16#8022).
-define(A_ALTERNATE_SERVER, 16#8023).
-define(A_FINGERPRINT, 16#8028).
-define(A_ICE_CONTROLLED, 16#8029).
-define(A_ICE_CONTROLLING, 16#802A).

%% RFC 8489 §14: limits expressed in bytes for UTF-8 values.
-define(MAX_USERNAME, 513).
-define(MAX_TEXT, 763).

%%====================================================================
%% Constructors
%%====================================================================

-spec new_txid() -> <<_:96>>.
new_txid() ->
    crypto:strong_rand_bytes(12).

-spec request(method(), [attr()]) -> #stun{}.
request(Method, Attrs) ->
    #stun{class = request, method = Method, txid = new_txid(), attrs = Attrs}.

-spec indication(method(), [attr()]) -> #stun{}.
indication(Method, Attrs) ->
    #stun{class = indication, method = Method, txid = new_txid(), attrs = Attrs}.

%% @doc Build a success response for `Request', reusing its transaction ID.
-spec success(#stun{}, [attr()]) -> #stun{}.
success(#stun{method = M, txid = T}, Attrs) ->
    #stun{class = success, method = M, txid = T, attrs = Attrs}.

-spec error_response(#stun{}, 300..699, [attr()]) -> #stun{}.
error_response(#stun{method = M, txid = T}, Code, Attrs) ->
    #stun{
        class = error,
        method = M,
        txid = T,
        attrs = [{error_code, {Code, error_reason(Code)}} | Attrs]
    }.

%% @doc Return the first attribute named `Name'.
-spec get(attr_name(), #stun{}) -> {ok, term()} | error.
get(Name, #stun{attrs = Attrs}) ->
    case lists:keyfind(Name, 1, Attrs) of
        {_, V} -> {ok, V};
        false -> error
    end.

-spec get(attr_name(), #stun{}, term()) -> term().
get(Name, Msg, Default) ->
    case get(Name, Msg) of
        {ok, V} -> V;
        error -> Default
    end.

%% @doc Long-term credential key, MD5 variant (RFC 8489 §9.2.2).
%% The password must already be SASLprep/OpaqueString processed.
-spec long_term_key(binary(), binary(), binary()) -> binary().
long_term_key(Username, Realm, Password) ->
    long_term_key(md5, Username, Realm, Password).

-spec long_term_key(md5 | sha256, binary(), binary(), binary()) -> binary().
long_term_key(md5, U, R, P) ->
    crypto:hash(md5, [U, $:, R, $:, P]);
long_term_key(sha256, U, R, P) ->
    crypto:hash(sha256, [U, $:, R, $:, P]).

%%====================================================================
%% Encoding
%%====================================================================

-spec encode(#stun{}) -> binary().
encode(Msg) ->
    encode(Msg, #{}).

%% @doc Encode a message. When `integrity' is given, MESSAGE-INTEGRITY
%% (or MESSAGE-INTEGRITY-SHA256) is appended after all attributes. When
%% `fingerprint' is true, FINGERPRINT is appended last (RFC 8489 §14.7).
-spec encode(#stun{}, encode_opts()) -> binary().
encode(#stun{class = Class, method = Method, txid = TxId, attrs = Attrs}, Opts) ->
    Type = encode_type(method_code(Method), class_code(Class)),
    Body0 = iolist_to_binary([encode_attr(A, TxId) || A <- Attrs]),
    Body1 =
        case maps:get(integrity, Opts, undefined) of
            undefined ->
                Body0;
            {Alg, Key} ->
                {AType, MacLen} = mi_params(Alg),
                Len = byte_size(Body0) + 4 + MacLen,
                Hdr = header(Type, Len, TxId),
                Mac = mac(Alg, Key, [Hdr, Body0]),
                <<Body0/binary, AType:16, MacLen:16, Mac/binary>>
        end,
    Body2 =
        case maps:get(fingerprint, Opts, false) of
            false ->
                Body1;
            true ->
                Hdr2 = header(Type, byte_size(Body1) + 8, TxId),
                Crc = fingerprint([Hdr2, Body1]),
                <<Body1/binary, ?A_FINGERPRINT:16, 4:16, Crc:32>>
        end,
    <<(header(Type, byte_size(Body2), TxId))/binary, Body2/binary>>.

header(Type, Len, TxId) ->
    <<0:2, Type:14, Len:16, ?STUN_MAGIC_COOKIE:32, TxId/binary>>.

%% RFC 8489 §5: M11..M7 C1 M6..M4 C0 M3..M0
encode_type(M, C) ->
    ((M band 16#F80) bsl 2) bor ((C band 2) bsl 7) bor ((M band 16#070) bsl 1) bor
        ((C band 1) bsl 4) bor (M band 16#00F).

decode_type(T) ->
    M = ((T band 16#3E00) bsr 2) bor ((T band 16#00E0) bsr 1) bor (T band 16#000F),
    C = ((T band 16#0100) bsr 7) bor ((T band 16#0010) bsr 4),
    {M, C}.

class_code(request) -> 0;
class_code(indication) -> 1;
class_code(success) -> 2;
class_code(error) -> 3.

class_name(0) -> request;
class_name(1) -> indication;
class_name(2) -> success;
class_name(3) -> error.

method_code(binding) -> ?STUN_BINDING;
method_code(allocate) -> ?TURN_ALLOCATE;
method_code(refresh) -> ?TURN_REFRESH;
method_code(send) -> ?TURN_SEND;
method_code(data) -> ?TURN_DATA;
method_code(create_permission) -> ?TURN_CREATE_PERMISSION;
method_code(channel_bind) -> ?TURN_CHANNEL_BIND;
method_code(N) when is_integer(N), N >= 0, N =< 16#FFF -> N.

method_name(?STUN_BINDING) -> binding;
method_name(?TURN_ALLOCATE) -> allocate;
method_name(?TURN_REFRESH) -> refresh;
method_name(?TURN_SEND) -> send;
method_name(?TURN_DATA) -> data;
method_name(?TURN_CREATE_PERMISSION) -> create_permission;
method_name(?TURN_CHANNEL_BIND) -> channel_bind;
method_name(N) -> N.

encode_attr({Name, Value}, TxId) ->
    {Type, Bin} = encode_value(Name, Value, TxId),
    Len = byte_size(Bin),
    [<<Type:16, Len:16>>, Bin, padding(Len)].

padding(Len) ->
    case Len rem 4 of
        0 -> <<>>;
        R -> <<0:((4 - R) * 8)>>
    end.

encode_value(mapped_address, Addr, _) ->
    {?A_MAPPED_ADDRESS, encode_address(Addr)};
encode_value(alternate_server, Addr, _) ->
    {?A_ALTERNATE_SERVER, encode_address(Addr)};
encode_value(xor_mapped_address, Addr, TxId) ->
    {?A_XOR_MAPPED_ADDRESS, encode_xor_address(Addr, TxId)};
encode_value(xor_peer_address, Addr, TxId) ->
    {?A_XOR_PEER_ADDRESS, encode_xor_address(Addr, TxId)};
encode_value(xor_relayed_address, Addr, TxId) ->
    {?A_XOR_RELAYED_ADDRESS, encode_xor_address(Addr, TxId)};
encode_value(username, V, _) when is_binary(V), byte_size(V) < ?MAX_USERNAME ->
    {?A_USERNAME, V};
encode_value(realm, V, _) when is_binary(V), byte_size(V) =< ?MAX_TEXT ->
    {?A_REALM, V};
encode_value(nonce, V, _) when is_binary(V), byte_size(V) =< ?MAX_TEXT ->
    {?A_NONCE, V};
encode_value(software, V, _) when is_binary(V), byte_size(V) =< ?MAX_TEXT ->
    {?A_SOFTWARE, V};
encode_value(alternate_domain, V, _) when is_binary(V) ->
    {?A_ALTERNATE_DOMAIN, V};
encode_value(userhash, V, _) when byte_size(V) =:= 32 ->
    {?A_USERHASH, V};
encode_value(error_code, {Code, Reason}, _) when Code >= 300, Code =< 699 ->
    {?A_ERROR_CODE, <<0:21, (Code div 100):3, (Code rem 100):8, Reason/binary>>};
encode_value(unknown_attributes, Types, _) ->
    {?A_UNKNOWN_ATTRIBUTES, <<<<T:16>> || T <- Types>>};
encode_value(priority, P, _) when P >= 1, P =< 16#FFFFFFFF ->
    {?A_PRIORITY, <<P:32>>};
encode_value(use_candidate, true, _) ->
    {?A_USE_CANDIDATE, <<>>};
encode_value(ice_controlled, T, _) ->
    {?A_ICE_CONTROLLED, <<T:64>>};
encode_value(ice_controlling, T, _) ->
    {?A_ICE_CONTROLLING, <<T:64>>};
encode_value(channel_number, N, _) when N >= 16#4000, N =< 16#4FFF ->
    {?A_CHANNEL_NUMBER, <<N:16, 0:16>>};
encode_value(lifetime, S, _) ->
    {?A_LIFETIME, <<S:32>>};
encode_value(data, D, _) when is_binary(D) ->
    {?A_DATA, D};
encode_value(requested_transport, udp, _) ->
    {?A_REQUESTED_TRANSPORT, <<17, 0:24>>};
encode_value(requested_transport, P, _) when is_integer(P) ->
    {?A_REQUESTED_TRANSPORT, <<P, 0:24>>};
encode_value(requested_address_family, F, _) ->
    {?A_REQUESTED_ADDRESS_FAMILY, <<(family_code(F)), 0:24>>};
encode_value(additional_address_family, F, _) ->
    {?A_ADDITIONAL_ADDRESS_FAMILY, <<(family_code(F)), 0:24>>};
encode_value(even_port, R, _) when is_boolean(R) ->
    {?A_EVEN_PORT, <<(bool_bit(R)):1, 0:7>>};
encode_value(dont_fragment, true, _) ->
    {?A_DONT_FRAGMENT, <<>>};
encode_value(reservation_token, T, _) when byte_size(T) =:= 8 ->
    {?A_RESERVATION_TOKEN, T};
encode_value(password_algorithm, {Alg, Params}, _) ->
    {?A_PASSWORD_ALGORITHM, encode_pw_alg(Alg, Params)};
encode_value(password_algorithms, Algs, _) ->
    {?A_PASSWORD_ALGORITHMS, iolist_to_binary([encode_pw_alg(A, P) || {A, P} <- Algs])};
encode_value(Type, Bin, _) when is_integer(Type), is_binary(Bin) ->
    {Type, Bin}.

encode_pw_alg(Alg, Params) ->
    Len = byte_size(Params),
    <<(pw_alg_code(Alg)):16, Len:16, Params/binary, (padding(Len))/binary>>.

pw_alg_code(md5) -> 1;
pw_alg_code(sha256) -> 2;
pw_alg_code(N) when is_integer(N) -> N.

pw_alg_name(1) -> md5;
pw_alg_name(2) -> sha256;
pw_alg_name(N) -> N.

bool_bit(true) -> 1;
bool_bit(false) -> 0.

family_code(ipv4) -> 1;
family_code(ipv6) -> 2.

encode_address({{A, B, C, D}, Port}) ->
    <<0, 1, Port:16, A, B, C, D>>;
encode_address({{A, B, C, D, E, F, G, H}, Port}) ->
    <<0, 2, Port:16, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

encode_xor_address({IP, Port}, TxId) ->
    <<0, Fam, P:16, Addr/binary>> = encode_address({IP, Port}),
    <<0, Fam, (P bxor (?STUN_MAGIC_COOKIE bsr 16)):16, (xor_addr(Addr, TxId))/binary>>.

xor_addr(<<A:32>>, _TxId) ->
    <<(A bxor ?STUN_MAGIC_COOKIE):32>>;
xor_addr(<<A:128>>, TxId) ->
    <<K:128>> = <<?STUN_MAGIC_COOKIE:32, TxId/binary>>,
    <<(A bxor K):128>>.

%%====================================================================
%% Decoding
%%====================================================================

%% @doc Cheap test used by the demultiplexer (RFC 7983 §7): first byte
%% in 0..3, a valid length and the magic cookie.
-spec is_stun(binary()) -> boolean().
is_stun(<<0:2, _:14, Len:16, ?STUN_MAGIC_COOKIE:32, _:96, Rest/binary>>) ->
    Len band 3 =:= 0 andalso byte_size(Rest) =:= Len;
is_stun(_) ->
    false.

%% @doc Decode a STUN message. FINGERPRINT, when present, is verified.
%% MESSAGE-INTEGRITY is not verified here; call `check_integrity/2' with
%% the original binary once the key is known.
-spec decode(binary()) -> {ok, #stun{}} | {error, term()}.
decode(<<0:2, Type:14, Len:16, ?STUN_MAGIC_COOKIE:32, TxId:12/binary, Body/binary>> = Bin) when
    Len band 3 =:= 0, byte_size(Body) =:= Len
->
    {M, C} = decode_type(Type),
    try decode_attrs(Body, TxId, Bin, 20, false, [], []) of
        {Attrs, Unknown} ->
            {ok, #stun{
                class = class_name(C),
                method = method_name(M),
                txid = TxId,
                attrs = Attrs,
                unknown = Unknown
            }}
    catch
        throw:Reason -> {error, Reason}
    end;
decode(<<0:2, _:14, Len:16, ?STUN_MAGIC_COOKIE:32, _:12/binary, Body/binary>>) when
    Len band 3 =/= 0; byte_size(Body) =/= Len
->
    {error, bad_length};
decode(<<0:2, _:30, Cookie:32, _/binary>>) when Cookie =/= ?STUN_MAGIC_COOKIE ->
    {error, bad_magic_cookie};
decode(_) ->
    {error, not_stun}.

%% AfterMI: once MESSAGE-INTEGRITY was seen, only
%% MESSAGE-INTEGRITY-SHA256 and FINGERPRINT are processed (§14.5, §14.6).
decode_attrs(<<>>, _TxId, _Bin, _Off, _AfterMI, Acc, Unk) ->
    {lists:reverse(Acc), lists:reverse(Unk)};
decode_attrs(<<?A_FINGERPRINT:16, 4:16, Crc:32>>, _TxId, Bin, Off, _AfterMI, Acc, Unk) ->
    <<Head:Off/binary, _/binary>> = Bin,
    <<H0:2/binary, _:16, HRest/binary>> = Head,
    Expected = fingerprint([H0, <<(Off - 20 + 8):16>>, HRest]),
    case Expected =:= Crc of
        true -> {lists:reverse([{fingerprint, Crc} | Acc]), lists:reverse(Unk)};
        false -> throw(bad_fingerprint)
    end;
decode_attrs(<<?A_FINGERPRINT:16, _/binary>>, _, _, _, _, _, _) ->
    %% FINGERPRINT must be the last attribute and 4 bytes long.
    throw(bad_fingerprint_position);
decode_attrs(<<Type:16, Len:16, Rest/binary>>, TxId, Bin, Off, AfterMI, Acc, Unk) ->
    Padded = (Len + 3) band (bnot 3),
    case Rest of
        <<Value:Len/binary, _:(Padded - Len)/binary, Tail/binary>> ->
            NextOff = Off + 4 + Padded,
            if
                AfterMI andalso Type =/= ?A_MESSAGE_INTEGRITY_SHA256 ->
                    decode_attrs(Tail, TxId, Bin, NextOff, AfterMI, Acc, Unk);
                true ->
                    IsMI =
                        Type =:= ?A_MESSAGE_INTEGRITY orelse
                            Type =:= ?A_MESSAGE_INTEGRITY_SHA256,
                    case decode_value(Type, Value, TxId) of
                        unknown when Type < 16#8000 ->
                            decode_attrs(Tail, TxId, Bin, NextOff, AfterMI, Acc, [Type | Unk]);
                        unknown ->
                            decode_attrs(Tail, TxId, Bin, NextOff, AfterMI, Acc, Unk);
                        Attr ->
                            decode_attrs(
                                Tail, TxId, Bin, NextOff, AfterMI orelse IsMI, [Attr | Acc], Unk
                            )
                    end
            end;
        _ ->
            throw(truncated_attribute)
    end;
decode_attrs(_, _, _, _, _, _, _) ->
    throw(truncated_attribute).

decode_value(?A_MAPPED_ADDRESS, V, _) ->
    {mapped_address, decode_address(V)};
decode_value(?A_ALTERNATE_SERVER, V, _) ->
    {alternate_server, decode_address(V)};
decode_value(?A_XOR_MAPPED_ADDRESS, V, TxId) ->
    {xor_mapped_address, decode_xor_address(V, TxId)};
decode_value(?A_XOR_PEER_ADDRESS, V, TxId) ->
    {xor_peer_address, decode_xor_address(V, TxId)};
decode_value(?A_XOR_RELAYED_ADDRESS, V, TxId) ->
    {xor_relayed_address, decode_xor_address(V, TxId)};
decode_value(?A_USERNAME, V, _) ->
    {username, limited(V, ?MAX_USERNAME - 1)};
decode_value(?A_REALM, V, _) ->
    {realm, limited(V, ?MAX_TEXT)};
decode_value(?A_NONCE, V, _) ->
    {nonce, limited(V, ?MAX_TEXT)};
decode_value(?A_SOFTWARE, V, _) ->
    {software, limited(V, ?MAX_TEXT)};
decode_value(?A_ALTERNATE_DOMAIN, V, _) ->
    {alternate_domain, V};
decode_value(?A_USERHASH, <<_:32/binary>> = V, _) ->
    {userhash, V};
decode_value(?A_ERROR_CODE, <<0:21, Class:3, Num:8, Reason/binary>>, _) when
    Class >= 3, Class =< 6, Num =< 99
->
    {error_code, {Class * 100 + Num, limited(Reason, ?MAX_TEXT)}};
decode_value(?A_UNKNOWN_ATTRIBUTES, V, _) when byte_size(V) rem 2 =:= 0 ->
    {unknown_attributes, [T || <<T:16>> <= V]};
decode_value(?A_MESSAGE_INTEGRITY, <<_:20/binary>> = V, _) ->
    {message_integrity, V};
decode_value(?A_MESSAGE_INTEGRITY_SHA256, V, _) when
    byte_size(V) >= 16, byte_size(V) =< 32, byte_size(V) rem 4 =:= 0
->
    {message_integrity_sha256, V};
decode_value(?A_PRIORITY, <<P:32>>, _) ->
    {priority, P};
decode_value(?A_USE_CANDIDATE, <<>>, _) ->
    {use_candidate, true};
decode_value(?A_ICE_CONTROLLED, <<T:64>>, _) ->
    {ice_controlled, T};
decode_value(?A_ICE_CONTROLLING, <<T:64>>, _) ->
    {ice_controlling, T};
decode_value(?A_CHANNEL_NUMBER, <<N:16, _:16>>, _) ->
    {channel_number, N};
decode_value(?A_LIFETIME, <<S:32>>, _) ->
    {lifetime, S};
decode_value(?A_DATA, V, _) ->
    {data, V};
decode_value(?A_REQUESTED_TRANSPORT, <<P, _:24>>, _) ->
    {requested_transport, P};
decode_value(?A_REQUESTED_ADDRESS_FAMILY, <<F, _:24>>, _) ->
    {requested_address_family, family_name(F)};
decode_value(?A_ADDITIONAL_ADDRESS_FAMILY, <<F, _:24>>, _) ->
    {additional_address_family, family_name(F)};
decode_value(?A_EVEN_PORT, <<R:1, _:7>>, _) ->
    {even_port, R =:= 1};
decode_value(?A_DONT_FRAGMENT, <<>>, _) ->
    {dont_fragment, true};
decode_value(?A_RESERVATION_TOKEN, <<_:8/binary>> = T, _) ->
    {reservation_token, T};
decode_value(?A_ADDRESS_ERROR_CODE, <<F, 0:13, Class:3, Num:8, Reason/binary>>, _) ->
    {address_error_code, {family_name(F), Class * 100 + Num, Reason}};
decode_value(?A_ICMP, <<0:16, Type, Code, Data:32>>, _) ->
    {icmp, {Type, Code, Data}};
decode_value(?A_PASSWORD_ALGORITHM, V, _) ->
    case decode_pw_algs(V, []) of
        [Alg] -> {password_algorithm, Alg};
        _ -> throw({bad_attribute, password_algorithm})
    end;
decode_value(?A_PASSWORD_ALGORITHMS, V, _) ->
    {password_algorithms, decode_pw_algs(V, [])};
decode_value(Type, _V, _) when
    Type =:= ?A_MAPPED_ADDRESS;
    Type =:= ?A_USERHASH;
    Type =:= ?A_ERROR_CODE;
    Type =:= ?A_UNKNOWN_ATTRIBUTES;
    Type =:= ?A_MESSAGE_INTEGRITY;
    Type =:= ?A_MESSAGE_INTEGRITY_SHA256;
    Type =:= ?A_PRIORITY;
    Type =:= ?A_USE_CANDIDATE;
    Type =:= ?A_ICE_CONTROLLED;
    Type =:= ?A_ICE_CONTROLLING;
    Type =:= ?A_CHANNEL_NUMBER;
    Type =:= ?A_LIFETIME;
    Type =:= ?A_REQUESTED_TRANSPORT;
    Type =:= ?A_REQUESTED_ADDRESS_FAMILY;
    Type =:= ?A_ADDITIONAL_ADDRESS_FAMILY;
    Type =:= ?A_EVEN_PORT;
    Type =:= ?A_DONT_FRAGMENT;
    Type =:= ?A_RESERVATION_TOKEN;
    Type =:= ?A_ADDRESS_ERROR_CODE;
    Type =:= ?A_ICMP
->
    throw({bad_attribute, Type});
decode_value(_Type, _V, _) ->
    unknown.

decode_pw_algs(<<>>, Acc) ->
    lists:reverse(Acc);
decode_pw_algs(<<Alg:16, Len:16, Rest/binary>>, Acc) ->
    Padded = (Len + 3) band (bnot 3),
    case Rest of
        <<P:Len/binary, _:(Padded - Len)/binary, Tail/binary>> ->
            decode_pw_algs(Tail, [{pw_alg_name(Alg), P} | Acc]);
        _ ->
            throw({bad_attribute, password_algorithms})
    end;
decode_pw_algs(_, _) ->
    throw({bad_attribute, password_algorithms}).

limited(V, Max) when byte_size(V) =< Max -> V;
limited(_, _) -> throw(attribute_too_long).

family_name(1) -> ipv4;
family_name(2) -> ipv6;
family_name(_) -> throw(bad_address_family).

decode_address(<<_, 1, Port:16, A, B, C, D>>) ->
    {{A, B, C, D}, Port};
decode_address(<<_, 2, Port:16, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {{A, B, C, D, E, F, G, H}, Port};
decode_address(_) ->
    throw(bad_address).

decode_xor_address(<<R, Fam, XP:16, XAddr/binary>>, TxId) when
    (Fam =:= 1 andalso byte_size(XAddr) =:= 4) orelse
        (Fam =:= 2 andalso byte_size(XAddr) =:= 16)
->
    Port = XP bxor (?STUN_MAGIC_COOKIE bsr 16),
    decode_address(<<R, Fam, Port:16, (xor_addr(XAddr, TxId))/binary>>);
decode_xor_address(_, _) ->
    throw(bad_address).

%%====================================================================
%% Integrity
%%====================================================================

%% @doc True when the message carries MESSAGE-INTEGRITY or
%% MESSAGE-INTEGRITY-SHA256.
-spec has_integrity(#stun{}) -> boolean().
has_integrity(#stun{attrs = Attrs}) ->
    lists:keymember(message_integrity, 1, Attrs) orelse
        lists:keymember(message_integrity_sha256, 1, Attrs).

%% @doc Verify message integrity of a raw, already decoded STUN message.
%% MESSAGE-INTEGRITY-SHA256 is preferred when both are present
%% (RFC 8489 §9.1.4). The comparison is constant time.
-spec check_integrity(binary(), binary()) ->
    ok | {error, no_integrity | bad_integrity}.
check_integrity(<<0:2, Type:14, _Len:16, _:32, TxId:12/binary, Body/binary>>, Key) ->
    case find_mi(Body, 0, none) of
        none ->
            {error, no_integrity};
        {Alg, Off, Mac} ->
            <<Covered:Off/binary, _/binary>> = Body,
            AttrLen = byte_size(Mac) + 4,
            Hdr = header(Type, Off + AttrLen, TxId),
            Expected = mac(Alg, Key, [Hdr, Covered]),
            case byte_size(Expected) >= byte_size(Mac) of
                true ->
                    <<Trunc:(byte_size(Mac))/binary, _/binary>> = Expected,
                    case crypto:hash_equals(Trunc, Mac) of
                        true -> ok;
                        false -> {error, bad_integrity}
                    end;
                false ->
                    {error, bad_integrity}
            end
    end;
check_integrity(_, _) ->
    {error, no_integrity}.

%% Locate the integrity attribute to verify, preferring SHA256.
find_mi(<<?A_MESSAGE_INTEGRITY:16, 20:16, Mac:20/binary, Rest/binary>>, Off, none) ->
    find_mi(Rest, Off + 24, {sha1, Off, Mac});
find_mi(<<?A_MESSAGE_INTEGRITY_SHA256:16, Len:16, Rest/binary>>, Off, _Found) when
    Len >= 16, Len =< 32, Len rem 4 =:= 0, byte_size(Rest) >= Len
->
    <<Mac:Len/binary, _/binary>> = Rest,
    {sha256, Off, Mac};
find_mi(<<_Type:16, Len:16, Rest/binary>>, Off, Found) ->
    Padded = (Len + 3) band (bnot 3),
    case Rest of
        <<_:Padded/binary, Tail/binary>> -> find_mi(Tail, Off + 4 + Padded, Found);
        _ -> Found
    end;
find_mi(_, _, Found) ->
    Found.

mi_params(sha1) -> {?A_MESSAGE_INTEGRITY, 20};
mi_params(sha256) -> {?A_MESSAGE_INTEGRITY_SHA256, 32}.

mac(sha1, Key, Data) -> crypto:mac(hmac, sha, Key, Data);
mac(sha256, Key, Data) -> crypto:mac(hmac, sha256, Key, Data).

fingerprint(Data) ->
    erlang:crc32(Data) bxor ?STUN_FINGERPRINT_XOR.

%%====================================================================
%% Error reasons (RFC 8489 §14.8, RFC 8445 §16.2, RFC 8656 §19)
%%====================================================================

-spec error_reason(300..699) -> binary().
error_reason(300) -> <<"Try Alternate">>;
error_reason(400) -> <<"Bad Request">>;
error_reason(401) -> <<"Unauthenticated">>;
error_reason(403) -> <<"Forbidden">>;
error_reason(420) -> <<"Unknown Attribute">>;
error_reason(437) -> <<"Allocation Mismatch">>;
error_reason(438) -> <<"Stale Nonce">>;
error_reason(440) -> <<"Address Family not Supported">>;
error_reason(441) -> <<"Wrong Credentials">>;
error_reason(442) -> <<"Unsupported Transport Protocol">>;
error_reason(443) -> <<"Peer Address Family Mismatch">>;
error_reason(486) -> <<"Allocation Quota Reached">>;
error_reason(487) -> <<"Role Conflict">>;
error_reason(500) -> <<"Server Error">>;
error_reason(508) -> <<"Insufficient Capacity">>;
error_reason(_) -> <<>>.
