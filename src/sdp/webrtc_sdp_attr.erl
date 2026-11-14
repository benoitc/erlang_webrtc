%% @doc SDP attribute codec: maps `a=' lines to typed terms and back.
%%
%% Known attributes become `{Key, Value}' with an atom key (see
%% `webrtc_sdp:attribute()'); property attributes become `{Key, true}' and
%% the four direction attributes become `{direction, Dir}'. Anything else
%% is kept as `{Name, Value}' with a binary name and the raw value
%% (`undefined' when the line has no colon), so unknown attributes round
%% trip unchanged and in order.
%%
%% Transport, ICE, DTLS and SCTP attributes are handled here, RTP ones in
%% `webrtc_sdp_rtp'.
-module(webrtc_sdp_attr).

-include("webrtc_sdp.hrl").

-export([parse/2, encode/1, name/1]).

-export_type([fingerprint/0, setup/0, rtcp/0, sctpmap/0, identity/0]).

-type fingerprint() :: #{hash := hash(), value := binary()}.
-type hash() :: sha | sha224 | sha256 | sha384 | sha512 | md5 | md2 | binary().
-type setup() :: actpass | active | passive | holdconn.
-type rtcp() :: #{port := inet:port_number(), connection := #sdp_connection{} | undefined}.
-type sctpmap() :: #{port := inet:port_number(), protocol := binary(), streams := pos_integer() | undefined}.
-type identity() :: #{assertion := binary(), extensions := [binary()]}.

%% Property attributes (no value).
flag(<<"extmap-allow-mixed">>) -> extmap_allow_mixed;
flag(<<"bundle-only">>) -> bundle_only;
flag(<<"ice-lite">>) -> ice_lite;
flag(<<"ice-mismatch">>) -> ice_mismatch;
flag(<<"end-of-candidates">>) -> end_of_candidates;
flag(<<"rtcp-mux">>) -> rtcp_mux;
flag(<<"rtcp-mux-only">>) -> rtcp_mux_only;
flag(<<"rtcp-rsize">>) -> rtcp_rsize;
flag(_) -> undefined.

direction(<<"sendrecv">>) -> sendrecv;
direction(<<"sendonly">>) -> sendonly;
direction(<<"recvonly">>) -> recvonly;
direction(<<"inactive">>) -> inactive;
direction(_) -> undefined.

%% Value attributes: {Key, Module}.
value(<<"rtpmap">>) -> {rtpmap, rtp};
value(<<"fmtp">>) -> {fmtp, rtp};
value(<<"rtcp-fb">>) -> {rtcp_fb, rtp};
value(<<"extmap">>) -> {extmap, rtp};
value(<<"msid">>) -> {msid, rtp};
value(<<"msid-semantic">>) -> {msid_semantic, rtp};
value(<<"ssrc">>) -> {ssrc, rtp};
value(<<"ssrc-group">>) -> {ssrc_group, rtp};
value(<<"rid">>) -> {rid, rtp};
value(<<"simulcast">>) -> {simulcast, rtp};
value(<<"mid">>) -> {mid, local};
value(<<"group">>) -> {group, local};
value(<<"ice-ufrag">>) -> {ice_ufrag, local};
value(<<"ice-pwd">>) -> {ice_pwd, local};
value(<<"ice-options">>) -> {ice_options, local};
value(<<"candidate">>) -> {candidate, local};
value(<<"fingerprint">>) -> {fingerprint, local};
value(<<"setup">>) -> {setup, local};
value(<<"tls-id">>) -> {tls_id, local};
value(<<"connection">>) -> {connection, local};
value(<<"sctp-port">>) -> {sctp_port, local};
value(<<"max-message-size">>) -> {max_message_size, local};
value(<<"sctpmap">>) -> {sctpmap, local};
value(<<"rtcp">>) -> {rtcp, local};
value(<<"ptime">>) -> {ptime, local};
value(<<"maxptime">>) -> {maxptime, local};
value(<<"framerate">>) -> {framerate, local};
value(<<"identity">>) -> {identity, local};
value(<<"label">>) -> {label, local};
value(<<"content">>) -> {content, local};
value(_) -> undefined.

%% @doc SDP name of a typed attribute key.
-spec name(atom()) -> binary().
name(direction) -> erlang:error({invalid_sdp, {attribute, direction}});
name(Key) -> binary:replace(atom_to_binary(Key), <<"_">>, <<"-">>, [global]).

%% @doc Parse one attribute. `Value' is the text after the first colon,
%% or `undefined' when there is no colon.
-spec parse(binary(), binary() | undefined) -> {ok, webrtc_sdp:attribute()} | error.
parse(Name, Value) ->
    case {flag(Name), direction(Name), value(Name)} of
        {Key, _, _} when Key =/= undefined ->
            case Value of
                undefined -> {ok, {Key, true}};
                _ -> error
            end;
        {_, Dir, _} when Dir =/= undefined ->
            case Value of
                undefined -> {ok, {direction, Dir}};
                _ -> error
            end;
        {_, _, {Key, Mod}} when is_binary(Value) ->
            case parse_value(Mod, Key, Value) of
                {ok, V} -> {ok, {Key, V}};
                _ -> error
            end;
        {_, _, {_, _}} ->
            error;
        {_, _, undefined} ->
            case webrtc_sdp_lex:is_token(Name) of
                true -> {ok, {Name, Value}};
                false -> error
            end
    end.

parse_value(rtp, Key, V) -> webrtc_sdp_rtp:parse(Key, V);
parse_value(local, Key, V) -> parse_local(Key, V).

parse_local(mid, V) ->
    token(V);
parse_local(group, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [Sem | Mids] = All} ->
            case lists:all(fun webrtc_sdp_lex:is_token/1, All) of
                true -> {ok, #{semantics => Sem, mids => Mids}};
                false -> error
            end;
        error ->
            error
    end;
parse_local(ice_ufrag, V) ->
    ice_chars(V, 4, 256);
parse_local(ice_pwd, V) ->
    ice_chars(V, 22, 256);
parse_local(ice_options, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, Tags} ->
            case lists:all(fun webrtc_sdp_lex:is_ice_chars/1, Tags) of
                true -> {ok, Tags};
                false -> error
            end;
        error ->
            error
    end;
parse_local(candidate, V) ->
    case webrtc_sdp_candidate:parse(<<"candidate:", V/binary>>) of
        {ok, C} -> {ok, C};
        {error, _} -> error
    end;
parse_local(fingerprint, V) ->
    case binary:split(V, <<" ">>) of
        [H, Hex] -> fingerprint(hash(webrtc_sdp_lex:lower(H)), Hex);
        _ -> error
    end;
parse_local(setup, <<"actpass">>) ->
    {ok, actpass};
parse_local(setup, <<"active">>) ->
    {ok, active};
parse_local(setup, <<"passive">>) ->
    {ok, passive};
parse_local(setup, <<"holdconn">>) ->
    {ok, holdconn};
parse_local(tls_id, V) ->
    case is_binary(V) andalso byte_size(V) >= 20 andalso byte_size(V) =< 255 andalso is_tls_id(V) of
        true -> {ok, V};
        false -> error
    end;
parse_local(connection, <<"new">>) ->
    {ok, new};
parse_local(connection, <<"existing">>) ->
    {ok, existing};
parse_local(sctp_port, V) ->
    webrtc_sdp_lex:parse_int(V, 0, 65535);
parse_local(max_message_size, V) ->
    webrtc_sdp_lex:parse_int(V);
parse_local(sctpmap, V) ->
    maybe
        {ok, [P, Proto | Streams]} ?= webrtc_sdp_lex:split_sp(V),
        true ?= length(Streams) =< 1,
        {ok, Port} ?= webrtc_sdp_lex:parse_int(P, 0, 65535),
        {ok, _} ?= token(Proto),
        {ok, S} ?=
            case Streams of
                [] -> {ok, undefined};
                [SB] -> webrtc_sdp_lex:parse_int(SB, 1, 65535)
            end,
        {ok, #{port => Port, protocol => Proto, streams => S}}
    else
        _ -> error
    end;
parse_local(rtcp, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [P | Addr]} when Addr =:= []; length(Addr) =:= 3 ->
            maybe
                {ok, Port} ?= webrtc_sdp_lex:parse_int(P, 0, 65535),
                {ok, Conn} ?= rtcp_addr(Addr),
                {ok, #{port => Port, connection => Conn}}
            else
                _ -> error
            end;
        _ ->
            error
    end;
parse_local(Key, V) when Key =:= ptime; Key =:= maxptime; Key =:= framerate ->
    webrtc_sdp_lex:parse_number(V);
parse_local(identity, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [A | Exts]} ->
            case is_base64(A) andalso lists:all(fun webrtc_sdp_lex:is_non_ws/1, Exts) of
                true -> {ok, #{assertion => A, extensions => Exts}};
                false -> error
            end;
        error ->
            error
    end;
parse_local(label, V) ->
    token(V);
parse_local(content, V) ->
    Tags = binary:split(V, <<",">>, [global]),
    case lists:all(fun webrtc_sdp_lex:is_token/1, Tags) of
        true -> {ok, Tags};
        false -> error
    end;
parse_local(_, _) ->
    error.

token(V) ->
    case is_binary(V) andalso webrtc_sdp_lex:is_token(V) of
        true -> {ok, V};
        false -> error
    end.

ice_chars(V, Min, Max) ->
    case is_binary(V) andalso byte_size(V) >= Min andalso byte_size(V) =< Max andalso webrtc_sdp_lex:is_ice_chars(V) of
        true -> {ok, V};
        false -> error
    end.

is_tls_id(<<C, R/binary>>) when
    (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) orelse
        (C >= $0 andalso C =< $9) orelse C =:= $+ orelse C =:= $/ orelse
        C =:= $- orelse C =:= $_
->
    is_tls_id(R);
is_tls_id(<<>>) ->
    true;
is_tls_id(_) ->
    false.

is_base64(B) ->
    byte_size(B) rem 4 =:= 0 andalso
        try base64:decode(B) of
            _ -> true
        catch
            error:_ -> false
        end.

rtcp_addr([]) ->
    {ok, undefined};
rtcp_addr([Net, Type, Addr]) ->
    case webrtc_sdp_lex:is_token(Net) andalso webrtc_sdp_lex:is_token(Type) andalso
        webrtc_sdp_lex:is_non_ws(Addr)
    of
        true -> {ok, #sdp_connection{nettype = Net, addrtype = Type, address = Addr}};
        false -> error
    end.

%% RFC 8122 §5 hash function names; lowercase is canonical.
hash(<<"sha-1">>) -> sha;
hash(<<"sha-224">>) -> sha224;
hash(<<"sha-256">>) -> sha256;
hash(<<"sha-384">>) -> sha384;
hash(<<"sha-512">>) -> sha512;
hash(<<"md5">>) -> md5;
hash(<<"md2">>) -> md2;
hash(Other) -> Other.

hash_name(sha) -> <<"sha-1">>;
hash_name(sha224) -> <<"sha-224">>;
hash_name(sha256) -> <<"sha-256">>;
hash_name(sha384) -> <<"sha-384">>;
hash_name(sha512) -> <<"sha-512">>;
hash_name(md5) -> <<"md5">>;
hash_name(md2) -> <<"md2">>;
hash_name(B) when is_binary(B) -> B.

hash_size(sha) -> 20;
hash_size(sha224) -> 28;
hash_size(sha256) -> 32;
hash_size(sha384) -> 48;
hash_size(sha512) -> 64;
hash_size(md5) -> 16;
hash_size(md2) -> 16;
hash_size(_) -> any.

%% fingerprint = 2UHEX *(":" 2UHEX). Lowercase hex digits are accepted on
%% input; the digest length must match a known hash function.
fingerprint(Hash, Hex) when is_atom(Hash); is_binary(Hash) ->
    IsToken = is_atom(Hash) orelse webrtc_sdp_lex:is_token(Hash),
    case IsToken andalso hex_bytes(Hex, <<>>) of
        {ok, Bytes} ->
            case hash_size(Hash) of
                any -> {ok, #{hash => Hash, value => Bytes}};
                N when N =:= byte_size(Bytes) -> {ok, #{hash => Hash, value => Bytes}};
                _ -> error
            end;
        _ ->
            error
    end.

hex_bytes(<<A, B>>, Acc) ->
    hex_byte(A, B, Acc, fun(Bytes) -> {ok, Bytes} end);
hex_bytes(<<A, B, $:, Rest/binary>>, Acc) when Rest =/= <<>> ->
    hex_byte(A, B, Acc, fun(Bytes) -> hex_bytes(Rest, Bytes) end);
hex_bytes(_, _) ->
    error.

hex_byte(A, B, Acc, K) ->
    case {nibble(A), nibble(B)} of
        {H, L} when is_integer(H), is_integer(L) -> K(<<Acc/binary, (H * 16 + L)>>);
        _ -> error
    end.

nibble(C) when C >= $0, C =< $9 -> C - $0;
nibble(C) when C >= $A, C =< $F -> C - $A + 10;
nibble(C) when C >= $a, C =< $f -> C - $a + 10;
nibble(_) -> error.

%%====================================================================
%% Encoding
%%====================================================================

%% @doc Encode one attribute as the text after `a='.
-spec encode(webrtc_sdp:attribute()) -> iodata().
encode({direction, D}) when D =:= sendrecv; D =:= sendonly; D =:= recvonly; D =:= inactive ->
    atom_to_binary(D);
encode({Name, undefined}) when is_binary(Name) ->
    attr_name(Name);
encode({Name, Value}) when is_binary(Name) ->
    webrtc_sdp_lex:check_text(Name, Value),
    [attr_name(Name), $:, Value];
encode({Key, true} = A) when is_atom(Key) ->
    case flag(name(Key)) of
        Key -> name(Key);
        _ -> bad(A)
    end;
encode({Key, V} = A) when is_atom(Key) ->
    case value(name(Key)) of
        {Key, rtp} -> [name(Key), $:, webrtc_sdp_rtp:encode(Key, V)];
        {Key, local} -> [name(Key), $:, enc_local(Key, V)];
        _ -> bad(A)
    end;
encode(A) ->
    bad(A).

attr_name(Name) ->
    case webrtc_sdp_lex:is_token(Name) of
        true -> Name;
        false -> bad({Name, name})
    end.

enc_local(mid, V) ->
    tok(V);
enc_local(group, #{semantics := S, mids := Mids}) ->
    lists:join($\s, [tok(T) || T <- [S | Mids]]);
enc_local(ice_ufrag, V) ->
    ok_or_bad(ice_chars(V, 4, 256), V);
enc_local(ice_pwd, V) ->
    ok_or_bad(ice_chars(V, 22, 256), V);
enc_local(ice_options, [_ | _] = Tags) ->
    lists:join($\s, [ok_or_bad(ice_chars(T, 1, 256), T) || T <- Tags]);
enc_local(candidate, #sdp_candidate{} = C) ->
    webrtc_sdp_candidate:encode(C);
enc_local(fingerprint, #{hash := H, value := Bytes} = F) ->
    case is_binary(Bytes) andalso fingerprint(H, iolist_to_binary(hex(Bytes))) of
        {ok, _} -> [hash_name(H), $\s, hex(Bytes)];
        _ -> bad({fingerprint, F})
    end;
enc_local(setup, R) when R =:= actpass; R =:= active; R =:= passive; R =:= holdconn ->
    atom_to_binary(R);
enc_local(tls_id, V) ->
    ok_or_bad(parse_local(tls_id, V), V);
enc_local(connection, C) when C =:= new; C =:= existing ->
    atom_to_binary(C);
enc_local(sctp_port, P) when is_integer(P), P >= 0, P =< 65535 ->
    integer_to_binary(P);
enc_local(max_message_size, N) ->
    webrtc_sdp_lex:int(N);
enc_local(sctpmap, #{port := P, protocol := Proto} = M) when is_integer(P), P >= 0, P =< 65535 ->
    S =
        case maps:get(streams, M, undefined) of
            undefined -> [];
            N when is_integer(N), N >= 1, N =< 65535 -> [$\s, integer_to_binary(N)]
        end,
    [integer_to_binary(P), $\s, tok(Proto) | S];
enc_local(rtcp, #{port := P} = M) when is_integer(P), P >= 0, P =< 65535 ->
    case maps:get(connection, M, undefined) of
        undefined ->
            integer_to_binary(P);
        #sdp_connection{nettype = N, addrtype = T, address = A} ->
            [integer_to_binary(P), $\s, tok(N), $\s, tok(T), $\s, nonws(A)]
    end;
enc_local(Key, N) when Key =:= ptime; Key =:= maxptime; Key =:= framerate ->
    webrtc_sdp_lex:encode_number(N);
enc_local(identity, #{assertion := A, extensions := Exts} = I) ->
    is_binary(A) andalso is_base64(A) orelse bad({identity, I}),
    lists:join($\s, [A | [nonws(E) || E <- Exts]]);
enc_local(label, V) ->
    tok(V);
enc_local(content, [_ | _] = Tags) ->
    lists:join($,, [tok(T) || T <- Tags]);
enc_local(Key, V) ->
    bad({Key, V}).

hex(Bytes) ->
    lists:join($:, [binary:encode_hex(<<B>>) || <<B>> <= Bytes]).

tok(V) -> ok_or_bad(token(V), V).

nonws(V) ->
    is_binary(V) andalso webrtc_sdp_lex:is_non_ws(V) orelse bad(V),
    V.

ok_or_bad({ok, V}, _) -> V;
ok_or_bad(_, V) -> bad(V).

-spec bad(term()) -> no_return().
bad(V) -> erlang:error({invalid_sdp, {attribute, V}}).
