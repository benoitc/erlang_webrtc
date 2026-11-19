%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Lexical helpers shared by the SDP codec modules.
%%
%% Character classes follow the ABNF of RFC 8866 §9 (token, byte-string,
%% non-ws-string), RFC 8839 §5.1 (ice-char) and RFC 8851 (rid-id).
%% Every parser here returns `{ok, Value}' or `error' and never raises on
%% malformed input.
-module(webrtc_sdp_lex).

-export([
    is_token/1,
    is_text/1,
    is_non_ws/1,
    is_ice_chars/1,
    is_rid_id/1,
    is_digits/1,
    parse_int/1,
    parse_int/3,
    parse_number/1,
    encode_number/1,
    split_sp/1,
    split_first/2,
    trim_sp/1,
    lower/1,
    parse_address/1,
    encode_address/1,
    check_text/2,
    int/1
]).

-export_type([address/0]).

%% An IPv4 or IPv6 address, or a host name (FQDN, including mDNS
%% `.local' names) kept as a binary.
-type address() :: inet:ip_address() | binary().

%% Integers are bounded to keep bignum conversion cheap on hostile input.
-define(MAX_DIGITS, 20).

%% RFC 8866 token-char.
-define(IS_TOKEN_CHAR(C),
    ((C >= $a andalso C =< $z) orelse
        (C >= $A andalso C =< $Z) orelse
        (C >= $0 andalso C =< $9) orelse
        C =:= $! orelse C =:= $# orelse C =:= $$ orelse C =:= $% orelse
        C =:= $& orelse C =:= $' orelse C =:= $* orelse C =:= $+ orelse
        C =:= $- orelse C =:= $. orelse C =:= $^ orelse C =:= $_ orelse
        C =:= $` orelse C =:= ${ orelse C =:= $| orelse C =:= $} orelse
        C =:= $~)
).

-define(IS_ALNUM(C),
    ((C >= $a andalso C =< $z) orelse
        (C >= $A andalso C =< $Z) orelse
        (C >= $0 andalso C =< $9))
).

%% @doc `token' of RFC 8866: one or more token-char.
-spec is_token(binary()) -> boolean().
is_token(<<>>) -> false;
is_token(B) -> all_chars(fun(C) -> ?IS_TOKEN_CHAR(C) end, B).

%% @doc `byte-string' (any byte except NUL, CR, LF), possibly empty.
-spec is_text(binary()) -> boolean().
is_text(B) -> all_chars(fun(C) -> C =/= 0 andalso C =/= $\r andalso C =/= $\n end, B).

%% @doc `non-ws-string': one or more VCHAR or bytes 0x80-0xFF.
-spec is_non_ws(binary()) -> boolean().
is_non_ws(<<>>) -> false;
is_non_ws(B) -> all_chars(fun(C) -> C >= 16#21 andalso C =/= 16#7F end, B).

%% @doc `ice-char' string (RFC 8839): ALPHA / DIGIT / "+" / "/".
-spec is_ice_chars(binary()) -> boolean().
is_ice_chars(<<>>) -> false;
is_ice_chars(B) -> all_chars(fun(C) -> ?IS_ALNUM(C) orelse C =:= $+ orelse C =:= $/ end, B).

%% @doc `rid-id' (RFC 8851): 1*(alpha-numeric / "-" / "_").
-spec is_rid_id(binary()) -> boolean().
is_rid_id(<<>>) -> false;
is_rid_id(B) -> all_chars(fun(C) -> ?IS_ALNUM(C) orelse C =:= $- orelse C =:= $_ end, B).

-spec is_digits(binary()) -> boolean().
is_digits(<<>>) -> false;
is_digits(B) -> all_chars(fun(C) -> C >= $0 andalso C =< $9 end, B).

all_chars(F, <<C, Rest/binary>>) ->
    F(C) andalso all_chars(F, Rest);
all_chars(_, <<>>) ->
    true.

%% @doc Parse `1*DIGIT' (at most 20 digits).
-spec parse_int(binary()) -> {ok, non_neg_integer()} | error.
parse_int(B) when byte_size(B) =< ?MAX_DIGITS ->
    case is_digits(B) of
        true -> {ok, binary_to_integer(B)};
        false -> error
    end;
parse_int(_) ->
    error.

-spec parse_int(binary(), integer(), integer() | infinity) -> {ok, non_neg_integer()} | error.
parse_int(B, Min, Max) ->
    case parse_int(B) of
        {ok, N} when N >= Min, (Max =:= infinity orelse N =< Max) -> {ok, N};
        _ -> error
    end.

%% @doc Parse `non-zero-int-or-real' (RFC 8866 §9), as used by ptime,
%% maxptime and framerate. Integers stay integers.
-spec parse_number(binary()) -> {ok, number()} | error.
parse_number(B) ->
    case binary:split(B, <<".">>) of
        [I] ->
            case parse_int(I) of
                {ok, N} when N > 0 -> {ok, N};
                _ -> error
            end;
        [I, F] ->
            case is_digits(I) andalso is_digits(F) andalso byte_size(B) =< ?MAX_DIGITS of
                true ->
                    case binary_to_float(B) of
                        V when V > 0 -> {ok, V};
                        _ -> error
                    end;
                false ->
                    error
            end
    end.

-spec encode_number(number()) -> binary().
encode_number(N) when is_integer(N), N > 0 -> integer_to_binary(N);
encode_number(F) when is_float(F), F > 0 -> float_to_binary(F, [short]).

%% @doc Split on single spaces. Returns `error' on empty fields, so
%% doubled, leading or trailing spaces are rejected.
-spec split_sp(binary()) -> {ok, [binary(), ...]} | error.
split_sp(B) ->
    Parts = binary:split(B, <<" ">>, [global]),
    case lists:member(<<>>, Parts) of
        true -> error;
        false -> {ok, Parts}
    end.

%% @doc Split at the first occurrence of `Sep'.
-spec split_first(binary(), binary()) -> {binary(), binary() | undefined}.
split_first(B, Sep) ->
    case binary:split(B, Sep) of
        [A, R] -> {A, R};
        [A] -> {A, undefined}
    end.

%% @doc Strip leading and trailing spaces and tabs. Works on bytes, so
%% input that is not valid UTF-8 is fine.
-spec trim_sp(binary()) -> binary().
trim_sp(<<C, R/binary>>) when C =:= $\s; C =:= $\t -> trim_sp(R);
trim_sp(B) -> trim_tail(B, byte_size(B)).

trim_tail(B, N) when N > 0 ->
    case binary:at(B, N - 1) of
        C when C =:= $\s; C =:= $\t -> trim_tail(B, N - 1);
        _ -> binary_part(B, 0, N)
    end;
trim_tail(_, 0) ->
    <<>>.

%% @doc ASCII lowercase, byte by byte.
-spec lower(binary()) -> binary().
lower(B) -> << <<(case C of _ when C >= $A, C =< $Z -> C + 32; _ -> C end)>> || <<C>> <= B >>.

%% @doc Parse a connection or candidate address: IPv4, IPv6 or FQDN
%% (RFC 8866 `unicast-address' without `extn-addr'). The presence of a
%% colon selects IPv6 (RFC 8839 §5.1).
-spec parse_address(binary()) -> {ok, address()} | error.
parse_address(B) when byte_size(B) > 0, byte_size(B) =< 255 ->
    case binary:match(B, <<":">>) of
        nomatch ->
            case all_chars(fun(C) -> (C >= $0 andalso C =< $9) orelse C =:= $. end, B) of
                true -> inet_parse(fun inet:parse_ipv4strict_address/1, B);
                false -> hostname(B)
            end;
        _ ->
            case all_chars(fun is_ipv6_char/1, B) of
                true -> inet_parse(fun inet:parse_ipv6strict_address/1, B);
                false -> error
            end
    end;
parse_address(_) ->
    error.

is_ipv6_char(C) ->
    (C >= $0 andalso C =< $9) orelse (C >= $a andalso C =< $f) orelse
        (C >= $A andalso C =< $F) orelse C =:= $: orelse C =:= $..

inet_parse(F, B) ->
    case F(binary_to_list(B)) of
        {ok, A} -> {ok, A};
        {error, _} -> error
    end.

%% RFC 8866 FQDN: 4*(alpha-numeric / "-" / ".").
hostname(B) when byte_size(B) >= 4 ->
    case all_chars(fun(C) -> ?IS_ALNUM(C) orelse C =:= $- orelse C =:= $. end, B) of
        true -> {ok, B};
        false -> error
    end;
hostname(_) ->
    error.

-spec encode_address(address()) -> binary().
encode_address(B) when is_binary(B) ->
    check_text(address, B),
    B;
encode_address(A) when is_tuple(A) ->
    case inet:ntoa(A) of
        {error, einval} ->
            erlang:error({invalid_sdp, {address, A}});
        S ->
            case lists:member($%, S) of
                %% inet:ntoa/1 writes a zone for link-local IPv6
                %% addresses; SDP addresses have none.
                true -> string:lowercase(iolist_to_binary(lists:join($:, [integer_to_binary(W, 16) || W <- tuple_to_list(A)])));
                false -> list_to_binary(S)
            end
    end.

%% @doc Raise `{invalid_sdp, {What, Value}}' unless `Value' is a binary
%% that can sit on a single SDP line. Used on the encode path to prevent
%% line injection.
-spec check_text(term(), term()) -> ok.
check_text(What, V) ->
    case is_binary(V) andalso is_text(V) of
        true -> ok;
        false -> erlang:error({invalid_sdp, {What, V}})
    end.

%% @doc Encode a non-negative integer.
-spec int(non_neg_integer()) -> binary().
int(N) when is_integer(N), N >= 0 -> integer_to_binary(N);
int(N) -> erlang:error({invalid_sdp, {integer, N}}).
