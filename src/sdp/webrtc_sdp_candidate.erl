%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc ICE candidate attribute codec (RFC 8839 §5.1, RFC 6544 §4.5).
%%
%% Used for `a=candidate' lines and for trickle ICE signaling, where a
%% candidate travels alone as `candidate:...' (RFC 8840).
%%
%% ```
%% {ok, C} = webrtc_sdp_candidate:parse(
%%     <<"candidate:1 1 udp 2122260223 192.0.2.1 54400 typ host">>),
%% <<"candidate:1 1 udp ", _/binary>> = webrtc_sdp_candidate:encode_attr(C).
%% '''
%%
%% Addresses are parsed to `inet:ip_address()' tuples; host names such as
%% mDNS `<uuid>.local' names (RFC 8839 allows FQDNs) stay binaries. Known
%% extension attributes other than `tcptype' (`generation', `ufrag',
%% `network-id', `network-cost', ...) are kept in order in `extensions'.
-module(webrtc_sdp_candidate).

-include("webrtc_sdp.hrl").

-export([
    parse/1,
    encode/1,
    encode_attr/1,
    extension/2,
    is_mdns/1
]).

-export_type([candidate/0]).

-type candidate() :: #sdp_candidate{}.

-define(MAX_PRIORITY, 2147483647).

%% @doc Parse a candidate. Accepts the bare attribute value, the
%% `candidate:' form used by trickle ICE, and the full `a=candidate:' line.
-spec parse(binary()) -> {ok, candidate()} | {error, term()}.
parse(<<"a=candidate:", Rest/binary>>) -> parse_value(Rest);
parse(<<"candidate:", Rest/binary>>) -> parse_value(Rest);
parse(Bin) when is_binary(Bin) -> parse_value(Bin).

parse_value(<<>>) ->
    {error, missing_fields};
parse_value(Bin) ->
    case webrtc_sdp_lex:split_sp(Bin) of
        {ok, [F, C, T, P, A, Port, <<"typ">>, Type | Rest]} ->
            try
                fields(F, C, T, P, A, Port, Type, Rest)
            catch
                throw:{bad_candidate, Why} -> {error, Why}
            end;
        {ok, _} ->
            {error, missing_fields};
        error ->
            {error, bad_spacing}
    end.

fields(F, C, T, P, A, Port, Type, Rest) ->
    Foundation = check(foundation, F, webrtc_sdp_lex:is_ice_chars(F) andalso byte_size(F) =< 32),
    Cand0 = #sdp_candidate{
        foundation = Foundation,
        component = int(component, C, 1, 256, 3),
        transport = check(transport, T, webrtc_sdp_lex:is_token(T)),
        priority = int(priority, P, 1, ?MAX_PRIORITY, 10),
        address = address(address, A),
        port = int(port, Port, 0, 65535, 5),
        type = cand_type(Type)
    },
    {Cand1, Rest1} = related(Cand0, Rest),
    {ok, extensions(Rest1, Cand1, [])}.

related(Cand, [<<"raddr">>, A | Rest]) ->
    related_port(Cand#sdp_candidate{raddr = address(raddr, A)}, Rest);
related(Cand, Rest) ->
    related_port(Cand, Rest).

related_port(Cand, [<<"rport">>, P | Rest]) ->
    {Cand#sdp_candidate{rport = int(rport, P, 0, 65535, 5)}, Rest};
related_port(Cand, Rest) ->
    {Cand, Rest}.

extensions([], Cand, Acc) ->
    Cand#sdp_candidate{extensions = lists:reverse(Acc)};
extensions([Name, Value | Rest], Cand, Acc) ->
    _ = check(extension_name, Name, webrtc_sdp_lex:is_token(Name)),
    _ = check(extension_value, Value, webrtc_sdp_lex:is_non_ws(Value)),
    case Name of
        <<"raddr">> ->
            throw({bad_candidate, misplaced_raddr});
        <<"rport">> ->
            throw({bad_candidate, misplaced_rport});
        <<"tcptype">> when Cand#sdp_candidate.tcptype =/= undefined ->
            throw({bad_candidate, duplicate_tcptype});
        <<"tcptype">> ->
            extensions(Rest, Cand#sdp_candidate{tcptype = tcptype(Value)}, Acc);
        _ ->
            extensions(Rest, Cand, [{Name, Value} | Acc])
    end;
extensions([_], _Cand, _Acc) ->
    throw({bad_candidate, odd_extension}).

tcptype(<<"active">>) -> active;
tcptype(<<"passive">>) -> passive;
tcptype(<<"so">>) -> so;
tcptype(_) -> throw({bad_candidate, tcptype}).

cand_type(<<"host">>) -> host;
cand_type(<<"srflx">>) -> srflx;
cand_type(<<"prflx">>) -> prflx;
cand_type(<<"relay">>) -> relay;
cand_type(T) -> check(type, T, webrtc_sdp_lex:is_token(T)).

check(_What, V, true) -> V;
check(What, _V, false) -> throw({bad_candidate, What}).

int(What, B, Min, Max, Digits) when byte_size(B) =< Digits ->
    case webrtc_sdp_lex:parse_int(B, Min, Max) of
        {ok, N} -> N;
        error -> throw({bad_candidate, What})
    end;
int(What, _, _, _, _) ->
    throw({bad_candidate, What}).

address(What, B) ->
    case webrtc_sdp_lex:parse_address(B) of
        {ok, A} -> A;
        error -> throw({bad_candidate, What})
    end.

%% @doc Encode as an attribute value, without the `candidate:' prefix.
%% Fields come in RFC 8839 order: `raddr', `rport', then `tcptype', then
%% the other extensions.
-spec encode(candidate()) -> binary().
encode(#sdp_candidate{} = C) ->
    #sdp_candidate{
        foundation = F,
        component = Comp,
        transport = T,
        priority = P,
        address = A,
        port = Port,
        type = Type,
        raddr = RA,
        rport = RP,
        tcptype = TcpType,
        extensions = Exts
    } = C,
    valid(foundation, F, is_binary(F) andalso webrtc_sdp_lex:is_ice_chars(F) andalso byte_size(F) =< 32),
    valid(component, Comp, is_integer(Comp) andalso Comp >= 1 andalso Comp =< 256),
    valid(transport, T, is_binary(T) andalso webrtc_sdp_lex:is_token(T)),
    valid(priority, P, is_integer(P) andalso P >= 1 andalso P =< ?MAX_PRIORITY),
    valid(port, Port, is_port_number(Port)),
    Head = [
        F, $\s, integer_to_binary(Comp), $\s, T, $\s, integer_to_binary(P), $\s,
        webrtc_sdp_lex:encode_address(A), $\s, integer_to_binary(Port), " typ ", enc_type(Type)
    ],
    Raddr =
        case RA of
            undefined -> [];
            _ -> [" raddr ", webrtc_sdp_lex:encode_address(RA)]
        end,
    Rport =
        case RP of
            undefined ->
                [];
            _ ->
                valid(rport, RP, is_port_number(RP)),
                [" rport ", integer_to_binary(RP)]
        end,
    Tcp =
        case TcpType of
            undefined -> [];
            _ when TcpType =:= active; TcpType =:= passive; TcpType =:= so ->
                [" tcptype ", atom_to_binary(TcpType)]
        end,
    Ext = [enc_ext(N, V) || {N, V} <- Exts],
    iolist_to_binary([Head, Raddr, Rport, Tcp, Ext]).

%% @doc Encode in the trickle ICE form `candidate:<value>'.
-spec encode_attr(candidate()) -> binary().
encode_attr(C) ->
    <<"candidate:", (encode(C))/binary>>.

enc_type(T) when T =:= host; T =:= srflx; T =:= prflx; T =:= relay -> atom_to_binary(T);
enc_type(T) when is_binary(T) ->
    valid(type, T, webrtc_sdp_lex:is_token(T)),
    T.

enc_ext(N, V) ->
    valid(extension_name, N, is_binary(N) andalso webrtc_sdp_lex:is_token(N)),
    valid(extension_value, V, is_binary(V) andalso webrtc_sdp_lex:is_non_ws(V)),
    [$\s, N, $\s, V].

is_port_number(P) -> is_integer(P) andalso P >= 0 andalso P =< 65535.

valid(_What, _V, true) -> ok;
valid(What, V, false) -> erlang:error({invalid_sdp, {candidate, What, V}}).

%% @doc Value of the first extension attribute named `Name'.
-spec extension(binary(), candidate()) -> {ok, binary()} | error.
extension(Name, #sdp_candidate{extensions = Exts}) ->
    case lists:keyfind(Name, 1, Exts) of
        {_, V} -> {ok, V};
        false -> error
    end.

%% @doc True when the candidate address is an mDNS `.local' host name
%% (draft-ietf-mmusic-mdns-ice-candidates).
-spec is_mdns(candidate()) -> boolean().
is_mdns(#sdp_candidate{address = A}) when is_binary(A), byte_size(A) > 6 ->
    webrtc_sdp_lex:lower(binary:part(A, byte_size(A), -6)) =:= <<".local">>;
is_mdns(_) ->
    false.
