%% @doc STUN and TURN server URIs (RFC 7064, RFC 7065) and the W3C
%% RTCIceServer list that carries them.
%%
%% stunURI = scheme ":" host [ ":" port ], scheme "stun" / "stuns";
%% turnURI = scheme ":" host [ ":" port ] [ "?transport=" transport ],
%% scheme "turn" / "turns", transport "udp" / "tcp" / transport-ext.
%% Host and port follow RFC 3986: an IPv4 address, an IPv6 address in
%% brackets, or a registered name (percent-encoding decoded).
%%
%% A parsed URI is `#{scheme, host, port, transport, explicit_port}':
%% `host' is an IP tuple or a name (string), `port' the given one or the
%% default (3478, 5349 for stuns and turns), `transport' `udp', `tcp' or
%% `tls'. A turn URI without transport uses UDP, a turns URI TLS over
%% TCP, as browsers do (RFC 5928's NAPTR step is not done).
-module(webrtc_ice_uri).

-export([parse/1, servers/1]).

-export_type([uri/0, server/0]).

-type uri() :: #{
    scheme := stun | stuns | turn | turns,
    host := inet:ip_address() | string(),
    port := inet:port_number(),
    explicit_port := boolean(),
    transport := udp | tcp | tls
}.

%% One entry to resolve: the URI, its text and the credentials of its
%% RTCIceServer.
-type server() :: #{uri := uri(), url := binary(), username => binary(), credential => binary()}.

%% @doc Parse one URI.
-spec parse(binary() | string()) -> {ok, uri()} | {error, term()}.
parse(Uri) when is_list(Uri) ->
    parse(unicode:characters_to_binary(Uri));
parse(Uri) when is_binary(Uri) ->
    case binary:split(Uri, <<":">>) of
        [Scheme, Rest] ->
            case scheme(string:lowercase(Scheme)) of
                {ok, S} -> rest(S, Rest);
                error -> {error, {unknown_scheme, Scheme}}
            end;
        _ ->
            {error, no_scheme}
    end;
parse(_) ->
    {error, not_a_uri}.

scheme(<<"stun">>) -> {ok, stun};
scheme(<<"stuns">>) -> {ok, stuns};
scheme(<<"turn">>) -> {ok, turn};
scheme(<<"turns">>) -> {ok, turns};
scheme(_) -> error.

rest(S, Rest) ->
    {HostPort, Query} =
        case binary:split(Rest, <<"?">>) of
            [HP] -> {HP, undefined};
            [HP, Q] -> {HP, Q}
        end,
    case {transport(S, Query), host_port(HostPort)} of
        {{ok, Transport}, {ok, Host, Port}} ->
            {ok, #{
                scheme => S,
                host => Host,
                port => case Port of undefined -> default_port(S); P -> P end,
                explicit_port => Port =/= undefined,
                transport => Transport
            }};
        {{error, _} = E, _} ->
            E;
        {_, {error, _} = E} ->
            E
    end.

%% RFC 7064 has no query; RFC 7065 only `transport'.
transport(S, undefined) when S =:= stun; S =:= turn -> {ok, udp};
transport(S, undefined) when S =:= stuns; S =:= turns -> {ok, tls};
transport(S, _) when S =:= stun; S =:= stuns -> {error, query_in_stun_uri};
transport(S, <<"transport=", T/binary>>) ->
    case {S, string:lowercase(T)} of
        {turn, <<"udp">>} -> {ok, udp};
        {turn, <<"tcp">>} -> {ok, tcp};
        {turns, <<"tcp">>} -> {ok, tls};
        %% TURN over DTLS (RFC 7350) and other transports.
        {_, Other} -> case unreserved(Other) of true -> {error, {unsupported_transport, T}}; false -> {error, bad_transport} end
    end;
transport(_, _) ->
    {error, bad_query}.

default_port(S) when S =:= stun; S =:= turn -> 3478;
default_port(S) when S =:= stuns; S =:= turns -> 5349.

host_port(<<"[", Rest/binary>>) ->
    case binary:split(Rest, <<"]">>) of
        [V6, After] ->
            case inet:parse_ipv6strict_address(binary_to_list(V6)) of
                {ok, IP} -> with_port(IP, After);
                {error, _} -> {error, bad_ipv6_address}
            end;
        _ ->
            {error, bad_ipv6_address}
    end;
host_port(HostPort) ->
    {Host, After} =
        case binary:split(HostPort, <<":">>) of
            [H] -> {H, <<>>};
            [H, P] -> {H, <<":", P/binary>>}
        end,
    case inet:parse_ipv4strict_address(binary_to_list(Host)) of
        {ok, IP} ->
            with_port(IP, After);
        {error, _} ->
            case reg_name(Host) of
                {ok, Name} -> with_port(Name, After);
                error -> {error, bad_host}
            end
    end.

with_port(Host, <<>>) ->
    {ok, Host, undefined};
with_port(Host, <<":", P/binary>>) when byte_size(P) > 0, byte_size(P) =< 5 ->
    case lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(P)) of
        true ->
            case binary_to_integer(P) of
                N when N > 0, N =< 65535 -> {ok, Host, N};
                _ -> {error, bad_port}
            end;
        false ->
            {error, bad_port}
    end;
with_port(_Host, _) ->
    {error, bad_port}.

%% reg-name = *( unreserved / pct-encoded / sub-delims ), not empty here.
reg_name(<<>>) ->
    error;
reg_name(Bin) ->
    reg_name(Bin, []).

reg_name(<<>>, Acc) ->
    {ok, string:lowercase(lists:reverse(Acc))};
reg_name(<<"%", A, B, Rest/binary>>, Acc) ->
    case {hex(A), hex(B)} of
        {X, Y} when is_integer(X), is_integer(Y) -> reg_name(Rest, [X * 16 + Y | Acc]);
        _ -> error
    end;
reg_name(<<C, Rest/binary>>, Acc) ->
    case unreserved_char(C) orelse lists:member(C, "!$&'()*+,;=") of
        true -> reg_name(Rest, [C | Acc]);
        false -> error
    end.

unreserved(<<>>) -> false;
unreserved(Bin) -> lists:all(fun unreserved_char/1, binary_to_list(Bin)).

unreserved_char(C) ->
    (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) orelse (C >= $0 andalso C =< $9) orelse
        lists:member(C, "-._~").

hex(C) when C >= $0, C =< $9 -> C - $0;
hex(C) when C >= $a, C =< $f -> C - $a + 10;
hex(C) when C >= $A, C =< $F -> C - $A + 10;
hex(_) -> undefined.

%% @doc The W3C RTCIceServer list: `urls' (one URI or a list),
%% `username' and `credential' (required for TURN), and as an extension
%% `tls_options' (`ssl' client options for turns URIs). Every URI must
%% parse; URIs whose scheme or transport is not supported are returned
%% apart, to be reported.
-spec servers([map()]) -> {ok, [server()], [{binary(), term()}]} | {error, term()}.
servers(List) when is_list(List) ->
    try
        Parsed = lists:append([entries(S) || S <- List]),
        {ok, [E || {ok, E} <- Parsed], [U || {unsupported, U} <- Parsed]}
    catch
        throw:Reason -> {error, Reason}
    end;
servers(_) ->
    {error, not_a_list}.

entries(#{urls := Urls} = S) ->
    List =
        case Urls of
            U when is_binary(U) -> [U];
            [_ | _] = L -> L;
            _ -> throw(bad_urls)
        end,
    [entry(unicode:characters_to_binary(U), S) || U <- List];
entries(_) ->
    throw(missing_urls).

entry(Url, S) ->
    case parse(Url) of
        {ok, #{scheme := Scheme} = Uri} when Scheme =:= turn; Scheme =:= turns ->
            case S of
                #{username := User, credential := Cred} when is_binary(User), is_binary(Cred) ->
                    {ok, maps:merge(maps:with([tls_options], S), #{uri => Uri, url => Url, username => User, credential => Cred})};
                _ ->
                    throw({missing_credentials, Url})
            end;
        {ok, #{scheme := stuns}} ->
            %% STUN over TLS is not implemented: binding requests go over UDP.
            {unsupported, {Url, unsupported_scheme}};
        {ok, Uri} ->
            {ok, #{uri => Uri, url => Url}};
        {error, {unsupported_transport, _} = R} ->
            {unsupported, {Url, R}};
        {error, R} ->
            throw({bad_uri, Url, R})
    end.
