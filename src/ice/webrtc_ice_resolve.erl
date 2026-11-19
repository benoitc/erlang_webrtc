%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Resolve STUN and TURN servers given by URI (webrtc_ice_uri) to
%% the addresses the ICE agent uses.
%%
%% RFC 5928 §3 for TURN and RFC 8489 §8.1 for STUN: an IP address is
%% used as is; a name with a port is looked up for A and AAAA records; a
%% name without a port first for SRV records (`_turn._udp',
%% `_turn._tcp', `_turns._tcp', `_stun._udp'), whose targets are taken
%% in priority order, then for A and AAAA records with the default port
%% when there are none. Each URI gives, per family, every address found,
%% SRV targets in order: the first is the server, the others are tried
%% in turn when it does not answer (RFC 8489 §8.1, RFC 5928 §3).
%% Candidates are gathered per family (RFC 8445 §5.1.1.2).
%%
%% Names are resolved in parallel within `timeout' (ms, default 2000).
%% `resolver' replaces the lookups: `fun(srv | inet | inet6, Name)'
%% returning `{ok, [{Priority, Weight, Port, Target}]}' for srv and
%% `{ok, [IP]}' otherwise, or `{error, Reason}'.
-module(webrtc_ice_resolve).

-export([resolve/2]).

-define(TIMEOUT, 2000).

%% The result: for each URI and family, its URI, the server entry
%% (`{stun, {IP, Port}}' or `{turn, Map}' as `turn_servers' takes it)
%% and the addresses to fall back to, in order; the URIs that gave none,
%% with the reason.
-type address() :: {inet:ip_address(), inet:port_number()}.
-spec resolve([webrtc_ice_uri:server()], map()) ->
    {[{binary(), {stun, address()} | {turn, map()}, [address()]}], [{binary(), term()}]}.
resolve(Servers, Opts) ->
    Timeout = maps:get(timeout, Opts, ?TIMEOUT),
    Resolver = maps:get(resolver, Opts, default_resolver(Timeout)),
    Self = self(),
    Jobs = [{spawn_monitor(fun() -> Self ! {self(), addresses(S, Resolver)} end), S} || S <- Servers],
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    Results = [collect(Ref, Pid, S, Deadline) || {{Pid, Ref}, S} <- Jobs],
    Found = [{Url, entry(S, A), Rest} || {#{url := Url} = S, {ok, Fams}} <- Results, [A | Rest] <- Fams],
    Errors = [{Url, R} || {#{url := Url}, {error, R}} <- Results],
    {Found, Errors}.

entry(#{uri := #{scheme := stun}}, Addr) -> {stun, Addr};
entry(S, Addr) -> {turn, turn(S, Addr)}.

collect(Ref, Pid, S, Deadline) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {Pid, R} ->
            erlang:demonitor(Ref, [flush]),
            {S, R};
        {'DOWN', Ref, process, Pid, Reason} ->
            {S, {error, Reason}}
    after Left ->
        exit(Pid, kill),
        receive {'DOWN', Ref, process, Pid, _} -> ok end,
        %% A result sent just before the kill.
        receive {Pid, _} -> ok after 0 -> ok end,
        {S, {error, timeout}}
    end.

turn(#{uri := #{host := Host, transport := T}, username := U, credential := C} = S, Addr) ->
    Base = maps:merge(maps:with([tls_options], S), #{address => Addr, username => U, password => C, transport => T}),
    %% TLS checks the server certificate against the name in the URI.
    case is_list(Host) of
        true -> Base#{hostname => Host};
        false -> Base
    end.

%% The addresses of one URI, a list per family.
addresses(#{uri := #{host := Host, port := Port}}, _Resolver) when is_tuple(Host) ->
    {ok, [[{Host, Port}]]};
addresses(#{uri := #{host := Name, port := Port, explicit_port := true}}, Resolver) ->
    by_name([{Name, Port}], Resolver);
addresses(#{uri := #{host := Name, port := Port} = Uri}, Resolver) ->
    Targets =
        case Resolver(srv, srv_name(Uri) ++ Name) of
            {ok, [_ | _] = Recs} -> [{T, P} || {_, _, P, T} <- lists:sort(fun srv_order/2, Recs)];
            _ -> [{Name, Port}]
        end,
    by_name(Targets, Resolver).

%% RFC 2782: lower priority first, then higher weight (no random
%% selection: the result is used for every gathering of the session).
srv_order({P1, W1, _, _}, {P2, W2, _, _}) -> {P1, -W1} =< {P2, -W2}.

srv_name(#{scheme := stun}) -> "_stun._udp.";
srv_name(#{scheme := turn, transport := udp}) -> "_turn._udp.";
srv_name(#{scheme := turn, transport := tcp}) -> "_turn._tcp.";
srv_name(#{scheme := turns}) -> "_turns._tcp.".

by_name(Targets, Resolver) ->
    Found = [{Fam, {IP, Port}} || {Name, Port} <- Targets, Fam <- [inet, inet6],
                                  {ok, IPs} <- [Resolver(Fam, Name)], IP <- IPs],
    case [L || Fam <- [inet, inet6], L <- [dedup([A || {F, A} <- Found, F =:= Fam])], L =/= []] of
        [] -> {error, nxdomain};
        Fams -> {ok, Fams}
    end.

dedup(L) -> lists:reverse(lists:foldl(fun(A, Acc) -> case lists:member(A, Acc) of true -> Acc; false -> [A | Acc] end end, [], L)).

default_resolver(Timeout) ->
    fun
        (srv, Name) -> {ok, inet_res:lookup(Name, in, srv, [{timeout, Timeout}])};
        (Fam, Name) -> inet:getaddrs(Name, Fam, Timeout)
    end.
