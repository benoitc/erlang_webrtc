%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private Host addresses found public, shared by every peer
%% connection of the node (draft-ietf-mmusic-mdns-ice-candidates
%% §3.1.2.2).
%%
%% A hidden host address is public when a STUN server maps it to
%% itself. The finding holds for the set of STUN servers that made it:
%% under another set it is discarded.
-module(webrtc_mdns_public).

-export([ensure/0, learn/2, is_public/2]).

-define(TAB, webrtc_mdns_public).

%% @doc Create the table when it does not exist yet.
-spec ensure() -> ok.
ensure() ->
    case ets:whereis(?TAB) of
        undefined ->
            try
                _ = ets:new(?TAB, [named_table, public, set, {read_concurrency, true}]),
                ok
            catch
                error:badarg -> ok
            end;
        _ ->
            ok
    end.

%% @doc `IP' was mapped to itself by one of `Stun'.
-spec learn(inet:ip_address(), [term()]) -> ok.
learn(IP, Stun) ->
    ok = ensure(),
    true = ets:insert(?TAB, {IP, lists:usort(Stun)}),
    ok.

%% @doc Whether `IP' is known public under the STUN servers `Stun'.
-spec is_public(inet:ip_address(), [term()]) -> boolean().
is_public(IP, Stun) ->
    ok = ensure(),
    Set = lists:usort(Stun),
    case ets:lookup(?TAB, IP) of
        [{_, Set}] -> true;
        [_] -> ets:delete(?TAB, IP), false;
        [] -> false
    end.
