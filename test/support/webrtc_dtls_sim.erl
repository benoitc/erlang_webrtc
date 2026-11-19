%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Test helper: run two webrtc_dtls endpoints over an in-memory
%% network with a fake clock.
%%
%% `run(Client, Server, Filter)' starts the client and delivers
%% datagrams until both endpoints are quiet. `Filter(From, N, Datagram)'
%% is applied to the N-th datagram sent by `From' (`c' or `s') and
%% returns the list of datagrams to deliver: `[]' drops it, `[D, D]'
%% duplicates it, a different binary tampers with it.
-module(webrtc_dtls_sim).
-export([run/2, run/3, run/4, deliver/3, pass/3, connected/1, sent/2]).

-define(MAX_STEPS, 20000).

pass(_From, _N, D) -> [D].

run(Cl, Sv) ->
    run(Cl, Sv, fun pass/3).

run(Cl, Sv, Filter) ->
    run(Cl, Sv, Filter, #{}).

%% Opts: `start' (default true), `now' (start time, default 0),
%% `horizon' (stop when the next timer is further than this, default
%% 600000 ms).
run(Cl0, Sv0, Filter, Opts) ->
    Now = maps:get(now, Opts, 0),
    {Cl1, A} =
        case maps:get(start, Opts, true) of
            true -> webrtc_dtls:start(Now, Cl0);
            false -> {Cl0, []}
        end,
    loop(#{
        c => Cl1,
        s => Sv0,
        now => Now,
        q => tag(c, A),
        ev => #{c => [], s => []},
        n => #{c => 0, s => 0},
        log => [],
        filter => Filter,
        horizon => maps:get(horizon, Opts, 600000),
        steps => 0
    }).

%% Continue an existing world after the caller injected actions.
deliver(W, From, Actions) ->
    loop(W#{q := maps:get(q, W) ++ tag(From, Actions)}).

tag(From, Actions) -> [{From, A} || A <- Actions].

other(c) -> s;
other(s) -> c.

loop(#{steps := N}) when N > ?MAX_STEPS ->
    error(too_many_steps);
loop(#{q := [{From, {send, D}} | Rest], n := Ns, filter := F, log := Log} = W) ->
    K = maps:get(From, Ns) + 1,
    Out = F(From, K, D),
    W1 = W#{q := Rest, n := Ns#{From := K}, steps := maps:get(steps, W) + 1, log := [{From, K, D, Out} | Log]},
    To = other(From),
    {St, Acts} = lists:foldl(
        fun(Dg, {S, AccA}) ->
            {S1, A} = webrtc_dtls:handle_packet(Dg, maps:get(now, W1), S),
            {S1, AccA ++ A}
        end,
        {maps:get(To, W1), []},
        Out
    ),
    loop(W1#{To := St, q := Rest ++ tag(To, Acts)});
loop(#{q := [{From, {event, E}} | Rest], ev := Ev} = W) ->
    loop(W#{q := Rest, ev := Ev#{From := maps:get(From, Ev) ++ [E]}});
loop(#{q := [], c := C, s := S, now := Now, horizon := H} = W) ->
    case min_t(webrtc_dtls:next_timeout(C), webrtc_dtls:next_timeout(S)) of
        infinity ->
            W;
        T when T > Now + H ->
            W;
        T0 ->
            T = max(T0, Now),
            {C1, AC} = webrtc_dtls:handle_timeout(T, C),
            {S1, AS} = webrtc_dtls:handle_timeout(T, S),
            loop(W#{c := C1, s := S1, now := T, q := tag(c, AC) ++ tag(s, AS), steps := maps:get(steps, W) + 1})
    end.

min_t(infinity, B) -> B;
min_t(A, infinity) -> A;
min_t(A, B) -> min(A, B).

connected(Events) ->
    [I || {connected, I} <- Events].

%% Datagrams sent by From, in order, as {N, Datagram, Delivered}.
sent(#{log := Log}, From) ->
    [{N, D, Out} || {F, N, D, Out} <- lists:reverse(Log), F =:= From].
