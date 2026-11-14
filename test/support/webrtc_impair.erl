%% @doc Seeded network impairment for tests, plugged into a peer
%% connection with the `outbound_filter' option:
%%
%% ```
%% {ok, Pc} = webrtc:new_peer_connection(#{loopback => true,
%%     outbound_filter => webrtc_impair:filter(#{loss => 0.1, seed => 42})}).
%% '''
%%
%% Options (all optional): `loss' (probability), `burst' ({PEnterBad,
%% PLeaveBad, LossInBad}, a Gilbert-Elliott model), `dup', `reorder'
%% (probability that a datagram is held back by `reorder_delay' ms),
%% `delay' and `jitter' (ms), `max_size' (datagrams above are dropped,
%% like a path MTU), `blackhole' (an atomics ref: drop everything while
%% its first slot is 1), `only_to' (a list of `{IP, Port}': datagrams to
%% any other destination are dropped, a firewall that only lets a relay
%% through), `rate' (bits per second, or a ref from `rate_limit/1' to
%% change it while running: a bottleneck that serves datagrams one after
%% the other at that rate, after the other impairments) with `queue_ms'
%% (default 200: datagrams that would wait longer are dropped), `seed'.
-module(webrtc_impair).

-export([filter/1, blackhole/0, set_blackhole/2, rate_limit/1, set_rate/2]).

filter(Opts) ->
    Seed = maps:get(seed, Opts, 1),
    State = #{rand => rand:seed_s(exsss, {Seed, Seed + 1, Seed + 2}), bad => false, busy_until => undefined},
    {fun(Dest, Bin, S) -> apply_filter(Dest, Bin, Opts, S) end, State}.

blackhole() ->
    atomics:new(1, []).

set_blackhole(Ref, On) ->
    atomics:put(Ref, 1, case On of true -> 1; false -> 0 end).

%% A rate that can be changed while the filter runs.
rate_limit(Bps) ->
    Ref = atomics:new(1, []),
    atomics:put(Ref, 1, Bps),
    {rate, Ref}.

set_rate({rate, Ref}, Bps) ->
    atomics:put(Ref, 1, Bps).

apply_filter(Dest, Bin, Opts, S0) ->
    case blackholed(Opts) orelse too_big(Bin, Opts) orelse firewalled(Dest, Opts) of
        true ->
            {[], S0};
        false ->
            {Lost, S1} = lost(Opts, S0),
            case Lost of
                true -> {[], S1};
                false -> bottleneck(Bin, Opts, deliver(Bin, Opts, S1))
            end
    end.

blackholed(#{blackhole := Ref}) -> atomics:get(Ref, 1) =:= 1;
blackholed(_) -> false.

firewalled(Dest, #{only_to := Allowed}) -> not lists:member(Dest, Allowed);
firewalled(_, _) -> false.

too_big(Bin, #{max_size := Max}) -> byte_size(Bin) > Max;
too_big(_, _) -> false.

lost(#{burst := {PEnter, PLeave, LossBad}} = Opts, #{bad := Bad} = S) ->
    {U1, S1} = uniform(S),
    Bad1 = case Bad of
        false -> U1 < PEnter;
        true -> U1 >= PLeave
    end,
    {U2, S2} = uniform(S1),
    P = case Bad1 of true -> LossBad; false -> maps:get(loss, Opts, 0.0) end,
    {U2 < P, S2#{bad := Bad1}};
lost(Opts, S) ->
    {U, S1} = uniform(S),
    {U < maps:get(loss, Opts, 0.0), S1}.

deliver(Bin, Opts, S0) ->
    {D1, S1} = delay(Opts, S0),
    {U, S2} = uniform(S1),
    D2 = case U < maps:get(reorder, Opts, 0.0) of
        true -> D1 + maps:get(reorder_delay, Opts, 30);
        false -> D1
    end,
    {U2, S3} = uniform(S2),
    Copies = case U2 < maps:get(dup, Opts, 0.0) of
        true -> [{D2, Bin}, {D2 + 1, Bin}];
        false -> [{D2, Bin}]
    end,
    {Copies, S3}.

%% Serve datagrams at the link rate, in order: each one waits for the
%% ones before it; a full queue drops.
bottleneck(Bin, #{rate := Rate} = Opts, {Copies, #{busy_until := Busy} = S}) ->
    Bps = case Rate of
        {rate, Ref} -> atomics:get(Ref, 1);
        N -> N
    end,
    Now = erlang:monotonic_time(microsecond),
    Start = case Busy of undefined -> Now; _ -> max(Now, Busy) end,
    case Start - Now > maps:get(queue_ms, Opts, 200) * 1000 of
        true ->
            {[], S};
        false ->
            Done = Start + (byte_size(Bin) * length(Copies) * 8000000) div max(Bps, 1),
            Wait = (Done - Now + 999) div 1000,
            {[{D + Wait, B} || {D, B} <- Copies], S#{busy_until := Done}}
    end;
bottleneck(_Bin, _Opts, Result) ->
    Result.

delay(Opts, S) ->
    Base = maps:get(delay, Opts, 0),
    case maps:get(jitter, Opts, 0) of
        0 -> {Base, S};
        J ->
            {U, S1} = uniform(S),
            {Base + round(U * J), S1}
    end.

uniform(#{rand := R} = S) ->
    {U, R1} = rand:uniform_s(R),
    {U, S#{rand := R1}}.
