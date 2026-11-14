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
%% its first slot is 1), `seed'.
-module(webrtc_impair).

-export([filter/1, blackhole/0, set_blackhole/2]).

filter(Opts) ->
    Seed = maps:get(seed, Opts, 1),
    State = #{rand => rand:seed_s(exsss, {Seed, Seed + 1, Seed + 2}), bad => false},
    {fun(Bin, S) -> apply_filter(Bin, Opts, S) end, State}.

blackhole() ->
    atomics:new(1, []).

set_blackhole(Ref, On) ->
    atomics:put(Ref, 1, case On of true -> 1; false -> 0 end).

apply_filter(Bin, Opts, S0) ->
    case blackholed(Opts) orelse too_big(Bin, Opts) of
        true ->
            {[], S0};
        false ->
            {Lost, S1} = lost(Opts, S0),
            case Lost of
                true -> {[], S1};
                false -> deliver(Bin, Opts, S1)
            end
    end.

blackholed(#{blackhole := Ref}) -> atomics:get(Ref, 1) =:= 1;
blackholed(_) -> false.

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
