%% Test-only bottleneck link: a drop-tail FIFO served at a fixed
%% capacity, followed by a propagation delay, with optional seeded
%% random loss before the queue, and optional ECN marking: with
%% `ecn_ms', an ECT packet (`{rtp, _, _, 2}') that finds the queue longer
%% than that may be marked CE (RFC 3168), with a probability growing as
%% the queue does, the way a RED-like AQM marks instead of dropping.
%%
%% `jitter' (#{std_ms, n_std}) adds packet delay variation as RFC 8868
%% §4.5 asks (NR-BPDV): a truncated Gaussian sample added to the
%% propagation delay, never letting a packet arrive before the previous
%% one plus its serialization time, so nothing is reordered.
%% `extra_delay' (fun(Pkt) -> Ms) adds a per-packet delay after that,
%% for paths of different lengths sharing the bottleneck; it must be
%% constant per flow so a flow stays in order.
%%
%% Times are microseconds. send/4 offers a packet at a time;
%% deliver/2 returns the packets whose arrival time has passed, in
%% order, as {ArrivalUs, Pkt, Size}.
-module(webrtc_cc_link).

-export([new/1, send/4, deliver/2, set_capacity/2, queue_delay/2, stats/1]).

new(Opts) ->
    Seed = maps:get(seed, Opts, 1),
    #{
        capacity => maps:get(capacity, Opts),
        delay => maps:get(delay_ms, Opts, 20) * 1000,
        %% Queue limit as a delay at the current capacity.
        queue_us => maps:get(queue_ms, Opts, 300) * 1000,
        loss => maps:get(loss, Opts, 0.0),
        ecn_us => case maps:get(ecn_ms, Opts, undefined) of undefined -> undefined; Ms -> Ms * 1000 end,
        jitter => maps:get(jitter, Opts, undefined),
        extra_delay => maps:get(extra_delay, Opts, fun(_) -> 0 end),
        marked => 0,
        rand => rand:seed_s(exsss, {Seed, Seed + 7, Seed + 13}),
        jrand => rand:seed_s(exsss, {Seed, Seed + 3, Seed + 5}),
        busy_until => 0,
        last_at => 0,
        n => 0,
        flight => gb_sets:new(),
        sent => 0,
        dropped => 0,
        lost => 0,
        delivered_bytes => 0
    }.

set_capacity(Bps, L) -> L#{capacity := Bps}.

send(Pkt, Size, Now, #{loss := P, rand := R0} = L) ->
    {U, R1} = rand:uniform_s(R0),
    L1 = L#{rand := R1, sent := maps:get(sent, L) + 1},
    case U < P of
        true -> L1#{lost := maps:get(lost, L1) + 1};
        false -> enqueue(Pkt, Size, Now, L1)
    end.

enqueue(Pkt0, Size, Now, #{busy_until := Busy, capacity := C, queue_us := Q} = L0) ->
    Start = max(Now, Busy),
    {Pkt, L} =
        case {Pkt0, maps:get(ecn_us, L0)} of
            {{rtp, _, _, 2}, E} when is_integer(E), Start - Now > E ->
                %% RED-like: the marking probability grows from 0 at
                %% `ecn_ms' to 10% at three times that.
                P = min(0.1, 0.1 * (Start - Now - E) / (2 * E)),
                {U, R} = rand:uniform_s(maps:get(rand, L0)),
                case U < P of
                    true -> {setelement(4, Pkt0, 3), L0#{marked := maps:get(marked, L0) + 1, rand := R}};
                    false -> {Pkt0, L0#{rand := R}}
                end;
            _ ->
                {Pkt0, L0}
        end,
    case Start - Now > Q of
        true ->
            L#{dropped := maps:get(dropped, L) + 1};
        false ->
            Ser = (Size * 8 * 1000000) div C,
            Done = Start + Ser,
            {Z, L1} = jitter(L),
            At0 = max(Done + maps:get(delay, L) + Z, maps:get(last_at, L) + Ser),
            At = At0 + (maps:get(extra_delay, L))(Pkt) * 1000,
            N = maps:get(n, L1),
            L1#{busy_until := Done, last_at := At0, n := N + 1,
                flight := gb_sets:add({At, N, Pkt, Size}, maps:get(flight, L1))}
    end.

jitter(#{jitter := undefined} = L) ->
    {0, L};
jitter(#{jitter := #{std_ms := Std} = J, jrand := R0} = L) ->
    NStd = maps:get(n_std, J, 3),
    {G, R} = rand:normal_s(R0),
    Z = max(-NStd, min(NStd, G)) * Std * 1000,
    {round(Z), L#{jrand := R}}.

deliver(Now, L) ->
    deliver(Now, L, []).

deliver(Now, #{flight := F} = L, Acc) ->
    case gb_sets:is_empty(F) of
        false ->
            case gb_sets:smallest(F) of
                {At, _, Pkt, Size} = E when At =< Now ->
                    deliver(Now, L#{flight := gb_sets:delete(E, F),
                                    delivered_bytes := maps:get(delivered_bytes, L) + Size},
                            [{At, Pkt, Size} | Acc]);
                _ ->
                    {lists:reverse(Acc), L}
            end;
        true ->
            {lists:reverse(Acc), L}
    end.

queue_delay(Now, #{busy_until := B}) -> max(0, B - Now).

stats(L) -> maps:with([sent, dropped, lost, marked, delivered_bytes], L).
