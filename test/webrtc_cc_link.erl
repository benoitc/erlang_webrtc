%% Test-only bottleneck link: a drop-tail FIFO served at a fixed
%% capacity, followed by a propagation delay, with optional seeded
%% random loss before the queue, and optional ECN marking: with
%% `ecn_ms', an ECT packet (`{_, _, _, 2}') that finds the queue longer
%% than that may be marked CE (RFC 3168), with a probability growing as
%% the queue does, the way a RED-like AQM marks instead of dropping.
%%
%% Times are microseconds. send/4 offers a packet at a time;
%% deliver/2 returns the packets whose arrival time has passed, in
%% order, with their arrival time.
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
        marked => 0,
        rand => rand:seed_s(exsss, {Seed, Seed + 7, Seed + 13}),
        busy_until => 0,
        flight => queue:new(),
        sent => 0,
        dropped => 0,
        lost => 0
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
            {{_, _, _, 2}, E} when is_integer(E), Start - Now > E ->
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
            Done = Start + (Size * 8 * 1000000) div C,
            At = Done + maps:get(delay, L),
            L#{busy_until := Done, flight := queue:in({At, Pkt}, maps:get(flight, L))}
    end.

deliver(Now, L) ->
    deliver(Now, L, []).

deliver(Now, #{flight := F} = L, Acc) ->
    case queue:peek(F) of
        {value, {At, Pkt}} when At =< Now ->
            deliver(Now, L#{flight := queue:drop(F)}, [{At, Pkt} | Acc]);
        _ ->
            {lists:reverse(Acc), L}
    end.

queue_delay(Now, #{busy_until := B}) -> max(0, B - Now).

stats(L) -> maps:with([sent, dropped, lost, marked], L).
