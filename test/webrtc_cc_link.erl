%% Test-only bottleneck link: a drop-tail FIFO served at a fixed
%% capacity, followed by a propagation delay, with optional seeded
%% random loss before the queue, and optional ECN marking by CoDel (RFC
%% 8289): with `ecn_ms' (the target) and `ecn_interval_ms' (100), once
%% the queuing delay has stayed above the target for an interval, ECT
%% packets (`{rtp, _, _, 2}') are marked CE (RFC 3168) at CoDel's
%% control law instead of being dropped. Other packets are never marked.
%%
%% `jitter' (#{std_ms, n_std}) adds packet delay variation as RFC 8868
%% §4.5 asks (NR-BPDV): a truncated Gaussian sample added to the
%% propagation delay, never letting a packet arrive before the previous
%% one of its flow plus its serialization time, so no flow is
%% reordered. Packets are tagged tuples whose second element names the
%% flow.
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
        interval_us => maps:get(ecn_interval_ms, Opts, 100) * 1000,
        %% CoDel state (RFC 8289 §5).
        first_above => 0,
        marking => false,
        count => 0,
        last_count => 0,
        mark_next => 0,
        jitter => maps:get(jitter, Opts, undefined),
        extra_delay => maps:get(extra_delay, Opts, fun(_) -> 0 end),
        marked => 0,
        rand => rand:seed_s(exsss, {Seed, Seed + 7, Seed + 13}),
        jrand => rand:seed_s(exsss, {Seed, Seed + 3, Seed + 5}),
        busy_until => 0,
        %% Arrival of the previous packet of each flow.
        last_at => #{},
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
    {Pkt, L} = codel(Pkt0, Start, Start - Now, L0),
    case Start - Now > Q of
        true ->
            L#{dropped := maps:get(dropped, L) + 1};
        false ->
            Ser = (Size * 8 * 1000000) div C,
            Done = Start + Ser,
            {Z, L1} = jitter(L),
            %% RFC 8868 §4.5: no reordering within a flow.
            Key = flow_key(Pkt),
            Last = maps:get(Key, maps:get(last_at, L), 0),
            At0 = max(Done + maps:get(delay, L) + Z, Last + Ser),
            At = At0 + (maps:get(extra_delay, L))(Pkt) * 1000,
            N = maps:get(n, L1),
            L1#{busy_until := Done, last_at := (maps:get(last_at, L))#{Key => At0}, n := N + 1,
                flight := gb_sets:add({At, N, Pkt, Size}, maps:get(flight, L1))}
    end.

flow_key(Pkt) -> element(2, Pkt).

%% CoDel at the packet's dequeue time (FIFO: when it starts to be sent),
%% marking where RFC 8289 §5.5 drops.
codel(Pkt, _At, _Sojourn, #{ecn_us := undefined} = L) ->
    {Pkt, L};
codel(Pkt, At, Sojourn, #{ecn_us := Target, interval_us := I} = L0) ->
    {OkToMark, L} =
        if
            Sojourn < Target -> {false, L0#{first_above := 0}};
            map_get(first_above, L0) =:= 0 -> {false, L0#{first_above := At + I}};
            true -> {At >= map_get(first_above, L0), L0}
        end,
    case {maps:get(marking, L), OkToMark} of
        {true, false} ->
            {Pkt, L#{marking := false}};
        {true, true} ->
            case At >= maps:get(mark_next, L) andalso ect(Pkt) of
                true ->
                    N = maps:get(count, L) + 1,
                    {mark(Pkt), counted(L#{count := N, mark_next := control_law(maps:get(mark_next, L), N, I)})};
                false ->
                    {Pkt, L}
            end;
        {false, true} ->
            case ect(Pkt) of
                true ->
                    Delta = maps:get(count, L) - maps:get(last_count, L),
                    N = case Delta > 1 andalso At - maps:get(mark_next, L) < 16 * I of true -> Delta; false -> 1 end,
                    {mark(Pkt), counted(L#{marking := true, count := N, last_count := N,
                                           mark_next := control_law(At, N, I)})};
                false ->
                    {Pkt, L}
            end;
        {false, false} ->
            {Pkt, L}
    end.

control_law(T, Count, Interval) -> T + round(Interval / math:sqrt(Count)).

ect({rtp, _, _, 2}) -> true;
ect(_) -> false.

mark(Pkt) -> setelement(4, Pkt, 3).

counted(L) -> L#{marked := maps:get(marked, L) + 1}.

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
