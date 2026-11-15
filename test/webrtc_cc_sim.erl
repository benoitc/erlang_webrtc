%% Test-only simulation of media flows over one bottleneck link
%% (webrtc_cc_link), each flow driven by the real congestion control
%% engine (webrtc_cc: pacer, transport-wide sequence numbers, GCC) on
%% the sender and on the receiver, with feedback going through the real
%% RTCP codec. Time advances in 1 ms steps; everything is seeded.
%%
%% The encoder of each flow produces 30 frames per second at the
%% current target bitrate (frame sizes vary by +-10%), cut into packets
%% of at most 1200 bytes. A flow's `media_cap' ([{AtMs, Bps | unlimited}])
%% makes it application limited: frames are sized for the smaller of
%% the target and the cap.
-module(webrtc_cc_sim).

-include("webrtc_rtp_rtcp.hrl").

-export([run/1, average/4, min_after/4, reached/3]).

%% Opts: link (webrtc_cc_link options), flows (list of webrtc_cc
%% options, one per flow, optionally with start_ms), duration_ms,
%% reverse_delay_ms, events ([{AtMs, {capacity, Bps}}]), seed.
run(Opts) ->
    Seed = maps:get(seed, Opts, 1),
    Flows = [new_flow(I, F, Seed) || {I, F} <- lists:enumerate(maps:get(flows, Opts))],
    Sim = #{
        t => 0,
        link => webrtc_cc_link:new(maps:get(link, Opts)),
        flows => maps:from_list([{maps:get(id, F), F} || F <- Flows]),
        reverse => [],
        reverse_delay => maps:get(reverse_delay_ms, Opts, 20),
        events => lists:keysort(1, maps:get(events, Opts, [])),
        samples => []
    },
    loop(maps:get(duration_ms, Opts), Sim).

new_flow(I, Opts, Seed) ->
    Cc = webrtc_cc:configure(
        #{twcc_send => true, twcc_recv => false, sender_ssrc => I},
        webrtc_cc:new(maps:without([start_ms, media_cap], Opts))
    ),
    Rx = webrtc_cc:configure(
        #{twcc_send => false, twcc_recv => true, sender_ssrc => 1000 + I},
        webrtc_cc:new(#{twcc_interval => maps:get(twcc_interval, Opts, 100)})
    ),
    #{
        id => I,
        cc => Cc,
        rx => Rx,
        start => maps:get(start_ms, Opts, 0),
        cap => lists:keysort(1, maps:get(media_cap, Opts, [])),
        next_frame => float(maps:get(start_ms, Opts, 0)),
        rand => rand:seed_s(exsss, {Seed, I, 99})
    }.

loop(Duration, #{t := T} = Sim) when T > Duration ->
    Sim#{samples := lists:reverse(maps:get(samples, Sim))};
loop(Duration, #{t := T} = Sim0) ->
    Sim1 = apply_events(T, Sim0),
    Sim2 = lists:foldl(fun(Id, S) -> sender_step(Id, T, S) end, Sim1, lists:sort(maps:keys(maps:get(flows, Sim1)))),
    Sim3 = link_step(T, Sim2),
    Sim4 = receivers_step(T, Sim3),
    Sim5 = reverse_step(T, Sim4),
    Sim6 = sample(T, Sim5),
    loop(Duration, Sim6#{t := T + 1}).

apply_events(T, #{events := [{At, {capacity, C}} | Rest], link := L} = Sim) when At =< T ->
    apply_events(T, Sim#{events := Rest, link := webrtc_cc_link:set_capacity(C, L)});
apply_events(_T, Sim) ->
    Sim.

sender_step(Id, T, #{flows := Fs} = Sim) ->
    F0 = maps:get(Id, Fs),
    {F1, Sim1} = encoder(T, F0, Sim),
    Cc = maps:get(cc, F1),
    {F2, Sim2} =
        case webrtc_cc:next_timeout(Cc) of
            At when At =/= infinity, At =< T ->
                {Out, _Fb, _Ev, Cc1} = webrtc_cc:handle_timeout(T, Cc),
                egress(Out, T, F1#{cc := Cc1}, Sim1);
            _ ->
                {F1, Sim1}
        end,
    Sim2#{flows := (maps:get(flows, Sim2))#{Id := F2}}.

encoder(T, #{start := Start} = F, Sim) when T < Start ->
    {F, Sim};
encoder(T, #{next_frame := Next} = F, Sim) when T < Next ->
    {F, Sim};
encoder(T, #{next_frame := Next, cc := Cc0, rand := R0} = F, Sim) ->
    {U, R1} = rand:uniform_s(R0),
    Bytes = round(min(webrtc_cc:target(Cc0), cap(T, maps:get(cap, F))) / 8 / 30 * (0.9 + 0.2 * U)),
    Sizes = split(max(Bytes, 100)),
    {Out, Cc} = lists:foldl(
        fun(Sz, {Acc, C}) ->
            {O, C1} = webrtc_cc:enqueue({video, Sz, Sz}, T, C),
            {Acc ++ O, C1}
        end,
        {[], Cc0},
        Sizes
    ),
    egress(Out, T, F#{next_frame := Next + 1000 / 30, cc := Cc, rand := R1}, Sim).

cap(T, Caps) ->
    case [C || {At, C} <- Caps, At =< T] of
        [] -> infinity;
        Cs -> case lists:last(Cs) of unlimited -> infinity; C -> C end
    end.

split(B) when B =< 1200 -> [B];
split(B) ->
    N = (B + 1199) div 1200,
    Each = B div N,
    [Each + (case I =< B rem N of true -> 1; false -> 0 end) || I <- lists:seq(1, N)].

egress(Sizes, T, #{id := Id} = F, #{link := L0} = Sim) ->
    {Cc, L} = lists:foldl(
        fun
            ({probe, Cluster, Sz}, {C, L1}) ->
                Seq = webrtc_cc:twcc_seq(C),
                C1 = webrtc_cc:sent_probe(Id, Sz, T, Cluster, C),
                {C1, webrtc_cc_link:send({Id, Seq, Sz}, Sz, T * 1000, L1)};
            (Sz, {C, L1}) ->
                Seq = webrtc_cc:twcc_seq(C),
                C1 = webrtc_cc:video_sent(T, webrtc_cc:sent(Id, Sz, T, C)),
                {C1, webrtc_cc_link:send({Id, Seq, Sz}, Sz, T * 1000, L1)}
        end,
        {maps:get(cc, F), L0},
        Sizes
    ),
    {F#{cc := Cc}, Sim#{link := L}}.

link_step(T, #{link := L0, flows := Fs0} = Sim) ->
    {Arrived, L} = webrtc_cc_link:deliver(T * 1000, L0),
    Fs = lists:foldl(
        fun({_At, {Id, Seq, _}}, Acc) ->
            F = maps:get(Id, Acc),
            Acc#{Id := F#{rx := webrtc_cc:arrival(Seq, Id, T, maps:get(rx, F))}}
        end,
        Fs0,
        Arrived
    ),
    Sim#{link := L, flows := Fs}.

receivers_step(T, #{flows := Fs} = Sim) ->
    maps:fold(
        fun(Id, F, S) ->
            Rx = maps:get(rx, F),
            case webrtc_cc:next_timeout(Rx) of
                At when At =/= infinity, At =< T ->
                    {_, Fb, _, Rx1} = webrtc_cc:handle_timeout(T, Rx),
                    Wire = [webrtc_rtcp:encode([P]) || P <- Fb],
                    Due = T + maps:get(reverse_delay, S),
                    S#{
                        flows := (maps:get(flows, S))#{Id := F#{rx := Rx1}},
                        reverse := maps:get(reverse, S) ++ [{Due, Id, W} || W <- Wire]
                    };
                _ ->
                    S
            end
        end,
        Sim,
        Fs
    ).

reverse_step(T, #{reverse := Rev} = Sim) ->
    {Due, Later} = lists:partition(fun({At, _, _}) -> At =< T end, Rev),
    lists:foldl(
        fun({_, Id, Wire}, S) ->
            {ok, Pkts} = webrtc_rtcp:decode(Wire),
            F = maps:get(Id, maps:get(flows, S)),
            Cc = lists:foldl(
                fun(P, C) ->
                    {_, C1} = webrtc_cc:rtcp(P, T, C),
                    C1
                end,
                maps:get(cc, F),
                Pkts
            ),
            S#{flows := (maps:get(flows, S))#{Id := F#{cc := Cc}}}
        end,
        Sim#{reverse := Later},
        Due
    ).

sample(T, #{flows := Fs, link := L} = Sim) when T rem 100 =:= 0 ->
    Targets = [webrtc_cc:target(maps:get(cc, maps:get(Id, Fs))) || Id <- lists:sort(maps:keys(Fs))],
    Q = webrtc_cc_link:queue_delay(T * 1000, L) div 1000,
    Sim#{samples := [{T, Targets, Q} | maps:get(samples, Sim)]};
sample(_T, Sim) ->
    Sim.

%% Average target of flow N (1-based) over [From, To] ms.
average(Samples, N, From, To) ->
    Vs = [lists:nth(N, Ts) || {T, Ts, _} <- Samples, T >= From, T =< To],
    lists:sum(Vs) / length(Vs).

%% First time (ms) flow N's target reached Bps, or never.
reached(Samples, N, Bps) ->
    case [T || {T, Ts, _} <- Samples, lists:nth(N, Ts) >= Bps] of
        [T | _] -> T;
        [] -> never
    end.

min_after(Samples, N, From, To) ->
    lists:min([lists:nth(N, Ts) || {T, Ts, _} <- Samples, T >= From, T =< To]).
