%% Test-only simulation of media flows over a bottleneck link
%% (webrtc_cc_link), each flow driven by the real congestion control
%% engine (webrtc_cc: pacer, transport-wide sequence numbers, GCC) on
%% the sender and on the receiver, with feedback going through the real
%% RTCP codec. Time advances in 1 ms steps; everything is seeded.
%%
%% The encoder of each flow produces `fps' (30) frames per second at the
%% current target bitrate (frame sizes vary by +-`variation', 10%), cut
%% into packets of at most 1200 bytes. A flow's `media_cap' ([{AtMs, Bps
%% | unlimited}]) makes it application limited: frames are sized for
%% the smaller of the target and the cap. With `feedback => ccfb' a flow
%% uses RFC 8888 feedback and ECN instead of transport-wide feedback.
%% `audio => true' adds a 20 kbps audio stream (one 50 byte packet every
%% 20 ms, RFC 8867 §4) on the same transport. `start_ms', `stop_ms' and
%% `pause' ([{FromMs, ToMs}]) shape the flow's timeline; `delay_ms' adds
%% to its one-way delay in both directions; `dir => backward' sends it
%% over the backward link, with its feedback on the forward one.
%%
%% Feedback, TCP ACKs and backward flows cross the backward link
%% (`reverse_link', webrtc_cc_link options), by default unlimited with
%% `reverse_delay_ms' (20) of delay. `tcp' adds TCP flows
%% (webrtc_cc_tcp): [#{app => long | {short, Opts}, delay_ms}].
-module(webrtc_cc_sim).

-export([run/1, average/4, min_after/4, reached/3]).
-export([rate/4, tcp_rate/4, link_rate/4, queue_percentile/4, received/2]).

-define(BIN, 200).

%% Opts: link (webrtc_cc_link options), flows (list of flow options),
%% duration_ms, reverse_delay_ms, reverse_link, tcp, events ([{AtMs,
%% {capacity, Bps} | {reverse_capacity, Bps}}]), seed.
run(Opts) ->
    Seed = maps:get(seed, Opts, 1),
    Flows = [new_flow(I, F, Seed) || {I, F} <- lists:enumerate(maps:get(flows, Opts))],
    Tcp = [new_tcp(K, T, Seed) || {K, T} <- lists:enumerate(maps:get(tcp, Opts, []))],
    Delays = maps:from_list([{Id, D} || #{id := Id, delay := D} <- Flows ++ Tcp, D > 0]),
    Extra = fun(P) -> maps:get(element(2, P), Delays, 0) end,
    Rev = maps:get(reverse_link, Opts, #{capacity => 1 bsl 40, delay_ms => maps:get(reverse_delay_ms, Opts, 20),
                                        queue_ms => 1 bsl 20}),
    Sim = #{
        t => 0,
        link => webrtc_cc_link:new((maps:get(link, Opts))#{extra_delay => Extra}),
        rlink => webrtc_cc_link:new(maps:merge(#{seed => Seed + 1}, Rev#{extra_delay => Extra})),
        flows => maps:from_list([{maps:get(id, F), F} || F <- Flows]),
        tcp => maps:from_list([{maps:get(id, T), T} || T <- Tcp]),
        events => lists:keysort(1, maps:get(events, Opts, [])),
        bins => #{},
        samples => []
    },
    loop(maps:get(duration_ms, Opts), Sim).

new_flow(I, Opts, Seed) ->
    Ccfb = maps:get(feedback, Opts, twcc) =:= ccfb,
    Cc = webrtc_cc:configure(
        #{twcc_send => not Ccfb, twcc_recv => false, sender_ssrc => I, ccfb => Ccfb, ecn => Ccfb},
        webrtc_cc:new(maps:without([start_ms, stop_ms, pause, media_cap, feedback, audio, fps, variation, delay_ms,
                                    dir], Opts))
    ),
    Rx = webrtc_cc:configure(
        #{twcc_send => false, twcc_recv => not Ccfb, sender_ssrc => 1000 + I, ccfb => Ccfb},
        webrtc_cc:new(#{twcc_interval => maps:get(twcc_interval, Opts, 100)})
    ),
    Start = maps:get(start_ms, Opts, 0),
    #{
        id => I,
        cc => Cc,
        rx => Rx,
        start => Start,
        stop => maps:get(stop_ms, Opts, infinity),
        pause => maps:get(pause, Opts, []),
        dir => maps:get(dir, Opts, forward),
        delay => maps:get(delay_ms, Opts, 0),
        ccfb => Ccfb,
        rtp_seq => 0,
        fps => maps:get(fps, Opts, 30),
        variation => maps:get(variation, Opts, 0.1),
        cap => lists:keysort(1, maps:get(media_cap, Opts, [])),
        next_frame => float(Start),
        audio => maps:get(audio, Opts, false),
        next_audio => Start,
        sent => 0,
        received => 0,
        rand => rand:seed_s(exsss, {Seed, I, 99})
    }.

new_tcp(K, Opts, Seed) ->
    #{
        id => {tcp, K},
        snd => webrtc_cc_tcp:new(maps:get(app, Opts, long), Seed * 100 + K),
        rcv => webrtc_cc_tcp:receiver(),
        start => maps:get(start_ms, Opts, 0),
        delay => maps:get(delay_ms, Opts, 0)
    }.

loop(Duration, #{t := T} = Sim) when T > Duration ->
    Sim#{samples := lists:reverse(maps:get(samples, Sim))};
loop(Duration, #{t := T} = Sim0) ->
    Sim1 = apply_events(T, Sim0),
    Sim2 = lists:foldl(fun(Id, S) -> sender_step(Id, T, S) end, Sim1, lists:sort(maps:keys(maps:get(flows, Sim1)))),
    Sim3 = lists:foldl(fun(K, S) -> tcp_step(K, T, S) end, Sim2, lists:sort(maps:keys(maps:get(tcp, Sim2)))),
    Sim4 = deliver(rlink, T, deliver(link, T, Sim3)),
    Sim5 = receivers_step(T, Sim4),
    Sim6 = sample(T, Sim5),
    loop(Duration, Sim6#{t := T + 1}).

apply_events(T, #{events := [{At, Ev} | Rest]} = Sim) when At =< T ->
    Sim1 =
        case Ev of
            {capacity, C} -> Sim#{link := webrtc_cc_link:set_capacity(C, maps:get(link, Sim))};
            {reverse_capacity, C} -> Sim#{rlink := webrtc_cc_link:set_capacity(C, maps:get(rlink, Sim))}
        end,
    apply_events(T, Sim1#{events := Rest});
apply_events(_T, Sim) ->
    Sim.

%% The link a flow's media takes, and the one its feedback takes.
out_link(#{dir := forward}) -> link;
out_link(#{dir := backward}) -> rlink.

back_link(#{dir := forward}) -> rlink;
back_link(#{dir := backward}) -> link.

put_link(Which, F, Sim) -> Sim#{Which := F(maps:get(Which, Sim))}.

%%====================================================================
%% Media senders
%%====================================================================

sender_step(Id, T, #{flows := Fs} = Sim) ->
    F0 = maps:get(Id, Fs),
    {F1, Sim1} = audio(T, F0, Sim),
    {F2, Sim2} = encoder(T, F1, Sim1),
    Cc = maps:get(cc, F2),
    {F3, Sim3} =
        case webrtc_cc:next_timeout(Cc) of
            At when At =/= infinity, At =< T ->
                {Out, _Fb, _Ev, Cc1} = webrtc_cc:handle_timeout(T, Cc),
                egress(Out, T, F2#{cc := Cc1}, Sim2);
            _ ->
                {F2, Sim2}
        end,
    Sim3#{flows := (maps:get(flows, Sim3))#{Id := F3}}.

active(T, #{start := Start, stop := Stop, pause := Pause}) ->
    T >= Start andalso T < Stop andalso not lists:any(fun({A, B}) -> T >= A andalso T < B end, Pause).

audio(T, #{audio := true, next_audio := Next} = F, Sim) when T >= Next ->
    F1 = F#{next_audio := Next + 20},
    case active(T, F1) of
        true ->
            {Out, Cc} = webrtc_cc:enqueue({audio, 50, {audio, 50}}, T, maps:get(cc, F1)),
            egress(Out, T, F1#{cc := Cc}, Sim);
        false ->
            {F1, Sim}
    end;
audio(_T, F, Sim) ->
    {F, Sim}.

encoder(T, #{start := Start} = F, Sim) when T < Start ->
    {F, Sim};
encoder(T, #{next_frame := Next} = F, Sim) when T < Next ->
    {F, Sim};
encoder(T, #{next_frame := Next, cc := Cc0, rand := R0, fps := Fps, variation := V} = F0, Sim) ->
    F = F0#{next_frame := Next + 1000 / Fps},
    case active(T, F) of
        true ->
            {U, R1} = rand:uniform_s(R0),
            Bytes = round(min(webrtc_cc:target(Cc0), cap(T, maps:get(cap, F))) / 8 / Fps * (1 - V + 2 * V * U)),
            Sizes = split(max(Bytes, 100)),
            {Out, Cc} = lists:foldl(
                fun(Sz, {Acc, C}) ->
                    {O, C1} = webrtc_cc:enqueue({video, Sz, Sz}, T, C),
                    {Acc ++ O, C1}
                end,
                {[], Cc0},
                Sizes
            ),
            egress(Out, T, F#{cc := Cc, rand := R1}, Sim);
        false ->
            {F, Sim}
    end.

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

egress(Items, T, #{id := Id, ccfb := true} = F, Sim) ->
    %% RFC 8888: the packet's own sequence number, ECT(0) when marking.
    {Cc, L, Next, N} = lists:foldl(
        fun(Item, {C, L1, Seq, K}) ->
            Ecn = case webrtc_cc:ecn_mark(C) of true -> 2; false -> 0 end,
            {C1, Sz} =
                case Item of
                    {probe, Cluster, PSz} -> {webrtc_cc:sent_probe_rtp(Id, Id, Seq, PSz, T, Cluster, C), PSz};
                    {audio, ASz} -> {webrtc_cc:sent_rtp(Id, Id, Seq, ASz, T, C), ASz};
                    Sz0 -> {webrtc_cc:video_sent(T, webrtc_cc:sent_rtp(Id, Id, Seq, Sz0, T, C)), Sz0}
                end,
            {C1, webrtc_cc_link:send({rtp, Id, Seq, Ecn}, Sz, T * 1000, L1), (Seq + 1) band 16#FFFF, K + 1}
        end,
        {maps:get(cc, F), maps:get(out_link(F), Sim), maps:get(rtp_seq, F), 0},
        Items
    ),
    {F#{cc := Cc, rtp_seq := Next, sent := maps:get(sent, F) + N}, Sim#{out_link(F) := L}};
egress(Items, T, #{id := Id} = F, Sim) ->
    {Cc, L} = lists:foldl(
        fun(Item, {C, L1}) ->
            Seq = webrtc_cc:twcc_seq(C),
            {C1, Sz} =
                case Item of
                    {probe, Cluster, PSz} -> {webrtc_cc:sent_probe(Id, PSz, T, Cluster, C), PSz};
                    {audio, ASz} -> {webrtc_cc:sent(Id, ASz, T, C), ASz};
                    Sz0 -> {webrtc_cc:video_sent(T, webrtc_cc:sent(Id, Sz0, T, C)), Sz0}
                end,
            {C1, webrtc_cc_link:send({twcc, Id, Seq}, Sz, T * 1000, L1)}
        end,
        {maps:get(cc, F), maps:get(out_link(F), Sim)},
        Items
    ),
    {F#{cc := Cc, sent := maps:get(sent, F) + length(Items)}, Sim#{out_link(F) := L}}.

%%====================================================================
%% TCP flows
%%====================================================================

tcp_step(K, T, #{tcp := Ts} = Sim) ->
    #{snd := S0, start := Start} = X = maps:get(K, Ts),
    case T >= Start of
        true ->
            S1 = webrtc_cc_tcp:timeout(T, S0),
            {Segs, S2} = webrtc_cc_tcp:output(T, S1),
            Sim1 = put_link(link, fun(L) ->
                lists:foldl(fun({Seq, Len}, L1) -> webrtc_cc_link:send({tcp, K, Seq, Len}, Len + 40, T * 1000, L1) end,
                            L, Segs)
            end, Sim),
            {Acks, R} = webrtc_cc_tcp:rtimeout(T, maps:get(rcv, X)),
            send_acks(K, Acks, T, Sim1#{tcp := (maps:get(tcp, Sim1))#{K := X#{snd := S2, rcv := R}}});
        false ->
            Sim
    end.

send_acks(K, Acks, T, Sim) ->
    put_link(rlink, fun(L) ->
        lists:foldl(
            fun({_, Sacks} = A, L1) -> webrtc_cc_link:send({ack, K, A}, 40 + 8 * min(4, length(Sacks)), T * 1000, L1) end,
            L, Acks
        )
    end, Sim).

%%====================================================================
%% Arrivals
%%====================================================================

deliver(Which, T, Sim) ->
    {Arrived, L} = webrtc_cc_link:deliver(T * 1000, maps:get(Which, Sim)),
    lists:foldl(
        fun({_At, Pkt, Size}, S) -> arrival(Pkt, T, count({link, Which}, T, Size, S)) end, Sim#{Which := L}, Arrived
    ).

arrival({twcc, Id, Seq}, T, Sim) ->
    media_in(Id, fun(Rx) -> webrtc_cc:arrival(Seq, Id, T, Rx) end, Sim);
arrival({rtp, Id, Seq, Ecn}, T, Sim) ->
    media_in(Id, fun(Rx) -> webrtc_cc:ccfb_arrival(Id, Seq, Ecn, T, Rx) end, Sim);
arrival({fb, Id, Wire}, T, Sim) ->
    {ok, Pkts} = webrtc_rtcp:decode(Wire),
    F = maps:get(Id, maps:get(flows, Sim)),
    Cc = lists:foldl(fun(P, C) -> element(2, webrtc_cc:rtcp(P, T, C)) end, maps:get(cc, F), Pkts),
    Sim#{flows := (maps:get(flows, Sim))#{Id := F#{cc := Cc}}};
arrival({tcp, K, Seq, Len}, T, Sim) ->
    X = maps:get(K, maps:get(tcp, Sim)),
    R0 = maps:get(rcv, X),
    {Acks, R} = webrtc_cc_tcp:recv(Seq, Len, T, R0),
    Sim1 = count(K, T, maps:get(bytes, R) - maps:get(bytes, R0), Sim),
    send_acks(K, Acks, T, Sim1#{tcp := (maps:get(tcp, Sim1))#{K := X#{rcv := R}}});
arrival({ack, K, Ack}, T, Sim) ->
    X = maps:get(K, maps:get(tcp, Sim)),
    Sim#{tcp := (maps:get(tcp, Sim))#{K := X#{snd := webrtc_cc_tcp:ack(Ack, T, maps:get(snd, X))}}}.

media_in(Id, Fun, Sim) ->
    F = maps:get(Id, maps:get(flows, Sim)),
    Sim#{flows := (maps:get(flows, Sim))#{Id := F#{rx := Fun(maps:get(rx, F)), received := maps:get(received, F) + 1}}}.

%% Bytes delivered to a receiver, per ?BIN ms.
count(Key, T, Bytes, #{bins := B} = Sim) ->
    K = {Key, T div ?BIN},
    Sim#{bins := B#{K => maps:get(K, B, 0) + Bytes}}.

receivers_step(T, #{flows := Fs} = Sim) ->
    maps:fold(
        fun(Id, F, S) ->
            Rx = maps:get(rx, F),
            case webrtc_cc:next_timeout(Rx) of
                At when At =/= infinity, At =< T ->
                    {_, Fb, _, Rx1} = webrtc_cc:handle_timeout(T, Rx),
                    Wire = [webrtc_rtcp:encode([P]) || P <- Fb],
                    S1 = S#{flows := (maps:get(flows, S))#{Id := F#{rx := Rx1}}},
                    put_link(back_link(F), fun(L) ->
                        lists:foldl(fun(W, L1) -> webrtc_cc_link:send({fb, Id, W}, byte_size(W), T * 1000, L1) end,
                                    L, Wire)
                    end, S1);
                _ ->
                    S
            end
        end,
        Sim,
        Fs
    ).

sample(T, #{flows := Fs, link := L} = Sim) when T rem 100 =:= 0 ->
    Targets = [webrtc_cc:target(maps:get(cc, maps:get(Id, Fs))) || Id <- lists:sort(maps:keys(Fs))],
    Q = webrtc_cc_link:queue_delay(T * 1000, L) div 1000,
    Sim#{samples := [{T, Targets, Q} | maps:get(samples, Sim)]};
sample(_T, Sim) ->
    Sim.

%%====================================================================
%% Results
%%====================================================================

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

%% Throughput (bps) of TCP flow K received over [From, To) ms.
tcp_rate(Sim, K, From, To) ->
    bin_rate(Sim, {tcp, K}, From, To).

%% Bits per second the link (`link' or `rlink') delivered over [From, To).
link_rate(Sim, Which, From, To) ->
    bin_rate(Sim, {link, Which}, From, To).

bin_rate(#{bins := B}, Key, From, To) ->
    Bins = lists:seq(From div ?BIN, (To div ?BIN) - 1),
    lists:sum([maps:get({Key, I}, B, 0) || I <- Bins]) * 8 * 1000 / (To - From).

%% Media rate of flow N: the average of its target, the rate its
%% encoder and pacer follow, over [From, To] ms.
rate(#{samples := S}, N, From, To) ->
    average(S, N, From, To).

%% Pth percentile of the bottleneck queue delay (ms) over [From, To].
queue_percentile(#{samples := S}, P, From, To) ->
    Qs = lists:sort([Q || {T, _, Q} <- S, T >= From, T =< To]),
    lists:nth(max(1, min(length(Qs), round(P / 100 * length(Qs)))), Qs).

%% {Sent, Received} media packets of flow N.
received(#{flows := Fs}, N) ->
    #{sent := Sent, received := R} = maps:get(N, Fs),
    {Sent, R}.
