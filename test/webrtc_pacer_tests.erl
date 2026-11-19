%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for webrtc_pacer: timing, priorities, bounded queue, burst cap.
-module(webrtc_pacer_tests).
-include_lib("eunit/include/eunit.hrl").

%% Drive the pacer with a 1 ms clock until the queue is empty; returns
%% [{Time, Packet}] in send order.
run(P, From, To) ->
    run(P, From, To, []).

run(P, T, To, Acc) when T > To ->
    {lists:reverse(Acc), P};
run(P, T, To, Acc) ->
    {Out, P1} = webrtc_pacer:handle_timeout(T, P),
    run(P1, T + 1, To, lists:reverse([{T, X} || X <- Out]) ++ Acc).

fill(P, Pkts, Now) ->
    lists:foldl(
        fun(Pkt, {Acc, Px}) ->
            {O, P1} = webrtc_pacer:enqueue(Pkt, Now, Px),
            {Acc ++ [{Now, X} || X <- O], P1}
        end,
        {[], P},
        Pkts
    ).

%% 1 Mbps pacing, 100 packets of 1250 bytes (10 ms each) queued at once:
%% they leave one every 10 ms, the whole batch in about one second.
timing_accuracy_test() ->
    P0 = webrtc_pacer:new(#{rate => 1000000, burst_ms => 10}),
    Pkts = [{video, 1250, I} || I <- lists:seq(1, 100)],
    {Now, P1} = fill(P0, Pkts, 0),
    {Later, P2} = run(P1, 1, 2000),
    Sent = Now ++ Later,
    ?assertEqual(lists:seq(1, 100), [I || {_, {_, _, I}} <- Sent]),
    ?assertEqual(0, webrtc_pacer:queue_length(P2)),
    {LastT, _} = lists:last(Sent),
    %% 125000 bytes at 1 Mbps take 1000 ms; the initial burst allows
    %% about 1.2 packets ahead of time.
    ?assert(LastT >= 970 andalso LastT =< 1000),
    %% Packets are evenly spaced once the burst is spent.
    Gaps = gaps([T || {T, _} <- Sent]),
    ?assert(lists:all(fun(G) -> G >= 9 andalso G =< 11 end, lists:nthtail(2, Gaps))).

gaps([A, B | Rest]) -> [B - A | gaps([B | Rest])];
gaps(_) -> [].

%% next_timeout/1 tells when the next packet may leave, so a sparse
%% caller (one wake up per timeout) sends at the same times.
next_timeout_test() ->
    P0 = webrtc_pacer:new(#{rate => 800000}),
    {Now, P1} = fill(P0, [{video, 1000, I} || I <- lists:seq(1, 10)], 0),
    %% The initial burst lets two packets leave at once, the other eight
    %% leave one per wake up, 10 ms apart (1000 bytes at 800 kbps).
    ?assertEqual(2, length(Now)),
    Times = wake(P1, []),
    ?assertEqual(8, length(Times)),
    ?assert(lists:all(fun(G) -> G =:= 10 end, gaps(Times))).

wake(P, Acc) ->
    case webrtc_pacer:next_timeout(P) of
        infinity ->
            lists:reverse(Acc);
        T ->
            {Out, P1} = webrtc_pacer:handle_timeout(T, P),
            ?assertEqual(1, length(Out)),
            wake(P1, [T | Acc])
    end.

empty_queue_has_no_timeout_test() ->
    P = webrtc_pacer:new(#{rate => 1000000}),
    ?assertEqual(infinity, webrtc_pacer:next_timeout(P)),
    {[{audio, 100, a}], P1} = webrtc_pacer:enqueue({audio, 100, a}, 0, P),
    ?assertEqual(infinity, webrtc_pacer:next_timeout(P1)).

%% Audio leaves first, then retransmissions, then video; each class in
%% order.
priority_test() ->
    P0 = webrtc_pacer:new(#{rate => 100000, burst_ms => 1}),
    %% The first packet uses the initial budget.
    {[{video, 1500, v0}], P1} = webrtc_pacer:enqueue({video, 1500, v0}, 0, P0),
    {[], P2} = fill(P1, [{video, 200, v1}, {rtx, 200, r1}, {video, 200, v2}, {audio, 200, a1}, {rtx, 200, r2}, {audio, 200, a2}], 0),
    {Sent, _} = run(P2, 1, 1000),
    ?assertEqual([a1, a2, r1, r2, v1, v2], [D || {_, {_, _, D}} <- Sent]).

%% A full queue drops the oldest video packet and counts it.
bounded_queue_drops_oldest_video_test() ->
    P0 = webrtc_pacer:new(#{rate => 100000, max_packets => 4}),
    {[_], P1} = webrtc_pacer:enqueue({video, 1500, first}, 0, P0),
    {[], P2} = fill(P1, [{video, 100, v1}, {audio, 100, a1}, {video, 100, v2}, {rtx, 100, r1}], 0),
    ?assertEqual(4, webrtc_pacer:queue_length(P2)),
    {[], P3} = webrtc_pacer:enqueue({audio, 100, a2}, 0, P2),
    ?assertEqual(4, webrtc_pacer:queue_length(P3)),
    ?assertMatch(#{dropped := #{video := 1, audio := 0, rtx := 0}}, webrtc_pacer:stats(P3)),
    {[], P4} = webrtc_pacer:enqueue({video, 100, v3}, 0, P3),
    {Sent, P5} = run(P4, 1, 2000),
    ?assertEqual([a1, a2, r1, v3], [D || {_, {_, _, D}} <- Sent]),
    ?assertMatch(#{dropped := #{video := 2}, sent := 5}, webrtc_pacer:stats(P5)).

%% With only audio and retransmissions queued, an incoming video packet
%% is the one dropped; then retransmissions go before audio.
bounded_queue_without_video_test() ->
    P0 = webrtc_pacer:new(#{rate => 100000, max_packets => 2}),
    {[_], P1} = webrtc_pacer:enqueue({audio, 1500, first}, 0, P0),
    {[], P2} = fill(P1, [{audio, 100, a1}, {rtx, 100, r1}], 0),
    {[], P3} = webrtc_pacer:enqueue({video, 100, v1}, 0, P2),
    ?assertMatch(#{dropped := #{video := 1}}, webrtc_pacer:stats(P3)),
    {[], P4} = webrtc_pacer:enqueue({audio, 100, a2}, 0, P3),
    ?assertMatch(#{dropped := #{rtx := 1}}, webrtc_pacer:stats(P4)),
    {Sent, _} = run(P4, 1, 1000),
    ?assertEqual([a1, a2], [D || {_, {_, _, D}} <- Sent]).

%% A long idle period does not build more than the burst cap.
idle_burst_is_bounded_test() ->
    P0 = webrtc_pacer:new(#{rate => 1000000, burst_ms => 10}),
    {_, P1} = webrtc_pacer:handle_timeout(10000, P0),
    %% 10 ms at 1 Mbps is 1250 bytes: one 1000 byte packet and a second
    %% one in debt, then nothing until the debt is repaid.
    {Out, _} = fill(P1, [{video, 1000, I} || I <- lists:seq(1, 10)], 10000),
    ?assertEqual(2, length(Out)).

%% max_queue_ms raises the rate so the queue drains in time.
queue_delay_bound_test() ->
    P0 = webrtc_pacer:new(#{rate => 100000, max_queue_ms => 500}),
    %% 100 KB at 100 kbps would take 8 s.
    {_, P1} = fill(P0, [{video, 1000, I} || I <- lists:seq(1, 100)], 0),
    {Sent, P2} = run(P1, 1, 10000),
    {Last, _} = lists:last(Sent),
    ?assertEqual(0, webrtc_pacer:queue_length(P2)),
    ?assert(Last =< 600),
    ?assertMatch(#{max_queue_delay := D} when D =< 600, webrtc_pacer:stats(P2)).

set_rate_test() ->
    P0 = webrtc_pacer:new(#{rate => 1000000}),
    {_, P1} = fill(P0, [{video, 1250, I} || I <- lists:seq(1, 20)], 0),
    P2 = webrtc_pacer:set_rate(2000000, 0, P1),
    ?assertEqual(2000000, webrtc_pacer:rate(P2)),
    {Sent, _} = run(P2, 1, 1000),
    {Last, _} = lists:last(Sent),
    %% 25000 bytes at 2 Mbps: about 100 ms.
    ?assert(Last >= 85 andalso Last =< 100).

flush_test() ->
    P0 = webrtc_pacer:new(#{rate => 100000}),
    {_, P1} = fill(P0, [{video, 1500, v1}, {video, 1500, v2}, {audio, 100, a1}], 0),
    {Pkts, P2} = webrtc_pacer:flush(P1),
    ?assertEqual([a1, v2], [D || {_, _, D} <- Pkts]),
    ?assertEqual(0, webrtc_pacer:queue_length(P2)),
    ?assertEqual(infinity, webrtc_pacer:next_timeout(P2)).
