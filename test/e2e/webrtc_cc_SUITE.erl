%% Congestion control between two Erlang peers over real UDP sockets.
%% The sender's outbound filter (webrtc_impair with `rate') is a
%% bandwidth limited bottleneck; the sender's application encodes video
%% at the `bandwidth_estimate' it receives, like a real encoder would,
%% and the estimate has to track the bottleneck.
-module(webrtc_cc_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([
    estimate_tracks_bottleneck/1,
    estimate_follows_capacity_drop/1,
    estimate_grows_without_bottleneck/1,
    pacing_can_be_disabled/1
]).

-define(S, webrtc_test_signal).
-define(FRAME_MS, 33).

all() ->
    [
        estimate_tracks_bottleneck,
        estimate_follows_capacity_drop,
        estimate_grows_without_bottleneck,
        pacing_can_be_disabled
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Config.

end_per_suite(_) -> ok.

init_per_testcase(TC, Config) ->
    ?S:flush(),
    Seed = erlang:phash2({TC, 2026}),
    ct:log("seed for ~p: ~p", [TC, Seed]),
    [{seed, Seed} | Config].

end_per_testcase(_, _) ->
    ?S:flush(),
    ok.

pair(Config, Impair) ->
    F = webrtc_impair:filter(Impair#{seed => ?config(seed, Config)}),
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, outbound_filter => F}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, _} = webrtc:add_transceiver(A, video, #{direction => sendonly}),
    {ok, _} = webrtc:add_transceiver(B, video, #{direction => recvonly}),
    ?S:connect(A, B, 60000),
    {A, B}.

close(A, B) ->
    webrtc:close(A),
    webrtc:close(B).

%% Send video for Ms milliseconds at the current estimate (start 300
%% kbps). At each frame, Change(ElapsedMs) may act on the link. Returns
%% the estimates seen as [{ElapsedMs, Bps}] and the packets received by B.
stream(A, B, Ms, Change) ->
    T0 = erlang:monotonic_time(millisecond),
    loop(A, B, T0, Ms, Change, 300000, 0, [], 0, T0).

loop(A, B, T0, Ms, Change, Rate, Frame, Est, Got, At) ->
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    case Elapsed >= Ms of
        true ->
            {lists:reverse(Est), Got + drain(B, 0)};
        false ->
            Change(Elapsed),
            Frame rem 30 =:= 0 andalso log_state(A, Elapsed),
            Bytes = Rate div 8 div (1000 div ?FRAME_MS),
            [send(A, Frame, Sz) || Sz <- split(Bytes)],
            %% Like a real encoder, a late frame is not followed by a
            %% burst of catch-up frames.
            Next = max(At + ?FRAME_MS, erlang:monotonic_time(millisecond)),
            {Rate1, Est1, Got1} = events(A, B, T0, Rate, Est, Got, Next),
            loop(A, B, T0, Ms, Change, Rate1, Frame + 1, Est1, Got1, Next)
    end.

%% One line per second in the test log: estimator and pacer state.
log_state(A, Elapsed) ->
    #{estimator := E, pacer := P} = stats_target(A),
    ct:log("~p ms: ~p~n   pacer ~p", [Elapsed, E, P]).

send(A, Frame, Size) ->
    case webrtc:send_rtp(A, <<"0">>, binary:copy(<<0>>, Size), #{timestamp => Frame * 3000}) of
        ok -> ok;
        {error, _} = E -> ct:fail({send_failed, E})
    end.

split(B) when B =< 1100 -> [max(B, 100)];
split(B) -> [1100 | split(B - 1100)].

%% Process events until the next frame is due.
events(A, B, T0, Rate, Est, Got, Until) ->
    Left = max(0, Until - erlang:monotonic_time(millisecond)),
    receive
        {webrtc, A, {bandwidth_estimate, Bps}} ->
            events(A, B, T0, Bps, [{erlang:monotonic_time(millisecond) - T0, Bps} | Est], Got, Until);
        {webrtc, B, {rtp, _, #rtp{}}} ->
            events(A, B, T0, Rate, Est, Got + 1, Until);
        {webrtc, _, _} ->
            events(A, B, T0, Rate, Est, Got, Until)
    after Left ->
        {Rate, Est, Got}
    end.

drain(B, N) ->
    receive
        {webrtc, B, {rtp, _, _}} -> drain(B, N + 1)
    after 200 -> N
    end.

%% Estimates between From and To ms.
window(Est, From, To) ->
    [Bps || {T, Bps} <- Est, T >= From, T =< To].

last_before(Est, T) ->
    case [Bps || {At, Bps} <- Est, At =< T] of
        [] -> undefined;
        L -> lists:last(L)
    end.

stats_target(A) ->
    #{transport := #{media := #{congestion_control := Cc}}} = webrtc:get_stats(A),
    Cc.

%% A 1 Mbps bottleneck: the estimate climbs from 300 kbps and settles
%% around the link rate.
estimate_tracks_bottleneck(Config) ->
    {A, B} = pair(Config, #{rate => 1000000, queue_ms => 300}),
    {Est, Got} = stream(A, B, 25000, fun(_) -> ok end),
    Cc = stats_target(A),
    ct:log("estimates ~p~nreceived ~p packets~ncc ~p", [Est, Got, Cc]),
    Final = maps:get(target_bitrate, Cc),
    ?assert(Final >= 500000),
    ?assert(Final =< 1300000),
    %% Settled: every estimate of the last 10 s is within bounds.
    Late = window(Est, 15000, 25000),
    ?assert(lists:all(fun(X) -> X >= 400000 andalso X =< 1300000 end, Late)),
    ?assert(lists:max([X || {_, X} <- Est]) > 600000),
    ?assertMatch(#{pacing := true}, Cc),
    close(A, B).

%% The link drops from 2 Mbps to 600 kbps after 12 s.
estimate_follows_capacity_drop(Config) ->
    Rate = webrtc_impair:rate_limit(2000000),
    {A, B} = pair(Config, #{rate => Rate, queue_ms => 300}),
    Change = fun
        (T) when T >= 12000 -> webrtc_impair:set_rate(Rate, 600000);
        (_) -> ok
    end,
    {Est, _} = stream(A, B, 22000, Change),
    ct:log("estimates ~p", [Est]),
    Before = last_before(Est, 12000),
    ?assert(Before >= 1000000),
    %% Within a few seconds of the drop the estimate is near 600 kbps.
    After = window(Est, 16000, 22000),
    ?assert(After =/= [] orelse last_before(Est, 16000) =< 800000),
    ?assert(lists:all(fun(X) -> X =< 800000 end, [last_before(Est, 16000) | After])),
    close(A, B).

%% Without a bottleneck the estimate keeps growing well past the start.
estimate_grows_without_bottleneck(Config) ->
    {A, B} = pair(Config, #{}),
    {Est, Got} = stream(A, B, 10000, fun(_) -> ok end),
    ct:log("estimates ~p, received ~p", [Est, Got]),
    ?assert(lists:max([X || {_, X} <- Est]) >= 1500000),
    close(A, B).

%% With pacing off every packet leaves at once and nothing is queued.
pacing_can_be_disabled(Config) ->
    {A, B} = pair(Config, #{}),
    ok = webrtc:set_congestion_control(A, #{pacing => false}),
    [send(A, I, 1100) || I <- lists:seq(1, 200)],
    Cc = stats_target(A),
    ?assertMatch(#{pacing := false, pacer := #{queued := 0}}, Cc),
    ?assertEqual(200, drain_n(B, 200, 0)),
    close(A, B).

drain_n(_B, N, N) -> N;
drain_n(B, N, I) ->
    receive
        {webrtc, B, {rtp, _, _}} -> drain_n(B, N, I + 1)
    after 3000 -> I
    end.
