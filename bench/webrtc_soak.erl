%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Soak run: connected pairs are created and closed without pause
%% for a given time, with audio, H.264 frames carrying a malformed SPS
%% (a picture order count cycle of 2^31 frames), data channel messages
%% and keyframe requests. Every minute it prints the process and port
%% counts, the sizes of the registry and ticket tables, the longest
%% message queue and the total memory. When the time is up and the
%% traffic has stopped, the node must be back to its baseline: it halts
%% with status 1 otherwise.
%%
%% Not run by the suites: `make soak DURATION=60' (minutes, default 60,
%% `WORKERS', default 4).
-module(webrtc_soak).

-export([run/0, run/2]).

run() ->
    run(list_to_integer(os:getenv("DURATION", "60")), list_to_integer(os:getenv("WORKERS", "4"))).

run(Minutes, Workers) ->
    {ok, _} = application:ensure_all_started(webrtc),
    io:format("soak: ~b minutes, ~b workers, OTP ~s~n", [Minutes, Workers, erlang:system_info(otp_release)]),
    %% A short warm-up so that code loading and first allocations are in
    %% the baseline.
    churn(1, 20),
    settle(),
    Base = sample(),
    print(0, Base),
    Deadline = erlang:monotonic_time(millisecond) + Minutes * 60000,
    Self = self(),
    Pids = [spawn_link(fun() -> worker(Deadline), Self ! {done, self()} end) || _ <- lists:seq(1, Workers)],
    Samples = monitor_loop(Pids, Deadline, 1, []),
    settle(),
    End = sample(),
    print(end_, End),
    Verdict = verdict(Base, End),
    io:format("soak: ~p pairs, peak memory ~b MB, longest queue ~b: ~s~n",
              [lists:max([0 | [maps:get(pairs, S, 0) || S <- Samples]]),
               lists:max([maps:get(memory, S) || S <- [Base | Samples]]) div (1024 * 1024),
               lists:max([maps:get(queue, S) || S <- [Base | Samples]]),
               case Verdict of ok -> "back to the baseline"; {grew, _} -> "GREW" end]),
    case Verdict of
        ok -> halt(0);
        {grew, What} -> io:format("soak: grew ~p~n", [What]), halt(1)
    end.

monitor_loop([], _Deadline, _Min, Acc) ->
    lists:reverse(Acc);
monitor_loop(Pids, Deadline, Min, Acc) ->
    receive
        {done, P} -> monitor_loop(Pids -- [P], Deadline, Min, Acc)
    after 60000 ->
        S = (sample())#{pairs => counter()},
        print(Min, S),
        monitor_loop(Pids, Deadline, Min + 1, [S | Acc])
    end.

worker(Deadline) ->
    case erlang:monotonic_time(millisecond) < Deadline of
        true -> churn(1, 1), worker(Deadline);
        false -> ok
    end.

churn(0, _) -> ok;
churn(N, Pairs) ->
    [cycle() || _ <- lists:seq(1, Pairs)],
    churn(N - 1, Pairs).

%% One connected pair with media and data, then closed.
cycle() ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, frames => true}),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(A, video, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, video, #{}),
    ok = webrtc:create_data_channel(A, <<"soak">>, #{}),
    try
        webrtc_test_signal:connect(A, B, 20000),
        [ok = webrtc:send_rtp(A, <<"0">>, <<16#F8, 16#FF, 16#FE>>, #{timestamp => I * 960}) || I <- lists:seq(1, 20)],
        [_ = webrtc:send_frame(A, <<"1">>, h264_frame(), #{timestamp => I * 3000, keyframe => true, codec => <<"H264">>})
         || I <- lists:seq(1, 5)],
        [_ = webrtc:request_keyframe(B, <<"1">>) || _ <- lists:seq(1, 10)],
        case webrtc_test_signal:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 5000) of
            {ok, {datachannel_open, Id, _, _, _}} -> [_ = webrtc:send_data(A, Id, binary, <<0:8192>>) || _ <- lists:seq(1, 20)];
            _ -> ok
        end,
        timer:sleep(100)
    catch
        _:_ -> ok
    after
        _ = webrtc:close(A),
        _ = webrtc:close(B),
        webrtc_test_signal:flush(),
        bump()
    end.

%% An IDR access unit whose SPS has a 2^31 frame picture order count
%% cycle (H.264 §7.4.2.1.1 allows 255).
h264_frame() ->
    Sps = <<16#67, 66, 0, 30, 1:1, 1:1, 2#010:3, 0:1, 1:1, 1:1, 0:31, 1:1, 0:31, 0:1>>,
    Pps = <<16#68, 16#CE, 16#38, 16#80>>,
    Idr = <<16#65, 16#88, 16#84, (binary:copy(<<16#21>>, 600))/binary>>,
    iolist_to_binary([[<<0, 0, 0, 1>>, N] || N <- [Sps, Pps, Idr]]).

bump() ->
    case ets:whereis(webrtc_soak_count) of
        undefined -> ok;
        _ -> ets:update_counter(webrtc_soak_count, pairs, 1)
    end.

counter() ->
    case ets:whereis(webrtc_soak_count) of
        undefined ->
            _ = ets:new(webrtc_soak_count, [named_table, public]),
            ets:insert(webrtc_soak_count, {pairs, 0}),
            0;
        _ ->
            [{pairs, N}] = ets:lookup(webrtc_soak_count, pairs),
            N
    end.

%% Let closing transports finish (the slowest wait 5 s for close_notify).
settle() ->
    timer:sleep(7000),
    erlang:garbage_collect().

sample() ->
    _ = counter(),
    #{processes => erlang:system_info(process_count),
      ports => erlang:system_info(port_count),
      transports => ets:info(webrtc_transports, size),
      tickets => case ets:info(webrtc_dtls_tickets, size) of undefined -> 0; T -> T end,
      queue => lists:max([0 | [Q || P <- processes(), {message_queue_len, Q} <- [process_info(P, message_queue_len)]]]),
      memory => erlang:memory(total)}.

print(Min, S) ->
    io:format("~6s processes ~6b ports ~5b transports ~4b tickets ~5b queue ~5b memory ~6b KB~n",
              [case Min of end_ -> "end"; _ -> integer_to_list(Min) ++ "m" end,
               maps:get(processes, S), maps:get(ports, S), maps:get(transports, S), maps:get(tickets, S),
               maps:get(queue, S), maps:get(memory, S) div 1024]).

%% Back to the baseline: a few processes and 30 MB of memory of slack.
verdict(Base, End) ->
    Grew = [{K, maps:get(K, Base), maps:get(K, End)}
            || {K, Slack} <- [{processes, 10}, {ports, 0}, {transports, 0}, {tickets, 0}, {memory, 30 * 1024 * 1024}],
               maps:get(K, End) > maps:get(K, Base) + Slack],
    case Grew of
        [] -> ok;
        _ -> {grew, Grew}
    end.
