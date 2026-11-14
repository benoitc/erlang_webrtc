%% @doc Peer connection benchmarks over loopback UDP. Not run by the
%% functional suites; use `make bench' or call `run/0' from a shell
%% started with the test profile paths.
%%
%% Measures: session establishment time (offer to both connected, data
%% channel open), memory per connected peer connection, data channel
%% throughput, RTP forwarding rate through an Erlang relay peer.
-module(webrtc_pc_bench).

-export([run/0, run/1]).

-include("webrtc_rtp.hrl").

run() ->
    run(#{}).

run(Opts) ->
    {ok, _} = application:ensure_all_started(webrtc),
    N = maps:get(pairs, Opts, 20),
    io:format("~nPeer connection benchmarks (loopback, OTP ~s)~n", [erlang:system_info(otp_release)]),
    establishment(N),
    memory(N),
    datachannel_throughput(maps:get(dc_bytes, Opts, 50 * 1024 * 1024), maps:get(dc_msg, Opts, 16384)),
    rtp_forwarding(maps:get(rtp_packets, Opts, 20000)),
    ok.

pair() ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    {A, B}.

connect_dc(A, B) ->
    ok = webrtc:create_data_channel(A, <<"b">>, #{}),
    webrtc_test_signal:connect(A, B, 30000),
    {ok, {datachannel_open, Id, _, _, _}} =
        webrtc_test_signal:wait(A, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 30000),
    {ok, _} = webrtc_test_signal:wait(B, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 30000),
    Id.

establishment(N) ->
    Times = [begin
                 {A, B} = pair(),
                 T0 = erlang:monotonic_time(microsecond),
                 _ = connect_dc(A, B),
                 T = erlang:monotonic_time(microsecond) - T0,
                 webrtc:close(A),
                 webrtc:close(B),
                 webrtc_test_signal:flush(),
                 T div 1000
             end
             || _ <- lists:seq(1, N)],
    S = lists:sort(Times),
    io:format("establishment (ICE+DTLS+SCTP+DCEP), ~b runs: median ~b ms, p90 ~b ms, max ~b ms~n",
              [N, lists:nth(max(1, N div 2), S), lists:nth(max(1, (N * 9) div 10), S), lists:last(S)]).

memory(N) ->
    erlang:garbage_collect(),
    M0 = erlang:memory(total),
    Pairs = [begin {A, B} = pair(), _ = connect_dc(A, B), {A, B} end || _ <- lists:seq(1, N)],
    erlang:garbage_collect(),
    M1 = erlang:memory(total),
    PerPc = (M1 - M0) div (2 * N),
    Procs = lists:sum([proc_mem(P) + proc_mem(transport(P)) || {A, B} <- Pairs, P <- [A, B]]) div (2 * N),
    io:format("memory per connected peer connection (data channel): ~b KiB VM total, ~b KiB in its two processes~n",
              [PerPc div 1024, Procs div 1024]),
    [begin webrtc:close(A), webrtc:close(B) end || {A, B} <- Pairs],
    webrtc_test_signal:flush().

transport(Pc) ->
    {ok, T} = gen_server:call(Pc, transport_pid),
    T.

proc_mem(P) ->
    {memory, M} = process_info(P, memory),
    M.

datachannel_throughput(Bytes, MsgSize) ->
    {A, B} = pair(),
    Id = connect_dc(A, B),
    Msg = crypto:strong_rand_bytes(MsgSize),
    Count = Bytes div MsgSize,
    T0 = erlang:monotonic_time(microsecond),
    Sender = spawn_link(fun() -> [send_retry(A, Id, Msg) || _ <- lists:seq(1, Count)] end),
    recv_n(B, Count),
    Us = erlang:monotonic_time(microsecond) - T0,
    unlink(Sender),
    io:format("data channel throughput, ~b B messages: ~.1f MB/s (~b messages in ~b ms)~n",
              [MsgSize, Bytes / Us, Count, Us div 1000]),
    webrtc:close(A),
    webrtc:close(B),
    webrtc_test_signal:flush().

send_retry(Pc, Id, M) ->
    case webrtc:send_data(Pc, Id, binary, M) of
        ok -> ok;
        {error, buffer_full} -> timer:sleep(1), send_retry(Pc, Id, M)
    end.

recv_n(_B, 0) -> ok;
recv_n(B, N) ->
    receive {webrtc, B, {channel_message, _, _, _}} -> recv_n(B, N - 1)
    after 30000 -> error({stalled, N})
    end.

%% A sends video RTP to R; R forwards every packet to C (SFU style).
rtp_forwarding(N) ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, R1} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, R2} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, C} = webrtc:new_peer_connection(#{loopback => true}),
    [{ok, _} = webrtc:add_transceiver(P, video, #{}) || P <- [A, R1, R2, C]],
    webrtc_test_signal:connect(A, R1, 30000),
    webrtc_test_signal:connect(R2, C, 30000),
    Self = self(),
    Fwd = spawn_link(fun() -> forward(R1, R2, Self, 0, N) end),
    ok = webrtc:controlling_process(R1, Fwd),
    Payload = crypto:strong_rand_bytes(1100),
    T0 = erlang:monotonic_time(microsecond),
    [ok = webrtc:send_rtp(A, <<"0">>, Payload, #{timestamp => I * 3000}) || I <- lists:seq(1, N)],
    Got = count_rtp(C, 0, N),
    Us = erlang:monotonic_time(microsecond) - T0,
    io:format("RTP forwarding A -> relay -> C, 1100 B payloads: ~b pkt/s end to end (~b of ~b delivered)~n",
              [round(Got * 1000000 / Us), Got, N]),
    unlink(Fwd),
    exit(Fwd, kill),
    [webrtc:close(P) || P <- [A, R1, R2, C]],
    webrtc_test_signal:flush().

forward(_In, _Out, _Parent, N, N) -> ok;
forward(In, Out, Parent, I, N) ->
    receive
        {webrtc, In, {rtp, _, Pkt}} ->
            _ = webrtc:send_rtp_packet(Out, <<"0">>, Pkt),
            forward(In, Out, Parent, I + 1, N);
        _ ->
            forward(In, Out, Parent, I, N)
    end.

count_rtp(_C, N, N) -> N;
count_rtp(C, I, N) ->
    receive {webrtc, C, {rtp, _, #rtp{}}} -> count_rtp(C, I + 1, N)
    after 2000 -> I
    end.
