%% Tests for webrtc_twcc_sender and webrtc_twcc_receiver, round trips
%% through the real RTCP codec.
-module(webrtc_twcc_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

%% Send packets at the given times; returns {[{Seq, SendMs}], Tx}.
send(Times, Tx0) ->
    lists:mapfoldl(
        fun(T, Tx) ->
            Seq = webrtc_twcc_sender:next_seq(Tx),
            {{Seq, T}, webrtc_twcc_sender:sent(1000, T, Tx)}
        end,
        Tx0,
        Times
    ).

wire(Fbs) ->
    lists:append([P || Fb <- Fbs, {ok, P} <- [webrtc_rtcp:decode(webrtc_rtcp:encode([Fb]))]]).

feedback(Fbs, Now, Tx0) ->
    lists:foldl(
        fun(Fb, {Acc, Tx}) ->
            {R, Tx1} = webrtc_twcc_sender:feedback(Fb, Now, Tx),
            {Acc ++ R, Tx1}
        end,
        {[], Tx0},
        wire(Fbs)
    ).

rx() -> webrtc_twcc_receiver:new(#{sender_ssrc => 7, interval => 100}).

arrive(Pkts, Rx) ->
    lists:foldl(fun({Seq, At}, R) -> webrtc_twcc_receiver:packet(Seq, 99, At, R) end, Rx, Pkts).

%% 20 packets every 5 ms, 30 ms one-way delay, the 8th lost.
round_trip_test() ->
    {Sent, Tx} = send([1000 + 5 * I || I <- lists:seq(0, 19)], webrtc_twcc_sender:new(#{})),
    Delivered = [{S, T + 30} || {S, T} <- lists:delete(lists:nth(8, Sent), Sent)],
    {Fb, _} = webrtc_twcc_receiver:flush(2000, arrive(Delivered, rx())),
    [#rtcp_twcc{sender_ssrc = 7, media_ssrc = 99}] = wire(Fb),
    {Results, _} = feedback(Fb, 2100, Tx),
    ?assertEqual(20, length(Results)),
    {_, lost, 1000} = lists:nth(8, Results),
    Got = [{S, A} || {S, A, _} <- Results, A =/= lost],
    {S0, A0} = hd(Got),
    %% Send times are ours; arrival differences are exact (30 ms delay).
    ?assertEqual([{S - S0, S - S0} || {S, _} <- Got], [{S - S0, A - A0} || {S, A} <- Got]),
    ?assertEqual(1000000, S0).

wraparound_test() ->
    {Sent, Tx} = send(lists:seq(0, 19), webrtc_twcc_sender:new(#{initial_seq => 65530})),
    ?assertEqual([65530, 65531, 65532, 65533, 65534, 65535, 0, 1], [S || {S, _} <- lists:sublist(Sent, 8)]),
    {Fb, _} = webrtc_twcc_receiver:flush(100, arrive([{S, T + 10} || {S, T} <- Sent], rx())),
    {Results, _} = feedback(Fb, 100, Tx),
    ?assertEqual([{T * 1000, size} || T <- lists:seq(0, 19)], [{S, size} || {S, _, 1000} <- Results]).

%% A packet lost between two feedback messages is reported by the
%% second one.
loss_between_feedbacks_test() ->
    {Sent, Tx0} = send(lists:seq(0, 9), webrtc_twcc_sender:new(#{})),
    {First, [_Lost | Second]} = lists:split(5, Sent),
    {Fb1, Rx1} = webrtc_twcc_receiver:flush(50, arrive([{S, T + 5} || {S, T} <- First], rx())),
    {Fb2, _} = webrtc_twcc_receiver:flush(100, arrive([{S, T + 5} || {S, T} <- Second], Rx1)),
    [#rtcp_twcc{base_seq = 5, packets = [{5, not_received} | _]}] = wire(Fb2),
    {R1, Tx1} = feedback(Fb1, 50, Tx0),
    {R2, _} = feedback(Fb2, 100, Tx1),
    ?assertEqual(5, length(R1)),
    ?assertMatch([{5000, lost, 1000} | _], R2),
    ?assertEqual(5, length(R2)).

%% The same feedback twice is reported once.
duplicate_feedback_test() ->
    {Sent, Tx0} = send(lists:seq(0, 4), webrtc_twcc_sender:new(#{})),
    {Fb, _} = webrtc_twcc_receiver:flush(50, arrive([{S, T} || {S, T} <- Sent], rx())),
    {R1, Tx1} = feedback(Fb, 50, Tx0),
    {R2, _} = feedback(Fb, 60, Tx1),
    ?assertEqual(5, length(R1)),
    ?assertEqual([], R2).

%% Reordering: a packet reported lost, then received, is returned again
%% as received; the receiver repeats what it reported after the late one.
late_packet_test() ->
    {Sent, Tx0} = send(lists:seq(0, 3), webrtc_twcc_sender:new(#{})),
    [P0, P1, P2, P3] = Sent,
    {Fb1, Rx1} = webrtc_twcc_receiver:flush(50, arrive([{S, T + 10} || {S, T} <- [P0, P2, P3]], rx())),
    {Fb2, _} = webrtc_twcc_receiver:flush(80, arrive([{element(1, P1), 60}], Rx1)),
    [#rtcp_twcc{base_seq = 1, packets = [{1, _}, {2, _}, {3, _}]}] = wire(Fb2),
    {R1, Tx1} = feedback(Fb1, 50, Tx0),
    ?assertMatch([_, {1000, lost, _}, _, _], R1),
    {R2, _} = feedback(Fb2, 80, Tx1),
    ?assertMatch([{1000, A, 1000}] when is_integer(A), R2).

%% Feedback is due one interval after the first unreported arrival.
interval_test() ->
    Rx0 = rx(),
    ?assertEqual(infinity, webrtc_twcc_receiver:next_timeout(Rx0)),
    Rx1 = webrtc_twcc_receiver:packet(10, 1, 500, Rx0),
    Rx2 = webrtc_twcc_receiver:packet(11, 1, 520, Rx1),
    ?assertEqual(600, webrtc_twcc_receiver:next_timeout(Rx2)),
    {[], Rx2} = webrtc_twcc_receiver:handle_timeout(599, Rx2),
    {[#rtcp_twcc{base_seq = 10, fb_count = 0}], Rx3} = webrtc_twcc_receiver:handle_timeout(600, Rx2),
    ?assertEqual(infinity, webrtc_twcc_receiver:next_timeout(Rx3)),
    Rx4 = webrtc_twcc_receiver:packet(12, 1, 700, Rx3),
    {[#rtcp_twcc{base_seq = 12, fb_count = 1}], _} = webrtc_twcc_receiver:flush(701, Rx4),
    ?assertMatch(#{feedback_sent := 1}, webrtc_twcc_receiver:stats(Rx3)).

%% Pending arrivals are bounded: feedback is due at once when full.
bounded_pending_test() ->
    Rx0 = webrtc_twcc_receiver:new(#{max_pending => 10}),
    Rx1 = arrive([{S, 100} || S <- lists:seq(1, 9)], Rx0),
    ?assertEqual(200, webrtc_twcc_receiver:next_timeout(Rx1)),
    Rx2 = arrive([{10, 101}], Rx1),
    ?assertEqual(101, webrtc_twcc_receiver:next_timeout(Rx2)),
    Rx3 = arrive([{S, 102} || S <- lists:seq(11, 40)], Rx2),
    ?assertMatch(#{pending := 20, overflow := 20}, webrtc_twcc_receiver:stats(Rx3)).

%% Large gaps are a restart, not thousands of losses.
gap_is_not_loss_test() ->
    {Fb1, Rx1} = webrtc_twcc_receiver:flush(10, arrive([{1, 0}], rx())),
    {Fb2, _} = webrtc_twcc_receiver:flush(20, arrive([{5000, 15}], Rx1)),
    [#rtcp_twcc{packets = [_]}] = wire(Fb1),
    [#rtcp_twcc{base_seq = 5000, packets = [_]}] = wire(Fb2).

%% Sequence numbers we never sent, or forgot, are ignored; history is
%% bounded.
unknown_and_old_test() ->
    {Sent, Tx} = send(lists:seq(0, 199), webrtc_twcc_sender:new(#{max_packets => 100})),
    {Fb, _} = webrtc_twcc_receiver:flush(300, arrive([{S, T + 1} || {S, T} <- Sent], rx())),
    {Results, _} = feedback(Fb, 300, Tx),
    ?assertEqual(100, length(Results)),
    ?assertEqual(100, webrtc_twcc_sender:in_flight(Tx)),
    Bogus = #rtcp_twcc{base_seq = 30000, ref_time = 0, packets = [{30000, 1}]},
    ?assertMatch({[], _}, webrtc_twcc_sender:feedback(Bogus, 300, Tx)),
    ?assertMatch({[], _}, webrtc_twcc_sender:feedback(Bogus, 0, webrtc_twcc_sender:new(#{}))).

%% Old entries expire by age.
age_limit_test() ->
    {_, Tx} = send([0, 1, 2], webrtc_twcc_sender:new(#{max_age => 1000})),
    {_, Tx1} = send([5000], Tx),
    ?assertEqual(1, webrtc_twcc_sender:in_flight(Tx1)).
