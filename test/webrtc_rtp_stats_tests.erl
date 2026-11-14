%% Tests for webrtc_rtp_stats (RFC 3550 Appendix A.1, A.3, A.8, §6.4.1).
-module(webrtc_rtp_stats_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

-define(S, webrtc_rtp_stats).

new() ->
    ?S:rx_new(16#1234, #{clock_rate => 8000}).

%% Feed {Seq, Ts, Now} triples, return the list of verdicts and the state.
feed(Packets, Rx) ->
    lists:mapfoldl(fun({Seq, Ts, Now}, R) -> ?S:rx_packet(Seq, Ts, Now, R) end, Rx, Packets).

seqs(Seqs) ->
    [{S, 0, 0} || S <- Seqs].

%% A.1: MIN_SEQUENTIAL = 2, the first packet is held in probation.
probation_test() ->
    {V, Rx} = feed(seqs([10, 11, 12]), new()),
    ?assertEqual([invalid, valid, valid], V),
    ?assertMatch(#{valid := true, received := 2, expected := 2, lost := 0, ext_max_seq := 12}, ?S:rx_info(Rx)).

probation_restart_test() ->
    %% out of order during probation restarts it
    {V, _} = feed(seqs([10, 20, 21]), new()),
    ?assertEqual([invalid, invalid, valid], V),
    {V0, _} = feed(seqs([10]), ?S:rx_new(1, #{clock_rate => 8000, min_sequential => 0})),
    ?assertEqual([valid], V0).

wraparound_test() ->
    {V, Rx} = feed(seqs([65533, 65534, 65535, 0, 1]), new()),
    ?assertEqual([invalid, valid, valid, valid, valid], V),
    ?assertMatch(#{cycles := 1, ext_max_seq := 65537, expected := 4, received := 4}, ?S:rx_info(Rx)),
    {RB, _} = ?S:report_block(0, Rx),
    ?assertEqual(65537, RB#rtcp_rb.ext_seq).

%% A.3: 1..10 without 5 -> base 2, expected 9, received 8.
loss_and_fraction_test() ->
    {_, Rx} = feed(seqs([1, 2, 3, 4, 6, 7, 8, 9, 10]), new()),
    {RB, Rx1} = ?S:report_block(0, Rx),
    ?assertEqual(#rtcp_rb{ssrc = 16#1234, fraction_lost = (1 bsl 8) div 9, lost = 1, ext_seq = 10}, RB),
    %% next interval without loss
    {_, Rx2} = feed(seqs([11, 12]), Rx1),
    {RB2, _} = ?S:report_block(0, Rx2),
    ?assertEqual({0, 1}, {RB2#rtcp_rb.fraction_lost, RB2#rtcp_rb.lost}).

duplicates_negative_loss_test() ->
    {_, Rx} = feed(seqs([1, 2, 3, 3, 3]), new()),
    {RB, _} = ?S:report_block(0, Rx),
    ?assertEqual({0, -2}, {RB#rtcp_rb.fraction_lost, RB#rtcp_rb.lost}).

misorder_and_dropout_test() ->
    {V, Rx} = feed(seqs([100, 101, 102, 50, 103]), new()),
    %% 50 is 52 behind: within MAX_MISORDER, counted
    ?assertEqual([invalid, valid, valid, valid, valid], V),
    ?assertMatch(#{received := 4, ext_max_seq := 103}, ?S:rx_info(Rx)),
    %% a jump of 5000 is refused; two in a row resynchronise
    {V2, Rx2} = feed(seqs([5103, 5104, 5105]), Rx),
    ?assertEqual([invalid, valid, valid], V2),
    ?assertMatch(#{received := 2, expected := 2, ext_max_seq := 5105}, ?S:rx_info(Rx2)),
    %% a jump within MAX_DROPOUT is a loss, not a restart
    {[valid], Rx3} = feed(seqs([7000]), Rx2),
    ?assertMatch(#{expected := 1897, received := 3}, ?S:rx_info(Rx3)).

%% A.8: 20 ms packets at 8 kHz on time keep jitter at 0; one packet 10 ms
%% late adds |D| / 16 = 80 / 16 = 5.
jitter_test() ->
    OnTime = [{S, S * 160, S * 20} || S <- lists:seq(0, 9)],
    {_, Rx} = feed(OnTime, new()),
    ?assertMatch(#{jitter := 0}, ?S:rx_info(Rx)),
    {[valid], Rx1} = feed([{10, 1600, 210}], Rx),
    ?assertMatch(#{jitter := 5}, ?S:rx_info(Rx1)),
    {RB, _} = ?S:report_block(210, Rx1),
    ?assertEqual(5, RB#rtcp_rb.jitter).

jitter_ts_wrap_test() ->
    %% timestamps wrapping 2^32 do not produce a jump
    Base = 16#FFFFFFFF - 320,
    Pkts = [{S, (Base + S * 160) band 16#FFFFFFFF, S * 20} || S <- lists:seq(0, 5)],
    {_, Rx} = feed(Pkts, new()),
    ?assertMatch(#{jitter := 0}, ?S:rx_info(Rx)).

jitter_time_unit_test() ->
    Rx0 = ?S:rx_new(1, #{clock_rate => 90000, time_unit => 1000000}),
    {_, Rx} = feed([{S, S * 3000, S * 33333 + (S rem 2) * 1000} || S <- lists:seq(0, 3)], Rx0),
    #{jitter := J} = ?S:rx_info(Rx),
    ?assert(J > 0).

lsr_dlsr_test() ->
    {_, Rx} = feed(seqs([1, 2]), new()),
    SR = #rtcp_sr{ssrc = 9, ntp = 16#e54f3a2b80000000},
    Rx1 = ?S:rx_sender_report(SR, 1000, Rx),
    {RB, _} = ?S:report_block(1500, Rx1),
    ?assertEqual({16#3a2b8000, 32768}, {RB#rtcp_rb.lsr, RB#rtcp_rb.dlsr}),
    {RB0, _} = ?S:report_block(1500, Rx),
    ?assertEqual({0, 0}, {RB0#rtcp_rb.lsr, RB0#rtcp_rb.dlsr}).

lost_clamp_test() ->
    %% expected far above received: clamp at 0x7fffff
    {_, Rx} = feed(seqs([1, 2]), ?S:rx_new(1, #{clock_rate => 8000, max_dropout => 65000})),
    Rx1 = lists:foldl(
        fun(I, R) ->
            {_, R1} = ?S:rx_packet((2 + I * 60000) band 16#FFFF, 0, 0, R),
            R1
        end,
        Rx,
        lists:seq(1, 200)
    ),
    {RB, _} = ?S:report_block(0, Rx1),
    ?assertEqual(16#7FFFFF, RB#rtcp_rb.lost),
    ?assertEqual(255, RB#rtcp_rb.fraction_lost).

empty_report_test() ->
    {RB, _} = ?S:report_block(0, new()),
    ?assertEqual(#rtcp_rb{ssrc = 16#1234}, RB).

sender_test() ->
    Tx = lists:foldl(fun(N, T) -> ?S:tx_packet(N, T) end, ?S:tx_new(), [100, 200, 300]),
    ?assertEqual(#{packets => 3, octets => 600}, ?S:tx_info(Tx)),
    SR = ?S:sender_report(7, 1 bsl 32, 960, Tx, [#rtcp_rb{ssrc = 1}]),
    ?assertEqual(
        #rtcp_sr{ssrc = 7, ntp = 1 bsl 32, rtp_ts = 960, packets = 3, octets = 600, reports = [#rtcp_rb{ssrc = 1}]},
        SR
    ).

%% RFC 3550 §6.4.1 example: A = 0xb710:8000, LSR = 0xb705:2000,
%% DLSR = 0x0005:4000, round trip 6.125 s.
rtt_rfc_example_test() ->
    Arrival = 16#b7108000 bsl 16,
    ?assertEqual({ok, 6125000}, ?S:rtt(16#b7052000, 16#00054000, Arrival)),
    ?assertEqual(undefined, ?S:rtt(0, 5, Arrival)),
    %% DLSR larger than the elapsed time (clock drift) reports 0
    ?assertEqual({ok, 0}, ?S:rtt(16#b7052000, 16#00104000, Arrival)).

rtt_wrap_test() ->
    %% LSR just before the 32-bit middle wraps, arrival after it
    Arrival = 16#00008000 bsl 16,
    ?assertEqual({ok, 1000000}, ?S:rtt(16#FFFF8000, 0, Arrival)).

ntp_test() ->
    ?assertEqual(2208988800 bsl 32, ?S:ntp_from_us(0)),
    ?assertEqual((2208988801 bsl 32) bor 16#80000000, ?S:ntp_from_us(1500000)),
    ?assertEqual(1500000, ?S:ntp_to_us(?S:ntp_from_us(1500000))),
    Us = 1731600000123456,
    ?assertEqual(Us, ?S:ntp_to_us(?S:ntp_from_us(Us))),
    ?assertEqual(16#3a2b8000, ?S:ntp_middle(16#e54f3a2b80000000)).
