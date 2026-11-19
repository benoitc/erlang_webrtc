%% End to end behavior under network impairment: loss, bursts,
%% duplication, reordering, jitter, a 1200 byte path MTU and a temporary
%% blackhole. Every impairment is seeded (see webrtc_impair) and the seed
%% is logged, so a failure reproduces exactly.
-module(webrtc_impairment_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([
    handshake_under_30pct_loss/1,
    reliable_channel_under_loss/1,
    reliable_channel_under_burst_loss/1,
    reordering_duplication_jitter/1,
    path_mtu_1200/1,
    unreliable_channel_under_loss/1,
    media_recovers_with_nack/1,
    blackhole_and_recovery/1,
    long_outage_recovery/1,
    path_mtu_1400/1
]).

-define(S, webrtc_test_signal).

all() ->
    [
        handshake_under_30pct_loss,
        reliable_channel_under_loss,
        reliable_channel_under_burst_loss,
        reordering_duplication_jitter,
        path_mtu_1200,
        unreliable_channel_under_loss,
        media_recovers_with_nack,
        blackhole_and_recovery,
        long_outage_recovery,
        path_mtu_1400
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Config.

end_per_suite(_) -> ok.

init_per_testcase(TC, Config) ->
    ?S:flush(),
    Seed = erlang:phash2({TC, 2026}),
    ct:log("impairment seed for ~p: ~p", [TC, Seed]),
    [{seed, Seed} | Config].

end_per_testcase(_, _) ->
    ?S:flush(),
    ok.

pair(Config, Impair) ->
    Seed = ?config(seed, Config),
    Mk = fun(N) ->
        F = webrtc_impair:filter(Impair#{seed => Seed + N}),
        {ok, Pc} = webrtc:new_peer_connection(#{loopback => true, outbound_filter => F}),
        Pc
    end,
    {Mk(0), Mk(1)}.

channel(Pc, Label) ->
    channel(Pc, Label, 30000).

channel(Pc, Label, Timeout) ->
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(Pc, fun({datachannel_open, _, L, _, _}) -> L =:= Label; (_) -> false end, Timeout),
    Id.

%% Send N numbered messages and check they all arrive, in order.
ordered_transfer(A, B, Id, N, Size) ->
    Msgs = [<<I:32, (crypto:strong_rand_bytes(Size))/binary>> || I <- lists:seq(1, N)],
    [ok = send_retry(A, Id, M) || M <- Msgs],
    Got = collect(B, N, 60000, []),
    ?assertEqual(length(Msgs), length(Got)),
    ?assertEqual(Msgs, Got).

%% The send buffer is bounded; back off while it is full.
send_retry(Pc, Id, M) ->
    case webrtc:send_data(Pc, Id, binary, M) of
        ok -> ok;
        {error, buffer_full} -> timer:sleep(20), send_retry(Pc, Id, M)
    end.

collect(_B, 0, _T, Acc) ->
    lists:reverse(Acc);
collect(B, N, T, Acc) ->
    receive
        {webrtc, B, {channel_message, _, binary, D}} -> collect(B, N - 1, T, [D | Acc])
    after T ->
        lists:reverse(Acc)
    end.

setup_channel(Config, Impair) ->
    setup_channel(Config, Impair, 30000).

setup_channel(Config, Impair, Timeout) ->
    {A, B} = pair(Config, Impair),
    ok = webrtc:create_data_channel(A, <<"c">>, #{}),
    ?S:connect(A, B, 60000),
    Id = channel(A, <<"c">>, Timeout),
    _ = channel(B, <<"c">>, Timeout),
    {A, B, Id}.

close(A, B) ->
    webrtc:close(A),
    webrtc:close(B).

handshake_under_30pct_loss(Config) ->
    %% ICE retransmits checks, DTLS retransmits flights, SCTP retransmits
    %% INIT and COOKIE: the connection still comes up.
    {A, B, Id} = setup_channel(Config, #{loss => 0.3}),
    ordered_transfer(A, B, Id, 20, 100),
    close(A, B).

reliable_channel_under_loss(Config) ->
    {A, B, Id} = setup_channel(Config, #{loss => 0.1}),
    ordered_transfer(A, B, Id, 300, 1000),
    %% Messages larger than one SCTP packet are fragmented and
    %% reassembled through the losses.
    ordered_transfer(A, B, Id, 10, 20000),
    close(A, B).

reliable_channel_under_burst_loss(Config) ->
    {A, B, Id} = setup_channel(Config, #{burst => {0.05, 0.3, 0.8}}),
    ordered_transfer(A, B, Id, 200, 500),
    close(A, B).

reordering_duplication_jitter(Config) ->
    {A, B, Id} = setup_channel(Config, #{reorder => 0.2, reorder_delay => 25, dup => 0.1, jitter => 15}),
    ordered_transfer(A, B, Id, 300, 800),
    close(A, B).

%% RFC 8899, RFC 8261 §5: the path carries datagrams up to 1400 bytes;
%% probes find a larger SCTP packet size than the 1200 byte base, and
%% large messages arrive.
path_mtu_1400(Config) ->
    {A, B, Id} = setup_channel(Config, #{max_size => 1400}),
    timer:sleep(5000),
    Pmtu = sctp_pmtu(A),
    ct:log("SCTP path MTU: ~p", [Pmtu]),
    ?assert(Pmtu > 1200 - 37),
    ?assert(Pmtu =< 1400 - 22),
    ordered_transfer(A, B, Id, 20, 50000),
    close(A, B).

sctp_pmtu(Pc) ->
    #{transport := #{sctp := #{pmtu := P}}} = webrtc:get_stats(Pc),
    P.

path_mtu_1200(Config) ->
    %% Datagrams above 1200 bytes are dropped: the DTLS handshake and
    %% every SCTP packet must fit.
    {A, B, Id} = setup_channel(Config, #{max_size => 1200}),
    ordered_transfer(A, B, Id, 20, 50000),
    close(A, B).

unreliable_channel_under_loss(Config) ->
    {A, B} = pair(Config, #{loss => 0.2}),
    ok = webrtc:create_data_channel(A, <<"u">>, #{ordered => false, max_retransmits => 0}),
    ?S:connect(A, B, 60000),
    Id = channel(A, <<"u">>),
    IdB = channel(B, <<"u">>),
    %% RFC 8832 §6: A sends ordered until it hears from B. A lost DCEP
    %% ACK would make this an ordered transfer; a message from B ends
    %% that phase.
    hear_from(B, IdB, A),
    N = 300,
    [ok = send_retry(A, Id, <<I:32>>) || I <- lists:seq(1, N)],
    Got = collect(B, N, 3000, []),
    ct:log("unreliable: ~p of ~p delivered", [length(Got), N]),
    %% Losses are not repaired: some messages are missing, and none is
    %% delivered twice.
    ?assert(length(Got) < N),
    ?assert(length(Got) > N div 2),
    ?assertEqual(length(Got), length(lists:usort(Got))),
    close(A, B).

hear_from(B, IdB, A) ->
    ok = send_retry(B, IdB, <<"hello">>),
    receive
        {webrtc, A, {channel_message, _, binary, <<"hello">>}} -> ok
    after 2000 -> hear_from(B, IdB, A)
    end.

media_recovers_with_nack(Config) ->
    {A, B} = pair(Config, #{loss => 0.1}),
    {ok, _} = webrtc:add_transceiver(A, video, #{}),
    {ok, _} = webrtc:add_transceiver(B, video, #{}),
    ?S:connect(A, B, 60000),
    N = 300,
    lists:foreach(
        fun(I) ->
            ok = webrtc:send_rtp(A, <<"0">>, <<I:32>>, #{timestamp => I * 3000}),
            timer:sleep(2)
        end,
        lists:seq(1, N)
    ),
    timer:sleep(2000),
    Got = lists:usort(rtp_payloads(B, [])),
    #{transport := #{media := #{counters := Counters}}} = webrtc:get_stats(A),
    ct:log("received ~p unique of ~p, sender counters ~p", [length(Got), N, Counters]),
    %% NACK + RTX repair most of the 10% loss.
    ?assert(maps:get(retransmitted, Counters, 0) > 0),
    ?assert(length(Got) >= N * 98 div 100),
    close(A, B).

rtp_payloads(B, Acc) ->
    receive
        {webrtc, B, {rtp, _, #rtp{payload = P}}} -> rtp_payloads(B, [P | Acc])
    after 0 ->
        Acc
    end.

%% A 20 s outage: SCTP retransmits at most every 3 s (the WebRTC
%% ceiling of the timer doubling), so a message queued during the outage
%% arrives within seconds of the path coming back. Doubling up to RTO.Max
%% would leave it waiting for the next retransmission, up to 15 s later.
long_outage_recovery(Config) ->
    Hole = webrtc_impair:blackhole(),
    {A, B, Id} = setup_channel(Config, #{blackhole => Hole}),
    webrtc_impair:set_blackhole(Hole, true),
    ok = send_retry(A, Id, <<"queued">>),
    timer:sleep(20000),
    webrtc_impair:set_blackhole(Hole, false),
    T0 = erlang:monotonic_time(millisecond),
    ?assertEqual([<<"queued">>], collect(B, 1, 10000, [])),
    Waited = erlang:monotonic_time(millisecond) - T0,
    ct:log("delivered ~p ms after the outage", [Waited]),
    ?assert(Waited < 4500),
    close(A, B).

blackhole_and_recovery(Config) ->
    Hole = webrtc_impair:blackhole(),
    {A, B, Id} = setup_channel(Config, #{blackhole => Hole}),
    webrtc_impair:set_blackhole(Hole, true),
    %% Messages sent during a 3 s outage are queued and retransmitted.
    [ok = send_retry(A, Id, <<I:32>>) || I <- lists:seq(1, 20)],
    timer:sleep(3000),
    webrtc_impair:set_blackhole(Hole, false),
    Got = collect(B, 20, 30000, []),
    ?assertEqual([<<I:32>> || I <- lists:seq(1, 20)], Got),
    ?assertEqual(connected, webrtc:connection_state(A)),
    close(A, B).
