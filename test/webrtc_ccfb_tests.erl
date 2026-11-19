%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% RFC 8888 congestion control feedback in webrtc_cc and
%% webrtc_ccfb_receiver, with ECN (RFC 6679, RFC 8888 §6) and the ECN
%% circuit breaker (RFC 8083 §4.4).
-module(webrtc_ccfb_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

-define(R, webrtc_ccfb_receiver).

%%--------------------------------------------------------------------
%% Receiver
%%--------------------------------------------------------------------

%% One report per interval: the run from the first unreported sequence
%% number to the highest, with ECN and arrival offsets; gaps are not
%% received; the next report starts after the highest.
receiver_report_test() ->
    R0 = ?R:new(#{sender_ssrc => 9, interval => 100}),
    R1 = lists:foldl(fun({Seq, Ecn, At}, R) -> ?R:packet(5, Seq, Ecn, At, R) end, R0,
                     [{10, 2, 0}, {11, 3, 10}, {13, 0, 20}]),
    ?assertEqual(100, ?R:next_timeout(R1)),
    {[], R1} = ?R:handle_timeout(99, R1),
    {[#rtcp_ccfb{sender_ssrc = 9, reports = [{5, 10, Ms}]}], R2} = ?R:handle_timeout(100, R1),
    [{2, A0}, {3, A1}, not_received, {0, A3}] = Ms,
    ?assert(A0 > A1 andalso A1 > A3),
    ?assertEqual((100 * 1024 + 999) div 1000, A0),
    ?assertEqual(infinity, ?R:next_timeout(R2)),
    R3 = ?R:packet(5, 15, 2, 150, R2),
    {[#rtcp_ccfb{reports = [{5, 14, [not_received, {2, _}]}]}], _} = ?R:handle_timeout(250, R3),
    ?assertMatch(#{feedback_sent := 1, ce_received := 1}, ?R:stats(R2)).

%% Arrival offsets saturate at 0x1FFE.
receiver_old_arrival_test() ->
    R1 = ?R:packet(1, 0, 0, 0, ?R:new(#{interval => 100})),
    {[#rtcp_ccfb{reports = [{1, 0, [{0, 16#1FFE}]}]}], _} = ?R:handle_timeout(10000, R1).

%%--------------------------------------------------------------------
%% Sender
%%--------------------------------------------------------------------

cc(Ecn) ->
    webrtc_cc:configure(#{twcc_send => false, twcc_recv => false, sender_ssrc => 1, ccfb => true, ecn => Ecn},
                        webrtc_cc:new(#{})).

send(Cc, Seqs, Now) ->
    lists:foldl(fun(Seq, C) -> webrtc_cc:sent_rtp(<<"1">>, 77, Seq, 1200, Now, C) end, Cc, Seqs).

%% Our packets as the peer would report them, arriving 20 ms apart.
report(Seqs, Ecn) ->
    #rtcp_ccfb{sender_ssrc = 2, timestamp = 65536 * 10,
               reports = [{77, hd(Seqs), [{Ecn, (length(Seqs) - I) * 20} || I <- lists:seq(1, length(Seqs))]}]}.

%% The reports feed the estimator, as transport-cc feedback does.
estimator_input_test() ->
    Cc = send(cc(false), lists:seq(1, 10), 0),
    {_, Cc1} = webrtc_cc:rtcp(report(lists:seq(1, 10), 0), 100, Cc),
    #{estimator := #{delay_based := D}, ecn := off, ccfb := #{send := true}} = webrtc_cc:stats(Cc1),
    ?assert(is_integer(D)),
    ?assertNot(webrtc_cc:ecn_mark(Cc1)).

%% ECT(0) marks reported back as ECT(0) or CE validate ECN; reported as
%% not-ECT the path clears them: marking stops.
ecn_validation_test() ->
    C0 = cc(true),
    ?assert(webrtc_cc:ecn_mark(C0)),
    {_, C1} = webrtc_cc:rtcp(report(lists:seq(1, 4), 2), 100, send(C0, lists:seq(1, 4), 0)),
    ?assertMatch(#{ecn := on}, webrtc_cc:stats(C1)),
    {_, C2} = webrtc_cc:rtcp(report(lists:seq(1, 4), 0), 100, send(C0, lists:seq(1, 4), 0)),
    ?assertMatch(#{ecn := failed}, webrtc_cc:stats(C2)),
    ?assertNot(webrtc_cc:ecn_mark(C2)),
    %% Without ECN on the socket nothing is marked.
    ?assertNot(webrtc_cc:ecn_mark(cc(false))).

%% RFC 8083 §4.4: CE marks count as lost in the next report block the
%% circuit breaker sees.
ce_counts_as_loss_test() ->
    {_, C1} = webrtc_cc:rtcp(report(lists:seq(1, 4), 3), 100, send(cc(true), lists:seq(1, 4), 0)),
    Rb = #rtcp_rb{ssrc = 77, fraction_lost = 0},
    {_, C2} = webrtc_cc:report(<<"1">>, Rb, 50, 200, C1),
    Loss = fun(C) -> #{circuit_breakers := #{<<"1">> := #{loss := L}}} = webrtc_cc:stats(C), L end,
    %% Every packet CE marked: counted as lost.
    ?assert(Loss(C2) > 0.9),
    %% The next block without CE is taken as it is.
    {_, C3} = webrtc_cc:report(<<"1">>, Rb, 50, 300, C2),
    ?assertEqual(0.0, Loss(C3)).

%% Transport-cc negotiated as well: it is used, not RFC 8888.
twcc_preferred_test() ->
    Cc = webrtc_cc:configure(#{twcc_send => true, twcc_recv => true, sender_ssrc => 1, ccfb => true, ecn => true},
                             webrtc_cc:new(#{})),
    ?assertMatch(#{ccfb := #{send := false, receive_stats := undefined}, ecn := off}, webrtc_cc:stats(Cc)).
