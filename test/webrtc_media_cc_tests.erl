%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Congestion control in webrtc_media: transport-wide sequence numbers
%% on outgoing packets, feedback generation and consumption, the pacer
%% on the send path, REMB and the RTCP timeout circuit breaker.
-module(webrtc_media_cc_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").

-define(TWCC_ID, 3).
-define(PROFILE, srtp_aead_aes_128_gcm).

jsep() ->
    webrtc_jsep:new(#{
        ice_ufrag => <<"ufrag">>,
        ice_pwd => <<"passwordpasswordpassword">>,
        fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]
    }).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

%% Audio + video negotiated both ways with the default extensions
%% (transport-wide-cc has id 3). Returns {A, B, Material}.
pair() ->
    pair(#{}).

pair(MediaOpts) ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, _, B1} = webrtc_jsep:add_transceiver(video, #{}, B0),
    {ok, O, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, O, A2),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, wire(O), B1),
    {ok, Ans, B3} = webrtc_jsep:create_answer(#{}, B2),
    {ok, B4} = webrtc_jsep:set_local_description(answer, Ans, B3),
    {ok, A4} = webrtc_jsep:set_remote_description(answer, wire(Ans), A3),
    #{media := MA} = webrtc_jsep:negotiated(A4),
    #{media := MB} = webrtc_jsep:negotiated(B4),
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(?PROFILE)),
    Mk = fun(Media, Role) ->
        webrtc_media:set_srtp(?PROFILE, Material, Role, 0, webrtc_media:configure(Media, webrtc_media:new(MediaOpts)))
    end,
    {Mk(MA, server), Mk(MB, client), Material}.

deliver(Actions, S, Now) ->
    lists:foldl(
        fun({send, Bin}, {S0, Acc}) ->
            {S1, A} = webrtc_media:handle_packet(Bin, Now, S0),
            {S1, Acc ++ A}
        end,
        {S, []},
        [A || {send, _} = A <- Actions]
    ).

events(Actions) -> [E || {event, E} <- Actions].

twcc_seq(#rtp{ext = Ext}) ->
    {ok, B} = webrtc_rtp_ext:find(?TWCC_ID, Ext),
    {ok, Seq} = webrtc_rtp_ext:decode_twcc_seq(B),
    Seq.

%% Every packet carries the next transport-wide sequence number, across
%% transceivers.
transport_wide_sequence_test() ->
    {A0, B0, _} = pair(),
    {ok, O1, A1} = webrtc_media:send(<<"0">>, <<"audio">>, #{}, 0, A0),
    {ok, O2, A2} = webrtc_media:send(<<"1">>, <<"video">>, #{}, 1, A1),
    {ok, O3, _} = webrtc_media:send(<<"0">>, <<"audio">>, #{}, 2, A2),
    {_, Acts} = deliver(O1 ++ O2 ++ O3, B0, 5),
    [S1, S2, S3] = [twcc_seq(P) || {rtp, _, P} <- events(Acts)],
    ?assertEqual([S1 + 1, S1 + 2], [S2, S3]).

%% Send 10 packets every 10 ms, let B give feedback, feed it to A.
exchange(A0, B0) ->
    {Out, A1} = lists:foldl(
        fun(I, {Acc, A}) ->
            {ok, O, A2} = webrtc_media:send(<<"1">>, <<I:8000>>, #{timestamp => I * 3000}, I * 10, A),
            {Acc ++ [{I * 10 + 25, O}], A2}
        end,
        {[], A0},
        lists:seq(1, 10)
    ),
    B1 = lists:foldl(fun({At, O}, B) -> element(1, deliver(O, B, At)) end, B0, Out),
    feedback_due(A1, B1, 10, []).

%% Run B's timers (regular reports may come first) until its
%% transport-wide feedback reaches A, within 100 ms of the last packet;
%% A's actions of every step are kept.
feedback_due(A1, B1, Tries, Acc) when Tries > 0 ->
    Due = webrtc_media:next_timeout(B1),
    ?assert(Due =< 135 + 100),
    {B2, Fb} = webrtc_media:handle_timeout(Due, B1),
    {A2, Acts} = deliver(Fb, A1, Due + 25),
    case [P || {rtcp, _, #rtcp_twcc{} = P} <- events(Acts)] of
        [] -> feedback_due(A2, B2, Tries - 1, Acc ++ Acts);
        _ -> {A2, B2, Acc ++ Acts, Due + 25}
    end.

feedback_round_trip_test() ->
    {A0, B0, _} = pair(),
    {_, _, Acts, _} = exchange(A0, B0),
    Ev = events(Acts),
    [#rtcp_twcc{packets = Pkts}] = [P || {rtcp, _, #rtcp_twcc{} = P} <- Ev],
    ?assertEqual(10, length([X || {_, X} <- Pkts, X =/= not_received])),
    ?assertMatch([{bandwidth_estimate, _}], [E || {bandwidth_estimate, _} = E <- Ev]).

%% Once feedback flows, video goes through the pacer: a burst of large
%% packets leaves over time, not at once, and pacing can be turned off.
pacing_test() ->
    %% Probe padding would count among the packets sent.
    {A0, B0, _} = pair(#{cc => #{probing => false}}),
    {A1a, _, _, Now} = exchange(A0, B0),
    %% Regular RTCP already due goes out first.
    {A1, _} = webrtc_media:handle_timeout(Now, A1a),
    ?assertMatch(#{congestion_control := #{pacing := true}}, webrtc_media:stats(A1)),
    {Immediate, A2} = lists:foldl(
        fun(I, {N, A}) ->
            {ok, O, A3} = webrtc_media:send(<<"1">>, <<I:9600>>, #{}, Now, A),
            {N + length(O), A3}
        end,
        {0, A1},
        lists:seq(1, 50)
    ),
    ?assert(Immediate < 50),
    Next = webrtc_media:next_timeout(A2),
    ?assert(Next > Now),
    {A3, Later0} = webrtc_media:handle_timeout(Next, A2),
    Later = rtp_sends(Later0),
    ?assert(length(Later) >= 1),
    {Flushed, A4} = webrtc_media:set_congestion_control(#{pacing => false}, Next, A3),
    ?assertEqual(50, Immediate + length(Later) + length(rtp_sends(Flushed))),
    {ok, [_], _} = webrtc_media:send(<<"1">>, <<1:9600>>, #{}, Next, A4).

%% REMB from the peer is an input of the estimate.
remb_test() ->
    {A0, _, Material} = pair(),
    {Out, _} = webrtc_srtp:dtls_contexts(?PROFILE, Material, client, #{}),
    Remb = #rtcp_remb{sender_ssrc = 5, bitrate = 640000, ssrcs = []},
    {ok, Bin, _} = webrtc_srtp:protect_rtcp(webrtc_rtcp:encode([#rtcp_rr{ssrc = 5}, Remb]), Out),
    {A1, Acts} = webrtc_media:handle_packet(Bin, 0, A0),
    ?assert(lists:member({bandwidth_estimate, 640000}, events(Acts))),
    ?assertMatch(#{congestion_control := #{target_bitrate := 640000}}, webrtc_media:stats(A1)).

%% RFC 8083 §4.1: media sent, no RTCP report for 15 s.
rtcp_timeout_test() ->
    {A0, _, _} = pair(),
    {ok, _, A1} = webrtc_media:send(<<"1">>, <<"x">>, #{}, 0, A0),
    {ok, _, A2} = webrtc_media:send(<<"1">>, <<"y">>, #{}, 10000, A1),
    {_, Acts} = webrtc_media:handle_timeout(15000, A2),
    ?assert(lists:member({circuit_breaker, <<"1">>, rtcp_timeout}, events(Acts))).

%% Receiver reports from the peer reach the breaker: no timeout.
reports_keep_breaker_quiet_test() ->
    {A0, B0, _} = pair(),
    {A, _} = lists:foldl(
        fun(T, {A1, B1}) ->
            {ok, O, A2} = webrtc_media:send(<<"1">>, <<"z">>, #{}, T, A1),
            {B2, _} = deliver(O, B1, T),
            {B3, R} = webrtc_media:handle_timeout(T + 1, B2),
            {A3, Acts} = deliver(R, A2, T + 2),
            ?assertEqual([], [E || {circuit_breaker, _, _} = E <- events(Acts)]),
            {A4, Acts2} = webrtc_media:handle_timeout(T + 3, A3),
            ?assertEqual([], [E || {circuit_breaker, _, _} = E <- events(Acts2)]),
            {A4, B3}
        end,
        {A0, B0},
        lists:seq(0, 40000, 2000)
    ),
    ?assertMatch(#{congestion_control := #{circuit_breakers := #{<<"1">> := #{tripped := []}}}},
                 webrtc_media:stats(A)).

rtp_sends(Acts) ->
    [S || {send, B} = S <- Acts, webrtc_rtp:classify(B) =:= rtp].
