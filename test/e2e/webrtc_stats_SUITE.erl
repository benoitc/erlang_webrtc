%% The W3C statistics (webrtc_stats) of a call between two of our peers:
%% every member is one of its dictionary's, every required member is
%% there, every id a report refers to exists, and the counters of the
%% two sides agree.
-module(webrtc_stats_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([members_follow_the_dictionaries/1, references_resolve/1, counters_agree/1, internal_format_unchanged/1]).

-define(S, webrtc_test_signal).

all() -> [members_follow_the_dictionaries, references_resolve, counters_agree, internal_format_unchanged].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    ?S:flush(),
    [{call, call()} | Config].

end_per_testcase(_TC, Config) ->
    {A, B, _, _} = ?config(call, Config),
    webrtc:close(A),
    webrtc:close(B),
    ?S:flush(),
    ok.

%%====================================================================
%% The dictionaries of https://www.w3.org/TR/webrtc-stats/ (WebIDL):
%% {Members, Required}, members of the parents included.
%%====================================================================

stats() -> {[id, type, timestamp], [id, type, timestamp]}.
rtp_stream() -> extend(stats(), [ssrc, kind, transportId, codecId], [ssrc, kind]).
received() -> extend(rtp_stream(), [packetsReceived, packetsReceivedWithEct1, packetsReceivedWithCe, packetsReportedAsLost,
                                    packetsReportedAsLostButRecovered, packetsLost, jitter], []).
sent() -> extend(rtp_stream(), [packetsSent, bytesSent], []).

dictionary(<<"codec">>) ->
    extend(stats(), [payloadType, transportId, mimeType, clockRate, channels, sdpFmtpLine],
           [payloadType, transportId, mimeType]);
dictionary(<<"inbound-rtp">>) ->
    extend(received(), [trackIdentifier, mid, remoteId, framesDecoded, keyFramesDecoded, framesRendered, framesDropped,
                        frameWidth, frameHeight, framesPerSecond, qpSum, totalDecodeTime, totalInterFrameDelay,
                        totalSquaredInterFrameDelay, pauseCount, totalPausesDuration, freezeCount, totalFreezesDuration,
                        lastPacketReceivedTimestamp, headerBytesReceived, packetsDiscarded, fecBytesReceived,
                        fecPacketsReceived, fecPacketsDiscarded, bytesReceived, nackCount, firCount, pliCount,
                        totalProcessingDelay, estimatedPlayoutTimestamp, jitterBufferDelay, jitterBufferTargetDelay,
                        jitterBufferEmittedCount, jitterBufferMinimumDelay, totalSamplesReceived, concealedSamples,
                        silentConcealedSamples, concealmentEvents, insertedSamplesForDeceleration,
                        removedSamplesForAcceleration, audioLevel, totalAudioEnergy, totalSamplesDuration, framesReceived,
                        decoderImplementation, playoutId, powerEfficientDecoder, framesAssembledFromMultiplePackets,
                        totalAssemblyTime, retransmittedPacketsReceived, retransmittedBytesReceived, rtxSsrc, fecSsrc,
                        totalCorruptionProbability, totalSquaredCorruptionProbability, corruptionMeasurements],
           [trackIdentifier]);
dictionary(<<"remote-inbound-rtp">>) ->
    extend(received(), [localId, roundTripTime, totalRoundTripTime, fractionLost, roundTripTimeMeasurements,
                        packetsWithBleachedEct1Marking], []);
dictionary(<<"outbound-rtp">>) ->
    extend(sent(), [mid, mediaSourceId, remoteId, rid, encodingIndex, headerBytesSent, retransmittedPacketsSent,
                    retransmittedBytesSent, rtxSsrc, targetBitrate, totalEncodedBytesTarget, frameWidth, frameHeight,
                    framesPerSecond, framesSent, hugeFramesSent, framesEncoded, keyFramesEncoded, qpSum, psnrSum,
                    psnrMeasurements, totalEncodeTime, totalPacketSendDelay, qualityLimitationReason,
                    qualityLimitationDurations, qualityLimitationResolutionChanges, nackCount, firCount, pliCount,
                    encoderImplementation, powerEfficientEncoder, active, scalabilityMode, packetsSentWithEct1], []);
dictionary(<<"remote-outbound-rtp">>) ->
    extend(sent(), [localId, remoteTimestamp, reportsSent, roundTripTime, totalRoundTripTime,
                    roundTripTimeMeasurements], []);
dictionary(<<"peer-connection">>) ->
    extend(stats(), [dataChannelsOpened, dataChannelsClosed], []);
dictionary(<<"data-channel">>) ->
    extend(stats(), [label, protocol, dataChannelIdentifier, state, messagesSent, bytesSent, messagesReceived,
                     bytesReceived], [state]);
dictionary(<<"transport">>) ->
    extend(stats(), [packetsSent, packetsReceived, bytesSent, bytesReceived, iceRole, iceLocalUsernameFragment, dtlsState,
                     iceState, selectedCandidatePairId, localCertificateId, remoteCertificateId, tlsVersion, dtlsCipher,
                     dtlsRole, srtpCipher, selectedCandidatePairChanges, ccfbMessagesSent, ccfbMessagesReceived],
           [dtlsState]);
dictionary(T) when T =:= <<"local-candidate">>; T =:= <<"remote-candidate">> ->
    extend(stats(), [transportId, address, port, protocol, candidateType, priority, url, relayProtocol, foundation,
                     relatedAddress, relatedPort, usernameFragment, tcpType], [transportId, candidateType]);
dictionary(<<"candidate-pair">>) ->
    extend(stats(), [transportId, localCandidateId, remoteCandidateId, state, nominated, packetsSent, packetsReceived,
                     bytesSent, bytesReceived, lastPacketSentTimestamp, lastPacketReceivedTimestamp, totalRoundTripTime,
                     currentRoundTripTime, availableOutgoingBitrate, availableIncomingBitrate, requestsReceived,
                     requestsSent, responsesReceived, responsesSent, consentRequestsSent, packetsDiscardedOnSend,
                     bytesDiscardedOnSend], [transportId, localCandidateId, remoteCandidateId, state]);
dictionary(<<"certificate">>) ->
    extend(stats(), [fingerprint, fingerprintAlgorithm, base64Certificate, issuerCertificateId],
           [fingerprint, fingerprintAlgorithm, base64Certificate]).

extend({M, R}, Members, Required) -> {M ++ Members, R ++ Required}.

%% Members of type DOMString or an enum.
strings() ->
    [id, type, kind, mimeType, sdpFmtpLine, trackIdentifier, mid, rid, label, protocol, state, iceRole,
     iceLocalUsernameFragment, dtlsState, iceState, tlsVersion, dtlsCipher, dtlsRole, srtpCipher, address,
     candidateType, foundation, relatedAddress, usernameFragment, tcpType, relayProtocol, url, fingerprint,
     fingerprintAlgorithm, base64Certificate] ++ references().

%% Members naming another stats object.
references() ->
    [transportId, codecId, remoteId, localId, localCandidateId, remoteCandidateId, selectedCandidatePairId,
     localCertificateId, remoteCertificateId, issuerCertificateId].

%%====================================================================
%% A call: audio, video and a data channel, both ways
%%====================================================================

call() ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    [{ok, _} = webrtc:add_transceiver(P, K, #{}) || P <- [A, B], K <- [audio, video]],
    ok = webrtc:create_data_channel(A, <<"stats">>, #{}),
    ?S:connect(A, B),
    {ok, {datachannel_open, IdA, _, _, _}} = ?S:wait(A, fun({datachannel_open, _, L, _, _}) -> L =:= <<"stats">>; (_) -> false end, 10000),
    {ok, {datachannel_open, IdB, _, _, _}} = ?S:wait(B, fun({datachannel_open, _, L, _, _}) -> L =:= <<"stats">>; (_) -> false end, 10000),
    [ok = webrtc:send_rtp(A, <<"0">>, <<"opus", N>>, #{timestamp => N * 960}) || N <- lists:seq(1, 20)],
    [ok = webrtc:send_rtp(A, <<"1">>, <<"vp8", N>>, #{timestamp => N * 3000, marker => true}) || N <- lists:seq(1, 20)],
    [ok = webrtc:send_rtp(B, <<"0">>, <<"back", N>>, #{timestamp => N * 960}) || N <- lists:seq(1, 10)],
    [ok = webrtc:send_data(A, IdA, text, <<"message ", (integer_to_binary(N))/binary>>) || N <- lists:seq(1, 5)],
    {ok, _} = ?S:wait(B, fun({rtp, <<"1">>, #rtp{payload = <<"vp8", 20>>}}) -> true; (_) -> false end, 10000),
    {ok, _} = ?S:wait(A, fun({rtp, <<"0">>, #rtp{payload = <<"back", 10>>}}) -> true; (_) -> false end, 10000),
    {ok, _} = ?S:wait(B, fun({channel_message, _, text, <<"message 5">>}) -> true; (_) -> false end, 10000),
    %% Let a round of RTCP reports go each way.
    timer:sleep(2500),
    {A, B, IdA, IdB}.

report(Pc) -> webrtc:get_stats(Pc, #{format => w3c}).

%%====================================================================
%% Cases
%%====================================================================

members_follow_the_dictionaries(Config) ->
    {A, B, _, _} = ?config(call, Config),
    [begin
         R = report(P),
         ct:pal("~p", [R]),
         maps:foreach(
             fun(Id, #{id := Id2, type := Type} = O) ->
                 ?assertEqual(Id, Id2),
                 {Members, Required} = dictionary(Type),
                 ?assertEqual({Id, []}, {Id, [K || K <- maps:keys(O), not lists:member(K, Members)]}),
                 ?assertEqual({Id, []}, {Id, [K || K <- Required, not maps:is_key(K, O)]}),
                 %% DOMString and enum members are strings.
                 ?assertEqual({Id, []}, {Id, [K || K := V <- O, lists:member(K, strings()), not is_binary(V)]})
             end,
             R),
         Types = lists:usort([T || _ := #{type := T} <- R]),
         [?assert(lists:member(T, Types)) || T <- [<<"codec">>, <<"inbound-rtp">>, <<"outbound-rtp">>,
                                                   <<"remote-inbound-rtp">>, <<"remote-outbound-rtp">>,
                                                   <<"peer-connection">>, <<"data-channel">>, <<"transport">>,
                                                   <<"candidate-pair">>, <<"local-candidate">>,
                                                   <<"remote-candidate">>, <<"certificate">>]]
     end || P <- [A, B]].

references_resolve(Config) ->
    {A, B, _, _} = ?config(call, Config),
    [begin
         R = report(P),
         Dangling = [{Id, K, V} || Id := O <- R, K <- references(), V <- [maps:get(K, O, undefined)],
                                   V =/= undefined, not maps:is_key(V, R)],
         ?assertEqual([], Dangling)
     end || P <- [A, B]].

counters_agree(Config) ->
    {A, B, _, _} = ?config(call, Config),
    RA = report(A),
    RB = report(B),
    Out = [O || _ := #{type := <<"outbound-rtp">>} = O <- RA],
    In = maps:from_list([{S, O} || _ := #{type := <<"inbound-rtp">>, ssrc := S} = O <- RB]),
    [begin
         #{packetsReceived := Rp, bytesReceived := Rb} = maps:get(S, In),
         ?assertEqual({S, P, Bs}, {S, Rp, Rb})
     end || #{ssrc := S, packetsSent := P, bytesSent := Bs} <- Out, P > 0],
    %% The data channel: five messages from A.
    [#{messagesSent := 5, bytesSent := Sent}] = [O || _ := #{type := <<"data-channel">>} = O <- RA],
    [#{messagesReceived := 5, bytesReceived := Sent}] = [O || _ := #{type := <<"data-channel">>} = O <- RB],
    [#{dataChannelsOpened := 1}] = [O || _ := #{type := <<"peer-connection">>} = O <- RA],
    %% DTLS 1.3 with AES-GCM and the SRTP profile it negotiated.
    [#{dtlsState := <<"connected">>, tlsVersion := <<"FEFC">>, srtpCipher := _}] =
        [O || _ := #{type := <<"transport">>} = O <- RA].

%% Without options get_stats/1 keeps its format.
internal_format_unchanged(Config) ->
    {A, _, _, _} = ?config(call, Config),
    ?assertMatch(#{connection_state := connected, transport := #{media := _}}, webrtc:get_stats(A)).
