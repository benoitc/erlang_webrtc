# W3C WebRTC statistics (webrtc-stats)

`webrtc:get_stats(Pc, #{format => w3c})` returns the statistics of [Identifiers for WebRTC's Statistics API](https://www.w3.org/TR/webrtc-stats/) (`webrtc_stats`): a map from stats id to a map of the dictionary's members, with `id`, `type` and `timestamp`. You need it to compare a call with what a browser reports, or to feed tools written for `getStats()`. `get_stats/1` keeps the internal format.

The member list below is the WebIDL of the specification (checked on 2026-11-17), one row per member. `webrtc_stats_SUITE` checks that every member reported belongs to its dictionary, that the required ones are there, that every id a report names exists, and that the counters of two peers agree; `webrtc_pc_interop_SUITE:stats_agree` compares them with Chrome's and Firefox's `getStats()`.

Status: **Reported** or **Not reported**, with the reason.


## RTCStats

| Member | Required | Status |
|---|---|---|
| timestamp | yes | Reported: ms since the Unix epoch |
| type | yes | Reported |
| id | yes | Reported |

## RTCRtpStreamStats

Inherits RTCStats.

| Member | Required | Status |
|---|---|---|
| ssrc | yes | Reported |
| kind | yes | Reported: from the m= section |
| transportId |  | Reported |
| codecId |  | Reported: the section's first codec (RFC 9429 §5.3.1) |

## RTCCodecStats (`codec`)

Inherits RTCStats.

| Member | Required | Status |
|---|---|---|
| payloadType | yes | Reported |
| transportId | yes | Reported |
| mimeType | yes | Reported |
| clockRate |  | Reported |
| channels |  | Reported: audio |
| sdpFmtpLine |  | Reported |

## RTCReceivedRtpStreamStats

Inherits RTCRtpStreamStats.

| Member | Required | Status |
|---|---|---|
| packetsReceived |  | Reported: every packet, retransmissions included |
| packetsReceivedWithEct1 |  | Not reported: L4S (ECT(1)) not used |
| packetsReceivedWithCe |  | Not reported: Not counted per stream |
| packetsReportedAsLost |  | Not reported: Not counted (RFC 8888) |
| packetsReportedAsLostButRecovered |  | Not reported: Not counted (RFC 8888) |
| packetsLost |  | Reported: RFC 3550 §6.4.1 (remote-inbound: the report block) |
| jitter |  | Reported: RFC 3550 §A.8, in seconds |

## RTCInboundRtpStreamStats (`inbound-rtp`)

Inherits RTCReceivedRtpStreamStats.

| Member | Required | Status |
|---|---|---|
| trackIdentifier | yes | Reported: the mid: there is no MediaStreamTrack |
| mid |  | Reported |
| remoteId |  | Reported |
| framesDecoded |  | Not reported: No media capture, encoding, decoding or playout in this library |
| keyFramesDecoded |  | Not reported: No media capture, encoding, decoding or playout in this library |
| framesRendered |  | Not reported: No media capture, encoding, decoding or playout in this library |
| framesDropped |  | Reported with `frames` on the transceiver, from the frame buffer: frames that missed packets or a frame they depend on |
| frameWidth |  | Reported with `frames` on the transceiver, from the frame buffer: from the last key frame (VP8, VP9 headers, H.264 SPS, AV1 sequence header) |
| frameHeight |  | Reported with `frames` on the transceiver, from the frame buffer: as frameWidth |
| framesPerSecond |  | Reported with `frames` on the transceiver, from the frame buffer: frames released in the last second |
| qpSum |  | Not reported: No media capture, encoding, decoding or playout in this library |
| totalDecodeTime |  | Not reported: No media capture, encoding, decoding or playout in this library |
| totalInterFrameDelay |  | Not reported: No media capture, encoding, decoding or playout in this library |
| totalSquaredInterFrameDelay |  | Not reported: No media capture, encoding, decoding or playout in this library |
| pauseCount |  | Not reported: No media capture, encoding, decoding or playout in this library |
| totalPausesDuration |  | Not reported: No media capture, encoding, decoding or playout in this library |
| freezeCount |  | Not reported: No media capture, encoding, decoding or playout in this library |
| totalFreezesDuration |  | Not reported: No media capture, encoding, decoding or playout in this library |
| lastPacketReceivedTimestamp |  | Reported |
| headerBytesReceived |  | Reported |
| packetsDiscarded |  | Reported with `frames` on the transceiver, from the frame buffer: packets that came after their frame left |
| fecBytesReceived |  | Not reported: No FEC yet |
| fecPacketsReceived |  | Not reported: No FEC yet |
| fecPacketsDiscarded |  | Not reported: No FEC yet |
| bytesReceived |  | Reported: payload octets |
| nackCount |  | Reported |
| firCount |  | Reported |
| pliCount |  | Reported |
| totalProcessingDelay |  | Not reported: No media capture, encoding, decoding or playout in this library |
| estimatedPlayoutTimestamp |  | Not reported: No media capture, encoding, decoding or playout in this library |
| jitterBufferDelay |  | Reported with `frames` on the transceiver, from the frame buffer |
| jitterBufferTargetDelay |  | Reported with `frames` on the transceiver, from the frame buffer |
| jitterBufferEmittedCount |  | Reported with `frames` on the transceiver, from the frame buffer |
| jitterBufferMinimumDelay |  | Reported with `frames` on the transceiver, from the frame buffer: three times the jitter, before `min_delay` and the playout-delay extension |
| totalSamplesReceived |  | Not reported: No media capture, encoding, decoding or playout in this library |
| concealedSamples |  | Not reported: No media capture, encoding, decoding or playout in this library |
| silentConcealedSamples |  | Not reported: No media capture, encoding, decoding or playout in this library |
| concealmentEvents |  | Not reported: No media capture, encoding, decoding or playout in this library |
| insertedSamplesForDeceleration |  | Not reported: No media capture, encoding, decoding or playout in this library |
| removedSamplesForAcceleration |  | Not reported: No media capture, encoding, decoding or playout in this library |
| audioLevel |  | Reported when the RFC 6464 extension is negotiated: the level the sender put in the last packet, not one measured on decoded audio |
| totalAudioEnergy |  | Reported with audioLevel: the level squared times each packet's duration (Opus TOC, G.711 and G.722 size) |
| totalSamplesDuration |  | Reported with audioLevel |
| framesReceived |  | Reported with `frames` on the transceiver, from the frame buffer |
| decoderImplementation |  | Not reported: No media capture, encoding, decoding or playout in this library |
| playoutId |  | Not reported: No media capture, encoding, decoding or playout in this library |
| powerEfficientDecoder |  | Not reported: No media capture, encoding, decoding or playout in this library |
| framesAssembledFromMultiplePackets |  | Reported with `frames` on the transceiver, from the frame buffer |
| totalAssemblyTime |  | Reported with `frames` on the transceiver, from the frame buffer |
| retransmittedPacketsReceived |  | Reported: RTX (RFC 4588) |
| retransmittedBytesReceived |  | Reported |
| rtxSsrc |  | Reported |
| fecSsrc |  | Not reported: No FEC yet |
| totalCorruptionProbability |  | Not reported: No media capture, encoding, decoding or playout in this library |
| totalSquaredCorruptionProbability |  | Not reported: No media capture, encoding, decoding or playout in this library |
| corruptionMeasurements |  | Not reported: No media capture, encoding, decoding or playout in this library |

## RTCRemoteInboundRtpStreamStats (`remote-inbound-rtp`)

Inherits RTCReceivedRtpStreamStats.

| Member | Required | Status |
|---|---|---|
| localId |  | Reported |
| roundTripTime |  | Reported: from LSR and DLSR (RFC 3550 §6.4.1) |
| totalRoundTripTime |  | Reported |
| fractionLost |  | Reported |
| roundTripTimeMeasurements |  | Reported |
| packetsWithBleachedEct1Marking |  | Not reported: L4S (ECT(1)) not used |

## RTCSentRtpStreamStats

Inherits RTCRtpStreamStats.

| Member | Required | Status |
|---|---|---|
| packetsSent |  | Reported: retransmissions included, on the RTX stream or not |
| bytesSent |  | Reported: payload octets, retransmissions included |

## RTCOutboundRtpStreamStats (`outbound-rtp`)

Inherits RTCSentRtpStreamStats.

| Member | Required | Status |
|---|---|---|
| mid |  | Reported |
| mediaSourceId |  | Not reported: No media capture, encoding, decoding or playout in this library |
| remoteId |  | Reported |
| rid |  | Reported |
| encodingIndex |  | Reported: the layer's place in the send encodings, 0 for a single stream |
| headerBytesSent |  | Reported |
| retransmittedPacketsSent |  | Reported |
| retransmittedBytesSent |  | Reported: payload octets of RTX packets; a retransmission without RTX replays the protected packet and adds no bytes |
| rtxSsrc |  | Reported when RTX is negotiated |
| targetBitrate |  | Not reported: The target is per transport (candidate pair availableOutgoingBitrate), not per encoder |
| totalEncodedBytesTarget |  | Not reported: No media capture, encoding, decoding or playout in this library |
| frameWidth |  | Reported: from the key frames sent (VP8, VP9 headers, H.264 SPS, AV1 sequence header) |
| frameHeight |  | Reported: as frameWidth |
| framesPerSecond |  | Reported: frames sent in the last second |
| framesSent |  | Reported: video frames, by marker bit |
| hugeFramesSent |  | Reported: frames of at least 2.5 times the average size of the frames sent before |
| framesEncoded |  | Not reported: No media capture, encoding, decoding or playout in this library |
| keyFramesEncoded |  | Not reported: No media capture, encoding, decoding or playout in this library |
| qpSum |  | Not reported: No media capture, encoding, decoding or playout in this library |
| psnrSum |  | Not reported: No media capture, encoding, decoding or playout in this library |
| psnrMeasurements |  | Not reported: No media capture, encoding, decoding or playout in this library |
| totalEncodeTime |  | Not reported: No media capture, encoding, decoding or playout in this library |
| totalPacketSendDelay |  | Reported: the time packets wait in the pacer |
| qualityLimitationReason |  | Not reported: No media capture, encoding, decoding or playout in this library |
| qualityLimitationDurations |  | Not reported: No media capture, encoding, decoding or playout in this library |
| qualityLimitationResolutionChanges |  | Not reported: No media capture, encoding, decoding or playout in this library |
| nackCount |  | Reported |
| firCount |  | Reported |
| pliCount |  | Reported |
| encoderImplementation |  | Not reported: No media capture, encoding, decoding or playout in this library |
| powerEfficientEncoder |  | Not reported: No media capture, encoding, decoding or playout in this library |
| active |  | Reported |
| scalabilityMode |  | Not reported: No media capture, encoding, decoding or playout in this library |
| packetsSentWithEct1 |  | Not reported: L4S (ECT(1)) not used |

## RTCRemoteOutboundRtpStreamStats (`remote-outbound-rtp`)

Inherits RTCSentRtpStreamStats.

| Member | Required | Status |
|---|---|---|
| localId |  | Reported |
| remoteTimestamp |  | Reported: the sender report NTP time |
| reportsSent |  | Reported |
| roundTripTime |  | Reported: from the DLRR block (RFC 3611 §4.5) answering our Receiver Reference Time block, which libwebrtc sends |
| totalRoundTripTime |  | Reported: as roundTripTime |
| roundTripTimeMeasurements |  | Reported: as roundTripTime |

## RTCMediaSourceStats

Inherits RTCStats.

Not reported: No media capture, encoding, decoding or playout in this library.


## RTCAudioSourceStats

Inherits RTCMediaSourceStats.

Not reported: No media capture, encoding, decoding or playout in this library.


## RTCVideoSourceStats

Inherits RTCMediaSourceStats.

Not reported: No media capture, encoding, decoding or playout in this library.


## RTCAudioPlayoutStats

Inherits RTCStats.

Not reported: No media capture, encoding, decoding or playout in this library.


## RTCPeerConnectionStats (`peer-connection`)

Inherits RTCStats.

| Member | Required | Status |
|---|---|---|
| dataChannelsOpened |  | Reported |
| dataChannelsClosed |  | Reported |

## RTCDataChannelStats (`data-channel`)

Inherits RTCStats.

| Member | Required | Status |
|---|---|---|
| label |  | Reported |
| protocol |  | Reported |
| dataChannelIdentifier |  | Reported |
| state | yes | Reported |
| messagesSent |  | Reported |
| bytesSent |  | Reported |
| messagesReceived |  | Reported |
| bytesReceived |  | Reported |

## RTCTransportStats (`transport`)

Inherits RTCStats.

| Member | Required | Status |
|---|---|---|
| packetsSent |  | Reported: datagrams other than ICE checks |
| packetsReceived |  | Reported |
| bytesSent |  | Reported |
| bytesReceived |  | Reported |
| iceRole |  | Reported |
| iceLocalUsernameFragment |  | Reported |
| dtlsState | yes | Reported |
| iceState |  | Reported |
| selectedCandidatePairId |  | Reported |
| localCertificateId |  | Reported |
| remoteCertificateId |  | Reported |
| tlsVersion |  | Reported |
| dtlsCipher |  | Reported |
| dtlsRole |  | Reported |
| srtpCipher |  | Reported |
| selectedCandidatePairChanges |  | Reported |
| ccfbMessagesSent |  | Reported: RFC 8888 feedback packets |
| ccfbMessagesReceived |  | Reported: RFC 8888 feedback packets |

## RTCIceCandidateStats (`local-candidate, remote-candidate`)

Inherits RTCStats.

| Member | Required | Status |
|---|---|---|
| transportId | yes | Reported |
| address |  | Reported |
| port |  | Reported |
| protocol |  | Reported |
| candidateType | yes | Reported |
| priority |  | Reported |
| url |  | Reported for server reflexive and relay candidates of a server given by URI |
| relayProtocol |  | Reported for relay candidates: how the TURN server is reached |
| foundation |  | Reported |
| relatedAddress |  | Reported |
| relatedPort |  | Reported |
| usernameFragment |  | Reported |
| tcpType |  | Reported |

## RTCIceCandidatePairStats (`candidate-pair`)

Inherits RTCStats.

| Member | Required | Status |
|---|---|---|
| transportId | yes | Reported |
| localCandidateId | yes | Reported |
| remoteCandidateId | yes | Reported |
| state | yes | Reported |
| nominated |  | Reported |
| packetsSent |  | Reported: the selected pair: the transport's datagrams |
| packetsReceived |  | Reported |
| bytesSent |  | Reported |
| bytesReceived |  | Reported |
| lastPacketSentTimestamp |  | Reported on the selected pair |
| lastPacketReceivedTimestamp |  | Reported on the selected pair |
| totalRoundTripTime |  | Reported: every check and consent response with a round trip (not those of retransmitted requests) |
| currentRoundTripTime |  | Reported: the last check |
| availableOutgoingBitrate |  | Reported: the congestion control target |
| availableIncomingBitrate |  | Not reported: Receiver side estimate (REMB) not computed |
| requestsReceived |  | Reported |
| requestsSent |  | Reported |
| responsesReceived |  | Reported |
| responsesSent |  | Reported |
| consentRequestsSent |  | Reported |
| packetsDiscardedOnSend |  | Reported on the selected pair: datagrams the socket refused |
| bytesDiscardedOnSend |  | Reported on the selected pair |

## RTCCertificateStats (`certificate`)

Inherits RTCStats.

| Member | Required | Status |
|---|---|---|
| fingerprint | yes | Reported |
| fingerprintAlgorithm | yes | Reported: sha-256 |
| base64Certificate | yes | Reported |
| issuerCertificateId |  | Not reported: Self-signed certificates only |
