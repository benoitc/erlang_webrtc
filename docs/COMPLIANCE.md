# Compliance matrix

This is the index of normative requirements the stack tracks, by protocol. Each protocol page lists requirements with their specification section, implementing module, test and status. Use it to see what is supported and what is missing before relying on a feature.

Statuses:

| Status | Meaning |
|---|---|
| Not implemented | No code yet |
| Implemented, untested | Code exists, no test covers it |
| Unit tested | Covered by eunit or PropEr tests |
| E2E tested | Covered by an Erlang to Erlang test over real sockets |
| Interoperability tested | Covered by a test against an independent implementation |
| Non-compliant / known limitation | Deviates from the specification, see notes |

A protocol is complete only when its mandatory requirements reach E2E tested, and interoperability tested where an independent peer exists.

## Summary

What works today, end to end and against independent implementations (see [INTEROP.md](INTEROP.md)):

- Full ICE and ICE-Lite, trickle, consent freshness, ICE restart in both directions, the `ice2` option with checks paced at Ta, ICE-TCP (passive and active), TURN relays reached over UDP, TCP or TLS.
- Remote candidates with mDNS `.local` names (Chromium's default) or DNS names, resolved over IPv4 and IPv6 multicast without blocking the transport; optional mDNS names for our own host candidates, answered with NSEC for the family they lack; a host address a STUN server maps to itself is found public and signaled as it is afterwards.
- DTLS 1.3 (RFC 9147) by default with fallback to DTLS 1.2 (use_srtp, extended master secret), connection IDs on request (1.2 and 1.3; 1.2 CIDs verified with mbedTLS and pion/dtls): 1.3 verified with OpenSSL 4.1 and Chromium in both roles, 1.2 with OTP ssl, OpenSSL, Pion and aiortc.
- SRTP and SRTCP (AES-CM and AES-GCM profiles), with CSRCs and header extensions encrypted by cryptex (RFC 9335) when the peer accepts it, verified with Pion, and single elements such as the audio level encrypted with RFC 6904 when negotiated.
- One transport for a BUNDLE group, or one per group or unbundled section, offered and answered, verified with Chromium and Firefox.
- RTP/RTCP with BUNDLE demultiplexing, sender and receiver reports, NACK with RTX, PLI and FIR, audio RED (RFC 2198) checked against Chromium and GStreamer, video FEC with ULPFEC in RED (checked against GStreamer) and FlexFEC (RFC 8627), SLI and RPSI handed to the encoder and sent when the decoder asks, rapid synchronisation of new streams (RFC 6051, ntp-64 and ntp-56, SR requests), one-byte and two-byte header extensions mixed when `extmap-allow-mixed` is negotiated, forwarding without decoding.
- Frame assembly and a jitter buffer for VP8, VP9, H.264, AV1 and audio, checked against GStreamer's payloaders and ffmpeg, Chromium and Firefox.
- The W3C statistics, with the decoder and encoder members from a codec plugin or the application.
- SCTP over DTLS with data channels: reliable, unordered, partially reliable, large messages, channel close by stream reset, priorities through a weighted fair queueing scheduler.
- JSEP offer/answer with answers and re-offers checked against the offer, renegotiation, rollback from offers and provisional answers, pranswer; a new DTLS certificate is accepted only with an ICE restart and starts a new association (RFC 8842).
- Simulcast with rid negotiation and the rid / repaired-rid header extensions: receiving layers from Chromium, sending layers to Pion, asking Firefox for layers it then sends, per-layer NACK, RTX, keyframe requests and RTP stream pause and resume (RFC 7728, between Erlang peers).
- Congestion control: transport-wide CC feedback in both directions, RFC 8888 feedback with ECN when transport-cc is not negotiated, a GCC delay and loss based estimator, bandwidth probing at the start (in simulation a 2 Mbps link reaches 70% in 200 ms), while application limited, after a drop and on a raised maximum, a pacer with audio and retransmission priority, RFC 8083 circuit breakers that halt a stream (timeouts) or cut its rate by ten then halt it (congestion), and receiver report based control for peers without transport-cc. Chromium's estimate grows on our feedback and encodes its top simulcast layer. The RFC 8867 evaluation cases pass in simulation, fairness between flows with different RTTs included; the two left are coupled congestion control (RFC 8699, not implemented) and multiple bottlenecks (not tested). TMMBR and TMMBN (RFC 5104) limit a sender with a bounding set, in both directions.
- DSCP marking by flow type and priority (RFC 8835, RFC 8837) on UDP and TCP, with a lower drop precedence for key frames.
- Behavior under loss, bursts, reordering, duplication, jitter, a 1200 byte MTU, outages, spoofing, replay, floods and SSRC churn; per-connection state stays bounded (DTLS reassembly, receive streams, SRTP state, data channel message size, per-SSRC statistics, the 0-RTT replay table). Private keys, credentials and session keys stay out of logs and crash reports, every process of a peer connection ends with it, and 0-RTT tickets stop working when the application restarts.

The gaps that once mattered for a full WebRTC deployment are closed; what remains not implemented is listed per area, with the reason, in the pages below.

Codec encoding and decoding are not part of the library. Opus, G.711, VP8, VP9, H.264 and AV1 are negotiated, packetized, assembled into frames and forwarded; producing or consuming the media is the application's job, or a codec plugin's (`webrtc_media_codec`).

## Specifications tracked

Superseded documents named in older WebRTC RFCs are tracked under their replacement.

| Area | Specification | Replaces / updates | Page |
|---|---|---|---|
| STUN | RFC 8489 | obsoletes RFC 5389 | [stun](compliance/stun.md) |
| STUN test vectors | RFC 5769 | | [stun](compliance/stun.md) |
| ICE | RFC 8445 | updated by RFC 8863 | [ice](compliance/ice.md) |
| ICE SDP | RFC 8839 | | [ice](compliance/ice.md) |
| Trickle ICE | RFC 8838 | | [ice](compliance/ice.md) |
| Consent freshness | RFC 7675 | | [ice](compliance/ice.md) |
| mDNS ICE candidates | draft-ietf-mmusic-mdns-ice-candidates-03 | | [ice](compliance/ice.md) |
| Multicast DNS | RFC 6762 | | [ice](compliance/ice.md) |
| TURN | RFC 8656 | obsoletes RFC 5766 | [turn](compliance/turn.md) |
| STUN URI | RFC 7064 | | [turn](compliance/turn.md) |
| TURN URI | RFC 7065 | | [turn](compliance/turn.md) |
| TURN server discovery | RFC 5928 | | [turn](compliance/turn.md) |
| Multiplexing | RFC 7983 | updated by RFC 9443 | [transport](compliance/transport.md) |
| DTLS 1.2 | RFC 6347 | | [dtls](compliance/dtls.md) |
| DTLS 1.3 | RFC 9147 | | [dtls](compliance/dtls.md) |
| Extended master secret | RFC 7627 | | [dtls](compliance/dtls.md) |
| DTLS-SRTP | RFC 5764 | updated by RFC 7983 | [dtls](compliance/dtls.md) |
| ICE and DTLS | RFC 8842 | | [dtls](compliance/dtls.md) |
| Fingerprints | RFC 8122 | updated by RFC 8842 | [dtls](compliance/dtls.md) |
| SRTP | RFC 3711 | | [srtp](compliance/srtp.md) |
| SRTP AES-GCM | RFC 7714 | | [srtp](compliance/srtp.md) |
| Encrypted header extensions | RFC 6904 | | [srtp](compliance/srtp.md) |
| Cryptex | RFC 9335 | | [srtp](compliance/srtp.md) |
| RTP/RTCP | RFC 3550 | | [rtp](compliance/rtp.md) |
| RTP usage in WebRTC | RFC 8834 | | [rtp](compliance/rtp.md) |
| AVPF | RFC 4585 | | [rtp](compliance/rtp.md) |
| CCM | RFC 5104 | | [rtp](compliance/rtp.md) |
| RTP stream pause and resume | RFC 7728 | | [rtp](compliance/rtp.md) |
| Header extensions | RFC 8285 | | [rtp](compliance/rtp.md) |
| RTX | RFC 4588 | | [rtp](compliance/rtp.md) |
| Redundant audio | RFC 2198 | | [rtp](compliance/rtp.md) |
| WebRTC FEC | RFC 8854 | | [rtp](compliance/rtp.md) |
| rtcp-mux | RFC 5761, RFC 8858 | | [rtp](compliance/rtp.md) |
| Congestion control | RFC 8836, RFC 8888 | | [rtp](compliance/rtp.md) |
| Congestion control test cases | RFC 8867, RFC 8868 | | [rtp](compliance/rtp.md) |
| SCTP | RFC 9260 | obsoletes RFC 4960 | [sctp](compliance/sctp.md) |
| PR-SCTP | RFC 3758 | | [sctp](compliance/sctp.md) |
| Stream reconfiguration | RFC 6525 | | [sctp](compliance/sctp.md) |
| Message interleaving | RFC 8260 | | [sctp](compliance/sctp.md) |
| SCTP over DTLS | RFC 8261 | | [sctp](compliance/sctp.md) |
| Zero checksum | RFC 9653 | | [sctp](compliance/sctp.md) |
| Data channels | RFC 8831 | | [datachannel](compliance/datachannel.md) |
| DCEP | RFC 8832 | | [datachannel](compliance/datachannel.md) |
| SDP for SCTP | RFC 8841 | | [sdp](compliance/sdp.md) |
| SDP | RFC 8866 | obsoletes RFC 4566 | [sdp](compliance/sdp.md) |
| Offer/answer | RFC 3264 | | [sdp](compliance/sdp.md) |
| JSEP | RFC 9429 | obsoletes RFC 8829 | [sdp](compliance/sdp.md) |
| BUNDLE | RFC 9143 | obsoletes RFC 8843 | [sdp](compliance/sdp.md) |
| Security architecture | RFC 8826, RFC 8827 | | [security](compliance/security.md) |
| Transports | RFC 8835 | | [transport](compliance/transport.md) |
| WebRTC statistics | W3C webrtc-stats | Candidate Recommendation | [stats](compliance/stats.md) |

Interoperability results are tracked separately in [INTEROP.md](INTEROP.md).
