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
| TURN | RFC 8656 | obsoletes RFC 5766 | [turn](compliance/turn.md) |
| Multiplexing | RFC 7983 | updated by RFC 9443 | [transport](compliance/transport.md) |
| DTLS 1.2 | RFC 6347 | | [dtls](compliance/dtls.md) |
| DTLS 1.3 | RFC 9147 | | [dtls](compliance/dtls.md) |
| Extended master secret | RFC 7627 | | [dtls](compliance/dtls.md) |
| DTLS-SRTP | RFC 5764 | updated by RFC 7983 | [dtls](compliance/dtls.md) |
| ICE and DTLS | RFC 8842 | | [dtls](compliance/dtls.md) |
| Fingerprints | RFC 8122 | updated by RFC 8842 | [dtls](compliance/dtls.md) |
| SRTP | RFC 3711 | | [srtp](compliance/srtp.md) |
| SRTP AES-GCM | RFC 7714 | | [srtp](compliance/srtp.md) |
| RTP/RTCP | RFC 3550 | | [rtp](compliance/rtp.md) |
| RTP usage in WebRTC | RFC 8834 | | [rtp](compliance/rtp.md) |
| AVPF | RFC 4585 | | [rtp](compliance/rtp.md) |
| CCM | RFC 5104 | | [rtp](compliance/rtp.md) |
| Header extensions | RFC 8285 | | [rtp](compliance/rtp.md) |
| RTX | RFC 4588 | | [rtp](compliance/rtp.md) |
| rtcp-mux | RFC 5761, RFC 8858 | | [rtp](compliance/rtp.md) |
| Congestion control | RFC 8836, RFC 8888 | | [rtp](compliance/rtp.md) |
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

Interoperability results are tracked separately in [INTEROP.md](INTEROP.md).
