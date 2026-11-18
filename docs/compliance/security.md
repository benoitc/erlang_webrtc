# Security architecture (RFC 8826, RFC 8827)

| ID | Spec | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SEC-1 | 8827 §6.5 | All media encrypted with SRTP keyed from DTLS-SRTP; no unencrypted RTP offered | webrtc_jsep_build (UDP/TLS/RTP/SAVPF only), webrtc_media | webrtc_pc_SUITE | Interoperability tested |
| SEC-2 | 8827 §6.5 | Data channels only over DTLS | webrtc_transport | webrtc_pc_SUITE | Interoperability tested |
| SEC-3 | 8827 §6.5 | DTLS 1.2 or later, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, P-256 | webrtc_dtls_crypto | dtls.md DTLS-13 | Interoperability tested |
| SEC-4 | 8827 §6.5 | Peer certificate verified against the SDP fingerprint, mismatch fatal | webrtc_dtls_hs | webrtc_pc_SUITE:fingerprint_mismatch_fails, webrtc_dtls_interop_SUITE | Interoperability tested |
| SEC-5 | 8827 §6.5 | Fresh self-signed certificate per peer connection by default | webrtc_pc | | Implemented, untested |
| SEC-6 | 8826 §4.2 | ICE consent before sending, consent freshness | webrtc_ice_agent | ice.md | Unit tested |
| SEC-7 | 8826 §4.2 | Traffic from unvalidated addresses ignored | webrtc_transport | webrtc_security_SUITE:spoofed_traffic_dropped | E2E tested |
| SEC-8 | 3711 §3.3.2, 6347 §4.1.2.6 | Replay protection for SRTP, SRTCP and DTLS | webrtc_srtp, webrtc_dtls | webrtc_security_SUITE:replayed_datagrams_dropped | E2E tested |
| SEC-9 | | Every externally reachable parser total on arbitrary input | all codecs | prop_webrtc_parsers, per-module truncation tests | Unit tested |
| SEC-10 | | Floods of invalid STUN or random datagrams do not grow state or break the session | webrtc_transport, webrtc_ice_agent | webrtc_security_SUITE | E2E tested |
| SEC-11 | 8827 §5 | Identity assertions (IdP) | | | Not implemented (browser identity provider API, out of scope for a library peer) |
| SEC-12 | 8827 §6.5 | SRTP MKI not used | webrtc_srtp | srtp.md | Unit tested |
| SEC-13 | 8827 §4 | Keys and credentials stay out of logs: crash reports and `sys:get_status/1` of the peer connection and transport show a summary, the last message's tag, a reason without values and a stack trace without arguments, and no queued message | webrtc_redact, webrtc_pc, webrtc_transport | webrtc_security_SUITE:no_secrets_in_crash_logs | E2E tested (DTLS private key, local and remote ICE passwords, TURN credential) |
| SEC-14 | 3550 §6.3, 8826 §4 | Per-peer state bounded by the streams we know: feedback (NACK, PLI, FIR) is counted on our streams only, an SR from a stream we do not receive creates nothing, PAUSE and XR entries are capped, TMMBR follows only the owners of its bounding set, a stream's statistics go with it on BYE or expiry, and the stream table refuses entries past twice the stream limit | webrtc_media_in, webrtc_media_out, webrtc_media_pause, webrtc_tmmbr | webrtc_media_bounds_tests | Unit tested: 10,000 PLI for unknown SSRCs and 5,000 random RTCP packets from random SSRCs leave the maps within their bounds |
| SEC-15 | | Nothing outlives its peer connection: the `webrtc_transports` rows are removed by `webrtc_registry`, which monitors every peer connection (after `kill` too) and drops rows naming a dead transport on lookup; the signaling helper monitors its peer connection, is killed on terminate, and holds at most 64 waiting messages; the workers opening TCP and TLS connections are linked to their transport and killed when it stops | webrtc_registry, webrtc_pc, webrtc_peer_sup, webrtc_transport_net | webrtc_lifecycle_SUITE | E2E tested: close, owner exit, kill of the peer connection or a transport, application stop and start, a stuck codec plugin, 200 abandoned and 200 short-lived connections all come back to the node's process, port and table counts; `make soak` repeats it for an hour |
