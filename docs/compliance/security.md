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
