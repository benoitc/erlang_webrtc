# DTLS (RFC 6347, RFC 5764, RFC 7627, RFC 8842, RFC 8122, RFC 8827 §6.5)

| ID | Spec | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| DTLS-1 | 6347 §4.1 | Record framing, several records per datagram | webrtc_dtls_record | webrtc_dtls_tests, interop suite | Interoperability tested |
| DTLS-2 | 6347 §4.1.2.6 | Anti-replay window (64) per epoch, updated only after authentication | webrtc_dtls_record, webrtc_dtls | record_replay_window_test, app_data_test | Unit tested |
| DTLS-3 | 6347 §4.1.2.7 | Invalid records silently discarded | webrtc_dtls | app_data_test (tampered), garbage_never_crashes_test | Unit tested |
| DTLS-4 | 6347 §4.2.1 | Cookie exchange (HelloVerifyRequest), first ClientHello and HVR excluded from transcript | webrtc_dtls_hs | basic_handshake_test, interop (OpenSSL server uses cookies) | Interoperability tested |
| DTLS-5 | 6347 §4.2.2 | message_seq handling, server takes it from ClientHello | webrtc_dtls, webrtc_dtls_hs | interop suite | Interoperability tested |
| DTLS-6 | 6347 §4.2.3 | Handshake fragmentation and reassembly, overlapping fragments | webrtc_dtls_msg, webrtc_dtls | small_mtu_fragmentation_test | Unit tested |
| DTLS-7 | 6347 §4.2.4 | Flight retransmission with exponential back-off, resend on peer retransmission | webrtc_dtls | single_loss_test_, heavy_loss_test, timeout_test | Unit tested |
| DTLS-8 | 6347 §4.2.6 | Transcript includes DTLS handshake headers | webrtc_dtls_hs | interop suite (Finished verified by OTP ssl and OpenSSL) | Interoperability tested |
| DTLS-9 | 5246 §7.4.1.4 | No unsolicited extensions in ServerHello; at most one extension per type | webrtc_dtls_hs, webrtc_dtls_msg | | Implemented, untested |
| DTLS-10 | 5246 §7.2 | close_notify sent and answered | webrtc_dtls | close_notify_test | Unit tested |
| DTLS-11 | 5746 | renegotiation_info sent; renegotiation refused | webrtc_dtls_hs | interop suite | Interoperability tested |
| DTLS-12 | 7627 | Extended master secret offered, required by default | webrtc_dtls_hs | basic_handshake_test, otp_server_without_ems_rejected | Interoperability tested |
| DTLS-13 | 8827 §6.5 | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 with P-256 | webrtc_dtls_crypto | suites_test_, groups_test_, interop | Interoperability tested |
| DTLS-14 | 9325 §4.2 | Only AEAD suites with forward secrecy offered | webrtc_dtls_crypto | suites_test_ | Unit tested |
| DTLS-15 | 7905 | ChaCha20-Poly1305 suites | webrtc_dtls_record | suites_test_ | Unit tested |
| DTLS-16 | 8422 | x25519, P-256, P-384; invalid and all-zero shared secrets rejected | webrtc_dtls_crypto | groups_test_ | Unit tested |
| DTLS-17 | 8827 §6.5 | Mutual authentication: CertificateRequest always sent, empty client certificate rejected | webrtc_dtls_hs | interop (OTP client), basic_handshake_test | Interoperability tested |
| DTLS-18 | 8122 §5 | Peer certificate must match an SDP fingerprint; SHA-1/224 not accepted | webrtc_dtls_cert, webrtc_dtls_hs | fingerprint_mismatch_test, sha1_fingerprint_not_accepted_test, otp_server_rejected_fingerprint | Interoperability tested |
| DTLS-19 | 8842 §5 | DTLS role given by the caller from a=setup, independent of ICE role | webrtc_dtls | (API) | Implemented, untested |
| DTLS-20 | 5764 §4.1.1 | use_srtp: client offers list, server selects exactly one offered profile | webrtc_dtls_hs | srtp_profile_selection_test, interop | Interoperability tested |
| DTLS-21 | 5764 §4.1.1 | Client rejects a ServerHello with a profile it did not offer | webrtc_dtls_hs | | Implemented, untested |
| DTLS-22 | 5764 §4.2, 5705 | Keying material exporter, label EXTRACTOR-dtls_srtp | webrtc_dtls, webrtc_dtls_crypto | interop compares key material with OTP ssl and OpenSSL | Interoperability tested |
| DTLS-23 | 5246 §5 | TLS 1.2 PRF | webrtc_dtls_crypto | prf_sha256_vector_test | Unit tested |
| DTLS-24 | | Malformed input never crashes the engine | webrtc_dtls | garbage_never_crashes_test, mutated_handshake_test | Unit tested |
| DTLS-25 | 8842 | Connection reported only after fingerprint verification; data held until then | webrtc_dtls | deferred_fingerprint_test, deferred_fingerprint_mismatch_test | Unit tested |
| DTLS-26 | 9147 | DTLS 1.3 | | | Not implemented. Peers fall back to DTLS 1.2, which every WebRTC implementation supports. |
| DTLS-27 | 6347 §4.2.8 | Session resumption | | | Not implemented (not used by WebRTC) |
| DTLS-28 | 9146 | Connection ID | | | Not implemented (optional) |
| DTLS-29 | 6347 §4.2.2 | HelloVerifyRequest record sequence equals the ClientHello's | webrtc_dtls_hs | | Non-compliant / known limitation: our server keeps per-association state, so it uses its own epoch 0 counter. No interop impact observed. |
