# DTLS (RFC 9147, RFC 8446, RFC 6347, RFC 5764, RFC 7627, RFC 8842, RFC 8122, RFC 8827 §6.5)

Both versions are offered by default (`versions => ['dtlsv1.3', 'dtlsv1.2']`); the server picks DTLS 1.3 when the client offers it. DTLS 1.2 rows are tested by the `dtls12_*` cases of webrtc_dtls_tests and the DTLS 1.2 interop cases; the other cases of webrtc_dtls_tests negotiate DTLS 1.3.

## DTLS 1.2 and shared requirements

| ID | Spec | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| DTLS-1 | 6347 §4.1 | Record framing, several records per datagram | webrtc_dtls_record, webrtc_dtls12 | webrtc_dtls_tests, interop suite | Interoperability tested |
| DTLS-2 | 6347 §4.1.2.6 | Anti-replay window (64) per epoch, updated only after authentication; a jump beyond the window resets it | webrtc_dtls_record, webrtc_dtls12 | record_replay_window_test, record_replay_window_jump_test, app_data_test | Unit tested |
| DTLS-3 | 6347 §4.1.2.7 | Invalid records silently discarded | webrtc_dtls12 | app_data_test (tampered), garbage_never_crashes_test | Unit tested |
| DTLS-4 | 6347 §4.2.1 | Cookie exchange (HelloVerifyRequest), first ClientHello and HVR excluded from transcript | webrtc_dtls_hs | dtls12_handshake_test, fallback_to_12_server_test, interop (OpenSSL server uses cookies) | Interoperability tested |
| DTLS-5 | 6347 §4.2.2 | message_seq handling, server takes it from ClientHello | webrtc_dtls_reasm, webrtc_dtls_hs | interop suite | Interoperability tested |
| DTLS-6 | 6347 §4.2.3 | Handshake fragmentation and reassembly, overlapping fragments | webrtc_dtls_msg, webrtc_dtls_reasm | dtls12_small_mtu_fragmentation_test | Unit tested |
| DTLS-7 | 6347 §4.2.4 | Flight retransmission with exponential back-off, resend on peer retransmission | webrtc_dtls12 | dtls12_single_loss_test_, dtls12_heavy_loss_test, timeout_test | Unit tested |
| DTLS-8 | 6347 §4.2.6 | Transcript includes DTLS handshake headers | webrtc_dtls_hs | interop suite (Finished verified by OTP ssl and OpenSSL) | Interoperability tested |
| DTLS-9 | 5246 §7.4.1.4 | No unsolicited extensions in ServerHello; at most one extension per type | webrtc_dtls_hs, webrtc_dtls_msg | | Implemented, untested |
| DTLS-10 | 5246 §7.2 | close_notify sent and answered | webrtc_dtls12 | dtls12_close_notify_test | Unit tested |
| DTLS-11 | 5746 | renegotiation_info sent; renegotiation refused | webrtc_dtls_hs | interop suite | Interoperability tested |
| DTLS-12 | 7627 | Extended master secret offered, required by default | webrtc_dtls_hs | dtls12_handshake_test, otp_server_without_ems_rejected | Interoperability tested |
| DTLS-13 | 8827 §6.5 | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 with P-256 | webrtc_dtls_crypto | suites_test_, dtls12_suites_test_, interop | Interoperability tested |
| DTLS-14 | 9325 §4.2 | Only AEAD suites with forward secrecy offered | webrtc_dtls_crypto | dtls12_suites_test_ | Unit tested |
| DTLS-15 | 7905 | ChaCha20-Poly1305 suites | webrtc_dtls_record | dtls12_suites_test_ | Unit tested |
| DTLS-16 | 8422 | x25519, P-256, P-384; invalid and all-zero shared secrets rejected | webrtc_dtls_crypto | dtls12_groups_test_, groups_test_ | Unit tested |
| DTLS-17 | 8827 §6.5 | Mutual authentication: CertificateRequest always sent, empty client certificate rejected | webrtc_dtls_hs | interop (OTP client) | Interoperability tested |
| DTLS-18 | 8122 §5 | Peer certificate must match an SDP fingerprint; SHA-1/224 not accepted | webrtc_dtls_cert, webrtc_dtls_hs | dtls12_fingerprint_mismatch_test, sha1_fingerprint_not_accepted_test, otp_server_rejected_fingerprint | Interoperability tested |
| DTLS-19 | 8842 §5 | DTLS role given by the caller from a=setup, independent of ICE role | webrtc_dtls | pc_dtls_version, pc_dtls_version_peer_offer (both roles with each peer) | Interoperability tested |
| DTLS-20 | 5764 §4.1.1 | use_srtp: client offers list, server selects exactly one offered profile | webrtc_dtls_hs | dtls12_srtp_profile_selection_test, interop | Interoperability tested |
| DTLS-21 | 5764 §4.1.1 | Client rejects a ServerHello with a profile it did not offer | webrtc_dtls_hs | | Implemented, untested |
| DTLS-22 | 5764 §4.2, 5705 | Keying material exporter, label EXTRACTOR-dtls_srtp | webrtc_dtls, webrtc_dtls_crypto | interop compares key material with OTP ssl and OpenSSL | Interoperability tested |
| DTLS-23 | 5246 §5 | TLS 1.2 PRF | webrtc_dtls_crypto | prf_sha256_vector_test | Unit tested |
| DTLS-24 | | Malformed input never crashes the engine (both versions) | webrtc_dtls12, webrtc_dtls13 | garbage_never_crashes_test, dtls12_mutated_handshake_test, garbage_test, mutated_handshake_test_ | Unit tested |
| DTLS-25 | 8842 | Connection reported only after fingerprint verification; data held until then (both versions) | webrtc_dtls_hs | dtls12_deferred_fingerprint_test, deferred_fingerprint_client_test, deferred_fingerprint_server_test, deferred_fingerprint_mismatch_test | Unit tested |
| DTLS-26 | 9147 | DTLS 1.3, negotiated with fallback to DTLS 1.2 (details in DTLS-30 to DTLS-59) | webrtc_dtls13* | webrtc_dtls13_tests, interop with OpenSSL 4.1 (both roles) and Chromium (both roles) | Interoperability tested |
| DTLS-27 | 6347 §4.2.8 | Session resumption | | | Not implemented (not used by WebRTC) |
| DTLS-28 | 9146 | Connection ID for DTLS 1.2 | | | Not implemented (optional) |
| DTLS-29 | 6347 §4.2.2 | HelloVerifyRequest record sequence equals the ClientHello's | webrtc_dtls_hs | | Non-compliant / known limitation: our server keeps per-association state, so it uses its own epoch 0 counter. No interop impact observed. RFC 9147 has no such rule for the HelloRetryRequest. |

## DTLS 1.3

| ID | Spec | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| DTLS-30 | 8446 §4.2.1, 9147 §5.3 | Version negotiation with supported_versions: 1.3 and 1.2 offered, the server picks 1.3 when offered, `versions` restricts; an endpoint without TLS 1.3 suites does not support 1.3 | webrtc_dtls_hs | fallback_to_12_server_test, fallback_to_12_client_test, no_common_version_test_, server_without_13_suites_test, openssl_any_client_our_server, openssl_any_server_our_12_client, otp_server_our_client | Interoperability tested |
| DTLS-31 | 8446 §4.1.3, 9147 §5.3 | Downgrade sentinel set by a 1.3 capable server that negotiates 1.2, checked by a client that offered 1.3 | webrtc_dtls_hs | downgrade_detection_test, downgrade_sentinel_ignored_by_12_client_test, openssl_downgrade_detected (OpenSSL's sentinel), openssl_any_client_our_12_server (OpenSSL checks ours) | Interoperability tested |
| DTLS-32 | 9147 §4, §4.1 | DTLSPlaintext only in epoch 0 and only for ClientHello, ServerHello and HelloRetryRequest; unified header with 16-bit sequence number and length; demultiplexing by first byte; records with a connection ID dropped | webrtc_dtls13_record, webrtc_dtls13 | split_test, record_roundtrip_test_, plaintext_alert_ignored_test, interop | Interoperability tested |
| DTLS-33 | 9147 §4.2.3 | Record number encryption (AES-ECB and ChaCha20 masks), ciphertexts under 16 bytes rejected | webrtc_dtls13_record | record_roundtrip_test_, replay_test, openssl13_aes256_our_client, openssl13_chacha20_our_client, openssl13_chacha20_our_server | Interoperability tested |
| DTLS-34 | 9147 §4.2.2 | Record number and epoch reconstruction | webrtc_dtls13_record | reconstruct_test, select_epoch_test, sequence_wrap_test_, many_key_updates_test | Unit tested |
| DTLS-35 | 9147 §4.5.1 | Replay window per epoch, updated after deprotection | webrtc_dtls13 | replay_test, reordering_test | Unit tested |
| DTLS-36 | 8446 §5.3, 9147 §4 | AEAD nonce from the 64-bit sequence number (epoch excluded, erratum 8141); AAD is the header before record number encryption; inner plaintext content type | webrtc_dtls13_record | record_roundtrip_test_, interop | Interoperability tested |
| DTLS-37 | 9147 §4.5.3, 8446 §5.5 | AEAD limits: forgeries counted per key (2^36 closes), KeyUpdate after `rekey_records` (default 2^23), no sending past 2^24.5 records with AES-GCM | webrtc_dtls13 | automatic_key_update_test | Partially tested: the limits themselves are out of reach of a test run |
| DTLS-38 | 8446 §7.1, 9147 §5.9 | Key schedule with the "dtls13" label prefix | webrtc_dtls13_keys | rfc8448_key_schedule_test, dtls13_label_prefix_test, hkdf_rfc5869_test, interop | Interoperability tested |
| DTLS-39 | 8446 §9.1 | TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256; server preference | webrtc_dtls13_keys, webrtc_dtls13_server | suites_test_, server_suite_preference_test, openssl13_* | Interoperability tested |
| DTLS-40 | 8446 §4.2.8 | ECDHE key share (x25519, P-256, P-384), one share offered for the preferred group | webrtc_dtls13_hs, webrtc_dtls13_server | groups_test_, hrr_key_share_test, no_common_group_test | Interoperability tested (x25519) |
| DTLS-41 | 9147 §5.1, 8446 §4.1.4, §4.4.1 | HelloRetryRequest with a stateless cookie (HMAC-SHA256, age limit `cookie_lifetime`), transcript with message_hash; invalid cookie refused with illegal_parameter; second HelloRetryRequest refused; key share retry for another group | webrtc_dtls13_server, webrtc_dtls13_hs | hrr_cookie_test, hrr_key_share_test, hrr_stateless_test, cookie_test, openssl13_client_our_server (X25519MLKEM768 share retried as x25519), openssl13_server_our_client (OpenSSL's HelloRetryRequest) | Interoperability tested |
| DTLS-42 | 9147 §5.3, erratum 8066 | legacy_cookie empty in a 1.3 ClientHello; legacy_session_id_echo empty | webrtc_dtls13_server, webrtc_dtls13_hs | legacy_cookie_test, session_id_echo_test | Unit tested |
| DTLS-43 | 5764 §4.1.1, 8446 §4.3.1 | use_srtp in EncryptedExtensions: one offered profile; unsolicited extensions refused | webrtc_dtls13_hs, webrtc_dtls13_server | srtp_profile_selection_test, no_common_srtp_profile_test, no_srtp_test, interop | Interoperability tested |
| DTLS-44 | 8827 §6.5, 8446 §4.3.2, §4.4.2 | Mutual authentication: CertificateRequest always sent, empty client Certificate refused with certificate_required | webrtc_dtls13_server | openssl13_client_without_certificate, interop | Interoperability tested |
| DTLS-45 | 8446 §4.4.3, §4.2.3 | CertificateVerify over the transcript: scheme we offered, no RSASSA-PKCS1-v1_5, ECDSA curve matching the certificate | webrtc_dtls13_hs | rsa_certificate_test, mixed_certificate_test, openssl13_rsa_certificates | Interoperability tested |
| DTLS-46 | 8446 §4.4.4 | Finished verified in constant time | webrtc_dtls13_hs | every handshake | Interoperability tested |
| DTLS-47 | 9147 §5.2 | Transcript over TLS 1.3 style messages, without message_seq and fragment fields | webrtc_dtls13_hs | interop (Finished verified by OpenSSL and Chromium) | Interoperability tested |
| DTLS-48 | 9147 §5.5 | Fragmentation and reassembly, overlapping fragments, one epoch per message | webrtc_dtls13, webrtc_dtls_reasm | small_mtu_test, small_mtu_loss_test_, interop (OpenSSL fragments its 1.4 KB ClientHello) | Interoperability tested |
| DTLS-49 | 9147 §7, §5.8 | ACK: final flight acknowledged in epoch 3, partial flights after a quarter of the timer, retransmission of the unacknowledged part only, implicit acknowledgement by the next flight, retransmitted final flight acknowledged again, post-handshake messages acknowledged | webrtc_dtls13 | ack_final_flight_test, lost_ack_test, partial_flight_ack_test, no_ack_no_connection_test, interop (OpenSSL ACKs and NewSessionTicket) | Interoperability tested |
| DTLS-50 | 9147 §7.2, erratum 8108 | ACK records for a later epoch than the ACK refused; unknown record numbers ignored | webrtc_dtls13 | ack_for_later_epoch_test, ack_unknown_records_test | Unit tested |
| DTLS-51 | 9147 §5.8.2 | Timers: 400 ms initial (the DTLS-SRTP recommendation), doubled up to 60 s, `rtx_limit` | webrtc_dtls13 | timeout_test, heavy_loss_test_ | Unit tested |
| DTLS-52 | 9147 §5.8.1 | Application data of epoch 3 or later processed only after the peer Finished; the client reports the connection once its final flight is acknowledged | webrtc_dtls13, webrtc_dtls13_hs | server_rejects_client_fingerprint_test, deferred_fingerprint_client_test, no_ack_no_connection_test | Unit tested |
| DTLS-53 | 9147 §4.2.1, §6.1 | Records of epoch 2 or 3 arriving before their keys are buffered (32) and processed once the keys exist; other epochs without keys are discarded | webrtc_dtls13 | records_before_server_hello_test, duplication_and_reordering_test | Unit tested |
| DTLS-54 | 9147 §8, errata 8047, 8050 | KeyUpdate: on request or after `rekey_records`, new keys only after the ACK, update_requested answered, a retransmitted KeyUpdate acknowledged again, previous read epoch kept for reordering, epochs limited to 2^16-1 | webrtc_dtls13_epoch | key_update_test, many_key_updates_test, key_update_lost_ack_test, automatic_key_update_test, key_update_errors_test, openssl13_server_key_update, openssl13_client_key_update | Interoperability tested |
| DTLS-55 | 8446 §7.5, 5764 §4.2 | Exporter, EXTRACTOR-dtls_srtp; no context and empty context are the same | webrtc_dtls13_keys | handshake_test, interop compares key material with OpenSSL; SRTP media with Chromium (webrtc_pc_interop_SUITE) | Interoperability tested |
| DTLS-56 | 8446 §4.6.1 | NewSessionTicket acknowledged and ignored (no resumption) | webrtc_dtls13_hs | interop (OpenSSL sends two tickets) | Interoperability tested |
| DTLS-57 | 9147 §5.1 | Amplification limit (three times the received bytes) before the address is validated | | | Not implemented: the cookie exchange is on by default, and with `use_cookie => false` WebRTC has validated the address with ICE first |
| DTLS-58 | 9147 §5.8.3, §5.8.2, §4.4 | At most 10 records per transmission; timer from the measured RTT; smaller records after repeated retransmissions | | | Not implemented: fixed timer with back-off, whole unacknowledged flight sent at once (a few records at the default 1200 byte MTU) |
| DTLS-59 | 8446 §2.2, §4.2.10, 9147 §9 | PSK, resumption, 0-RTT, post-handshake authentication, connection ID | | | Not implemented (not used by WebRTC); none is offered, early data records are discarded |
| DTLS-60 | 6347 §4.2.3, 9147 §5.5 | Reassembly bounded under hostile fragmentation: held bytes never exceed the advertised length, at most 256 pieces per message, 256 KiB across buffered messages; fragments over the limits dropped | webrtc_dtls_reasm | webrtc_dtls_reasm_tests | Unit tested |
