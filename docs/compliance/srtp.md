# SRTP and SRTCP (RFC 3711, RFC 7714, RFC 9335)

This page tracks the SRTP and SRTCP requirements implemented by `src/srtp`: packet protection (RFC 3711), AES-GCM (RFC 7714), encrypted CSRCs and header extensions (RFC 9335), keying from DTLS-SRTP (RFC 5764 §4.1.2 and §4.2) and the WebRTC profile rules (RFC 8827 §6.5). Read it before you rely on a profile or a replay and rekey behavior. Tests named `*_tests:` are in `test/`; `prop_webrtc_srtp` holds the PropEr properties.

## RFC 3711: SRTP and SRTCP processing

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SRTP-1 | 3.1 | Without cryptex only the RTP payload (with padding) is encrypted; header, CSRC list and header extension stay in the clear and are authenticated | webrtc_srtp, webrtc_srtp_cipher | webrtc_srtp_tests:roundtrip_rtp_test_, prop_webrtc_srtp:prop_rtp_roundtrip | Unit tested |
| SRTP-2 | 3.3.1 | Sender ROC starts at 0 and increments when SEQ wraps | webrtc_srtp | rollover_test_, multiple_rollovers_test | Unit tested |
| SRTP-3 | 3.3.1 | Receiver starts with ROC 0 and s_l set to the SEQ of the first packet | webrtc_srtp | rollover_test_ | Unit tested |
| SRTP-4 | 3.3.1, App. A | Index estimate: v in {ROC-1, ROC, ROC+1}, closest to 2^16 * ROC + s_l | webrtc_srtp | estimate_index_test, reorder_near_rollover_test_, sender_reorder_near_rollover_test | Unit tested |
| SRTP-5 | 3.3.1 | ROC and s_l updated only after the packet is authenticated, with the v / SEQ rule | webrtc_srtp | forged_does_not_move_window_test, reorder_near_rollover_test_ | Unit tested |
| SRTP-6 | 3.3.1 | A receiver joining a running stream is given the ROC out of band | webrtc_srtp (set_roc/4) | set_roc_test | Unit tested |
| SRTP-7 | 3.3.1 | ROC is not reset on rekey | webrtc_srtp (roc/3, set_roc/4) | set_roc_test | Non-compliant / known limitation: a context does not rekey itself; the caller carries the ROC into the new context with roc/3 and set_roc/4. WebRTC does not rekey a DTLS-SRTP session. |
| SRTP-8 | 3.3.2 | Replay list as a sliding window of at least 64 entries (default 1024 for SRTP) | webrtc_srtp_replay | webrtc_srtp_replay_tests, default_window_is_1024_test | Unit tested |
| SRTP-9 | 3.3.2 | Accept only indices ahead of the window or inside it and not yet received; update after authentication | webrtc_srtp_replay, webrtc_srtp | webrtc_srtp_replay_tests:model_test, rtp_replay_test_ | Unit tested |
| SRTP-10 | 3.3 | Replayed packets MUST be discarded and SHOULD be logged | webrtc_srtp | rtp_replay_test_ | Unit tested (returns `{error, replay}` or `{error, too_old}`; logging is left to the caller) |
| SRTP-11 | 3.3 | Authentication checked before decryption; failed packets discarded | webrtc_srtp_cipher | tamper_rtp_test_, wrong_key_test_, prop_unprotect_mutated | Unit tested |
| SRTP-12 | 4.2 | Tag comparison does not leak timing | webrtc_srtp_cipher | (crypto:hash_equals for HMAC, OpenSSL for GCM) | Implemented, untested |
| SRTP-13 | 4.2 | SRTP MAC input is Authenticated Portion concatenated with ROC | webrtc_srtp_cipher | libsrtp_aes_cm_rtp_test, rollover_test_ | Unit tested |
| SRTP-14 | 4.2.1 | HMAC-SHA1 truncated to the 80 or 32 left-most bits | webrtc_srtp_cipher | libsrtp_aes_cm_rtp_test, sha1_32_tag_lengths_test | Unit tested |
| SRTP-15 | 4.1.1 | AES-CM IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16) | webrtc_srtp_cipher | webrtc_srtp_kdf_tests:b2_through_protect_test | Unit tested |
| SRTP-16 | 4.1.1 | AES-CM keystream from RFC 3711 B.2 | webrtc_srtp_kdf | webrtc_srtp_kdf_tests:b2_keystream_test | Unit tested |
| SRTP-17 | 4.1.1 | At most 2^16 keystream blocks per IV | webrtc_srtp_cipher | cm_keystream_limit_test | Unit tested |
| SRTP-18 | 4.1.1 | (ROC, SEQ, SSRC) never reused with one key on the send side | webrtc_srtp | sender_refuses_index_reuse_test_ | Unit tested |
| SRTP-19 | 3.4 | SRTCP appends E flag, 31-bit index and tag; index starts at 0 and increments per packet | webrtc_srtp | srtcp_index_sequence_test, libsrtp_aes_cm_rtcp_test | Unit tested |
| SRTP-20 | 3.4, 4.1.1 | SRTCP encrypts from octet 9; IV uses the SSRC of the first header and the SRTCP index | webrtc_srtp_cipher | libsrtp_aes_cm_rtcp_test, roundtrip_rtcp_test_ | Unit tested |
| SRTP-21 | 3.4 | SRTCP decrypts only when E = 1; E = 0 leaves the payload untouched but authenticated | webrtc_srtp_cipher | roundtrip_rtcp_test_ (E=false), rfc7714_17_3_test | Unit tested |
| SRTP-22 | 3.4 | SRTCP message authentication is REQUIRED | webrtc_srtp_cipher | tamper_rtcp_test_ | Unit tested |
| SRTP-23 | 3.4 | SRTCP replay protection with its own replay list (default 128) | webrtc_srtp | rtcp_replay_test_ | Unit tested |
| SRTP-24 | 3.4 | SRTCP index not reset after rekey | webrtc_srtp (set_rtcp_index/3) | rfc7714_17_1_test | Non-compliant / known limitation: as SRTP-7, the caller carries the index with set_rtcp_index/3. |
| SRTP-25 | 3.4 | avg_rtcp_size includes the SRTCP overhead | | | Not implemented (belongs to the RTCP scheduler) |
| SRTP-26 | 3.3.1, 9.2 | No more than 2^48 SRTP and 2^31 SRTCP packets per key; then `{error, key_exhausted}` | webrtc_srtp | srtp_key_exhausted_test_, srtcp_key_exhausted_test_ | Unit tested |
| SRTP-27 | 3.1, 8.1 | MKI | | | Not implemented: RFC 8827 §6.5 forbids MKI in WebRTC |
| SRTP-28 | 3.3, 3.4 | Malformed or truncated packets are refused without crashing | webrtc_srtp | truncated_test_, malformed_test_, prop_unprotect_random_binary | Unit tested |
| SRTP-29 | 3.3.2 | Receive state bounded: `forget/2` drops an SSRC and keeps its highest SRTP and SRTCP indices for the last 1024 SSRCs forgotten, so earlier packets stay refused and the stream continues after them; at most 512 SSRCs with receive state (`{error, too_many_streams}`) | webrtc_srtp, webrtc_srtp_replay | forget_test, forget_bounded_test, rx_streams_bounded_test | Unit tested |

## RFC 3711: key derivation

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SRTP-KDF-1 | 4.3.1 | Session keys from master key and salt with labels 0x00 to 0x02, kdr = 0 | webrtc_srtp_kdf | b3_cipher_key_test, b3_cipher_salt_test, b3_auth_key_test | Unit tested |
| SRTP-KDF-2 | 4.3.3 | AES-CM PRF: AES-CM keyed with the master key, IV = x * 2^16 | webrtc_srtp_kdf | b3_prf_input_test | Unit tested |
| SRTP-KDF-3 | 4.3.2 | SRTCP keys with labels 0x03 to 0x05 | webrtc_srtp_kdf | session_keys_cm_test, rtp_rtcp_keys_separate_test | Unit tested |
| SRTP-KDF-4 | 4.3.1; RFC 7714 §11 | KDF with a 96-bit master salt (AES-GCM) and a 256-bit master key (AES_256_CM_PRF, RFC 6188) | webrtc_srtp_kdf | session_keys_gcm_test, libsrtp_aes_gcm_rtp_test | Unit tested. Note: the 96-bit salt is extended to 112 bits with trailing zero octets, as libsrtp does. A literal reading of the RFC 3711 right alignment would add leading zeros instead. Browsers use libsrtp, and the libsrtp reference packet matches. |
| SRTP-KDF-5 | 4.3.1 | Keys derived once per context, never per packet | webrtc_srtp | (session keys and AEAD states built in new/4) | Implemented, untested |

## RFC 7714: AES-GCM

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| GCM-1 | 8.1 | SRTP IV = (00 00, SSRC, ROC, SEQ) XOR salt | webrtc_srtp_cipher | rfc7714_16_1_encrypt_test, rfc7714_16_2_encrypt_test | Unit tested |
| GCM-2 | 8.2 | AAD is the RTP header with CSRCs and extension; plaintext is payload, padding and pad count | webrtc_srtp_cipher | rfc7714_16_1_decrypt_test, roundtrip_rtp_test_ | Unit tested |
| GCM-3 | 8.2 | Every SRTP packet is encrypted and authenticated, empty payloads included | webrtc_srtp_cipher | roundtrip_rtp_test_ (empty payload) | Unit tested |
| GCM-4 | 8.3 | RFC 6904 header extension encryption | | | Not implemented: cryptex (RFC 9335, below) encrypts every extension and the CSRCs instead, and no peer we test against offers RFC 6904 |
| GCM-5 | 8.4 | (ROC, SEQ, SSRC) checked by the SRTP implementation so an IV is never reused | webrtc_srtp | sender_refuses_index_reuse_test_ | Unit tested |
| GCM-6 | 8.4 | SSRC pools when several senders share a master key | | | Not implemented: DTLS-SRTP gives each direction its own master key; SSRC allocation belongs to the RTP layer |
| GCM-7 | 9.1 | SRTCP IV = (00 00, SSRC, 00 00, 0, index) XOR salt | webrtc_srtp_cipher | rfc7714_17_1_test, rfc7714_17_2_test | Unit tested |
| GCM-8 | 9.2 | E = 1: AAD is the first 8 octets and the ESRTCP word; tag before the ESRTCP word | webrtc_srtp_cipher | rfc7714_17_1_test, rfc7714_17_2_test, rfc7714_17_eflag_test | Unit tested |
| GCM-9 | 9.3 | E = 0: whole packet and ESRTCP word are AAD, cipher is the tag alone | webrtc_srtp_cipher | rfc7714_17_3_test, rfc7714_17_4_test | Unit tested |
| GCM-10 | 9.4, 10 | At most 2^48 SRTP and 2^31 SRTCP invocations per key | webrtc_srtp | srtp_key_exhausted_test_, srtcp_key_exhausted_test_ | Unit tested |
| GCM-11 | 10 | AEAD tag is 16 octets, IV 12 octets | webrtc_srtp_profile, webrtc_srtp_cipher | rfc7714_16_* | Unit tested |
| GCM-12 | 12 | Both AEAD_AES_128_GCM and AEAD_AES_256_GCM supported | webrtc_srtp_profile | rfc7714_16_*, rfc7714_17_* | Unit tested |

## RFC 9335: cryptex

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| CRYPTEX-1 | 5.1 | Profile 0xC0DE for one-byte and 0xC2DE for two-byte extensions; CSRCs without extensions get an empty 0xC0DE block and the X bit | webrtc_srtp | webrtc_srtp_cryptex_tests:vectors_test_ (A.1.5, A.1.6) | Unit tested |
| CRYPTEX-2 | 5.2, 6.2 | AES-CM: CSRCs, extension data and payload encrypted as one keystream, authentication unchanged | webrtc_srtp_cipher | webrtc_srtp_cryptex_tests:vectors_test_ (A.1) | Unit tested |
| CRYPTEX-3 | 5.2, 6.2 | AES-GCM: fixed header and extension header are the associated data, CSRCs, extension data and payload the plaintext | webrtc_srtp_cipher | webrtc_srtp_cryptex_tests:vectors_test_ (A.2), tampered_test | Unit tested |
| CRYPTEX-4 | 6.3 | The receiver recognises cryptex by the extension profile and accepts both forms | webrtc_srtp | webrtc_srtp_cryptex_tests:vectors_test_ | Unit tested |
| CRYPTEX-5 | 6.1 | `a=cryptex` offered on RTP sections; answered for a transport whose RTP sections all have it (media or session level); sent once every section negotiated it | webrtc_jsep_build, webrtc_jsep_params, webrtc_media | webrtc_pc_SUITE:cryptex, webrtc_pc_interop_SUITE:cryptex_echo | Interoperability tested (Pion) |
| CRYPTEX-6 | 6.3 | Refusing packets without cryptex once it is required | | | Not implemented: packets in either form are accepted |

## RFC 5764: DTLS-SRTP keying

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| KEY-1 | 4.1.2; RFC 7714 §14.2 | Profile ids 0x0001, 0x0002, 0x0007, 0x0008 | webrtc_srtp_profile | profile_ids_test | Unit tested |
| KEY-2 | 4.1.2 | SRTP_AES128_CM_HMAC_SHA1_32: 32-bit SRTP tag, 80-bit SRTCP tag | webrtc_srtp_profile | sha1_32_tag_lengths_test | Unit tested |
| KEY-3 | 4.1.2 | Key derivation rate is 0 and the RFC 3711 AES-CM PRF is used | webrtc_srtp_kdf | b3_* tests | Unit tested |
| KEY-4 | 4.1.2 | maximum_lifetime of 2^31 packets per key set for the AES-CM profiles | webrtc_srtp | | Non-compliant / known limitation: the AES-CM profiles use the RFC 3711 limits (2^48 indices per SRTP stream, 2^31 per SRTCP stream) like libsrtp. A WebRTC session cannot rekey, so a 2^31 total would end long video calls that browsers keep running. |
| KEY-5 | 4.2 | Export 2 * (key_len + salt_len) octets with label "EXTRACTOR-dtls_srtp" and no context | webrtc_srtp_profile | key_material_length_test | Unit tested (the export itself is done by the DTLS layer) |
| KEY-6 | 4.2 | Layout client_key, server_key, client_salt, server_salt | webrtc_srtp_profile | split_layout_test | Unit tested |
| KEY-7 | 4.2 | Each side sends with its own write keys and only uses the peer's keys to receive | webrtc_srtp (dtls_contexts/4) | dtls_contexts_test | Unit tested |

## RFC 8827: WebRTC security architecture

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| WEBRTC-SRTP-1 | 6.5 | SRTP_AES128_CM_HMAC_SHA1_80 MUST be supported | webrtc_srtp_profile | roundtrip_rtp_test_, libsrtp_aes_cm_rtp_test | Unit tested |
| WEBRTC-SRTP-2 | 6.5 | NULL encryption profiles MUST NOT be negotiated | webrtc_srtp_profile | null_profiles_rejected_test, bad_options_test | Unit tested |
| WEBRTC-SRTP-3 | 6.5 | MKI MUST NOT be used | webrtc_srtp | | Implemented, untested (no MKI support: a packet carrying an MKI fails authentication) |
| WEBRTC-SRTP-4 | 6.5 | AEAD profiles SHOULD be favored | webrtc_srtp_profile | aead_preferred_test | Unit tested |
| WEBRTC-SRTP-5 | 6.5 | All media and RTCP protected: SRTCP authentication always on | webrtc_srtp | tamper_rtcp_test_ | Unit tested |
