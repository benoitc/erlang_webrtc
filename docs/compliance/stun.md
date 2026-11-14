# STUN (RFC 8489)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| STUN-1 | 5 | Header: two zero bits, 14-bit type, length multiple of 4, magic cookie | webrtc_stun | webrtc_stun_tests:malformed_test_ | Unit tested |
| STUN-2 | 5 | Method/class bit interleaving for all classes | webrtc_stun | all_methods_and_classes_test | Unit tested |
| STUN-3 | 14 | Attributes padded to 4 bytes, padding content ignored on receive | webrtc_stun | request_decode_test (RFC 5769 pads with 0x20) | Unit tested |
| STUN-4 | 14.2 | XOR-MAPPED-ADDRESS for IPv4 and IPv6 | webrtc_stun | ipv4_response_test, ipv6_response_test | Unit tested |
| STUN-5 | 14.5 | MESSAGE-INTEGRITY HMAC-SHA1 with adjusted length | webrtc_stun | request_decode_test, reencode_ipv4_response_test | Unit tested |
| STUN-6 | 14.6 | MESSAGE-INTEGRITY-SHA256, preferred when present | webrtc_stun | roundtrip_all_attrs_test | Unit tested |
| STUN-7 | 14.5 | Attributes after MESSAGE-INTEGRITY ignored, except MI-SHA256 and FINGERPRINT | webrtc_stun | attrs_after_integrity_ignored_test | Unit tested |
| STUN-8 | 14.7 | FINGERPRINT is CRC-32 xor 0x5354554e, last attribute | webrtc_stun | bad_fingerprint_test, fingerprint_not_last_test | Unit tested |
| STUN-9 | 9.2.2 | Long-term credential key MD5(user:realm:pass) | webrtc_stun | long_term_test | Unit tested |
| STUN-10 | 9.2.2 | Long-term key SHA-256 variant (PASSWORD-ALGORITHM) | webrtc_stun | | Implemented, untested |
| STUN-11 | 6.3.1, 14 | Unknown comprehension-required attributes reported (for 420) | webrtc_stun | unknown_comprehension_required_test | Unit tested |
| STUN-12 | 14.3 | USERNAME < 513 bytes; REALM, NONCE, SOFTWARE, reason <= 763 bytes | webrtc_stun | | Implemented, untested |
| STUN-13 | 9.2.4 | Integrity comparison is constant time | webrtc_stun | (crypto:hash_equals) | Implemented, untested |
| STUN-14 | 6.2.1 | Request retransmission: RTO, Rc=7, Rm=16 | webrtc_stun_tx | | Not implemented |
| STUN-15 | 9.1 | Short-term credential mechanism (used by ICE) | webrtc_ice_agent | | Not implemented |
| STUN-16 | 9.1.3 | SASLprep/OpaqueString of passwords | | | Non-compliant / known limitation: passwords are used as given. ICE passwords are ASCII (RFC 8839 ice-char) so ICE is unaffected. |
