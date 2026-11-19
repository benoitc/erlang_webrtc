# ADR 0001: DTLS is implemented in the library, OTP ssl is a test oracle

## Context

WebRTC needs DTLS 1.2 (and DTLS 1.3 where the peer supports it) with the `use_srtp` extension (RFC 5764), keying material export, a DTLS role decided by SDP (RFC 8842), self-signed certificates checked against the SDP fingerprint (RFC 8122), and STUN, DTLS and SRTP sharing one UDP socket (RFC 7983, RFC 9443).

OTP 29 (ssl 11.7.8) was examined:

1. `use_srtp` is supported as a hello extension. On the server side `ssl_handshake:handle_client_hello_extensions` sends back `use_srtp_ext(Opts)`, i.e. every locally configured profile, instead of selecting one profile from the client's offer. RFC 5764 §4.1.1 requires the server to pick exactly one profile that the client offered.
2. The negotiated profile is not reported by `ssl:connection_information/1`.
3. `ssl:export_key_materials/4` provides the RFC 5705 exporter. This part is correct.
4. DTLS sockets are opened by ssl itself (`Transport:open/2`). Sharing the ICE socket requires a custom `cb_info` transport that emulates `gen_udp`. That API is documented as experimental, and the DTLS server path registers listeners globally by `{IP, Port}` in `dtls_listener_sup`, which does not fit one association per ICE component.
5. Handshake retransmission timers are internal to ssl and cannot be driven by a test clock.
6. DTLS 1.3 (RFC 9147) is not implemented.

## Decision

Implement DTLS (record layer, handshake, key schedule, `use_srtp`, exporter, extended master secret) as a sans-IO engine in `src/dtls`, using `crypto` and `public_key` for primitives and certificates.

Use OTP ssl and OpenSSL as independent DTLS peers in the test suite. This checks our implementation against two implementations we did not write.

## Consequences

- The library controls the socket, timers and role, and can be tested deterministically.
- More code to own. The handshake is restricted to what WebRTC requires (ECDHE with ECDSA or RSA, AEAD ciphers), which keeps it small.
- OTP limitations 1 and 2 should be reported upstream with a regression test. Until fixed, interop tests against OTP ssl as a server offer a single profile.

## Findings from the interop suite

- OTP ssl 11.7.8 does not implement the extended master secret (RFC 7627). Our endpoint requires it by default (`require_ems => true`), as Chrome, Firefox, OpenSSL and Pion support it. The OTP interop tests set `require_ems => false` explicitly, and `otp_server_without_ems_rejected` checks the default refuses the fallback.
- `ssl:export_key_materials/4` returns `{ok, Binary}` for a single label in this release, not `{ok, [Binary]}` as its spec states.

## Addendum: DTLS 1.3

### Context

OTP 29 (ssl 11.7.8) still has no DTLS 1.3: `ssl:versions()` lists `dtlsv1.2` only and `{versions, ['dtlsv1.3']}` is refused. Browsers have started to negotiate DTLS 1.3 for WebRTC, OpenSSL 4 implements it, and DTLS 1.2 stays the common baseline (Pion v3.1 and aiortc only speak DTLS 1.2).

### Decision

Implement DTLS 1.3 (RFC 9147) in the same sans-IO engine, behind the same API, negotiated with fallback to DTLS 1.2:

- The client offers both versions in `supported_versions` with one key share; the server picks DTLS 1.3 when it is offered. A server that falls back to DTLS 1.2 while it supports DTLS 1.3 sets the RFC 8446 §4.1.3 sentinel, and a client that offered DTLS 1.3 checks it. The `versions` option restricts the offer; an endpoint without a TLS 1.3 suite does not support DTLS 1.3.
- The DTLS 1.3 server uses a stateless HelloRetryRequest: the cookie carries the hash of the first ClientHello and the parameters chosen for it, under an HMAC and an age limit, so nothing is kept before the client proves it receives our packets. `use_cookie` keeps its DTLS 1.2 meaning (on by default).
- Reliability uses the RFC 9147 ACK: records remember which bytes of which message they carry, so a partial ACK leads to retransmitting only what is missing; partial flights are acknowledged after a quarter of the timer.
- The client reports `connected` only after the server acknowledged its final flight (or sent a post-handshake message). In DTLS 1.2 the last message comes from the server, so `connected` means both sides accepted each other; keeping that meaning avoids announcing a connection, and deriving SRTP keys, before the server has checked our certificate.
- `info/1` gains `version`; `extended_master_secret` is reported as true for DTLS 1.3, whose key schedule binds every secret to the transcript. `key_update/2` starts a KeyUpdate; one also starts after `rekey_records` records.
- The key schedule follows RFC 8446 §7 with the "dtls13" label prefix; the HKDF code follows `quic_hkdf` from erlang_quic (same author, Apache 2.0) with the prefix as a parameter, which lets the RFC 8448 TLS 1.3 traces test it.
- Modules: `webrtc_dtls13` (records, ACKs, flights, timers), `webrtc_dtls13_epoch` (epoch keys, KeyUpdate), `webrtc_dtls13_hs` (client and shared steps), `webrtc_dtls13_server`, `webrtc_dtls13_keys`, `webrtc_dtls13_record`, `webrtc_dtls13_msg`; `webrtc_dtls12` holds the DTLS 1.2 record layer and `webrtc_dtls_reasm` the reassembly both versions share.
- Not implemented, as WebRTC does not use them: PSK, resumption, 0-RTT, post-handshake authentication, connection IDs.

### Consequences

- Peers with DTLS 1.3 get its shorter handshake, encrypted handshake messages and record numbers, and KeyUpdate; others fall back to DTLS 1.2 with downgrade protection.
- OTP ssl can no longer be the only oracle: DTLS 1.3 is checked against OpenSSL 4 and, through the peer connection suite, against Chromium.

### Findings from the interop suite

- OpenSSL 4.1 `s_server -dtls1_3` and `s_client -dtls1_3` interoperate in both roles with every TLS 1.3 suite, RSA and ECDSA certificates and KeyUpdate started by either side; exported keying material matches. OpenSSL always starts with a HelloRetryRequest carrying a cookie, sends two NewSessionTickets after the handshake, and as a client sends only an X25519MLKEM768 key share (our server retries for x25519). OpenSSL in `-dtls` mode sets the downgrade sentinel when it falls back to DTLS 1.2, which `openssl_downgrade_detected` checks.
- Chromium (Playwright build 1228) negotiates DTLS 1.3 by default, in both DTLS roles; data channels and SRTP media keyed from the DTLS 1.3 exporter work (`webrtc_pc_interop_SUITE`).
- Pion v3.1.15 (DTLS 1.3 is work in progress there) and aiortc negotiate DTLS 1.2: our DTLS 1.3 offer falls back.
- Firefox could not be started in the test environment, so its DTLS 1.3 support was not checked.
- The mutation tests found that a record with a sequence number far ahead of the replay window made the bitmap shift raise `system_limit`. This affected DTLS 1.2 too; a jump beyond the window now resets it.
