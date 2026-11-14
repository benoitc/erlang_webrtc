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
