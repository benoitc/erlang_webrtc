# Interoperability matrix

This page records which independent implementations the stack has been tested against, per protocol layer and scenario. Use it to check what is proven to work before you deploy against a given peer. Every row comes from an automated suite under `test/interop`; a peer that is not installed is reported as skipped by the suite, never as passed.

Run it with `make test-interop` after building the adapters (`make -C interop all`, `npm ci` in `interop/browser`).

## DTLS (webrtc_dtls_interop_SUITE)

| Peer | Our role | Handshake | SRTP profile | Exported keys match | App data | Status |
|---|---|---|---|---|---|---|
| OTP ssl 11.7.8 (DTLS 1.2) | client | yes | AEAD_AES_128_GCM | yes | both ways | Pass (with `require_ems => false`, OTP has no RFC 7627) |
| OTP ssl 11.7.8 | server | yes | AEAD_AES_128_GCM | yes | both ways | Pass (same) |
| OTP ssl 11.7.8 | client, wrong fingerprint | refused | | | | Pass |
| OTP ssl 11.7.8 | client, EMS required | refused with `extended_master_secret_required` | | | | Pass |
| OpenSSL 4.1 s_server | client | yes | negotiated | printed only by s_client | to OpenSSL | Pass |
| OpenSSL 4.1 s_client | server | yes | negotiated | yes | from OpenSSL | Pass |

## Harness control (webrtc_harness_SUITE)

These runs connect independent implementations to each other through the controller, to prove the harness before it is used against this stack.

| A | B | Scenario | Status |
|---|---|---|---|
| Pion v4.2.26 | Pion v4.2.26 | data channel echo | Pass |
| Pion v4.2.26 | Pion v4.2.26 | audio and video negotiation | Pass |
| Pion v4.2.26 | aiortc 1.16.0 | data channel echo | Pass |
| Chromium 147 | Pion v4.2.26 | data channel echo | Pass |
| Chromium 147 | Chromium 147 | audio and video, frames decoded | Pass |
| Firefox 148 | any | | Skipped on macOS in the sandboxed dev environment (browser launch denied); runs in CI on Linux |

## Peer connection (Erlang stack against independent peers)

Not run yet: the transport and peer connection layers are being integrated. Rows will be added per scenario (offerer and answerer roles, data channels reliable and partially reliable, audio and video, renegotiation, ICE restart, teardown).
