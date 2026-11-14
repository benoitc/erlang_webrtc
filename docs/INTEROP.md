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

## Peer connection (webrtc_pc_interop_SUITE)

The full Erlang peer connection (ICE, DTLS, SRTP, RTP/RTCP, SCTP, DCEP, JSEP) against independent implementations over UDP on the test host.

| Scenario | Pion v4.2.26 | aiortc 1.16.0 | Chromium 147 | Firefox 148 |
|---|---|---|---|---|
| Erlang offers, data channel, text echo | Pass | Pass | Pass | Not run (1) |
| Peer offers, data channel, both directions | Pass | Pass | Pass | Not run (1) |
| Unordered, max_retransmits 0 channel offered by the peer | Pass | Pass | Pass | Not run (1) |
| 60 KB binary message and echo | Pass | Pass | Pass | Not run (1) |
| Erlang sends Opus RTP (peer echoes or decodes) | Pass (echo verified) | Pass (decoded) | Pass (decoded) | Not run (1) |
| Peer sends its own audio and video, Erlang forwards every packet back, peer decodes 10+ video frames | Skipped (2) | Pass | Pass | Not run (1) |
| Peer closes, Erlang reports the connection closed | Pass | Pass | Pass | Not run (1) |

1. Firefox cannot launch inside the sandbox of the development machine; the suite reports it as skipped. It runs in the CI interop job.
2. The Pion adapter has no media source of its own; Pion media is covered by the echo case.

### Interoperability findings

| Peer | Finding | Resolution |
|---|---|---|
| Pion | Sends DATA_CHANNEL_ACK padded to 4 bytes (`02 00 00 00`). We rejected it and reset the stream. | RFC 8832 §5.2 defines the message by its type byte; libwebrtc reads only that byte. Trailing bytes are now ignored (`webrtc_dcep_tests:ack_test`). |
| OTP ssl | No RFC 7627 extended master secret. | Kept required by default; the OTP DTLS tests opt out explicitly. |
| Harness | Pion adapter echo built RTP headers with version 0, which RFC 7983 demultiplexing classifies as STUN. | Fixed in the adapter; not a stack issue. |
