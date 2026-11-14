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

## TURN relay (webrtc_turn_interop_SUITE)

Erlang peers against the pion/turn v5 server (`interop/turn`). A filter drops every datagram not addressed to the server, so only relayed pairs can work.

| Scenario | Selected pair | Status |
|---|---|---|
| Both peers relay-only, data channel | relay / relay | Pass |
| Both peers relay-only, RTP | relay / relay | Pass |
| One peer relay-only, the other direct | relay / host | Pass |
| Wrong TURN password: no relay candidate, no connection | | Pass |

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
| Erlang renegotiates: adds an audio section, data channel survives | Pass | Pass | Pass | Not run (1) |
| ICE restart started by Erlang, DTLS and SCTP survive | Pass | Pass | Pass | Not run (1) |
| ICE restart started by the peer | Pass | Pass | Pass | Not run (1) |
| Erlang as ICE-Lite agent answering a full agent | Pass | Pass | Pass | Not run (1) |
| Peer sends three simulcast layers (rid q, h, f), Erlang receives 50+ packets on each and a keyframe request reaches one layer only | Skipped (3) | Skipped (3) | Pass | Not run (1) |
| Erlang sends three simulcast layers, the peer receives each one by rid | Pass | Skipped (4) | Skipped (4) | Not run (1) |
| Peer offers with mDNS host candidates only, Erlang resolves them, data channel both ways | | | Pass (5) | |
| Erlang offers, peer answers with mDNS host candidates only, Erlang's checks to the resolved addresses answered | | | Pass (5) | |

1. Firefox cannot launch inside the sandbox of the development machine; the suite reports it as skipped. It runs in the CI interop job.
2. The Pion adapter has no media source of its own; Pion media is covered by the echo case.
3. The adapter has no simulcast encoder.
4. Browsers do not receive simulcast (RFC 9429 §3.7); aiortc answers without it.
5. Group `chromium_mdns`: Chromium launched with its default `WebRtcHideLocalIpsWithMdns` (adapter option `--mdns`, no media permission granted), so every host candidate is a `<uuid>.local` name. The group is skipped with the reason when IPv4 multicast to 224.0.0.251:5353 does not loop back on the test host.

### Interoperability findings

| Peer | Finding | Resolution |
|---|---|---|
| Pion | Sends DATA_CHANNEL_ACK padded to 4 bytes (`02 00 00 00`). We rejected it and reset the stream. | RFC 8832 §5.2 defines the message by its type byte; libwebrtc reads only that byte. Trailing bytes are now ignored (`webrtc_dcep_tests:ack_test`). |
| OTP ssl | No RFC 7627 extended master secret. | Kept required by default; the OTP DTLS tests opt out explicitly. |
| aiortc 1.16.0 | Answering a re-offer raises `ValueError` in `and_direction` when a local transceiver created before the first negotiation is still unassociated (`_offerDirection` is `None`). | aiortc bug; our re-offer is valid (Pion and Chromium accept it). The renegotiation case gives aiortc no local track. |
| Chromium | Discards remote candidates of the previous ICE generation on restart. | Our transport now signals its candidates again after `restart_ice` (RFC 8445 §9); this was a bug on our side, hidden by Pion keeping old candidates. |
| Chromium | Its bandwidth estimate stays at the start value when transport-wide congestion control is negotiated but no feedback comes, so the top simulcast layer is never encoded. | Fixed by our transport-wide congestion control feedback: with it negotiated, Chromium encodes all three layers. With a 640x360 capture Chromium also limits itself to two layers; the case captures 1280x720. |
| Harness | Pion adapter echo built RTP headers with version 0, which RFC 7983 demultiplexing classifies as STUN. | Fixed in the adapter; not a stack issue. |
| Chromium | Its mDNS responder ignores queries with more than one question and QU questions, and answers QM questions by multicast only. | The resolver sends A and AAAA in separate messages, retransmits as QM after 250 ms and listens on the group (SO_REUSEPORT) as well as on its query port. |
| Chromium | When Chromium is controlling, ICE may complete through the peer-reflexive candidate its checks create before the names resolve. | Expected (draft section 6.3); the resolved candidates are still added. |
