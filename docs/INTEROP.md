# Interoperability matrix

This page records which independent implementations the stack has been tested against, per protocol layer and scenario. Use it to check what is proven to work before you deploy against a given peer. Every row comes from an automated suite under `test/interop`; a peer that is not installed is reported as skipped by the suite, never as passed.

Run it with `make test-interop` after building the adapters (`make -C interop all`, `npm ci` in `interop/browser`).

## DTLS (webrtc_dtls_interop_SUITE)

DTLS 1.3 is offered by default. It was negotiated with OpenSSL 4.1 (`-dtls1_3`, both roles, all three suites, KeyUpdate, HelloRetryRequest, matching exported keys) and Chromium (both DTLS roles, data channel and SRTP keyed from the 1.3 exporter). Pion, aiortc and OTP ssl only support DTLS 1.2: our offer falls back, and a stripped ClientHello is detected through the downgrade sentinel. The rows below are the DTLS 1.2 cases.

Resumption and 0-RTT (`dtls => #{resumption => true, early_data => true}`) were tested with OpenSSL 4.1 in both roles:

- `s_client -sess_out` then `-sess_in` resumes against our server, and its `-early_data` is accepted in 0-RTT.
- Our client resumes against `s_server` with a ticket OpenSSL issued. `s_server` always sends its cookie HelloRetryRequest, which rejects 0-RTT, so our client reports `early_data_rejected` and resends after the handshake. With anti-replay on, OpenSSL uses single-use tickets that the first ClientHello consumes, so the retried one gets a full handshake; the case runs `s_server -no_anti_replay`.

| Peer | Our role | Handshake | SRTP profile | Exported keys match | App data | Status |
|---|---|---|---|---|---|---|
| OTP ssl 11.7.8 (DTLS 1.2) | client | yes | AEAD_AES_128_GCM | yes | both ways | Pass (with `require_ems => false`, OTP has no RFC 7627) |
| OTP ssl 11.7.8 | server | yes | AEAD_AES_128_GCM | yes | both ways | Pass (same) |
| OTP ssl 11.7.8 | client, wrong fingerprint | refused | | | | Pass |
| OTP ssl 11.7.8 | client, EMS required | refused with `extended_master_secret_required` | | | | Pass |
| OpenSSL 4.1 s_server | client | yes | negotiated | printed only by s_client | to OpenSSL | Pass |
| OpenSSL 4.1 s_client | server | yes | negotiated | yes | from OpenSSL | Pass |
| mbedTLS 3.6 ssl_server2, CID | client (offering 1.3 and 1.2) | DTLS 1.2, CIDs both ways | AES128_CM_SHA1_80 | yes | both ways | Pass |
| mbedTLS 3.6 ssl_client2, CID | server | DTLS 1.2, CIDs both ways | AES128_CM_SHA1_80 | yes | both ways | Pass |
| mbedTLS 3.6 ssl_server2 without CID | client | DTLS 1.2, no CID | AES128_CM_SHA1_80 | | | Pass |
| pion/dtls 3.1 server, 8 byte CID | client | DTLS 1.2, CIDs both ways | negotiated | yes | both ways | Pass |
| pion/dtls 3.1 client, 8 byte CID | server | DTLS 1.2, CIDs both ways | negotiated | yes | both ways | Pass |
| pion/dtls 3.1 server, send-only CID | client | DTLS 1.2, plain records to pion, CID records to us | negotiated | | both ways | Pass |

The CID cases check the wire: every protected record we send carries the peer's CID. mbedTLS pads the inner plaintext of CID records to 16 bytes. Its `exp_label` option stops `ssl_server2` 3.6 after the handshake, so the keys are compared through the DTLS-SRTP key material it prints anyway.

## BoringSSL's DTLS tests (webrtc_bogo_SUITE)

BoringSSL's test runner (BoGo, pinned in `interop/bogo/BORINGSSL_REV`) drives our DTLS engine through a shim (`interop/bogo`). The runner is an independent DTLS 1.2 and 1.3 implementation that sends reordered, fragmented, replayed and deliberately broken traffic and checks every record we send back.

Of its 1,488 DTLS tests, 236 run and pass, and none fails. The others are:
- unimplemented in the shim: features a WebRTC peer does not use (resumption in DTLS 1.2, PSK, ECH, OCSP, ALPN, raw public keys, credential selection), and server tests without client authentication, which WebRTC always requires (RFC 8827);
- disabled in `interop/bogo/config.json`, each with its reason: DTLS 1.0, static RSA and CBC suites, records we discard where BoringSSL aborts (RFC 6347 §4.1.2.7), and tests that check a BoringSSL choice the RFC does not make: an ACK for a copy of a HelloRetryRequest (RFC 9147 §7.1 says SHOULD NOT), a ClientHello resent after a complete ServerHello (§7.2 makes the ServerHello an implicit ACK), and a KeyUpdate answered before its ACK (we follow Figure 14, as OpenSSL requires).

Running the suite found and fixed:
- an ECDSA client that could not reach an RSA server, the HelloVerifyRequest version, reassembly of one-byte fragments;
- wrong alerts for unexpected messages, unsolicited extensions, oversized records and bad Finished messages;
- a replayed or final flight that made the client resend its own, a DTLS 1.3 ServerHello accepted after a HelloVerifyRequest, alerts in the wrong epoch, empty certificate_authorities accepted;
- copies of the peer's flight in the same burst making us resend ours, the client's final flight taken as acknowledged by a NewSessionTicket or KeyUpdate, messages spanning a key change accepted, ACK sets without bound and an ACK timer re-armed after its ACK, the previous epoch kept forever after a KeyUpdate, and a reassembly window one message wider than a flight.

## DTLS state machine learning (interop/dtlsfuzzer)

DTLS-Fuzzer (pinned in `interop/dtlsfuzzer/DTLS_FUZZER_REV`) learns the state machine of our DTLS 1.2 server from its answers to handshake messages sent in every order. You run it by hand with `interop/dtlsfuzzer/learn.sh`, which compares the learned model with `interop/dtlsfuzzer/models/server_ecdhe_cert_req.dot`.

The first model showed the server taking a ChangeCipherSpec before the client's CertificateVerify, then reading that CertificateVerify encrypted. The server now holds the ChangeCipherSpec until the CertificateVerify is verified (DTLS-74). No other path reaches the connected state.

## TURN relay (webrtc_turn_interop_SUITE)

Erlang peers against the pion/turn v5 server (`interop/turn`). A filter drops every datagram not addressed to the server, so only relayed pairs can work.

| Scenario | Selected pair | Status |
|---|---|---|
| Both peers relay-only, data channel | relay / relay | Pass |
| Both peers relay-only, RTP | relay / relay | Pass |
| One peer relay-only, the other direct | relay / host | Pass |
| Wrong TURN password: no relay candidate, no connection | | Pass |
| One peer reaches the server only over TCP (no UDP leaves it), data channel | relay (TCP to the server) / host | Pass |
| The same over TLS, server certificate verified against the suite's CA | relay (TLS to the server) / host | Pass |
| TLS server certificate not trusted: no relay candidate | | Pass |

## Redundant audio against GStreamer (webrtc_red_gst_SUITE)

RED (RFC 2198) is an RTP payload format, so the suite exchanges it with GStreamer's `rtpredenc` and `rtpreddec` over plain RTP on UDP, without a WebRTC stack around them. GStreamer is the one RED implementation independent of libwebrtc: Firefox, Pion and aiortc have no audio RED. Install it with `brew install gstreamer` or `apt-get install gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good`; without it the suite is skipped.

- GStreamer encodes Opus in RED with `distance` 1 and 2; every redundant block matches the primary it repeats, and with every third packet lost we get 59 of 60 packets back (the last one has no later packet).
- We encode, with every third packet lost: `rtpreddec` and `opusdec` decode 226560 bytes of audio, against 230400 with no loss and 153600 without redundancy.

Running it found that a redundant block was taken for the previous packet, as libwebrtc sends it, when GStreamer's `distance` 2 repeats the one before; blocks are now placed by their timestamp.

## Frames against GStreamer and ffmpeg (webrtc_frames_gst_SUITE)

GStreamer encodes 90 frames of 320 x 240 and packetizes them with its own payloaders (`rtpvp8pay`, `rtpvp9pay`, `rtph264pay`, `rtpav1pay`, 600 byte MTU) over plain RTP on UDP; our frame buffer puts the frames together; ffmpeg decodes them. Install them with `brew install gstreamer ffmpeg`, or `apt-get install gstreamer1.0-plugins-good gstreamer1.0-plugins-ugly gstreamer1.0-plugins-bad ffmpeg`; a codec whose elements are missing is skipped with their names (`rtpav1pay` comes from gst-plugins-rs, which Ubuntu does not package).

- In order: every frame comes out, ffmpeg decodes each one without an error, at 320 x 240, with the same key frames.
- One packet in 40 lost and packets reordered by up to 30 ms (no PLI reaches GStreamer, which sends a key frame every 30 frames): what comes out decodes without an error. AV1 46 of 90 frames, VP8 45, VP9 29, H.264 15.

Running it, and the property test with the same frames, found an IDR slice taken for the start of its access unit while the packet with its SPS and PPS was still on its way, and a frame put together with parameter sets that came after it.

## Guide examples (webrtc_examples_SUITE)

The examples of [docs/guides](guides) run as written. `examples/browser_datachannel` serves its page with OTP's inets; headless Chromium and Firefox load it, post their offer, and get the greeting and the echo over the data channel. Playwright's Firefox does not start from a terminal on macOS, so the Firefox case runs on Linux.

## Harness control (webrtc_harness_SUITE)

These runs connect independent implementations to each other through the controller, to prove the harness before it is used against this stack.

| A | B | Scenario | Status |
|---|---|---|---|
| Pion v4.2.26 | Pion v4.2.26 | data channel echo | Pass |
| Pion v4.2.26 | Pion v4.2.26 | audio and video negotiation | Pass |
| Pion v4.2.26 | aiortc 1.16.0 | data channel echo | Pass |
| Chromium 147 | Pion v4.2.26 | data channel echo | Pass |
| Chromium 147 | Chromium 147 | audio and video, frames decoded | Pass |
| Firefox 160 | Pion v4.2.26 | data channel echo | Pass |
| Firefox 160 | Firefox 160 | audio and video, frames decoded | Pass |

## Peer connection (webrtc_pc_interop_SUITE)

The full Erlang peer connection (ICE, DTLS, SRTP, RTP/RTCP, SCTP, DCEP, JSEP) against independent implementations over UDP on the test host.

| Scenario | Pion v4.2.26 | aiortc 1.16.0 | Chromium 147 | Firefox 160 |
|---|---|---|---|---|
| Erlang offers, data channel, text echo | Pass | Pass | Pass | Pass |
| Peer offers, data channel, both directions | Pass | Pass | Pass | Pass |
| Unordered, max_retransmits 0 channel offered by the peer | Pass | Pass | Pass | Pass |
| 60 KB binary message and echo | Pass | Pass | Pass | Pass |
| Erlang sends Opus RTP (peer echoes or decodes) | Pass (echo verified) | Pass (decoded) | Pass (decoded) | Pass |
| Peer sends its own audio and video, Erlang forwards every packet back, peer decodes 10+ video frames | Skipped (2) | Pass | Pass | Pass |
| Peer closes, Erlang reports the connection closed | Pass | Pass | Pass | Pass |
| Erlang renegotiates: adds an audio section, data channel survives | Pass | Pass | Pass | Pass |
| ICE restart started by Erlang, DTLS and SCTP survive | Pass | Pass | Pass | Pass |
| ICE restart started by the peer | Pass | Pass | Pass | Pass |
| Erlang as ICE-Lite agent answering a full agent | Pass | Pass | Pass | Pass |
| Peer sends three simulcast layers (rid q, h, f), Erlang receives 50+ packets on each and a keyframe request reaches one layer only | Skipped (3) | Skipped (3) | Pass | Pass |
| Erlang sends three simulcast layers, the peer receives each one by rid | Pass | Skipped (4) | Skipped (4) | Pass |
| Erlang sends Opus with the RFC 6464 audio level (offered in clear), the peer reads the level | Pass (no level negotiated) | Pass | Pass | Pass |
| Erlang offers the audio level clear and encrypted (RFC 6904, `encrypt_header_extensions => offer`), the peer falls back | Pass (no level) | Skipped (13) | Pass (14) | Pass (clear) |
| The peer sends its audio with the level, Erlang reads it | Skipped (2) | Pass | Pass | Pass |
| Cryptex (RFC 9335): the answer accepts it, Erlang's RTP leaves with encrypted extensions (0xC0DE), the peer decrypts and echoes it | Pass | Skipped (12) | Skipped (12) | Skipped (12) |
| Erlang offers to receive three simulcast layers, the peer answers sending them, Erlang receives 50+ packets on each | Skipped (10) | Skipped (10) | Skipped (11) | Pass |
| Peer offers with mDNS host candidates only, Erlang resolves them, data channel both ways | | | Pass (5) | |
| Erlang offers, peer answers with mDNS host candidates only, Erlang's checks to the resolved addresses answered | | | Pass (5) | |
| ICE-TCP, Erlang offers: no UDP leaves Erlang, data channel echo, selected pair TCP | | | Pass (6) | Pass (6) |
| ICE-TCP, peer offers: the same, the peer sends | | | Pass (6) | Pass (6) |
| Erlang offers without BUNDLE (`bundle => false`): audio, video and data each on their own ICE and DTLS transport, data channel echo and Opus received | Skipped (7) | Skipped (8) | Pass (9) | Pass |
| The peer sends VP8, VP9, H.264 and AV1 in turn, Erlang receives frames (`frames => true`): each one parses, as many frames and key frames as the peer encoded | Skipped (15) | Skipped (15) | Pass | Pass (16) |

1. Firefox is the installed release (160 on the development machine), driven over WebDriver BiDi with puppeteer-core. On macOS it is started through launchd: a Firefox started from a terminal inherits the terminal's privacy restrictions and cannot read its profile. Without an installed Firefox the suite falls back to Playwright's build.
2. The Pion adapter has no media source of its own; Pion media is covered by the echo case.
3. The adapter has no simulcast encoder.
4. Browsers do not receive simulcast (RFC 9429 §3.7); aiortc answers without it.
6. Groups `chromium_tcp` and `firefox_tcp`: Erlang with `ice_tcp` and an outbound filter that drops every UDP datagram, so only a TCP pair can work. Both browsers gather active TCP candidates and connect to Erlang's passive one.
7. Pion runs one ICE transport per peer connection and rejects sections outside a BUNDLE group.
8. aiortc answers an unbundled offer with a BUNDLE group; we refuse such answers (RFC 9143 §7.3, see the findings).
9. Chromium with `bundlePolicy: 'balanced'`; with `max-bundle` it refuses offers without BUNDLE, as the W3C policy requires.
10. The peer answers with a single stream.
11. Chromium 147 answers an offer to receive simulcast with `a=inactive`.
12. The peer answers without `a=cryptex`.
13. aiortc 1.16 cannot parse an `a=extmap` line with an extension attribute (see the findings).
14. Chromium 149 answers without the audio level at all when it is offered in both forms.
15. Only the browsers are given a codec to send.
16. VP8, VP9 and AV1. Firefox lists H.264 but encodes nothing without its OpenH264 plugin, which a fresh profile has not downloaded.
5. Group `chromium_mdns`: Chromium launched with its default `WebRtcHideLocalIpsWithMdns` (adapter option `--mdns`, no media permission granted), so every host candidate is a `<uuid>.local` name. The group is skipped with the reason when IPv4 multicast to 224.0.0.251:5353 does not loop back on the test host.

### Interoperability findings

| Peer | Finding | Resolution |
|---|---|---|
| Pion | Sends DATA_CHANNEL_ACK padded to 4 bytes (`02 00 00 00`). We rejected it and reset the stream. | RFC 8832 §5.2 defines the message by its type byte; libwebrtc reads only that byte. Trailing bytes are now ignored (`webrtc_dcep_tests:ack_test`). |
| OTP ssl | No RFC 7627 extended master secret. | Kept required by default; the OTP DTLS tests opt out explicitly. |
| aiortc 1.16.0 | Answering a re-offer raises `ValueError` in `and_direction` when a local transceiver created before the first negotiation is still unassociated (`_offerDirection` is `None`). | aiortc bug; our re-offer is valid (Pion and Chromium accept it). The renegotiation case gives aiortc no local track. |
| Chromium | Discards remote candidates of the previous ICE generation on restart. | Our transport now signals its candidates again after `restart_ice` (RFC 8445 §9); this was a bug on our side, hidden by Pion keeping old candidates. |
| Chromium | Its bandwidth estimate stays at the start value when transport-wide congestion control is negotiated but no feedback comes, so the top simulcast layer is never encoded. | Fixed by our transport-wide congestion control feedback: with it negotiated, Chromium encodes all three layers. With a 640x360 capture Chromium also limits itself to two layers; the case captures 1280x720. |
| Firefox | Offers with the max-bundle policy: every bundled m= section but the first has port 0 and `a=bundle-only`. We treated port 0 as rejected and answered the video section rejected, so Firefox never sent video. | Our bug (RFC 9143 §6, RFC 9429 §5.2.1). Bundle-only sections of a BUNDLE group are now accepted (`webrtc_jsep_tests:bundle_only_section_accepted_test`). Chromium uses port 9 everywhere, which hid it. |
| aiortc 1.16.0 | Answers an offer without BUNDLE with `a=group:BUNDLE` over every section. We accepted it, so our transports no longer matched the answer and ICE never completed. | aiortc bug (RFC 9143 §7.3). Such answers are now refused with `bundle_not_offered` (`webrtc_jsep_tests:answer_adds_bundle_refused_test`). |
| aiortc 1.16.0 | Raises `ValueError` on `a=extmap:N urn:ietf:params:rtp-hdrext:encrypt <uri>`: its parser expects exactly two fields, while RFC 8285 §8 allows extension attributes. | aiortc bug. We offer the encrypted forms only with `encrypt_header_extensions => offer`; the default accepts them when offered. |
| Chromium 149 | Never negotiates RFC 6904 (not with `WebRtcEncryptedRtpHeaderExtensions` either) and, offered an extension in both forms, answers without it. Its synchronization sources (the RFC 6464 level) only update while the received audio plays out. | Default as above. The browser adapter plays received audio in a muted element to read the level. |
| Harness | Pion adapter echo built RTP headers with version 0, which RFC 7983 demultiplexing classifies as STUN. | Fixed in the adapter; not a stack issue. |
| Chromium | Its mDNS responder ignores queries with more than one question and QU questions, and answers QM questions by multicast only. | The resolver sends A and AAAA in separate messages, retransmits as QM after 250 ms and listens on the group (SO_REUSEPORT) as well as on its query port. |
| Chromium | When Chromium is controlling, ICE may complete through the peer-reflexive candidate its checks create before the names resolve. | Expected (draft section 6.3); the resolved candidates are still added. |
