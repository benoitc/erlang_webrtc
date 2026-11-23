# Changelog

All notable changes are listed here, newest first. Each release section is also its release notes.

## 0.3.0 (2026-11-23)

- A codec plugin can now run its codec in a process of its own and deliver the decoded outputs and encoded frames later, so a slow codec no longer holds up the connection's other media and data channels. A plugin opts in by exporting `init/4`; others work as before.
- A codec plugin can now hear what concerns its encoder: key frame requests from the peer, the peer's bitrate limit, and a target bitrate the application sets with the new `webrtc:set_target_bitrate/3`. It can free its native resources when its stream ends, skip a bad frame or picture without being turned off, and report the frames it dropped. Plugins written for 0.2.0 keep working unchanged.
- The plugin documentation said a decoder could ask for a key frame only when slice loss indications were negotiated. It always can.
- H.264 frames were packetized for packetization mode 1 whatever mode was negotiated, which a peer that accepts mode 0 or mode 2 alone cannot depacketize. Each mode now gets the packet types it allows. In mode 0, a frame with a NAL unit too large for one packet is refused with an error instead of being sent.

## 0.2.0 (2026-11-19)

- AV1 and H.264 frames were dropped, and key frames asked for again and again, when the peer sent bandwidth probes on the video stream, which it does when RTX is not negotiated. No frame is lost to them now.
- The LICENSE file had one word more than the Apache License 2.0 ("submitted to the Licensor"); its terms now match the licence word for word.
- `webrtc:default_codecs/1` returns the codecs a peer connection offers by default, and `webrtc:prefer_codec/2` moves one codec, with its retransmission entry, to the front of such a list. Use them with the `codecs` option to offer AV1 or H.264 first, without reaching into internal modules.

## 0.1.0 (2026-11-19)

The first release: a WebRTC stack in pure Erlang, with no native code and no dependency beyond OTP. You can use it to build servers that talk to browsers and other WebRTC stacks, such as SFUs, media gateways, data channel services and test peers. Signaling, media coding and routing stay in your application.

### Connections

- Peer connections negotiate offers and answers as browsers do, including renegotiation, rollback and provisional answers.
- ICE finds a path through NATs with STUN and TURN servers given as browser-style URIs, over UDP, TCP or TLS, and with ICE-TCP. It accepts the hidden `.local` addresses browsers send by default, can restart on its own when the path stops working if you ask it to, and can run as ICE lite.
- DTLS 1.3 is used by default, with fallback to DTLS 1.2. Certificates are checked against the fingerprints in the session description.
- Media and data share one network path by default (BUNDLE). Sessions that use several paths, or none bundled, also work.

### Data channels

- Reliable, unordered and partially reliable channels, large messages, channel priorities, and a signal when a full send buffer has room again.
- After a network outage, channels resume within seconds of the path coming back, and they stay open as long as the connection does. The retransmission timers can be changed.

### Audio and video

- Send and receive Opus, G.711, VP8, VP9, H.264 and AV1, as RTP packets or as whole frames.
- Forward packets between peer connections without decoding them, SFU style, with keyframe requests passed to the sender.
- Simulcast: receive several layers from a browser and send layers to peers that accept them, and pause and resume a layer.
- Lost packets are retransmitted. Audio can carry redundancy (RED), and video can carry FEC, so a lost packet is rebuilt without waiting for a retransmission.
- Frames arrive in order through a jitter buffer, and a keyframe is requested when a frame cannot be completed.
- New streams are synchronised quickly, without waiting for the first sender report.
- A codec plugin can decode the frames you receive and encode what you send. The library itself does no media coding.

### Bandwidth and quality of service

- Congestion control estimates the available bandwidth from the peer's feedback, paces what you send, and tells you the rate to give your encoders. It is tested against the standard RMCAT evaluation cases in simulation.
- Circuit breakers stop a stream that would harm the network.
- A peer can limit the rate you send on a stream, and you can limit what a peer sends you (TMMBR).
- Packets are marked for network quality of service (DSCP), by media type and priority.

### Statistics

- The W3C statistics a browser's `getStats()` returns, with the decoder and encoder figures coming from your codec plugin or from your application.

### Security and robustness

- Every parser is tested with hostile input, and each connection's state has fixed limits, whatever a peer sends.
- Private keys, passwords and session keys never appear in logs or crash reports.
- Every process of a peer connection ends with it, however it ends.
- 0-RTT data cannot be replayed, even after the application restarts.

### Tested against

- Chromium, Firefox, Pion, aiortc, GStreamer, pion/turn, OTP ssl and OpenSSL, plus the BoringSSL DTLS tests, DTLS-Fuzzer and the ETSI SCTP conformance tests.
