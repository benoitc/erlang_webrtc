# erlang_webrtc: a codec plugin package, and device capture: prompt

Paste the block below into a Claude Code session opened on a new, empty
repository (for example `~/Projects/webrtc_codecs`). erlang_webrtc stays pure
Erlang; this package is where native code comes in.

```text
Context
- erlang_webrtc (~/Projects/erlang_webrtc, branch feature/webrtc-stack) is a pure
  Erlang WebRTC stack. It packetizes and reassembles media but never encodes or
  decodes it. A codec plugin does that, through the behaviour
  src/transport/webrtc_media_codec.erl. Read that module, the "Decode and encode
  with a codec plugin" and "Receive frames" sections of its README.md, and the
  test plugin test/support/webrtc_test_codec.erl before anything else.
- The behaviour:
    init(audio | video, Codec, Opts) -> {ok, State} | {error, Reason}
        Codec is the negotiated codec map: name (<<"VP8">>, <<"opus">>, ...),
        clock_rate, channels, fmtp.
    decode(Frame, State) -> {ok, [Out], Stats, State} | {error, Reason}
        Frame is #{data, timestamp, keyframe, codec} plus width and height for
        video. data is a VP8 or VP9 frame, an H.264 access unit in Annex B, an
        AV1 temporal unit in the low overhead format, an Opus packet, or a G.711
        payload. Every Out becomes {webrtc, Pc, {decoded, Mid, Out}}.
    encode(Raw, State) -> {ok, [Frame], Stats, State} | {error, Reason}
        Raw is whatever the plugin defines; the application passes it to
        webrtc:send_media(Pc, Mid, Raw). Each returned Frame is
        #{data, timestamp (RTP clock), keyframe}; the stack packetizes it.
    info(State) -> #{implementation => binary(), power_efficient => boolean()}
- Stats are W3C member names: framesDecoded, keyFramesDecoded, totalDecodeTime,
  qpSum, concealedSamples, framesEncoded, keyFramesEncoded, totalEncodeTime,
  qualityLimitationReason, ... Counters add up across calls, other members
  replace. They show in webrtc:get_stats(Pc, #{format => w3c}).
- Use: webrtc:add_transceiver(Pc, video, #{frames => true,
  codec_plugin => {Module, Opts}}), or codec_plugins => #{audio => ...,
  video => ...} with frames => true on new_peer_connection/1 for transceivers a
  remote offer creates.
- The plugin runs inside the transport process: a slow call delays every packet
  of the connection. A plugin that raises or returns an error is turned off for
  its transceiver ({codec_plugin_error, Mid, Reason}).
- The owner also gets {keyframe_request, Mid} (the peer lost a frame: the next
  encoded frame must be a key frame) and {bandwidth_estimate, Bps} (the target
  bitrate of the connection).

Goal
A package, separate from erlang_webrtc and depending on it, with codec plugins
for Opus and G.711 (audio) and VP8, VP9, H.264 and AV1 (video), decoding and
encoding, plus the device capture and playback described below. Start with a
plan: propose the native layer and the module layout and wait for my answer.

Native layer: choose and justify in the plan
- FFmpeg (libavcodec) through a NIF: every codec in one library; mind LGPL and
  the codecs FFmpeg is built with (libx264 is GPL, prefer openh264 or a hardware
  encoder for H.264).
- The reference libraries through NIFs: libopus, libvpx, openh264, dav1d (AV1
  decode), libaom or SVT-AV1 (AV1 encode).
- A port program (ffmpeg or a small C program over stdio): crashes stay out of
  the VM, at the cost of a copy and a context switch per frame.
- NIFs must run codec work on dirty CPU schedulers, keep codec contexts in
  resource objects freed by a destructor, never block a normal scheduler, and
  turn every native error into {error, Reason}.

Requirements
1. One plugin module per codec family, each implementing webrtc_media_codec,
   with init/3 choosing decoder or encoder settings from the negotiated codec
   (H.264 profile-level-id and packetization-mode, VP9 profile-id, Opus stereo
   and useinbandfec).
2. Decode: Out carries raw pictures (I420 planes, width, height, timestamp) and
   raw audio (PCM, sample rate, channels). Report framesDecoded,
   keyFramesDecoded, totalDecodeTime, and for audio totalSamplesReceived and
   concealedSamples; decoderImplementation through info/1.
3. Encode: Raw is a documented map (pictures: I420 planes, width, height,
   timestamp; audio: PCM frames of 10 or 20 ms) with an optional
   keyframe => true the application sets after {keyframe_request, Mid}. The
   encoder follows the bitrate the application passes after
   {bandwidth_estimate, Bps} (Opts or a field of Raw: decide in the plan).
   Report framesEncoded, keyFramesEncoded, totalEncodeTime, targetBitrate,
   encoderImplementation.
4. Timestamps: decoded frames keep the RTP timestamp they came with; encoded
   frames get an RTP timestamp at the codec clock rate (90 kHz video, 48 kHz
   Opus, 8 kHz G.711).
5. Bounded: no queue grows without bound; a frame that cannot be decoded is
   dropped and counted, not retried forever.

Device capture and playback
erlang_webrtc captures nothing. The package adds capture as its own modules,
separate from the codecs:
- Sources: a camera and a microphone, through FFmpeg's libavdevice
  (avfoundation on macOS, v4l2 and alsa or pulse on Linux, dshow on Windows) or
  GStreamer (autovideosrc, autoaudiosrc), in a port program or a NIF thread.
  macOS asks the user for camera and microphone access the first time (the
  terminal or app bundle needs the permission); Linux needs the user in the
  video and audio groups.
- A capture process owns the device and sends raw frames to an owner process,
  which calls webrtc:send_media(Pc, Mid, Raw). Two flows to support:
    raw capture -> send_media/3 -> the plugin encodes -> RTP
    capture and encode in one native pipeline -> webrtc:send_frame/4 (no plugin)
- Playback: decoded frames to a sink (SDL window, speaker) in a port, for
  manual tests; files (IVF, WAV, MP4 through FFmpeg) for automated ones.
- List devices, pick one by name or index, set size, frame rate, sample rate.

Tests
- Round trips: encode then decode, compare (PSNR above a threshold for video,
  sample counts for audio).
- Against erlang_webrtc's corpus (test/corpora/frames): decode every frame, the
  sizes and key frames match.
- Two erlang_webrtc peers on loopback, one encoding from a test pattern, the
  other decoding: framesEncoded and framesDecoded agree in get_stats.
- A browser: Chromium (Playwright, as erlang_webrtc's interop/browser does)
  sends its fake camera; the plugin decodes it. Erlang encodes a test pattern,
  the browser decodes it (framesDecoded rises).
- Capture tests skip with the reason when no device exists (CI); a fake device
  (FFmpeg lavfi testsrc, GStreamer videotestsrc) covers them there.

Rules
- Read erlang_webrtc's AGENTS.md and follow its style: one PR per item, several
  commits, no co-authored-by or generated lines, concise comments and PR
  descriptions (intent, solution, breaking changes), no test plan in PRs, docs
  task-oriented in the second person, never the word "comprehensive", no em
  dash.
- Do not change erlang_webrtc to suit the plugin without asking; report what the
  behaviour lacks instead.
```
