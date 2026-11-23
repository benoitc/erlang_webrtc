# Receive frames and write a codec plugin

By default a transceiver hands you RTP packets. Ask for frames instead and the library puts the packets of each frame in order, joins them and releases the frame at its playout time, dropping what cannot be completed and asking for a key frame. A codec plugin, a module with the `webrtc_media_codec` behaviour, then decodes those frames and encodes what you send. The library itself stays pure Erlang and does no media coding, and it does not capture or play anything. You need this guide to record, analyse or decode what a peer sends, to plug an encoder or decoder in, or to feed a camera and microphone from another package. The example [`examples/browser_video`](https://github.com/benoitc/erlang_webrtc/tree/main/examples/browser_video) receives a browser's camera as frames and reports the counts back over a data channel.

## When to use

- You decode, record or inspect the media a peer sends: ask for frames.
- You have an encoder that gives whole frames: send them with `send_frame/4`.
- You wrap a native codec (FFmpeg, libvpx, Opus) so that decoding, encoding and their statistics happen per transceiver: write a codec plugin.
- You capture from devices: build it outside the library, as described at the end.

## How

### Run the example

```sh
rebar3 shell
```

```erlang
1> cd("examples/browser_video").
2> c(browser_video).
3> browser_video:start(8080).
```

Open `http://localhost:8080/` and allow the camera. Every second the page shows `erlang: frames: N keyframes: K width: 640 height: 480`. `browser_video:stop()` stops the server.

### Ask for frames

On one transceiver:

```erlang
{ok, _} = webrtc:add_transceiver(Pc, video, #{frames => true}),
```

Or for every transceiver, those a remote offer creates included:

```erlang
{ok, Pc} = webrtc:new_peer_connection(#{frames => true}),
```

Frames arrive in place of `{rtp, Mid, Packet}`:

```erlang
{webrtc, Pc, {frame, Mid, #{data := Data, keyframe := Key, codec := Codec}}} ->
    store(Mid, Codec, Key, Data),
```

A simulcast layer gives `{frame, Mid, Rid, Frame}`.

### Read a frame

| Member | Value |
|---|---|
| `data` | the encoded frame: a VP8 or VP9 frame, an H.264 access unit in Annex B, an AV1 temporal unit in the low overhead format; for audio, the payload |
| `timestamp` | the RTP timestamp (90 kHz for video, the codec clock for audio) |
| `keyframe` | `true` for a key frame |
| `codec` | the codec name, `<<"VP8">>`, `<<"opus">>`, ... |
| `width`, `height` | video only, from the last key frame, `undefined` until one came |
| `ntp_time` | when RFC 6051 is negotiated: the capture time on the sender's clock, in microseconds since the Unix epoch |

### Bound the delay

A frame leaves at its timestamp plus the smallest transit time seen, plus a target delay of three times the jitter. You bound that target in ms (defaults 0 and 10000):

```erlang
{ok, _} = webrtc:add_transceiver(Pc, video, #{frames => #{min_delay => 50, max_delay => 500}}),
```

A frame that misses packets waits for retransmissions, then is dropped with the frames that depend on it, and a key frame is requested for you.

### Send frames

`send_frame/4` splits an encoded frame into RTP payloads for its codec:

```erlang
ok = webrtc:send_frame(Pc, Mid, Vp8Frame, #{timestamp => Ts, keyframe => true}),
```

Timestamps, keyframe requests and the other options are in [send media](send-media.md).

### Write a codec plugin

The behaviour has four callbacks and one optional:

| Callback | Called | Returns |
|---|---|---|
| `init(audio \| video, Codec, Opts)` | before the first decode of a received stream, and again when its codec changes; before the first encode | `{ok, State}` or `{error, Reason}` |
| `decode(Frame, State)` | for each frame received | `{ok, Outs, Stats, State}`, `{ok, Outs, Stats, State, Feedback}` or `{error, Reason}` |
| `encode(Raw, State)` | for each `send_media/3` call | `{ok, Frames, Stats, State}` or `{error, Reason}` |
| `info(State)` | after each decode and encode | `#{implementation => binary(), power_efficient => boolean()}` |
| `feedback(Indication, State)` (optional) | when the remote decoder reports lost slices or asks for a reference picture | `{ok, State}` or `{error, Reason}` |

`Codec` is the negotiated codec: `name`, `clock_rate`, `channels`, `fmtp`. `Frame` is the map above. `Raw` is whatever your plugin defines. Each returned frame is `#{data, timestamp, keyframe}`, with the timestamp in the codec clock; the library packetizes it.

```erlang
-module(my_vp8).
-behaviour(webrtc_media_codec).
-export([init/3, decode/2, encode/2, info/1]).

init(video, #{name := <<"VP8">>}, Opts) -> {ok, my_vp8_nif:new(Opts)}.

decode(#{data := Frame, keyframe := Key}, D) ->
    Picture = my_vp8_nif:decode(D, Frame),
    {ok, [Picture], #{framesDecoded => 1, keyFramesDecoded => key(Key)}, D}.

encode(#{picture := Picture, timestamp := Ts} = Raw, E) ->
    {Frame, Key} = my_vp8_nif:encode(E, Picture, maps:get(keyframe, Raw, false)),
    {ok, [#{data => Frame, keyframe => Key, timestamp => Ts}], #{framesEncoded => 1}, E}.

info(_) -> #{implementation => <<"libvpx">>}.

key(true) -> 1;
key(false) -> 0.
```

### Use the plugin

Set it on a transceiver that delivers frames; `codec_plugin` without `frames` is refused:

```erlang
{ok, _} = webrtc:add_transceiver(Pc, video, #{frames => true, codec_plugin => {my_vp8, #{}}}),
```

For transceivers a remote offer creates, set it by kind on the peer connection:

```erlang
{ok, Pc} = webrtc:new_peer_connection(#{frames => true, codec_plugins => #{video => {my_vp8, #{}}}}),
```

Each output of `decode/2` arrives after its `{frame, Mid, Frame}` event. `send_media/3` hands raw media to `encode/2` and sends the frames it returns:

```erlang
{webrtc, Pc, {decoded, Mid, Picture}} -> show(Picture),

ok = webrtc:send_media(Pc, Mid, #{picture => Picture, timestamp => Ts}),
```

### Follow key frame requests and bitrates

Export `control/2` and the encoder hears what concerns it: `keyframe_request` when the peer asks for a key frame, `{max_bitrate, Bps}` when the peer limits the stream with TMMBR, and `{target_bitrate, Bps}` when you set one. Ignore the events you do not know:

```erlang
control(keyframe_request, E) -> {ok, E#{force_key => true}};
control({target_bitrate, Bps}, E) -> {ok, my_vp8_nif:set_bitrate(E, Bps)};
control({max_bitrate, Bps}, E) -> {ok, E#{ceiling => Bps}};
control(_, E) -> {ok, E}.
```

The bandwidth estimate covers the whole connection, so you split it between your encoders and set each one's share:

```erlang
{webrtc, Pc, {bandwidth_estimate, Bps}} -> ok = webrtc:set_target_bitrate(Pc, VideoMid, Bps * 9 div 10),
```

A bitrate set before the first `send_media/3` reaches the encoder when it starts. The owner still gets `{keyframe_request, Mid}` and `{max_bitrate, Mid, Bps}`.

### Free native resources

Export `terminate/1` to free what `init/3` took. It runs once, when the stream ends, its transceiver goes in a renegotiation, the plugin is turned off, or the connection closes:

```erlang
terminate(E) -> my_vp8_nif:free(E).
```

### Report loss to the remote encoder

`decode/2` may return a fifth element, a list of what to send the remote encoder: `keyframe_request` asks for a key frame, always; `{slice_loss, [{First, Number, PictureId}]}` and `{reference_picture, Pt, Bits}` go out when the transceiver negotiated `nack sli` or `nack rpsi`. The other way, the remote decoder's reports reach `feedback/2` of your encoding plugin, and the owner as `{slice_loss, Mid, Entries}` and `{reference_picture, Mid, Pt, Bits}`.

### Handle errors

Return `{error, Reason, State}` for a bad frame or picture you can get past: the plugin goes on with `State`. A decode error counts the frame in `framesDropped`; an encode error makes that `send_media/3` return `{error, {encode, Reason}}`:

```erlang
decode(#{data := D}, Dec) ->
    case my_vp8_nif:decode(Dec, D) of
        {ok, Picture} -> {ok, [Picture], #{framesDecoded => 1}, Dec};
        {error, corrupt} -> {error, corrupt, Dec}
    end.
```

A callback that raises, returns `{error, Reason}` or returns something else turns the plugin off for that stream, and the owner gets:

```erlang
{webrtc, Pc, {codec_plugin_error, Mid, Reason}} -> logger:warning("plugin off on ~s: ~p", [Mid, Reason]),
```

Frames keep coming. Once the plugin is off, `send_media/3` returns `{error, {codec_plugin, Reason}}`. Without a plugin it returns `{error, no_codec_plugin}`.

### Report statistics

`Stats` are W3C member names of the stream: `framesDecoded`, `keyFramesDecoded`, `framesDropped` (added to the frames the buffer dropped), `totalDecodeTime`, `qpSum`, `totalSamplesReceived`, `concealedSamples` for decoding; `framesEncoded`, `keyFramesEncoded`, `totalEncodeTime`, `targetBitrate`, `qualityLimitationReason` for encoding. Counters add up across calls; other members replace the previous value. `info/1` fills `decoderImplementation` or `encoderImplementation`, and `powerEfficientDecoder` or `powerEfficientEncoder`.

If you code media yourself, without a plugin, report the same members with `report_media_stats/4`:

```erlang
webrtc:report_media_stats(Pc, Mid, inbound, #{framesDecoded => 1, totalDecodeTime => 0.004}),
webrtc:report_media_stats(Pc, Mid, source, #{width => 1280, height => 720, frames => 1}),
```

See [read the statistics](statistics.md).

### Run the codec in its own process

The plugin's callbacks run in the transport process: a slow call delays every packet of the connection, media, RTCP and data channels alike. For a codec that takes milliseconds per frame, export `init/4` instead of `init/3`. It gets a handle; give it to a process of your own, return from `decode/2` and `encode/2` at once with no output, and deliver the results from that process:

```erlang
init(video, Codec, Opts, Handle) ->
    W = spawn_link(fun() -> worker(Handle, my_vp8_nif:new(Codec, Opts)) end),
    {ok, W}.

decode(Frame, W) -> W ! {decode, Frame}, {ok, [], #{}, W}.
encode(Raw, W) -> W ! {encode, Raw}, {ok, [], #{}, W}.

terminate(W) -> exit(W, shutdown).

worker(H, Ctx) ->
    receive
        {decode, #{data := D}} ->
            {ok, Picture} = my_vp8_nif:decode(Ctx, D),
            webrtc_media_codec:decoded(H, [Picture], #{framesDecoded => 1});
        {encode, {Picture, Ts}} ->
            {Frame, Key} = my_vp8_nif:encode(Ctx, Picture),
            webrtc_media_codec:encoded(H, [#{data => Frame, keyframe => Key, timestamp => Ts}], #{framesEncoded => 1})
    end,
    worker(H, Ctx).
```

- `decoded/3` gives the owner `{decoded, Mid, Out}` for each output, as a synchronous decoder would; `encoded/3` sends the frames as `encode/2`'s result would be sent; `decoder_feedback/2` sends what `decode/2`'s fifth element would (`keyframe_request`, loss indications).
- They never wait. A delivery after the plugin's stream ended, the plugin was turned off, or the connection closed is dropped and counted (`codec_deliveries_stale` among the internal counters of `get_stats/1`); a malformed one too (`codec_deliveries_rejected`). Neither turns the plugin off.
- Keep a bounded number of frames in flight: deliveries go through the transport's mailbox. Drop what the worker cannot keep up with and count it in `framesDropped` with `report_media_stats/4`, which any process may call.
- Stop the worker in `terminate/1`.

### Capture from a camera and a microphone

The library captures nothing and plays nothing. Build that as its own package that depends on erlang_webrtc, next to your codec plugins:

1. A capture process owns the device and sends raw pictures (I420 planes, width, height, timestamp) or audio (PCM frames of 10 or 20 ms) to the process that owns the peer connection.
2. That process sends them on, one of two ways:
   - raw media to `send_media/3`, and the plugin encodes;
   - capture and encode in one native pipeline, then `send_frame/4`, with no plugin.
3. For playback, a decoding plugin's outputs go to a sink: a window or a speaker for manual tests, a file (IVF, WAV, MP4) for automated ones.

For the device and codec layer you have three choices:

| Choice | What you get | What to watch |
|---|---|---|
| FFmpeg (libavcodec, libavdevice) in a NIF | every codec and every platform's devices in one library | its licence and the codecs it is built with: libx264 is GPL, so prefer OpenH264 or a hardware encoder for H.264 |
| The reference libraries in NIFs | libopus, libvpx, OpenH264, dav1d to decode AV1, libaom or SVT-AV1 to encode it | one binding per library |
| A port program (`ffmpeg`, GStreamer, or a small C program over stdio) | a crash stays out of the VM | a copy and a context switch per frame |

Devices by platform: avfoundation on macOS, v4l2 and ALSA or PulseAudio on Linux, dshow on Windows through libavdevice; or GStreamer's `autovideosrc` and `autoaudiosrc`. macOS asks for camera and microphone access the first time, so the terminal or the app bundle needs the permission; on Linux the user must be in the `video` and `audio` groups. Let the user list devices, pick one by name or index, and set the size, frame rate and sample rate.

In a NIF:

- run codec work on dirty CPU schedulers, never on a normal scheduler;
- keep codec contexts in resource objects freed by a destructor;
- turn every native error into `{error, Reason}`.

In the plugin:

- choose decoder and encoder settings in `init/3` from the negotiated codec: H.264 `profile-level-id` and `packetization-mode`, VP9 `profile-id`, Opus `stereo` and `useinbandfec`;
- keep the RTP timestamp a decoded frame came with; give encoded frames a timestamp at the codec clock (90 kHz video, 48 kHz Opus, 8 kHz G.711);
- force a key frame on `keyframe_request` and follow `{target_bitrate, Bps}` and `{max_bitrate, Bps}` in `control/2`; free native contexts in `terminate/1`;
- keep every queue bounded: drop and count a frame that cannot be decoded, do not retry it.

To test the package:

- encode then decode and compare (PSNR over a threshold for video, sample counts for audio);
- decode every frame of erlang_webrtc's corpus, `test/corpora/frames`, and check sizes and key frames;
- connect two peers on loopback, one encoding a test pattern, the other decoding: `framesEncoded` and `framesDecoded` agree in `get_stats`;
- with a browser, decode its fake camera, and let it decode your test pattern (its `framesDecoded` rises);
- without a device (CI), use a fake one (FFmpeg `lavfi` `testsrc`, GStreamer `videotestsrc`) and skip the device tests with the reason.

## Notes

- `frames` and `codec_plugin` are [transceiver options](../REFERENCE.md#transceiver-options); `frames` and `codec_plugins` on the peer connection are [peer connection options](../REFERENCE.md#peer-connection-options).
- Each received stream (each simulcast layer) has its own decoder state; each sent stream its own encoder state.
- H.264 with B frames is not supported: timestamps must rise with sequence numbers. WebRTC encoders do not send B frames.
- Frame buffer counters (`framesReceived`, `framesDropped`, `jitterBufferDelay`, ...) appear in the statistics when you ask for frames.
- The behaviour is documented in `src/media/webrtc_media_codec.erl`; a small working plugin is `test/support/webrtc_test_codec.erl`.

## Read next

- [Read the statistics](statistics.md)
- [Send media to a browser](send-media.md)
- [Bandwidth and QoS](bandwidth-and-qos.md)
- [Concepts](../CONCEPTS.md): frames, jitter buffer, key frames.
