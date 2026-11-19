# Send media to a browser

A peer connection carries audio and video on transceivers, one per m= section of the SDP. You hand the library encoded media, RTP payloads or whole frames, and it packetizes, encrypts, paces and sends them, answers retransmission requests and adds FEC. It does not capture or encode anything: the media comes from your code, a file or a codec plugin. You need this guide to play audio or video from Erlang in a browser, or to make the offer yourself.

## When to use

- You have encoded audio (Opus, G.711) or video (VP8, VP9, H.264, AV1) and want a browser to play it.
- You answer a browser's offer and want to send back, not only receive.
- To relay what another peer sends, see [forward media](forward-media.md) instead.

## How

### Add the transceivers before you answer

A transceiver you add before `set_remote_description/3` is matched to the next offered m= section of the same kind, so the answer can send on it:

```erlang
{ok, Pc} = webrtc:new_peer_connection(#{ice_servers => [#{urls => [<<"stun:stun.l.google.com:19302">>]}]}),
{ok, _AudioId} = webrtc:add_transceiver(Pc, audio, #{direction => sendonly}),
{ok, _VideoId} = webrtc:add_transceiver(Pc, video, #{direction => sendonly}),
ok = webrtc:set_remote_description(Pc, offer, Offer),
{ok, Answer} = webrtc:create_answer(Pc, #{}),
ok = webrtc:set_local_description(Pc, answer, Answer),
```

The page asks to receive and plays what arrives:

```js
pc.addTransceiver('audio', { direction: 'recvonly' });
pc.addTransceiver('video', { direction: 'recvonly' });
pc.ontrack = (e) => { video.srcObject = new MediaStream([e.track]); };
```

If you did not add one, the offer creates a `recvonly` transceiver. Change it with `set_direction/3` before `create_answer/2`:

```erlang
[Id] = [Id || #{id := Id, kind := video} <- webrtc:transceivers(Pc)],
ok = webrtc:set_direction(Pc, Id, sendrecv),
```

### Find the mid

You send on a transceiver by its mid, a binary the offer gave it. `add_transceiver/3` returns the id; `transceivers/1` maps one to the other:

```erlang
Mids = #{Kind => Mid || #{kind := Kind, mid := Mid} <- webrtc:transceivers(Pc)},
#{audio := AudioMid, video := VideoMid} = Mids,
```

### Wait for the connection

Sending before the connection is up returns an error. Wait for:

```erlang
receive {webrtc, Pc, {connection_state, connected}} -> ok end,
```

### Send audio as RTP payloads

`send_rtp/4` sends one payload as one RTP packet. You set the timestamp, in the codec's clock: 48 kHz for Opus, so 960 per 20 ms frame; 8 kHz for G.711, so 160 per 20 ms. Call it at the media's pace:

```erlang
audio(Pc, Mid, [Opus | Rest], Ts) ->
    receive after 20 -> ok end,
    _ = webrtc:send_rtp(Pc, Mid, Opus, #{timestamp => Ts}),
    audio(Pc, Mid, Rest, (Ts + 960) band 16#FFFFFFFF);
audio(_Pc, _Mid, [], _Ts) ->
    ok.
```

Options of `send_rtp/4`:

| Option | Meaning |
|---|---|
| `timestamp` | RTP timestamp, default 0: always set it |
| `marker` | the RTP marker bit, default `false` |
| `codec` or `pt` | the codec by name (`<<"PCMU">>`) or payload type; default the first negotiated |
| `audio_level` | `{Voice, Level}`, Level in -dBov 0..127 (RFC 6464), sent when the extension is negotiated |
| `red` | `true` sends the payload in RED with the previous one (RFC 2198) when the peer negotiated `audio/red` |
| `rid` | the simulcast layer to send on |

### Send video as frames

`send_frame/4` takes an encoded frame and splits it into RTP payloads for its codec, the marker bit on the last: a VP8 or VP9 frame, an H.264 access unit in Annex B, an AV1 temporal unit. Video runs on a 90 kHz clock, so 3000 per frame at 30 frames a second:

```erlang
ok = webrtc:send_frame(Pc, VideoMid, Vp8Frame, #{timestamp => Ts, keyframe => true}),
```

Set `keyframe => true` on key frames: VP9 and AV1 signal it in the payload, and its packets get the lower drop precedence. Pass `codec => <<"H264">>` when several video codecs are negotiated; the default is the first. To packetize yourself, use `send_rtp/4` with `marker => true` on the last packet of each frame.

### Answer keyframe requests

When the browser loses a frame or a new decoder starts, it asks for a key frame:

```erlang
{webrtc, Pc, {keyframe_request, Mid}} ->
    %% make the next frame you send on Mid a key frame
```

With simulcast it is `{keyframe_request, Mid, Rid}`, for one layer.

### Change directions later

`set_direction/3` takes `sendrecv`, `sendonly`, `recvonly` or `inactive`. You get `negotiation_needed`; then offer again:

```erlang
ok = webrtc:set_direction(Pc, Id, inactive),
{ok, Offer} = webrtc:create_offer(Pc, #{}),
ok = webrtc:set_local_description(Pc, offer, Offer),
%% send Offer, receive Answer
ok = webrtc:set_remote_description(Pc, answer, Answer),
```

`transceivers/1` gives `direction` (what you asked) and `current_direction` (what was negotiated). `stop_transceiver/2` rejects the m= section in the next offer. On the receiving side, `{track, Mid, audio | video}` tells you the peer sends on a transceiver.

### Make the offer yourself

```erlang
{ok, Pc} = webrtc:new_peer_connection(),
{ok, _AudioId} = webrtc:add_transceiver(Pc, audio, #{}),
ok = webrtc:create_data_channel(Pc, <<"chat">>, #{}),
{ok, Offer} = webrtc:create_offer(Pc, #{}),
ok = webrtc:set_local_description(Pc, offer, Offer),
%% send Offer, receive Answer
ok = webrtc:set_remote_description(Pc, answer, Answer).
```

The mids are set when the offer is created, in order (`<<"0">>`, `<<"1">>`, ...); `transceivers/1` gives them.

## Notes

- `send_rtp/4` and `send_frame/4` return `{error, Reason}` without sending: `not_sending` (the transceiver does not send, or the layer was removed), `unknown_codec`, `paused` (the peer paused the stream, see `{stream_paused, Mid}`), `{circuit_breaker, Reason}` (see [bandwidth and QoS](bandwidth-and-qos.md)), `not_ready`, `closed`. `send_frame/4` also returns `empty_frame`.
- `send_rtp/4` sends the payload as it is. Keep it under about 1100 bytes so the packet fits a 1200 byte path; `send_frame/4` does that for you.
- Adapt your encoder to `{bandwidth_estimate, Bps}` and `{max_bitrate, Mid, Bps}`: see [bandwidth and QoS](bandwidth-and-qos.md).
- To encode raw pictures and samples with a codec plugin, use `send_media/3`: see [frames and codec plugins](frames-and-codec-plugins.md).
- Every option of `add_transceiver/3` is in the [reference](../REFERENCE.md#transceiver-options); every event in [Events](../REFERENCE.md#events).
- `getUserMedia` needs HTTPS, except on `localhost`; receiving media in a page does not.

## Read next

- [Forward media between peers](forward-media.md)
- [Receive frames and write a codec plugin](frames-and-codec-plugins.md)
- [Bandwidth and QoS](bandwidth-and-qos.md)
- [Read the statistics](statistics.md)
