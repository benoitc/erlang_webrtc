# Read the statistics

`get_stats/2` gives you the statistics of a peer connection in two formats: the W3C format, the one a browser's `getStats()` returns, and the library's internal format, closer to each engine. You need them to watch a call (packets lost, round trip time, bitrate), to compare it with what the browser reports, or to feed a tool written for `getStats()`.

## When to use

- You want the numbers a browser would show: use the W3C format.
- You debug the stack itself (ICE pairs, DTLS, pacer, congestion control, frame buffer): use the internal format.
- You decode or encode media yourself and want the decoder and encoder members filled: report them, as below.

## How

### Get the W3C report

The report maps each stats id to a map of the dictionary's members, with `id`, `type` and `timestamp` (ms since the Unix epoch):

```erlang
Report = webrtc:get_stats(Pc, #{format => w3c}),
[#{packetsSent := Sent} | _] = [S || _ := #{type := <<"outbound-rtp">>} = S <- Report],
```

Types: `codec`, `inbound-rtp`, `outbound-rtp`, `remote-inbound-rtp`, `remote-outbound-rtp`, `media-source`, `media-playout`, `peer-connection`, `data-channel`, `transport`, `candidate-pair`, `local-candidate`, `remote-candidate`, `certificate`. Times are in seconds and rates in bits per second, as the specification defines them.

### Follow a stream

Ids link the objects: an `inbound-rtp` names its `codecId` and `transportId`, an `outbound-rtp` its `remoteId`:

```erlang
[{Rtt, Lost} || _ := #{type := <<"outbound-rtp">>, remoteId := RemoteId} <- Report,
                #{roundTripTime := Rtt, fractionLost := Lost} <- [maps:get(RemoteId, Report, #{})]],
```

Members that need a report from the peer, such as `remoteId` and `roundTripTime`, appear once one has come.

### Get the internal report

`get_stats/1`, or `get_stats/2` with `#{format => internal}`, gives the engines' own maps:

```erlang
#{connection_state := State, transport := T} = webrtc:get_stats(Pc),
#{media := #{congestion_control := #{target_bitrate := Bps}, receivers := Receivers}} = T,
```

`transport` holds `ice`, `dtls`, `media`, `sctp`, `channels` and the socket counters; `transports` the other transports when the sections are not bundled. In `media`, each entry of `receivers` has `frames` (the frame buffer) when you ask for frames.

### Know what fills the decoder and encoder members

The library does not decode or encode, so some members come from you:

| Members | Filled by |
|---|---|
| packets, bytes, loss, jitter, NACK, PLI, FIR, round trip | the library |
| `framesReceived`, `framesDropped`, `frameWidth`, `frameHeight`, `framesPerSecond`, `jitterBufferDelay`, ... of `inbound-rtp` | the frame buffer, when the transceiver has `frames` |
| `framesSent`, `frameWidth`, `frameHeight`, `framesPerSecond` of `outbound-rtp` | the library, from the packets sent |
| `framesDecoded`, `totalDecodeTime`, `concealedSamples`, `decoderImplementation`, ... | a codec plugin, or `report_media_stats/4` |
| `framesEncoded`, `totalEncodeTime`, `qualityLimitationReason`, `encoderImplementation`, ... | a codec plugin, or `report_media_stats/4` |
| `media-source` and `media-playout` | `report_media_stats/4` |

A codec plugin returns them from `decode/2` and `encode/2` (see [frames and codec plugins](frames-and-codec-plugins.md)).

### Report them yourself

`report_media_stats/4` takes the mid, the object (`inbound`, `outbound`, `source` or `playout`) and W3C member names:

```erlang
webrtc:report_media_stats(Pc, Mid, inbound, #{framesDecoded => 1, totalDecodeTime => 0.004}),
webrtc:report_media_stats(Pc, Mid, outbound, #{framesEncoded => 1, qualityLimitationReason => <<"bandwidth">>}),
webrtc:report_media_stats(Pc, Mid, source, #{width => 1280, height => 720, frames => 1}),
webrtc:report_media_stats(Pc, Mid, playout, #{totalSamplesCount => 960}),
```

Counters add up across reports; other members replace the previous value. An unknown member or a value of the wrong type is dropped. Any process can call it, and it does not wait.

## Notes

- [`../compliance/stats.md`](../compliance/stats.md) lists every W3C member, whether it is reported and where it comes from.
- An `inbound-rtp` stream that ends (BYE, or 60 s without packets) is still reported with its last values, until its SSRC is replaced or its transceiver stops; at most 16 ended streams are kept per transport.
- `candidate-pair` `availableOutgoingBitrate` is the congestion control target, the same value as the `{bandwidth_estimate, Bps}` event.
- `get_stats` calls the peer connection and its transports; do not call it for every packet.

## Read next

- [Receive frames and write a codec plugin](frames-and-codec-plugins.md)
- [Bandwidth and QoS](bandwidth-and-qos.md)
- [W3C statistics compliance](../compliance/stats.md)
