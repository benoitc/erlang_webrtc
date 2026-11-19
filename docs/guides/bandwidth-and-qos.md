# Bandwidth and QoS

Each peer connection runs congestion control on the media it sends: it estimates the bitrate the path can take, paces packets to it, and stops a stream that keeps overloading the path. It also marks packets with DSCP so that networks that honour it can favour audio over video and video over bulk data, and adds FEC to video so a lost packet can be rebuilt without a round trip. The library cannot change your encoder's rate, so it tells you the target and you adapt. You need this guide to keep media within the path, to cap what a connection uses, or to set priorities between streams.

## When to use

- You encode media yourself or through a plugin and must follow the available bandwidth.
- You want to cap or floor the bitrate of a connection.
- A stream stopped with `{circuit_breaker, Mid, Reason}` and you want it back.
- You set priorities between audio, video and data channels, or tune video FEC.

## How

### Follow the bandwidth estimate

The owner gets the target bitrate for all media sent on the connection whenever it changes:

```erlang
{webrtc, Pc, {bandwidth_estimate, Bps}} ->
    set_encoder_rate(Bps - audio_rate()),
```

Split it between your streams; keep audio first. The estimate rests on the peer's feedback (transport-wide congestion control, RFC 8888 feedback or REMB). Until feedback comes, it is a guess and packets are not held back.

### Set the limits

When you create the connection, give the starting point and the bounds in bits per second (defaults 300000, 30000 and 50000000):

```erlang
{ok, Pc} = webrtc:new_peer_connection(#{congestion_control => #{
    start_bitrate => 1000000, min_bitrate => 100000, max_bitrate => 2500000}}),
```

Change them later, once the first description is set:

```erlang
ok = webrtc:set_congestion_control(Pc, #{max_bitrate => 800000}),
```

`set_congestion_control/2` takes `min_bitrate`, `max_bitrate`, `pacing` (default `true`; `false` sends every packet at once) and `pacing_factor` (default 2.5, the pacing rate over the target). `congestion_control` on `new_peer_connection/1` also takes `probing`, `rtcp_timeout` and `circuit_breaker_hold`; see [Congestion control options](../REFERENCE.md#congestion-control-options).

### Handle a circuit breaker

The RTP circuit breakers of RFC 8083 watch each transceiver:

```erlang
{webrtc, Pc, {circuit_breaker, Mid, Reason}} ->
    %% Reason: rtcp_timeout, media_timeout or congestion
```

- `rtcp_timeout` and `media_timeout` halt the transceiver's streams at once.
- `congestion` first cuts the target to a tenth of the rate being sent; if it triggers again soon after, the streams are halted. The cut is lifted after the hold time without a new trigger.

While halted, `send_rtp/4` returns `{error, {circuit_breaker, Reason}}`; RTCP keeps flowing. Restart the streams when a user asks or you see the path recover:

```erlang
case webrtc:resume_stream(Pc, Mid) of
    ok -> ok;
    {error, {retry_after, Ms}} -> erlang:send_after(Ms, self(), {resume, Mid})
end,
```

`resume_stream/2` is refused during the hold time, `circuit_breaker_hold`, 15 s by default.

### Follow a peer's limit (TMMBR)

A peer that negotiated `ccm tmmbr` may cap a stream you send. You get the payload rate it allows, and the connection holds the stream to it:

```erlang
{webrtc, Pc, {max_bitrate, Mid, Bps}} -> set_encoder_rate(Mid, Bps),
```

`Bps` is `infinity` when the limit is lifted. To cap a peer the same way, use `request_max_bitrate/3` (see [forward media](forward-media.md#limit-what-a-sender-sends-tmmbr)). Browsers do not negotiate TMMBR.

### Mark packets with DSCP

Set `priority` on a transceiver, on one simulcast layer, or on a data channel: `very_low`, `low` (default), `medium` or `high`:

```erlang
{ok, _} = webrtc:add_transceiver(Pc, audio, #{priority => high}),
{ok, _} = webrtc:add_transceiver(Pc, video, #{priority => medium,
    send_encodings => [#{rid => <<"h">>, priority => high}, #{rid => <<"l">>}]}),
ok = webrtc:create_data_channel(Pc, <<"bulk">>, #{priority => very_low}),
```

The DSCP follows RFC 8837:

| Flow | `very_low` | `low` | `medium` | `high` |
|---|---|---|---|---|
| audio | LE (1) | none | EF (46) | EF (46) |
| interactive video | LE (1) | none | AF42, AF43 | AF41, AF42 |
| non-interactive video | LE (1) | none | AF32, AF33 | AF31, AF32 |
| data | LE (1) | none | AF11 | AF21 |

Where there are two values, key frame packets get the first, with the lower drop precedence. For video nobody answers live (a broadcast, a recording), set `interactive => false` on the transceiver to use AF3x. Data channel priority also shares the association between channels in proportion to it.

If the path drops packets with a mark, the flows that used it go unmarked and you get:

```erlang
{webrtc, Pc, {dscp_disabled, Dscp}} -> ok,
```

### Tune video FEC

Video FEC is negotiated by default: FlexFEC (RFC 8627) on its own stream, or ULPFEC in RED (RFC 8854) with peers without FlexFEC, such as browsers. With `video_fec => auto` (the default) the sender adds FEC packets after each frame as the peer reports loss: twice the fraction lost, at most one for two media packets, none without loss. Fix the rate or turn it off:

```erlang
{ok, Pc} = webrtc:new_peer_connection(#{video_fec => 0.5}),   %% one FEC packet for two media packets
{ok, Pc} = webrtc:new_peer_connection(#{video_fec => 0.0}),   %% none
```

## Notes

- Retransmissions are limited to the target bitrate over one second, so NACKs after a sudden drop do not keep the path overloaded; the ones over the limit are counted as `rtx_limited`.
- The internal statistics show the controller: `get_stats(Pc)`, then `transport`, `media`, `congestion_control` (`target_bitrate`, `pacer`, `circuit_breakers`, `halted`, `rate_cut`, `probing`). The W3C report gives `availableOutgoingBitrate` on the `candidate-pair`. See [read the statistics](statistics.md).
- With ICE over TCP, one TCP connection carries every flow, so it is marked with the highest DSCP among them.
- The events are listed in [Events](../REFERENCE.md#events); `priority` and `interactive` in [Transceiver options](../REFERENCE.md#transceiver-options).

## Read next

- [Send media to a browser](send-media.md)
- [Forward media between peers](forward-media.md)
- [Read the statistics](statistics.md)
- [RTP compliance](../compliance/rtp.md): congestion control, pacing, circuit breakers, FEC.
