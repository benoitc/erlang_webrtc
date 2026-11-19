# Forward media between peers

An SFU (selective forwarding unit) receives each participant's media and sends it on to the others without decoding it. With this library you hold one peer connection per participant and move RTP packets from one to another; the library gives the forwarded stream its own SSRC and sequence numbers and handles retransmissions on each leg. You need this guide to build a conference server, a broadcast relay or a recorder that also forwards. The example [`examples/browser_relay`](../../examples/browser_relay) relays one browser page's video to a second page.

## When to use

- You relay what one peer sends to one or more others, without decoding.
- You pick one simulcast layer per receiver.
- You need to tell a sender how much it may send (TMMBR, between non-browser peers).
- To send media you produce yourself, see [send media](send-media.md).

## How

### Run the example

```sh
rebar3 shell
```

```erlang
1> cd("examples/browser_relay").
2> c(browser_relay).
3> browser_relay:start(8080).
```

Open `http://localhost:8080/?role=send` and `http://localhost:8080/?role=receive`, in either order. The second page shows the first page's camera. `browser_relay:stop()` stops the server.

### Receive on one peer connection, send on another

The publisher's connection `In` has a transceiver that receives; the viewer's connection `Out` has one that sends. When the viewer is a browser that offers to receive only (`recvonly`), the transceiver its offer creates is `recvonly` on your side too, as JSEP says. Make it send between `set_remote_description/3` and `create_answer/2`:

```erlang
ok = webrtc:set_remote_description(Out, offer, Offer),
[Id] = [Id || #{id := Id, kind := video} <- webrtc:transceivers(Out)],
ok = webrtc:set_direction(Out, Id, sendonly),
{ok, Answer} = webrtc:create_answer(Out, #{}),
```

Each `{rtp, Mid, Packet}` from `In` goes to `send_rtp_packet/3` on `Out`:

```erlang
-include_lib("webrtc/include/webrtc_rtp.hrl").

relay(In, InMid, Out, OutMid) ->
    receive
        {webrtc, In, {rtp, InMid, #rtp{} = Pkt}} ->
            _ = webrtc:send_rtp_packet(Out, OutMid, Pkt),
            relay(In, InMid, Out, OutMid);
        {webrtc, Out, {keyframe_request, OutMid}} ->
            ok = webrtc:request_keyframe(In, InMid),
            relay(In, InMid, Out, OutMid);
        {webrtc, _, {connection_state, closed}} ->
            ok;
        {webrtc, _, _} ->
            relay(In, InMid, Out, OutMid)
    end.
```

Events of both connections reach the process that owns them. To run one process per connection, hand it over with `controlling_process/2` and pass packets between processes.

`send_rtp_packet/3` replaces the SSRC and sequence number with those of `OutMid`. The payload type, timestamp, marker and payload stay as they came.

### Match the payload types

`send_rtp_packet/3` rewrites the SSRC and sequence number, not the payload type. Forwarding works as it is when both peers use the same payload type for the codec. When you relay between different browsers, check the payload types each answer negotiated, and when the viewer's differs, set it:

```erlang
_ = webrtc:send_rtp_packet(Out, OutMid, Pkt#rtp{pt = OutPt}),
```

### Ask for a key frame when a viewer joins

A new viewer cannot decode until a key frame arrives. Ask the publisher for one (PLI, or FIR when PLI is not negotiated):

```erlang
ok = webrtc:request_keyframe(In, InMid),
```

Do the same when a viewer sends `{keyframe_request, OutMid}`, as in the loop above.

### Forward simulcast layers

A browser publishing simulcast sends several layers on one transceiver, each with its rid. The answer accepts the layers it offers, and each packet arrives with its rid:

```erlang
{webrtc, In, {rtp, InMid, Rid, Pkt}} when Rid =:= Wanted ->
    _ = webrtc:send_rtp_packet(Out, OutMid, Pkt),
```

To switch a viewer to another layer, ask for a key frame on that layer and start forwarding it from that key frame:

```erlang
ok = webrtc:request_keyframe(In, InMid, #{rid => <<"h">>}),
```

To receive layers from a peer that offers to send them, list them on your transceiver; `#{rid => Rid, paused => true}` starts one paused (`request_resume/3` resumes it):

```erlang
{ok, _} = webrtc:add_transceiver(In, video, #{direction => recvonly, recv_rids => [<<"h">>, <<"m">>, <<"l">>]}),
```

To send layers yourself, give `send_encodings` and pass the layer's `rid` to `send_rtp_packet/4`:

```erlang
{ok, _} = webrtc:add_transceiver(Out, video, #{send_encodings => [#{rid => <<"h">>}, #{rid => <<"l">>}]}),
_ = webrtc:send_rtp_packet(Out, OutMid, Pkt, #{rid => <<"l">>}),
```

The negotiated layers are in `send_encodings` of `transceivers/1`. A layer the answer removed returns `{error, not_sending}`.

### Let the library repair loss

You do nothing for retransmissions. On each leg:

- the receiving side sends NACKs for missing packets, with backoff, and asks for a key frame when too many are missing;
- the sending side keeps what it sent, forwarded packets included, and resends them, on the RTX stream when RTX is negotiated;
- retransmissions are delivered to you already decapsulated, on their layer.

### Limit what a sender sends (TMMBR)

Between peers that both negotiated `ccm tmmbr` (browsers do not), you can ask the sender of a transceiver to stay under a rate, for example the bandwidth of a SIP leg. The rate counts RTP headers and payload; `infinity` lifts the limit:

```erlang
ok = webrtc:request_max_bitrate(In, InMid, 300000),
```

It returns `{error, not_negotiated}` when TMMBR is not negotiated. The request is repeated until the sender acknowledges it.

When a peer limits what you send, you get the payload rate it allows. The connection holds the stream to it, queuing and at worst dropping packets, so keep your encoder under it:

```erlang
{webrtc, Pc, {max_bitrate, Mid, Bps}} -> set_encoder_rate(Bps),
```

With simulcast the event is `{max_bitrate, Mid, Rid, Bps}`.

## Notes

- Forwarded packets go through the receiving leg's pacer and congestion control, like your own. If the viewer's path is slower than the publisher's, pick a lower layer for it: watch `{bandwidth_estimate, Bps}` on `Out` (see [bandwidth and QoS](bandwidth-and-qos.md)).
- Timestamps and codec payload headers (VP8 picture IDs, for example) are not rewritten. When you switch layers or publishers on one outgoing stream, rewrite what the receiving decoder needs to stay continuous.
- `{rtp, Mid, Packet}` only comes on transceivers without `frames`. With `frames => true` you get whole frames instead; forward those with `send_frame/4`.
- `request_pause/2,3` and `request_resume/2,3` ask a sender to pause and resume a stream (RFC 7728), when both sides negotiated `ccm pause`; the answers come as `{remote_paused, Mid}`, `{remote_resumed, Mid}` or `{pause_refused, Mid}`.
- The events are in the [reference](../REFERENCE.md#events); the transceiver options (`recv_rids`, `send_encodings`) in [Transceiver options](../REFERENCE.md#transceiver-options).

## Read next

- [Send media to a browser](send-media.md)
- [Bandwidth and QoS](bandwidth-and-qos.md)
- [Read the statistics](statistics.md)
- [Architecture](../ARCHITECTURE.md): how a packet travels through the stack.
