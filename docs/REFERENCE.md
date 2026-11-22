# Configuration and events reference

This page lists every option you can pass to the `webrtc` module and every message a peer connection sends to its owner. Use it when you configure a peer connection, add a transceiver or a data channel, or write the `receive` loop that handles `{webrtc, Pc, Event}` messages. The guides show how the pieces fit together; this page is where you look up a key, its type and its default.

The public API is the `webrtc` module and the `webrtc_media_codec` behaviour. Every other module is internal and may change between releases. When a row below names an internal module, it is only to say where the behaviour lives.

A test (`test/webrtc_docs_tests.erl`) checks that the option tables on this page match the keys the code reads, so a key the code reads but this page misses, or a key listed here that the code does not read, fails `rebar3 eunit`.

## Peer connection options

You pass these in the map of `webrtc:new_peer_connection/1`. Every key is optional; `webrtc:new_peer_connection/0` is the same as an empty map. Keys the code does not read are ignored, so check the spelling against this table.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `owner` | `pid()` | the caller | Process that receives every event; the peer connection closes when it exits. Change it later with `webrtc:controlling_process/2`. |
| `stun_servers` | `[{IP, Port}]` | `[]` | STUN servers used to gather server reflexive candidates. |
| `turn_servers` | `[map()]` | `[]` | TURN servers, see [TURN server entries](#turn-server-entries). |
| `ice_servers` | `[map()]` | none | The W3C RTCIceServer list, see [ICE server entries](#ice-server-entries). Resolved when the peer connection starts and added to `stun_servers` and `turn_servers`. A malformed list returns `{error, {badarg, ice_servers}}`. |
| `ice_server_timeout` | ms | `2000` | Time allowed to resolve the names of `ice_servers`. |
| `ice_resolver` | `fun((srv \| inet \| inet6, Name) -> {ok, list()} \| {error, term()})` | DNS lookups | Replaces the DNS lookups of `ice_servers` names: SRV answers as `[{Priority, Weight, Port, Target}]`, others as `[IP]`. Meant for tests. |
| `ice_lite` | `boolean()` | `false` | Run as an ICE-Lite agent, for a server with a public address. A lite agent is always the controlled side. |
| `ice_pacing` | integer, ms, at least 5 | `50` | Interval between connectivity checks (Ta). A value other than 50 is announced with `a=ice-pacing`; both sides use the higher one. Anything below 5 returns `{error, {badarg, ice_pacing}}`. |
| `ice_auto_restart` | `disconnected \| failed \| false` | `false` | Restart ICE by itself when the selected path stops working: after `ice_restart_delay` of trouble (`disconnected`), only once consent is lost (`failed`), or never (`false`, as browsers do: the application decides, with `restart_ice/1`). A restart needs a new offer and answer: send them on `negotiation_needed`, or use the `signaling` option. Up to 3 restarts per incident; meanwhile the connection is reported `disconnected`, not `failed`. |
| `ice_restart_delay` | ms | `2000` | Delay before an automatic restart. The controlled side waits three times as long, so the controlling side normally restarts first. |
| `signaling` | `fun((offer \| answer, Sdp) -> any())` | none | Sends a description to the peer. When set, ICE restarts run without you: the connection creates and applies the restart offer, answers restart offers you pass to `set_remote_description/3`, and hands each description to the function. It runs in a helper process. |
| `addresses` | `[{IP, Port}]` | every usable interface that is up and not loopback, port 0 | Local addresses to bind. |
| `loopback` | `boolean()` | `false` | With `true` and no `addresses`, bind only `127.0.0.1`. |
| `ice_tcp` | `boolean()` | `false` | Also gather TCP host candidates (RFC 6544), a passive and an active one per UDP host address, below UDP in priority. |
| `mdns_host_candidates` | `boolean()` | `false` | Signal host candidates as a random `<uuid>.local` name answered by multicast DNS instead of the address. Remote `.local` names are always resolved. |
| `mdns_expose_public` | `boolean()` | `true` | With `mdns_host_candidates`, a host address that a STUN server maps to itself is public, and later gatherings signal it as it is. |
| `mdns` | `map()` | `#{}` | Options of the mDNS resolver and responder, see [mDNS options](#mdns-options). |
| `consent` | `boolean()` | `true` | Run ICE consent freshness checks (RFC 7675) on the selected pair. Turning them off is for tests. |
| `nomination` | `best \| first` | `best` | Which valid pair the controlling agent nominates: the best one once checks settle, or the first that works. |
| `outbound_filter` | `{Fun, State}` | none | Test hook that sees every outgoing datagram and can delay, drop or mark it. `Fun(Dest, Bin, State)` or `Fun(Dest, Bin, Tos, State)` returns `{[{DelayMs, Bin} \| {DelayMs, Bin, Ecn}], NewState}`. Not for production. |
| `certificate` | result of `webrtc_dtls_cert:generate/1` | a fresh ECDSA P-256 certificate, valid 30 days | DTLS certificate; its SHA-256 fingerprint goes in the SDP. |
| `dtls` | `map()` | `#{}` | DTLS options, see [DTLS options](#dtls-options). |
| `sctp` | `map()` | `#{}` | SCTP timers of the data channels, see [SCTP options](#sctp-options). |
| `srtp_profiles` | `[integer()]` | `[16#0007, 16#0008, 16#0001, 16#0002]` | SRTP protection profiles offered in DTLS, most preferred first: AES-GCM 128 and 256, then AES-CM with an 80 and a 32 bit tag. |
| `cryptex` | `boolean()` | `true` | Offer and accept encrypted CSRC lists and header extensions (RFC 9335). Media is sent that way only when every section negotiated it. |
| `encrypt_header_extensions` | `accept \| offer \| false` | `accept` | RFC 6904 encrypted header extensions: `accept` answers an encrypted offer encrypted but offers only the clear form, `offer` offers both forms, `false` neither offers nor accepts them. |
| `bundle` | `boolean()` | `true` | Offer every m= section in one BUNDLE group. With `false` each section gets its own ICE and DTLS transport, and you relay candidates with `webrtc:add_ice_candidate/3` and the mid of their event. Answers follow the offer whatever this says. |
| `rtcp_mux_policy` | `negotiate \| require` | `negotiate` | `require` adds `a=rtcp-mux-only` to offers. RTP and RTCP are always multiplexed. |
| `codecs` | `#{audio => [map()], video => [map()]}` | `webrtc:default_codecs/1` for each kind | Codecs to negotiate, in order of preference. A codec on payload type 64 to 95 returns `{error, {badarg, {payload_type, Pt}}}`. See [Codecs](#codecs) and [send media](guides/send-media.md). |
| `extensions` | `#{audio => [map()], video => [map()]}` | computed by `webrtc_jsep_caps:default_extensions/1` for each kind | RTP header extensions to negotiate, as `#{id, uri}` maps; `encrypt => true` marks the encrypted form. |
| `max_message_size` | positive integer, bytes | `262144` | Largest data channel message you accept, announced in the SDP. A peer message over it closes the channel. Zero or a non-integer returns `{error, {badarg, max_message_size}}`. See [data channels](guides/data-channels.md). |
| `congestion_control` | `map()` | `#{}` | Initial options of the bandwidth estimator, pacer and circuit breakers, see [Congestion control options](#congestion-control-options). A non-map returns `{error, {badarg, congestion_control}}`. |
| `rtcp_report_interval` | ms | `1000` | Shortest interval between regular RTCP reports (T_rr_interval of RFC 4585). `0` keeps only the RFC 3550 interval. Feedback messages are not bound by it. |
| `video_fec` | `auto` or a number | `auto` | FEC packets sent per video packet, FlexFEC or ULPFEC in RED, whichever the peer negotiates. `auto` sends twice the fraction lost the peer reports, at most 0.5, none without loss; `0.0` sends none. See [bandwidth and QoS](guides/bandwidth-and-qos.md). |
| `frames` | `false \| true \| #{min_delay => Ms, max_delay => Ms}` | `false` | The `frames` option of every transceiver added without one, including those a remote offer creates. See [Transceiver options](#transceiver-options). |
| `codec_plugins` | `#{audio => {Module, Opts}, video => {Module, Opts}}` | `#{}` | Codec plugin of the transceivers of each kind added without `codec_plugin`. Only used when `frames` is not `false`. A bad entry returns `{error, {badarg, {codec_plugins, Entry}}}`. See [frames and codec plugins](guides/frames-and-codec-plugins.md). |

### TURN server entries

Each entry of `turn_servers` is a map:

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `address` | `{IP, Port}` | required | Server address. |
| `username`, `password` | `binary()` | required | Long-term credentials. |
| `transport` | `udp \| tcp \| tls` | `udp` | How the server is reached. The relay itself is always UDP. |
| `hostname` | string or binary | the IP address | Name checked against the server certificate with `tls`. |
| `tls_options` | `[ssl:tls_client_option()]` | verify against the system CA store and `hostname` | Replace the TLS defaults, for example `[{cacerts, [Der]}]`. |

### ICE server entries

Each entry of `ice_servers` is a W3C RTCIceServer map:

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `urls` | URI or list of URIs (binary) | required | `stun:`, `turn:` and `turns:` URIs, for example `<<"turn:turn.example.com?transport=tcp">>`. A name without a port is looked up with SRV first. |
| `username`, `credential` | `binary()` | required for TURN | TURN credentials. |
| `tls_options` | `ssl` client options | system CA store | For `turns:` URIs. |

At most eight STUN and TURN servers are used in all, counting `stun_servers` and `turn_servers`. A URI that cannot be used is reported as `{ice_server_error, Url, Reason}`.

### DTLS options

The `dtls` map:

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `connection_id` | `true` or `binary()` | off | Offer and accept a DTLS connection ID (RFC 9147 for 1.3, RFC 9146 for 1.2). With DTLS 1.3 records move to a spare connection ID after an ICE restart or a new selected pair. |
| `resumption` | `boolean()` | `false` | Issue DTLS 1.3 tickets and resume the next association between the same certificates with them. |
| `ticket_lifetime` | seconds | `7200` | Lifetime of the tickets issued. |

### SCTP options

The `sctp` map changes the timers of the SCTP association that carries the data channels. The defaults are those of browsers: a timer that expires doubles up to 3 s, not up to 60 s, so a path that comes back after an outage is used again within seconds; and the association never gives up on its own, it ends when ICE consent or DTLS ends.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `max_backoff` | ms or `infinity` | `3000` | Ceiling of the doubling after a retransmission timer expires (data, INIT, COOKIE ECHO, SHUTDOWN). Never below the RTO measured on the path. `infinity` doubles up to `rto_max`, as RFC 9260 suggests. |
| `max_retransmissions` | `non_neg_integer()` or `infinity` | `infinity` | Association.Max.Retrans: consecutive errors after which the peer is unreachable and the association closes (`{sctp_closed, max_retransmissions}`). RFC 9260 suggests 10. |
| `max_init_retransmissions` | `non_neg_integer()` | `8` | Max.Init.Retransmits: retransmissions of INIT and COOKIE ECHO before the setup fails, about 25 s with the default ceiling. |
| `rto_initial`, `rto_min`, `rto_max` | ms | `1000`, `1000`, `60000` | RTO.Initial, RTO.Min and RTO.Max of RFC 9260. |

A bad value returns `{error, {badarg, sctp}}`.

### Congestion control options

The `congestion_control` map. `webrtc:set_congestion_control/2` changes `pacing`, `pacing_factor`, `min_bitrate` and `max_bitrate` later. See [bandwidth and QoS](guides/bandwidth-and-qos.md).

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `start_bitrate` | bits/s | `300000` | First target, kept between `min_bitrate` and `max_bitrate`. |
| `min_bitrate` | bits/s | `30000` | Lowest target. |
| `max_bitrate` | bits/s | `50000000` | Highest target. |
| `pacing` | `boolean()` | `true` | Pace packets at `pacing_factor` times the target. `false` sends every packet at once. |
| `pacing_factor` | number | `2.5` | Pacing rate over the target. |
| `probing` | `boolean()` | `true` | Send probe clusters of padding to find capacity faster. |
| `burst_ms` | ms | `10` | Burst the pacer allows. |
| `max_queue_packets` | integer | `1000` | Pacer queue limit in packets. |
| `max_queue_ms` | ms | `1000` | Pacer queue limit in time. |
| `twcc_interval` | ms | `100` | Interval of transport-wide feedback you send. |
| `rtcp_timeout` | ms | `15000` | No RTCP from the peer for this long trips the RTCP timeout circuit breaker. |
| `circuit_breaker_hold` | ms | `15000` | Time before `webrtc:resume_stream/2` is accepted after a circuit breaker tripped. |
| `startup_gain`, `change_threshold`, `feedback_timeout` | number, number, ms | `1.5`, `0.05`, `1500` | Tuning of the estimator (`webrtc_gcc`). |

### mDNS options

The `mdns` map is mostly for tests: `group` and `listen` (`{IP, Port}` of the IPv4 group and socket), `group6` and `listen6` (the same for IPv6), `schedule`, `max_queries`, `max_cache`, `max_pending` (default 32), `fqdn_timeout` (ms, default 3000) and `check_source` (default `true`).

## Transceiver options

You pass these in the third argument of `webrtc:add_transceiver(Pc, audio | video, Opts)`. It returns `{ok, Id}`; use `Id` with `set_direction/3` and `stop_transceiver/2`, and the mid from `webrtc:transceivers/1` with the media functions.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `direction` | `sendrecv \| sendonly \| recvonly \| inactive` | `sendrecv` | Direction offered. |
| `stream_id` | `binary()` | random, 12 characters | MediaStream id in `a=msid`. |
| `track_id` | `binary()` | random, 12 characters | Track id in `a=msid`. |
| `send_encodings` | `[#{rid => Rid, restrictions => [{Name, Value}], priority => P}]` | `[]` | Simulcast layers to send (RFC 8853), most preferred first. A missing rid is generated; one encoding without a rid means no simulcast. Duplicate or malformed rids return `{error, invalid_encodings}`. See [send media](guides/send-media.md). |
| `recv_rids` | `[Rid \| #{rid => Rid, paused => true}]` | `[]` | Simulcast layers to ask the peer for; a `paused` layer starts paused. Bad rids return `{error, invalid_recv_rids}`. |
| `frames` | `false \| true \| #{min_delay => Ms, max_delay => Ms}` | the peer connection's `frames` | Deliver `{frame, Mid, Frame}` (assembled frames released at their playout time) instead of `{rtp, Mid, Packet}`. `min_delay` defaults to 0 and `max_delay` to 10000. See [frames and codec plugins](guides/frames-and-codec-plugins.md). |
| `codec_plugin` | `{Module, Opts}` | the peer connection's `codec_plugins` entry for the kind | A `webrtc_media_codec` module that decodes received frames and encodes what you pass to `send_media/3,4`. Needs `frames`, otherwise `{error, {badarg, {codec_plugin, needs_frames}}}`. |
| `priority` | `very_low \| low \| medium \| high` | `low` | DSCP marking of RFC 8837: EF for audio, AF4x for video, LE at `very_low`, none at `low`. Also accepted per encoding in `send_encodings`. See [bandwidth and QoS](guides/bandwidth-and-qos.md). |
| `interactive` | `boolean()` | `true` | `false` marks video nobody answers live with AF3x instead of AF4x. |

A transceiver without `send_encodings` that answers an offer asking to receive simulcast sends the offered layers.

## Data channel options

You pass these in the third argument of `webrtc:create_data_channel(Pc, Label, Opts)`. It returns `{ok, Id}` when the id is known (association up, or a negotiated channel), otherwise `ok`, and the `datachannel_open` event carries the id. See [data channels](guides/data-channels.md).

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `ordered` | `boolean()` | `true` | Deliver messages in order. |
| `max_retransmits` | integer, 0 to 2^32-1 | none (reliable) | Partial reliability: give up after this many retransmissions. Cannot be combined with `max_packet_life_time`. |
| `max_packet_life_time` | ms, 0 to 2^32-1 | none (reliable) | Partial reliability: give up after this time. Cannot be combined with `max_retransmits`. |
| `protocol` | `binary()` | `<<>>` | Subprotocol name sent to the peer. |
| `negotiated` | `boolean()` | `false` | `true` when both sides create the channel with the same `id` out of band; no DCEP message is sent. |
| `id` | integer, 0 to 65534 | the next free id of your parity | Stream id. Required with `negotiated => true` (`{error, missing_id}`). Without `negotiated`, it must have your parity (even for the DTLS client, odd for the server), or `{error, wrong_parity}`. |
| `priority` | `very_low \| low \| medium \| high` or 0..65535 | `low` | Share of the association the channel gets (RFC 8831), told to the peer. |

Invalid values return `{error, badarg}`.

## Codecs

Two functions build the `codecs` option:

| Function | Returns |
|----------|---------|
| `webrtc:default_codecs(audio \| video)` | The codecs a peer connection offers when `codecs` is not given, in order of preference: VP8, VP9, H.264, AV1 for video, each followed by its rtx entry, then RED, ULPFEC and FlexFEC; Opus, RED, PCMU, PCMA and telephone-event for audio. |
| `webrtc:prefer_codec(Name, Codecs)` | `{ok, List}` with codec `Name` first, followed by its rtx entries and then the others in their order, or `{error, {unknown_codec, Name}}`. Every entry with that name moves (all H.264 profiles); names compare without case. |

```erlang
{ok, Video} = webrtc:prefer_codec(<<"AV1">>, webrtc:default_codecs(video)),
{ok, Pc} = webrtc:new_peer_connection(#{codecs => #{video => Video}}).
```

The order is that of our offers, and the peer answers in it, so the first codec it accepts is the one sent. When you answer an offer, the answer keeps the offer's order (RFC 3264 §6.1). Keep the rtx entries: without them, loss is repaired by key frames only.

## Other call options

### `create_offer/2` and `create_answer/2`

The options map is not read yet; pass `#{}`.

### `send_rtp/4`

`webrtc:send_rtp(Pc, Mid, Payload, Opts)` sends one RTP payload. See [send media](guides/send-media.md).

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `timestamp` | integer, RTP clock | `0` | RTP timestamp. |
| `marker` | `boolean()` | `false` | Marker bit. |
| `codec` | `binary()` | the first negotiated media codec | Codec name, case insensitive. |
| `pt` | integer | the first negotiated media codec | Payload type; takes precedence over `codec`. |
| `rid` | `binary()` | none | Send on this simulcast layer. |
| `keyframe` | `boolean()` | `false` | The payload belongs to a key frame: it then carries the RFC 6051 NTP time when negotiated and gets the lower drop precedence. |
| `audio_level` | `{Voice :: boolean(), Level :: 0..127}` | none | RFC 6464 audio level in -dBov, added when the extension is negotiated, encrypted when negotiated so. |
| `red` | `boolean()` | `false` | Send redundant audio (RFC 2198) when RED is negotiated. |

It returns `{error, not_sending}` when the transceiver does not send (or the layer was removed), `{error, unknown_codec}`, `{error, paused}` while the peer paused the stream, and `{error, {circuit_breaker, Reason}}` after a circuit breaker halted it.

### `send_frame/4`

`webrtc:send_frame(Pc, Mid, Frame, Opts)` splits an encoded frame into RTP payloads. Options: `timestamp`, `keyframe` (VP9 and AV1 also signal it in the payload), `codec`, `rid` and `audio_level`, as in `send_rtp/4`. An empty frame returns `{error, empty_frame}`. H.264 is packetized in the negotiated `packetization-mode`: mode 0 sends one NAL unit per packet and returns `{error, {nal_unit_too_large, Size}}`, sending nothing, when a NAL unit does not fit in one packet (keep the encoder's slices under about 1100 bytes); mode 1 aggregates and fragments (STAP-A, FU-A); mode 2 interleaves (STAP-B, FU-B, FU-A).

### `send_media/4`

`webrtc:send_media(Pc, Mid, Raw, Opts)` encodes with the transceiver's codec plugin. Option: `rid`. Without a plugin it returns `{error, no_codec_plugin}`. See [frames and codec plugins](guides/frames-and-codec-plugins.md).

### Calls that take only `rid`

`send_rtp_packet/4`, `request_keyframe/3`, `send_slice_loss/4`, `send_reference_picture/5`, `request_pause/3` and `request_resume/3` take `#{rid => Rid}` to act on one simulcast layer. See [forward media](guides/forward-media.md).

### `set_congestion_control/2`

Options `pacing`, `pacing_factor`, `min_bitrate` and `max_bitrate`, as in [Congestion control options](#congestion-control-options). It works once the transport exists, after the first description is set.

### `get_stats/2`

`#{format => w3c}` returns the W3C WebRTC statistics: a map from stats id to a map of the dictionary's members. Any other map returns the internal statistics of `get_stats/1`. See [statistics](guides/statistics.md).

### `report_media_stats/4`

The fourth argument is a map of W3C member names for `inbound`, `outbound`, `source` or `playout`. Counters add up across reports, other members replace the previous value, and unknown members are dropped. See [statistics](guides/statistics.md).

## Events

The owner receives every event as `{webrtc, Pc, Event}`. Below, `Mid` is the transceiver's mid (a binary) and `Rid` a simulcast layer (a binary). An event with a `Rid` concerns one layer of a transceiver that sends or receives several.

### Signaling and ICE

| Event | When it arrives |
|-------|-----------------|
| `negotiation_needed` | You added or stopped a transceiver, changed a direction, created a data channel while no data section is negotiated, or ICE restarted (`restart_ice/1`, or automatically without the `signaling` option). Create and send an offer. |
| `{signaling_state, State}` | A description was set. `State` is `stable`, `have_local_offer`, `have_remote_offer`, `have_local_pranswer`, `have_remote_pranswer` or `closed`. |
| `{ice_candidate, Candidate, Mid}` | A local candidate to send to the peer. `Candidate` is `<<"candidate:...">>` or `end_of_candidates`; pass `Mid` to `add_ice_candidate/3` on the other side. With the `signaling` option it arrives after the description it belongs to. |
| `{ice_gathering_state, new \| gathering \| complete}` | Gathering of the main transport changed. `complete` is followed by `{ice_candidate, end_of_candidates, Mid}`. |
| `{ice_connection_state, State}` | The ICE state of the main transport changed: `new`, `checking`, `connected`, `completed`, `disconnected`, `failed` or `closed`. |
| `{ice_restart, disconnected \| consent_lost}` | The connection restarted ICE by itself (`ice_auto_restart`). A `negotiation_needed` follows unless the `signaling` option sends the offer for you. |
| `{ice_server_error, Url, Reason}` | An `ice_servers` URI cannot be used: unsupported, not resolved, over the limit of eight (`too_many_servers`), or none of its addresses answered (`unreachable`). |

### Connection state

| Event | When it arrives |
|-------|-----------------|
| `{connection_state, State}` | The W3C RTCPeerConnectionState over every transport changed: `new`, `connecting`, `connected`, `disconnected`, `failed` or `closed`. |
| `{dtls_error, Reason}` | The DTLS handshake or association failed; `{connection_state, failed}` follows. |

### Data channels

| Event | When it arrives |
|-------|-----------------|
| `{datachannel_open, Id, Label, Protocol, Opts}` | A channel is usable, opened by you or the peer. `Opts` has `ordered`, `priority`, `negotiated`, `initiator` (`local` or `remote`) and `max_retransmits` or `max_packet_life_time` when set. |
| `{channel_message, Id, text \| binary, Data}` | A message arrived. |
| `{buffered_amount_low, Id}` | The data queued on the channel fell to 0. |
| `{datachannel_closed, Id}` | The channel is closed in both directions. |
| `{datachannel_error, Id, message_too_large}` | The peer sent a message over your `max_message_size`; the channel is closed. |
| `{datachannel_error, Id, invalid_stream_id}` | A channel created before the connection uses an id beyond the streams negotiated with the peer; it is closed. |
| `{datachannel_open_failed, Label, Reason}` | A channel created before the connection could not be opened once the association came up. |
| `{sctp_closed, Reason}` | The SCTP association ended, for example `shutdown`, `{peer_abort, Causes}` or `max_retransmissions`. |

### Media

| Event | When it arrives |
|-------|-----------------|
| `{track, Mid, audio \| video}` | After negotiation, the peer sends media on this transceiver. Sent once per mid. |
| `{rtp, Mid, Packet}`, `{rtp, Mid, Rid, Packet}` | An RTP packet (`#rtp{}` from `include/webrtc_rtp.hrl`) on a transceiver without `frames`. Retransmissions arrive already decapsulated. See [forward media](guides/forward-media.md). |
| `{frame, Mid, Frame}`, `{frame, Mid, Rid, Frame}` | An assembled frame on a transceiver with `frames`. `Frame` is `#{timestamp, keyframe, data, codec}`, with `width` and `height` for video and `ntp_time` (capture time, microseconds since the Unix epoch) when RFC 6051 is negotiated. See [frames and codec plugins](guides/frames-and-codec-plugins.md). |
| `{decoded, Mid, Out}` | An output of the codec plugin's `decode/2`, after the `frame` event. |
| `{keyframe_request, Mid}`, `{keyframe_request, Mid, Rid}` | The peer asked for a key frame (PLI or FIR) on a stream you send. |
| `{slice_loss, Mid, Entries}`, `{slice_loss, Mid, Rid, Entries}` | The remote decoder lost slices (SLI): `Entries` are `{First, Number, PictureId}`. A codec plugin also gets it in `feedback/2`. |
| `{reference_picture, Mid, Pt, Bits}`, `{reference_picture, Mid, Rid, Pt, Bits}` | The remote decoder asks for a reference picture (RPSI). |
| `{stream_paused, Mid}`, `{stream_resumed, Mid}` (and with `Rid`) | The peer asked you to pause or resume what you send (RFC 7728). `send_rtp` returns `{error, paused}` meanwhile. |
| `{remote_paused, Mid}`, `{remote_resumed, Mid}`, `{pause_refused, Mid}` (and with `Rid`) | Answers to your `request_pause/2,3` and `request_resume/2,3`. |
| `{ssrc_changed, Mid, Old, New}` | The peer sent with one of your SSRCs, so yours changed (RFC 3550); a BYE went out for the old one. |
| `{bye, Mid, Ssrc}` | The peer sent an RTCP BYE for `Ssrc`. `Mid` is `undefined` when the SSRC was not mapped to a transceiver. |

### Congestion and bandwidth

See [bandwidth and QoS](guides/bandwidth-and-qos.md).

| Event | When it arrives |
|-------|-----------------|
| `{bandwidth_estimate, Bps}` | The congestion controller changed the target bitrate for all media on the connection. Adapt your encoders. |
| `{max_bitrate, Mid, Bps}`, `{max_bitrate, Mid, Rid, Bps}` | The peer limited the stream with TMMBR (RFC 5104), in bits per second, or lifted the limit (`infinity`). The connection holds the stream to it. |
| `{circuit_breaker, Mid, Reason}` | An RFC 8083 circuit breaker tripped: `rtcp_timeout`, `media_timeout` or `congestion`. The first two halt the transceiver's streams at once; `congestion` first cuts the target to a tenth and halts on a second trip. Once halted, `send_rtp` returns `{error, {circuit_breaker, Reason}}` until `webrtc:resume_stream/2`. RTCP keeps flowing. |
| `{rtcp, undefined, Packet}` | Congestion feedback from the peer (REMB, transport-wide feedback or RFC 8888 feedback). The second element is always `undefined`. |
| `{dscp_disabled, Dscp}` | The path drops packets marked `Dscp`; the flows that used it now go unmarked. |

### Codec plugins

| Event | When it arrives |
|-------|-----------------|
| `{codec_plugin_error, Mid, Reason}` | The codec plugin raised or returned an error. It is turned off for that transceiver; frames keep coming and `send_media` returns `{error, {codec_plugin, Reason}}`. See [frames and codec plugins](guides/frames-and-codec-plugins.md). |

Statistics are not sent as events: call `webrtc:get_stats/1,2` when you need them ([statistics](guides/statistics.md)).

## Notes

- What each option implements, requirement by requirement, is in [COMPLIANCE.md](COMPLIANCE.md) and the pages it links to, such as [ICE](compliance/ice.md) and [data channels](compliance/datachannel.md).
- Internal keys that the peer connection adds to its own options (`peer_sup`, `server_fallbacks`, `server_urls`, `servers_down`) are not options; do not pass them.
