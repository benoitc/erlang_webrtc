# Interop peer protocol

Every peer adapter (Pion, aiortc, browsers through a driver) is a process that speaks newline-delimited JSON on stdin and stdout. The Erlang test controller (`test/interop/webrtc_interop_peer.erl`) starts the adapter, sends commands and waits for events. This protocol exists only for tests; the library never depends on it.

Diagnostics go to stderr, which the controller saves next to the test logs.

## Commands (controller to peer)

| cmd | fields | effect |
|---|---|---|
| `init` | `media`: list of `"audio"`/`"video"`, `channels`: list of channel specs, `ice_lite`: bool, `simulcast`: bool | Create the peer connection. Channel specs are `{label, ordered, max_retransmits, max_packet_life_time, negotiated, id, protocol}`; they are created when the peer makes the offer. With `simulcast`, browsers send their video as three layers with rids `q`, `h` and `f` (scaled down by 4, 2 and 1), and Pion negotiates the MID, rid and repaired-rid header extensions to receive layers. |
| `create_offer` | `ice_restart`: bool | Create an offer, set it as local description, emit `local_description`. |
| `remote_description` | `type`, `sdp` | Apply. When `type` is `offer` the peer answers and emits `local_description`. |
| `remote_candidate` | `candidate`, `mid` | Add a trickled candidate. An empty `candidate` means end of candidates. |
| `send` | `label`, `data`, `binary` (data is base64 when binary) | Send on a data channel. |
| `create_channel` | channel spec | Open a new data channel after connection. |
| `close_channel` | `label` | Close a data channel. |
| `stats` | | Emit `stats`. |
| `close` | | Close the peer connection and exit. |

## Events (peer to controller)

| event | fields |
|---|---|
| `ready` | `implementation`, `version` |
| `local_description` | `type`, `sdp` |
| `local_candidate` | `candidate`, `mid` (empty candidate: gathering complete) |
| `ice_state`, `connection_state`, `signaling_state` | `state` |
| `channel_open` | `label`, `id`, `protocol`, `ordered` |
| `channel_close` | `label` |
| `message` | `label`, `data`, `binary` |
| `track` | `mid`, `kind`, `ssrc`, `codec`, `rid` (Pion; empty without simulcast) |
| `rtp` | `mid`, `count`, `bytes` (sent every 50 packets and on the first one), `rid` (Pion, per layer) |
| `stats` | `stats` |
| `error` | `message` |

## Behavior

- Every data channel message received is sent back on the same channel prefixed with `echo:` (binary messages are echoed unchanged with a 4 byte `echo` prefix).
- Every RTP packet received on a track is written back unchanged (payload, marker, timestamp) on the peer's local track of the same kind. The Erlang side checks the packets it gets back.
