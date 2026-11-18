# Performance

This page gives the benchmark numbers of the current code and how to reproduce them. Use it to size a deployment, to check that a change did not regress the media or data path, and to find where time goes when it did. Benchmarks live in `bench/` and never run with the functional suites.

## Run the benchmarks

```sh
make bench
```

`make bench` runs `webrtc_srtp_bench` (SRTP packet rates per profile) and `webrtc_pc_bench` (establishment, memory, data channel throughput, RTP forwarding).

## Profile a change

```sh
make -C interop turn   # once, for the relayed setup timeline
make profile
```

`make profile` runs `webrtc_profile` and prints:

- the connection setup timeline: the first time each event is seen on each side, median of 15 runs, for a direct connection and for one side behind TURN (skipped when the TURN server is not built);
- the RTP send capacity: the cost of one `send_rtp/4` call and the packet rate one transport sustains with pacing off;
- tprof call time and allocation profiles of the data channel, RTP and handshake paths, across every process, for the `webrtc` modules and the library calls they make.

From a shell, profile one workload of your own:

```erlang
webrtc_profile:profile(my_case, fun() -> my_workload() end, 25).
```

tprof traces every call, so functions called millions of times (CRC32c, map folds) look bigger than they are. Confirm a hotspot with a micro benchmark before optimizing it.

## Results

Apple M-series laptop, 14 schedulers, OTP 29.1.2, OpenSSL 4.1, loopback UDP. Treat the numbers as orders of magnitude.

| Measurement | Result |
|---|---|
| SRTP protect, AEAD_AES_128_GCM, 1200 byte payload | 1.1 M packets/s |
| SRTP protect, AES128_CM_HMAC_SHA1_80 | 0.43 M packets/s |
| SCTP association alone, 16 KiB messages (in-memory, `webrtc_sctp_bench`) | 78 MB/s |
| Session establishment: offer to both sides connected and data channel open (ICE, DTLS, SCTP, DCEP) | median 1.4 ms |
| Same, one side behind a TURN server that only it can reach | median 104 ms |
| Memory per connected peer connection with a data channel | 125 KiB of VM memory, 90 KiB in its two processes |
| Data channel throughput, 16 KiB messages, one channel | 65 to 70 MB/s |
| `send_rtp/4`, 1100 byte payloads, pacing off | 23 us per call, 44 000 packets/s |
| RTP forwarding, sender to an Erlang relay peer to a receiver, 1100 byte payloads, one stream | 40 000 to 46 000 packets/s end to end, no loss |

### Congestion control (RFC 8867)

The RMCAT cases run in simulation on six seeds (`rebar3 eunit --module=webrtc_rmcat_tests`, about 45 s), or on 24 with `RMCAT_SEEDS=24` (about 3 minutes). Rates are averages from 10 s after each change; see the RMCAT rows of [compliance/rtp.md](compliance/rtp.md) for the bounds. The ranges are over 24 seeds.

| Case | Result |
|---|---|
| 5.1, one flow, capacity 1, 2.5, 0.6, 1 Mbps | 0.84 to 1.00 of the available rate, queue p95 at most 98 ms |
| 5.2, two flows, capacity 4 to 1 Mbps | together 0.85 to 1.00 of the available rate, queue p95 at most 73 ms |
| 5.3, media both ways | reference 0.87 to 1.00, backward link congested 0.80 to 1.00 forward and 0.90 to 1.00 backward |
| 5.4, three flows joining | Jain index 0.934 to 1.000, 0.93 to 0.95 of the link |
| 5.5, RTT fairness | Jain index 0.945 to 0.997 |
| 5.6, against a long TCP flow (300 / 1000 ms queue) | media 193 to 242 / 318 to 474 kbps, TCP 1672 to 1718 / 1447 to 1584 kbps |
| 5.7, against ten short TCP flows | media 330 to 481 kbps, never below the minimum |
| 5.8, pause and resume | Jain index 0.942 to 0.998 after the resume |
| 6.2, ECN (CoDel marking), one flow | 0.82 to 1.00 of the available rate, queue p95 at most 58 ms |
| 6.2, ECN (CoDel marking), three flows | Jain index 0.900 to 1.000 |

Fair sharing is measured from the convergence time of RFC 8867 §4.1, which is 0 s in almost every run and at most 6 s. Over 24 seeds, one run out of 288 misses a bound: the 5.3 reference on seed 20, with a queue p95 of 104 ms between 30 and 40 s. The flow creeps past the 1 Mbps capacity by its additive increase, and the trendline detector stays just under its threshold for 2 s while the queue grows. Before these changes two runs missed: a 5.3 phase at 129 ms and a 5.4 Jain index of 0.898.

## Where the time goes

- Each peer connection is two processes: `webrtc_pc` (signaling) and `webrtc_transport` (packets). Peer connections scale with schedulers; there is no shared state on the packet path.
- One transport handles one BUNDLE group, so a single busy peer connection is bound by one scheduler on each side. At full data channel rate both transports are busy all the time.
- Sending a UDP datagram through `gen_udp` costs about 7 us, more than SRTP or DTLS encryption (under 1 us) and SCTP's CRC32c (about 1 us per 1200 bytes, skipped with peers that accept RFC 9653 zero checksum). The `socket` backend sends about a third faster.
- With one side behind TURN, the relayed pair needs a round trip through the server before it is valid: setup is bound by that, not by DTLS.
- AES-CM profiles are limited by HMAC-SHA1. Prefer AEAD_AES_128_GCM, which is also the first profile we offer.

## Not measured yet

Scheduler utilization under many concurrent media streams, recovery time after loss bursts at high rates, and the cost of pacing at high packet rates (the forwarding and capacity benchmarks run with pacing off).

## Soak (make soak)

`make soak DURATION=60 WORKERS=4`, one hour on Apple M4 Pro, OTP 29. Four workers create and close connected pairs without pause. Each pair carries audio, H.264 key frames whose SPS has a picture order count cycle of 2^31 frames, data channel messages and keyframe requests.

| | Baseline | During (each minute) | After |
|---|---|---|---|
| Processes | 70 | 97 to 98 | 70 |
| Ports | 1 | 7 to 9 | 1 |
| `webrtc_transports` rows | 0 | 6 to 8 | 0 |
| Ticket table entries | 1 (the key) | 1 | 1 |
| Longest message queue | 0 | 80 to 102 | 4 |
| Total memory | 55.4 MB | 60.4 to 62.1 MB | 55.7 MB |

130,969 pairs were connected and closed. Every count came back to its baseline, and memory stayed within 1 MB of it. The longest queues belong to the transports of pairs being set up: 4 workers and 8 peer connections at a time.

The lifecycle suite (`webrtc_lifecycle_SUITE`) checks the same return to the baseline in CI. It covers close, owner exit, kill of a peer connection or a transport, an application restart, a stuck codec plugin, and 200 abandoned and 200 short-lived connections.

The lifecycle suite also connects 40 pairs at once on a single scheduler and then on all of them, and drives a peer connection from another node: data and statistics from a node that does not run the application, and an owner there whose node goes away.

Not covered: multi-day runs (`make soak DURATION=...` runs as long as asked) and forced VM resource exhaustion.
