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

## Where the time goes

- Each peer connection is two processes: `webrtc_pc` (signaling) and `webrtc_transport` (packets). Peer connections scale with schedulers; there is no shared state on the packet path.
- One transport handles one BUNDLE group, so a single busy peer connection is bound by one scheduler on each side. At full data channel rate both transports are busy all the time.
- Sending a UDP datagram through `gen_udp` costs about 7 us, more than SRTP or DTLS encryption (under 1 us) and SCTP's CRC32c (about 1 us per 1200 bytes, skipped with peers that accept RFC 9653 zero checksum). The `socket` backend sends about a third faster.
- With one side behind TURN, the relayed pair needs a round trip through the server before it is valid: setup is bound by that, not by DTLS.
- AES-CM profiles are limited by HMAC-SHA1. Prefer AEAD_AES_128_GCM, which is also the first profile we offer.

## Not measured yet

Scheduler utilization under many concurrent media streams, recovery time after loss bursts at high rates, and the cost of pacing at high packet rates (the forwarding and capacity benchmarks run with pacing off).
