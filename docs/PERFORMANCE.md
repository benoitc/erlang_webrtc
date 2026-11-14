# Performance

This page gives the benchmark numbers of the current code and how to reproduce them. Use it to size a deployment and to check that a change did not regress the media or data path. Benchmarks live in `bench/` and never run with the functional suites.

## Run

```sh
make bench
```

## Results

Apple M-series laptop, 14 schedulers, OTP 29.1.2, OpenSSL 4.1, loopback UDP. Single run, so treat the numbers as orders of magnitude.

| Measurement | Result |
|---|---|
| SRTP protect, AEAD_AES_128_GCM, 1200 byte payload | 1.0 to 1.7 M packets/s |
| SRTP protect, AES128_CM_HMAC_SHA1_80 | 0.4 M packets/s |
| SCTP association alone, 16 KiB messages (in-memory, `webrtc_sctp_bench`) | 78 MB/s |
| Session establishment: offer to both sides connected and data channel open (ICE, DTLS, SCTP, DCEP) | median 51 ms, p90 52 ms |
| Memory per connected peer connection with a data channel | 157 KiB of VM memory, 121 KiB in its two processes |
| Data channel throughput, 16 KiB messages, one channel | 51 MB/s |
| RTP forwarding, sender to an Erlang relay peer to a receiver, 1100 byte payloads, one stream | 55 000 packets/s end to end, no loss |

## Where the time goes

- Each peer connection is two processes: `webrtc_pc` (signaling) and `webrtc_transport` (packets). Peer connections scale with schedulers; there is no shared state on the packet path.
- Media sends go straight to the transport process. One transport handles one BUNDLE group, so a single very busy peer connection is bound by one scheduler.
- AES-CM profiles are limited by HMAC-SHA1. Prefer AEAD_AES_128_GCM, which is also the first profile we offer.

## Not measured yet

Scheduler utilization under many concurrent media streams, recovery time after loss bursts at high rates, and congestion controlled sending (no pacer yet, see COMPLIANCE.md).
