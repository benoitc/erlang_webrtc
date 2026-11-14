# Testing

This page explains how the test suites are organized, how to run each layer, and how to reproduce a failure. Read it before you add a protocol feature: every feature lands with conformance tests, and with E2E or interop tests once it is reachable from the peer connection.

## Layers

| Layer | Where | Runs with | Needs |
|---|---|---|---|
| Conformance (codecs, engines) | `test/*_tests.erl` | `rebar3 eunit` | nothing |
| Properties (round trips, hostile input) | `test/prop_*.erl` | `rebar3 proper` | nothing |
| Erlang to Erlang over UDP | `test/e2e/*_SUITE.erl` | `rebar3 ct --dir test/e2e` | loopback |
| Interop | `test/interop/*_SUITE.erl` | `rebar3 ct --dir test/interop` | adapters, see below |
| Benchmarks | `bench/` | by hand, see each module doc | nothing |

`make test-all` runs everything that does not need extra tooling plus the interop suites; a peer that is missing is reported as skipped.

## Run a single test

```sh
rebar3 eunit --module=webrtc_dtls_tests
rebar3 proper --module=prop_webrtc_srtp -n 2000
rebar3 ct --dir test/interop --suite webrtc_dtls_interop_SUITE --case otp_client_our_server
```

## Deterministic engine tests

Every protocol engine is sans-IO (see [ARCHITECTURE.md](ARCHITECTURE.md)), so tests drive it with a synthetic clock and an in-memory network:

```erlang
{Cl1, Actions} = webrtc_dtls:start(0, Cl0),
%% route {send, Bin} actions to the other engine with handle_packet/3,
%% advance time to next_timeout/1 and call handle_timeout/2.
```

Loss, duplication and reordering are injected by the network helper of each test module with a fixed `rand:seed/2`. When a randomized test fails, the seed in the test reproduces it exactly.

## Interop adapters

Each independent implementation runs behind the same line-delimited JSON protocol ([interop/PROTOCOL.md](../interop/PROTOCOL.md)). The controller is `test/interop/webrtc_interop_peer.erl`.

```sh
make -C interop pion          # Go toolchain
make -C interop aiortc        # Python 3
(cd interop/browser && npm ci && npx playwright install chromium firefox)
```

`webrtc_harness_SUITE` connects independent implementations to each other. Run it first: if it fails, the problem is the harness or the environment, not this stack.

## Reproduce an interop failure

1. Run the single case: `rebar3 ct --dir test/interop --suite <SUITE> --case <case>`.
2. Open `_build/test/logs/index.html`. Each case has a `log_private` directory with the stderr of every adapter (`pion_peer.log`, `chromium_peer.log`, ...).
3. The CT log has every event the adapter emitted, including the SDP it produced.
4. To replay by hand, start the adapter (`interop/pion/bin/pion-peer`) and type the JSON commands from the protocol page.

## Rules

- Malformed input must never crash a parser or engine. Every externally reachable decoder has a test feeding it every truncation of a valid message and random bytes.
- Never weaken a check to make a test pass. When an independent implementation disagrees with us, find the requirement in the RFC, write the failing test, then fix whichever side is wrong and record it in [COMPLIANCE.md](COMPLIANCE.md) or [INTEROP.md](INTEROP.md).
- A peer that cannot run is reported with `{skip, Reason}`, never as a pass.
