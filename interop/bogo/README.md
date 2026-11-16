# BoGo: BoringSSL's DTLS tests

This directory runs BoringSSL's TLS test suite (BoGo, `ssl/test/runner`) against our DTLS engine. Use it when you change anything in `src/dtls`: the runner is an independent DTLS implementation that sends deliberately broken, reordered, fragmented and replayed traffic, and checks what we answer on the wire.

## Run it

```sh
rebar3 compile
make -C interop bogo        # fetch BoringSSL at the pinned revision, build the shim
rebar3 ct --dir test/interop --suite webrtc_bogo_SUITE
```

The suite fails when a test that is not disabled fails. To run the runner by hand, for one test with a wire dump:

```sh
cd interop/bogo/boringssl/ssl/test/runner
go test -shim-path ../../../../bogo_shim -shim-config ../../../../config.json \
    -allow-unimplemented -loose-errors -test 'DTLS-Replay-TLS13' -debug
```

`BOGO_SHIM_TRACE=/tmp/trace.txt` makes the shim log every action of the engine.

## How it works

- `bogo_shim` starts `webrtc_bogo_shim` with the runner's flags. The shim connects back to the runner over TCP and runs one DTLS connection over the packet adaptor of `ssl/test/packeted_bio.cc`, on the clock the runner advances.
- A flag the shim does not implement makes it exit 89, which the runner reports as unimplemented, never as a pass. `BOGO_SHIM_LOG=/tmp/unimpl.txt` lists them.
- WebRTC pins the peer certificate by fingerprint. The runner makes its certificates at run time, so the shim pins the one the handshake brought.
- A WebRTC DTLS server always authenticates the client (RFC 8827), so server tests without `-require-any-client-certificate` are unimplemented.

## Disabled tests

`config.json` lists the tests that are not run, each with its reason:

- Behaviour we chose on purpose, with the requirement behind it: DTLS 1.0, static RSA and CBC suites are not offered; records that cannot be valid are discarded rather than ending the connection; KeyUpdates are acknowledged at once.
- Tests that assume BoringSSL internals, such as the runner panicking when the server sends no NewSessionTicket.
- Open items, marked "Open:": failures understood but not fixed yet, to address in later changes.

The BoringSSL revision is pinned in `BORINGSSL_REV`; the runner's interface is not stable, so update it on purpose and rerun.
