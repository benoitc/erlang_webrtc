REBAR ?= rebar3

.PHONY: all compile test test-protocol test-e2e test-interop test-network test-security test-all dialyzer xref fmt bench clean

all: compile

compile:
	$(REBAR) compile

## Unit and conformance tests (eunit + PropEr). Fast, no network.
test-protocol:
	$(REBAR) eunit
	$(REBAR) proper -n 200

test: test-protocol

## Erlang to Erlang over real UDP sockets on loopback.
test-e2e:
	$(REBAR) ct --dir test/e2e

## Interop against independent stacks. Peers that are not installed are
## reported as skipped by the suite, never as passed.
test-interop:
	$(REBAR) ct --dir test/interop

## Seeded impairment (loss, bursts, reordering, duplication, jitter,
## path MTU, blackhole) between real peer connections.
test-network:
	$(REBAR) ct --dir test/e2e --suite webrtc_impairment_SUITE

## Spoofing, replay, floods, teardown, and every parser on hostile input.
test-security:
	$(REBAR) ct --dir test/e2e --suite webrtc_security_SUITE
	$(REBAR) proper -n 5000 --module=prop_webrtc_parsers

test-all: test-protocol test-e2e test-interop dialyzer xref

dialyzer:
	$(REBAR) dialyzer

xref:
	$(REBAR) xref

fmt:
	$(REBAR) fmt

## Benchmarks are separate from the functional suites.
bench:
	$(REBAR) as test compile
	erl -noshell -pa _build/test/lib/*/ebin -pa _build/test/lib/webrtc/bench \
	    -pa _build/test/lib/webrtc/test/support \
	    -eval 'webrtc_srtp_bench:run(), webrtc_pc_bench:run(), halt().'

clean:
	$(REBAR) clean
