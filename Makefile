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

## Impairment tests (loss, reordering, duplication, MTU) on the
## deterministic in-memory network.
test-network:
	$(REBAR) ct --dir test/e2e --suite webrtc_impairment_SUITE

## Malformed input, replay, spoofing, floods.
test-security:
	$(REBAR) eunit --module=webrtc_security_tests
	$(REBAR) proper -n 2000 --module=prop_webrtc_parsers

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
	    -eval 'webrtc_srtp_bench:run(), halt().'

clean:
	$(REBAR) clean
