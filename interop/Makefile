# Build the interop peer adapters. Each target is independent; a missing
# toolchain only disables the matching peer (reported as skipped).

.PHONY: all pion piondtls aiortc turn bogo dtlsfuzzer clean

all: pion piondtls aiortc turn bogo

pion:
	cd pion && go build -o bin/pion-peer .

piondtls:
	cd piondtls && go build -o bin/piondtls .

turn:
	cd turn && go build -o bin/turn-server .

# BoringSSL's test runner at the pinned revision, and the shim it drives.
BORINGSSL_REV := $(shell cat bogo/BORINGSSL_REV)

bogo:
	test -d bogo/boringssl/.git || git init -q bogo/boringssl
	cd bogo/boringssl && (git cat-file -e $(BORINGSSL_REV)^{commit} 2>/dev/null || \
	    git fetch -q --depth 1 https://boringssl.googlesource.com/boringssl $(BORINGSSL_REV)) && \
	    git checkout -q $(BORINGSSL_REV)
	mkdir -p bogo/ebin && erlc -o bogo/ebin bogo/webrtc_bogo_shim.erl

# DTLS-Fuzzer at the pinned revision (Java 21 and Maven), and our endpoint.
# Not part of `all`: it takes a while to build and is run by hand.
DTLS_FUZZER_REV := $(shell cat dtlsfuzzer/DTLS_FUZZER_REV)

dtlsfuzzer:
	test -d dtlsfuzzer/dtls-fuzzer/.git || git clone -q https://github.com/assist-project/dtls-fuzzer.git dtlsfuzzer/dtls-fuzzer
	cd dtlsfuzzer/dtls-fuzzer && git checkout -q $(DTLS_FUZZER_REV) && \
	    (test -f target/dtls-fuzzer.jar || \
	    MAVEN_ARGS="-Dspotless.check.skip=true -Dspotless.apply.skip=true" ./install.sh)
	mkdir -p dtlsfuzzer/ebin && erlc -o dtlsfuzzer/ebin dtlsfuzzer/webrtc_dtls_sut.erl

aiortc:
	python3 -m venv aiortc/.venv
	aiortc/.venv/bin/pip install -q -r aiortc/requirements.txt

clean:
	rm -rf pion/bin piondtls/bin turn/bin aiortc/.venv bogo/ebin dtlsfuzzer/ebin dtlsfuzzer/output
