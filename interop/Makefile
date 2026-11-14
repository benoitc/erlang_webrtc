# Build the interop peer adapters. Each target is independent; a missing
# toolchain only disables the matching peer (reported as skipped).
.PHONY: all pion aiortc clean

all: pion aiortc

pion:
	cd pion && go build -o bin/pion-peer .

aiortc:
	python3 -m venv aiortc/.venv
	aiortc/.venv/bin/pip install -q -r aiortc/requirements.txt

clean:
	rm -rf pion/bin aiortc/.venv
