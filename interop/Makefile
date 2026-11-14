# Build the interop peer adapters. Each target is independent; a missing
# toolchain only disables the matching peer (reported as skipped).

.PHONY: all pion aiortc turn clean

all: pion aiortc turn

pion:
	cd pion && go build -o bin/pion-peer .

turn:
	cd turn && go build -o bin/turn-server .

aiortc:
	python3 -m venv aiortc/.venv
	aiortc/.venv/bin/pip install -q -r aiortc/requirements.txt

clean:
	rm -rf pion/bin turn/bin aiortc/.venv
