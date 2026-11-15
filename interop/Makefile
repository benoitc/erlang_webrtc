# Build the interop peer adapters. Each target is independent; a missing
# toolchain only disables the matching peer (reported as skipped).

.PHONY: all pion piondtls aiortc turn clean

all: pion piondtls aiortc turn

pion:
	cd pion && go build -o bin/pion-peer .

piondtls:
	cd piondtls && go build -o bin/piondtls .

turn:
	cd turn && go build -o bin/turn-server .

aiortc:
	python3 -m venv aiortc/.venv
	aiortc/.venv/bin/pip install -q -r aiortc/requirements.txt

clean:
	rm -rf pion/bin piondtls/bin turn/bin aiortc/.venv
