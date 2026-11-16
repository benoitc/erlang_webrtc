#!/bin/bash
# Learn the state machine of our DTLS 1.2 server with DTLS-Fuzzer and
# compare it with the reference model. Run `make -C interop dtlsfuzzer`
# and `rebar3 compile` first.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
F="$DIR/dtls-fuzzer"
OUT="$DIR/output/server_ecdhe_cert_req"
KS="$F/experiments/keystore"

erl -noshell -noinput -pa "$ROOT/_build/default/lib/webrtc/ebin" -pa "$DIR/ebin" \
    -run webrtc_dtls_sut start -extra server 20000 "$KS/rsa2048_cert.pem" "$KS/rsa2048_key.pem" &
SUT=$!
trap 'kill $SUT 2>/dev/null' EXIT
sleep 2

rm -rf "$OUT"
(cd "$F" && java -jar target/dtls-fuzzer.jar @"$DIR/learn_server_ecdhe_cert_req" \
    -cmd "$DIR/reset.sh" -output "$OUT")

if diff -q "$DIR/models/server_ecdhe_cert_req.dot" "$OUT/learnedModel.dot" >/dev/null; then
    echo "learned model matches models/server_ecdhe_cert_req.dot"
else
    echo "learned model differs from the reference: $OUT/learnedModel.dot"
    exit 1
fi
