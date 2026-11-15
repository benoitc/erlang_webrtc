# libwebrtc corpora

Seed inputs of libwebrtc's fuzzers (`test/fuzzers/corpora` of https://webrtc.googlesource.com/src, commit 42a497714596d8f726da4dae4fb4f133cbaa15df), under the BSD license in `LICENSE`. Directory names follow the upstream ones without the `-corpus` suffix; `h264` and `av1` are `h264-depacketizer-fuzzer-corpus` and `rtp-depacketizer-av1-assemble-frame-corpus`.

`webrtc_corpus_tests` and `prop_webrtc_parsers:prop_corpus_mutations` read them.
