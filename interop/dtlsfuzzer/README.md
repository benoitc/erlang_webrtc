# DTLS-Fuzzer: the state machine of our DTLS 1.2 server

This directory learns the state machine of our DTLS 1.2 server with [DTLS-Fuzzer](https://github.com/assist-project/dtls-fuzzer) and compares it with a reference model. Use it when you change the DTLS 1.2 handshake in `src/dtls`. DTLS-Fuzzer sends sequences of handshake messages in every order, including orders no correct client sends. From our answers it builds a state machine, which shows any path to the connected state that skips a step.

## Run it

You need Java 21 and Maven, and Graphviz if you want to draw the models.

```sh
rebar3 compile
make -C interop dtlsfuzzer        # fetch and build DTLS-Fuzzer at the pinned revision
interop/dtlsfuzzer/learn.sh
```

`learn.sh` starts our server on UDP port 20000 and learns its state machine. It then compares the model it learned with `models/server_ecdhe_cert_req.dot`. Learning takes two hours: the model is usually final within the first hour, and the rest of the time goes to testing it. The learned model and DTLS-Fuzzer's statistics go to `output/server_ecdhe_cert_req`.

To draw a model:

```sh
dot -Tpdf models/server_ecdhe_cert_req.dot -o server.pdf
```

## How it works

- `webrtc_dtls_sut` runs our DTLS engine over UDP. It gives each client address a new engine and echoes application data back, as the other systems tested by DTLS-Fuzzer do.
- Before each test, DTLS-Fuzzer runs `reset.sh`. The script sends `reset` to port 20001, and the server drops every connection, so each test starts from the initial state even when the fuzzer reuses a client port.
- The fuzzer waits a fixed time for each answer. The server therefore does not retransmit during a test (`rtx_initial`), and it does not require extended master secret, which DTLS-Fuzzer's TLS-Attacker configuration leaves out.
- WebRTC pins the peer certificate by fingerprint, and the fuzzer's certificate is only known once it arrives. The server pins that certificate when the handshake brings it.
- The alphabet is ECDHE with a client certificate (`piondtls_ecdhe_cert.xml`), the WebRTC case.

## Reading the model

The happy path is ClientHello, HelloVerifyRequest, ClientHello, then the server's flight, then Certificate, ClientKeyExchange, CertificateVerify, ChangeCipherSpec, Finished. After it, application data is echoed back. Two other kinds of state are expected:

- The sink state the fuzzer reaches when it changes epoch on its own side: we cannot read what it sends after that.
- The state an empty client Certificate leads to: it answers with a handshake_failure alert.

DTLS-Fuzzer may report a few queries as nondeterministic, where the same CertificateVerify sometimes gets a decrypt_error alert. TLS-Attacker drops the leading zero bytes of its RSA signatures, so about one signature in 256 is shorter than the modulus, and we refuse it (RFC 8017 §8.2.2). The fuzzer reruns these queries, and they do not change the model.

The first run found that the server took a ChangeCipherSpec before the CertificateVerify, so the fuzzer's encrypted CertificateVerify was read in epoch 1 (RFC 5246 §7.4.8). The server now holds that ChangeCipherSpec until the CertificateVerify is verified.

The DTLS-Fuzzer revision is pinned in `DTLS_FUZZER_REV`. When you update it, or change the handshake on purpose, relearn the model and commit the new one.
