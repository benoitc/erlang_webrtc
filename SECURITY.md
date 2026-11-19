# Security policy

This page tells you how to report a vulnerability in erlang_webrtc and what counts as one. The library parses input from remote peers you do not control (STUN, DTLS, SRTP, RTP, RTCP, SCTP, SDP), so a bug that a peer can trigger is a security bug.

## Report a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Please do not open a public issue.

Include:

- the version or commit you tested;
- what a peer or a signaling message has to send, and what happens (a crash, memory growth, a secret in a log, an accepted replay);
- a reproducer if you have one: a packet capture, a test case, or a script.

Once a fix is released, the CHANGELOG says what was wrong and the advisory credits you unless you ask otherwise.

## In scope

Anything a remote peer, or a session description passed to the library, can cause:

- a crash of a process other than the one connection the peer belongs to;
- memory, process or table growth without a bound;
- a secret in a log or crash report: private keys, ICE or TURN credentials, DTLS or SRTP keys;
- accepted replayed or forged packets: SRTP, DTLS records, 0-RTT data, STUN without integrity;
- a certificate or fingerprint check that can be bypassed.

## Out of scope

- Codec plugins: they run your code in the transport process, so a stuck or crashing plugin is the plugin's bug.
- The signaling channel between your peers: authenticating it is the application's job.
- Denial of service by bandwidth alone, which no endpoint can prevent.

## Supported versions

Fixes go to the latest release.

## Read next

- [docs/compliance/security.md](docs/compliance/security.md): the security requirements the library tracks and how each is tested.
- [docs/TESTING.md](docs/TESTING.md): how to run the hostile input and lifecycle suites.
