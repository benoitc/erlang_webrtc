# ADR 0006: Logs and crash reports never carry secrets

## Context

The state of a peer connection and of a transport holds secrets: the DTLS private key, ICE passwords, TURN credentials, DTLS and SRTP keys, 0-RTT tickets. OTP prints a process's state, its last message, the stack with arguments, and supervisor child arguments in crash reports and in `sys:get_status/1`. A production safety review found all of these printed.

## Decision

- `format_status/1` in `webrtc_pc` and `webrtc_transport` shows a summary (owner, transports, signaling, ICE, DTLS and connection states), the tag of the last message only, and stack frames without their arguments.
- A callback crash is caught by `webrtc_redact:guard/3`, which logs a redacted report itself and stops the process with `{shutdown, {crashed, Crash}}`. OTP writes no crash report for a shutdown reason.
- `terminate/2` drops the messages still queued, since a crash report would list them.
- Child start arguments are wrapped in funs, because supervisor reports print arguments but not a fun's environment.

## Consequences

- A crash is logged once, by the library, under the `[webrtc]` logger domain, without secrets.
- A crashed peer connection or transport exits with `{shutdown, {crashed, _}}` instead of the raw reason, and the API treats it as a closed connection.
- `webrtc_security_SUITE:no_secrets_in_crash_logs` crashes processes in several ways and checks that no key, password or credential reaches a log handler. A new field holding a secret needs no change, as long as the summary lists fields explicitly instead of printing the state.
- Debugging a crash relies on the redacted report and the internal counters (`webrtc:get_stats/1`), not on the full state.
