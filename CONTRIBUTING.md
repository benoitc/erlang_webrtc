# Contributing

This page is for you if you want to change erlang_webrtc: fix a bug, add a feature, or add an interop peer. It says how to propose a change, what to run before you send it, and how commits and pull requests are written. For where the code lives and how to change it, read [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) next.

## Propose a change

- For a bug, open an issue with what you expected, what happened, and how to reproduce it. A packet capture or a failing test helps most.
- For a new feature or a change that touches several layers, open an issue first and describe the approach. It saves you rewriting a large pull request.
- For a security problem, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Before you send it

Run the checks CI runs:

```sh
rebar3 compile
rebar3 eunit
rebar3 proper -n 200
rebar3 dialyzer
rebar3 xref
rebar3 ct --dir test/e2e
```

If you change behaviour on the wire, also run the interop suites for the peers it affects (see [docs/TESTING.md](docs/TESTING.md)). Peers that are not installed are reported as skipped, never as passed.

The rules every change follows:

- A change that implements or changes a requirement updates its row in `docs/compliance/`, with the status its tests justify.
- A bug fix comes with a test that fails before the fix.
- Never weaken a check (a validation, a bound, an assertion, a test) to make something pass. If a check is wrong, fix it and say why.
- Engines stay sans-IO: no sockets, timers or messages in protocol modules (see the engine contract in the developer guide).

## Commits and pull requests

- Small commits, each one passing `rebar3 eunit`.
- A commit subject says what changes for the user, in plain English: "Retry TURN allocations after 300 Try Alternate", not "update webrtc_turn".
- A pull request description says what was wrong and why it matters, the solution in a few lines, and any breaking change. The reviewer reads the code for the rest.
- User-visible changes get a line in [CHANGELOG.md](CHANGELOG.md): short, plain English, no internals.

## Supported OTP

OTP 29 and later. CI tests OTP 29.

## Read next

- [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md): where things live and how to change them.
- [docs/TESTING.md](docs/TESTING.md): the test layers and how to run each one.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the pieces fit together.
