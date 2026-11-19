# erlang_webrtc

A WebRTC protocol stack in pure Erlang for OTP 29: ICE (full and lite) with TURN and mDNS candidates, DTLS 1.3 and 1.2 with DTLS-SRTP, SRTP/SRTCP, RTP/RTCP with retransmission, feedback, simulcast and congestion control, SCTP over DTLS with data channels, and JSEP negotiation on structured SDP. No NIFs and no runtime dependency beyond OTP (`crypto`, `public_key`).

Demo video: [your webcam in a browser, served by Erlang](https://youtu.be/vVp7s2ch2u8). To try it yourself, run one of the [examples](https://github.com/benoitc/erlang_webrtc/tree/main/examples).

Use it to build servers that talk to browsers and other WebRTC stacks: SFUs, media gateways, SIP to WebRTC bridges, data channel services, test peers. Those applications are not part of the library; it gives you peer connections and leaves signaling, codecs and routing to you.

Status: the transport stack works end to end against Chromium, Firefox, Pion, aiortc, GStreamer, pion/turn, OTP ssl and OpenSSL; see the summary and known gaps at the top of [docs/COMPLIANCE.md](docs/COMPLIANCE.md). What is implemented and tested is tracked requirement by requirement in [docs/COMPLIANCE.md](docs/COMPLIANCE.md); which independent implementations it has been tested against is in [docs/INTEROP.md](docs/INTEROP.md).

## Build and test

```sh
rebar3 compile
rebar3 eunit            # conformance tests
rebar3 proper           # properties
rebar3 ct --dir test/e2e
make test-interop       # needs the adapters, see docs/TESTING.md
rebar3 dialyzer
```

## Answer a browser offer

You receive an offer from a browser through your signaling channel and answer it.

```erlang
{ok, Pc} = webrtc:new_peer_connection(#{ice_servers => [#{urls => [<<"stun:stun.l.google.com:19302">>]}]}),
ok = webrtc:set_remote_description(Pc, offer, OfferSdp),
{ok, AnswerSdp} = webrtc:create_answer(Pc, #{}),
ok = webrtc:set_local_description(Pc, answer, AnswerSdp),
%% send AnswerSdp to the browser
```

Events arrive in the owner process (the caller by default):

```erlang
loop(Pc) ->
    receive
        {webrtc, Pc, {ice_candidate, Cand, Mid}} ->
            %% send Cand and Mid to the browser
            loop(Pc);
        {webrtc, Pc, {datachannel_open, Id, Label, _Proto, _Opts}} ->
            io:format("channel ~s open~n", [Label]),
            loop(Pc);
        {webrtc, Pc, {channel_message, Id, text, Text}} ->
            ok = webrtc:send_data(Pc, Id, text, <<"echo: ", Text/binary>>),
            loop(Pc);
        {webrtc, Pc, {rtp, Mid, Packet}} ->
            loop(Pc);
        {webrtc, Pc, {connection_state, closed}} ->
            ok;
        {webrtc, Pc, _} ->
            loop(Pc)
    end.
```

Trickled candidates from the browser:

```erlang
ok = webrtc:add_ice_candidate(Pc, <<"candidate:1 1 udp 2122260223 192.0.2.10 54321 typ host">>).
```

## Use STUN and TURN servers by URI

You give the servers as a browser would, with `stun:`, `turn:` and `turns:` URIs. Names are resolved when the peer connection starts.

```erlang
{ok, Pc} = webrtc:new_peer_connection(#{ice_servers => [
    #{urls => [<<"stun:stun.l.google.com:19302">>]},
    #{urls => [<<"turn:turn.example.com?transport=udp">>, <<"turns:turn.example.com">>],
      username => <<"user">>, credential => <<"secret">>}
]}).
```

- A URI without a port is looked up with DNS SRV first (`_turn._udp`, `_turns._tcp`, ...), then A and AAAA on the default port.
- A URI that cannot be used (a name that does not resolve, `stuns:`, TURN over DTLS) arrives as `{webrtc, Pc, {ice_server_error, Url, Reason}}`; the others are used.
- For `turns:` with your own CA, add `tls_options => [{cacerts, [Der]}]` to the entry.

## Documentation

Start here:

- [docs/CONCEPTS.md](docs/CONCEPTS.md): the WebRTC terms the code and the docs use.
- [examples](https://github.com/benoitc/erlang_webrtc/tree/main/examples): pages that talk to Erlang, ready to run.

Guides, task by task:

- [Talk to a browser over a data channel](docs/guides/data-channels.md)
- [Send media to a browser](docs/guides/send-media.md): transceivers, `send_rtp`, `send_frame`, directions, making the offer.
- [Forward media between peers](docs/guides/forward-media.md): SFU relaying, simulcast layers, TMMBR.
- [Receive frames and write a codec plugin](docs/guides/frames-and-codec-plugins.md): frames, codec plugins, device capture.
- [Read the statistics](docs/guides/statistics.md): W3C and internal formats.
- [Bandwidth and QoS](docs/guides/bandwidth-and-qos.md): congestion control, circuit breakers, DSCP, FEC.

Reference and internals:

- [docs/REFERENCE.md](docs/REFERENCE.md): every option and event.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, processes, how a packet travels.
- [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md): where things live and how to add a feature.
- [docs/TESTING.md](docs/TESTING.md): test layers, interop adapters, reproducing failures.
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) and [docs/INTEROP.md](docs/INTEROP.md): what is implemented, and against what it is tested.
- [docs/adr](https://github.com/benoitc/erlang_webrtc/tree/main/docs/adr): design decisions.

Project:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CHANGELOG.md](CHANGELOG.md)

## License

Copyright (c) 2026 Enki Multimedia and Benoit Chesneau. Apache 2.0, see [LICENSE](LICENSE).
