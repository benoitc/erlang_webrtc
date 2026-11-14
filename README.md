# erlang_webrtc

A WebRTC protocol stack in pure Erlang for OTP 29: ICE (full and lite) with TURN, DTLS 1.2 with DTLS-SRTP, SRTP/SRTCP, RTP/RTCP with retransmission and feedback, SCTP over DTLS with data channels, and JSEP negotiation on structured SDP. No NIFs and no runtime dependency beyond OTP (`crypto`, `public_key`).

Use it to build servers that talk to browsers and other WebRTC stacks: SFUs, media gateways, SIP to WebRTC bridges, data channel services, test peers. Those applications are not part of the library; it gives you peer connections and leaves signaling, codecs and routing to you.

Status: under active development. What is implemented and tested is tracked requirement by requirement in [docs/COMPLIANCE.md](docs/COMPLIANCE.md); which independent implementations it has been tested against is in [docs/INTEROP.md](docs/INTEROP.md).

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
{ok, Pc} = webrtc:new_peer_connection(#{stun_servers => [{{74,125,250,129}, 19302}]}),
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
            %% send Cand to the browser
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
            ok
    end.
```

Trickled candidates from the browser:

```erlang
ok = webrtc:add_ice_candidate(Pc, <<"candidate:1 1 udp 2122260223 192.0.2.10 54321 typ host">>).
```

## Make an offer

```erlang
{ok, Pc} = webrtc:new_peer_connection(),
{ok, _AudioId} = webrtc:add_transceiver(Pc, audio, #{}),
ok = webrtc:create_data_channel(Pc, <<"chat">>, #{}),
{ok, Offer} = webrtc:create_offer(Pc, #{}),
ok = webrtc:set_local_description(Pc, offer, Offer),
%% send Offer, receive Answer
ok = webrtc:set_remote_description(Pc, answer, Answer).
```

## Send and forward media

The library moves RTP payloads; encoding and decoding are up to you.

```erlang
ok = webrtc:send_rtp(Pc, <<"0">>, OpusFrame, #{timestamp => Ts, codec => <<"opus">>}).
```

Forward a packet received on one peer connection to another (SFU style). SSRC and sequence numbers are rewritten for the outgoing stream:

```erlang
{webrtc, In, {rtp, _Mid, Pkt}} -> webrtc:send_rtp_packet(Out, <<"1">>, Pkt).
```

Ask the sender for a keyframe when a new receiver joins:

```erlang
ok = webrtc:request_keyframe(In, <<"1">>).
```

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, processes, how a packet travels.
- [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md): where things live and how to add a feature.
- [docs/TESTING.md](docs/TESTING.md): test layers, interop adapters, reproducing failures.
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) and [docs/INTEROP.md](docs/INTEROP.md).
- [docs/adr](docs/adr): design decisions.

## License

Apache 2.0.
