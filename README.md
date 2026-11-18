# erlang_webrtc

A WebRTC protocol stack in pure Erlang for OTP 29: ICE (full and lite) with TURN and mDNS candidates, DTLS 1.3 and 1.2 with DTLS-SRTP, SRTP/SRTCP, RTP/RTCP with retransmission, feedback, simulcast and congestion control, SCTP over DTLS with data channels, and JSEP negotiation on structured SDP. No NIFs and no runtime dependency beyond OTP (`crypto`, `public_key`).

Use it to build servers that talk to browsers and other WebRTC stacks: SFUs, media gateways, SIP to WebRTC bridges, data channel services, test peers. Those applications are not part of the library; it gives you peer connections and leaves signaling, codecs and routing to you.

Status: the transport stack works end to end against Chromium, Pion, aiortc, pion/turn, OTP ssl and OpenSSL; see the summary and known gaps at the top of [docs/COMPLIANCE.md](docs/COMPLIANCE.md). What is implemented and tested is tracked requirement by requirement in [docs/COMPLIANCE.md](docs/COMPLIANCE.md); which independent implementations it has been tested against is in [docs/INTEROP.md](docs/INTEROP.md).

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

Video FEC (ULPFEC in RED, RFC 8854 §5.2) is negotiated by default: lost packets are rebuilt from FEC packets the sender adds after each frame. The sender adds them as the peer reports loss; `video_fec => 0.5` on `new_peer_connection/1` fixes one FEC packet for two media packets, `0.0` turns them off.

Ask the sender for a keyframe when a new receiver joins:

```erlang
ok = webrtc:request_keyframe(In, <<"1">>).
```

## Receive frames

To decode or record what a peer sends, ask for frames instead of packets. The packets of each frame are put in order, joined and released at their playout time; a frame that cannot be completed is dropped and a key frame is asked for.

```erlang
{ok, _} = webrtc:add_transceiver(Pc, video, #{frames => true}),
%% or for every transceiver, those a remote offer creates included:
{ok, Pc} = webrtc:new_peer_connection(#{frames => true}),

{webrtc, Pc, {frame, _Mid, #{data := Data, keyframe := Key, width := W, height := H}}} -> decode(Data).
```

`data` is a VP8 or VP9 frame, an H.264 access unit in Annex B, or an AV1 temporal unit; audio frames are the payloads. `#{min_delay => Ms, max_delay => Ms}` instead of `true` bounds the delay.

Send an encoded frame the same way; it is split into RTP payloads for its codec:

```erlang
ok = webrtc:send_frame(Pc, <<"1">>, Vp8Frame, #{timestamp => Ts, keyframe => true}).
```

## Decode and encode with a codec plugin

The library does no media coding. A codec plugin, a module with the `webrtc_media_codec` behaviour, usually a separate package with native code, decodes the frames a transceiver receives and encodes what you send, and reports the W3C decoder and encoder statistics.

```erlang
-module(my_vp8).
-behaviour(webrtc_media_codec).
-export([init/3, decode/2, encode/2, info/1]).

init(video, #{name := <<"VP8">>}, Opts) -> {ok, my_vp8_nif:new(Opts)}.
decode(#{data := Frame}, D) -> {ok, [my_vp8_nif:decode(D, Frame)], #{framesDecoded => 1}, D}.
encode({Picture, Ts}, E) ->
    {Frame, Key} = my_vp8_nif:encode(E, Picture),
    {ok, [#{data => Frame, keyframe => Key, timestamp => Ts}], #{framesEncoded => 1}, E}.
info(_) -> #{implementation => <<"libvpx">>}.
```

```erlang
{ok, _} = webrtc:add_transceiver(Pc, video, #{frames => true, codec_plugin => {my_vp8, #{}}}),
ok = webrtc:send_media(Pc, <<"1">>, {Picture, Ts}),
{webrtc, Pc, {decoded, _Mid, Picture}} -> show(Picture).
```

`codec_plugins => #{video => {my_vp8, #{}}}` with `frames => true` on `new_peer_connection/1` sets it for transceivers a remote offer creates. A plugin that raises is turned off for its transceiver and you get `{codec_plugin_error, Mid, Reason}`.

If you code media yourself, report the statistics instead; counters add up, other members replace:

```erlang
webrtc:report_media_stats(Pc, <<"1">>, inbound, #{framesDecoded => 1, totalDecodeTime => 0.004}),
webrtc:report_media_stats(Pc, <<"1">>, source, #{width => 1280, height => 720, frames => 1}).
```

## Read the statistics

You get the W3C statistics, the ones a browser's `getStats()` returns, as a map from stats id to the members of each dictionary.

```erlang
Report = webrtc:get_stats(Pc, #{format => w3c}),
[#{packetsSent := Sent}] = [S || _ := #{type := <<"outbound-rtp">>} = S <- Report].
```

The frame members of received streams come from the frame buffer when you ask for frames; the decoder, encoder, media-source and media-playout members from a codec plugin or `report_media_stats/4`. [docs/compliance/stats.md](docs/compliance/stats.md) lists every member.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, processes, how a packet travels.
- [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md): where things live and how to add a feature.
- [docs/TESTING.md](docs/TESTING.md): test layers, interop adapters, reproducing failures.
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) and [docs/INTEROP.md](docs/INTEROP.md).
- [docs/adr](docs/adr): design decisions.

## License

Apache 2.0.
