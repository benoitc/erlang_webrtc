# Talk to a browser over a data channel

A data channel carries text and binary messages between a browser and your Erlang node, encrypted, over the same connection as WebRTC audio and video, with no server in between once it is set up. You need it to push events to a page, take commands from it, or move files and telemetry with a latency close to the network's. This guide builds a page that opens a channel to Erlang, gets a greeting and has its messages echoed back. The finished code is in [`examples/browser_datachannel`](https://github.com/benoitc/erlang_webrtc/tree/main/examples/browser_datachannel).

## How it works

- ICE finds a UDP path between the browser and your node (through a STUN or TURN server when there is NAT on the way).
- DTLS encrypts that path; each side checks the other's certificate against the fingerprint in the SDP.
- SCTP runs inside DTLS and carries the messages, keeping their boundaries.
- Each channel is opened by DCEP (RFC 8832): one side sends the label, the other acknowledges, and the channel gets a stream number, the `Id` you use in Erlang.

You move the SDP offer and answer between the two sides yourself. Here it is one HTTP request.

## Run the example

```sh
rebar3 shell
```

```erlang
1> cd("examples/browser_datachannel").
2> c(browser_datachannel).
3> browser_datachannel:start(8080).
```

Open `http://localhost:8080/`. The page shows `open`, `erlang: hello from Erlang on chat`, then `erlang: echo: hello from the browser`; type in the box to send more. `browser_datachannel:stop()` stops the server.

## Signal with one request

The page waits until it has gathered its candidates, so the offer carries all of them, and posts it:

```js
const pc = new RTCPeerConnection();
const channel = pc.createDataChannel('chat');

await pc.setLocalDescription(await pc.createOffer());
if (pc.iceGatheringState !== 'complete') {
  await new Promise((done) => {
    pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') done(); };
  });
}
const res = await fetch('/offer', { method: 'POST', body: pc.localDescription.sdp });
await pc.setRemoteDescription({ type: 'answer', sdp: await res.text() });
```

On the Erlang side, start one process per browser. It owns the peer connection, so it gets its events. It answers, waits for its own candidates, and returns the local description, which now holds them:

```erlang
session({From, Offer}) ->
    {ok, Pc} = webrtc:new_peer_connection(#{}),
    ok = webrtc:set_remote_description(Pc, offer, Offer),
    {ok, Answer} = webrtc:create_answer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, answer, Answer),
    receive {webrtc, Pc, {ice_gathering_state, complete}} -> ok after 5000 -> ok end,
    From ! {answer, self(), webrtc:local_description(Pc)},
    loop(Pc).
```

The example serves this with OTP's `inets` (`do/1` in the module). Any HTTP server works. To connect faster, trickle candidates over a WebSocket instead: forward `{ice_candidate, Cand, Mid}` events to the page and pass its candidates to `webrtc:add_ice_candidate/3`.

## Send and receive messages

The channel the browser created arrives as `datachannel_open`; messages as `channel_message`:

```erlang
loop(Pc) ->
    receive
        {webrtc, Pc, {datachannel_open, Id, Label, _Protocol, _Opts}} ->
            ok = webrtc:send_data(Pc, Id, text, <<"hello from Erlang on ", Label/binary>>),
            loop(Pc);
        {webrtc, Pc, {channel_message, Id, text, Text}} ->
            ok = webrtc:send_data(Pc, Id, text, <<"echo: ", Text/binary>>),
            loop(Pc);
        {webrtc, Pc, {channel_message, Id, binary, Bin}} ->
            ok = webrtc:send_data(Pc, Id, binary, Bin),
            loop(Pc);
        {webrtc, Pc, {connection_state, S}} when S =:= closed; S =:= failed ->
            webrtc:close(Pc);
        {webrtc, Pc, _} ->
            loop(Pc)
    end.
```

`text` arrives in the browser as a string. For `binary`, set `channel.binaryType = 'arraybuffer'` to get an `ArrayBuffer` rather than a `Blob`.

## Open a channel from Erlang

Create it before the offer, or at any time once connected. The browser gets it in `ondatachannel`:

```erlang
ok = webrtc:create_data_channel(Pc, <<"events">>, #{}),
```

```js
pc.ondatachannel = (e) => { e.channel.onmessage = (m) => console.log(m.data); };
```

`create_data_channel/3` returns `{ok, Id}` once the connection is up, `ok` before; then the `datachannel_open` event gives the id.

## Choose the reliability

| You send | Options |
|---|---|
| Commands, chat, files: every message, in order | `#{}` (the default) |
| Positions, telemetry: only the latest matters | `#{ordered => false, max_retransmits => 0}` |
| Live data that is useless after a while | `#{ordered => false, max_packet_life_time => 200}` (ms) |
| Several channels on one connection | `#{priority => high}` (`very_low`, `low`, `medium`, `high`) |

## Send large messages

- A message you send may be as large as the browser accepts, the `max-message-size` of its SDP (256 KB for Chromium, 1 GB for Firefox); a larger one returns `{error, message_too_large}`, so split it. What you accept is `max_message_size` on `new_peer_connection/1` (default 256 KB).
- When you send faster than the path allows, messages queue in the node. Wait for `{webrtc, Pc, {buffered_amount_low, Id}}`, sent when everything you queued on the channel has gone, before you send the next batch.

## Close

```erlang
ok = webrtc:close_data_channel(Pc, Id).
```

The browser gets `onclose`, and you get `{datachannel_closed, Id}`. `webrtc:close(Pc)` ends the whole connection.

## Notes

- Across the internet, give both sides a STUN server, and a TURN server for networks that block UDP: `#{ice_servers => [#{urls => [<<"stun:stun.example.com">>]}]}` in Erlang, `new RTCPeerConnection({ iceServers: [...] })` in the page.
- Browsers hide their local addresses behind `<uuid>.local` names unless the page has camera or microphone access. The library resolves these names over multicast DNS, which works when the browser and the node are on the same network.
- Data channels need no HTTPS; `getUserMedia` does, except on `localhost`.
- `webrtc_examples_SUITE` runs this example in headless Chromium and Firefox, so the code here is the code that works.
