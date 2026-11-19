"""aiortc peer adapter for the erlang_webrtc interop suite.

Speaks the line-delimited JSON protocol described in ../PROTOCOL.md.

aiortc decodes media, so instead of echoing RTP it sends synthetic
media from its own encoders (Opus silence, VP8 frames) and reports the
frames it decodes from the remote side. The Erlang side echoes the RTP
it receives, which makes aiortc decode packets that went through our
SRTP and RTP stacks twice.
"""

import asyncio
import base64
import json
import sys

import aiortc
from aiortc import (
    RTCDataChannel,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.mediastreams import AudioStreamTrack, VideoStreamTrack
from aiortc.sdp import candidate_from_sdp

pc = None
channels = {}


def emit(**ev):
    sys.stdout.write(json.dumps(ev) + "\n")
    sys.stdout.flush()


def watch_channel(dc: RTCDataChannel):
    channels[dc.label] = dc

    def opened():
        emit(event="channel_open", label=dc.label, id=dc.id,
             protocol=dc.protocol, ordered=dc.ordered)

    if dc.readyState == "open":
        opened()
    else:
        dc.on("open", opened)

    @dc.on("close")
    def on_close():
        emit(event="channel_close", label=dc.label)

    @dc.on("message")
    def on_message(msg):
        if isinstance(msg, str):
            emit(event="message", label=dc.label, data=msg, binary=False)
            dc.send("echo:" + msg)
        else:
            emit(event="message", label=dc.label,
                 data=base64.b64encode(msg).decode(), binary=True)
            dc.send(b"echo" + msg)


async def consume(track):
    count = 0
    while True:
        try:
            await track.recv()
        except Exception:
            return
        count += 1
        if count == 1 or count % 25 == 0:
            emit(event="rtp", kind=track.kind, count=count, bytes=0)


def make_channel(spec):
    kwargs = {}
    if "ordered" in spec and spec["ordered"] is not None:
        kwargs["ordered"] = spec["ordered"]
    if spec.get("max_retransmits") is not None:
        kwargs["maxRetransmits"] = spec["max_retransmits"]
    if spec.get("max_packet_life_time") is not None:
        kwargs["maxPacketLifeTime"] = spec["max_packet_life_time"]
    if spec.get("negotiated"):
        kwargs["negotiated"] = True
        kwargs["id"] = spec["id"]
    if spec.get("protocol"):
        kwargs["protocol"] = spec["protocol"]
    watch_channel(pc.createDataChannel(spec["label"], **kwargs))


async def handle(c):
    global pc
    cmd = c["cmd"]
    if cmd == "init":
        pc = RTCPeerConnection()

        @pc.on("connectionstatechange")
        def on_state():
            emit(event="connection_state", state=pc.connectionState)

        @pc.on("iceconnectionstatechange")
        def on_ice():
            emit(event="ice_state", state=pc.iceConnectionState)

        @pc.on("signalingstatechange")
        def on_sig():
            emit(event="signaling_state", state=pc.signalingState)

        @pc.on("datachannel")
        def on_dc(dc):
            watch_channel(dc)

        @pc.on("track")
        def on_track(track):
            emit(event="track", kind=track.kind, mid="", ssrc=0, codec="")
            asyncio.ensure_future(consume(track))

        for kind in c.get("media", []):
            pc.addTrack(AudioStreamTrack() if kind == "audio" else VideoStreamTrack())
        for spec in c.get("channels", []):
            make_channel(spec)
    elif cmd == "create_offer":
        await pc.setLocalDescription(await pc.createOffer())
        emit(event="local_description", type="offer", sdp=pc.localDescription.sdp)
        # aiortc does not trickle: candidates are in the SDP.
        emit(event="local_candidate", candidate="", mid="0")
    elif cmd == "remote_description":
        await pc.setRemoteDescription(RTCSessionDescription(sdp=c["sdp"], type=c["type"]))
        if c["type"] == "offer":
            await pc.setLocalDescription(await pc.createAnswer())
            emit(event="local_description", type="answer", sdp=pc.localDescription.sdp)
            emit(event="local_candidate", candidate="", mid="0")
    elif cmd == "remote_candidate":
        cand = c.get("candidate", "")
        if cand:
            if cand.startswith("candidate:"):
                cand = cand[len("candidate:"):]
            ice = candidate_from_sdp(cand)
            ice.sdpMid = c.get("mid")
            await pc.addIceCandidate(ice)
        else:
            await pc.addIceCandidate(None)
    elif cmd == "send":
        dc = channels[c["label"]]
        dc.send(base64.b64decode(c["data"]) if c.get("binary") else c["data"])
    elif cmd == "create_channel":
        make_channel(c)
    elif cmd == "close_channel":
        channels[c["label"]].close()
    elif cmd == "stats":
        stats = await pc.getStats()
        emit(event="stats", stats={k: str(v) for k, v in stats.items()})
    elif cmd == "close":
        await pc.close()
        return False
    else:
        raise ValueError("unknown command " + cmd)
    return True


async def main():
    emit(event="ready", implementation="aiortc", version=aiortc.__version__)
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=1 << 24)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            if not await handle(json.loads(line)):
                break
        except Exception as e:  # report and keep serving
            import traceback
            traceback.print_exc(file=sys.stderr)
            emit(event="error", message=f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
