#!/usr/bin/env python3
"""RFC 6051 ntp-64 header extension through GStreamer's rtphdrextntp64,
for webrtc_sync_gst_SUITE.

send PORT N: N Opus packets to 127.0.0.1:PORT. Each input buffer gets a
timestamp/x-ntp reference meta (the wall clock, ns since 1900) that the
payloader's ntp-64 extension writes; prints "rtp TS NTP" per packet, NTP
the 64-bit value it carries.

recv PORT N: N Opus packets from PORT, depayloaded; prints "ntp NTP" with
the 64-bit value GStreamer read from each one's extension.
"""
import sys
import time

import gi

gi.require_version("Gst", "1.0")
gi.require_version("GstRtp", "1.0")
from gi.repository import GLib, Gst, GstRtp  # noqa: E402

URI = "urn:ietf:params:rtp-hdrext:ntp-64"
NTP_UNIX = 2208988800
Gst.init(None)
NTP_CAPS = Gst.Caps.from_string("timestamp/x-ntp")


def ns_to_ntp(ns):
    return (ns << 32) // Gst.SECOND


def send(port, count):
    p = Gst.parse_launch(
        "appsrc name=src is-live=true format=time "
        "caps=audio/x-opus,channel-mapping-family=0,channels=1,rate=48000 ! "
        f"rtpopuspay name=pay pt=111 ! application/x-rtp,extmap-6=(string){URI} ! "
        f"udpsink host=127.0.0.1 port={port} sync=false async=false")
    src = p.get_by_name("src")

    def show(_pad, info):
        ok, rtp = GstRtp.RTPBuffer.map(info.get_buffer(), Gst.MapFlags.READ)
        if ok:
            ts = rtp.get_timestamp()
            found, data = rtp.get_extension_onebyte_header(6, 0)
            rtp.unmap()
            if found:
                print(f"rtp {ts} {int.from_bytes(bytes(data), 'big')}", flush=True)
        return Gst.PadProbeReturn.OK

    def push(i=[0]):
        if i[0] >= count:
            src.emit("end-of-stream")
            return False
        # 20 ms of CELT silence (RFC 6716), the wall clock as its x-ntp time.
        buf = Gst.Buffer.new_wrapped(b"\xf8\xff\xfe")
        buf.pts = i[0] * 20 * Gst.MSECOND
        buf.duration = 20 * Gst.MSECOND
        buf.add_reference_timestamp_meta(NTP_CAPS, int((time.time() + NTP_UNIX) * Gst.SECOND), Gst.CLOCK_TIME_NONE)
        src.emit("push-buffer", buf)
        i[0] += 1
        return True

    p.get_by_name("pay").get_static_pad("src").add_probe(Gst.PadProbeType.BUFFER, show)
    GLib.timeout_add(20, push)
    run(p)


def recv(port, count):
    caps = (f"application/x-rtp,media=audio,clock-rate=48000,encoding-name=OPUS,payload=111,"
            f"extmap-6=(string){URI}")
    p = Gst.parse_launch(f'udpsrc port={port} caps="{caps}" ! rtpopusdepay name=depay ! fakesink')
    seen = [0]

    def show(_pad, info):
        meta = info.get_buffer().get_reference_timestamp_meta(NTP_CAPS)
        if meta:
            print(f"ntp {ns_to_ntp(meta.timestamp)}", flush=True)
        seen[0] += 1
        if seen[0] >= count:
            GLib.idle_add(lambda: p.send_event(Gst.Event.new_eos()) and False)
        return Gst.PadProbeReturn.OK

    p.get_by_name("depay").get_static_pad("src").add_probe(Gst.PadProbeType.BUFFER, show)
    print("ready", flush=True)
    run(p)


def run(p):
    loop = GLib.MainLoop()
    bus = p.get_bus()
    bus.add_signal_watch()
    bus.connect("message::eos", lambda *_: loop.quit())
    bus.connect("message::error", lambda _b, m: (print("error", m.parse_error()[0].message, flush=True), loop.quit()))
    GLib.timeout_add_seconds(20, loop.quit)
    p.set_state(Gst.State.PLAYING)
    loop.run()
    p.set_state(Gst.State.NULL)


if __name__ == "__main__":
    {"send": send, "recv": recv}[sys.argv[1]](int(sys.argv[2]), int(sys.argv[3]))
