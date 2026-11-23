# ADR 0004: The library does no media coding; codec plugins do

## Context

The library is pure Erlang with no runtime dependency beyond OTP (`crypto`, `public_key`), and no NIFs. Encoding and decoding Opus, VP8, VP9, H.264 or AV1 in practice means native libraries (libopus, libvpx, OpenH264, dav1d), and each application picks its own.

Many applications do not need coding at all: an SFU forwards packets, a recorder writes frames, a gateway passes media through.

## Decision

- The library negotiates codecs, packetizes and depacketizes their payload formats, assembles frames and forwards packets. It never encodes or decodes media.
- An application that needs coding plugs in a module with the `webrtc_media_codec` behaviour, usually a separate package with the native code, per transceiver (`codec_plugin`) or per media kind (`codec_plugins`). The plugin decodes the frames received and encodes what `webrtc:send_media/3` gets, and reports the W3C decoder and encoder statistics.
- An application that codes media itself reports those statistics with `webrtc:report_media_stats/4`.

## Consequences

- The library stays free of NIFs and of codec dependencies.
- A plugin's callbacks run in the transport process, so a slow one delays the media of its own connection. A plugin that exports `init/4` avoids this: it runs the codec in its own process and delivers the results later (0.3.0). The lifecycle suite checks that a stuck plugin does not stop the connection from closing.
- A plugin that raises or returns `{error, Reason}` is turned off for its transceiver and reported as `{codec_plugin_error, Mid, Reason}`; `{error, Reason, State}` loses one frame or picture and keeps it on (0.3.0).
- The behaviour is part of the public API, with the `webrtc` module.
- Capturing cameras and microphones is outside the library too; see [the frames and codec plugins guide](../guides/frames-and-codec-plugins.md).
