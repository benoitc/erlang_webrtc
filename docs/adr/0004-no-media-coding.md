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
- A plugin runs in the transport process. A slow plugin delays the media of its own connection; a plugin that raises is turned off for its transceiver and reported as `{codec_plugin_error, Mid, Reason}`. The lifecycle suite checks that a stuck plugin does not stop the connection from closing.
- The behaviour is part of the public API, with the `webrtc` module.
- Capturing cameras and microphones is outside the library too; see [the frames and codec plugins guide](../guides/frames-and-codec-plugins.md).
