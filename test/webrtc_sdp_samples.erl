%% @doc Realistic session descriptions used by the SDP tests. They follow
%% what current browsers and servers emit, with CRLF line endings.
-module(webrtc_sdp_samples).

-export([
    all/0,
    chrome_offer/0,
    chrome_answer/0,
    firefox_offer/0,
    firefox_legacy_datachannel/0,
    safari_offer/0,
    pion_answer/0,
    ice_lite_answer/0,
    trickle_candidates/0,
    simulcast_paused/0,
    rfc8866_example/0,
    fp_sha256/0
]).

-spec all() -> [{atom(), binary()}].
all() ->
    [
        {chrome_offer, chrome_offer()},
        {chrome_answer, chrome_answer()},
        {firefox_offer, firefox_offer()},
        {firefox_legacy_datachannel, firefox_legacy_datachannel()},
        {safari_offer, safari_offer()},
        {pion_answer, pion_answer()},
        {ice_lite_answer, ice_lite_answer()},
        {trickle_candidates, trickle_candidates()},
        {simulcast_paused, simulcast_paused()},
        {rfc8866_example, rfc8866_example()}
    ].

sdp(Lines) -> iolist_to_binary([[L, "\r\n"] || L <- Lines]).

-spec fp_sha256() -> binary().
fp_sha256() ->
    <<"D2:FA:0E:C3:22:59:5E:14:95:69:92:3D:13:B4:84:24:2C:C2:A2:C0:3E:FD:34:8E:5E:EA:6F:AF:52:CE:E6:0F">>.

fp_answer() ->
    <<"7B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08">>.

fp_sha512() ->
    <<
        "2C:7D:23:4F:3B:9E:1A:D0:C4:68:E7:1F:B2:09:3A:56:7E:91:CC:0D:F4:A8:13:6B:"
        "E2:47:5D:90:3C:B1:8A:2F:6E:D3:05:99:47:BC:12:E0:7A:3F:C8:61:9D:24:B5:0E:"
        "83:F1:6C:2A:D7:58:39:E4:A0:1B:C6:72:FD:09:4E:B3"
    >>.

-spec chrome_offer() -> binary().
chrome_offer() ->
    Stream = <<"5b4ef5e8-1a0b-4c2f-9c3d-6e7f8a9b0c1d">>,
    Audio = <<"a7c3e1f0-2b4d-4e6f-8a9b-0c1d2e3f4a5b">>,
    Video = <<"c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f">>,
    Ice = [
        <<"a=ice-ufrag:EsAw">>,
        <<"a=ice-pwd:P2uYro0UCOQ4zxjKXaWCBui1">>,
        <<"a=ice-options:trickle">>,
        <<"a=fingerprint:sha-256 ", (fp_sha256())/binary>>,
        <<"a=setup:actpass">>
    ],
    Fb = fun(Pt) ->
        [
            <<"a=rtcp-fb:", Pt/binary, " goog-remb">>,
            <<"a=rtcp-fb:", Pt/binary, " transport-cc">>,
            <<"a=rtcp-fb:", Pt/binary, " ccm fir">>,
            <<"a=rtcp-fb:", Pt/binary, " nack">>,
            <<"a=rtcp-fb:", Pt/binary, " nack pli">>
        ]
    end,
    sdp(
        [
            <<"v=0">>,
            <<"o=- 4215775240449105457 2 IN IP4 127.0.0.1">>,
            <<"s=-">>,
            <<"t=0 0">>,
            <<"a=group:BUNDLE 0 1 2">>,
            <<"a=extmap-allow-mixed">>,
            <<"a=msid-semantic: WMS ", Stream/binary>>,
            <<"m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126">>,
            <<"c=IN IP4 0.0.0.0">>,
            <<"a=rtcp:9 IN IP4 0.0.0.0">>
        ] ++ Ice ++
            [
                <<"a=mid:0">>,
                <<"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level">>,
                <<"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>,
                <<"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>,
                <<"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid">>,
                <<"a=sendrecv">>,
                <<"a=msid:", Stream/binary, " ", Audio/binary>>,
                <<"a=rtcp-mux">>,
                <<"a=rtcp-rsize">>,
                <<"a=rtpmap:111 opus/48000/2">>,
                <<"a=rtcp-fb:111 transport-cc">>,
                <<"a=fmtp:111 minptime=10;useinbandfec=1">>,
                <<"a=rtpmap:63 red/48000/2">>,
                <<"a=fmtp:63 111/111">>,
                <<"a=rtpmap:9 G722/8000">>,
                <<"a=rtpmap:0 PCMU/8000">>,
                <<"a=rtpmap:8 PCMA/8000">>,
                <<"a=rtpmap:13 CN/8000">>,
                <<"a=rtpmap:110 telephone-event/48000">>,
                <<"a=rtpmap:126 telephone-event/8000">>,
                <<"a=ssrc:3570614608 cname:4TOk42mSjXCkVIa6">>,
                <<"a=ssrc:3570614608 msid:", Stream/binary, " ", Audio/binary>>,
                <<"m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99 100 101 45 46 102 103 104">>,
                <<"c=IN IP4 0.0.0.0">>,
                <<"a=rtcp:9 IN IP4 0.0.0.0">>
            ] ++ Ice ++
            [
                <<"a=mid:1">>,
                <<"a=extmap:14 urn:ietf:params:rtp-hdrext:toffset">>,
                <<"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>,
                <<"a=extmap:13 urn:3gpp:video-orientation">>,
                <<"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>,
                <<"a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay">>,
                <<"a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type">>,
                <<"a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing">>,
                <<"a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space">>,
                <<"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid">>,
                <<"a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>,
                <<"a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>,
                <<"a=sendrecv">>,
                <<"a=msid:", Stream/binary, " ", Video/binary>>,
                <<"a=rtcp-mux">>,
                <<"a=rtcp-rsize">>,
                <<"a=rtpmap:96 VP8/90000">>
            ] ++ Fb(<<"96">>) ++
            [
                <<"a=rtpmap:97 rtx/90000">>,
                <<"a=fmtp:97 apt=96">>,
                <<"a=rtpmap:98 VP9/90000">>
            ] ++ Fb(<<"98">>) ++
            [
                <<"a=fmtp:98 profile-id=0">>,
                <<"a=rtpmap:99 rtx/90000">>,
                <<"a=fmtp:99 apt=98">>,
                <<"a=rtpmap:100 H264/90000">>
            ] ++ Fb(<<"100">>) ++
            [
                <<"a=fmtp:100 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f">>,
                <<"a=rtpmap:101 rtx/90000">>,
                <<"a=fmtp:101 apt=100">>,
                <<"a=rtpmap:45 AV1/90000">>
            ] ++ Fb(<<"45">>) ++
            [
                <<"a=fmtp:45 level-idx=5;profile=0;tier=0">>,
                <<"a=rtpmap:46 rtx/90000">>,
                <<"a=fmtp:46 apt=45">>,
                <<"a=rtpmap:102 red/90000">>,
                <<"a=rtpmap:103 rtx/90000">>,
                <<"a=fmtp:103 apt=102">>,
                <<"a=rtpmap:104 ulpfec/90000">>,
                <<"a=ssrc-group:FID 1105218712 2851338383">>,
                <<"a=ssrc:1105218712 cname:4TOk42mSjXCkVIa6">>,
                <<"a=ssrc:1105218712 msid:", Stream/binary, " ", Video/binary>>,
                <<"a=ssrc:2851338383 cname:4TOk42mSjXCkVIa6">>,
                <<"a=ssrc:2851338383 msid:", Stream/binary, " ", Video/binary>>,
                <<"m=application 9 UDP/DTLS/SCTP webrtc-datachannel">>,
                <<"c=IN IP4 0.0.0.0">>
            ] ++ Ice ++
            [
                <<"a=mid:2">>,
                <<"a=sctp-port:5000">>,
                <<"a=max-message-size:262144">>
            ]
    ).

-spec chrome_answer() -> binary().
chrome_answer() ->
    Ice = [
        <<"a=ice-ufrag:Vw2c">>,
        <<"a=ice-pwd:0cz9VY5J8h3kq5h2T6LZxQ4m">>,
        <<"a=ice-options:trickle">>,
        <<"a=fingerprint:sha-256 ", (fp_answer())/binary>>,
        <<"a=setup:active">>
    ],
    sdp(
        [
            <<"v=0">>,
            <<"o=- 7931862353451283604 2 IN IP4 127.0.0.1">>,
            <<"s=-">>,
            <<"t=0 0">>,
            <<"a=group:BUNDLE 0 1 2">>,
            <<"a=extmap-allow-mixed">>,
            <<"a=msid-semantic: WMS">>,
            <<"m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126">>,
            <<"c=IN IP4 0.0.0.0">>,
            <<"a=rtcp:9 IN IP4 0.0.0.0">>
        ] ++ Ice ++
            [
                <<"a=mid:0">>,
                <<"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level">>,
                <<"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>,
                <<"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>,
                <<"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid">>,
                <<"a=recvonly">>,
                <<"a=rtcp-mux">>,
                <<"a=rtpmap:111 opus/48000/2">>,
                <<"a=rtcp-fb:111 transport-cc">>,
                <<"a=fmtp:111 minptime=10;useinbandfec=1">>,
                <<"a=rtpmap:63 red/48000/2">>,
                <<"a=fmtp:63 111/111">>,
                <<"a=rtpmap:9 G722/8000">>,
                <<"a=rtpmap:0 PCMU/8000">>,
                <<"a=rtpmap:8 PCMA/8000">>,
                <<"a=rtpmap:13 CN/8000">>,
                <<"a=rtpmap:110 telephone-event/48000">>,
                <<"a=rtpmap:126 telephone-event/8000">>,
                <<"m=video 9 UDP/TLS/RTP/SAVPF 96 97 45 46">>,
                <<"c=IN IP4 0.0.0.0">>,
                <<"a=rtcp:9 IN IP4 0.0.0.0">>
            ] ++ Ice ++
            [
                <<"a=mid:1">>,
                <<"a=extmap:14 urn:ietf:params:rtp-hdrext:toffset">>,
                <<"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>,
                <<"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid">>,
                <<"a=recvonly">>,
                <<"a=rtcp-mux">>,
                <<"a=rtcp-rsize">>,
                <<"a=rtpmap:96 VP8/90000">>,
                <<"a=rtcp-fb:96 transport-cc">>,
                <<"a=rtcp-fb:96 ccm fir">>,
                <<"a=rtcp-fb:96 nack">>,
                <<"a=rtcp-fb:96 nack pli">>,
                <<"a=rtpmap:97 rtx/90000">>,
                <<"a=fmtp:97 apt=96">>,
                <<"a=rtpmap:45 AV1/90000">>,
                <<"a=rtcp-fb:45 transport-cc">>,
                <<"a=rtcp-fb:45 nack pli">>,
                <<"a=fmtp:45 level-idx=5;profile=0;tier=0">>,
                <<"a=rtpmap:46 rtx/90000">>,
                <<"a=fmtp:46 apt=45">>,
                <<"m=application 9 UDP/DTLS/SCTP webrtc-datachannel">>,
                <<"c=IN IP4 0.0.0.0">>
            ] ++ Ice ++
            [
                <<"a=mid:2">>,
                <<"a=sctp-port:5000">>,
                <<"a=max-message-size:262144">>
            ]
    ).

-spec firefox_offer() -> binary().
firefox_offer() ->
    Ice = [
        <<"a=ice-pwd:6a0b5e9d2c8f4a1b7e3d9c0f5a2b8e4d">>,
        <<"a=ice-ufrag:3f1c7a9e">>
    ],
    Stream = <<"{f2b9d6e1-0c3a-4b5d-8e7f-1a2b3c4d5e6f}">>,
    sdp(
        [
            <<"v=0">>,
            <<"o=mozilla...THIS_IS_SDPARTA-121.0 6191785185155588015 0 IN IP4 0.0.0.0">>,
            <<"s=-">>,
            <<"t=0 0">>,
            <<"a=fingerprint:sha-256 ", (fp_sha256())/binary>>,
            <<"a=group:BUNDLE 0 1 2">>,
            <<"a=ice-options:trickle">>,
            <<"a=msid-semantic:WMS *">>,
            <<"m=audio 9 UDP/TLS/RTP/SAVPF 109 9 0 8 101">>,
            <<"c=IN IP4 0.0.0.0">>,
            <<"a=sendrecv">>,
            <<"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level">>,
            <<"a=extmap:2/recvonly urn:ietf:params:rtp-hdrext:csrc-audio-level">>,
            <<"a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid">>,
            <<"a=fmtp:109 maxplaybackrate=48000;stereo=1;useinbandfec=1">>,
            <<"a=fmtp:101 0-15">>
        ] ++ Ice ++
            [
                <<"a=mid:0">>,
                <<"a=msid:", Stream/binary, " {5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a}">>,
                <<"a=rtcp-mux">>,
                <<"a=rtpmap:109 opus/48000/2">>,
                <<"a=rtpmap:9 G722/8000/1">>,
                <<"a=rtpmap:0 PCMU/8000">>,
                <<"a=rtpmap:8 PCMA/8000">>,
                <<"a=rtpmap:101 telephone-event/8000/1">>,
                <<"a=setup:actpass">>,
                <<"a=ssrc:2655508255 cname:{6c1f1d4a-2e8b-4f3c-9d0e-7a6b5c4d3e2f}">>,
                <<"m=video 9 UDP/TLS/RTP/SAVPF 120 124 121 125 126 127 97 98 123 122 119">>,
                <<"c=IN IP4 0.0.0.0">>,
                <<"a=sendrecv">>,
                <<"a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid">>,
                <<"a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>,
                <<"a=extmap:5 urn:ietf:params:rtp-hdrext:toffset">>,
                <<"a=extmap:6/recvonly http://www.webrtc.org/experiments/rtp-hdrext/playout-delay">>,
                <<"a=extmap:7 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>,
                <<"a=extmap:8 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>,
                <<"a=extmap:9 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>,
                <<"a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1">>,
                <<"a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1">>,
                <<"a=fmtp:120 max-fs=12288;max-fr=60">>,
                <<"a=fmtp:124 apt=120">>,
                <<"a=fmtp:121 max-fs=12288;max-fr=60">>,
                <<"a=fmtp:125 apt=121">>,
                <<"a=fmtp:127 apt=126">>,
                <<"a=fmtp:98 apt=97">>,
                <<"a=fmtp:119 apt=122">>
            ] ++ Ice ++
            [
                <<"a=mid:1">>,
                <<"a=msid:", Stream/binary, " {9e8d7c6b-5a4f-4e3d-2c1b-0a9f8e7d6c5b}">>,
                <<"a=rid:h send">>,
                <<"a=rid:m send">>,
                <<"a=rid:l send">>,
                <<"a=rtcp-fb:120 nack">>,
                <<"a=rtcp-fb:120 nack pli">>,
                <<"a=rtcp-fb:120 ccm fir">>,
                <<"a=rtcp-fb:120 goog-remb">>,
                <<"a=rtcp-fb:120 transport-cc">>,
                <<"a=rtcp-fb:121 nack">>,
                <<"a=rtcp-fb:121 nack pli">>,
                <<"a=rtcp-fb:121 ccm fir">>,
                <<"a=rtcp-fb:121 goog-remb">>,
                <<"a=rtcp-fb:121 transport-cc">>,
                <<"a=rtcp-fb:126 nack">>,
                <<"a=rtcp-fb:126 nack pli">>,
                <<"a=rtcp-fb:126 ccm fir">>,
                <<"a=rtcp-fb:126 goog-remb">>,
                <<"a=rtcp-fb:126 transport-cc">>,
                <<"a=rtcp-fb:97 nack">>,
                <<"a=rtcp-fb:97 nack pli">>,
                <<"a=rtcp-fb:97 ccm fir">>,
                <<"a=rtcp-fb:97 goog-remb">>,
                <<"a=rtcp-fb:97 transport-cc">>,
                <<"a=rtcp-fb:123 nack">>,
                <<"a=rtcp-fb:123 nack pli">>,
                <<"a=rtcp-fb:123 ccm fir">>,
                <<"a=rtcp-fb:123 goog-remb">>,
                <<"a=rtcp-fb:123 transport-cc">>,
                <<"a=rtcp-fb:122 nack">>,
                <<"a=rtcp-fb:122 nack pli">>,
                <<"a=rtcp-fb:122 ccm fir">>,
                <<"a=rtcp-fb:122 goog-remb">>,
                <<"a=rtcp-fb:122 transport-cc">>,
                <<"a=rtcp-mux">>,
                <<"a=rtcp-rsize">>,
                <<"a=rtpmap:120 VP8/90000">>,
                <<"a=rtpmap:124 rtx/90000">>,
                <<"a=rtpmap:121 VP9/90000">>,
                <<"a=rtpmap:125 rtx/90000">>,
                <<"a=rtpmap:126 H264/90000">>,
                <<"a=rtpmap:127 rtx/90000">>,
                <<"a=rtpmap:97 H264/90000">>,
                <<"a=rtpmap:98 rtx/90000">>,
                <<"a=rtpmap:123 ulpfec/90000">>,
                <<"a=rtpmap:122 red/90000">>,
                <<"a=rtpmap:119 rtx/90000">>,
                <<"a=setup:actpass">>,
                <<"a=simulcast:send h;m;l">>,
                <<"a=ssrc:3011228617 cname:{6c1f1d4a-2e8b-4f3c-9d0e-7a6b5c4d3e2f}">>,
                <<"a=ssrc:1543270375 cname:{6c1f1d4a-2e8b-4f3c-9d0e-7a6b5c4d3e2f}">>,
                <<"a=ssrc:2208961234 cname:{6c1f1d4a-2e8b-4f3c-9d0e-7a6b5c4d3e2f}">>,
                <<"a=ssrc:4116312009 cname:{6c1f1d4a-2e8b-4f3c-9d0e-7a6b5c4d3e2f}">>,
                <<"a=ssrc:1029873456 cname:{6c1f1d4a-2e8b-4f3c-9d0e-7a6b5c4d3e2f}">>,
                <<"a=ssrc:3398112207 cname:{6c1f1d4a-2e8b-4f3c-9d0e-7a6b5c4d3e2f}">>,
                <<"a=ssrc-group:FID 3011228617 1543270375">>,
                <<"a=ssrc-group:FID 2208961234 4116312009">>,
                <<"a=ssrc-group:FID 1029873456 3398112207">>,
                <<"m=application 9 UDP/DTLS/SCTP webrtc-datachannel">>,
                <<"c=IN IP4 0.0.0.0">>,
                <<"a=sendrecv">>
            ] ++ Ice ++
            [
                <<"a=mid:2">>,
                <<"a=setup:actpass">>,
                <<"a=sctp-port:5000">>,
                <<"a=max-message-size:1073741823">>
            ]
    ).

%% Firefox before version 63 negotiated data channels with the
%% draft-ietf-mmusic-sctp-sdp-05 syntax.
-spec firefox_legacy_datachannel() -> binary().
firefox_legacy_datachannel() ->
    sdp([
        <<"v=0">>,
        <<"o=mozilla...THIS_IS_SDPARTA-52.0 2813547637436516034 0 IN IP4 0.0.0.0">>,
        <<"s=-">>,
        <<"t=0 0">>,
        <<"a=sendrecv">>,
        <<"a=fingerprint:sha-256 ", (fp_sha256())/binary>>,
        <<"a=group:BUNDLE sdparta_0">>,
        <<"a=ice-options:trickle">>,
        <<"a=msid-semantic:WMS *">>,
        <<"m=application 9 DTLS/SCTP 5000">>,
        <<"c=IN IP4 0.0.0.0">>,
        <<"a=sendrecv">>,
        <<"a=ice-pwd:9f8e7d6c5b4a39281706f5e4d3c2b1a0">>,
        <<"a=ice-ufrag:a1b2c3d4">>,
        <<"a=mid:sdparta_0">>,
        <<"a=sctpmap:5000 webrtc-datachannel 256">>,
        <<"a=setup:actpass">>,
        <<"a=max-message-size:1073741823">>
    ]).

-spec safari_offer() -> binary().
safari_offer() ->
    Stream = <<"C7E5A0F2-3B1D-4E9C-8F6A-2D0B4C8E1A37">>,
    Ice = [
        <<"a=ice-ufrag:Kq3V">>,
        <<"a=ice-pwd:q6Yd9Lh2mWc8zR4tN1bF0sXe">>,
        <<"a=ice-options:trickle">>,
        <<"a=fingerprint:sha-256 ", (fp_sha256())/binary>>,
        <<"a=setup:actpass">>
    ],
    sdp(
        [
            <<"v=0">>,
            <<"o=- 1937452168834207114 2 IN IP4 127.0.0.1">>,
            <<"s=-">>,
            <<"t=0 0">>,
            <<"a=group:BUNDLE 0 1">>,
            <<"a=extmap-allow-mixed">>,
            <<"a=msid-semantic: WMS ", Stream/binary>>,
            <<"m=audio 9 UDP/TLS/RTP/SAVPF 111 63 103 9 102 0 8 105 13 110 113 126">>,
            <<"c=IN IP4 0.0.0.0">>,
            <<"a=rtcp:9 IN IP4 0.0.0.0">>
        ] ++ Ice ++
            [
                <<"a=mid:0">>,
                <<"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level">>,
                <<"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>,
                <<"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>,
                <<"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid">>,
                <<"a=sendrecv">>,
                <<"a=msid:", Stream/binary, " 0F6E9B2A-4C3D-4A1B-9E8F-7D6C5B4A3F2E">>,
                <<"a=rtcp-mux">>,
                <<"a=rtpmap:111 opus/48000/2">>,
                <<"a=rtcp-fb:111 transport-cc">>,
                <<"a=fmtp:111 minptime=10;useinbandfec=1">>,
                <<"a=rtpmap:63 red/48000/2">>,
                <<"a=fmtp:63 111/111">>,
                <<"a=rtpmap:103 ISAC/16000">>,
                <<"a=rtpmap:9 G722/8000">>,
                <<"a=rtpmap:102 ILBC/8000">>,
                <<"a=rtpmap:0 PCMU/8000">>,
                <<"a=rtpmap:8 PCMA/8000">>,
                <<"a=rtpmap:105 CN/16000">>,
                <<"a=rtpmap:13 CN/8000">>,
                <<"a=rtpmap:110 telephone-event/48000">>,
                <<"a=rtpmap:113 telephone-event/16000">>,
                <<"a=rtpmap:126 telephone-event/8000">>,
                <<"a=ssrc:1428792105 cname:Yd2qk1k0C9zQ7f3D">>,
                <<"a=ssrc:1428792105 msid:", Stream/binary, " 0F6E9B2A-4C3D-4A1B-9E8F-7D6C5B4A3F2E">>,
                <<"m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99 100 101 127 125 104">>,
                <<"c=IN IP4 0.0.0.0">>,
                <<"a=rtcp:9 IN IP4 0.0.0.0">>
            ] ++ Ice ++
            [
                <<"a=mid:1">>,
                <<"a=extmap:14 urn:ietf:params:rtp-hdrext:toffset">>,
                <<"a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>,
                <<"a=extmap:13 urn:3gpp:video-orientation">>,
                <<"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>,
                <<"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid">>,
                <<"a=sendrecv">>,
                <<"a=msid:", Stream/binary, " 6A5B4C3D-2E1F-4A0B-9C8D-7E6F5A4B3C2D">>,
                <<"a=rtcp-mux">>,
                <<"a=rtcp-rsize">>,
                <<"a=rtpmap:96 H264/90000">>,
                <<"a=rtcp-fb:96 goog-remb">>,
                <<"a=rtcp-fb:96 transport-cc">>,
                <<"a=rtcp-fb:96 ccm fir">>,
                <<"a=rtcp-fb:96 nack">>,
                <<"a=rtcp-fb:96 nack pli">>,
                <<"a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f">>,
                <<"a=rtpmap:97 rtx/90000">>,
                <<"a=fmtp:97 apt=96">>,
                <<"a=rtpmap:98 H264/90000">>,
                <<"a=rtcp-fb:98 goog-remb">>,
                <<"a=rtcp-fb:98 transport-cc">>,
                <<"a=rtcp-fb:98 ccm fir">>,
                <<"a=rtcp-fb:98 nack">>,
                <<"a=rtcp-fb:98 nack pli">>,
                <<"a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f">>,
                <<"a=rtpmap:99 rtx/90000">>,
                <<"a=fmtp:99 apt=98">>,
                <<"a=rtpmap:100 H265/90000">>,
                <<"a=rtcp-fb:100 goog-remb">>,
                <<"a=rtcp-fb:100 transport-cc">>,
                <<"a=rtcp-fb:100 ccm fir">>,
                <<"a=rtcp-fb:100 nack">>,
                <<"a=rtcp-fb:100 nack pli">>,
                <<"a=rtpmap:101 rtx/90000">>,
                <<"a=fmtp:101 apt=100">>,
                <<"a=rtpmap:127 VP8/90000">>,
                <<"a=rtcp-fb:127 goog-remb">>,
                <<"a=rtcp-fb:127 transport-cc">>,
                <<"a=rtcp-fb:127 ccm fir">>,
                <<"a=rtcp-fb:127 nack">>,
                <<"a=rtcp-fb:127 nack pli">>,
                <<"a=rtpmap:125 rtx/90000">>,
                <<"a=fmtp:125 apt=127">>,
                <<"a=rtpmap:104 red/90000">>,
                <<"a=ssrc-group:FID 2393155063 3916215813">>,
                <<"a=ssrc:2393155063 cname:Yd2qk1k0C9zQ7f3D">>,
                <<"a=ssrc:2393155063 msid:", Stream/binary, " 6A5B4C3D-2E1F-4A0B-9C8D-7E6F5A4B3C2D">>,
                <<"a=ssrc:3916215813 cname:Yd2qk1k0C9zQ7f3D">>,
                <<"a=ssrc:3916215813 msid:", Stream/binary, " 6A5B4C3D-2E1F-4A0B-9C8D-7E6F5A4B3C2D">>
            ]
    ).

%% pion/webrtc v4 answer: session-level fingerprint, legacy ssrc
%% mslabel/label lines and inline candidates.
-spec pion_answer() -> binary().
pion_answer() ->
    sdp([
        <<"v=0">>,
        <<"o=- 6845128346843719221 1731600000 IN IP4 0.0.0.0">>,
        <<"s=-">>,
        <<"t=0 0">>,
        <<"a=msid-semantic:WMS *">>,
        <<"a=fingerprint:sha-256 ", (fp_answer())/binary>>,
        <<"a=extmap-allow-mixed">>,
        <<"a=group:BUNDLE 0 1">>,
        <<"m=audio 9 UDP/TLS/RTP/SAVPF 111">>,
        <<"c=IN IP4 0.0.0.0">>,
        <<"a=setup:active">>,
        <<"a=mid:0">>,
        <<"a=ice-ufrag:pQfRrAQjSHoyXvIW">>,
        <<"a=ice-pwd:RmCwUdPBKXHngXXzqHmgSKwBTmBVzqJh">>,
        <<"a=rtcp-mux">>,
        <<"a=rtcp-rsize">>,
        <<"a=rtpmap:111 opus/48000/2">>,
        <<"a=fmtp:111 minptime=10;useinbandfec=1">>,
        <<"a=rtcp-fb:111 transport-cc">>,
        <<"a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid">>,
        <<"a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>,
        <<"a=ssrc:2849239671 cname:pion-audio">>,
        <<"a=ssrc:2849239671 msid:pion-stream audio-track">>,
        <<"a=ssrc:2849239671 mslabel:pion-stream">>,
        <<"a=ssrc:2849239671 label:audio-track">>,
        <<"a=msid:pion-stream audio-track">>,
        <<"a=sendrecv">>,
        <<"a=candidate:2930149473 1 udp 2130706431 192.168.1.10 51234 typ host">>,
        <<"a=candidate:2930149473 2 udp 2130706431 192.168.1.10 51234 typ host">>,
        <<"a=candidate:233762139 1 udp 2130706431 172.17.0.1 51235 typ host">>,
        <<"a=candidate:1052832478 1 udp 1694498815 198.51.100.20 51234 typ srflx raddr 0.0.0.0 rport 51234">>,
        <<"a=end-of-candidates">>,
        <<"m=application 9 UDP/DTLS/SCTP webrtc-datachannel">>,
        <<"c=IN IP4 0.0.0.0">>,
        <<"a=setup:active">>,
        <<"a=mid:1">>,
        <<"a=sendrecv">>,
        <<"a=sctp-port:5000">>,
        <<"a=ice-ufrag:pQfRrAQjSHoyXvIW">>,
        <<"a=ice-pwd:RmCwUdPBKXHngXXzqHmgSKwBTmBVzqJh">>
    ]).

%% Answer from an ICE-lite SFU with a public address, UDP and passive TCP
%% candidates and a SHA-512 fingerprint.
-spec ice_lite_answer() -> binary().
ice_lite_answer() ->
    sdp([
        <<"v=0">>,
        <<"o=sfu 10000 1 IN IP4 203.0.113.10">>,
        <<"s=-">>,
        <<"t=0 0">>,
        <<"a=ice-lite">>,
        <<"a=fingerprint:sha-512 ", (fp_sha512())/binary>>,
        <<"a=msid-semantic: WMS *">>,
        <<"a=group:BUNDLE 0 1">>,
        <<"m=audio 7000 UDP/TLS/RTP/SAVPF 100">>,
        <<"c=IN IP4 203.0.113.10">>,
        <<"a=rtpmap:100 opus/48000/2">>,
        <<"a=fmtp:100 minptime=10;stereo=1;usedtx=1;useinbandfec=1">>,
        <<"a=rtcp-fb:100 transport-cc">>,
        <<"a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid">>,
        <<"a=extmap:10 urn:ietf:params:rtp-hdrext:ssrc-audio-level vad=on">>,
        <<"a=setup:passive">>,
        <<"a=mid:0">>,
        <<"a=recvonly">>,
        <<"a=ice-ufrag:sfu8kzp1n0q3w7ty">>,
        <<"a=ice-pwd:x3c9v2b7n5m1q8w4e6r0t2y9u7i5o3p1">>,
        <<"a=candidate:udpcandidate 1 udp 1076302079 203.0.113.10 7000 typ host">>,
        <<"a=candidate:tcpcandidate 1 tcp 1076276479 203.0.113.10 7000 typ host tcptype passive">>,
        <<"a=end-of-candidates">>,
        <<"a=ice-options:renomination">>,
        <<"a=rtcp-mux">>,
        <<"a=rtcp-rsize">>,
        <<"m=video 7000 UDP/TLS/RTP/SAVPF 101 102">>,
        <<"c=IN IP4 203.0.113.10">>,
        <<"b=AS:2500">>,
        <<"b=TIAS:2500000">>,
        <<"a=rtpmap:101 VP8/90000">>,
        <<"a=rtcp-fb:101 transport-cc">>,
        <<"a=rtcp-fb:101 ccm fir">>,
        <<"a=rtcp-fb:101 nack">>,
        <<"a=rtcp-fb:101 nack pli">>,
        <<"a=rtpmap:102 rtx/90000">>,
        <<"a=fmtp:102 apt=101">>,
        <<"a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid">>,
        <<"a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>,
        <<"a=setup:passive">>,
        <<"a=mid:1">>,
        <<"a=sendonly">>,
        <<"a=ice-ufrag:sfu8kzp1n0q3w7ty">>,
        <<"a=ice-pwd:x3c9v2b7n5m1q8w4e6r0t2y9u7i5o3p1">>,
        <<"a=candidate:udpcandidate 1 udp 1076302079 203.0.113.10 7000 typ host">>,
        <<"a=candidate:tcpcandidate 1 tcp 1076276479 203.0.113.10 7000 typ host tcptype passive">>,
        <<"a=end-of-candidates">>,
        <<"a=msid:sfu-stream-1 sfu-video-1">>,
        <<"a=ssrc-group:FID 11111111 22222222">>,
        <<"a=ssrc:11111111 cname:sfu">>,
        <<"a=ssrc:22222222 cname:sfu">>,
        <<"a=rtcp-mux">>,
        <<"a=rtcp-rsize">>
    ]).

%% An offer after trickle ICE completed: IPv4, IPv6, mDNS host names,
%% srflx with mDNS-hidden related address, TCP and relay candidates.
-spec trickle_candidates() -> binary().
trickle_candidates() ->
    sdp([
        <<"v=0">>,
        <<"o=- 3496071820117458001 3 IN IP4 127.0.0.1">>,
        <<"s=-">>,
        <<"t=0 0">>,
        <<"a=group:BUNDLE 0">>,
        <<"a=ice-options:trickle ice2">>,
        <<"a=msid-semantic: WMS">>,
        <<"m=application 54400 UDP/DTLS/SCTP webrtc-datachannel">>,
        <<"c=IN IP4 198.51.100.7">>,
        <<"a=candidate:1467250027 1 udp 2122260223 192.168.0.196 54400 typ host generation 0 network-id 1 network-cost 10">>,
        <<"a=candidate:2986571240 1 udp 2122197247 2001:db8:85a3::8a2e:370:7334 56143 typ host generation 0 network-id 2 network-cost 10">>,
        <<"a=candidate:1052832478 1 udp 2122262783 fe80::1c2b:3a4d:5e6f:7081 56144 typ host generation 0 network-id 3">>,
        <<"a=candidate:3828580934 1 udp 2113937151 4c1e3a8f-6b2d-4e57-9c0a-1d2e3f4a5b6c.local 54401 typ host generation 0 ufrag EsAw network-cost 999">>,
        <<"a=candidate:842163049 1 udp 1677729535 198.51.100.7 54400 typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag EsAw network-id 1 network-cost 10">>,
        <<"a=candidate:4171542561 1 tcp 1518280447 192.168.0.196 9 typ host tcptype active generation 0 network-id 1">>,
        <<"a=candidate:2442287811 1 udp 41885439 203.0.113.5 61002 typ relay raddr 198.51.100.7 rport 54400 generation 0 network-id 1 network-cost 10">>,
        <<"a=end-of-candidates">>,
        <<"a=ice-ufrag:EsAw">>,
        <<"a=ice-pwd:P2uYro0UCOQ4zxjKXaWCBui1">>,
        <<"a=ice-options:trickle renomination">>,
        <<"a=fingerprint:sha-256 ", (fp_sha256())/binary>>,
        <<"a=setup:actpass">>,
        <<"a=mid:0">>,
        <<"a=sctp-port:5000">>,
        <<"a=max-message-size:262144">>
    ]).

%% Simulcast send with RID restrictions, an alternative format and paused
%% layers, plus a receive stream.
-spec simulcast_paused() -> binary().
simulcast_paused() ->
    sdp([
        <<"v=0">>,
        <<"o=- 8320471929421342510 2 IN IP4 127.0.0.1">>,
        <<"s=-">>,
        <<"t=0 0">>,
        <<"a=group:BUNDLE 0">>,
        <<"a=extmap-allow-mixed">>,
        <<"a=msid-semantic: WMS s1">>,
        <<"m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99">>,
        <<"c=IN IP4 0.0.0.0">>,
        <<"a=rtcp:9 IN IP4 0.0.0.0">>,
        <<"a=ice-ufrag:Hq7d">>,
        <<"a=ice-pwd:t4Kc1wB9xV2nM6zP8sLq3rYe">>,
        <<"a=ice-options:trickle">>,
        <<"a=fingerprint:sha-256 ", (fp_sha256())/binary>>,
        <<"a=setup:actpass">>,
        <<"a=mid:0">>,
        <<"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid">>,
        <<"a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>,
        <<"a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>,
        <<"a=sendrecv">>,
        <<"a=msid:s1 t1">>,
        <<"a=rtcp-mux">>,
        <<"a=rtcp-mux-only">>,
        <<"a=rtcp-rsize">>,
        <<"a=rtpmap:96 VP8/90000">>,
        <<"a=rtcp-fb:96 goog-remb">>,
        <<"a=rtcp-fb:96 transport-cc">>,
        <<"a=rtcp-fb:96 ccm fir">>,
        <<"a=rtcp-fb:96 nack">>,
        <<"a=rtcp-fb:96 nack pli">>,
        <<"a=rtpmap:97 rtx/90000">>,
        <<"a=fmtp:97 apt=96">>,
        <<"a=rtpmap:98 H264/90000">>,
        <<"a=rtcp-fb:* nack">>,
        <<"a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f">>,
        <<"a=rtpmap:99 rtx/90000">>,
        <<"a=fmtp:99 apt=98">>,
        <<"a=framerate:29.97">>,
        <<"a=rid:f send pt=96,98;max-width=1280;max-height=720;max-fps=30">>,
        <<"a=rid:h send pt=96;max-width=640;max-height=360">>,
        <<"a=rid:h2 send pt=98;max-width=640;max-height=360">>,
        <<"a=rid:q send max-width=320;max-height=180;max-br=150000;depend=h">>,
        <<"a=rid:r0 recv">>,
        <<"a=simulcast:send f;~h,h2;~q recv r0">>
    ]).

%% Example of RFC 8866 §5 extended with every session-level field.
-spec rfc8866_example() -> binary().
rfc8866_example() ->
    sdp([
        <<"v=0">>,
        <<"o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1">>,
        <<"s=Call to John Smith">>,
        <<"i=SDP Offer #1">>,
        <<"u=http://www.jdoe.example.com/home.html">>,
        <<"e=Jane Doe <jane@jdoe.example.com>">>,
        <<"p=+1 617 555-6011">>,
        <<"c=IN IP4 198.51.100.1">>,
        <<"b=AS:2000">>,
        <<"t=3034423619 3042462419">>,
        <<"r=604800 3600 0 90000">>,
        <<"r=7d 1h 0 25h">>,
        <<"z=2882844526 -1h 2898848070 0">>,
        <<"t=0 0">>,
        <<"k=prompt">>,
        <<"a=recvonly">>,
        <<"a=tool:custom">>,
        <<"m=audio 49170 RTP/AVP 0">>,
        <<"i=Voice">>,
        <<"a=ptime:20">>,
        <<"a=maxptime:40">>,
        <<"m=audio 49180/2 RTP/AVP 0 8">>,
        <<"c=IN IP4 233.252.0.1/127">>,
        <<"m=video 51372 RTP/AVP 99">>,
        <<"c=IN IP6 2001:db8::2">>,
        <<"b=AS:512">>,
        <<"k=clear:secret">>,
        <<"a=rtpmap:99 h263-1998/90000">>,
        <<"a=content:main,slides">>,
        <<"a=label:1">>,
        <<"a=connection:new">>,
        <<"a=tls-id:abc3de65cddef001be82">>
    ]).
