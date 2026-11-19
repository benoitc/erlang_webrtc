%% Tests for webrtc_rtp_opus (RFC 7587, RFC 6716 §3.1 TOC).
-module(webrtc_rtp_opus_tests).
-include_lib("eunit/include/eunit.hrl").

-define(OPUS, webrtc_rtp_opus).

opus_test_() ->
    [
        ?_assertEqual(48000, ?OPUS:clock_rate()),
        %% browsers' default 20 ms frames: TOC 0x78 (hybrid FB 20 ms) and
        %% 0xFC (CELT FB 20 ms, stereo)
        ?_assertEqual({ok, 960}, ?OPUS:duration(<<16#78, 1, 2>>)),
        ?_assertMatch(
            {ok, #{config := 31, mode := celt, stereo := true, code := 0, frame_samples := 960}},
            ?OPUS:toc(<<16#FC>>)
        ),
        %% SILK NB 60 ms, two frames (code 1) = 120 ms
        ?_assertEqual({ok, 5760}, ?OPUS:duration(<<(3 bsl 3 bor 1)>>)),
        %% CELT 2.5 ms, code 3 with 6 frames = 15 ms
        ?_assertEqual({ok, 720}, ?OPUS:duration(<<(16 bsl 3 bor 3), 6>>)),
        ?_assertEqual({error, too_long}, ?OPUS:duration(<<(31 bsl 3 bor 3), 48>>)),
        ?_assertEqual({error, bad_frame_count}, ?OPUS:duration(<<(31 bsl 3 bor 3), 0>>)),
        ?_assertEqual({error, truncated}, ?OPUS:duration(<<(31 bsl 3 bor 3)>>)),
        ?_assertEqual({error, empty}, ?OPUS:duration(<<>>)),
        ?_assertEqual([<<1, 2>>], ?OPUS:packetize(<<1, 2>>)),
        ?_assertEqual({ok, <<1>>}, ?OPUS:depacketize(<<1>>)),
        ?_assertEqual({error, empty}, ?OPUS:depacketize(<<>>))
    ].
