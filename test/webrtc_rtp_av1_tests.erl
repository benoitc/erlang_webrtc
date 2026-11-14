%% Tests for webrtc_rtp_av1 key frame detection.
-module(webrtc_rtp_av1_tests).
-include_lib("eunit/include/eunit.hrl").

av1_test_() ->
    A = webrtc_rtp_av1,
    [
        ?_assert(A:is_keyframe(<<2#00011000, 1, 2>>)),
        ?_assertNot(A:is_keyframe(<<2#00010000, 1, 2>>)),
        ?_assertNot(A:is_keyframe(<<2#10011000, 1, 2>>)),
        ?_assertNot(A:is_keyframe(<<>>)),
        ?_assertEqual(
            {ok, #{continuation => false, continues => true, obu_count => 2, new_sequence => true}},
            A:aggregation_header(<<2#01101000>>)
        )
    ].
