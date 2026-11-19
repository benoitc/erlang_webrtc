%% Tests for webrtc_rtp_seq (RFC 3550 §5.1 wraparound).
-module(webrtc_rtp_seq_tests).
-include_lib("eunit/include/eunit.hrl").

seq_test_() ->
    S = webrtc_rtp_seq,
    [
        ?_assertEqual(0, S:seq_add(65535, 1)),
        ?_assertEqual(65535, S:seq_add(0, -1)),
        ?_assertEqual(1, S:seq_diff(0, 65535)),
        ?_assertEqual(-1, S:seq_diff(65535, 0)),
        ?_assertEqual(32767, S:seq_diff(32767, 0)),
        ?_assertEqual(-32768, S:seq_diff(32768, 0)),
        ?_assert(S:seq_lt(65535, 0)),
        ?_assert(S:seq_gt(0, 65535)),
        ?_assert(S:seq_le(5, 5)),
        ?_assertNot(S:seq_lt(5, 5)),
        ?_assertEqual(65536, S:seq_unwrap(0, 65535)),
        ?_assertEqual(65535, S:seq_unwrap(65535, 65536)),
        ?_assertEqual(196608 + 10, S:seq_unwrap(10, 131072 + 65530)),
        ?_assertEqual(-1, S:seq_unwrap(65535, 0)),
        ?_assertEqual(7, S:seq_unwrap(7, undefined))
    ].

ts_test_() ->
    S = webrtc_rtp_seq,
    [
        ?_assertEqual(0, S:ts_add(16#FFFFFFFF, 1)),
        ?_assertEqual(959, S:ts_add(16#FFFFFFFF, 960)),
        ?_assertEqual(960, S:ts_diff(959, 16#FFFFFFFF)),
        ?_assert(S:ts_lt(16#FFFFFF00, 5)),
        ?_assert(S:ts_gt(5, 16#FFFFFF00)),
        ?_assertEqual(16#100000000 + 5, S:ts_unwrap(5, 16#FFFFFF00)),
        ?_assertEqual(16#FFFFFF00, S:ts_unwrap(16#FFFFFF00, 16#100000000 + 5))
    ].
