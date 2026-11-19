%% Tests for transport-wide CC feedback
%% (draft-holmer-rmcat-transport-wide-cc-extensions-01 §3.1).
-module(webrtc_rtcp_twcc_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

-import(webrtc_test_hex, [b/1]).

%% base 100, 5 packets: small 4, small 1, lost, large -4, small 255.
%% One two-bit status vector chunk 0xD490, zero padding to 32 bits.
mixed() ->
    b(
        "8f cd 00 06 00 00 00 01 2a 3b 4c 5d\n"
        "       00 64 00 05 00 01 23 07\n"
        "       d4 90 04 01 ff fc ff 00"
    ).

mixed_record() ->
    #rtcp_twcc{
        sender_ssrc = 1,
        media_ssrc = 16#2a3b4c5d,
        base_seq = 100,
        ref_time = 16#123,
        fb_count = 7,
        packets = [{100, 4}, {101, 1}, {102, not_received}, {103, -4}, {104, 255}]
    }.

mixed_test() ->
    Bin = mixed(),
    ?assertEqual({ok, [mixed_record()]}, webrtc_rtcp:decode(Bin)),
    ?assertEqual(Bin, webrtc_rtcp:encode(mixed_record())).

%% libwebrtc pads with the P bit and a count octet instead.
padding_bit_test() ->
    Bin = b(
        "af cd 00 06 00 00 00 01 2a 3b 4c 5d\n"
        "             00 64 00 05 00 01 23 07\n"
        "             d4 90 04 01 ff fc ff 01"
    ),
    ?assertEqual({ok, [mixed_record()]}, webrtc_rtcp:decode(Bin)).

%% Draft §3.1.3 example 1: run of 221 "not received".
run_length_example_test() ->
    T = #rtcp_twcc{base_seq = 0, packets = [{S, not_received} || S <- lists:seq(0, 220)]},
    Fci = webrtc_rtcp_twcc:encode_fci(T),
    ?assertEqual(<<0:16, 221:16, 0:24, 0:8, 16#00, 16#DD, 0, 0>>, Fci),
    ?assertEqual({ok, [T]}, webrtc_rtcp:decode(webrtc_rtcp:encode(T))).

%% Draft §3.1.4 example 1: one-bit vector 1x lost, 5x received, 3x lost,
%% 3x received, 2x lost.
one_bit_vector_example_test() ->
    Pattern = [0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0],
    Packets = [
        case P of
            0 -> {S, not_received};
            1 -> {S, 2}
        end
     || {S, P} <- lists:zip(lists:seq(1000, 1013), Pattern)
    ],
    T = #rtcp_twcc{base_seq = 1000, packets = Packets},
    Fci = webrtc_rtcp_twcc:encode_fci(T),
    <<1000:16, 14:16, _:32, Chunk:16, Deltas:8/binary, _/binary>> = Fci,
    ?assertEqual(16#9F1C, Chunk),
    ?assertEqual(binary:copy(<<2>>, 8), Deltas),
    ?assertEqual({ok, [T]}, webrtc_rtcp:decode(webrtc_rtcp:encode(T))).

%% Draft §3.1.4 example 2 uses symbol 11, which is reserved.
reserved_symbol_test() ->
    Bin = b("8f cd 00 05 00 00 00 01 00 00 00 02 00 00 00 07 00 00 00 00 cd 50 00 00"),
    ?assertEqual({error, {bad_packet, 205, reserved_symbol}}, webrtc_rtcp:decode(Bin)),
    Rle = b("8f cd 00 05 00 00 00 01 00 00 00 02 00 00 00 07 00 00 00 00 60 07 00 00"),
    ?assertEqual({error, {bad_packet, 205, reserved_symbol}}, webrtc_rtcp:decode(Rle)).

run_length_received_test() ->
    T = #rtcp_twcc{
        base_seq = 65530, packets = [{(65530 + I) band 16#FFFF, 1} || I <- lists:seq(0, 19)]
    },
    Fci = webrtc_rtcp_twcc:encode_fci(T),
    <<65530:16, 20:16, _:32, 16#2014:16, _/binary>> = Fci,
    ?assertEqual({ok, [T]}, webrtc_rtcp:decode(webrtc_rtcp:encode(T))).

%% A vector chunk may describe more symbols than the status count; the
%% extra ones are ignored.
status_count_cuts_vector_test() ->
    Bin = b("8f cd 00 05 00 00 00 01 00 00 00 02 00 0a 00 02 00 00 00 00 d7 ff 05 06"),
    ?assertMatch(
        {ok, [#rtcp_twcc{base_seq = 10, packets = [{10, 5}, {11, 6}]}]}, webrtc_rtcp:decode(Bin)
    ).

%% A run length chunk longer than the status count.
long_run_cut_test() ->
    Bin = b("8f cd 00 05 00 00 00 01 00 00 00 02 00 00 00 02 00 00 00 00 3f ff 05 06"),
    ?assertMatch({ok, [#rtcp_twcc{packets = [{0, 5}, {1, 6}]}]}, webrtc_rtcp:decode(Bin)).

twcc_errors_test_() ->
    [
        %% two received symbols but one delta
        ?_assertMatch(
            {error, {bad_packet, 205, truncated}},
            webrtc_rtcp:decode(
                b("8f cd 00 05 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 00 20 03 05 00")
            )
        ),
        %% status count with no chunk
        ?_assertMatch(
            {error, {bad_packet, 205, truncated}},
            webrtc_rtcp:decode(b("8f cd 00 04 00 00 00 01 00 00 00 02 00 00 00 02 00 00 00 00"))
        ),
        %% more than 3 trailing bytes
        ?_assertMatch(
            {error, {bad_packet, 205, trailing_data}},
            webrtc_rtcp:decode(
                b(
                    "8f cd 00 06 00 00 00 01 00 00 00 02 00 00 00 01 00 00 00 00 20 01 05 00 00 00 00 00"
                )
            )
        ),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_twcc{base_seq = 1, packets = [{2, 1}]})),
        ?_assertError(badarg, webrtc_rtcp:encode(#rtcp_twcc{base_seq = 1, packets = [{1, 40000}]}))
    ].

every_truncation_test() ->
    Bin = mixed(),
    [
        ?assertMatch({error, _}, webrtc_rtcp:decode(binary:part(Bin, 0, N)))
     || N <- lists:seq(0, byte_size(Bin) - 1)
    ].

empty_feedback_test() ->
    T = #rtcp_twcc{base_seq = 5, fb_count = 1},
    ?assertEqual({ok, [T]}, webrtc_rtcp:decode(webrtc_rtcp:encode(T))).

from_arrivals_test() ->
    %% arrivals in microseconds: 64 ms reference grid, 250 us ticks
    Arrivals = [
        {65535, 128000 + 1000}, {0, 128000 + 1500}, {2, 128000 + 1250}, {3, 128000 + 101500}
    ],
    [T] = webrtc_rtcp_twcc:from_arrivals(1, 2, 9, Arrivals),
    ?assertEqual(65535, T#rtcp_twcc.base_seq),
    ?assertEqual(2, T#rtcp_twcc.ref_time),
    ?assertEqual(9, T#rtcp_twcc.fb_count),
    ?assertEqual([{65535, 4}, {0, 2}, {1, not_received}, {2, -1}, {3, 401}], T#rtcp_twcc.packets),
    ?assertEqual(
        [{65535, 129000}, {0, 129500}, {1, not_received}, {2, 129250}, {3, 229500}],
        webrtc_rtcp_twcc:arrivals(T)
    ),
    ?assertEqual({ok, [T]}, webrtc_rtcp:decode(webrtc_rtcp:encode(T))).

from_arrivals_split_test() ->
    %% a 9 s gap does not fit a 16-bit delta: two messages
    [A, B] = webrtc_rtcp_twcc:from_arrivals(1, 2, 255, [{10, 0}, {11, 9000000}]),
    ?assertEqual({10, 255, [{10, 0}]}, {
        A#rtcp_twcc.base_seq, A#rtcp_twcc.fb_count, A#rtcp_twcc.packets
    }),
    ?assertEqual({11, 0}, {B#rtcp_twcc.base_seq, B#rtcp_twcc.fb_count}),
    ?assertEqual([{11, 9000000}], webrtc_rtcp_twcc:arrivals(B)),
    ?assertEqual([], webrtc_rtcp_twcc:from_arrivals(1, 2, 0, [])).
