%% Tests for webrtc_rtp (RFC 3550 §5.1, RFC 5761 §4) and webrtc_rtp_seq.
-module(webrtc_rtp_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

-import(webrtc_test_hex, [b/1]).

%% Opus packet as sent by a browser: X=1, PT 111, one-byte extensions
%% ssrc-audio-level (id 1) and abs-send-time (id 2), two padding bytes in
%% the extension block.
opus_packet() ->
    b("90 6f 12 34  00 00 03 c0  de ad be ef
       be de 00 02  10 ff 22 12  34 56 00 00
       fc ff fe").

minimal_test() ->
    Bin = b("80 60 00 01 00 00 00 02 00 00 00 03"),
    {ok, P} = webrtc_rtp:decode(Bin),
    ?assertEqual(#rtp{pt = 96, seq = 1, ts = 2, ssrc = 3}, P),
    ?assertEqual(Bin, webrtc_rtp:encode(P)).

opus_decode_test() ->
    Bin = opus_packet(),
    {ok, P} = webrtc_rtp:decode(Bin),
    ?assertMatch(
        #rtp{
            marker = false,
            pt = 111,
            seq = 16#1234,
            ts = 960,
            ssrc = 16#deadbeef,
            csrcs = [],
            ext = {16#BEDE, <<16#10, 16#ff, 16#22, 16#12, 16#34, 16#56, 0, 0>>},
            payload = <<16#fc, 16#ff, 16#fe>>
        },
        P
    ),
    ?assertEqual(Bin, webrtc_rtp:encode(P)),
    {ok, P2} = webrtc_rtp:decode(Bin, #{extensions => parse}),
    ?assertEqual([{1, <<16#ff>>}, {2, <<16#12, 16#34, 16#56>>}], P2#rtp.ext),
    ?assertEqual({ok, [{1, <<16#ff>>}, {2, <<16#12, 16#34, 16#56>>}]}, webrtc_rtp:extensions(P)),
    %% Re-encoding the parsed form reproduces the bytes.
    ?assertEqual(Bin, webrtc_rtp:encode(P2)).

csrc_and_marker_test() ->
    Csrcs = lists:seq(1, 15),
    P = #rtp{marker = true, pt = 127, seq = 65535, ts = 16#FFFFFFFF, ssrc = 7, csrcs = Csrcs},
    Bin = webrtc_rtp:encode(P),
    <<16#8F, 16#FF, _/binary>> = Bin,
    ?assertEqual(12 + 60, byte_size(Bin)),
    ?assertEqual({ok, P}, webrtc_rtp:decode(Bin)).

padding_test() ->
    %% P=1, payload "ab", 3 padding octets (count 3).
    Bin = b("a0 60 00 01 00 00 00 02 00 00 00 03 61 62 00 00 03"),
    {ok, P} = webrtc_rtp:decode(Bin),
    ?assertEqual(<<"ab">>, P#rtp.payload),
    ?assertEqual(3, P#rtp.padding),
    ?assertEqual(Bin, webrtc_rtp:encode(P)).

padding_only_test() ->
    %% Padding may cover the whole payload (probing packets).
    Bin = b("a0 60 00 01 00 00 00 02 00 00 00 03 00 00 00 04"),
    {ok, P} = webrtc_rtp:decode(Bin),
    ?assertEqual(<<>>, P#rtp.payload),
    ?assertEqual(4, P#rtp.padding).

bad_padding_test_() ->
    Hdr = b("a0 60 00 01 00 00 00 02 00 00 00 03"),
    [
        %% count 0 is invalid
        ?_assertEqual({error, bad_padding}, webrtc_rtp:decode(<<Hdr/binary, 1, 2, 0>>)),
        %% count larger than what follows the header
        ?_assertEqual({error, bad_padding}, webrtc_rtp:decode(<<Hdr/binary, 1, 4>>)),
        %% P set but nothing after the header
        ?_assertEqual({error, bad_padding}, webrtc_rtp:decode(Hdr))
    ].

bad_version_test_() ->
    [
        ?_assertEqual({error, bad_version}, webrtc_rtp:decode(b("40 60 00 01 00 00 00 02 00 00 00 03"))),
        ?_assertEqual({error, bad_version}, webrtc_rtp:decode(b("00 60 00 01 00 00 00 02 00 00 00 03"))),
        ?_assertEqual({error, bad_version}, webrtc_rtp:decode(b("c0 60 00 01 00 00 00 02 00 00 00 03")))
    ].

extension_length_test_() ->
    Hdr = b("90 60 00 01 00 00 00 02 00 00 00 03"),
    [
        %% declared 2 words, 1 present
        ?_assertEqual(
            {error, bad_extension},
            webrtc_rtp:decode(<<Hdr/binary, 16#BE, 16#DE, 0, 2, 1, 2, 3, 4>>)
        ),
        %% extension header itself cut
        ?_assertEqual({error, truncated}, webrtc_rtp:decode(<<Hdr/binary, 16#BE, 16#DE>>)),
        %% zero length extension is valid
        ?_assertMatch(
            {ok, #rtp{ext = {16#BEDE, <<>>}, payload = <<"x">>}},
            webrtc_rtp:decode(<<Hdr/binary, 16#BE, 16#DE, 0, 0, "x">>)
        )
    ].

max_extension_length_test() ->
    Data = binary:copy(<<1, 2, 3, 4>>, 16#FFFF),
    P = #rtp{pt = 96, seq = 1, ts = 1, ssrc = 1, ext = {16#1234, Data}, payload = <<"p">>},
    Bin = webrtc_rtp:encode(P),
    ?assertEqual({ok, P}, webrtc_rtp:decode(Bin)),
    ?assertError(badarg, webrtc_rtp:encode(P#rtp{ext = {16#1234, <<Data/binary, 0, 0, 0, 0>>}})),
    ?assertError(badarg, webrtc_rtp:encode(P#rtp{ext = {16#1234, <<1, 2>>}})).

unknown_profile_kept_raw_test() ->
    Bin = b("90 60 00 01 00 00 00 02 00 00 00 03 12 34 00 01 aa bb cc dd"),
    ?assertMatch(
        {ok, #rtp{ext = {16#1234, <<16#aa, 16#bb, 16#cc, 16#dd>>}}},
        webrtc_rtp:decode(Bin, #{extensions => parse})
    ),
    {ok, P} = webrtc_rtp:decode(Bin),
    ?assertEqual({error, {not_rfc8285, 16#1234}}, webrtc_rtp:extensions(P)).

bad_rfc8285_ext_test() ->
    %% one-byte element claims 4 bytes, only 3 left in the block
    Bin = b("90 60 00 01 00 00 00 02 00 00 00 03 be de 00 01 13 01 02 03"),
    ?assertMatch({ok, _}, webrtc_rtp:decode(Bin)),
    ?assertEqual({error, {bad_extension, truncated}}, webrtc_rtp:decode(Bin, #{extensions => parse})).

encode_badarg_test_() ->
    P = #rtp{pt = 96, seq = 1, ts = 1, ssrc = 1},
    [
        ?_assertError(badarg, webrtc_rtp:encode(P#rtp{pt = 128})),
        ?_assertError(badarg, webrtc_rtp:encode(P#rtp{seq = 65536})),
        ?_assertError(badarg, webrtc_rtp:encode(P#rtp{ts = -1})),
        ?_assertError(badarg, webrtc_rtp:encode(P#rtp{csrcs = lists:seq(1, 16)})),
        ?_assertError(badarg, webrtc_rtp:encode(P#rtp{csrcs = [1 bsl 32]})),
        ?_assertError(badarg, webrtc_rtp:encode(P#rtp{padding = 256}))
    ].

%% Every cut inside the header (fixed part, CSRCs, extension) is an
%% error; cuts in the payload give a shorter valid packet; nothing crashes.
truncation_test() ->
    P = #rtp{pt = 96, seq = 1, ts = 1, ssrc = 1, csrcs = [9, 8], ext = [{1, <<"a">>}, {3, <<"xyz">>}], payload = <<"payload">>},
    Bin = webrtc_rtp:encode(P),
    {ok, HdrSize} = webrtc_rtp:header_size(Bin),
    ?assertEqual(12 + 8 + 4 + 8, HdrSize),
    lists:foreach(
        fun(N) ->
            Cut = binary:part(Bin, 0, N),
            R = webrtc_rtp:decode(Cut),
            case N < HdrSize of
                true ->
                    ?assertMatch({error, _}, R),
                    ?assertMatch({error, _}, webrtc_rtp:header_size(Cut));
                false ->
                    ?assertMatch({ok, _}, R),
                    ?assertEqual({ok, HdrSize}, webrtc_rtp:header_size(Cut))
            end
        end,
        lists:seq(0, byte_size(Bin))
    ).

padded_truncation_never_crashes_test() ->
    Bin = webrtc_rtp:encode(#rtp{pt = 96, seq = 1, ts = 1, ssrc = 1, padding = 4, payload = <<"abc">>}),
    [
        ?assertMatch({_, _}, webrtc_rtp:decode(binary:part(Bin, 0, N)))
     || N <- lists:seq(0, byte_size(Bin))
    ].

peek_rewrite_test() ->
    Bin = opus_packet(),
    ?assertEqual(
        {ok, #{marker => false, pt => 111, seq => 16#1234, ts => 960, ssrc => 16#deadbeef}},
        webrtc_rtp:peek(Bin)
    ),
    {ok, Bin2} = webrtc_rtp:rewrite(Bin, #{seq => 7, ts => 16#FFFFFFFF, ssrc => 42, pt => 96, marker => true}),
    {ok, P} = webrtc_rtp:decode(Bin),
    {ok, P2} = webrtc_rtp:decode(Bin2),
    ?assertEqual(P#rtp{seq = 7, ts = 16#FFFFFFFF, ssrc = 42, pt = 96, marker = true}, P2),
    ?assertEqual(binary:part(Bin, 12, byte_size(Bin) - 12), binary:part(Bin2, 12, byte_size(Bin2) - 12)),
    ?assertEqual({ok, Bin}, webrtc_rtp:rewrite(Bin, #{})),
    ?assertError(badarg, webrtc_rtp:rewrite(Bin, #{seq => 70000})),
    ?assertEqual({error, truncated}, webrtc_rtp:peek(<<16#80, 0>>)),
    ?assertEqual({error, bad_version}, webrtc_rtp:rewrite(<<0:96>>, #{})),
    ?assertEqual({error, truncated}, webrtc_rtp:rewrite(<<>>, #{})).

%% RFC 5761 §4: second octet 192..223 is RTCP.
classify_test_() ->
    [
        ?_assertEqual(rtcp, webrtc_rtp:classify(<<16#80, 200, 0, 6>>)),
        ?_assertEqual(rtcp, webrtc_rtp:classify(<<16#81, 205, 0, 2>>)),
        ?_assertEqual(rtcp, webrtc_rtp:classify(<<16#80, 192, 0, 0>>)),
        ?_assertEqual(rtcp, webrtc_rtp:classify(<<16#80, 223, 0, 0>>)),
        ?_assertEqual(rtp, webrtc_rtp:classify(<<16#80, 191, 0, 0>>)),
        ?_assertEqual(rtp, webrtc_rtp:classify(<<16#80, 224, 0, 0>>)),
        %% PT 96 with marker set is 224: RTP
        ?_assertEqual(rtp, webrtc_rtp:classify(<<16#80, (128 + 96), 0, 0>>)),
        ?_assertEqual(rtp, webrtc_rtp:classify(<<16#80, 111, 0, 0>>)),
        ?_assertEqual(unknown, webrtc_rtp:classify(<<16#40, 200, 0, 0>>)),
        ?_assertEqual(unknown, webrtc_rtp:classify(<<16#80>>)),
        ?_assert(webrtc_rtp:is_rtcp(<<16#80, 201, 0, 1>>)),
        ?_assertNot(webrtc_rtp:is_rtcp(opus_packet()))
    ].

%%--------------------------------------------------------------------
%% Sequence and timestamp arithmetic
%%--------------------------------------------------------------------

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
