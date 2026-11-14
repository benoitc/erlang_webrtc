%% Tests for webrtc_rtp_ext (RFC 8285 and typed extension values).
-module(webrtc_rtp_ext_tests).
-include_lib("eunit/include/eunit.hrl").

-import(webrtc_test_hex, [b/1]).

%% RFC 8285 §4.2 figure: elements with L=0 (1 byte), L=1 (2 bytes), two
%% padding bytes, L=3 (4 bytes); 3 words.
one_byte_figure_test() ->
    Data = b("10 aa 21 bb cc 00 00 33 01 02 03 04"),
    ?assertEqual(
        {ok, [{1, <<16#aa>>}, {2, <<16#bb, 16#cc>>}, {3, <<1, 2, 3, 4>>}]},
        webrtc_rtp_ext:decode(16#BEDE, Data)
    ).

%% RFC 8285 §4.3 figure: L=0 (no data), L=1, one padding byte, L=4.
two_byte_figure_test() ->
    Data = b("01 00 02 01 aa 00 03 04 01 02 03 04"),
    ?assertEqual(
        {ok, [{1, <<>>}, {2, <<16#aa>>}, {3, <<1, 2, 3, 4>>}]},
        webrtc_rtp_ext:decode(16#1000, Data)
    ),
    %% appbits are ignored
    ?assertEqual(webrtc_rtp_ext:decode(16#1000, Data), webrtc_rtp_ext:decode(16#100F, Data)).

id15_stops_test() ->
    %% id 15 terminates processing; its length is ignored
    Data = b("10 aa f3 bb cc dd 00 00"),
    ?assertEqual({ok, [{1, <<16#aa>>}]}, webrtc_rtp_ext:decode(16#BEDE, Data)),
    ?assertEqual({ok, []}, webrtc_rtp_ext:decode(16#BEDE, <<16#F0>>)).

one_byte_errors_test_() ->
    [
        ?_assertEqual({error, truncated}, webrtc_rtp_ext:decode(16#BEDE, b("13 01 02 03"))),
        %% id 0 with a non-zero length is not padding
        ?_assertEqual({error, bad_padding}, webrtc_rtp_ext:decode(16#BEDE, b("01 00 00 00"))),
        ?_assertEqual({error, truncated}, webrtc_rtp_ext:decode(16#1000, b("05"))),
        ?_assertEqual({error, truncated}, webrtc_rtp_ext:decode(16#1000, b("05 04 01 02"))),
        ?_assertEqual({error, {not_rfc8285, 16#1234}}, webrtc_rtp_ext:decode(16#1234, <<>>))
    ].

is_rfc8285_test_() ->
    [
        ?_assert(webrtc_rtp_ext:is_rfc8285(16#BEDE)),
        ?_assert(webrtc_rtp_ext:is_rfc8285(16#1000)),
        ?_assert(webrtc_rtp_ext:is_rfc8285(16#100F)),
        ?_assertNot(webrtc_rtp_ext:is_rfc8285(16#1010)),
        ?_assertNot(webrtc_rtp_ext:is_rfc8285(0))
    ].

encode_one_byte_test() ->
    Elems = [{1, <<16#aa>>}, {2, <<16#bb, 16#cc>>}, {3, <<1, 2, 3, 4>>}],
    {16#BEDE, Data} = webrtc_rtp_ext:encode(Elems),
    ?assertEqual(b("10 aa 21 bb cc 33 01 02 03 04 00 00"), Data),
    ?assertEqual({ok, Elems}, webrtc_rtp_ext:decode(16#BEDE, Data)).

%% An empty value, an id above 14 or a value longer than 16 bytes needs
%% the two-byte form (allowed with a=extmap-allow-mixed).
encode_auto_two_byte_test_() ->
    Cases = [
        [{1, <<>>}],
        [{15, <<"x">>}],
        [{200, <<"x">>}],
        [{1, binary:copy(<<"a">>, 17)}],
        [{1, <<"mixed">>}, {2, binary:copy(<<"b">>, 255)}]
    ],
    [
        ?_test(begin
            {P, Data} = webrtc_rtp_ext:encode(E),
            ?assertEqual(16#1000, P),
            ?assertEqual(0, byte_size(Data) rem 4),
            ?assertEqual({ok, E}, webrtc_rtp_ext:decode(P, Data))
        end)
     || E <- Cases
    ].

encode_forced_form_test_() ->
    [
        ?_assertError(badarg, webrtc_rtp_ext:encode([{15, <<"x">>}], #{form => one_byte})),
        ?_assertError(badarg, webrtc_rtp_ext:encode([{1, <<>>}], #{form => one_byte})),
        ?_assertError(badarg, webrtc_rtp_ext:encode([{0, <<"x">>}])),
        ?_assertError(badarg, webrtc_rtp_ext:encode([{256, <<"x">>}])),
        ?_assertError(badarg, webrtc_rtp_ext:encode([{1, binary:copy(<<"a">>, 256)}])),
        ?_assertEqual(
            {16#1003, b("01 01 61 00")},
            webrtc_rtp_ext:encode([{1, <<"a">>}], #{form => two_byte, appbits => 3})
        ),
        ?_assertEqual({16#BEDE, <<>>}, webrtc_rtp_ext:encode([]))
    ].

find_test() ->
    ?assertEqual({ok, <<"b">>}, webrtc_rtp_ext:find(2, [{1, <<"a">>}, {2, <<"b">>}])),
    ?assertEqual(error, webrtc_rtp_ext:find(3, [{1, <<"a">>}])).

every_truncation_test() ->
    {P, Data} = webrtc_rtp_ext:encode([{1, <<"abc">>}, {2, <<"defgh">>}]),
    %% Every cut either fails or yields a prefix of the elements.
    [
        ?assert(
            case webrtc_rtp_ext:decode(P, binary:part(Data, 0, N)) of
                {error, truncated} -> true;
                {ok, L} -> lists:prefix(L, [{1, <<"abc">>}, {2, <<"defgh">>}])
            end
        )
     || N <- lists:seq(0, byte_size(Data))
    ].

%%--------------------------------------------------------------------
%% Typed values
%%--------------------------------------------------------------------

abs_send_time_test() ->
    ?assertEqual(<<16#12, 16#34, 16#56>>, webrtc_rtp_ext:abs_send_time(16#123456)),
    ?assertEqual({ok, 16#123456}, webrtc_rtp_ext:decode_abs_send_time(<<16#12, 16#34, 16#56>>)),
    ?assertEqual({error, bad_length}, webrtc_rtp_ext:decode_abs_send_time(<<1, 2>>)),
    %% 1.5 s in NTP: seconds 1, fraction 0x80000000 -> 6.18: 1 << 18 | 1 << 17
    Ntp = (1 bsl 32) bor 16#80000000,
    ?assertEqual((1 bsl 18) bor (1 bsl 17), webrtc_rtp_ext:abs_send_time_from_ntp(Ntp)),
    %% seconds wrap at 64
    ?assertEqual(0, webrtc_rtp_ext:abs_send_time_from_ntp(64 bsl 32)).

twcc_seq_test() ->
    ?assertEqual(<<16#FF, 16#FF>>, webrtc_rtp_ext:twcc_seq(65535)),
    ?assertEqual({ok, 258}, webrtc_rtp_ext:decode_twcc_seq(<<1, 2>>)),
    ?assertEqual({error, bad_length}, webrtc_rtp_ext:decode_twcc_seq(<<1>>)).

%% RFC 6464 §3: V bit then 7-bit level in -dBov.
audio_level_test() ->
    ?assertEqual(<<(16#80 bor 42)>>, webrtc_rtp_ext:audio_level(true, 42)),
    ?assertEqual(<<127>>, webrtc_rtp_ext:audio_level(false, 127)),
    ?assertEqual({ok, {true, 42}}, webrtc_rtp_ext:decode_audio_level(<<16#AA>>)),
    %% two-byte form may carry padding after the level
    ?assertEqual({ok, {false, 10}}, webrtc_rtp_ext:decode_audio_level(<<10, 0, 0>>)),
    ?assertEqual({error, bad_length}, webrtc_rtp_ext:decode_audio_level(<<>>)),
    ?assertError(function_clause, webrtc_rtp_ext:audio_level(true, 128)).

sdes_test() ->
    ?assertEqual(<<"0">>, webrtc_rtp_ext:sdes(<<"0">>)),
    ?assertEqual({ok, <<"mid1">>}, webrtc_rtp_ext:decode_sdes(<<"mid1">>)),
    ?assertEqual({ok, <<"hi">>}, webrtc_rtp_ext:decode_sdes(<<"hi", 0, 0>>)),
    ?assertEqual({error, empty}, webrtc_rtp_ext:decode_sdes(<<0>>)),
    ?assertEqual({error, empty}, webrtc_rtp_ext:decode_sdes(<<>>)).

toffset_test() ->
    ?assertEqual(<<16#FF, 16#FF, 16#FF>>, webrtc_rtp_ext:toffset(-1)),
    ?assertEqual({ok, -1}, webrtc_rtp_ext:decode_toffset(<<16#FF, 16#FF, 16#FF>>)),
    ?assertEqual({ok, 16#7FFFFF}, webrtc_rtp_ext:decode_toffset(<<16#7F, 16#FF, 16#FF>>)),
    ?assertEqual({error, bad_length}, webrtc_rtp_ext:decode_toffset(<<1>>)).

video_orientation_test() ->
    O = #{camera => back, flip => true, rotation => 270},
    ?assertEqual(<<2#00001111>>, webrtc_rtp_ext:video_orientation(O)),
    ?assertEqual({ok, O}, webrtc_rtp_ext:decode_video_orientation(<<2#00001111>>)),
    ?assertEqual(
        {ok, #{camera => front, flip => false, rotation => 90}},
        webrtc_rtp_ext:decode_video_orientation(<<1>>)
    ),
    ?assertEqual({error, bad_length}, webrtc_rtp_ext:decode_video_orientation(<<>>)).

playout_delay_test() ->
    ?assertEqual(<<16#00, 16#A0, 16#64>>, webrtc_rtp_ext:playout_delay(100, 1000)),
    ?assertEqual({ok, {100, 1000}}, webrtc_rtp_ext:decode_playout_delay(<<16#00, 16#A0, 16#64>>)),
    ?assertEqual(
        {ok, {40950, 40950}}, webrtc_rtp_ext:decode_playout_delay(<<16#FF, 16#FF, 16#FF>>)
    ),
    ?assertEqual({error, bad_length}, webrtc_rtp_ext:decode_playout_delay(<<1, 2>>)).
