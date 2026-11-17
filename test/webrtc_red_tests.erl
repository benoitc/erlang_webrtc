%% RTP payload for redundant data (RFC 2198) and its negotiation (RFC
%% 8854 §4.2).
-module(webrtc_red_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

-define(R, webrtc_red).

%% RFC 2198 §3: a redundant block header is F = 1, the block payload
%% type, a 14-bit timestamp offset and a 10-bit length; the primary's is
%% F = 0 and its payload type; then the blocks in the same order.
layout_test() ->
    Bin = ?R:encode([{111, 960, <<"old">>}], {111, <<"new!">>}),
    ?assertEqual(<<1:1, 111:7, 960:14, 3:10, 0:1, 111:7, "old", "new!">>, Bin),
    ?assertEqual({ok, [{111, 960, <<"old">>}, {111, 0, <<"new!">>}]}, ?R:decode(Bin)).

primary_only_test() ->
    ?assertEqual(<<0:1, 111:7, "x">>, ?R:encode([], {111, <<"x">>})),
    ?assertEqual({ok, [{111, 0, <<"x">>}]}, ?R:decode(<<0:1, 111:7, "x">>)).

%% Two redundant blocks, oldest first.
two_blocks_test() ->
    Bin = ?R:encode([{0, 320, <<"a">>}, {0, 160, <<"bb">>}], {0, <<"ccc">>}),
    ?assertEqual({ok, [{0, 320, <<"a">>}, {0, 160, <<"bb">>}, {0, 0, <<"ccc">>}]}, ?R:decode(Bin)).

%% Blocks the header cannot describe are left out (§3: 14-bit offset,
%% 10-bit length); a zero offset is not a redundant block.
limits_test_() ->
    [
        ?_assertEqual({ok, [{1, 0, <<>>}]}, ?R:decode(?R:encode([{1, 16#4000, <<"x">>}], {1, <<>>}))),
        ?_assertEqual({ok, [{1, 0, <<>>}]}, ?R:decode(?R:encode([{1, 10, binary:copy(<<0>>, 1024)}], {1, <<>>}))),
        ?_assertEqual({ok, [{1, 0, <<>>}]}, ?R:decode(?R:encode([{1, 0, <<"x">>}], {1, <<>>}))),
        ?_assertMatch({ok, [{1, 16#3FFF, _}, _]}, ?R:decode(?R:encode([{1, 16#3FFF, binary:copy(<<0>>, 1023)}], {1, <<>>})))
    ].

malformed_test_() ->
    [
        ?_assertEqual({error, truncated_header}, ?R:decode(<<>>)),
        ?_assertEqual({error, truncated_header}, ?R:decode(<<1:1, 0:7, 0:14>>)),
        ?_assertEqual({error, truncated_block}, ?R:decode(<<1:1, 0:7, 10:14, 5:10, 0:1, 0:7, "ab">>))
    ].

%% Every byte string either decodes or is refused, never crashes, and
%% what decodes encodes back to the same bytes.
fuzz_test() ->
    rand:seed(exsss, {7, 7, 7}),
    lists:foreach(
        fun(_) ->
            Bin = crypto:strong_rand_bytes(rand:uniform(40)),
            case ?R:decode(Bin) of
                {ok, Blocks} ->
                    {Red, [{Pt, 0, Primary}]} = lists:split(length(Blocks) - 1, Blocks),
                    case [B || {_, O, _} = B <- Red, O =:= 0] of
                        [] -> ?assertEqual(Bin, ?R:encode(Red, {Pt, Primary}));
                        _ -> ok
                    end;
                {error, _} ->
                    ok
            end
        end,
        lists:seq(1, 5000)
    ).

%% The packets a RED packet carries: the redundant block becomes the
%% packet before, with its timestamp; the primary keeps the marker.
packets_test() ->
    Red = #rtp{pt = 63, seq = 100, ts = 9600, ssrc = 7, marker = true},
    {ok, Blocks} = ?R:decode(?R:encode([{111, 960, <<"old">>}], {111, <<"new">>})),
    ?assertEqual([#rtp{pt = 111, seq = 99, ts = 8640, ssrc = 7, marker = false, payload = <<"old">>},
                  #rtp{pt = 111, seq = 100, ts = 9600, ssrc = 7, marker = true, payload = <<"new">>}],
                 ?R:packets(Red, Blocks, fun(_) -> true end)),
    ?assertEqual([], ?R:packets(Red, Blocks, fun(_) -> false end)).

%%====================================================================
%% Negotiation
%%====================================================================

audio() -> webrtc_jsep_caps:default_codecs(audio).

%% RFC 8854 §4.2: audio/red is offered, after the codec it protects.
offered_test() ->
    Names = [N || #{name := N} <- audio()],
    ?assert(lists:member(<<"red">>, Names)),
    [#{fmtp := [<<"111/111">>]}] = [C || #{name := <<"red">>} = C <- audio()].

%% Answered with the offer's payload types; dropped when it names a
%% codec that is not kept.
answer_test_() ->
    Opus = #{pt => 109, name => <<"opus">>, clock_rate => 48000, channels => 2, fmtp => [], rtcp_fb => []},
    Red = #{pt => 120, name => <<"red">>, clock_rate => 48000, channels => 2, fmtp => [<<"109/109">>], rtcp_fb => []},
    BadRed = Red#{fmtp => [<<"110/110">>]},
    [
        ?_assertMatch([#{name := <<"red">>, pt := 120, fmtp := [<<"109/109">>]}, #{name := <<"opus">>, pt := 109}],
                      webrtc_jsep_caps:answer_codecs([Red, Opus], audio())),
        ?_assertMatch([#{name := <<"opus">>}], webrtc_jsep_caps:answer_codecs([BadRed, Opus], audio())),
        ?_assertMatch([#{name := <<"opus">>}], webrtc_jsep_caps:answer_codecs([Red#{fmtp => []}, Opus], audio()))
    ].

%% An offer may list RED first: the codec sent by default is the first
%% media codec, never a repair format.
default_send_codec_test() ->
    Red = #{pt => 63, name => <<"red">>},
    Rtx = #{pt => 97, name => <<"rtx">>},
    Opus = #{pt => 111, name => <<"opus">>},
    [{_, S}] = webrtc_media_out:senders(#{mid => <<"0">>, kind => audio, ssrc => 1, rtx_ssrc => 2,
                                          send_codecs => [Red#{fmtp => []}, Rtx#{fmtp => []}, Opus#{fmtp => []}]}, #{}),
    ?assertEqual({ok, 111}, webrtc_media_out:pick_pt(#{}, S)),
    ?assertEqual({ok, 63}, webrtc_media_out:red_pt(S)).
