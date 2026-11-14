%% Tests for webrtc_rtp_h264 (RFC 6184, packetization-mode 1).
-module(webrtc_rtp_h264_tests).
-include_lib("eunit/include/eunit.hrl").

-import(webrtc_test_hex, [b/1]).

never_crashes(Fun, Bin) ->
    [_ = Fun(binary:part(Bin, 0, N)) || N <- lists:seq(0, byte_size(Bin))],
    ok.

-define(H264, webrtc_rtp_h264).

sps() -> b("67 42 c0 1f da 01 40 16 e8").
pps() -> b("68 ce 3c 80").
idr(N) -> <<16#65, (binary:copy(<<16#88>>, N))/binary>>.

annexb_test() ->
    Stream = iolist_to_binary([<<0, 0, 0, 1>>, sps(), <<0, 0, 1>>, pps(), <<0, 0, 0, 1>>, idr(10)]),
    ?assertEqual([sps(), pps(), idr(10)], ?H264:split_annexb(Stream)),
    ?assertEqual([], ?H264:split_annexb(<<1, 2, 3>>)).

stap_a_test() ->
    [Stap] = ?H264:packetize([sps(), pps(), idr(20)], 1200),
    <<_:1, Nri:2, 24:5, Rest/binary>> = Stap,
    %% NRI is the maximum of the aggregated units (3 for SPS/PPS/IDR)
    ?assertEqual(3, Nri),
    ?assertEqual(<<9:16, (sps())/binary, 4:16, (pps())/binary, 21:16, (idr(20))/binary>>, Rest),
    ?assertEqual({ok, [sps(), pps(), idr(20)]}, ?H264:depacketize(Stap)),
    ?assert(?H264:is_keyframe(Stap)),
    ?assertEqual([7, 8, 5], ?H264:nal_types(Stap)).

single_nal_test() ->
    Nal = <<16#41, 1, 2, 3>>,
    ?assertEqual([Nal], ?H264:packetize([Nal], 1200)),
    ?assertEqual({ok, [Nal]}, ?H264:depacketize(Nal)),
    ?assertNot(?H264:is_keyframe(Nal)),
    %% a unit that fits alone but not with the next one
    Big = <<16#41, (binary:copy(<<7>>, 1190))/binary>>,
    ?assertEqual([sps(), Big], ?H264:packetize([sps(), Big], 1200)).

fu_a_test() ->
    Nal = idr(3000),
    Payloads = ?H264:packetize([Nal], 1200),
    ?assertEqual(3, length(Payloads)),
    ?assert(lists:all(fun(P) -> byte_size(P) =< 1200 end, Payloads)),
    [First, Middle, Last] = Payloads,
    ?assertMatch(<<0:1, 3:2, 28:5, 1:1, 0:1, 0:1, 5:5, _/binary>>, First),
    ?assertMatch(<<_:8, 0:1, 0:1, 0:1, 5:5, _/binary>>, Middle),
    ?assertMatch(<<_:8, 0:1, 1:1, 0:1, 5:5, _/binary>>, Last),
    ?assert(?H264:is_keyframe(First)),
    ?assertNot(?H264:is_keyframe(Middle)),
    %% reassembly
    D0 = ?H264:depacketizer_new(),
    {ok, [], D1} = ?H264:depacketizer_push(65535, First, D0),
    {ok, [], D2} = ?H264:depacketizer_push(0, Middle, D1),
    {ok, [Out], _} = ?H264:depacketizer_push(1, Last, D2),
    ?assertEqual(Nal, Out),
    %% a missing middle fragment drops the unit
    {ok, [], E1} = ?H264:depacketizer_push(10, First, D0),
    ?assertMatch({error, lost_fragment, _}, ?H264:depacketizer_push(12, Last, E1)),
    %% a fragment without its start
    ?assertMatch({error, lost_fragment, _}, ?H264:depacketizer_push(5, Middle, D0)).

h264_errors_test_() ->
    [
        ?_assertEqual({error, empty}, ?H264:depacketize(<<>>)),
        ?_assertEqual({error, bad_fu_a}, ?H264:depacketize(<<16#7C, 16#C5, 1>>)),
        ?_assertEqual({error, truncated}, ?H264:depacketize(<<16#7C>>)),
        ?_assertEqual({error, truncated}, ?H264:depacketize(<<16#78, 0, 5, 1, 2>>)),
        ?_assertEqual({error, empty_stap_a}, ?H264:depacketize(<<16#78>>)),
        ?_assertEqual({error, truncated}, ?H264:depacketize(<<16#78, 0, 0>>)),
        ?_assertEqual({error, {unsupported, 25}}, ?H264:depacketize(<<16#79, 0>>)),
        ?_assertEqual({error, {unsupported, 29}}, ?H264:depacketize(<<16#7D, 0>>)),
        ?_assertEqual({error, {bad_nal_type, 0}}, ?H264:depacketize(<<16#00, 0>>)),
        ?_assertEqual({error, {bad_nal_type, 30}}, ?H264:depacketize(<<16#1E, 0>>)),
        ?_test(never_crashes(fun ?H264:depacketize/1, hd(?H264:packetize([sps(), pps(), idr(5)], 1200)))),
        ?_test(never_crashes(fun ?H264:is_keyframe/1, hd(?H264:packetize([idr(3000)], 1200))))
    ].
