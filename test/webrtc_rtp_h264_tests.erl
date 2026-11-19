%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for webrtc_rtp_h264 (RFC 6184, packetization-modes 1 and 2).
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
        ?_test(
            never_crashes(
                fun ?H264:depacketize/1, hd(?H264:packetize([sps(), pps(), idr(5)], 1200))
            )
        ),
        ?_test(never_crashes(fun ?H264:is_keyframe/1, hd(?H264:packetize([idr(3000)], 1200))))
    ].

%%--------------------------------------------------------------------
%% Interleaved mode (packetization-mode 2)
%%--------------------------------------------------------------------

slice(N, Fill) -> <<16#41, (binary:copy(<<Fill>>, N))/binary>>.

%% §5.7.1: small units share a STAP-B numbered from its DON; a unit
%% alone is a STAP-B too (§6.4).
stap_b_test() ->
    {[Stap], 12} = ?H264:packetize_interleaved([sps(), pps(), idr(20)], 1200, 9),
    <<_:1, 3:2, 25:5, 9:16, Rest/binary>> = Stap,
    ?assertEqual(<<9:16, (sps())/binary, 4:16, (pps())/binary, 21:16, (idr(20))/binary>>, Rest),
    ?assertEqual({ok, [#{nal => sps(), don => 9, ts_offset => 0}, #{nal => pps(), don => 10, ts_offset => 0},
                       #{nal => idr(20), don => 11, ts_offset => 0}]},
                 ?H264:depacketize_interleaved(Stap)),
    {[Alone], 0} = ?H264:packetize_interleaved([slice(10, 1)], 1200, 65535),
    ?assertMatch(<<_:3, 25:5, 65535:16, 11:16, _/binary>>, Alone).

%% §5.8: a large unit becomes an FU-B with its DON, then FU-A.
fu_b_test() ->
    Nal = idr(3000),
    {[First | Rest], 6} = ?H264:packetize_interleaved([Nal], 1200, 5),
    ?assertMatch(<<_:3, 29:5, 1:1, 0:1, 0:1, 5:5, 5:16, _/binary>>, First),
    ?assert(lists:all(fun(P) -> byte_size(P) =< 1200 end, [First | Rest])),
    ?assert(lists:all(fun(<<_:3, T:5, _/binary>>) -> T =:= 28 end, Rest)),
    %% Just over a STAP-B: still two fragments, S and E apart.
    {[A, B], _} = ?H264:packetize_interleaved([slice(1196, 2)], 1200, 0),
    ?assertMatch({fragment, start, _, 0, _}, ?H264:depacketize_interleaved(A)),
    ?assertMatch({fragment, 'end', _, _}, ?H264:depacketize_interleaved(B)).

%% §5.7.2: DONB is the first in decoding order, DOND and the timestamp
%% offset are per unit.
mtap_test() ->
    Units = [{slice(5, 1), 102, 0}, {slice(6, 2), 100, 3000}, {slice(7, 3), 101, 6000}],
    {ok, M16} = ?H264:mtap(Units, 16),
    ?assertMatch(<<_:3, 26:5, 100:16, 6:16, 2:8, 0:16, _/binary>>, M16),
    ?assertEqual({ok, [#{nal => N, don => D, ts_offset => O} || {N, D, O} <- Units]}, ?H264:depacketize_interleaved(M16)),
    {ok, M24} = ?H264:mtap([{slice(5, 1), 65535, 70000}, {slice(5, 2), 0, 0}], 24),
    ?assertEqual({ok, [#{nal => slice(5, 1), don => 65535, ts_offset => 70000}, #{nal => slice(5, 2), don => 0, ts_offset => 0}]},
                 ?H264:depacketize_interleaved(M24)),
    ?assertEqual({error, badarg}, ?H264:mtap([{slice(5, 1), 0, 70000}], 16)),
    ?assertEqual({error, badarg}, ?H264:mtap([{slice(5, 1), 0, 0}, {slice(5, 1), 300, 0}], 16)).

%% §7.2: units leave in decoding order once depth + 1 VCL units wait.
deinterleave_test() ->
    Nals = [slice(10, I) || I <- lists:seq(1, 6)],
    {[P1], _} = ?H264:packetize_interleaved(lists:sublist(Nals, 4, 3), 1200, 3),
    {[P0], _} = ?H264:packetize_interleaved(lists:sublist(Nals, 1, 3), 1200, 0),
    %% Sent in the other order.
    D0 = ?H264:deinterleaver_new(3),
    {ok, [], D1} = ?H264:deinterleaver_push(1, P1, D0),
    {ok, Out, D2} = ?H264:deinterleaver_push(2, P0, D1),
    {Rest, _} = ?H264:deinterleaver_flush(D2),
    ?assertEqual(Nals, Out ++ Rest),
    %% Release stops below depth + 1 VCL units: three leave.
    ?assertEqual(lists:sublist(Nals, 3), Out).

%% FU-B and FU-A fragments rebuild the unit with the FU-B's DON; a gap
%% drops it.
deinterleave_fragments_test() ->
    Nal = idr(3000),
    {Pkts, _} = ?H264:packetize_interleaved([Nal, slice(5, 9)], 1200, 40),
    D = lists:foldl(fun({Seq, P}, Acc) -> {ok, _, A} = ?H264:deinterleaver_push(Seq, P, Acc), A end,
                    ?H264:deinterleaver_new(5), lists:enumerate(Pkts)),
    ?assertEqual({[Nal, slice(5, 9)], element(2, ?H264:deinterleaver_flush(D))}, ?H264:deinterleaver_flush(D)),
    [F, _Lost | More] = Pkts,
    {ok, [], D1} = ?H264:deinterleaver_push(1, F, ?H264:deinterleaver_new(0)),
    ?assertMatch({error, lost_fragment, _}, ?H264:deinterleaver_push(3, hd(More), D1)).

interleaved_errors_test_() ->
    [
        ?_assertEqual({error, empty}, ?H264:depacketize_interleaved(<<>>)),
        ?_assertEqual({error, {not_interleaved, 24}}, ?H264:depacketize_interleaved(<<16#78, 0, 1, 1>>)),
        ?_assertEqual({error, {not_interleaved, 1}}, ?H264:depacketize_interleaved(slice(3, 1))),
        ?_assertEqual({error, bad_fu_a}, ?H264:depacketize_interleaved(<<16#7C, 16#85, 1>>)),
        ?_assertEqual({error, empty_mtap}, ?H264:depacketize_interleaved(<<16#7A, 0, 0>>)),
        ?_assertEqual({error, truncated}, ?H264:depacketize_interleaved(<<16#7A, 0, 0, 0, 9, 0, 0>>)),
        ?_test(never_crashes(fun ?H264:depacketize_interleaved/1, element(2, ?H264:mtap([{slice(20, 1), 3, 9}], 24))))
    ].

%% A picture order count cycle of 2^31 - 1 frames in 13 bytes: §7.4.2.1.1
%% allows 255. Parsed in a process with a 100,000 word heap limit.
sps_poc_cycle_bound_test() ->
    %% id 0, log2_max_frame_num 0, poc type 1, delta_pic_order_always_zero,
    %% two offsets of 0, then the cycle length.
    Bits = <<1:1, 1:1, 2#010:3, 0:1, 1:1, 1:1, 0:31, 1:1, 0:31, 0:1>>,
    Sps = <<16#67, 66, 0, 30, Bits/bitstring>>,
    ?assert(is_binary(Sps)),
    Self = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        process_flag(max_heap_size, #{size => 100000, kill => true, error_logger => false}),
        Self ! {self(), webrtc_rtp_h264:sps_size(Sps)}
    end),
    receive
        {Pid, R} -> ?assertEqual(error, R);
        {'DOWN', Ref, process, Pid, Why} -> ?assertEqual(answered, Why)
    after 5000 ->
        ?assert(false)
    end.

%% Fields beyond their §7.4.2.1.1 range are refused.
sps_field_ranges_test() ->
    Ue = fun(V) -> N = length(integer_to_list(V + 1, 2)), <<0:(N - 1), (V + 1):N>> end,
    Sps = fun(Fields) ->
              Body = << <<F/bitstring>> || F <- Fields >>,
              Pad = (8 - bit_size(Body) rem 8) rem 8,
              <<16#67, 66, 0, 30, Body/bitstring, 0:Pad>>
          end,
    %% id, log2_max_frame_num_minus4, poc type 2, refs, gaps, w, h,
    %% frame_mbs_only, direct8x8, crop, vui, stop bit.
    Good = fun(Id, Refs, W) -> Sps([Ue(Id), Ue(0), Ue(2), Ue(Refs), <<0:1>>, Ue(W), Ue(10), <<1:1, 0:1, 0:1, 0:1, 1:1>>]) end,
    ?assertEqual({ok, {320, 176}}, webrtc_rtp_h264:sps_size(Good(0, 1, 19))),
    ?assertEqual(error, webrtc_rtp_h264:sps_size(Good(32, 1, 19))),
    ?assertEqual(error, webrtc_rtp_h264:sps_size(Good(0, 17, 19))),
    ?assertEqual({ok, {1056 * 16, 176}}, webrtc_rtp_h264:sps_size(Good(0, 1, 1055))),
    ?assertEqual(error, webrtc_rtp_h264:sps_size(Good(0, 1, 2048))).
