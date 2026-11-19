%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Frame assembly and jitter buffer (webrtc_frame_buffer): frames of
%% real encoders (test/corpora/frames) packetized by our packetizers,
%% then reordered, repeated, lost and repaired.
-module(webrtc_frame_buffer_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

-define(F, webrtc_test_frames).
-define(CODECS, [vp8, vp9, h264, av1]).

opts(Codec) -> #{codecs => [#{pt => 96, name => ?F:name(Codec)}]}.

%% One frame every 33 ms, its packets 1 ms apart.
arrivals(Pkts) ->
    lists:append([[{I * 33 + J, P} || {J, P} <- lists:enumerate(0, Ps)] || {I, Ps} <- Pkts]).

same(av1, A, B) -> webrtc_rtp_av1:obus(A) =:= webrtc_rtp_av1:obus(B);
same(_, A, B) -> A =:= B.

check_frames(Codec, Expected, Got) ->
    ?assertEqual(length(Expected), length(Got)),
    lists:foreach(
        fun({#{expect := E, key := K}, #{data := D, keyframe := K2}}) ->
            ?assert(same(Codec, E, D)),
            ?assertEqual(K, K2)
        end,
        lists:zip(Expected, Got)
    ).

dims(vp8) -> {176, 144};
dims(vp9) -> {176, 144};
dims(h264) -> {174, 130};
dims(av1) -> {176, 144}.

in_order_test_() ->
    [{atom_to_list(C), fun() ->
        Frames = ?F:frames(C),
        {Out, Req, Stats} = ?F:run(arrivals(?F:packets(C, Frames)), opts(C)),
        Got = [F || {_, F} <- Out],
        check_frames(C, Frames, Got),
        {W, H} = dims(C),
        ?assert(lists:all(fun(#{width := W1, height := H1}) -> {W1, H1} =:= {W, H} end, Got)),
        ?assertEqual(0, Req),
        ?assertMatch(#{frames_dropped := 0, frames_received := 12, jitter_buffer_emitted_count := 12,
                       frame_width := W, frame_height := H}, Stats)
    end} || C <- ?CODECS].

%% Packets reordered within 8 places and a fifth of them twice: the same
%% frames come out.
reorder_and_duplicates_test_() ->
    [{atom_to_list(C), fun() ->
        Frames = ?F:frames(C),
        rand:seed(exsss, {1, 2, 3}),
        Arr = arrivals(?F:packets(C, Frames)),
        Shuffled = [{T + rand:uniform(8), P} || {T, P} <- Arr],
        Dups = [{T + 5, P} || {T, P} <- Shuffled, rand:uniform(5) =:= 1],
        {Out, Req, Stats} = ?F:run(lists:keysort(1, Shuffled ++ Dups), opts(C)),
        check_frames(C, Frames, [F || {_, F} <- Out]),
        ?assertEqual(0, Req),
        ?assertEqual(length(Dups), maps:get(duplicates, Stats, 0) + maps:get(packets_discarded, Stats, 0))
    end} || C <- ?CODECS].

%% A packet of frame 2 lost and no NACK: frames 2 to 5 depend on it and
%% are dropped, one key frame is requested, frame 6 starts again.
loss_breaks_chain_test_() ->
    [{atom_to_list(C), fun() ->
        Frames = ?F:frames(C),
        Pkts = ?F:packets(C, Frames),
        {2, [_ | _] = F2} = lists:keyfind(2, 1, Pkts),
        Lost = (lists:last(F2))#rtp.seq,
        Arr = [X || {_, #rtp{seq = S}} = X <- arrivals(Pkts), S =/= Lost],
        {Out, Req, Stats} = ?F:run(Arr, opts(C)),
        Kept = [F || {I, F} <- lists:enumerate(0, Frames), I < 2 orelse I >= 6],
        check_frames(C, Kept, [F || {_, F} <- Out]),
        ?assert(Req >= 1),
        %% Frame 2, or what is left of it, and the three after it.
        ?assert(lists:member(maps:get(frames_dropped, Stats), [3, 4]))
    end} || C <- ?CODECS].

%% With NACK the lost packet comes back 250 ms later, within three round
%% trips: nothing is dropped.
retransmission_test_() ->
    [{atom_to_list(C), fun() ->
        Frames = ?F:frames(C),
        Pkts = ?F:packets(C, Frames),
        {2, F2} = lists:keyfind(2, 1, Pkts),
        Lost = (hd(F2))#rtp.seq,
        Arr = [case X of {T, #rtp{seq = Lost}} -> {T + 250, P}; _ -> X end || {_, P} = X <- arrivals(Pkts)],
        {Out, Req, _} = ?F:run(lists:keysort(1, Arr), (opts(C))#{nack => true}),
        check_frames(C, Frames, [F || {_, F} <- Out]),
        ?assertEqual(0, Req)
    end} || C <- ?CODECS].

%% NACK gave up on the packet: the frame goes without waiting.
lost_report_test() ->
    Frames = ?F:frames(vp8),
    Pkts = ?F:packets(vp8, Frames),
    {2, F2} = lists:keyfind(2, 1, Pkts),
    #rtp{seq = Lost} = hd(F2),
    Arr = [X || {_, #rtp{seq = S}} = X <- arrivals(Pkts), S =/= Lost],
    %% Reported lost when frame 3 arrives.
    {3, [#rtp{seq = S3} | _]} = lists:keyfind(3, 1, Pkts),
    {Before, After} = lists:splitwith(fun({_, #rtp{seq = S}}) -> S =/= S3 end, Arr),
    {T3, _} = hd(After),
    {Out, Req, _} = ?F:run(Before ++ [{T3, {lost, [Lost]}} | After], (opts(vp8))#{nack => true, min_delay => 500}),
    ?assertEqual(8, length(Out)),
    ?assert(Req >= 1),
    %% Frame 6 (key) did not wait for three round trips past frame 3.
    [_, {T6, _} | _] = [X || {_, #{keyframe := true}} = X <- Out],
    ?assert(T6 < 6 * 33 + 500 + 50).

%% VP8 temporal layers (RFC 7741 §4.2): a lost frame of layer 2 takes
%% nothing with it and asks for no key frame; a lost base frame does.
temporal_layers_test() ->
    Frames = ?F:frames(vp8),
    Tid = fun(I) -> element((I rem 4) + 1, {0, 2, 1, 2}) end,
    Extra = fun(I) -> #{tid => Tid(I), tl0picidx => (I div 4) band 255} end,
    Pkts = ?F:packets(vp8, Frames, #{extra => Extra}),
    Drop = fun(N) ->
        {N, Ps} = lists:keyfind(N, 1, Pkts),
        Seqs = [S || #rtp{seq = S} <- Ps],
        [X || {_, #rtp{seq = S}} = X <- arrivals(Pkts), not lists:member(S, Seqs)]
    end,
    %% Frame 3 is on layer 2.
    {Out1, Req1, _} = ?F:run(Drop(3), opts(vp8)),
    ?assertEqual(11, length(Out1)),
    ?assertEqual(0, Req1),
    %% Frame 2 is on layer 1: frame 3 (layer 2, after it) goes too, the
    %% base frame 4 does not.
    {Out2, Req2, _} = ?F:run(Drop(2), opts(vp8)),
    ?assertEqual([0, 1, 4, 5, 6, 7, 8, 9, 10, 11], [I || {_, #{timestamp := Ts}} <- Out2, I <- [(Ts - 1000) div 3000]]),
    ?assertEqual(0, Req2),
    %% Frame 4 is a base frame: frame 5 (layer 2) cannot be decoded
    %% either; the key frame 6 starts again.
    {Out3, _, _} = ?F:run(Drop(4), opts(vp8)),
    ?assertEqual([0, 1, 2, 3, 6, 7, 8, 9, 10, 11], [(Ts - 1000) div 3000 || {_, #{timestamp := Ts}} <- Out3]),
    %% Without that key frame, the next base frame (8) asks for one.
    Drop6 = [X || {_, #rtp{seq = S}} = X <- Drop(4),
                  not lists:member(S, [S6 || #rtp{seq = S6} <- element(2, lists:keyfind(6, 1, Pkts))])],
    {Out4, Req4, _} = ?F:run(Drop6, opts(vp8)),
    ?assertEqual([0, 1, 2, 3], [(Ts - 1000) div 3000 || {_, #{timestamp := Ts}} <- Out4]),
    ?assert(Req4 >= 1).

%% VP9 flexible mode (RFC 9628 §4.2): a frame waits for the pictures it
%% references, not for the others.
vp9_flexible_test() ->
    Frames = ?F:frames(vp9),
    %% Frames 1 and 2 reference the key frame, 3 to 5 reference frame 2.
    Extra = fun(I) when I rem 6 =:= 0 -> #{flexible => true};
               (I) when I rem 6 =< 2 -> #{flexible => true, refs => [I rem 6]};
               (I) -> #{flexible => true, refs => [I rem 6 - 2]}
            end,
    Pkts = ?F:packets(vp9, Frames, #{extra => Extra}),
    {2, Ps} = lists:keyfind(2, 1, Pkts),
    Seqs = [S || #rtp{seq = S} <- Ps],
    Arr = [X || {_, #rtp{seq = S}} = X <- arrivals(Pkts), not lists:member(S, Seqs)],
    {Out, Req, _} = ?F:run(Arr, opts(vp9)),
    ?assertEqual(8, length(Out)),
    ?assertEqual(1, Req),
    %% Frame 1 is referenced by none: its loss costs nothing else.
    {1, Ps1} = lists:keyfind(1, 1, Pkts),
    Seqs1 = [S || #rtp{seq = S} <- Ps1],
    {Out1, Req1, _} = ?F:run([X || {_, #rtp{seq = S}} = X <- arrivals(Pkts), not lists:member(S, Seqs1)], opts(vp9)),
    ?assertEqual(11, length(Out1)),
    ?assertEqual(0, Req1).

%% Frames leave at their playout time: arrival at the smallest transit
%% plus the target delay, here the minimum delay asked for.
playout_time_test() ->
    Frames = ?F:frames(vp8),
    {Out, _, Stats} = ?F:run(arrivals(?F:packets(vp8, Frames)), (opts(vp8))#{min_delay => 100}),
    %% Arrivals 33 ms apart for 33.3 ms of media time: the smallest
    %% transit follows the drift, by a millisecond here and there.
    Gaps = [B - A || {{A, _}, {B, _}} <- lists:zip(lists:droplast(Out), tl(Out))],
    ?assert(lists:all(fun(G) -> G >= 30 andalso G =< 36 end, Gaps)),
    ?assertEqual(100, maps:get(target_delay, Stats)),
    Mean = maps:get(jitter_buffer_delay, Stats) / maps:get(jitter_buffer_emitted_count, Stats),
    ?assert(Mean >= 0.097 andalso Mean =< 0.101).

%% The playout-delay extension from the sender raises the minimum.
playout_delay_extension_test() ->
    Frames = ?F:frames(vp8),
    Fb0 = webrtc_frame_buffer:new((opts(vp8))#{kind => video, clock_rate => 90000}),
    [{0, [P | _]} | _] = ?F:packets(vp8, Frames),
    {_, Fb1} = webrtc_frame_buffer:push(P, 0, #{playout_delay => {200, 400}}, Fb0),
    ?assertEqual(200, maps:get(target_delay, webrtc_frame_buffer:stats(Fb1))).

%% A packet of a frame that already left is late.
late_packet_test() ->
    Frames = ?F:frames(vp8),
    Arr = arrivals(?F:packets(vp8, Frames)),
    {T, P} = hd(Arr),
    {Out, _, Stats} = ?F:run(Arr ++ [{T + 2000, P#rtp{payload = P#rtp.payload}}], opts(vp8)),
    ?assertEqual(12, length(Out)),
    ?assertEqual(1, maps:get(packets_discarded, Stats)).

%% Joining after the key frame: nothing is decodable until the next one,
%% which is asked for.
join_late_test_() ->
    [{atom_to_list(C), fun() ->
        Frames = ?F:frames(C),
        Arr = [X || {T, _} = X <- arrivals(?F:packets(C, Frames)), T >= 2 * 33],
        {Out, Req, _} = ?F:run(Arr, opts(C)),
        check_frames(C, lists:nthtail(6, Frames), [F || {_, F} <- Out]),
        ?assert(Req >= 1)
    end} || C <- ?CODECS].

%% Audio: one packet is one frame, a gap is skipped.
audio_test() ->
    Pkts = [#rtp{pt = 111, seq = S, ts = S * 960, ssrc = 1, payload = <<S>>} || S <- lists:seq(1, 10), S =/= 4],
    Opts = #{kind => audio, clock_rate => 48000, codecs => [#{pt => 111, name => <<"opus">>}]},
    {Out, Req, _} = ?F:run([{S * 20, P} || #rtp{seq = S} = P <- Pkts], Opts),
    ?assertEqual([<<S>> || S <- lists:seq(1, 10), S =/= 4], [D || {_, #{data := D}} <- Out]),
    ?assertEqual(0, Req),
    ?assertNot(lists:any(fun({_, F}) -> maps:is_key(width, F) end, Out)).

%% The number of packets held is bounded.
bound_test() ->
    Opts = #{codecs => [#{pt => 96, name => <<"VP8">>}]},
    %% Frames that never complete (no marker).
    Arr = [{S, #rtp{pt = 96, seq = S, ts = S div 4, ssrc = 1, payload = <<16#10, 0, 0, 0>>}} || S <- lists:seq(1, 5000)],
    {_, _, Stats} = ?F:run(Arr, Opts),
    ?assert(maps:get(buffered_packets, Stats) =< 2048).

%%====================================================================
%% Frame sizes from the bitstream
%%====================================================================

frame_size_test_() ->
    [{atom_to_list(C), fun() ->
        [#{data := D} | _] = ?F:frames(C),
        Got = case C of
                  vp8 -> webrtc_rtp_vp8:frame_size(D);
                  vp9 -> webrtc_rtp_vp9:frame_size(D);
                  av1 -> webrtc_rtp_av1:frame_size(D);
                  h264 -> webrtc_rtp_h264:sps_size(hd([N || N <- D, webrtc_rtp_h264:nal_type(N) =:= 7]))
              end,
        ?assertEqual({ok, dims(C)}, Got)
    end} || C <- ?CODECS].

%% Delta frames carry no size.
no_size_in_delta_test() ->
    [_, #{data := D} | _] = ?F:frames(vp8),
    ?assertEqual(error, webrtc_rtp_vp8:frame_size(D)),
    [_, #{data := D9} | _] = ?F:frames(vp9),
    ?assertEqual(error, webrtc_rtp_vp9:frame_size(D9)).

%%====================================================================
%% Payload formats
%%====================================================================

vp9_descriptor_test() ->
    [P] = webrtc_rtp_vp9:packetize(<<1, 2, 3>>, 100, #{picture_id => 300, flexible => true, refs => [1, 3], tid => 1,
                                                      sid => 0, layer_sizes => [{320, 180}, {640, 360}]}),
    {ok, D, Data} = webrtc_rtp_vp9:parse_payload(P),
    ?assertEqual(<<1, 2, 3>>, Data),
    ?assertMatch(#{picture_id := {15, 300}, refs := [1, 3], tid := 1, sid := 0, flexible := true,
                   layer_sizes := [{320, 180}, {640, 360}], start := true, 'end' := true}, D).

av1_fragments_test() ->
    [#{data := Tu} | _] = ?F:frames(av1),
    Pkts = webrtc_rtp_av1:packetize(Tu, 100, #{new_sequence => true}),
    ?assert(length(Pkts) > 10),
    ?assert(webrtc_rtp_av1:is_keyframe(hd(Pkts))),
    {ok, Out} = webrtc_rtp_av1:depacketize(Pkts),
    ?assertEqual(webrtc_rtp_av1:obus(Tu), webrtc_rtp_av1:obus(Out)),
    %% A fragment without its start fails the frame.
    ?assertMatch({error, _}, webrtc_rtp_av1:depacketize(tl(Pkts))).

%% The W field: the last element has no length (AV1 RTP §4.4).
av1_obu_count_test() ->
    Obu1 = <<0:1, 6:4, 0:1, 0:1, 0:1, 1, 2, 3>>,
    Obu2 = <<0:1, 6:4, 0:1, 0:1, 0:1, 4, 5>>,
    P = <<0:1, 0:1, 2:2, 0:1, 0:3, 4, Obu1/binary, Obu2/binary>>,
    {ok, Out} = webrtc_rtp_av1:depacketize([P]),
    ?assertEqual({ok, [{2, <<>>}, {6, <<1, 2, 3>>}, {6, <<4, 5>>}]}, webrtc_rtp_av1:obus(Out)).

%% H.264 parameter sets sent before, in their own frame: put back before
%% the IDR.
h264_parameter_sets_test() ->
    [#{data := Au} | _] = ?F:frames(h264),
    {Ps, Slices} = lists:partition(fun(N) -> lists:member(webrtc_rtp_h264:nal_type(N), [7, 8]) end, Au),
    Fb0 = webrtc_frame_buffer:new((opts(h264))#{kind => video, clock_rate => 90000}),
    Mk = fun(Seq, Ts, Nal) -> #rtp{pt = 96, seq = Seq, ts = Ts, ssrc = 1, marker = true, payload = Nal} end,
    %% SPS and PPS alone in a STAP-A, then the IDR slices.
    [Stap] = webrtc_rtp_h264:packetize(Ps, 1200),
    {_, Fb1} = webrtc_frame_buffer:push(Mk(1, 0, Stap), 0, #{}, Fb0),
    Idr = webrtc_rtp_h264:packetize([N || N <- Slices, webrtc_rtp_h264:nal_type(N) =:= 5], 1200),
    Last = length(Idr),
    {A0, Fb3} = lists:foldl(
        fun({J, P}, {Acc, Fb}) ->
            {A1, Fb2} = webrtc_frame_buffer:push((Mk(1 + J, 3000, P))#rtp{marker = J =:= Last}, 33 + J, #{}, Fb),
            {Acc ++ A1, Fb2}
        end, {[], Fb1}, lists:enumerate(Idr)),
    %% The first packet received only probably starts its frame: the
    %% buffer waits for earlier ones first.
    {A2, _} = webrtc_frame_buffer:timeout(2000, Fb3),
    A = A0 ++ A2,
    [#{data := D, keyframe := true, width := 174, height := 130}] = [F || {frame, F} <- A, maps:get(keyframe, F)],
    [Sps, Pps | _] = webrtc_rtp_h264:split_annexb(D),
    ?assertEqual({7, 8}, {webrtc_rtp_h264:nal_type(Sps), webrtc_rtp_h264:nal_type(Pps)}).
