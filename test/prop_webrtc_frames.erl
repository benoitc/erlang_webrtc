%% PropEr properties of the frame buffer (webrtc_frame_buffer) over the
%% frames of real encoders (test/corpora/frames): packets reordered,
%% repeated and lost at random.
-module(prop_webrtc_frames).
-include_lib("proper/include/proper.hrl").
-include("webrtc_rtp.hrl").

-export([prop_frames_survive_network/0, prop_garbage_never_crashes/0]).

-define(F, webrtc_test_frames).

codec() -> oneof([vp8, vp9, h264, av1]).

%% Per packet: a delay up to 40 ms, dropped or not, repeated or not.
fates(N) -> vector(N, {integer(0, 40), frequency([{12, keep}, {1, drop}]), frequency([{8, once}, {1, twice}])}).

network() ->
    ?LET({Codec, Mtu}, {codec(), integer(120, 1200)},
         begin
             Pkts = ?F:packets(Codec, ?F:frames(Codec), #{mtu => Mtu}),
             N = length(lists:append([Ps || {_, Ps} <- Pkts])),
             {Codec, Mtu, fates(N)}
         end).

%% Every frame that comes out is the one sent, byte for byte, in order:
%% a frame that lost a packet comes out only when what it lost can be
%% put back (H.264 parameter sets seen before). A delta frame comes out
%% only after the frame before it; with nothing lost, every frame comes
%% out and no key frame is asked for.
prop_frames_survive_network() ->
    ?FORALL({Codec, Mtu, Fates}, network(),
        begin
            Frames = ?F:frames(Codec),
            Pkts = ?F:packets(Codec, Frames, #{mtu => Mtu}),
            Flat = lists:append([[{I, J, P} || {J, P} <- lists:enumerate(0, Ps)] || {I, Ps} <- Pkts]),
            Sent = lists:zip(Flat, Fates),
            Lost = lists:usort([I || {{I, _, _}, {_, drop, _}} <- Sent]),
            Arr = lists:keysort(1, lists:append(
                [[{I * 33 + J + D, P} || Fate =/= drop] ++ [{I * 33 + J + D + 7, P} || Fate =/= drop, Twice =:= twice]
                 || {{I, J, P}, {D, Fate, Twice}} <- Sent])),
            {Out, Req, _} = ?F:run(Arr, #{codecs => [#{pt => 96, name => ?F:name(Codec)}]}),
            Index = fun(#{timestamp := Ts}) -> (Ts - 1000) div 3000 end,
            Got = [Index(F) || {_, F} <- Out],
            Keys = [I || {I, #{key := true}} <- lists:enumerate(0, Frames)],
            Same = lists:all(fun({_, #{data := D} = F}) ->
                                 #{expect := E} = lists:nth(Index(F) + 1, Frames),
                                 same(Codec, E, D)
                             end, Out),
            Chained = lists:all(fun(I) -> lists:member(I, Keys) orelse lists:member(I - 1, Got) end, Got),
            ?WHENFAIL(io:format("~p mtu ~p lost ~p got ~p requests ~p~n", [Codec, Mtu, Lost, Got, Req]),
                      Same andalso Got =:= lists:usort(Got) andalso Chained andalso
                          (Codec =:= h264 orelse [I || I <- Got, lists:member(I, Lost)] =:= []) andalso
                          (Lost =/= [] orelse (Got =:= lists:seq(0, length(Frames) - 1) andalso Req =:= 0)))
        end).

same(av1, A, B) -> webrtc_rtp_av1:obus(A) =:= webrtc_rtp_av1:obus(B);
%% An SEI lost before the slices is not needed to decode them.
same(h264, A, B) -> no_sei(A) =:= no_sei(B);
same(_, A, B) -> A =:= B.

no_sei(Bin) -> [N || N <- webrtc_rtp_h264:split_annexb(Bin), webrtc_rtp_h264:nal_type(N) =/= 6].

%% Arbitrary payloads, sequence numbers and timestamps: no crash, the
%% buffer stays bounded.
prop_garbage_never_crashes() ->
    ?FORALL(Pkts, list({integer(0, 3), integer(0, 65535), integer(0, 16#FFFFFFFF), boolean(), binary()}),
        begin
            Fb0 = webrtc_frame_buffer:new(#{codecs => [#{pt => 96, name => <<"VP8">>}, #{pt => 97, name => <<"VP9">>},
                                                       #{pt => 98, name => <<"H264">>}, #{pt => 99, name => <<"AV1">>}],
                                            nack => true}),
            {_, Fb} = lists:foldl(
                fun({{Pt, Seq, Ts, M, P}, I}, {_, F}) ->
                    {_, F1} = webrtc_frame_buffer:push(#rtp{pt = 96 + Pt, seq = Seq, ts = Ts, marker = M, ssrc = 1,
                                                            payload = P}, I, #{}, F),
                    {_, F2} = webrtc_frame_buffer:timeout(I + 5000, F1),
                    {ok, F2}
                end, {ok, Fb0}, lists:zip(Pkts, lists:seq(1, length(Pkts)))),
            maps:get(buffered_packets, webrtc_frame_buffer:stats(Fb)) =< 2048
        end).
