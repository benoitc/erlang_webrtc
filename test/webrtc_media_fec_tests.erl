%% ULPFEC (RFC 5109) in RED between two media sessions: video goes in
%% RED, FEC packets follow each frame, and the receiver gets lost
%% packets back without a retransmission.
-module(webrtc_media_fec_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

jsep() ->
    webrtc_jsep:new(#{ice_ufrag => <<"ufrag">>, ice_pwd => <<"passwordpasswordpassword">>,
                      fingerprints => [{sha256, crypto:strong_rand_bytes(32)}], frames => true}).

wire(Sdp) -> {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)), P.

pair(Fec) ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(video, #{}, jsep()),
    {ok, O, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, A2} = webrtc_jsep:set_local_description(offer, O, A1),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(O), jsep()),
    {ok, Ans, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Ans, B2),
    {ok, A3} = webrtc_jsep:set_remote_description(answer, wire(Ans), A2),
    #{media := MA} = webrtc_jsep:negotiated(A3),
    #{media := MB} = webrtc_jsep:negotiated(B3),
    Profile = srtp_aead_aes_128_gcm,
    K = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA = webrtc_media:set_srtp(Profile, K, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{video_fec => Fec}))),
    SB = webrtc_media:set_srtp(Profile, K, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{}))),
    {SA, SB}.

%% Send the corpus's VP8 frames; Drop(N) for the Nth datagram A sends.
run(Fec, Drop) ->
    {SA0, SB0} = pair(Fec),
    Frames = webrtc_test_frames:frames(vp8),
    {_, SB, Acts, N} = lists:foldl(
        fun({I, #{data := D, key := Key}}, {SA, SB, Acc, N0}) ->
            {ok, Out, SA1} = webrtc_media:send_frame(<<"0">>, D, #{timestamp => 1000 + I * 3000, keyframe => Key}, I * 33, SA),
            {Kept, N1} = lists:foldl(fun({send, _} = X, {K, Nn}) -> {[X || not Drop(Nn)] ++ K, Nn + 1};
                                        (_, Acc1) -> Acc1 end, {[], N0}, Out),
            {SB1, A} = deliver(lists:reverse(Kept), I * 33, SB),
            {SA1, SB1, Acc ++ A, N1}
        end,
        {SA0, SB0, [], 0},
        lists:enumerate(0, Frames)
    ),
    {SB2, A2} = timers(5000, SB),
    {[F || {event, {frame, _, F}} <- Acts ++ A2], N, SB2}.

deliver(Sends, Now, S0) ->
    {S1, A} = lists:foldl(fun({send, B}, {S, Acc}) -> {S2, A1} = webrtc_media:handle_packet(B, Now, S), {S2, Acc ++ A1} end,
                          {S0, []}, Sends),
    {S2, A2} = timers(Now, S1),
    {S2, A ++ A2}.

timers(Now, S) ->
    case webrtc_media:next_timeout(S) of
        T when is_integer(T), T =< Now -> {S1, A} = webrtc_media:handle_timeout(T, S), {S2, A2} = timers(Now, S1), {S2, A ++ A2};
        _ -> {S, []}
    end.

counter(K, S) -> maps:get(K, maps:get(counters, webrtc_media:stats(S)), 0).

%% One datagram in seven lost, one FEC packet for two: every frame
%% comes out, put back by FEC.
recovery_test() ->
    {Frames, Sent, SB} = run(0.5, fun(N) -> N rem 7 =:= 3 end),
    ?assert(Sent > 20),
    ?assertEqual([D || #{data := D} <- webrtc_test_frames:frames(vp8)], [D || #{data := D} <- Frames]),
    ?assert(counter(fec_recovered, SB) >= 3),
    [#{fec := #{fec_packets_received := R, packets_recovered := Rec}}] =
        [X || _ := #{fec := _} = X <- maps:get(receivers, webrtc_media:stats(SB))],
    ?assert(R > 0 andalso Rec =:= counter(fec_recovered, SB)),
    %% Recovered packets are not received ones: the receiver reports them
    %% lost, so the sender keeps sending FEC.
    [#{lost := Lost}] = [X || _ := #{fec := _} = X <- maps:get(receivers, webrtc_media:stats(SB))],
    ?assert(Lost >= Rec).

%% No FEC: the same losses cost frames.
without_fec_test() ->
    {Frames, _, SB} = run(0.0, fun(N) -> N rem 7 =:= 3 end),
    ?assert(length(Frames) < 12),
    ?assertEqual(0, counter(fec_recovered, SB)).

%% Nothing lost: all frames, the FEC packets discarded.
no_loss_test() ->
    {Frames, _, SB} = run(0.5, fun(_) -> false end),
    ?assertEqual(12, length(Frames)),
    [#{fec := #{fec_packets_discarded := D, fec_packets_received := R}}] =
        [X || _ := #{fec := _} = X <- maps:get(receivers, webrtc_media:stats(SB))],
    ?assertEqual(R, D).
