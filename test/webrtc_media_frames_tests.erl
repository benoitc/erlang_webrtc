%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% `frames' on a transceiver: the receiving media session delivers
%% frames from its buffer (webrtc_frame_buffer) instead of packets, and
%% asks for a key frame with the request the stream negotiated.
-module(webrtc_media_frames_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").

jsep(Extra) ->
    webrtc_jsep:new(maps:merge(#{
        ice_ufrag => <<"ufrag">>,
        ice_pwd => <<"passwordpasswordpassword">>,
        fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]
    }, Extra)).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

%% A sends audio and video; B receives. `BOpts' are B's JSEP options:
%% its transceivers come from A's offer.
pair(AOpts, BOpts) ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, jsep(AOpts)),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, O, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, O, A2),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(O), jsep(BOpts)),
    {ok, Ans, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Ans, B2),
    {ok, A4} = webrtc_jsep:set_remote_description(answer, wire(Ans), A3),
    #{media := MA} = webrtc_jsep:negotiated(A4),
    #{media := MB} = webrtc_jsep:negotiated(B3),
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{cname => <<"a">>}))),
    SB = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{cname => <<"b">>}))),
    {SA, SB}.

%% Send the VP8 frames of the corpus from A at 33 ms intervals, minus
%% the packets `Drop' says; B takes them at once and runs its timers.
send_vp8(SA0, SB0, Drop) ->
    Frames = webrtc_test_frames:frames(vp8),
    {_, SA, SB, Acts} = lists:foldl(
        fun({I, #{data := D}}, {_, SA1, SB1, Acc}) ->
            Now = I * 33,
            Payloads = webrtc_rtp_vp8:packetize(D, 1000, #{picture_id => I}),
            N = length(Payloads),
            {SA2, Out} = lists:foldl(
                fun({J, P}, {S, O}) ->
                    {ok, O1, S1} = webrtc_media:send(<<"1">>, P, #{timestamp => 1000 + I * 3000, marker => J =:= N,
                                                                   codec => <<"VP8">>}, Now, S),
                    {S1, O ++ [X || X <- O1, not Drop(I, J)]}
                end,
                {SA1, []},
                lists:enumerate(Payloads)
            ),
            {SB2, A1} = run(Now, Out, SB1),
            {I, SA2, SB2, Acc ++ A1}
        end,
        {0, SA0, SB0, []},
        lists:enumerate(0, Frames)
    ),
    {SB3, A2} = run(5000, [], SB),
    {SA, SB3, Acts ++ A2}.

run(Now, Sends, S0) ->
    {S1, A1} = lists:foldl(
        fun({send, Bin}, {S, A}) -> {S2, A2} = webrtc_media:handle_packet(Bin, Now, S), {S2, A ++ A2};
           (_, Acc) -> Acc
        end,
        {S0, []},
        Sends
    ),
    timers(Now, S1, A1).

timers(Now, S, Acc) ->
    case webrtc_media:next_timeout(S) of
        T when is_integer(T), T =< Now ->
            {S1, A} = webrtc_media:handle_timeout(T, S),
            timers(Now, S1, Acc ++ A);
        _ ->
            {S, Acc}
    end.

frames_test() ->
    {SA, SB} = pair(#{}, #{frames => true}),
    {_, _, Acts} = send_vp8(SA, SB, fun(_, _) -> false end),
    Frames = [F || {event, {frame, <<"1">>, F}} <- Acts],
    ?assertEqual([D || #{data := D} <- webrtc_test_frames:frames(vp8)], [D || #{data := D} <- Frames]),
    ?assertMatch([#{keyframe := true, width := 176, height := 144, codec := <<"VP8">>, timestamp := 1000} | _], Frames),
    ?assertEqual([], [x || {event, {rtp, <<"1">>, _}} <- Acts]).

%% The receiver's statistics carry the buffer's.
stats_test() ->
    {SA, SB} = pair(#{}, #{frames => true}),
    {_, SB1, _} = send_vp8(SA, SB, fun(_, _) -> false end),
    #{receivers := Rs} = webrtc_media:stats(SB1),
    [#{frames := #{frames_received := 12, frame_width := 176}}] = [R || _ := #{mid := <<"1">>} = R <- Rs].

%% Without the option, packets as before.
packets_without_option_test() ->
    {SA, SB} = pair(#{}, #{}),
    {_, _, Acts} = send_vp8(SA, SB, fun(_, _) -> false end),
    ?assertEqual([], [x || {event, {frame, _, _}} <- Acts]),
    ?assert(length([x || {event, {rtp, <<"1">>, _}} <- Acts]) >= 12).

%% A delta frame lost: B asks for a key frame with a PLI.
pli_on_loss_test() ->
    {SA, SB} = pair(#{}, #{frames => true}),
    {_, SB1, Acts} = send_vp8(SA, SB, fun(I, _) -> I =:= 2 end),
    #{pli := Pli, fir := Fir} = requests(SB1),
    ?assert(Pli >= 1),
    ?assertEqual(0, Fir),
    ?assertEqual(8, length([F || {event, {frame, <<"1">>, F}} <- Acts])).

%% Only `ccm fir' negotiated: a FIR, with a new sequence number each
%% time (RFC 5104 §4.3.1.2).
fir_only_test() ->
    Caps = #{video => [C#{rtcp_fb => [F || #{type := T, param := P} = F <- Fb, {T, P} =/= {<<"nack">>, <<"pli">>}]}
                       || #{rtcp_fb := Fb} = C <- webrtc_jsep_caps:default_codecs(video)]},
    {SA, SB} = pair(#{codecs => Caps}, #{codecs => Caps, frames => true}),
    {_, SB1, _} = send_vp8(SA, SB, fun(I, _) -> I =:= 2 end),
    #{pli := Pli, fir := Fir} = requests(SB1),
    ?assertEqual(0, Pli),
    ?assert(Fir >= 1),
    [Ssrc] = [S || S := #{mid := <<"1">>} <- maps:get(receivers, webrtc_media:stats(SB1))],
    {[#rtcp_fir{entries = [{Ssrc, N}]}], SB2} = webrtc_media_in:keyframe_feedback(Ssrc, SB1),
    {[#rtcp_fir{entries = [{Ssrc, N1}]}], _} = webrtc_media_in:keyframe_feedback(Ssrc, SB2),
    ?assertEqual(Fir, N),
    ?assertEqual((N + 1) band 255, N1).

%% The application asks: the same choice.
application_request_fir_test() ->
    Caps = #{video => [C#{rtcp_fb => [F || #{type := T, param := P} = F <- Fb, {T, P} =/= {<<"nack">>, <<"pli">>}]}
                       || #{rtcp_fb := Fb} = C <- webrtc_jsep_caps:default_codecs(video)]},
    {SA, SB} = pair(#{codecs => Caps}, #{codecs => Caps}),
    {_, SB1, _} = send_vp8(SA, SB, fun(_, _) -> false end),
    {_, SB2} = webrtc_media:request_keyframe(<<"1">>, 6000, SB1),
    ?assertMatch(#{pli := 0, fir := 1}, requests(SB2)).

%% PLI and FIR sent for the video stream.
requests(S) ->
    #{streams := St} = webrtc_media:stats(S),
    In = [V || {in, _} := V <- St],
    #{pli => lists:sum([maps:get(pli_count, V, 0) || V <- In]), fir => lists:sum([maps:get(fir_count, V, 0) || V <- In])}.

%% send_frame/5: each codec's frames split by its payload format, put
%% back together by the receiver.
send_frame_test_() ->
    [{atom_to_list(C), fun() ->
        {SA0, SB0} = pair(#{}, #{frames => true}),
        Frames = webrtc_test_frames:frames(C),
        {_, _, Acts} = lists:foldl(
            fun({I, #{data := D0, key := K}}, {SA, SB, Acc}) ->
                D = case C of h264 -> iolist_to_binary([[<<0, 0, 0, 1>>, N] || N <- D0]); _ -> D0 end,
                {ok, Out, SA1} = webrtc_media:send_frame(<<"1">>, D, #{timestamp => 1000 + I * 3000, keyframe => K,
                                                                      codec => webrtc_test_frames:name(C)}, I * 33, SA),
                {SB1, A} = run(I * 33, Out, SB),
                {SA1, SB1, Acc ++ A}
            end,
            {SA0, SB0, []},
            lists:enumerate(0, Frames)
        ),
        Got = [F || {event, {frame, <<"1">>, F}} <- Acts],
        Same = fun(#{expect := E}, #{data := D}) ->
                   case C of av1 -> webrtc_rtp_av1:obus(E) =:= webrtc_rtp_av1:obus(D); _ -> E =:= D end
               end,
        ?assertEqual(length(Frames), length(Got)),
        ?assert(lists:all(fun({E, G}) -> Same(E, G) end, lists:zip(Frames, Got)))
    end} || C <- [vp8, vp9, h264, av1]].

%% A padding-only packet on the media stream (what a sender's bandwidth
%% probes are without RTX) between the frames: its sequence number is no
%% gap, so codecs without picture IDs lose no frame.
padding_between_frames_test_() ->
    [{atom_to_list(C), fun() ->
        {SA0, SB0} = pair(#{}, #{frames => true}),
        Frames = webrtc_test_frames:frames(C),
        {_, _, Acts} = lists:foldl(
            fun({I, #{expect := D, key := K}}, {SA, SB, Acc}) ->
                Ts = 1000 + I * 3000,
                {ok, Out, SA1} = webrtc_media:send_frame(<<"1">>, D, #{timestamp => Ts, keyframe => K,
                                                                      codec => webrtc_test_frames:name(C)}, I * 33, SA),
                {SB1, A} = run(I * 33, Out, SB),
                Pad = #rtp{pt = pt(C, SA1), ts = Ts, payload = <<>>, padding = 200},
                {ok, PadOut, SA2} = webrtc_media:send_packet(<<"1">>, Pad, I * 33 + 10, SA1),
                {SB2, A2} = run(I * 33 + 10, PadOut, SB1),
                {SA2, SB2, Acc ++ A ++ A2}
            end,
            {SA0, SB0, []},
            lists:enumerate(0, Frames)
        ),
        Got = [F || {event, {frame, <<"1">>, F}} <- Acts],
        ?assertEqual(length(Frames), length(Got)),
        ?assertEqual([], [R || {event, {keyframe_request, _} = R} <- Acts])
    end} || C <- [vp8, vp9, h264, av1]].

%% The payload type of codec `C': both sides use the default codecs.
pt(C, _S) ->
    Name = webrtc_test_frames:name(C),
    hd([Pt || #{name := N, pt := Pt} <- webrtc_jsep_caps:default_codecs(video), N =:= Name]).
