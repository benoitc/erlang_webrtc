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

%% RFC 6184 §6: send_frame/5 packetizes H.264 in the negotiated
%% packetization mode. Mode 0 allows single NAL unit packets only
%% (types 1 to 23, §6.2), mode 2 STAP-B, MTAP and FU packets only
%% (§6.4); mode 1 aggregates and fragments with STAP-A and FU-A.
h264_mode(Mode) ->
    [Base | _] = [C || #{name := <<"H264">>} = C <- webrtc_jsep_caps:default_codecs(video)],
    Fmtp = lists:keystore(<<"packetization-mode">>, 1, maps:get(fmtp, Base), {<<"packetization-mode">>, Mode}),
    Fmtp2 = case Mode of
                <<"2">> -> lists:keystore(<<"sprop-interleaving-depth">>, 1, Fmtp, {<<"sprop-interleaving-depth">>, <<"0">>});
                _ -> Fmtp
            end,
    #{codecs => #{video => [Base#{fmtp => Fmtp2}]}}.

%% The NAL unit types of the payloads B receives for the corpus frames
%% A sends with send_frame/5, and the access units they give back.
h264_types(Mode, Frames) ->
    Opts = h264_mode(Mode),
    {SA0, SB0} = pair(Opts, Opts),
    {_, _, Acts} = lists:foldl(
        fun({I, Frame}, {SA, SB, Acc}) ->
            {ok, Out, SA1} = webrtc_media:send_frame(<<"1">>, Frame, #{timestamp => 1000 + I * 3000}, I * 33, SA),
            {SB1, A} = run(I * 33, Out, SB),
            {SA1, SB1, Acc ++ A}
        end,
        {SA0, SB0, []},
        lists:enumerate(0, Frames)
    ),
    [Type || {event, {rtp, <<"1">>, #rtp{payload = <<_:3, Type:5, _/binary>>}}} <- Acts].

annexb(Frames) -> [E || #{expect := E} <- Frames].

%% Every corpus frame, and one with a NAL unit too large for one packet.
h264_frames() ->
    Big = <<0, 0, 0, 1, 16#41, (binary:copy(<<16#5A>>, 3000))/binary>>,
    annexb(webrtc_test_frames:frames(h264)) ++ [Big].

%% A mode 0 encoder keeps every NAL unit within a packet: the corpus
%% delta frames, and an access unit of the key frame's SPS, PPS and
%% 636 byte slice, which mode 1 would aggregate in one STAP-A.
h264_mode0_single_nal_units_test() ->
    Fits = fun(F) -> lists:all(fun(N) -> byte_size(N) =< 1100 end, webrtc_rtp_h264:split_annexb(F)) end,
    [Key | _] = annexb(webrtc_test_frames:frames(h264)),
    Small = iolist_to_binary([[<<0, 0, 0, 1>>, N] || N <- webrtc_rtp_h264:split_annexb(Key), byte_size(N) =< 1100]),
    Frames = [Small | [F || F <- annexb(webrtc_test_frames:frames(h264)), Fits(F)]],
    Nals = lists:sum([length(webrtc_rtp_h264:split_annexb(F)) || F <- Frames]),
    Types = h264_types(<<"0">>, Frames),
    ?assertEqual(Nals, length(Types)),
    ?assertEqual([], [T || T <- Types, T < 1 orelse T > 23]),
    ?assertEqual([24], [T || T <- h264_types(<<"1">>, [Small])]).

%% No packet of mode 0 can carry a NAL unit larger than the payload
%% size: the frame is refused, nothing is sent.
h264_mode0_too_large_test() ->
    Opts = h264_mode(<<"0">>),
    {SA, _} = pair(Opts, Opts),
    Big = <<0, 0, 0, 1, 16#41, (binary:copy(<<16#5A>>, 3000))/binary>>,
    ?assertEqual({error, {nal_unit_too_large, 3001}}, webrtc_media:send_frame(<<"1">>, Big, #{timestamp => 1000}, 0, SA)).

h264_mode1_aggregates_and_fragments_test() ->
    Types = h264_types(<<"1">>, h264_frames()),
    ?assert(lists:member(28, Types)),
    ?assertEqual([], [T || T <- Types, T > 23, T =/= 24, T =/= 28]).

h264_mode2_interleaved_test() ->
    Types = h264_types(<<"2">>, h264_frames()),
    ?assertNotEqual([], Types),
    ?assertEqual([], [T || T <- Types, not lists:member(T, [25, 26, 27, 28, 29])]),
    ?assert(lists:member(29, Types)).

%%====================================================================
%% Codec plugins: control/2, recoverable errors, terminate/1
%%====================================================================

%% A sends video through `APlugin' (a transceiver option); B decodes
%% with `BPlugin' (for the transceivers A's offer creates).
plugin_pair(APlugin, BPlugin) ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, jsep(#{})),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{frames => true, codec_plugin => APlugin}, A0),
    {ok, O, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, O, A2),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(O), jsep(#{frames => true, codec_plugins => #{video => BPlugin}})),
    {ok, Ans, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Ans, B2),
    {ok, A4} = webrtc_jsep:set_remote_description(answer, wire(Ans), A3),
    #{media := MA} = webrtc_jsep:negotiated(A4),
    #{media := MB} = webrtc_jsep:negotiated(B3),
    Profile = srtp_aead_aes_128_gcm,
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(Profile)),
    SA = webrtc_media:set_srtp(Profile, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{cname => <<"a">>}))),
    SB = webrtc_media:set_srtp(Profile, Material, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{cname => <<"b">>}))),
    {SA, SB, MA, MB}.

%% A encodes `N' frames with send_media/5; B takes them.
encode_frames(N, T0, SA0, SB0) ->
    [#{data := D} | _] = webrtc_test_frames:frames(vp8),
    lists:foldl(
        fun(I, {SA, SB, Acc}) ->
            Now = T0 + I * 33,
            {ok, Out, SA1} = webrtc_media:send_media(<<"1">>, {frame, D, I =:= 0, 1000 + (T0 div 33 + I) * 3000}, #{}, Now, SA),
            {SB1, A} = run(Now, Out, SB),
            {SA1, SB1, Acc ++ A}
        end,
        {SA0, SB0, []},
        lists:seq(0, N - 1)).

got(Msg) ->
    receive Msg -> true after 0 -> false end.

flush_codec() ->
    receive {codec_control, _} -> flush_codec(); {codec_terminate, _} -> flush_codec(); {codec_feedback, _} -> flush_codec()
    after 0 -> ok end.

%% Item 2 of #76: a PLI from the peer reaches the encoder.
control_keyframe_request_test() ->
    flush_codec(),
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec, #{notify => self()}}, {webrtc_test_codec_plain, #{}}),
    {SA1, SB1, _} = encode_frames(3, 0, SA0, SB0),
    {Out, _SB2} = webrtc_media:request_keyframe(<<"1">>, 200, SB1),
    {_SA2, Acts} = run(200, Out, SA1),
    ?assert(lists:member({event, {keyframe_request, <<"1">>}}, Acts)),
    ?assert(got({codec_control, keyframe_request})).

%% Item 1 of #76: the peer's TMMBR limit and the target the application
%% sets reach the encoder; a target set before the first frame reaches
%% it when it starts.
control_bitrate_test() ->
    flush_codec(),
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec, #{notify => self()}}, {webrtc_test_codec_plain, #{}}),
    {ok, [], SAt} = webrtc_media:target_bitrate(<<"1">>, 400000, SA0),
    {SA1, SB1, _} = encode_frames(3, 0, SAt, SB0),
    ?assert(got({codec_control, {target_bitrate, 400000}})),
    {ok, [], SA2} = webrtc_media:target_bitrate(<<"1">>, 250000, SA1),
    ?assert(got({codec_control, {target_bitrate, 250000}})),
    {ok, Out, _SB2} = webrtc_media:request_max_bitrate(<<"1">>, 300000, 200, SB1),
    {_SA3, Acts} = run(200, Out, SA2),
    [Bps] = [B || {event, {max_bitrate, <<"1">>, B}} <- Acts],
    ?assert(got({codec_control, {max_bitrate, Bps}})),
    ?assertEqual({error, not_sending}, webrtc_media:target_bitrate(<<"9">>, 1, SA2)).

%% A plugin without control/2 or terminate/1 gets nothing of them and
%% keeps working.
control_optional_test() ->
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec_plain, #{}}, {webrtc_test_codec_plain, #{}}),
    {SA1, SB1, _} = encode_frames(3, 0, SA0, SB0),
    {ok, [], SA2} = webrtc_media:target_bitrate(<<"1">>, 400000, SA1),
    {Out, _} = webrtc_media:request_keyframe(<<"1">>, 200, SB1),
    {SA3, Acts} = run(200, Out, SA2),
    ?assertEqual([], [E || {event, {codec_plugin_error, _, _} = E} <- Acts]),
    {_, _, More} = encode_frames(2, 300, SA3, SB1),
    ?assertNotEqual([], [F || {event, {frame, <<"1">>, F}} <- More]),
    _ = webrtc_media:close(SA3).

%% Item 4 of #76: {error, Reason, State} from decode/2 drops that frame
%% only; the plugin goes on and the drop is counted.
recoverable_decode_error_test() ->
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec_plain, #{}}, {webrtc_test_codec, #{decode_error => 1}}),
    {_, SB1, Acts} = encode_frames(4, 0, SA0, SB0),
    ?assertEqual([], [E || {event, {codec_plugin_error, _, _} = E} <- Acts]),
    Decoded = [D || {event, {decoded, <<"1">>, D}} <- Acts],
    Frames = [F || {event, {frame, <<"1">>, F}} <- Acts],
    ?assertEqual(length(Frames) - 1, length(Decoded)),
    #{streams := St} = webrtc_media:stats(SB1),
    [Reported] = [R || {in, _} := #{reported := R} <- St],
    ?assertMatch(#{framesDropped := 1}, Reported).

%% {error, Reason, State} from encode/2: send_media/5 returns the error,
%% the next picture encodes.
recoverable_encode_error_test() ->
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec, #{encode_error => 1}}, {webrtc_test_codec_plain, #{}}),
    {SA1, _, _} = encode_frames(1, 0, SA0, SB0),
    [#{data := D} | _] = webrtc_test_frames:frames(vp8),
    {error, {encode, bad_picture}, SA2} = webrtc_media:send_media(<<"1">>, {frame, D, false, 4000}, #{}, 50, SA1),
    ?assertMatch({ok, [_ | _], _}, webrtc_media:send_media(<<"1">>, {frame, D, false, 7000}, #{}, 80, SA2)).

%% Item 6 of #76: terminate/1 once, when the transport closes, when the
%% stream goes in a renegotiation, and when the plugin is turned off; a
%% raise in it is caught.
terminate_on_close_test() ->
    flush_codec(),
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec, #{notify => self()}}, {webrtc_test_codec, #{notify => self()}}),
    {SA1, SB1, _} = encode_frames(2, 0, SA0, SB0),
    _ = webrtc_media:close(SA1),
    ?assert(got({codec_terminate, 2})),
    _ = webrtc_media:close(SB1),
    ?assert(got({codec_terminate, 2})),
    ?assertNot(got({codec_terminate, '_'})).

terminate_on_renegotiation_test() ->
    flush_codec(),
    {SA0, SB0, MA, _} = plugin_pair({webrtc_test_codec, #{notify => self()}}, {webrtc_test_codec, #{notify => self()}}),
    {SA1, SB1, _} = encode_frames(2, 0, SA0, SB0),
    Audio = [S || #{kind := audio} = S <- MA],
    SA2 = webrtc_media:configure(Audio, SA1),
    ?assert(got({codec_terminate, 2})),
    SB2 = webrtc_media:configure([], SB1),
    ?assert(got({codec_terminate, 2})),
    _ = webrtc_media:close(SA2),
    _ = webrtc_media:close(SB2),
    ?assertNot(got({codec_terminate, 2})).

terminate_when_off_test() ->
    flush_codec(),
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec, #{notify => self(), crash => 2}}, {webrtc_test_codec_plain, #{}}),
    {SA1, _, _} = encode_frames(2, 0, SA0, SB0),
    [#{data := D} | _] = webrtc_test_frames:frames(vp8),
    {ok, Acts, SA2} = webrtc_media:send_media(<<"1">>, {frame, D, false, 9000}, #{}, 90, SA1),
    ?assertMatch([{event, {codec_plugin_error, <<"1">>, _}}], Acts),
    ?assert(got({codec_terminate, 2})),
    _ = webrtc_media:close(SA2),
    ?assertNot(got({codec_terminate, 2})).

terminate_crash_caught_test() ->
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec, #{terminate_crash => true}}, {webrtc_test_codec_plain, #{}}),
    {SA1, _, _} = encode_frames(1, 0, SA0, SB0),
    ?assertEqual(ok, webrtc_media:close(SA1)).

%% A plugin whose control/2 fails while the bit rates set before it
%% started are given to it is turned off before it encodes anything.
control_fails_at_start_test() ->
    {SA0, _, _, _} = plugin_pair({webrtc_test_codec, #{control_error => true}}, {webrtc_test_codec_plain, #{}}),
    {ok, [], SA1} = webrtc_media:target_bitrate(<<"1">>, 400000, SA0),
    [#{data := D} | _] = webrtc_test_frames:frames(vp8),
    {ok, Acts, SA2} = webrtc_media:send_media(<<"1">>, {frame, D, true, 1000}, #{}, 0, SA1),
    ?assertEqual([{event, {codec_plugin_error, <<"1">>, refused}}], Acts),
    ?assertEqual({error, {codec_plugin, refused}}, webrtc_media:send_media(<<"1">>, {frame, D, false, 4000}, #{}, 33, SA2)).

%%====================================================================
%% Asynchronous plugins: init/4, deliveries from the plugin's process
%%====================================================================

%% The deliveries an asynchronous plugin's worker cast to this process
%% (standing for the transport), applied to `S' in order.
deliver(S, Now) -> deliver(S, Now, []).

deliver(S, Now, Acc) ->
    receive
        {'$gen_cast', {codec_delivery, Dir, Key, Ref, Msg}} ->
            {A, S1} = webrtc_media:delivery(Dir, Key, Ref, Msg, Now, S),
            deliver(S1, Now, Acc ++ A)
    after 200 ->
        {S, Acc}
    end.

%% One delivery, kept to replay it later.
one_delivery() ->
    receive {'$gen_cast', {codec_delivery, _, _, _, _} = D} -> D after 1000 -> error(no_delivery) end.

counter(S, K) ->
    #{counters := C} = webrtc_media:stats(S),
    maps:get(K, C, 0).

%% decode/2 hands the frame over; the worker's outputs and statistics
%% come later and reach the owner as from a synchronous decoder.
async_decode_test() ->
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec_plain, #{}}, {webrtc_test_codec_async, #{}}),
    {_, SB1, Acts} = encode_frames(4, 0, SA0, SB0),
    Frames = [F || {event, {frame, <<"1">>, F}} <- Acts],
    ?assertEqual([], [D || {event, {decoded, _, D}} <- Acts]),
    {SB2, Later} = deliver(SB1, 200),
    ?assertEqual(length(Frames), length([D || {event, {decoded, <<"1">>, {size, _}} = D} <- Later])),
    #{streams := St} = webrtc_media:stats(SB2),
    [#{framesDecoded := N, decoderImplementation := <<"async VP8">>}] = [R || {in, _} := #{reported := R} <- St],
    ?assertEqual(length(Frames), N).

%% encode/2 hands the picture over; the frames the worker delivers are
%% sent and B receives them.
async_encode_test() ->
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec_async, #{}}, {webrtc_test_codec_plain, #{}}),
    [#{data := D} | _] = webrtc_test_frames:frames(vp8),
    {ok, [], SA1} = webrtc_media:send_media(<<"1">>, {frame, D, true, 1000}, #{}, 0, SA0),
    {_SA2, Out} = deliver(SA1, 10),
    ?assertMatch([_ | _], [X || {send, _} = X <- Out]),
    {_, Got} = run(10, Out, SB0),
    ?assertMatch([_], [F || {event, {frame, <<"1">>, F}} <- Got]).

%% decoder_feedback/2 with keyframe_request sends a PLI to the encoder.
async_decoder_feedback_test() ->
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec_plain, #{}}, {webrtc_test_codec_async, #{feedback => [keyframe_request]}}),
    {SA1, SB1, _} = encode_frames(2, 0, SA0, SB0),
    {_, Later} = deliver(SB1, 200),
    {_, AtA} = run(200, [X || {send, _} = X <- Later], SA1),
    ?assert(lists:member({event, {keyframe_request, <<"1">>}}, AtA)).

%% A delivery to an instance that ended is dropped and counted, and does
%% not reach the instance that started after it on the same stream.
async_stale_delivery_test() ->
    {SA0, SB0, MA, _} = plugin_pair({webrtc_test_codec_async, #{}}, {webrtc_test_codec_plain, #{}}),
    [#{data := D} | _] = webrtc_test_frames:frames(vp8),
    {ok, [], SA1} = webrtc_media:send_media(<<"1">>, {frame, D, true, 1000}, #{}, 0, SA0),
    {codec_delivery, Dir, Key, Ref, Msg} = one_delivery(),
    %% The sender goes in a renegotiation and comes back: a new instance.
    Audio = [S || #{kind := audio} = S <- MA],
    SA2 = webrtc_media:configure(MA, webrtc_media:configure(Audio, SA1)),
    {ok, [], SA3} = webrtc_media:send_media(<<"1">>, {frame, D, true, 4000}, #{}, 33, SA2),
    {Stale, SA4} = webrtc_media:delivery(Dir, Key, Ref, Msg, 40, SA3),
    ?assertEqual([], Stale),
    ?assertEqual(1, counter(SA4, codec_deliveries_stale)),
    {SA5, Fresh} = deliver(SA4, 50),
    ?assertMatch([_ | _], [X || {send, _} = X <- Fresh]),
    _ = webrtc_media:close(SA5),
    _ = SB0.

%% A malformed delivery is dropped and counted; the plugin stays on.
async_bad_delivery_test() ->
    {SA0, SB0, _, _} = plugin_pair({webrtc_test_codec_async, #{}}, {webrtc_test_codec_plain, #{}}),
    [#{data := D} | _] = webrtc_test_frames:frames(vp8),
    {ok, [], SA1} = webrtc_media:send_media(<<"1">>, {frame, D, true, 1000}, #{}, 0, SA0),
    {codec_delivery, out, Key, Ref, _} = one_delivery(),
    {[], SA2} = webrtc_media:delivery(out, Key, Ref, {encoded, [#{data => <<>>}], #{}}, 10, SA1),
    {[], SA3} = webrtc_media:delivery(out, Key, Ref, nonsense, 10, SA2),
    ?assertEqual(2, counter(SA3, codec_deliveries_rejected)),
    {ok, [], SA4} = webrtc_media:send_media(<<"1">>, {frame, D, false, 4000}, #{}, 33, SA3),
    {_, Out} = deliver(SA4, 40),
    ?assertMatch([_ | _], [X || {send, _} = X <- Out]),
    _ = SB0.
