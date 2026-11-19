%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% SLI and RPSI between two media sessions (RFC 4585 §6.3.2, §6.3.3,
%% RFC 8834 §5.1.3, §5.1.4): only where `nack sli' / `nack rpsi' was
%% negotiated.
-module(webrtc_media_loss_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

-define(PROFILE, srtp_aead_aes_128_gcm).

jsep() ->
    webrtc_jsep:new(#{ice_ufrag => <<"ufrag">>, ice_pwd => <<"passwordpasswordpassword">>,
                      fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]}).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

sections() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, _, B1} = webrtc_jsep:add_transceiver(video, #{}, B0),
    {ok, O, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, O, A2),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, wire(O), B1),
    {ok, Ans, B3} = webrtc_jsep:create_answer(#{}, B2),
    {ok, B4} = webrtc_jsep:set_local_description(answer, Ans, B3),
    {ok, A4} = webrtc_jsep:set_remote_description(answer, wire(Ans), A3),
    #{media := MA} = webrtc_jsep:negotiated(A4),
    #{media := MB} = webrtc_jsep:negotiated(B4),
    {MA, MB}.

strip(Sections) ->
    Keep = fun(Fb) -> [F || #{type := T, param := P} = F <- Fb, not (T =:= <<"nack">> andalso (P =:= <<"sli">> orelse P =:= <<"rpsi">>))] end,
    [S#{send_codecs := [C#{rtcp_fb := Keep(Fb)} || #{rtcp_fb := Fb} = C <- maps:get(send_codecs, S)]} || S <- Sections].

pair(MA, MB) ->
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(?PROFILE)),
    {webrtc_media:set_srtp(?PROFILE, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{}))),
     webrtc_media:set_srtp(?PROFILE, Material, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{})))}.

deliver(Acts, S) ->
    lists:foldl(fun({send, Bin}, {SA, AA}) -> {S1, A} = webrtc_media:handle_packet(Bin, 0, SA), {S1, AA ++ A};
                   (_, Acc) -> Acc
                end, {S, []}, Acts).

%% B learns A's video SSRC from one packet, then sends an indication.
indicate(MA, MB, Fb) ->
    {SA, SB} = pair(MA, MB),
    {ok, Out, SA1} = webrtc_media:send(<<"1">>, <<"frame">>, #{timestamp => 1}, 0, SA),
    {SB1, _} = deliver(Out, SB),
    {ok, Req, _} = webrtc_media:send_loss_indication(<<"1">>, Fb, 0, SB1),
    deliver(Req, SA1).

negotiated_test() ->
    {MA, MB} = sections(),
    {_, A1} = indicate(MA, MB, {slice_loss, [{1, 2, 3}]}),
    ?assertEqual([{slice_loss, <<"1">>, [{1, 2, 3}]}], [E || {event, {slice_loss, _, _} = E} <- A1]),
    {_, A2} = indicate(MA, MB, {reference_picture, 96, <<5:3>>}),
    ?assertEqual([{reference_picture, <<"1">>, 96, <<5:3>>}], [E || {event, {reference_picture, _, _, _} = E} <- A2]).

%% A did not negotiate them for what it sends: ignored and counted.
ignored_test() ->
    {MA, MB} = sections(),
    {SA, A} = indicate(strip(MA), MB, {slice_loss, [{1, 2, 3}]}),
    ?assertEqual([], [E || {event, {slice_loss, _, _} = E} <- A]),
    #{counters := C} = webrtc_media:stats(SA),
    ?assertEqual(1, maps:get(sli_ignored, C)).

not_negotiated_test() ->
    {MA, MB} = sections(),
    {_, SB} = pair(MA, MB),
    %% Audio has neither.
    ?assertEqual({error, not_negotiated}, webrtc_media:send_loss_indication(<<"0">>, {slice_loss, [{1, 2, 3}]}, 0, SB)).
