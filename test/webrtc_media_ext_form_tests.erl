%% RFC 8285 §6: without a=extmap-allow-mixed on both sides, a stream
%% uses one header extension form throughout (§4.1.2); with it, each
%% packet takes the form its elements need.
-module(webrtc_media_ext_form_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_sdp.hrl").

-define(LEVEL, <<"urn:ietf:params:rtp-hdrext:ssrc-audio-level">>).
-define(MIDURI, <<"urn:ietf:params:rtp-hdrext:sdes:mid">>).
-define(PROFILE, srtp_aead_aes_128_gcm).

jsep() ->
    webrtc_jsep:new(#{
        ice_ufrag => <<"ufrag">>,
        ice_pwd => <<"passwordpasswordpassword">>,
        fingerprints => [{sha256, crypto:strong_rand_bytes(32)}],
        cryptex => false
    }).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

%% A offers audio and video; `Strip' removes a=extmap-allow-mixed from
%% the offer B receives, as a peer that does not support it.
negotiate(Strip) ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, O, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, O, A2),
    Offer = case Strip of
                true -> O#sdp{attributes = [X || X <- O#sdp.attributes, X =/= {extmap_allow_mixed, true}]};
                false -> O
            end,
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, _, B01} = webrtc_jsep:add_transceiver(video, #{}, B0),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), B01),
    {ok, Ans, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Ans, B2),
    {ok, A4} = webrtc_jsep:set_remote_description(answer, wire(Ans), A3),
    #{media := MA} = webrtc_jsep:negotiated(A4),
    #{media := MB} = webrtc_jsep:negotiated(B3),
    {MA, MB, wire(Ans)}.

sender(Sections) ->
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(?PROFILE)),
    S = webrtc_media:set_srtp(?PROFILE, Material, server, 0, webrtc_media:configure(Sections, webrtc_media:new(#{}))),
    {S, element(2, webrtc_srtp:dtls_contexts(?PROFILE, Material, client, #{}))}.

%% The extension profile of every packet sent on mid 0, with the audio
%% level on every other packet.
profiles(Sections) ->
    {S0, In0} = sender(Sections),
    {Profiles, _, _} = lists:foldl(
        fun(N, {Acc, S, In}) ->
            Opts = #{timestamp => N * 960, marker => true},
            Opts1 = case N rem 2 of 0 -> Opts#{audio_level => {true, 30}}; 1 -> Opts end,
            {ok, Out, S1} = webrtc_media:send(<<"0">>, <<"opus">>, Opts1, N * 20, S),
            {Ps, In1} = lists:foldl(
                fun({send, Bin}, {P, I}) ->
                    {ok, Plain, I1} = webrtc_srtp:unprotect_rtp(Bin, I),
                    {ok, #rtp{ext = {Profile, _}}} = webrtc_rtp:decode(Plain),
                    {[Profile | P], I1}
                end,
                {[], In},
                [A || {send, _} = A <- Out]
            ),
            {Acc ++ lists:reverse(Ps), S1, In1}
        end,
        {[], S0, In0},
        lists:seq(1, 6)
    ),
    lists:usort(Profiles).

%% The audio level moved to id 15, which only the two-byte form carries.
level_at_15(Sections) ->
    [case maps:get(mid, M) of
         <<"0">> -> M#{send_extensions := (maps:get(send_extensions, M))#{?LEVEL => 15}};
         _ -> M
     end || M <- Sections].

negotiation_test() ->
    {MA, MB, _} = negotiate(false),
    ?assert(lists:all(fun(M) -> maps:get(ext_mixed, M) end, MA ++ MB)),
    {MA1, MB1, Answer} = negotiate(true),
    ?assertNot(lists:any(fun(M) -> maps:get(ext_mixed, M) end, MA1 ++ MB1)),
    %% Not answered when it was not offered.
    ?assertEqual(error, webrtc_sdp_media:attr(extmap_allow_mixed, Answer)),
    ?assertEqual([], [M || M <- Answer#sdp.media, webrtc_sdp_media:attr(extmap_allow_mixed, M) =/= error]).

%% An offer with it at media level only is answered at media level.
media_level_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, O, A1} = webrtc_jsep:create_offer(#{}, A0),
    {ok, _} = webrtc_jsep:set_local_description(offer, O, A1),
    [M0] = O#sdp.media,
    Offer = O#sdp{attributes = [X || X <- O#sdp.attributes, X =/= {extmap_allow_mixed, true}],
                  media = [M0#sdp_media{attributes = M0#sdp_media.attributes ++ [{extmap_allow_mixed, true}]}]},
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, wire(Offer), B0),
    {ok, Ans, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Ans, B2),
    Answer = wire(Ans),
    ?assertEqual(error, webrtc_sdp_media:attr(extmap_allow_mixed, Answer)),
    [AM] = Answer#sdp.media,
    ?assertEqual({ok, true}, webrtc_sdp_media:attr(extmap_allow_mixed, AM)),
    #{media := [#{ext_mixed := true}]} = webrtc_jsep:negotiated(B3).

one_byte_throughout_test() ->
    {_, MB, _} = negotiate(true),
    ?assertEqual([16#BEDE], profiles(MB)).

two_byte_throughout_test() ->
    {_, MB, _} = negotiate(true),
    ?assertEqual([16#1000], profiles(level_at_15(MB))).

long_mid_two_byte_test() ->
    {_, MB, _} = negotiate(true),
    Long = <<"a-mid-of-17-bytes">>,
    MB1 = [case maps:get(mid, M) of <<"0">> -> M#{mid := Long}; _ -> M end || M <- MB],
    {S, In} = sender(MB1),
    {ok, Out, S1} = webrtc_media:send(Long, <<"opus">>, #{timestamp => 960}, 0, S),
    {ok, Out2, _} = webrtc_media:send(Long, <<"opus">>, #{timestamp => 1920, audio_level => {true, 1}}, 20, S1),
    {Profiles, _} = lists:foldl(
        fun({send, Bin}, {P, I}) ->
            {ok, Plain, I1} = webrtc_srtp:unprotect_rtp(Bin, I),
            {ok, #rtp{ext = {Profile, _}}} = webrtc_rtp:decode(Plain),
            {[Profile | P], I1}
        end,
        {[], In},
        [A || {send, _} = A <- Out ++ Out2]
    ),
    ?assertEqual([16#1000], lists:usort(Profiles)).

mixed_allowed_test() ->
    {_, MB, _} = negotiate(false),
    %% Each packet takes the form it needs.
    ?assertEqual([16#1000, 16#BEDE], profiles(level_at_15(MB))).
