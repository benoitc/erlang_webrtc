%% FlexFEC negotiation (RFC 8627 §5.2, §7.1): the repair stream grouped
%% with its source by FEC-FR (RFC 5956), the repair window checked.
-module(webrtc_jsep_flexfec_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_sdp.hrl").

jsep() ->
    webrtc_jsep:new(#{ice_ufrag => <<"ufrag">>, ice_pwd => <<"passwordpasswordpassword">>,
                      fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]}).

%% Our offer: flexfec with its repair window, the repair SSRC grouped
%% with the media SSRC; the answerer reads the group.
offer_and_answer_test() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(video, #{}, jsep()),
    {ok, O, A1} = webrtc_jsep:create_offer(#{}, A0),
    Sdp = iolist_to_binary(webrtc_sdp:encode(O)),
    ?assertMatch({_, _}, binary:match(Sdp, <<"a=rtpmap:119 flexfec/90000">>)),
    ?assertMatch({_, _}, binary:match(Sdp, <<"a=fmtp:119 repair-window=200000">>)),
    {match, [[Src, Fec]]} = re:run(Sdp, <<"a=ssrc-group:FEC-FR (\\d+) (\\d+)">>, [global, {capture, all_but_first, binary}]),
    {ok, _} = webrtc_jsep:set_local_description(offer, O, A1),
    {ok, P} = webrtc_sdp:parse(Sdp),
    {ok, B1} = webrtc_jsep:set_remote_description(offer, P, jsep()),
    {ok, Ans, B2} = webrtc_jsep:create_answer(#{}, B1),
    {ok, B3} = webrtc_jsep:set_local_description(answer, Ans, B2),
    #{media := [#{remote_ssrcs := [R], recv_codecs := Cs}]} = webrtc_jsep:negotiated(B3),
    ?assertEqual({binary_to_integer(Src), binary_to_integer(Fec)}, {maps:get(ssrc, R), maps:get(fec_ssrc, R)}),
    ?assert(lists:any(fun(#{name := N}) -> N =:= <<"flexfec">> end, Cs)).

offered(Fmtp) ->
    [#{pt => 96, name => <<"VP8">>, clock_rate => 90000, fmtp => [], rtcp_fb => []},
     #{pt => 110, name => <<"flexfec">>, clock_rate => 90000, fmtp => Fmtp, rtcp_fb => []}].

names(Cs) -> [N || #{name := N} <- Cs].

%% §5.2.1: a repair window we cannot keep, or none, rejects FlexFEC.
repair_window_test_() ->
    Local = webrtc_jsep_caps:default_codecs(video),
    Answer = fun(F) -> names(webrtc_jsep_caps:answer_codecs(offered(F), Local)) end,
    [?_assertEqual([<<"VP8">>, <<"flexfec">>], Answer([{<<"repair-window">>, <<"200000">>}])),
     %% The second example of §7.1.2 writes it with a colon.
     ?_assertEqual([<<"VP8">>, <<"flexfec">>], Answer([<<"repair-window:200000">>])),
     ?_assertEqual([<<"VP8">>], Answer([{<<"repair-window">>, <<"5000000">>}])),
     ?_assertEqual([<<"VP8">>], Answer([])),
     ?_assertEqual([<<"VP8">>], Answer([{<<"repair-window">>, <<"soon">>}]))].

%% The example SDP of §7.1.1 writes `a=fmtp:98; repair-window=...',
%% without the space RFC 8866 §6.15 puts after the format: refused as
%% written, read with the space.
rfc_example_test() ->
    Sdp = fun(Fmtp) ->
        <<"v=0\r\no=mo 1122334455 1122334466 IN IP4 fec.example.com\r\ns=FlexFEC minimal SDP signaling Example\r\n"
          "t=0 0\r\nm=video 30000 RTP/AVP 96 98\r\nc=IN IP4 233.252.0.1/127\r\na=rtpmap:96 VP8/90000\r\n"
          "a=rtpmap:98 flexfec/90000\r\n", Fmtp/binary, "\r\n">>
    end,
    ?assertMatch({error, {9, {bad_attribute, <<"fmtp">>}}}, webrtc_sdp:parse(Sdp(<<"a=fmtp:98; repair-window=200000">>))),
    {ok, #sdp{media = [M]}} = webrtc_sdp:parse(Sdp(<<"a=fmtp:98 repair-window=200000">>)),
    [#{name := <<"flexfec">>, fmtp := Fmtp}] = [C || #{name := <<"flexfec">>} = C <- webrtc_sdp_media:codecs(M)],
    ?assertEqual([{<<"repair-window">>, <<"200000">>}], Fmtp).
