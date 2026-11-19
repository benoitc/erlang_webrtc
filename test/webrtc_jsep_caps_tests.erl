%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% RFC 7728 §9: negotiation of `ccm pause'.
-module(webrtc_jsep_caps_tests).
-include_lib("eunit/include/eunit.hrl").

-define(C, webrtc_jsep_caps).

vp8(Fb) ->
    #{pt => 96, name => <<"VP8">>, clock_rate => 90000, channels => undefined, fmtp => [], rtcp_fb => Fb}.

fb(T, P) -> #{type => T, param => P}.

answer_fb(OfferedFb) ->
    [#{rtcp_fb := Fb}] = ?C:answer_codecs([vp8(OfferedFb)], ?C:default_codecs(video)),
    Fb.

offered_test() ->
    [#{rtcp_fb := Fb} | _] = ?C:default_codecs(video),
    ?assert(lists:member(fb(<<"ccm">>, <<"pause nowait">>), Fb)).

answer_test() ->
    %% Any config is answered with the full implementation; nowait only
    %% when offered.
    ?assertEqual([fb(<<"ccm">>, <<"pause nowait">>)], answer_fb([fb(<<"ccm">>, <<"pause config=2 nowait">>)])),
    ?assertEqual([fb(<<"ccm">>, <<"pause">>)], answer_fb([fb(<<"ccm">>, <<"pause">>)])),
    ?assertEqual([fb(<<"ccm">>, <<"fir">>)], answer_fb([fb(<<"ccm">>, <<"fir">>)])),
    %% Not offered: not answered.
    ?assertEqual([], answer_fb([])).

pause_params_test() ->
    ?assertEqual([<<"config=3">>, <<"nowait">>], ?C:pause_params(fb(<<"CCM">>, <<"pause config=3 nowait">>))),
    ?assertEqual([], ?C:pause_params(fb(<<"ccm">>, <<"pause">>))),
    ?assertEqual(undefined, ?C:pause_params(fb(<<"ccm">>, <<"fir">>))),
    ?assertEqual(undefined, ?C:pause_params(fb(<<"nack">>, undefined))).

%% RFC 6184 §8.2.2: packetization-mode 2 is another codec than mode 1;
%% it is answered only when configured locally.
h264(Pt, Mode) ->
    #{pt => Pt, name => <<"H264">>, clock_rate => 90000, channels => undefined, rtcp_fb => [],
      fmtp => [{<<"packetization-mode">>, Mode}, {<<"profile-level-id">>, <<"42e01f">>},
               {<<"sprop-interleaving-depth">>, <<"4">>}]}.

h264_interleaved_test() ->
    Offer = [h264(100, <<"2">>), h264(102, <<"1">>)],
    ?assertEqual([102], [Pt || #{pt := Pt} <- ?C:answer_codecs(Offer, ?C:default_codecs(video))]),
    Local = [h264(120, <<"2">>)],
    ?assertEqual([100], [Pt || #{pt := Pt} <- ?C:answer_codecs(Offer, Local)]),
    ?assertNot(?C:same_codec(h264(1, <<"1">>), h264(2, <<"2">>))).

%% prefer/2: the codec, then its rtx, then the others in their order.
prefer_test_() ->
    Video = ?C:default_codecs(video),
    Names = fun(Cs) -> [{N, Pt} || #{name := N, pt := Pt} <- Cs] end,
    {ok, Av1} = ?C:prefer(<<"AV1">>, Video),
    [?_assertEqual([{<<"AV1">>, 45}, {<<"rtx">>, 46}], lists:sublist(Names(Av1), 2)),
     ?_assertEqual(lists:sort(Video), lists:sort(Av1)),
     ?_assertEqual(Names(Video) -- [{<<"AV1">>, 45}, {<<"rtx">>, 46}], tl(tl(Names(Av1)))),
     ?_assertEqual({ok, Av1}, ?C:prefer(<<"av1">>, Video)),
     ?_assertEqual({ok, Video}, ?C:prefer(<<"VP8">>, Video)),
     ?_assertEqual({error, {unknown_codec, <<"H265">>}}, ?C:prefer(<<"H265">>, Video)),
     ?_assertEqual({error, {unknown_codec, <<"rtx">>}}, ?C:prefer(<<"rtx">>, Video)),
     %% Every H.264 entry goes first, each followed by nothing else
     %% before the rtx entries that name them.
     ?_test(begin
                Two = [h264(100, <<"1">>), #{name => <<"rtx">>, pt => 101, clock_rate => 90000, channels => undefined,
                                             fmtp => [{<<"apt">>, <<"100">>}], rtcp_fb => []},
                       hd(Video), h264(102, <<"0">>), #{name => <<"rtx">>, pt => 103, clock_rate => 90000,
                                                        channels => undefined, fmtp => [{<<"apt">>, <<"102">>}], rtcp_fb => []}],
                {ok, P} = ?C:prefer(<<"H264">>, Two),
                ?assertEqual([100, 102, 101, 103, 96], [Pt || #{pt := Pt} <- P])
            end)].
