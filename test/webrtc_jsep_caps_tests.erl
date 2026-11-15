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
