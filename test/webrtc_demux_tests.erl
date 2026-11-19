%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
-module(webrtc_demux_tests).
-include_lib("eunit/include/eunit.hrl").

ranges_test() ->
    C = fun(B) -> webrtc_demux:classify(<<B, 0>>) end,
    ?assertEqual([stun], lists:usort([C(B) || B <- lists:seq(0, 3)])),
    ?assertEqual([unknown], lists:usort([C(B) || B <- lists:seq(4, 19)])),
    ?assertEqual([dtls], lists:usort([C(B) || B <- lists:seq(20, 63)])),
    ?assertEqual([turn_channel], lists:usort([C(B) || B <- lists:seq(64, 79)])),
    ?assertEqual([unknown], lists:usort([C(B) || B <- lists:seq(80, 127)])),
    ?assertEqual([rtp], lists:usort([C(B) || B <- lists:seq(128, 191)])),
    ?assertEqual([unknown], lists:usort([C(B) || B <- lists:seq(192, 255)])),
    ?assertEqual(unknown, webrtc_demux:classify(<<>>)).
