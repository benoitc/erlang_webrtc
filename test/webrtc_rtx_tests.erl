%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for webrtc_rtx (RFC 4588 §4).
-module(webrtc_rtx_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

rtx_test() ->
    Orig = #rtp{
        marker = true,
        pt = 96,
        seq = 16#1234,
        ts = 90000,
        ssrc = 1,
        csrcs = [5],
        ext = [{1, <<"m">>}],
        padding = 4,
        payload = <<"frame">>
    },
    Rtx = webrtc_rtx:encapsulate(Orig, #{ssrc => 2, pt => 97, seq => 7}),
    ?assertEqual(
        Orig#rtp{pt = 97, seq = 7, ssrc = 2, padding = 0, payload = <<16#12, 16#34, "frame">>}, Rtx
    ),
    ?assertEqual({ok, 16#1234}, webrtc_rtx:osn(Rtx)),
    %% over the wire and back
    {ok, Wire} = webrtc_rtp:decode(webrtc_rtp:encode(Rtx), #{extensions => parse}),
    {ok, Back} = webrtc_rtx:decapsulate(Wire, #{ssrc => 1, pt => 96}),
    ?assertEqual(Orig#rtp{padding = 0}, Back).

rtx_padding_only_test() ->
    Probe = #rtp{pt = 97, seq = 8, ts = 0, ssrc = 2, padding = 200},
    ?assertEqual({error, no_osn}, webrtc_rtx:decapsulate(Probe, #{ssrc => 1, pt => 96})),
    ?assertEqual({error, no_osn}, webrtc_rtx:osn(Probe#rtp{payload = <<1>>})).
