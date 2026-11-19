%% The RTT measured from report blocks reaches the NACK requesters and
%% the retransmission buffers (RFC 4585 §3.4, RFC 4588 §5).
-module(webrtc_media_rtt_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("webrtc/src/transport/webrtc_media.hrl").

path_rtt_test() ->
    N0 = webrtc_nack:new(#{}),
    B0 = webrtc_nack_buffer:new(#{size => 16}),
    M0 = webrtc_media:new(#{}),
    M = M0#media{
        receivers = #{1 => #rcv{mid = <<"0">>, clock_rate = 90000, rx = undefined, nack = N0},
                      2 => #rcv{mid = <<"1">>, clock_rate = 48000, rx = undefined, nack = undefined}},
        senders = #{<<"0">> => #snd{mid = <<"0">>, buffer = B0}}
    },
    M1 = webrtc_media_in:path_rtt(250, M),
    ?assertEqual(webrtc_nack:set_rtt(250, N0), (maps:get(1, M1#media.receivers))#rcv.nack),
    ?assertEqual(undefined, (maps:get(2, M1#media.receivers))#rcv.nack),
    ?assertEqual(webrtc_nack_buffer:set_rtt(250, B0), (maps:get(<<"0">>, M1#media.senders))#snd.buffer),
    ?assertEqual(M, webrtc_media_in:path_rtt(undefined, M)).
