%% Unit tests of the SCTP receive side on its own state.
-module(webrtc_sctp_recv_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("webrtc/src/sctp/webrtc_sctp_assoc.hrl").

%% RFC 6525 §5.2.2 E3: an empty stream list resets every incoming
%% stream. With no stream state it is a no-op and must return.
reset_all_without_state_test_() ->
    {timeout, 2, fun() ->
        R = webrtc_sctp_recv:new(#cfg{}),
        ?assertMatch({done, #rcv{}}, webrtc_sctp_recv:reset_incoming([], 0, 1, R))
    end}.
