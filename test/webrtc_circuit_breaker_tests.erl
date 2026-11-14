%% Tests for webrtc_circuit_breaker (RFC 8083 §4.1 to §4.3).
-module(webrtc_circuit_breaker_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp_rtcp.hrl").

%% Send one 1000 byte packet every 20 ms in [From, To).
send(Cb, From, To) ->
    send(Cb, From, To, 20).

send(Cb, From, To, Every) ->
    lists:foldl(fun(T, C) -> webrtc_circuit_breaker:sent(v, 1000, T, C) end, Cb, lists:seq(From, To - 1, Every)).

rb(Ext, Fraction) -> #rtcp_rb{ssrc = 1, ext_seq = Ext, fraction_lost = Fraction}.

%% §4.1: sending without any report for 3 x Td (Tmin 5 s) triggers.
rtcp_timeout_test() ->
    Cb0 = send(webrtc_circuit_breaker:new(#{}), 0, 16000),
    ?assertEqual(15000, webrtc_circuit_breaker:next_timeout(Cb0)),
    {[], _} = webrtc_circuit_breaker:handle_timeout(14999, Cb0),
    {[{circuit_breaker, v, rtcp_timeout}], Cb1} = webrtc_circuit_breaker:handle_timeout(15000, Cb0),
    %% Reported once.
    {[], Cb1} = webrtc_circuit_breaker:handle_timeout(16000, Cb1),
    ?assertEqual(infinity, webrtc_circuit_breaker:next_timeout(Cb1)),
    %% A report re-arms it.
    {[], Cb2} = webrtc_circuit_breaker:report(v, rb(100, 0), 50, 16000, Cb1),
    Cb3 = send(Cb2, 16000, 16100),
    ?assertEqual(31000, webrtc_circuit_breaker:next_timeout(Cb3)).

reports_prevent_rtcp_timeout_test() ->
    Cb = lists:foldl(
        fun(I, C0) ->
            C1 = send(C0, I * 1000, (I + 1) * 1000),
            {[], C2} = webrtc_circuit_breaker:report(v, rb(I * 50, 0), 40, (I + 1) * 1000, C1),
            {[], C3} = webrtc_circuit_breaker:handle_timeout((I + 1) * 1000, C2),
            C3
        end,
        webrtc_circuit_breaker:new(#{}),
        lists:seq(0, 30)
    ),
    ?assertMatch(#{v := #{tripped := []}}, webrtc_circuit_breaker:stats(Cb)).

%% Not sending: no timeout, and no busy timer.
idle_stream_test() ->
    Cb0 = send(webrtc_circuit_breaker:new(#{}), 0, 100),
    {[], Cb1} = webrtc_circuit_breaker:handle_timeout(40000, Cb0),
    ?assertEqual(infinity, webrtc_circuit_breaker:next_timeout(Cb1)),
    %% Sending again starts a new period.
    Cb2 = send(Cb1, 50000, 50100),
    ?assertEqual(65000, webrtc_circuit_breaker:next_timeout(Cb2)).

%% §4.2: five reports with a non-increasing highest sequence number
%% while sending.
media_timeout_test() ->
    {Events, _} = lists:foldl(
        fun(I, {Acc, C0}) ->
            C1 = send(C0, I * 1000, (I + 1) * 1000),
            {E, C2} = webrtc_circuit_breaker:report(v, rb(500, 0), 40, (I + 1) * 1000, C1),
            {Acc ++ [{I, E}], C2}
        end,
        {[], webrtc_circuit_breaker:new(#{})},
        lists:seq(0, 7)
    ),
    %% The first report sets the reference, the next five do not move.
    ?assertEqual([{5, [{circuit_breaker, v, media_timeout}]}], [X || {_, [_ | _]} = X <- Events]).

media_progress_resets_test() ->
    {Events, _} = lists:foldl(
        fun(I, {Acc, C0}) ->
            C1 = send(C0, I * 1000, (I + 1) * 1000),
            Ext = case I rem 4 of 0 -> I * 10; _ -> (I - I rem 4) * 10 end,
            {E, C2} = webrtc_circuit_breaker:report(v, rb(Ext, 0), 40, (I + 1) * 1000, C1),
            {Acc ++ E, C2}
        end,
        {[], webrtc_circuit_breaker:new(#{})},
        lists:seq(0, 20)
    ),
    ?assertEqual([], Events).

%% §4.3: at 4 Mbps on a 100 ms path, 50% loss allows a TCP throughput
%% of about 17 KB/s, and 500 KB/s is more than ten times that; with 1%
%% loss TCP gets about 113 KB/s and the breaker stays off.
congestion_test() ->
    ?assertEqual([{circuit_breaker, v, congestion}], congestion(128)),
    ?assertEqual([], congestion(3)).

congestion(Fraction) ->
    {Events, _} = lists:foldl(
        fun(I, {Acc, C0}) ->
            C1 = send(C0, I * 1000, (I + 1) * 1000, 2),
            {E, C2} = webrtc_circuit_breaker:report(v, rb((I + 1) * 500, Fraction), 100, (I + 1) * 1000, C1),
            {Acc ++ E, C2}
        end,
        {[], webrtc_circuit_breaker:new(#{})},
        lists:seq(0, 10)
    ),
    Events.

%% Without an RTT the congestion breaker cannot be evaluated.
congestion_needs_rtt_test() ->
    {Events, _} = lists:foldl(
        fun(I, {Acc, C0}) ->
            C1 = send(C0, I * 1000, (I + 1) * 1000),
            {E, C2} = webrtc_circuit_breaker:report(v, rb((I + 1) * 50, 200), undefined, (I + 1) * 1000, C1),
            {Acc ++ E, C2}
        end,
        {[], webrtc_circuit_breaker:new(#{})},
        lists:seq(0, 10)
    ),
    ?assertEqual([], Events).

unknown_stream_test() ->
    ?assertMatch({[], _}, webrtc_circuit_breaker:report(x, rb(1, 0), 10, 0, webrtc_circuit_breaker:new(#{}))).
