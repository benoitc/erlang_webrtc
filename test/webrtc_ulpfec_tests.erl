%% ULPFEC (RFC 5109): FEC payloads made by protect/2 give back any one
%% missing packet of each group, byte for byte.
-module(webrtc_ulpfec_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

packets(N) ->
    [{S band 16#FFFF, webrtc_rtp:encode(#rtp{pt = 96, seq = S band 16#FFFF, ts = 9000 + S div 3, ssrc = 77,
                                             marker = S rem 3 =:= 2, csrcs = [S || S rem 5 =:= 0],
                                             payload = crypto:strong_rand_bytes(20 + S * 7 rem 300)})}
     || S <- lists:seq(65530, 65530 + N - 1)].

%% Every burst of K losses within a group of N is recovered.
burst_recovery_test_() ->
    [{lists:flatten(io_lib:format("n ~b k ~b", [N, K])), fun() -> burst(N, K) end}
     || {N, K} <- [{1, 1}, {5, 1}, {10, 2}, {16, 4}, {20, 5}, {48, 8}]].

burst(N, K) ->
    Pkts = packets(N),
    Fecs = webrtc_ulpfec:protect(Pkts, K),
    ?assertEqual(min(N, K), length(Fecs)),
    [begin
         Lost = lists:sublist(Pkts, From, K),
         Kept = Pkts -- Lost,
         Rx0 = lists:foldl(fun({S, B}, R) -> element(2, webrtc_ulpfec:media(S, B, R)) end, webrtc_ulpfec:new(), Kept),
         {Got, Rx} = lists:foldl(fun(F, {Acc, R}) -> {A, R1} = webrtc_ulpfec:fec({77, F}, R), {Acc ++ A, R1} end,
                                 {[], Rx0}, Fecs),
         ?assertEqual(lists:sort([B || {_, B} <- Lost]), lists:sort(Got)),
         ?assertEqual(length(Lost), maps:get(packets_recovered, webrtc_ulpfec:stats(Rx)))
     end || From <- lists:seq(1, N - K + 1)].

%% Two losses in one group: not recoverable, nothing made up.
two_in_a_group_test() ->
    Pkts = packets(6),
    [F] = webrtc_ulpfec:protect(Pkts, 1),
    Rx0 = lists:foldl(fun({S, B}, R) -> element(2, webrtc_ulpfec:media(S, B, R)) end, webrtc_ulpfec:new(),
                      lists:nthtail(2, Pkts)),
    ?assertMatch({[], _}, webrtc_ulpfec:fec({77, F}, Rx0)).

%% Nothing lost: the FEC payload is discarded (W3C fecPacketsDiscarded).
nothing_lost_test() ->
    Pkts = packets(4),
    [F] = webrtc_ulpfec:protect(Pkts, 1),
    Rx0 = lists:foldl(fun({S, B}, R) -> element(2, webrtc_ulpfec:media(S, B, R)) end, webrtc_ulpfec:new(), Pkts),
    {[], Rx} = webrtc_ulpfec:fec({77, F}, Rx0),
    ?assertMatch(#{fec_packets_received := 1, fec_packets_discarded := 1, packets_recovered := 0}, webrtc_ulpfec:stats(Rx)).

%% The FEC payload arrives first, the missing packet is found when the
%% others come.
fec_first_test() ->
    Pkts = packets(4),
    [F] = webrtc_ulpfec:protect(Pkts, 1),
    {[], Rx0} = webrtc_ulpfec:fec({77, F}, webrtc_ulpfec:new()),
    [{_, Lost} | Rest] = Pkts,
    {Got, _} = lists:foldl(fun({S, B}, {Acc, R}) -> {A, R1} = webrtc_ulpfec:media(S, B, R), {Acc ++ A, R1} end,
                           {[], Rx0}, Rest),
    ?assertEqual([Lost], Got).

%% §7.3: L = 1 and a 48 bit mask past 16 packets.
long_mask_test() ->
    [F] = webrtc_ulpfec:protect(packets(20), 1),
    <<0:1, 1:1, _/bits>> = F,
    {ok, #{offsets := Offs}} = webrtc_ulpfec:decode(F),
    ?assertEqual(lists:seq(0, 19), Offs).

decode_errors_test() ->
    ?assertEqual({error, extension}, webrtc_ulpfec:decode(<<1:1, 0:79>>)),
    ?assertEqual({error, truncated}, webrtc_ulpfec:decode(<<0:80, 0:16>>)),
    ?assertEqual({error, empty_mask}, webrtc_ulpfec:decode(<<0:80, 0:16, 0:16>>)).
