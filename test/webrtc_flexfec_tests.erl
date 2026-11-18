%% FlexFEC (RFC 8627): repair payloads from protect/2, read back by
%% decode/2, give lost source packets back through webrtc_ulpfec.
-module(webrtc_flexfec_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

-define(SSRC, 4242).

packets(N) ->
    [{S band 16#FFFF, webrtc_rtp:encode(#rtp{pt = 96, seq = S band 16#FFFF, ts = 3000 * (S div 4), ssrc = ?SSRC,
                                             marker = S rem 4 =:= 3, csrcs = [S || S rem 6 =:= 0],
                                             payload = crypto:strong_rand_bytes(10 + S * 13 rem 400)})}
     || S <- lists:seq(65500, 65500 + N - 1)].

recover(Kept, Repairs) ->
    Rx0 = lists:foldl(fun({S, B}, R) -> element(2, webrtc_ulpfec:media(S, B, R)) end, webrtc_ulpfec:new(), Kept),
    lists:foldl(fun(P, {Acc, R}) ->
                    {ok, #{blocks := [Block]} = F} = webrtc_flexfec:decode(P, 1),
                    {A, R1} = webrtc_ulpfec:repair({?SSRC, Block, F, byte_size(P)}, R),
                    {Acc ++ A, R1}
                end, {[], Rx0}, Repairs).

%% Bursts of K losses, masks of 15, 46 and 110 bits.
burst_test_() ->
    [{lists:flatten(io_lib:format("n ~b k ~b", [N, K])), fun() ->
        Pkts = packets(N),
        Repairs = webrtc_flexfec:protect(Pkts, K),
        [begin
             Lost = lists:sublist(Pkts, From, K),
             {Got, _} = recover(Pkts -- Lost, Repairs),
             ?assertEqual(lists:sort([B || {_, B} <- Lost]), lists:sort(Got))
         end || From <- lists:seq(1, N - K + 1)]
    end} || {N, K} <- [{1, 1}, {14, 2}, {15, 1}, {40, 4}, {46, 1}, {100, 10}, {110, 1}]].

%% §4.2.2.1: the k bits say whether another mask block follows.
mask_sizes_test() ->
    Size = fun(N) -> [P] = webrtc_flexfec:protect(packets(N), 1), <<_:64, _:16, Rest/bits>> = P, Rest end,
    <<0:1, _/bits>> = Size(15),
    <<1:1, _:15, 0:1, _/bits>> = Size(16),
    <<1:1, _:15, 1:1, _/bits>> = Size(47),
    {ok, #{blocks := [{_, Offs}]}} = webrtc_flexfec:decode(hd(webrtc_flexfec:protect(packets(110), 1)), 1),
    ?assertEqual(lists:seq(0, 109), Offs).

%% §4.2.2.2: fixed L columns and D rows.
fixed_rows_and_columns_test() ->
    Hdr = <<0:1, 1:1, 0:6, 96, 0:16, 0:32>>,
    {ok, #{blocks := [{100, [0, 1, 2, 3]}]}} = webrtc_flexfec:decode(<<Hdr/binary, 100:16, 4, 0>>, 1),
    {ok, #{blocks := [{100, [0, 1, 2, 3]}]}} = webrtc_flexfec:decode(<<Hdr/binary, 100:16, 4, 1>>, 1),
    {ok, #{blocks := [{100, [0, 4, 8]}]}} = webrtc_flexfec:decode(<<Hdr/binary, 100:16, 4, 3>>, 1),
    ?assertEqual({error, reserved}, webrtc_flexfec:decode(<<Hdr/binary, 100:16, 0, 0>>, 1)).

%% A column of a fixed block recovers like a mask.
column_recovery_test() ->
    Pkts = packets(12),
    Column = [P || {I, P} <- lists:enumerate(0, Pkts), I rem 4 =:= 1],
    [Masked] = webrtc_flexfec:protect(Column, 1),
    <<0:1, 0:1, B0:6, B1, L:16, Ts:32, _Base:16, _:16, Data/binary>> = Masked,
    [{Base, _} | _] = Column,
    Fixed = <<0:1, 1:1, B0:6, B1, L:16, Ts:32, Base:16, 4, 3, Data/binary>>,
    [{_, Lost} | _] = Column,
    {Got, _} = recover(Pkts -- [hd(Column)], [Fixed]),
    ?assertEqual([Lost], Got).

%% §4.2.2.3: a retransmission is the source packet, R and F in place of
%% the version.
retransmission_test() ->
    [{_, <<2:2, Rest/bits>> = Src} | _] = packets(1),
    ?assertEqual({retransmission, Src}, webrtc_flexfec:decode(<<1:1, 0:1, Rest/bits>>, 0)).

errors_test() ->
    ?assertEqual({error, reserved}, webrtc_flexfec:decode(<<1:1, 1:1, 0:94>>, 1)),
    ?assertEqual({error, truncated}, webrtc_flexfec:decode(<<0:64>>, 1)),
    ?assertEqual({error, truncated}, webrtc_flexfec:decode(<<0:96>>, 0)),
    %% A mask cut short.
    ?assertEqual({error, truncated}, webrtc_flexfec:decode(<<0:64, 1:16, 1:1, 0:15, 0:8>>, 1)).
