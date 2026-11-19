%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for webrtc_sctp_crc32c (RFC 9260 Appendix A, RFC 3720 B.4,
%% RFC 9653 Figure 1).
-module(webrtc_sctp_crc32c_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_sctp.hrl").

-import(webrtc_test_hex, [b/1]).

-define(MASK, 16#FFFFFFFF).

%% Bitwise reference implementation.
naive(Bin) ->
    naive(Bin, ?MASK) bxor ?MASK.

naive(<<B, Rest/binary>>, C) ->
    naive(Rest, bits(C bxor B, 8));
naive(<<>>, C) ->
    C.

bits(C, 0) ->
    C;
bits(C, N) ->
    case C band 1 of
        1 -> bits((C bsr 1) bxor 16#82F63B78, N - 1);
        0 -> bits(C bsr 1, N - 1)
    end.

crc(X) -> webrtc_sctp_crc32c:crc32c(X).

check_value_test() ->
    ?assertEqual(16#E3069283, crc(<<"123456789">>)),
    ?assertEqual(16#E3069283, naive(<<"123456789">>)).

empty_test() ->
    ?assertEqual(0, crc(<<>>)),
    ?assertEqual(0, crc([])),
    ?assertEqual(0, webrtc_sctp_crc32c:update(0, <<>>)).

iscsi_vectors_test_() ->
    Asc = list_to_binary(lists:seq(0, 31)),
    Desc = list_to_binary(lists:seq(31, 0, -1)),
    [
        ?_assertEqual(16#8A9136AA, crc(binary:copy(<<0>>, 32))),
        ?_assertEqual(16#62A8AB43, crc(binary:copy(<<16#FF>>, 32))),
        ?_assertEqual(16#46DD794E, crc(Asc)),
        ?_assertEqual(16#113FDB5C, crc(Desc))
    ].

%% RFC 9653 Figure 1: an INIT packet whose correct CRC32c is zero.
rfc9653_figure1_test() ->
    Pkt = b(
        "13 89 13 89 00 00 00 00 00 00 00 00\n"
        "         01 00 00 14 fc b7 5c ca 00 00 05 dc 00 01 00 01 00 00 00 00"
    ),
    ?assertEqual(0, crc(Pkt)),
    ?assertEqual(0, naive(Pkt)).

%% A COOKIE ACK packet (ports 5000, vtag 16#01020304) computed by hand
%% with the bitwise reference; the checksum is stored little endian.
sctp_placement_test() ->
    Zeroed = b("13 88 13 88 01 02 03 04 00 00 00 00 0b 00 00 04"),
    Crc = naive(Zeroed),
    ?assertEqual(Crc, crc(Zeroed)),
    <<H:8/binary, _:4/binary, Rest/binary>> = Zeroed,
    ?assertEqual(16#A5515AEE, Crc),
    Wire = <<H/binary, Crc:32/little, Rest/binary>>,
    %% Least significant byte first, as RFC 3720 B.4 prints the digest of
    %% 32 zero bytes ("aa 36 91 8a" for 16#8A9136AA).
    ?assertEqual(b("13 88 13 88 01 02 03 04 ee 5a 51 a5 0b 00 00 04"), Wire),
    ?assertEqual(
        Wire,
        webrtc_sctp_chunk:encode(#sctp_packet{vtag = 16#01020304, chunks = [cookie_ack]})
    ),
    ?assert(webrtc_sctp_chunk:checksum_ok(Wire, false)).

iodata_test() ->
    ?assertEqual(16#E3069283, crc([<<"12">>, [$3, [<<"45">>, $6]], "789"])),
    ?assertEqual(16#E3069283, crc("123456789")).

incremental_test() ->
    Bin = rand_bytes(1000),
    Full = crc(Bin),
    ?assertEqual(Full, webrtc_sctp_crc32c:update(0, Bin)),
    lists:foreach(
        fun(N) ->
            <<A:N/binary, B/binary>> = Bin,
            ?assertEqual(Full, webrtc_sctp_crc32c:update(crc(A), B)),
            ?assertEqual(Full, crc([A, B]))
        end,
        [0, 1, 3, 7, 8, 9, 15, 16, 17, 500, 999, 1000]
    ).

random_vs_naive_test() ->
    Sizes = lists:seq(0, 70) ++ [127, 128, 129, 1000, 4097, 65537],
    lists:foreach(
        fun(N) ->
            Bin = rand_bytes(N),
            ?assertEqual(naive(Bin), crc(Bin))
        end,
        Sizes
    ).

%% Unaligned sub binaries must give the same result.
sub_binary_test() ->
    Big = rand_bytes(200),
    lists:foreach(
        fun(Off) ->
            Sub = binary:part(Big, Off, 150),
            ?assertEqual(naive(Sub), crc(Sub))
        end,
        lists:seq(0, 9)
    ).

throughput_test() ->
    Bin = rand_bytes(1 bsl 20),
    _ = crc(Bin),
    Rounds = 10,
    {Us, _} = timer:tc(fun() -> [crc(Bin) || _ <- lists:seq(1, Rounds)] end),
    MBs = Rounds * 1.048576 * 1.0e6 / max(Us, 1),
    ?debugFmt("CRC32c throughput on 1 MiB: ~.1f MB/s", [MBs]).

rand_bytes(N) ->
    crypto:strong_rand_bytes(N).
