%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for webrtc_sctp_chunk and webrtc_sctp_param (RFC 9260 §3,
%% RFC 3758, RFC 4820, RFC 6525, RFC 8260, RFC 9653).
-module(webrtc_sctp_chunk_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_sctp.hrl").

-import(webrtc_test_hex, [b/1]).

%%--------------------------------------------------------------------
%% Chunk vectors: {Name, Term, Encoded bytes including padding}
%%--------------------------------------------------------------------

chunk_vectors() ->
    [
        {data, #sctp_data{tsn = 1, sid = 2, mid = 3, ppid = 51, data = <<"abc">>},
            "00 03 00 13 00 00 00 01 00 02 00 03 00 00 00 33 61 62 63 00"},
        {data_all_flags,
            #sctp_data{
                tsn = 16#FFFFFFFF,
                sid = 16#FFFF,
                mid = 16#FFFF,
                ppid = 16#FFFFFFFF,
                unordered = true,
                immediate = true,
                data = <<1, 2, 3, 4>>
            },
            "00 0f 00 14 ff ff ff ff ff ff ff ff ff ff ff ff 01 02 03 04"},
        {data_middle_fragment,
            #sctp_data{
                tsn = 9,
                sid = 0,
                mid = 1,
                ppid = 50,
                beginning = false,
                ending = false,
                data = <<"x">>
            },
            "00 00 00 11 00 00 00 09 00 00 00 01 00 00 00 32 78 00 00 00"},
        {data_empty, #sctp_data{tsn = 5, sid = 1, mid = 0, ppid = 56, data = <<>>},
            "00 03 00 10 00 00 00 05 00 01 00 00 00 00 00 38"},
        {idata_first,
            #sctp_data{
                idata = true, tsn = 10, sid = 1, mid = 7, ppid = 53, ending = false, data = <<"hi">>
            },
            "40 02 00 16 00 00 00 0a 00 01 00 00 00 00 00 07 00 00 00 35 68 69 00 00"},
        {idata_fragment,
            #sctp_data{
                idata = true,
                tsn = 11,
                sid = 1,
                mid = 16#01020304,
                fsn = 4,
                unordered = true,
                beginning = false,
                ending = true,
                data = <<"end">>
            },
            "40 05 00 17 00 00 00 0b 00 01 00 00 01 02 03 04 00 00 00 04 65 6e 64 00"},
        {init,
            #sctp_init{
                tag = 16#01020304,
                a_rwnd = 131072,
                os = 1024,
                mis = 1024,
                tsn = 16#0A0B0C0D,
                params = [forward_tsn_supported, {supported_extensions, [130, 192, 194]}]
            },
            "01 00 00 1f 01 02 03 04 00 02 00 00 04 00 04 00 0a 0b 0c 0d\n"
            "             c0 00 00 04 80 08 00 07 82 c0 c2 00"},
        {init_ack,
            #sctp_init{
                ack = true,
                tag = 7,
                a_rwnd = 1500,
                os = 1,
                mis = 2,
                tsn = 3,
                params = [{state_cookie, <<"ck">>}, {zero_checksum_acceptable, 1}]
            },
            "02 00 00 24 00 00 00 07 00 00 05 dc 00 01 00 02 00 00 00 03\n"
            "             00 07 00 06 63 6b 00 00 80 01 00 08 00 00 00 01"},
        {init_no_params, #sctp_init{tag = 1, a_rwnd = 2, os = 3, mis = 4, tsn = 5},
            "01 00 00 14 00 00 00 01 00 00 00 02 00 03 00 04 00 00 00 05"},
        {sack, #sctp_sack{cum_tsn = 100, a_rwnd = 4096, gaps = [{2, 3}, {5, 5}], dups = [99]},
            "03 00 00 1c 00 00 00 64 00 00 10 00 00 02 00 01\n"
            "             00 02 00 03 00 05 00 05 00 00 00 63"},
        {sack_empty, #sctp_sack{cum_tsn = 1, a_rwnd = 2},
            "03 00 00 10 00 00 00 01 00 00 00 02 00 00 00 00"},
        {heartbeat, {heartbeat, <<1, 2, 3, 4, 5>>},
            "04 00 00 0d 00 01 00 09 01 02 03 04 05 00 00 00"},
        {heartbeat_ack, {heartbeat_ack, <<1, 2, 3, 4>>}, "05 00 00 0c 00 01 00 08 01 02 03 04"},
        {abort_t, {abort, true, [{user_abort, <<"bye">>}]}, "06 01 00 0b 00 0c 00 07 62 79 65 00"},
        {abort_empty, {abort, false, []}, "06 00 00 04"},
        {abort_two_causes, {abort, false, [{protocol_violation, <<"x">>}, out_of_resource]},
            "06 00 00 10 00 0d 00 05 78 00 00 00 00 04 00 04"},
        {shutdown, {shutdown, 16#11223344}, "07 00 00 08 11 22 33 44"},
        {shutdown_ack, shutdown_ack, "08 00 00 04"},
        {op_error, {op_error, [{invalid_stream, 5}, {missing_param, [7]}]},
            "09 00 00 16 00 01 00 08 00 05 00 00 00 02 00 0a 00 00 00 01 00 07 00 00"},
        {cookie_echo, {cookie_echo, <<"cookie">>}, "0a 00 00 0a 63 6f 6f 6b 69 65 00 00"},
        {cookie_ack, cookie_ack, "0b 00 00 04"},
        {shutdown_complete_t, {shutdown_complete, true}, "0e 01 00 04"},
        {shutdown_complete, {shutdown_complete, false}, "0e 00 00 04"},
        {forward_tsn, {forward_tsn, 200, [{1, 5}, {2, 6}]},
            "c0 00 00 10 00 00 00 c8 00 01 00 05 00 02 00 06"},
        {forward_tsn_empty, {forward_tsn, 1, []}, "c0 00 00 08 00 00 00 01"},
        {i_forward_tsn, {i_forward_tsn, 300, [{1, true, 9}, {2, false, 10}]},
            "c2 00 00 18 00 00 01 2c 00 01 00 01 00 00 00 09 00 02 00 00 00 00 00 0a"},
        {reconfig_out_reset, {reconfig, [{out_reset, 1, 0, 16, [1, 2, 3]}]},
            "82 00 00 1a 00 0d 00 16 00 00 00 01 00 00 00 00 00 00 00 10\n"
            "             00 01 00 02 00 03 00 00"},
        {reconfig_response, {reconfig, [{reconf_response, 1, success_performed, undefined}]},
            "82 00 00 10 00 10 00 0c 00 00 00 01 00 00 00 01"},
        {reconfig_response_tsns, {reconfig, [{reconf_response, 2, denied, {5, 6}}]},
            "82 00 00 18 00 10 00 14 00 00 00 02 00 00 00 02 00 00 00 05 00 00 00 06"},
        {reconfig_out_in, {reconfig, [{out_reset, 1, 0, 16, [1]}, {in_reset, 2, [4]}]},
            "82 00 00 22 00 0d 00 12 00 00 00 01 00 00 00 00 00 00 00 10\n"
            "             00 01 00 00 00 0e 00 0a 00 00 00 02 00 04 00 00"},
        {pad, {pad, 3}, "84 00 00 07 00 00 00 00"},
        {pad_empty, {pad, 0}, "84 00 00 04"},
        {unknown, {unknown_chunk, 16#80, 5, <<1, 2, 3>>}, "80 05 00 07 01 02 03 00"},
        {unknown_ecne, {unknown_chunk, 12, 0, <<0, 0, 0, 1>>}, "0c 00 00 08 00 00 00 01"}
    ].

chunk_encode_test_() ->
    [
        {atom_to_list(Name), ?_assertEqual(b(Hex), webrtc_sctp_chunk:encode_chunk(Term))}
     || {Name, Term, Hex} <- chunk_vectors()
    ].

chunk_decode_test_() ->
    [
        {atom_to_list(Name), ?_assertEqual({ok, [Term]}, webrtc_sctp_chunk:decode_chunks(b(Hex)))}
     || {Name, Term, Hex} <- chunk_vectors()
    ].

chunk_size_test_() ->
    [
        {atom_to_list(Name), ?_assertEqual(byte_size(b(Hex)), webrtc_sctp_chunk:chunk_size(Term))}
     || {Name, Term, Hex} <- chunk_vectors()
    ].

all_vectors_in_one_area_test() ->
    Terms = [T || {_, T, _} <- chunk_vectors()],
    Bin = iolist_to_binary([b(H) || {_, _, H} <- chunk_vectors()]),
    ?assertEqual({ok, Terms}, webrtc_sctp_chunk:decode_chunks(Bin)).

%% Every truncation inside a chunk must fail, alone or in a packet.
truncation_test_() ->
    [
        {atom_to_list(Name), fun() -> check_truncations(b(Hex)) end}
     || {Name, _Term, Hex} <- chunk_vectors()
    ].

check_truncations(Bin) ->
    <<_:16, Len:16, _/binary>> = Bin,
    Hdr = <<5000:16, 5000:16, 1:32, 0:32>>,
    lists:foreach(
        fun(N) ->
            Part = binary:part(Bin, 0, N),
            ?assertMatch({N, {error, _}}, {N, webrtc_sctp_chunk:decode_chunks(Part)}),
            ?assertMatch(
                {N, {error, _}}, {N, webrtc_sctp_chunk:decode(<<Hdr/binary, Part/binary>>)}
            )
        end,
        lists:seq(1, Len - 1)
    ).

%% The unpadded chunk (missing final padding) decodes the same.
missing_final_padding_test_() ->
    [
        {atom_to_list(Name), fun() ->
            Bin = b(Hex),
            <<_:16, Len:16, _/binary>> = Bin,
            ?assertEqual({ok, [Term]}, webrtc_sctp_chunk:decode_chunks(binary:part(Bin, 0, Len)))
        end}
     || {Name, Term, Hex} <- chunk_vectors()
    ].

%%--------------------------------------------------------------------
%% Strict validation
%%--------------------------------------------------------------------

dc(Hex) -> webrtc_sctp_chunk:decode_chunks(b(Hex)).

bad_lengths_test_() ->
    [
        {"sack count mismatch",
            ?_assertEqual(
                {error, {bad_chunk, 3}},
                dc("03 00 00 14 00 00 00 01 00 00 00 02 00 01 00 01 00 02 00 03")
            )},
        {"sack too short",
            ?_assertEqual({error, {bad_chunk, 3}}, dc("03 00 00 0c 00 00 00 01 00 00 00 02"))},
        {"shutdown len 12",
            ?_assertEqual({error, {bad_chunk, 7}}, dc("07 00 00 0c 00 00 00 01 00 00 00 00"))},
        {"shutdown len 4", ?_assertEqual({error, {bad_chunk, 7}}, dc("07 00 00 04"))},
        {"shutdown ack len 8",
            ?_assertEqual({error, {bad_chunk, 8}}, dc("08 00 00 08 00 00 00 00"))},
        {"cookie ack len 8",
            ?_assertEqual({error, {bad_chunk, 11}}, dc("0b 00 00 08 00 00 00 00"))},
        {"shutdown complete len 8",
            ?_assertEqual({error, {bad_chunk, 14}}, dc("0e 00 00 08 00 00 00 00"))},
        {"forward tsn len 10",
            ?_assertEqual({error, {bad_chunk, 192}}, dc("c0 00 00 0a 00 00 00 01 00 01 00 00"))},
        {"forward tsn len 4", ?_assertEqual({error, {bad_chunk, 192}}, dc("c0 00 00 04"))},
        {"i-forward tsn len 12",
            ?_assertEqual({error, {bad_chunk, 194}}, dc("c2 00 00 0c 00 00 00 01 00 01 00 00"))},
        {"data len 15",
            ?_assertEqual(
                {error, {bad_chunk, 0}}, dc("00 03 00 0f 00 00 00 01 00 02 00 03 00 00 00 00")
            )},
        {"idata len 19",
            ?_assertEqual(
                {error, {bad_chunk, 64}},
                dc("40 03 00 13 00 00 00 01 00 02 00 00 00 00 00 03 00 00 00 00")
            )},
        {"init len 16",
            ?_assertEqual(
                {error, {bad_chunk, 1}}, dc("01 00 00 10 00 00 00 01 00 00 00 02 00 03 00 04")
            )},
        {"init ack len 16",
            ?_assertEqual(
                {error, {bad_chunk, 2}}, dc("02 00 00 10 00 00 00 01 00 00 00 02 00 03 00 04")
            )},
        {"chunk length 2", ?_assertEqual({error, {bad_chunk, 0}}, dc("00 00 00 02"))},
        {"chunk length 0", ?_assertEqual({error, {bad_chunk, 11}}, dc("0b 00 00 00"))},
        {"chunk length beyond area",
            ?_assertEqual({error, {bad_chunk, 10}}, dc("0a 00 00 10 01 02 03 04"))},
        {"heartbeat without info",
            ?_assertEqual({error, {bad_chunk, 4}}, dc("04 00 00 08 00 02 00 04"))},
        {"heartbeat empty", ?_assertEqual({error, {bad_chunk, 4}}, dc("04 00 00 04"))},
        {"heartbeat bad param length",
            ?_assertEqual({error, {bad_param, 1}}, dc("04 00 00 08 00 01 00 0c"))},
        {"heartbeat trailing bytes in value",
            ?_assertEqual({error, {bad_chunk, 5}}, dc("05 00 00 0a 00 01 00 04 00 00 00 00"))},
        {"empty reconfig", ?_assertEqual({error, {bad_chunk, 130}}, dc("82 00 00 04"))},
        {"reconf response len 16",
            ?_assertEqual(
                {error, {bad_param, 16}},
                dc("82 00 00 14 00 10 00 10 00 00 00 01 00 00 00 01 00 00 00 05")
            )},
        {"ipv4 param len 12",
            ?_assertEqual(
                {error, {bad_param, 5}},
                dc(
                    "01 00 00 20 00 00 00 01 00 00 00 02 00 03 00 04 00 00 00 05\n"
                    "                    00 05 00 0c c0 00 02 01 00 00 00 00"
                )
            )},
        {"abort bad cause",
            ?_assertEqual({error, {bad_cause, 4}}, dc("06 00 00 0c 00 04 00 08 00 00 00 00"))},
        {"error cause beyond chunk",
            ?_assertEqual({error, {bad_cause, 12}}, dc("09 00 00 08 00 0c 00 10"))}
    ].

trailing_bytes_test_() ->
    [
        ?_assertEqual({error, trailing_bytes}, dc("0b 00 00 04 00")),
        ?_assertEqual({error, trailing_bytes}, dc("0b 00 00 04 00 00")),
        ?_assertEqual({error, trailing_bytes}, dc("0b 00 00 04 00 00 00")),
        ?_assertEqual({error, trailing_bytes}, dc("00")),
        %% Partial padding after the last chunk.
        ?_assertEqual({error, trailing_bytes}, dc("0a 00 00 05 01 00")),
        %% A missing padding before another chunk.
        ?_assertMatch({error, _}, dc("0a 00 00 05 01 0b 00 00 04"))
    ].

padding_content_ignored_test() ->
    ?assertEqual(
        {ok, [{cookie_echo, <<1>>}, cookie_ack]}, dc("0a 00 00 05 01 ff ff ff 0b 00 00 04")
    ).

%% Padding of the last parameter may be counted in the chunk length.
last_param_padding_counted_test_() ->
    Init = #sctp_init{
        tag = 16#01020304,
        a_rwnd = 131072,
        os = 1024,
        mis = 1024,
        tsn = 16#0A0B0C0D,
        params = [forward_tsn_supported, {supported_extensions, [130, 192, 194]}]
    },
    [
        ?_assertEqual(
            {ok, [Init]},
            dc(
                "01 00 00 20 01 02 03 04 00 02 00 00 04 00 04 00 0a 0b 0c 0d\n"
                "                 c0 00 00 04 80 08 00 07 82 c0 c2 00"
            )
        ),
        ?_assertEqual(
            {ok, [{abort, true, [{user_abort, <<"bye">>}]}]},
            dc("06 01 00 0c 00 0c 00 07 62 79 65 00")
        ),
        ?_assertEqual(
            {ok, [{heartbeat, <<1, 2, 3, 4, 5>>}]},
            dc("04 00 00 10 00 01 00 09 01 02 03 04 05 00 00 00")
        )
    ].

ignored_flags_test_() ->
    [
        ?_assertEqual({ok, [cookie_ack]}, dc("0b ff 00 04")),
        ?_assertEqual({ok, [{shutdown, 1}]}, dc("07 ff 00 08 00 00 00 01")),
        ?_assertEqual({ok, [{abort, true, []}]}, dc("06 ff 00 04")),
        ?_assertEqual({ok, [{shutdown_complete, false}]}, dc("0e fe 00 04")),
        ?_assertEqual(
            {ok, [#sctp_sack{cum_tsn = 1, a_rwnd = 2}]},
            dc("03 ff 00 10 00 00 00 01 00 00 00 02 00 00 00 00")
        ),
        %% I-FORWARD-TSN reserved bits and I-DATA reserved field are ignored.
        ?_assertEqual(
            {ok, [{i_forward_tsn, 1, [{2, false, 3}]}]},
            dc("c2 00 00 10 00 00 00 01 00 02 ff fe 00 00 00 03")
        ),
        ?_assertEqual(
            {ok, [#sctp_data{idata = true, tsn = 1, sid = 2, mid = 3, ppid = 4, data = <<>>}]},
            dc("40 03 00 14 00 00 00 01 00 02 ff ff 00 00 00 03 00 00 00 04")
        ),
        %% Flag bits above I are ignored on DATA.
        ?_assertEqual(
            {ok, [#sctp_data{tsn = 1, sid = 2, mid = 3, ppid = 4, data = <<>>}]},
            dc("00 f3 00 10 00 00 00 01 00 02 00 03 00 00 00 04")
        )
    ].

pad_content_ignored_test() ->
    ?assertEqual({ok, [{pad, 3}]}, dc("84 00 00 07 01 02 03 00")).

encode_data_ssn_overflow_test() ->
    ?assertError(_, webrtc_sctp_chunk:encode_chunk(#sctp_data{mid = 16#10000})).

unrecognized_chunk_action_test_() ->
    A = fun webrtc_sctp_chunk:unrecognized_chunk_action/1,
    [
        ?_assertEqual({stop, false}, A(16#00)),
        ?_assertEqual({stop, false}, A(16#0F)),
        ?_assertEqual({stop, false}, A(16#3F)),
        ?_assertEqual({stop, true}, A(16#40)),
        ?_assertEqual({stop, true}, A(16#4F)),
        ?_assertEqual({skip, false}, A(16#80)),
        ?_assertEqual({skip, false}, A(16#8F)),
        ?_assertEqual({skip, true}, A(16#C0)),
        ?_assertEqual({skip, true}, A(16#CF)),
        ?_assertEqual({skip, true}, A(16#FF))
    ].

%%--------------------------------------------------------------------
%% Packets
%%--------------------------------------------------------------------

rfc9653_packet() ->
    b(
        "13 89 13 89 00 00 00 00 00 00 00 00\n"
        "         01 00 00 14 fc b7 5c ca 00 00 05 dc 00 01 00 01 00 00 00 00"
    ).

rfc9653_packet_test() ->
    Pkt = rfc9653_packet(),
    ?assertEqual(
        {ok, #sctp_packet{
            src_port = 5001,
            dst_port = 5001,
            vtag = 0,
            checksum = 0,
            chunks = [#sctp_init{tag = 16#FCB75CCA, a_rwnd = 1500, os = 1, mis = 1, tsn = 0}]
        }},
        webrtc_sctp_chunk:decode(Pkt)
    ),
    ?assert(webrtc_sctp_chunk:checksum_ok(Pkt, false)),
    ?assert(webrtc_sctp_chunk:checksum_ok(Pkt, true)),
    {ok, P} = webrtc_sctp_chunk:decode(Pkt),
    ?assertEqual(Pkt, webrtc_sctp_chunk:encode(P)),
    ?assertEqual(Pkt, webrtc_sctp_chunk:encode(P, #{checksum => zero})).

packet_roundtrip_test() ->
    P = #sctp_packet{
        src_port = 5000,
        dst_port = 5001,
        vtag = 16#DEADBEEF,
        chunks = [T || {_, T, _} <- chunk_vectors()]
    },
    Bin = webrtc_sctp_chunk:encode(P),
    ?assert(webrtc_sctp_chunk:checksum_ok(Bin, false)),
    <<_:8/binary, Csum:32/little, _/binary>> = Bin,
    ?assertEqual({ok, P#sctp_packet{checksum = Csum}}, webrtc_sctp_chunk:decode(Bin)),
    ?assertEqual(Bin, webrtc_sctp_chunk:encode(P#sctp_packet{checksum = 12345}, #{})).

checksum_test() ->
    P = #sctp_packet{vtag = 1, chunks = [cookie_ack, {shutdown, 7}]},
    Good = webrtc_sctp_chunk:encode(P),
    Zero = webrtc_sctp_chunk:encode(P, #{checksum => zero}),
    <<H:8/binary, Csum:32/little, Rest/binary>> = Good,
    Bad = <<H/binary, (Csum bxor 1):32/little, Rest/binary>>,
    ?assertEqual(<<H/binary, 0:32, Rest/binary>>, Zero),
    ?assert(webrtc_sctp_chunk:checksum_ok(Good, false)),
    ?assert(webrtc_sctp_chunk:checksum_ok(Good, true)),
    ?assertNot(webrtc_sctp_chunk:checksum_ok(Bad, false)),
    ?assertNot(webrtc_sctp_chunk:checksum_ok(Bad, true)),
    ?assertNot(webrtc_sctp_chunk:checksum_ok(Zero, false)),
    ?assert(webrtc_sctp_chunk:checksum_ok(Zero, true)),
    %% A flipped payload bit is detected.
    <<Pre:15/binary, X, Post/binary>> = Good,
    ?assertNot(webrtc_sctp_chunk:checksum_ok(<<Pre/binary, (X bxor 16#10), Post/binary>>, true)),
    ?assertNot(webrtc_sctp_chunk:checksum_ok(<<>>, true)),
    ?assertNot(webrtc_sctp_chunk:checksum_ok(<<0:88>>, true)),
    ?assert(webrtc_sctp_chunk:checksum_ok(<<0:96>>, true)).

packet_decode_errors_test_() ->
    [
        ?_assertEqual({error, too_short}, webrtc_sctp_chunk:decode(<<>>)),
        ?_assertEqual({error, too_short}, webrtc_sctp_chunk:decode(<<0:88>>)),
        ?_assertEqual(
            {ok, #sctp_packet{src_port = 1, dst_port = 2, vtag = 3, checksum = 4, chunks = []}},
            webrtc_sctp_chunk:decode(<<1:16, 2:16, 3:32, 4:32/little>>)
        ),
        ?_assertEqual(
            {error, trailing_bytes}, webrtc_sctp_chunk:decode(<<1:16, 2:16, 3:32, 4:32, 0, 0>>)
        ),
        ?_assertEqual(
            {error, {bad_chunk, 11}},
            webrtc_sctp_chunk:decode(<<1:16, 2:16, 3:32, 4:32, 11, 0, 0, 2>>)
        )
    ].

%%--------------------------------------------------------------------
%% INIT parameters
%%--------------------------------------------------------------------

param_vectors() ->
    [
        {{ipv4_address, {192, 0, 2, 1}}, "00 05 00 08 c0 00 02 01"},
        {
            {ipv6_address, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}},
            "00 06 00 14 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01"
        },
        {{state_cookie, <<"abcde">>}, "00 07 00 09 61 62 63 64 65 00 00 00"},
        {{state_cookie, <<>>}, "00 07 00 04"},
        {
            {unrecognized_param, <<16#43, 16#21, 0, 5, 9, 0, 0, 0>>},
            "00 08 00 0c 43 21 00 05 09 00 00 00"
        },
        {{cookie_preservative, 60000}, "00 09 00 08 00 00 ea 60"},
        {{host_name, <<"h", 0>>}, "00 0b 00 06 68 00 00 00"},
        {{supported_address_types, [5, 6]}, "00 0c 00 08 00 05 00 06"},
        {{supported_address_types, [5]}, "00 0c 00 06 00 05 00 00"},
        {ecn_capable, "80 00 00 04"},
        {{zero_checksum_acceptable, 1}, "80 01 00 08 00 00 00 01"},
        {{padding, 2}, "80 05 00 06 00 00 00 00"},
        {{padding, 0}, "80 05 00 04"},
        {{supported_extensions, [130, 192, 64, 194]}, "80 08 00 08 82 c0 40 c2"},
        {{supported_extensions, []}, "80 08 00 04"},
        {forward_tsn_supported, "c0 00 00 04"},
        {{unknown_param, 16#4321, <<9>>}, "43 21 00 05 09 00 00 00"},
        {{unknown_param, 1, <<"hb">>}, "00 01 00 06 68 62 00 00"}
    ].

param_roundtrip_test_() ->
    [
        ?_test(begin
            Bin = b(Hex),
            ?assertEqual(Bin, webrtc_sctp_param:encode_param(P)),
            ?assertEqual(Bin, webrtc_sctp_param:encode_params([P])),
            ?assertEqual({ok, [P]}, webrtc_sctp_param:decode_params(Bin))
        end)
     || {P, Hex} <- param_vectors()
    ].

params_list_test() ->
    Ps = [P || {P, _} <- param_vectors()],
    Bin = iolist_to_binary([b(H) || {_, H} <- param_vectors()]),
    ?assertEqual(Bin, webrtc_sctp_param:encode_params(Ps)),
    ?assertEqual({ok, Ps}, webrtc_sctp_param:decode_params(Bin)),
    ?assertEqual({ok, []}, webrtc_sctp_param:decode_params(<<>>)),
    ?assertEqual(<<>>, webrtc_sctp_param:encode_params([])).

param_truncation_test_() ->
    [
        ?_test(check_tlv_truncations(fun webrtc_sctp_param:decode_params/1, b(Hex)))
     || {_, Hex} <- param_vectors()
    ].

check_tlv_truncations(Decode, Bin) ->
    <<_:16, Len:16, _/binary>> = Bin,
    lists:foreach(
        fun(N) -> ?assertMatch({N, {error, _}}, {N, Decode(binary:part(Bin, 0, N))}) end,
        lists:seq(1, Len - 1)
    ),
    ?assertMatch({ok, [_]}, Decode(binary:part(Bin, 0, Len))).

bad_params_test_() ->
    D = fun(Hex) -> webrtc_sctp_param:decode_params(b(Hex)) end,
    [
        ?_assertEqual({error, {bad_param, 5}}, D("00 05 00 0c c0 00 02 01 00 00 00 00")),
        ?_assertEqual({error, {bad_param, 5}}, D("00 05 00 07 c0 00 02 00")),
        ?_assertEqual({error, {bad_param, 6}}, D("00 06 00 08 00 00 00 00")),
        ?_assertEqual({error, {bad_param, 9}}, D("00 09 00 04")),
        ?_assertEqual({error, {bad_param, 12}}, D("00 0c 00 07 00 05 00 00")),
        ?_assertEqual({error, {bad_param, 16#8000}}, D("80 00 00 08 00 00 00 00")),
        ?_assertEqual({error, {bad_param, 16#8001}}, D("80 01 00 04")),
        ?_assertEqual({error, {bad_param, 16#C000}}, D("c0 00 00 05 00 00 00 00")),
        ?_assertEqual({error, {bad_param, 7}}, D("00 07 00 02")),
        ?_assertEqual({error, {bad_param, 7}}, D("00 07 00 10 00 00 00 00")),
        ?_assertEqual({error, trailing_bytes}, D("c0 00 00 04 00")),
        ?_assertEqual({error, trailing_bytes}, D("00 07 00 05 01 00"))
    ].

unrecognized_param_action_test_() ->
    A = fun webrtc_sctp_param:unrecognized_param_action/1,
    [
        ?_assertEqual({stop, false}, A(16#0005)),
        ?_assertEqual({stop, false}, A(16#3FFF)),
        ?_assertEqual({stop, true}, A(16#4001)),
        ?_assertEqual({skip, false}, A(16#8005)),
        ?_assertEqual({skip, true}, A(16#C000)),
        ?_assertEqual({skip, true}, A(16#FFFF))
    ].

%%--------------------------------------------------------------------
%% RE-CONFIG parameters
%%--------------------------------------------------------------------

reconf_vectors() ->
    [
        {
            {out_reset, 1, 2, 3, [4, 5]},
            "00 0d 00 14 00 00 00 01 00 00 00 02 00 00 00 03 00 04 00 05"
        },
        {{out_reset, 1, 2, 3, []}, "00 0d 00 10 00 00 00 01 00 00 00 02 00 00 00 03"},
        {{out_reset, 1, 2, 3, [7]}, "00 0d 00 12 00 00 00 01 00 00 00 02 00 00 00 03 00 07 00 00"},
        {{in_reset, 9, [1, 2, 3]}, "00 0e 00 0e 00 00 00 09 00 01 00 02 00 03 00 00"},
        {{in_reset, 9, []}, "00 0e 00 08 00 00 00 09"},
        {{tsn_reset, 4}, "00 0f 00 08 00 00 00 04"},
        {
            {reconf_response, 1, success_nothing_to_do, undefined},
            "00 10 00 0c 00 00 00 01 00 00 00 00"
        },
        {{reconf_response, 1, success_performed, undefined}, "00 10 00 0c 00 00 00 01 00 00 00 01"},
        {{reconf_response, 1, denied, undefined}, "00 10 00 0c 00 00 00 01 00 00 00 02"},
        {{reconf_response, 1, error_wrong_ssn, undefined}, "00 10 00 0c 00 00 00 01 00 00 00 03"},
        {
            {reconf_response, 1, error_request_in_progress, undefined},
            "00 10 00 0c 00 00 00 01 00 00 00 04"
        },
        {
            {reconf_response, 1, error_bad_sequence_number, undefined},
            "00 10 00 0c 00 00 00 01 00 00 00 05"
        },
        {{reconf_response, 1, in_progress, undefined}, "00 10 00 0c 00 00 00 01 00 00 00 06"},
        {{reconf_response, 1, 99, undefined}, "00 10 00 0c 00 00 00 01 00 00 00 63"},
        {
            {reconf_response, 2, success_performed, {16#10, 16#20}},
            "00 10 00 14 00 00 00 02 00 00 00 01 00 00 00 10 00 00 00 20"
        },
        {{add_out_streams, 5, 16}, "00 11 00 0c 00 00 00 05 00 10 00 00"},
        {{add_in_streams, 6, 17}, "00 12 00 0c 00 00 00 06 00 11 00 00"},
        {{unknown_param, 16#C000, <<>>}, "c0 00 00 04"},
        {{unknown_param, 19, <<1, 2>>}, "00 13 00 06 01 02 00 00"}
    ].

reconf_roundtrip_test_() ->
    [
        ?_test(begin
            Bin = b(Hex),
            ?assertEqual(Bin, webrtc_sctp_param:encode_reconf_params([P])),
            ?assertEqual({ok, [P]}, webrtc_sctp_param:decode_reconf_params(Bin)),
            check_tlv_truncations(fun webrtc_sctp_param:decode_reconf_params/1, Bin)
        end)
     || {P, Hex} <- reconf_vectors()
    ].

reconf_list_test() ->
    Ps = [P || {P, _} <- reconf_vectors()],
    Bin = webrtc_sctp_param:encode_reconf_params(Ps),
    ?assertEqual({ok, Ps}, webrtc_sctp_param:decode_reconf_params(Bin)),
    Chunk = webrtc_sctp_chunk:encode_chunk({reconfig, Ps}),
    ?assertEqual({ok, [{reconfig, Ps}]}, webrtc_sctp_chunk:decode_chunks(Chunk)).

bad_reconf_test_() ->
    D = fun(Hex) -> webrtc_sctp_param:decode_reconf_params(b(Hex)) end,
    [
        ?_assertEqual(
            {error, {bad_param, 16}}, D("00 10 00 10 00 00 00 01 00 00 00 01 00 00 00 05")
        ),
        ?_assertEqual({error, {bad_param, 16}}, D("00 10 00 08 00 00 00 01")),
        ?_assertEqual({error, {bad_param, 13}}, D("00 0d 00 0c 00 00 00 01 00 00 00 02")),
        ?_assertEqual(
            {error, {bad_param, 13}},
            D("00 0d 00 11 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 00")
        ),
        ?_assertEqual({error, {bad_param, 14}}, D("00 0e 00 09 00 00 00 01 00 00 00 00")),
        ?_assertEqual({error, {bad_param, 15}}, D("00 0f 00 0c 00 00 00 01 00 00 00 00")),
        ?_assertEqual({error, {bad_param, 17}}, D("00 11 00 08 00 00 00 01")),
        ?_assertEqual(
            {error, {bad_param, 18}}, D("00 12 00 10 00 00 00 01 00 01 00 00 00 00 00 00")
        )
    ].

%%--------------------------------------------------------------------
%% Error causes
%%--------------------------------------------------------------------

cause_vectors() ->
    [
        {{invalid_stream, 5}, "00 01 00 08 00 05 00 00"},
        {{missing_param, [7]}, "00 02 00 0a 00 00 00 01 00 07 00 00"},
        {{missing_param, [7, 9]}, "00 02 00 0c 00 00 00 02 00 07 00 09"},
        {{missing_param, []}, "00 02 00 08 00 00 00 00"},
        {{stale_cookie, 1000}, "00 03 00 08 00 00 03 e8"},
        {out_of_resource, "00 04 00 04"},
        {{unresolvable_address, <<0, 5, 0, 8, 1, 2, 3, 4>>}, "00 05 00 0c 00 05 00 08 01 02 03 04"},
        {{unrecognized_chunk, <<16#0c, 0, 0, 5, 1>>}, "00 06 00 09 0c 00 00 05 01 00 00 00"},
        {invalid_mandatory_param, "00 07 00 04"},
        {{unrecognized_params, <<16#43, 16#21, 0, 4>>}, "00 08 00 08 43 21 00 04"},
        {{no_user_data, 16#01020304}, "00 09 00 08 01 02 03 04"},
        {cookie_while_shutting_down, "00 0a 00 04"},
        {
            {restart_new_addresses, <<0, 5, 0, 8, 10, 0, 0, 1>>},
            "00 0b 00 0c 00 05 00 08 0a 00 00 01"
        },
        {{user_abort, <<"bye">>}, "00 0c 00 07 62 79 65 00"},
        {{user_abort, <<>>}, "00 0c 00 04"},
        {{protocol_violation, <<"oops!">>}, "00 0d 00 09 6f 6f 70 73 21 00 00 00"},
        {{unknown_cause, 16#0101, <<1, 2>>}, "01 01 00 06 01 02 00 00"}
    ].

cause_roundtrip_test_() ->
    [
        ?_test(begin
            Bin = b(Hex),
            ?assertEqual(Bin, webrtc_sctp_param:encode_causes([C])),
            ?assertEqual({ok, [C]}, webrtc_sctp_param:decode_causes(Bin)),
            check_tlv_truncations(fun webrtc_sctp_param:decode_causes/1, Bin),
            %% Inside an ERROR chunk too.
            Chunk = webrtc_sctp_chunk:encode_chunk({op_error, [C]}),
            ?assertEqual({ok, [{op_error, [C]}]}, webrtc_sctp_chunk:decode_chunks(Chunk))
        end)
     || {C, Hex} <- cause_vectors()
    ].

causes_list_test() ->
    Cs = [C || {C, _} <- cause_vectors()],
    Bin = webrtc_sctp_param:encode_causes(Cs),
    ?assertEqual({ok, Cs}, webrtc_sctp_param:decode_causes(Bin)),
    ?assertEqual({ok, []}, webrtc_sctp_param:decode_causes(<<>>)).

bad_causes_test_() ->
    D = fun(Hex) -> webrtc_sctp_param:decode_causes(b(Hex)) end,
    [
        ?_assertEqual({error, {bad_cause, 1}}, D("00 01 00 04")),
        ?_assertEqual({error, {bad_cause, 2}}, D("00 02 00 0a 00 00 00 02 00 07 00 00")),
        ?_assertEqual({error, {bad_cause, 2}}, D("00 02 00 0c 00 00 00 01 00 07 00 09")),
        ?_assertEqual({error, {bad_cause, 3}}, D("00 03 00 0c 00 00 00 00 00 00 00 00")),
        ?_assertEqual({error, {bad_cause, 4}}, D("00 04 00 05 00 00 00 00")),
        ?_assertEqual({error, {bad_cause, 7}}, D("00 07 00 08 00 00 00 00")),
        ?_assertEqual({error, {bad_cause, 9}}, D("00 09 00 04")),
        ?_assertEqual({error, {bad_cause, 10}}, D("00 0a 00 08 00 00 00 00")),
        ?_assertEqual({error, {bad_cause, 12}}, D("00 0c 00 03")),
        ?_assertEqual({error, trailing_bytes}, D("00 04 00 04 00 00"))
    ].
