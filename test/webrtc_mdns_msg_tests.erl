%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% DNS message codec (RFC 1035 §4, RFC 6762) with packets written byte
%% by byte, in the shape real responders send them.
-module(webrtc_mdns_msg_tests).
-include_lib("eunit/include/eunit.hrl").

-define(M, webrtc_mdns_msg).

-define(NAME, "0c9a4bd2-5b1e-4f7a-9d3e-6a1b2c3d4e5f.local").
%% 0c9a4bd2-... as a 36 octet label, then "local", then the root.
-define(WIRE_NAME, 36, "0c9a4bd2-5b1e-4f7a-9d3e-6a1b2c3d4e5f", 5, "local", 0).

%% A multicast response as Chromium sends it: ID 0, QR and AA, no
%% question, an A answer with the cache-flush bit, TTL 120 and an NSEC
%% record in the additional section whose owner name and next-domain
%% field are compression pointers to offset 12.
chromium_response() ->
    <<16#00, 16#00, 16#84, 16#00, 16#00, 16#00, 16#00, 16#01, 16#00, 16#00, 16#00, 16#01,
      %% answer: name, type A, class IN | cache-flush, TTL 120, RDLENGTH 4
      ?WIRE_NAME, 16#00, 16#01, 16#80, 16#01, 16#00, 16#00, 16#00, 16#78, 16#00, 16#04,
      10, 0, 1, 87,
      %% additional: pointer to 12, type NSEC (47), TTL 120, RDLENGTH 5
      16#C0, 16#0C, 16#00, 16#2F, 16#80, 16#01, 16#00, 16#00, 16#00, 16#78, 16#00, 16#05,
      16#C0, 16#0C, 16#00, 16#01, 16#40>>.

%% A legacy unicast reply (RFC 6762 §6.7) as macOS mDNSResponder sends
%% it: query ID echoed, the question repeated with its QU bit, then A
%% and AAAA answers whose names point at the question (offset 12),
%% TTL 10, no cache-flush bit.
legacy_response() ->
    <<16#12, 16#34, 16#84, 16#00, 16#00, 16#01, 16#00, 16#02, 16#00, 16#00, 16#00, 16#00,
      ?WIRE_NAME, 16#00, 16#01, 16#80, 16#01,
      16#C0, 16#0C, 16#00, 16#01, 16#00, 16#01, 16#00, 16#00, 16#00, 16#0A, 16#00, 16#04,
      192, 168, 1, 20,
      16#C0, 16#0C, 16#00, 16#1C, 16#00, 16#01, 16#00, 16#00, 16#00, 16#0A, 16#00, 16#10,
      16#FE, 16#80, 0, 0, 0, 0, 0, 0, 16#02, 16#11, 16#22, 16#FF, 16#FE, 16#33, 16#44, 16#55>>.

%% A question for "local" at offset 12; the answer name is a label
%% followed by a pointer to it; the additional record's name points at
%% the answer name (offset 23), a pointer to a name ending in a pointer.
chained_response() ->
    <<16#00, 16#00, 16#84, 16#00, 16#00, 16#01, 16#00, 16#01, 16#00, 16#00, 16#00, 16#01,
      5, "local", 0, 16#00, 16#FF, 16#00, 16#01,
      4, "Host", 16#C0, 16#0C, 16#00, 16#01, 16#00, 16#01, 16#00, 16#00, 16#00, 16#3C, 16#00, 16#04,
      127, 0, 0, 1,
      16#C0, 16#17, 16#00, 16#1C, 16#80, 16#01, 16#00, 16#00, 16#00, 16#3C, 16#00, 16#10,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>.

chromium_test() ->
    {ok, M} = ?M:decode(chromium_response()),
    ?assertMatch(#{id := 0, qr := true, aa := true, tc := false, opcode := 0, rcode := 0, questions := []}, M),
    [A] = maps:get(answers, M),
    ?assertEqual(
        #{name => <<?NAME>>, type => a, class => 1, cache_flush => true, ttl => 120, data => {10, 0, 1, 87}}, A
    ),
    [Nsec] = maps:get(additional, M),
    ?assertMatch(#{name := <<?NAME>>, type := nsec, data := <<16#C0, 16#0C, 0, 1, 16#40>>}, Nsec).

legacy_test() ->
    {ok, M} = ?M:decode(legacy_response()),
    ?assertMatch(#{id := 16#1234, qr := true}, M),
    ?assertEqual([#{name => <<?NAME>>, type => a, class => 1, unicast => true}], maps:get(questions, M)),
    [A, AAAA] = maps:get(answers, M),
    ?assertMatch(#{name := <<?NAME>>, type := a, ttl := 10, cache_flush := false, data := {192, 168, 1, 20}}, A),
    ?assertMatch(
        #{name := <<?NAME>>, type := aaaa, data := {16#FE80, 0, 0, 0, 16#0211, 16#22FF, 16#FE33, 16#4455}}, AAAA
    ).

chained_pointers_test() ->
    {ok, M} = ?M:decode(chained_response()),
    ?assertMatch([#{name := <<"local">>, type := any}], maps:get(questions, M)),
    %% Names are lower-cased (RFC 6762 §16).
    ?assertMatch([#{name := <<"host.local">>, data := {127, 0, 0, 1}}], maps:get(answers, M)),
    ?assertMatch([#{name := <<"host.local">>, type := aaaa, cache_flush := true}], maps:get(additional, M)).

header(QD) -> <<0:16, 0:16, QD:16, 0:16, 0:16, 0:16>>.

self_pointer_test() ->
    ?assertEqual({error, forward_pointer}, ?M:decode(<<(header(1))/binary, 16#C0, 16#0C, 0, 1, 0, 1>>)).

pointer_loop_test() ->
    %% 12 -> 14 -> 12: the first pointer already goes forward.
    Bin = <<(header(1))/binary, 16#C0, 16#0E, 16#C0, 16#0C, 0, 1, 0, 1>>,
    ?assertEqual({error, forward_pointer}, ?M:decode(Bin)),
    %% A pointer into the name being read.
    Bin2 = <<(header(1))/binary, 1, "a", 16#C0, 16#0D, 0, 1, 0, 1>>,
    ?assertEqual({error, forward_pointer}, ?M:decode(Bin2)).

too_many_pointers_test() ->
    %% Question k points at question k-1: names follow more and more
    %% pointers until the limit.
    First = <<1, "x", 0, 0, 1, 0, 1>>,
    {Qs, _} = lists:foldl(
        fun(_, {Acc, Prev}) -> {<<Acc/binary, 3:2, Prev:14, 0, 1, 0, 1>>, 12 + byte_size(Acc)} end,
        {First, 12},
        lists:seq(1, 70)
    ),
    ?assertEqual({error, too_many_pointers}, ?M:decode(<<(header(71))/binary, Qs/binary>>)),
    {Ok, _} = lists:foldl(
        fun(_, {Acc, Prev}) -> {<<Acc/binary, 3:2, Prev:14, 0, 1, 0, 1>>, 12 + byte_size(Acc)} end,
        {First, 12},
        lists:seq(1, 10)
    ),
    {ok, #{questions := Q}} = ?M:decode(<<(header(11))/binary, Ok/binary>>),
    ?assertEqual(11, length(Q)),
    ?assert(lists:all(fun(#{name := N}) -> N =:= <<"x">> end, Q)).

name_too_long_test() ->
    Label = <<63, (binary:copy(<<"a">>, 63))/binary>>,
    Long = binary:copy(Label, 4),
    ?assertEqual({error, name_too_long}, ?M:decode(<<(header(1))/binary, Long/binary, 0, 0, 1, 0, 1>>)),
    %% 3 * 64 + (1 + 62) + 1 = 256 octets
    Long2 = <<(binary:copy(Label, 3))/binary, 62, (binary:copy(<<"b">>, 62))/binary>>,
    ?assertEqual({error, name_too_long}, ?M:decode(<<(header(1))/binary, Long2/binary, 0, 0, 1, 0, 1>>)),
    %% 255 octets is the maximum (RFC 1035 §2.3.4).
    Max = <<(binary:copy(Label, 3))/binary, 61, (binary:copy(<<"b">>, 61))/binary>>,
    ?assertMatch({ok, _}, ?M:decode(<<(header(1))/binary, Max/binary, 0, 0, 1, 0, 1>>)).

bad_label_type_test() ->
    ?assertEqual({error, bad_label_type}, ?M:decode(<<(header(1))/binary, 16#40, 0, 0, 1, 0, 1>>)),
    ?assertEqual({error, bad_label_type}, ?M:decode(<<(header(1))/binary, 16#80, 0, 0, 1, 0, 1>>)).

bad_rdata_length_test() ->
    Bin = <<0:16, 16#8400:16, 0:16, 1:16, 0:16, 0:16, 1, "a", 0, 0, 1, 0, 1, 0:32, 5:16, 1, 2, 3, 4, 5>>,
    ?assertEqual({error, bad_a_length}, ?M:decode(Bin)),
    Bin6 = <<0:16, 16#8400:16, 0:16, 1:16, 0:16, 0:16, 1, "a", 0, 0, 28, 0, 1, 0:32, 4:16, 1, 2, 3, 4>>,
    ?assertEqual({error, bad_aaaa_length}, ?M:decode(Bin6)).

escaped_labels_test() ->
    %% A label holding a dot cannot be confused with two labels.
    Bin = <<(header(1))/binary, 3, "a.b", 5, "LOCAL", 0, 0, 1, 0, 1>>,
    {ok, #{questions := [#{name := N}]}} = ?M:decode(Bin),
    ?assertEqual(<<"a\\.b.local">>, N).

every_truncation_test() ->
    lists:foreach(
        fun(Pkt) ->
            ?assertMatch({ok, _}, ?M:decode(Pkt)),
            [?assertMatch({error, _}, ?M:decode(binary:part(Pkt, 0, L))) || L <- lists:seq(0, byte_size(Pkt) - 1)]
        end,
        [chromium_response(), legacy_response(), chained_response()]
    ).

random_input_never_crashes_test() ->
    rand:seed(exsss, {1, 2, 3}),
    Pkts = [chromium_response(), legacy_response(), chained_response()],
    lists:foreach(
        fun(I) ->
            Bin =
                case I rem 2 of
                    0 -> rand:bytes(rand:uniform(300) - 1);
                    1 -> mutate(lists:nth(1 + I rem 3, Pkts))
                end,
            case ?M:decode(Bin) of
                {ok, #{}} -> ok;
                {error, _} -> ok
            end
        end,
        lists:seq(1, 20000)
    ).

mutate(Pkt) ->
    lists:foldl(
        fun(_, B) ->
            P = rand:uniform(byte_size(B)) - 1,
            <<H:P/binary, _, T/binary>> = B,
            <<H/binary, (rand:uniform(256) - 1), T/binary>>
        end,
        Pkt,
        lists:seq(1, rand:uniform(4))
    ).

encode_query_test() ->
    %% Byte layout of a QU question for A (RFC 6762 §5.4).
    Expected = <<16#AB, 16#CD, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, ?WIRE_NAME, 16#00, 16#01, 16#80, 16#01>>,
    ?assertEqual(Expected, ?M:encode_query(16#ABCD, [{<<?NAME>>, a, true}])),
    {ok, M} = ?M:decode(?M:encode_query(7, [{<<"x.local.">>, aaaa, false}])),
    ?assertMatch(#{id := 7, qr := false, questions := [#{name := <<"x.local">>, type := aaaa, unicast := false}]}, M).

encode_bad_name_test() ->
    ?assertError({bad_name, _}, ?M:encode_query(0, [{<<"a..local">>, a, false}])),
    ?assertError({bad_name, _}, ?M:encode_query(0, [{binary:copy(<<"a">>, 64), a, false}])).

encode_response_test() ->
    Bin = ?M:encode_response(
        9, [{<<"h.local">>, a}], [{<<"h.local">>, {10, 0, 0, 1}, 10, false}], [{<<"h.local">>, {0, 0, 0, 0, 0, 0, 0, 1}, 120, true}]
    ),
    {ok, M} = ?M:decode(Bin),
    ?assertMatch(#{id := 9, qr := true, aa := true, questions := [#{name := <<"h.local">>}]}, M),
    ?assertMatch([#{type := a, ttl := 10, cache_flush := false, data := {10, 0, 0, 1}}], maps:get(answers, M)),
    ?assertMatch([#{type := aaaa, cache_flush := true, data := {0, 0, 0, 0, 0, 0, 0, 1}}], maps:get(additional, M)).

normalize_test() ->
    ?assertEqual({ok, <<"abc.local">>}, ?M:normalize_name(<<"ABC.Local.">>)),
    ?assertEqual(error, ?M:normalize_name(<<>>)),
    ?assertEqual(error, ?M:normalize_name(<<".">>)),
    ?assertEqual(error, ?M:normalize_name(<<"a..b">>)),
    ?assertEqual(error, ?M:normalize_name(not_a_binary)).
