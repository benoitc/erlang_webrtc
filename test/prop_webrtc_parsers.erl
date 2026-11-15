%% Every externally reachable decoder returns a value or an error tuple
%% on arbitrary input, and never raises.
-module(prop_webrtc_parsers).
-include_lib("proper/include/proper.hrl").

-define(DECODERS, [
    {stun, fun webrtc_stun:decode/1},
    {stun_integrity, fun(B) -> webrtc_stun:check_integrity(B, <<"key">>) end},
    {turn_channel, fun webrtc_turn_channel:decode/1},
    {dtls_record, fun webrtc_dtls_record:decode/1},
    {dtls12_cid_record, fun(B) -> webrtc_dtls_record:decode(B, 8) end},
    {dtls12_cid_open, fun(B) -> [webrtc_dtls_record:open(R, cid_cipher()) || R <- webrtc_dtls_record:decode(B, 4)] end},
    {dtls_fragment, fun webrtc_dtls_msg:decode_fragment/1},
    {dtls_client_hello, fun(B) -> webrtc_dtls_msg:decode_body(client_hello, B) end},
    {dtls_server_hello, fun(B) -> webrtc_dtls_msg:decode_body(server_hello, B) end},
    {dtls_certificate, fun(B) -> webrtc_dtls_msg:decode_body(certificate, B) end},
    {dtls_ske, fun(B) -> webrtc_dtls_msg:decode_body(server_key_exchange, B) end},
    {rtp, fun webrtc_rtp:decode/1},
    {rtp_ext, fun(B) -> webrtc_rtp:decode(B, #{extensions => parse}) end},
    {rtcp, fun webrtc_rtcp:decode/1},
    {sctp, fun webrtc_sctp_chunk:decode/1},
    {dcep, fun webrtc_dcep:decode/1},
    {sdp, fun webrtc_sdp:parse/1},
    {candidate, fun webrtc_sdp_candidate:parse/1},
    {demux, fun webrtc_demux:classify/1},
    {mdns, fun webrtc_mdns_msg:decode/1},
    {mdns_resolver, fun(B) -> webrtc_mdns_resolver:handle_packet(multicast, B, 0, mdns_resolver()) end},
    {mdns_responder, fun(B) -> webrtc_mdns_responder:handle_query({{127, 0, 0, 1}, 5353}, 5353, B, 0, mdns_responder()) end}
]).

mdns_resolver() ->
    element(1, webrtc_mdns_resolver:resolve(<<"a.local">>, 0, webrtc_mdns_resolver:new(#{}))).

mdns_responder() ->
    {ok, _, R} = webrtc_mdns_responder:register({127, 0, 0, 1}, webrtc_mdns_responder:new(#{})),
    R.

prop_decoders_never_raise() ->
    ?FORALL(
        {Bin, Prefix},
        {binary(), oneof([
            <<>>, <<0, 1>>, <<128>>, <<22, 254, 253>>, <<"v=0\r\n">>, <<"candidate:">>,
            %% DNS headers: a response with one answer, a query with one question
            <<0, 0, 16#84, 0, 0, 0, 0, 1, 0, 0, 0, 0>>, <<0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0>>
        ])},
        no_raise(<<Prefix/binary, Bin/binary>>)
    ).

no_raise(Input) ->
    lists:all(
        fun({Name, F}) ->
            try
                _ = F(Input),
                true
            catch
                C:R -> io:format("~p raised ~p:~p on ~p~n", [Name, C, R, Input]), false
            end
        end,
        ?DECODERS
    ).

%% libwebrtc's corpora (webrtc_corpus_tests) as seeds: one to four
%% mutations of a real message reach code that random bytes do not.
prop_corpus_mutations() ->
    Seeds = list_to_tuple([B || {_, _, B} <- webrtc_corpus_tests:files(), byte_size(B) > 0, byte_size(B) =< 8192]),
    ?FORALL(
        {I, J, Ms},
        {range(1, tuple_size(Seeds)), range(1, tuple_size(Seeds)), resize(4, non_empty(list(mutation())))},
        no_raise(lists:foldl(fun(M, B) -> mutate(M, B, element(J, Seeds)) end, element(I, Seeds), Ms))
    ).

mutation() ->
    oneof([
        {flip, nat(), range(0, 7)},
        {insert, nat(), byte()},
        {delete, nat()},
        {truncate, nat()},
        {splice, nat(), nat()},
        {len16, nat(), range(0, 65535)}
    ]).

mutate(_, <<>>, _) ->
    <<>>;
mutate({flip, P, Bit}, B, _) ->
    {H, <<X, T/binary>>} = split_binary(B, P rem byte_size(B)),
    <<H/binary, (X bxor (1 bsl Bit)), T/binary>>;
mutate({insert, P, X}, B, _) ->
    {H, T} = split_binary(B, P rem (byte_size(B) + 1)),
    <<H/binary, X, T/binary>>;
mutate({delete, P}, B, _) ->
    {H, <<_, T/binary>>} = split_binary(B, P rem byte_size(B)),
    <<H/binary, T/binary>>;
mutate({truncate, P}, B, _) ->
    binary:part(B, 0, P rem byte_size(B));
mutate({splice, P, Q}, B, Other) ->
    {H, _} = split_binary(B, P rem (byte_size(B) + 1)),
    {_, T} = split_binary(Other, Q rem (byte_size(Other) + 1)),
    <<H/binary, T/binary>>;
mutate({len16, P, V}, B, _) when byte_size(B) >= 2 ->
    {H, <<_:16, T/binary>>} = split_binary(B, P rem (byte_size(B) - 1)),
    <<H/binary, V:16, T/binary>>;
mutate({len16, _, _}, B, _) ->
    B.

%% Encoded mDNS responses decode to the same records, names lower-cased.
prop_mdns_roundtrip() ->
    ?FORALL(
        {Id, Labels, IPs, TTL},
        {range(0, 65535), non_empty(list(dns_label())), non_empty(list(ip())), range(0, 16#7FFFFFFF)},
        ?IMPLIES(
            lists:sum([byte_size(L) + 1 || L <- Labels]) + 1 =< 255,
            begin
                Name = iolist_to_binary(lists:join($., Labels)),
                Bin = webrtc_mdns_msg:encode_response(Id, [{Name, a}], [{Name, IP, TTL, true} || IP <- IPs], []),
                {ok, #{id := Id, questions := [#{name := N}], answers := As}} = webrtc_mdns_msg:decode(Bin),
                {ok, Lower} = webrtc_mdns_msg:normalize_name(Name),
                N =:= Lower andalso [D || #{data := D} <- As] =:= IPs andalso
                    lists:all(fun(#{ttl := T, name := AN}) -> T =:= TTL andalso AN =:= Lower end, As)
            end
        )
    ).

dns_label() ->
    ?LET(
        Cs,
        ?SUCHTHAT(L, list(oneof([range($a, $z), range($A, $Z), range($0, $9), $-])), L =/= [] andalso length(L) =< 63),
        list_to_binary(Cs)
    ).

ip() ->
    oneof([{byte(), byte(), byte(), byte()}, {word(), word(), word(), word(), word(), word(), word(), word()}]).

word() -> range(0, 65535).

cid_cipher() ->
    webrtc_dtls_record:new_cipher(element(2, webrtc_dtls_crypto:suite(16#C02B)), <<0:128>>, <<0:32>>).
