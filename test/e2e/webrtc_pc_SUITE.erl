%% Erlang to Erlang peer connections over real UDP sockets on loopback:
%% ICE, DTLS, SRTP, RTP/RTCP, SCTP and data channels end to end.
-module(webrtc_pc_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([
    data_channel_echo/1,
    data_channel_both_sides/1,
    data_channel_large_message/1,
    data_channel_unordered_unreliable/1,
    negotiated_data_channel/1,
    data_channel_close/1,
    audio_video_rtp/1,
    keyframe_request/1,
    renegotiation_adds_video/1,
    ice_restart/1,
    fingerprint_mismatch_fails/1,
    close_notifies_peer/1,
    concurrent_peer_connections/1,
    candidates_before_local_description/1
]).

-define(S, webrtc_test_signal).

all() ->
    [
        data_channel_echo,
        data_channel_both_sides,
        data_channel_large_message,
        data_channel_unordered_unreliable,
        negotiated_data_channel,
        data_channel_close,
        audio_video_rtp,
        keyframe_request,
        renegotiation_adds_video,
        ice_restart,
        fingerprint_mismatch_fails,
        close_notifies_peer,
        concurrent_peer_connections,
        candidates_before_local_description
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    ?S:flush(),
    Config.

end_per_testcase(_TC, _Config) ->
    ?S:flush(),
    ok.

pc() ->
    {ok, Pc} = webrtc:new_peer_connection(#{loopback => true}),
    Pc.

open_event(Label) ->
    fun({datachannel_open, _Id, L, _, _}) -> L =:= Label; (_) -> false end.

channel_id(Pc, Label) ->
    {ok, {datachannel_open, Id, _, _, _}} = ?S:wait(Pc, open_event(Label), 10000),
    Id.

message(Pc, Data) ->
    {ok, {channel_message, Id, Type, D}} =
        ?S:wait(Pc, fun({channel_message, _, _, D}) -> D =:= Data; (_) -> false end, 10000),
    {Id, Type, D}.

data_channel_echo(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"chat">>, #{}),
    ?S:connect(A, B),
    IdA = channel_id(A, <<"chat">>),
    IdB = channel_id(B, <<"chat">>),
    ?assertEqual(IdA, IdB),
    ok = webrtc:send_data(A, IdA, text, <<"hello">>),
    ?assertMatch({_, text, <<"hello">>}, message(B, <<"hello">>)),
    ok = webrtc:send_data(B, IdB, binary, <<1, 2, 3>>),
    ?assertMatch({_, binary, <<1, 2, 3>>}, message(A, <<1, 2, 3>>)),
    %% Empty messages use their own PPIDs (RFC 8831 §6.6).
    ok = webrtc:send_data(A, IdA, text, <<>>),
    ?assertMatch({_, text, <<>>}, message(B, <<>>)),
    webrtc:close(A),
    webrtc:close(B).

data_channel_both_sides(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"from-a">>, #{}),
    ?S:connect(A, B),
    IdFromA = channel_id(A, <<"from-a">>),
    ?assertEqual(1, IdFromA rem 2),
    %% After connection, B opens one too: ids have the other parity
    %% (RFC 8832 §6).
    IdB =
        case webrtc:create_data_channel(B, <<"from-b">>, #{}) of
            {ok, I} -> I;
            %% SCTP not up yet on B: the id comes with the open event.
            ok -> channel_id(B, <<"from-b">>)
        end,
    IdA = channel_id(A, <<"from-b">>),
    %% B answered with setup:active, so it is the DTLS client and uses
    %% even stream ids; A, the server, uses odd ones (RFC 8832 §6).
    ?assertEqual(0, IdB rem 2),
    ?assertEqual(IdB, IdA),
    ok = webrtc:send_data(A, IdA, text, <<"to b">>),
    _ = message(B, <<"to b">>),
    webrtc:close(A),
    webrtc:close(B).

data_channel_large_message(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"bulk">>, #{}),
    ?S:connect(A, B),
    Id = channel_id(A, <<"bulk">>),
    Big = crypto:strong_rand_bytes(200000),
    ok = webrtc:send_data(A, Id, binary, Big),
    ?assertMatch({_, binary, Big}, message(B, Big)),
    webrtc:close(A),
    webrtc:close(B).

data_channel_unordered_unreliable(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"game">>, #{ordered => false, max_retransmits => 0}),
    ?S:connect(A, B),
    {ok, {datachannel_open, Id, _, _, Opts}} = ?S:wait(B, open_event(<<"game">>), 10000),
    ?assertMatch(#{ordered := false, max_retransmits := 0}, Opts),
    ok = webrtc:send_data(B, Id, text, <<"state">>),
    _ = message(A, <<"state">>),
    webrtc:close(A),
    webrtc:close(B).

negotiated_data_channel(_Config) ->
    A = pc(),
    B = pc(),
    {ok, 7} = webrtc:create_data_channel(A, <<"pre">>, #{negotiated => true, id => 7}),
    {ok, 7} = webrtc:create_data_channel(B, <<"pre">>, #{negotiated => true, id => 7}),
    ?S:connect(A, B),
    _ = channel_id(A, <<"pre">>),
    _ = channel_id(B, <<"pre">>),
    ok = webrtc:send_data(A, 7, text, <<"pre-agreed">>),
    _ = message(B, <<"pre-agreed">>),
    webrtc:close(A),
    webrtc:close(B).

data_channel_close(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"tmp">>, #{}),
    ?S:connect(A, B),
    Id = channel_id(A, <<"tmp">>),
    _ = channel_id(B, <<"tmp">>),
    ok = webrtc:close_data_channel(A, Id),
    {ok, _} = ?S:wait(B, fun(E) -> E =:= {datachannel_closed, Id} end, 10000),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {datachannel_closed, Id} end, 10000),
    webrtc:close(A),
    webrtc:close(B).

av(Pc) ->
    {ok, _} = webrtc:add_transceiver(Pc, audio, #{}),
    {ok, _} = webrtc:add_transceiver(Pc, video, #{}),
    ok.

rtp(Pc, Mid, Payload) ->
    {ok, {rtp, Mid, #rtp{} = P}} =
        ?S:wait(Pc, fun({rtp, M, #rtp{payload = Pl}}) -> M =:= Mid andalso Pl =:= Payload; (_) -> false end, 10000),
    P.

audio_video_rtp(_Config) ->
    A = pc(),
    B = pc(),
    av(A),
    av(B),
    ?S:connect(A, B),
    {ok, _} = ?S:wait(B, fun({track, <<"0">>, audio}) -> true; (_) -> false end, 5000),
    {ok, _} = ?S:wait(B, fun({track, <<"1">>, video}) -> true; (_) -> false end, 5000),
    [ok = webrtc:send_rtp(A, <<"0">>, <<"opus", N>>, #{timestamp => N * 960}) || N <- lists:seq(1, 20)],
    [ok = webrtc:send_rtp(A, <<"1">>, <<"vp8", N>>, #{timestamp => N * 3000, marker => true})
     || N <- lists:seq(1, 20)],
    P = rtp(B, <<"0">>, <<"opus", 20>>),
    ?assertEqual(111, P#rtp.pt),
    _ = rtp(B, <<"1">>, <<"vp8", 20>>),
    %% And the other way.
    ok = webrtc:send_rtp(B, <<"0">>, <<"back">>, #{timestamp => 1}),
    _ = rtp(A, <<"0">>, <<"back">>),
    %% Forwarding: send the received packet on as is.
    ok = webrtc:send_rtp_packet(B, <<"1">>, P#rtp{pt = 96}),
    _ = rtp(A, <<"1">>, <<"opus", 20>>),
    Stats = webrtc:get_stats(A),
    ct:pal("stats: ~p", [Stats]),
    webrtc:close(A),
    webrtc:close(B).

keyframe_request(_Config) ->
    A = pc(),
    B = pc(),
    av(A),
    av(B),
    ?S:connect(A, B),
    ok = webrtc:send_rtp(A, <<"1">>, <<"frame">>, #{timestamp => 1}),
    _ = rtp(B, <<"1">>, <<"frame">>),
    ok = webrtc:request_keyframe(B, <<"1">>),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {keyframe_request, <<"1">>} end, 5000),
    webrtc:close(A),
    webrtc:close(B).

renegotiation_adds_video(_Config) ->
    A = pc(),
    B = pc(),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    ?S:connect(A, B),
    {ok, _} = webrtc:add_transceiver(A, video, #{}),
    _ = ?S:negotiate(A, B),
    {ok, _} = ?S:wait(B, fun({track, <<"1">>, video}) -> true; (_) -> false end, 5000),
    %% B answered recvonly for the new section, A sends on it.
    ok = webrtc:send_rtp(A, <<"1">>, <<"new">>, #{timestamp => 1}),
    _ = rtp(B, <<"1">>, <<"new">>),
    %% The original audio keeps working over the same DTLS association.
    ok = webrtc:send_rtp(A, <<"0">>, <<"still">>, #{timestamp => 1}),
    _ = rtp(B, <<"0">>, <<"still">>),
    webrtc:close(A),
    webrtc:close(B).

ice_restart(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"keep">>, #{}),
    ?S:connect(A, B),
    Id = channel_id(A, <<"keep">>),
    ok = webrtc:restart_ice(A),
    {Offer, _} = ?S:negotiate(A, B),
    ?assertNotEqual(nomatch, binary:match(Offer, <<"a=ice-ufrag:">>)),
    %% Trickle the new candidates; DTLS and SCTP survive the restart
    %% (RFC 8842 §4).
    relay_for(A, B, 2000),
    ok = webrtc:send_data(A, Id, text, <<"after restart">>),
    _ = message(B, <<"after restart">>),
    webrtc:close(A),
    webrtc:close(B).

relay_for(A, B, Ms) ->
    receive
        {webrtc, A, {ice_candidate, C, _}} -> _ = webrtc:add_ice_candidate(B, C), relay_for(A, B, Ms);
        {webrtc, B, {ice_candidate, C, _}} -> _ = webrtc:add_ice_candidate(A, C), relay_for(A, B, Ms)
    after Ms -> ok
    end.

fingerprint_mismatch_fails(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"x">>, #{}),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    %% Replace A's fingerprint with another certificate's.
    Other = webrtc_dtls_cert:format_fingerprint(
        webrtc_dtls_cert:fingerprint(sha256, maps:get(der, webrtc_dtls_cert:generate()))
    ),
    Tampered = re:replace(Offer, <<"a=fingerprint:[^\r]*">>, <<"a=fingerprint:", Other/binary>>,
                          [global, {return, binary}]),
    ok = webrtc:set_remote_description(B, offer, Tampered),
    {ok, Answer} = webrtc:create_answer(B, #{}),
    ok = webrtc:set_local_description(B, answer, Answer),
    ok = webrtc:set_remote_description(A, answer, Answer),
    ?assertMatch({error, {failed, B}}, ?S:wait_connected([A, B], 10000)),
    webrtc:close(A),
    webrtc:close(B).

close_notifies_peer(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"bye">>, #{}),
    ?S:connect(A, B),
    ok = webrtc:close(A),
    %% close_notify reaches B (RFC 5246 §7.2.1).
    {ok, _} = ?S:wait(B, fun({connection_state, closed}) -> true; (_) -> false end, 5000),
    ?assertNot(is_process_alive(A)),
    webrtc:close(B).

concurrent_peer_connections(_Config) ->
    N = 10,
    Pairs = [{pc(), pc()} || _ <- lists:seq(1, N)],
    [ok = webrtc:create_data_channel(A, <<"c">>, #{}) || {A, _} <- Pairs],
    [?S:negotiate(A, B) || {A, B} <- Pairs],
    ok = ?S:wait_pairs_connected(Pairs, 30000),
    lists:foreach(
        fun({A, B}) ->
            Id = channel_id(A, <<"c">>),
            Msg = term_to_binary({A, B}),
            ok = webrtc:send_data(A, Id, binary, Msg),
            {ok, _} = ?S:wait(B, fun({channel_message, _, binary, D}) -> D =:= Msg; (_) -> false end, 10000)
        end,
        Pairs
    ),
    [begin webrtc:close(A), webrtc:close(B) end || {A, B} <- Pairs],
    ok.

%% Trickled candidates can arrive after the remote offer but before the
%% answer is set; they are kept and used once the transport starts.
candidates_before_local_description(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"early">>, #{}),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    ok = webrtc:set_remote_description(B, offer, Offer),
    ?assertEqual({error, no_remote_description}, webrtc:add_ice_candidate(A, <<"candidate:1 1 UDP 1 127.0.0.1 9 typ host">>)),
    %% Deliver A's candidates to B now, before B has a local description.
    Early = gather_candidates(A, []),
    ?assert(length(Early) > 0),
    [ok = webrtc:add_ice_candidate(B, C) || C <- Early],
    {ok, Answer} = webrtc:create_answer(B, #{}),
    ok = webrtc:set_local_description(B, answer, Answer),
    ok = webrtc:set_remote_description(A, answer, Answer),
    ok = ?S:wait_connected([A, B], 10000),
    _ = channel_id(B, <<"early">>),
    webrtc:close(A),
    webrtc:close(B).

gather_candidates(Pc, Acc) ->
    receive
        {webrtc, Pc, {ice_candidate, end_of_candidates, _}} -> lists:reverse([end_of_candidates | Acc]);
        {webrtc, Pc, {ice_candidate, C, _}} -> gather_candidates(Pc, [C | Acc])
    after 3000 -> lists:reverse(Acc)
    end.
