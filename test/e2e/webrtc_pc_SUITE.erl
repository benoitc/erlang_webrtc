%% Erlang to Erlang peer connections over real UDP sockets on loopback:
%% ICE, DTLS, SRTP, RTP/RTCP, SCTP and data channels end to end.
-module(webrtc_pc_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_ice.hrl").

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
    ice_auto_restart/1,
    ice_auto_restart_signaling/1,
    ice_auto_restart_glare/1,
    ice_auto_restart_off/1,
    connection_id_rotation/1,
    fingerprint_mismatch_fails/1,
    close_notifies_peer/1,
    concurrent_peer_connections/1,
    candidates_before_local_description/1,
    fingerprint_change_refused/1,
    max_message_size_wired/1,
    fingerprint_change_ends_association/1,
    remote_ice_restart_rolled_back/1,
    pranswer_connects/1,
    ice_tcp_only/1,
    simulcast_layers/1,
    simulcast_sfu_forward/1,
    unbundled/1,
    pause_resume/1,
    simulcast_answerer/1,
    cryptex/1,
    channel_priorities/1,
    dtls_connection_id/1,
    header_extension_encryption/1,
    dtls_resumption/1
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
        ice_auto_restart,
        ice_auto_restart_signaling,
        ice_auto_restart_glare,
        ice_auto_restart_off,
        connection_id_rotation,
        fingerprint_mismatch_fails,
        close_notifies_peer,
        concurrent_peer_connections,
        candidates_before_local_description,
        fingerprint_change_refused,
        max_message_size_wired,
        fingerprint_change_ends_association,
        remote_ice_restart_rolled_back,
        pranswer_connects,
        ice_tcp_only,
        simulcast_layers,
        simulcast_sfu_forward,
        unbundled,
        pause_resume,
        simulcast_answerer,
        cryptex,
        channel_priorities,
        dtls_connection_id,
        header_extension_encryption,
        dtls_resumption
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

%% Without BUNDLE every m= section has its own ICE and DTLS transport
%% (RFC 9143, RFC 9429 §5.2.1): media and data flow on each of them.
unbundled(_Config) ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, bundle => false}),
    B = pc(),
    av(A),
    av(B),
    ok = webrtc:create_data_channel(A, <<"solo">>, #{}),
    {Offer, Answer} = ?S:connect(A, B),
    ?assertEqual(nomatch, binary:match(Offer, <<"a=group:BUNDLE">>)),
    ?assertEqual(nomatch, binary:match(Answer, <<"a=group:BUNDLE">>)),
    Ufrags = re:run(Answer, <<"a=ice-ufrag:(\\S+)">>, [global, {capture, all_but_first, binary}]),
    ?assertMatch({match, [_, _, _]}, Ufrags),
    {match, U} = Ufrags,
    ?assertEqual(3, length(lists:usort(U))),
    {ok, _} = ?S:wait(B, fun({track, <<"1">>, video}) -> true; (_) -> false end, 5000),
    Id = channel_id(A, <<"solo">>),
    ok = webrtc:send_rtp(A, <<"0">>, <<"a0">>, #{timestamp => 1}),
    _ = rtp(B, <<"0">>, <<"a0">>),
    ok = webrtc:send_rtp(A, <<"1">>, <<"v1">>, #{timestamp => 1, marker => true}),
    _ = rtp(B, <<"1">>, <<"v1">>),
    ok = webrtc:send_rtp(B, <<"1">>, <<"back">>, #{timestamp => 1}),
    _ = rtp(A, <<"1">>, <<"back">>),
    ok = webrtc:send_data(A, Id, text, <<"over its own transport">>),
    _ = message(B, <<"over its own transport">>),
    #{transports := Ts} = webrtc:get_stats(A),
    %% The primary transport, plus one per other section.
    ?assertEqual(2, map_size(Ts)),
    %% An ICE restart restarts every transport; each keeps its DTLS
    %% association.
    ok = webrtc:restart_ice(A),
    {Offer2, _} = ?S:negotiate(A, B),
    {match, U2} = re:run(Offer2, <<"a=ice-ufrag:(\\S+)">>, [global, {capture, all_but_first, binary}]),
    {match, U1} = re:run(Offer, <<"a=ice-ufrag:(\\S+)">>, [global, {capture, all_but_first, binary}]),
    ?assertEqual([], [X || X <- U2, lists:member(X, U1)]),
    relay_for(A, B, 2000),
    ok = webrtc:send_rtp(A, <<"1">>, <<"v2">>, #{timestamp => 2, marker => true}),
    _ = rtp(B, <<"1">>, <<"v2">>),
    ok = webrtc:send_data(A, Id, text, <<"after restart">>),
    _ = message(B, <<"after restart">>),
    %% A restart offered by the peer restarts them too.
    ok = webrtc:restart_ice(B),
    {Offer3, _} = ?S:negotiate(B, A),
    %% Negotiated transports stay as they are (RFC 9429 §5.2.2).
    ?assertEqual(nomatch, binary:match(Offer3, <<"a=group:BUNDLE">>)),
    relay_for(A, B, 2000),
    ok = webrtc:send_rtp(B, <<"0">>, <<"a3">>, #{timestamp => 3}),
    _ = rtp(A, <<"0">>, <<"a3">>),
    ok = webrtc:send_data(A, Id, text, <<"after peer restart">>),
    _ = message(B, <<"after peer restart">>),
    webrtc:close(A),
    webrtc:close(B),
    ?assertEqual([], ets:match_object(webrtc_transports, {{A, '_'}, '_'})).

%% RFC 7728: the receiver pauses the remote video stream and resumes it.
pause_resume(_Config) ->
    A = pc(),
    B = pc(),
    av(A),
    av(B),
    {Offer, _} = ?S:connect(A, B),
    ?assertNotEqual(nomatch, binary:match(Offer, <<"ccm pause nowait">>)),
    ok = webrtc:send_rtp(A, <<"1">>, <<"v1">>, #{timestamp => 1, marker => true}),
    _ = rtp(B, <<"1">>, <<"v1">>),
    %% Audio has no pause line.
    ?assertEqual({error, pause_not_negotiated}, webrtc:request_pause(B, <<"0">>)),
    ok = webrtc:request_pause(B, <<"1">>),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {stream_paused, <<"1">>} end, 5000),
    {ok, _} = ?S:wait(B, fun(E) -> E =:= {remote_paused, <<"1">>} end, 5000),
    ?assertEqual({error, paused}, webrtc:send_rtp(A, <<"1">>, <<"v2">>, #{timestamp => 2})),
    %% Audio keeps flowing.
    ok = webrtc:send_rtp(A, <<"0">>, <<"a1">>, #{timestamp => 1}),
    _ = rtp(B, <<"0">>, <<"a1">>),
    ok = webrtc:request_resume(B, <<"1">>),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {stream_resumed, <<"1">>} end, 5000),
    ok = webrtc:send_rtp(A, <<"1">>, <<"v3">>, #{timestamp => 3, marker => true}),
    _ = rtp(B, <<"1">>, <<"v3">>),
    {ok, _} = ?S:wait(B, fun(E) -> E =:= {remote_resumed, <<"1">>} end, 5000),
    %% A second pause uses the next PauseID.
    ok = webrtc:request_pause(B, <<"1">>),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {stream_paused, <<"1">>} end, 5000),
    webrtc:close(A),
    webrtc:close(B).

%% RFC 9335: with cryptex negotiated the header extensions leave
%% encrypted (profile 0xC0DE); when one side does not offer it they stay
%% in the clear (0xBEDE). Media flows in both cases.
cryptex(_Config) ->
    [cryptex_case(Opt, Profile) || {Opt, Profile} <- [{true, 16#C0DE}, {false, 16#BEDE}]],
    ok.

cryptex_case(Cryptex, Profile) ->
    Self = self(),
    Tap = {fun(_Dest, Bin, P) -> P ! {wire, Bin}, {[{0, Bin}], P} end, Self},
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, outbound_filter => Tap}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, cryptex => Cryptex}),
    av(A),
    av(B),
    {Offer, Answer} = ?S:connect(A, B),
    ?assertNotEqual(nomatch, binary:match(Offer, <<"a=cryptex">>)),
    ?assertEqual(Cryptex, binary:match(Answer, <<"a=cryptex">>) =/= nomatch),
    flush_wire(),
    ok = webrtc:send_rtp(A, <<"1">>, <<"secret">>, #{timestamp => 1, marker => true}),
    _ = rtp(B, <<"1">>, <<"secret">>),
    ?assertEqual(Profile, wire_profile(2000)),
    webrtc:close(A),
    webrtc:close(B).

flush_wire() ->
    receive {wire, _} -> flush_wire() after 0 -> ok end.

%% The extension profile of the first SRTP packet sent.
wire_profile(Timeout) ->
    receive
        {wire, <<2:2, _:1, 1:1, CC:4, _:1, PT:7, _/binary>> = Bin} when PT < 64; PT > 95 ->
            Off = 12 + CC * 4,
            <<_:Off/binary, P:16, _/binary>> = Bin,
            P;
        {wire, _} ->
            wire_profile(Timeout)
    after Timeout ->
        timeout
    end.

%% RFC 8831 §6.4, RFC 8260 §3.6: a high priority channel queued after a
%% very low priority bulk transfer finishes first, and the peer learns
%% the priority from DCEP.
channel_priorities(_Config) ->
    %% A 4 Mbps bottleneck keeps a backlog in the SCTP send queue, where
    %% the scheduler chooses.
    Limit = webrtc_impair:filter(#{rate => 4000000, queue_ms => 200, seed => 1}),
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, outbound_filter => Limit}),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"bulk">>, #{priority => very_low}),
    ok = webrtc:create_data_channel(A, <<"urgent">>, #{priority => high}),
    ?S:connect(A, B),
    Bulk = channel_id(A, <<"bulk">>),
    Urgent = channel_id(A, <<"urgent">>),
    {ok, {datachannel_open, _, _, _, #{priority := 1024}}} =
        ?S:wait(B, fun({datachannel_open, _, L, _, _}) -> L =:= <<"urgent">>; (_) -> false end, 5000),
    Data = binary:copy(<<"x">>, 16000),
    [ok = webrtc:send_data(A, Bulk, binary, <<"b", I, Data/binary>>) || I <- lists:seq(1, 30)],
    [ok = webrtc:send_data(A, Urgent, binary, <<"u", I, Data/binary>>) || I <- lists:seq(1, 30)],
    Order = arrivals(B, 60, []),
    LastBulk = last_index(<<"b">>, Order),
    LastUrgent = last_index(<<"u">>, Order),
    ct:log("last bulk at ~p, last urgent at ~p", [LastBulk, LastUrgent]),
    ?assert(LastUrgent < LastBulk),
    webrtc:close(A),
    webrtc:close(B).

arrivals(_B, 0, Acc) ->
    lists:reverse(Acc);
arrivals(B, N, Acc) ->
    receive
        {webrtc, B, {channel_message, _, binary, <<Tag:1/binary, _/binary>>}} -> arrivals(B, N - 1, [Tag | Acc])
    after 20000 -> ct:fail({missing, N})
    end.

last_index(Tag, Order) ->
    lists:max([I || {I, T} <- lists:enumerate(Order), T =:= Tag]).

%% RFC 9147 §9: both peers ask for a DTLS 1.3 connection ID; SRTP and
%% data channels run over records that carry it.
dtls_connection_id(_Config) ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, dtls => #{connection_id => true}}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, dtls => #{connection_id => true}}),
    av(A),
    av(B),
    ok = webrtc:create_data_channel(A, <<"cid">>, #{}),
    ?S:connect(A, B),
    Id = channel_id(A, <<"cid">>),
    ok = webrtc:send_data(A, Id, text, <<"over cid">>),
    _ = message(B, <<"over cid">>),
    ok = webrtc:send_rtp(A, <<"0">>, <<"a">>, #{timestamp => 1}),
    _ = rtp(B, <<"0">>, <<"a">>),
    #{transport := #{dtls := #{version := 'dtlsv1.3', connection_id := true}}} = webrtc:get_stats(A),
    webrtc:close(A),
    webrtc:close(B).

%% RFC 9147 §9, RFC 9146 §8: after each ICE restart A's records carry a
%% CID of B's not seen before (a spare B gave), so the new path cannot
%% be linked to the old one by the CID, and data still flows. Five
%% restarts use more CIDs than B holds at once: B retires those A moved
%% away from to make room.
connection_id_rotation(_Config) ->
    Self = self(),
    Tap = {fun(_Dest, Bin, S) ->
                case Bin of
                    <<H, Cid:8/binary, _/binary>> when H band 16#E0 =:= 16#20, H band 16#10 =/= 0 -> Self ! {cid, Cid};
                    _ -> ok
                end,
                {[{0, Bin}], S}
           end, undefined},
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, outbound_filter => Tap, dtls => #{connection_id => true}}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, dtls => #{connection_id => true}}),
    ok = webrtc:create_data_channel(A, <<"cid">>, #{}),
    ?S:connect(A, B),
    Id = channel_id(A, <<"cid">>),
    ok = webrtc:send_data(A, Id, text, <<"before">>),
    _ = message(B, <<"before">>),
    [First] = cids([]),
    Used = lists:foldl(
        fun(I, Seen) ->
            ok = webrtc:restart_ice(A),
            _ = ?S:negotiate(A, B),
            relay_for(A, B, 1500),
            flush_cids(),
            Msg = <<"after restart ", (integer_to_binary(I))/binary>>,
            ok = webrtc:send_data(A, Id, text, Msg),
            _ = message(B, Msg),
            [New] = cids([]),
            ct:log("restart ~p: ~p", [I, New]),
            ?assertNot(lists:member(New, Seen)),
            [New | Seen]
        end,
        [First],
        lists:seq(1, 5)
    ),
    ?assertEqual(6, length(Used)),
    #{transport := #{dtls := #{connection_id := true}}} = webrtc:get_stats(B),
    webrtc:close(A),
    webrtc:close(B).

cids(Acc) ->
    receive {cid, C} -> cids([C | Acc])
    after 200 -> lists:usort(Acc)
    end.

flush_cids() ->
    receive {cid, _} -> flush_cids()
    after 0 -> ok
    end.

%% RFC 6904, RFC 8834 §5.2.2: the audio level travels encrypted when
%% one side offers it and the other accepts (the default), in clear
%% when the answerer turned it off; MID stays in
%% clear and media still demultiplexes; with cryptex on as well the
%% packet is cryptex; both SRTP profiles.
header_extension_encryption(_Config) ->
    Level = webrtc_rtp_ext:audio_level(true, 42),
    %% Encrypted, AES-GCM (the default profile).
    {Wire1, Got1} = audio_level_case(#{cryptex => false, encrypt_header_extensions => offer}, #{cryptex => false}),
    ?assert(lists:any(fun(W) -> element_data(5, W) =/= Level end, Wire1)),
    ?assertEqual([<<"0">>], lists:usort([element_data(4, W) || W <- Wire1])),
    ?assertEqual({ok, {true, 42}}, Got1),
    %% Encrypted, AES-CM.
    {Wire2, Got2} = audio_level_case(#{cryptex => false, encrypt_header_extensions => offer, srtp_profiles => [16#0001]},
                                     #{cryptex => false}),
    ?assert(lists:any(fun(W) -> element_data(5, W) =/= Level end, Wire2)),
    ?assertEqual({ok, {true, 42}}, Got2),
    %% The peer turned encryption off: clear, under the clear id.
    {Wire3, Got3} = audio_level_case(#{cryptex => false, encrypt_header_extensions => offer},
                                     #{encrypt_header_extensions => false}),
    ?assertEqual([Level], lists:usort([element_data(1, W) || W <- Wire3])),
    ?assertEqual({ok, {true, 42}}, Got3),
    %% Cryptex and RFC 6904 both negotiated: cryptex packets.
    {Wire4, Got4} = audio_level_case(#{encrypt_header_extensions => offer}, #{}),
    ?assert(lists:all(fun(<<_:12/binary, P:16, _/binary>>) -> P =:= 16#C0DE end, Wire4)),
    ?assertEqual({ok, {true, 42}}, Got4).

%% A sends audio with a level; returns the SRTP packets A sent and the
%% level B decoded.
audio_level_case(OptsA, OptsB) ->
    Self = self(),
    Tap = {fun(_Dest, Bin, P) -> P ! {wire, Bin}, {[{0, Bin}], P} end, Self},
    {ok, A} = webrtc:new_peer_connection(OptsA#{loopback => true, outbound_filter => Tap}),
    {ok, B} = webrtc:new_peer_connection(OptsB#{loopback => true}),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    ?S:connect(A, B),
    flush_wire(),
    [ok = webrtc:send_rtp(A, <<"0">>, <<"opus", N>>, #{timestamp => N * 960, audio_level => {true, 42}})
     || N <- lists:seq(1, 5)],
    #rtp{ext = Ext} = rtp(B, <<"0">>, <<"opus", 5>>),
    [#{recv_extensions := #{<<"urn:ietf:params:rtp-hdrext:ssrc-audio-level">> := Id}}] = webrtc:transceivers(B),
    {ok, Data} = webrtc_rtp_ext:find(Id, Ext),
    Wire = wire_rtp(5, []),
    webrtc:close(A),
    webrtc:close(B),
    {Wire, webrtc_rtp_ext:decode_audio_level(Data)}.

wire_rtp(0, Acc) ->
    lists:reverse(Acc);
wire_rtp(N, Acc) ->
    receive
        {wire, <<2:2, _:1, 1:1, _:4, _:1, PT:7, _/binary>> = Bin} when PT < 64; PT > 95 -> wire_rtp(N - 1, [Bin | Acc]);
        {wire, _} -> wire_rtp(N, Acc)
    after 2000 -> lists:reverse(Acc)
    end.

%% The data of one-byte element `Id' in a protected packet, as sent.
element_data(Id, <<_:4, CC:4, _/binary>> = Bin) ->
    Off = 12 + CC * 4,
    <<_:Off/binary, 16#BEDE:16, W:16, Ext:W/binary-unit:32, _/binary>> = Bin,
    find_element(Id, Ext).

find_element(_Id, <<>>) -> none;
find_element(Id, <<0, Rest/binary>>) -> find_element(Id, Rest);
find_element(Id, <<I:4, L:4, Rest/binary>>) ->
    Len = L + 1,
    <<Data:Len/binary, Tail/binary>> = Rest,
    case I of
        Id -> Data;
        _ -> find_element(Id, Tail)
    end.

%% RFC 8446 §2.2: the second association between the same certificates
%% resumes with the ticket of the first, without certificate messages;
%% data channels work on it.
dtls_resumption(_Config) ->
    CA = webrtc_dtls_cert:generate(),
    CB = webrtc_dtls_cert:generate(),
    Opts = fun(C) -> #{loopback => true, certificate => C, dtls => #{resumption => true}} end,
    Resumed = [begin
                   {ok, A} = webrtc:new_peer_connection(Opts(CA)),
                   {ok, B} = webrtc:new_peer_connection(Opts(CB)),
                   ok = webrtc:create_data_channel(A, <<"r">>, #{}),
                   ?S:connect(A, B),
                   Id = channel_id(A, <<"r">>),
                   ok = webrtc:send_data(A, Id, text, <<"hi">>),
                   _ = message(B, <<"hi">>),
                   %% Let the ticket arrive before closing.
                   timer:sleep(200),
                   #{transport := #{dtls := #{resumed := R}}} = webrtc:get_stats(A),
                   webrtc:close(A),
                   webrtc:close(B),
                   R
               end || _ <- [1, 2]],
    ?assertEqual([false, true], Resumed).

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

%% RFC 8445 §8.1.1, JSEP §4.1.14: when the selected path stops working
%% the controlling peer restarts ICE by itself (`ice_auto_restart'),
%% asks for a new offer (negotiation_needed), and the new session picks
%% the path that still works; the data channel and DTLS survive. The
%% peers have an IPv4 and an IPv6 loopback address; A's packets of the
%% selected family are dropped.
ice_auto_restart(_Config) ->
    Block = atomics:new(1, []),
    Filter = {fun({IP, _}, Bin, S) ->
                   case atomics:get(Block, 1) of
                       F when F =/= 0, tuple_size(IP) =:= F -> {[], S};
                       _ -> {[{0, Bin}], S}
                   end
              end, undefined},
    Addrs = [{{127, 0, 0, 1}, 0}, {{0, 0, 0, 0, 0, 0, 0, 1}, 0}],
    {ok, A} = webrtc:new_peer_connection(#{addresses => Addrs, outbound_filter => Filter, ice_restart_delay => 500}),
    {ok, B} = webrtc:new_peer_connection(#{addresses => Addrs, ice_restart_delay => 500}),
    ok = webrtc:create_data_channel(A, <<"keep">>, #{}),
    ?S:connect(A, B),
    Id = channel_id(A, <<"keep">>),
    Before = selected_address(A),
    ct:log("selected before: ~p", [Before]),
    atomics:put(Block, 1, tuple_size(Before)),
    %% A's consent requests are lost: disconnected after the disconnect
    %% timeout, then A restarts.
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {ice_restart, disconnected} end, 20000),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= negotiation_needed end, 1000),
    _ = ?S:negotiate(A, B),
    ok = ?S:wait_connected([A, B], 15000),
    After = selected_address(A),
    ct:log("selected after: ~p", [After]),
    ?assertNotEqual(tuple_size(Before), tuple_size(After)),
    ok = webrtc:send_data(A, Id, text, <<"after the restart">>),
    _ = message(B, <<"after the restart">>),
    webrtc:close(A),
    webrtc:close(B).

%% With `signaling' the peers run the restart offer and answer by
%% themselves: the application only carries the descriptions and the
%% candidates.
ice_auto_restart_signaling(_Config) ->
    Block = atomics:new(1, []),
    Filter = {fun({IP, _}, Bin, S) ->
                   case atomics:get(Block, 1) of
                       F when F =/= 0, tuple_size(IP) =:= F -> {[], S};
                       _ -> {[{0, Bin}], S}
                   end
              end, undefined},
    Peers = ets:new(peers, [public]),
    To = fun(Who) -> fun(Type, Sdp) -> [{_, P}] = ets:lookup(Peers, Who), webrtc:set_remote_description(P, Type, Sdp) end end,
    Addrs = [{{127, 0, 0, 1}, 0}, {{0, 0, 0, 0, 0, 0, 0, 1}, 0}],
    {ok, A} = webrtc:new_peer_connection(#{addresses => Addrs, outbound_filter => Filter, ice_restart_delay => 500,
                                           signaling => To(b)}),
    {ok, B} = webrtc:new_peer_connection(#{addresses => Addrs, ice_restart_delay => 500, signaling => To(a)}),
    true = ets:insert(Peers, [{a, A}, {b, B}]),
    ok = webrtc:create_data_channel(A, <<"keep">>, #{}),
    ?S:connect(A, B),
    Id = channel_id(A, <<"keep">>),
    Before = selected_address(A),
    atomics:put(Block, 1, tuple_size(Before)),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {ice_restart, disconnected} end, 20000),
    ok = ?S:wait_connected([A, B], 15000),
    ?assertEqual(stable, webrtc:signaling_state(A)),
    ?assertEqual(stable, webrtc:signaling_state(B)),
    After = selected_address(A),
    ?assertNotEqual(tuple_size(Before), tuple_size(After)),
    ok = webrtc:send_data(A, Id, text, <<"after the restart">>),
    _ = message(B, <<"after the restart">>),
    webrtc:close(A),
    webrtc:close(B).

%% Both peers restart at the same time (the controlled one has a
%% shorter delay): the controlled peer rolls its offer back and answers.
ice_auto_restart_glare(_Config) ->
    Block = atomics:new(1, []),
    Filter = fun() -> {fun({IP, _}, Bin, S) ->
                           case atomics:get(Block, 1) of
                               F when F =/= 0, tuple_size(IP) =:= F -> {[], S};
                               _ -> {[{0, Bin}], S}
                           end
                       end, undefined} end,
    Peers = ets:new(peers, [public]),
    To = fun(Who) -> fun(Type, Sdp) -> [{_, P}] = ets:lookup(Peers, Who), webrtc:set_remote_description(P, Type, Sdp) end end,
    Addrs = [{{127, 0, 0, 1}, 0}, {{0, 0, 0, 0, 0, 0, 0, 1}, 0}],
    {ok, A} = webrtc:new_peer_connection(#{addresses => Addrs, outbound_filter => Filter(), ice_restart_delay => 600,
                                           signaling => To(b)}),
    {ok, B} = webrtc:new_peer_connection(#{addresses => Addrs, outbound_filter => Filter(), ice_restart_delay => 200,
                                           signaling => To(a)}),
    true = ets:insert(Peers, [{a, A}, {b, B}]),
    ok = webrtc:create_data_channel(A, <<"keep">>, #{}),
    ?S:connect(A, B),
    Id = channel_id(A, <<"keep">>),
    Before = selected_address(A),
    atomics:put(Block, 1, tuple_size(Before)),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {ice_restart, disconnected} end, 20000),
    ok = ?S:wait_connected([A, B], 15000),
    {ok, _} = ?S:wait(B, fun(E) -> element(1, E) =:= ice_restart end, 0),
    ?assertEqual(stable, webrtc:signaling_state(A)),
    ?assertEqual(stable, webrtc:signaling_state(B)),
    ok = webrtc:send_data(A, Id, text, <<"after the restart">>),
    _ = message(B, <<"after the restart">>),
    webrtc:close(A),
    webrtc:close(B).

%% With `ice_auto_restart => false' nothing restarts by itself: the
%% application sees the ICE state and decides.
ice_auto_restart_off(_Config) ->
    Block = atomics:new(1, []),
    Filter = {fun(_Dest, Bin, S) ->
                   case atomics:get(Block, 1) of 1 -> {[], S}; _ -> {[{0, Bin}], S} end
              end, undefined},
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, outbound_filter => Filter, ice_auto_restart => false,
                                           ice_restart_delay => 100}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, ice_auto_restart => false}),
    ok = webrtc:create_data_channel(A, <<"x">>, #{}),
    ?S:connect(A, B),
    [_] = wait_selected(A, 50),
    atomics:put(Block, 1, 1),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {ice_connection_state, disconnected} end, 20000),
    ?assertMatch({error, timeout}, ?S:wait(A, fun({ice_restart, _}) -> true; (_) -> false end, 1500)),
    webrtc:close(A),
    webrtc:close(B).

selected_address(Pc) ->
    [{L, _}] = wait_selected(Pc, 50),
    L#ice_cand.address.

relay_for(A, B, Ms) ->
    receive
        {webrtc, A, {ice_candidate, C, M}} -> _ = webrtc:add_ice_candidate(B, C, M), relay_for(A, B, Ms);
        {webrtc, B, {ice_candidate, C, M}} -> _ = webrtc:add_ice_candidate(A, C, M), relay_for(A, B, Ms)
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
    %% B refuses A's certificate; A may learn it from B's alert first.
    {error, {failed, First}} = ?S:wait_connected([A, B], 10000),
    ?assert(First =:= A orelse First =:= B),
    case First of
        B -> ok;
        A -> {ok, _} = ?S:wait(B, fun(E) -> E =:= {connection_state, failed} end, 10000)
    end,
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

%%--------------------------------------------------------------------
%% Simulcast (RFC 8853) with rid header extensions (RFC 8852)
%%--------------------------------------------------------------------

-define(RIDS, [<<"q">>, <<"h">>, <<"f">>]).

simulcast_sender(Pc) ->
    {ok, _} = webrtc:add_transceiver(Pc, video, #{
        direction => sendonly,
        send_encodings => [#{rid => R} || R <- ?RIDS]
    }),
    ok.

layer_rtp(Pc, Mid, Rid, Payload) ->
    {ok, {rtp, Mid, Rid, #rtp{} = P}} =
        ?S:wait(Pc, fun({rtp, M, R, #rtp{payload = Pl}}) -> {M, R, Pl} =:= {Mid, Rid, Payload};
                       (_) -> false end, 10000),
    P.

%% A sends three layers, B receives each one with its rid and asks for a
%% keyframe on one of them.
simulcast_layers(_Config) ->
    A = pc(),
    B = pc(),
    ok = simulcast_sender(A),
    {Offer, Answer} = ?S:connect(A, B),
    ?assertNotEqual(nomatch, binary:match(Offer, <<"a=simulcast:send q;h;f">>)),
    ?assertNotEqual(nomatch, binary:match(Answer, <<"a=simulcast:recv q;h;f">>)),
    [#{send_encodings := Encs}] = webrtc:transceivers(A),
    ?assertEqual(?RIDS, [R || #{rid := R} <- Encs]),
    {ok, _} = ?S:wait(B, fun({track, <<"0">>, video}) -> true; (_) -> false end, 5000),
    [ok = webrtc:send_rtp(A, <<"0">>, <<R/binary, N>>, #{rid => R, timestamp => N * 3000, marker => true})
     || N <- lists:seq(1, 20), R <- ?RIDS],
    Pkts = [layer_rtp(B, <<"0">>, R, <<R/binary, 20>>) || R <- ?RIDS],
    ?assertEqual(3, length(lists:usort([S || #rtp{ssrc = S} <- Pkts]))),
    ?assertEqual({error, not_sending}, webrtc:send_rtp(A, <<"0">>, <<"x">>, #{})),
    ok = webrtc:request_keyframe(B, <<"0">>, #{rid => <<"h">>}),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {keyframe_request, <<"0">>, <<"h">>} end, 5000),
    ok = webrtc:request_keyframe(B, <<"0">>),
    [{ok, _} = ?S:wait(A, fun(E) -> E =:= {keyframe_request, <<"0">>, R} end, 5000) || R <- ?RIDS],
    #{transport := #{media := #{receivers := Rcv}}} = webrtc:get_stats(B),
    ?assertEqual(lists:sort(?RIDS), lists:sort([R || #{rid := R} <- maps:values(Rcv)])),
    webrtc:close(A),
    webrtc:close(B).

%% RFC 9429 §5.10: B offers to receive three layers, h paused; A
%% answers with them and sends q and f; B resumes h (RFC 7728) once it
%% learned its SSRC from A's RTCP.
simulcast_answerer(_Config) ->
    A = pc(),
    B = pc(),
    {ok, _} = webrtc:add_transceiver(B, video, #{direction => recvonly,
                                                recv_rids => [<<"q">>, #{rid => <<"h">>, paused => true}, <<"f">>]}),
    {ok, _} = webrtc:add_transceiver(A, video, #{}),
    {Offer, Answer} = ?S:connect(B, A),
    ?assertNotEqual(nomatch, binary:match(Offer, <<"a=simulcast:recv q;~h;f">>)),
    ?assertNotEqual(nomatch, binary:match(Answer, <<"a=simulcast:send q;h;f">>)),
    ?assertEqual({error, paused}, webrtc:send_rtp(A, <<"0">>, <<"h">>, #{rid => <<"h">>})),
    [ok = webrtc:send_rtp(A, <<"0">>, <<R/binary, N>>, #{rid => R, timestamp => N * 3000, marker => true})
     || N <- lists:seq(1, 10), R <- [<<"q">>, <<"f">>]],
    _ = [layer_rtp(B, <<"0">>, R, <<R/binary, 10>>) || R <- [<<"q">>, <<"f">>]],
    ok = resume_when_known(B, <<"0">>, <<"h">>, 50),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {stream_resumed, <<"0">>, <<"h">>} end, 5000),
    ok = webrtc:send_rtp(A, <<"0">>, <<"h1">>, #{rid => <<"h">>, timestamp => 1, marker => true}),
    _ = layer_rtp(B, <<"0">>, <<"h">>, <<"h1">>),
    webrtc:close(A),
    webrtc:close(B).

%% The SSRC of a layer that sends nothing comes with the RTCP SDES.
resume_when_known(Pc, Mid, Rid, Tries) ->
    case webrtc:request_resume(Pc, Mid, #{rid => Rid}) of
        {error, unknown_stream} when Tries > 0 ->
            timer:sleep(100),
            resume_when_known(Pc, Mid, Rid, Tries - 1);
        Other ->
            Other
    end.

%% SFU: the peer connection B of the SFU receives the layers of A, and
%% the SFU forwards one layer to C through its peer connection D as a
%% plain stream; a keyframe request of C is relayed to that layer.
simulcast_sfu_forward(_Config) ->
    [A, B, C, D] = [pc() || _ <- lists:seq(1, 4)],
    ok = simulcast_sender(A),
    ?S:connect(A, B),
    {ok, _} = webrtc:add_transceiver(D, video, #{direction => sendonly}),
    ?S:connect(D, C),
    [ok = webrtc:send_rtp(A, <<"0">>, <<R/binary, N>>, #{rid => R, timestamp => N * 3000})
     || N <- lists:seq(1, 5), R <- ?RIDS],
    Pkt = layer_rtp(B, <<"0">>, <<"h">>, <<"h", 5>>),
    ok = webrtc:send_rtp_packet(D, <<"0">>, Pkt),
    {ok, {rtp, <<"0">>, #rtp{payload = <<"h", 5>>}}} =
        ?S:wait(C, fun({rtp, <<"0">>, #rtp{payload = P}}) -> P =:= <<"h", 5>>; (_) -> false end, 10000),
    ok = webrtc:request_keyframe(C, <<"0">>),
    {ok, _} = ?S:wait(D, fun(E) -> E =:= {keyframe_request, <<"0">>} end, 5000),
    ok = webrtc:request_keyframe(B, <<"0">>, #{rid => <<"h">>}),
    {ok, _} = ?S:wait(A, fun(E) -> E =:= {keyframe_request, <<"0">>, <<"h">>} end, 5000),
    [webrtc:close(P) || P <- [A, B, C, D]],
    ok.

tamper_fingerprint(Sdp) ->
    Other = webrtc_dtls_cert:format_fingerprint(
        webrtc_dtls_cert:fingerprint(sha256, maps:get(der, webrtc_dtls_cert:generate()))
    ),
    re:replace(Sdp, <<"a=fingerprint:[^\r]*">>, <<"a=fingerprint:", Other/binary>>, [global, {return, binary}]).

%% RFC 8842 §5, RFC 9429 §5.8.3: other fingerprints without an ICE
%% restart are refused.
fingerprint_change_refused(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"id">>, #{}),
    ?S:connect(A, B),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ?assertEqual({error, dtls_identity_changed}, webrtc:set_remote_description(B, offer, tamper_fingerprint(Offer))),
    webrtc:close(A),
    webrtc:close(B).

%% With an ICE restart the description is accepted, and the peer that
%% got the new fingerprint drops the old association: its channels close
%% and nothing more flows on the old keys.
fingerprint_change_ends_association(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"id">>, #{}),
    ?S:connect(A, B),
    IdB = channel_id(B, <<"id">>),
    ok = webrtc:restart_ice(A),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    ok = webrtc:set_remote_description(B, offer, tamper_fingerprint(Offer)),
    {ok, Answer} = webrtc:create_answer(B, #{}),
    ok = webrtc:set_local_description(B, answer, Answer),
    ok = webrtc:set_remote_description(A, answer, Answer),
    {ok, _} = ?S:wait(B, fun(E) -> E =:= {datachannel_closed, IdB} end, 10000),
    ?assertMatch({error, _}, webrtc:send_data(B, IdB, text, <<"old keys">>)),
    webrtc:close(A),
    webrtc:close(B).

%% RFC 9429 §5.7: a remote offer that restarts ICE and is then rolled
%% back leaves the live ICE generation alone. The answer prepared in
%% between carried new credentials; they are dropped with the rollback.
remote_ice_restart_rolled_back(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"keep">>, #{}),
    ?S:connect(A, B),
    IdA = channel_id(A, <<"keep">>),
    IdB = channel_id(B, <<"keep">>),
    LocalB = webrtc:local_description(B),
    Before = wait_selected(B, 50),
    ?assertNotEqual([], Before),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    Restart = re:replace(
        re:replace(Offer, <<"a=ice-ufrag:[^\r]*">>, <<"a=ice-ufrag:rstr">>, [global, {return, binary}]),
        <<"a=ice-pwd:[^\r]*">>, <<"a=ice-pwd:restartrestartrestartrest">>, [global, {return, binary}]
    ),
    ok = webrtc:set_remote_description(B, offer, Restart),
    {ok, Answer} = webrtc:create_answer(B, #{}),
    ?assertNotEqual(ufrag(LocalB), ufrag(Answer)),
    ?assertEqual(Before, selected_pair(B)),
    ok = webrtc:set_remote_description(B, rollback, <<>>),
    ?assertEqual(stable, webrtc:signaling_state(B)),
    ?assertEqual(Before, selected_pair(B)),
    {ok, Reoffer} = webrtc:create_offer(B, #{}),
    ?assertEqual(ufrag(LocalB), ufrag(Reoffer)),
    ok = webrtc:send_data(A, IdA, text, <<"a to b">>),
    _ = message(B, <<"a to b">>),
    ok = webrtc:send_data(B, IdB, text, <<"b to a">>),
    _ = message(A, <<"b to a">>),
    webrtc:close(A),
    webrtc:close(B).

%% RFC 9429 §4.1.10.1: with a provisional answer the connection comes
%% up and data flows; the final answer keeps it.
pranswer_connects(_Config) ->
    A = pc(),
    B = pc(),
    ok = webrtc:create_data_channel(A, <<"early">>, #{}),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    ok = webrtc:set_remote_description(B, offer, Offer),
    {ok, Pr} = webrtc:create_answer(B, #{}),
    ok = webrtc:set_local_description(B, pranswer, Pr),
    ok = webrtc:set_remote_description(A, pranswer, Pr),
    ok = ?S:wait_connected([A, B], 10000),
    ?assertEqual({have_remote_pranswer, have_local_pranswer}, {webrtc:signaling_state(A), webrtc:signaling_state(B)}),
    IdA = channel_id(A, <<"early">>),
    ok = webrtc:send_data(A, IdA, text, <<"provisional">>),
    _ = message(B, <<"provisional">>),
    {ok, Answer} = webrtc:create_answer(B, #{}),
    ok = webrtc:set_local_description(B, answer, Answer),
    ok = webrtc:set_remote_description(A, answer, Answer),
    ok = webrtc:send_data(A, IdA, text, <<"final">>),
    _ = message(B, <<"final">>),
    webrtc:close(A),
    webrtc:close(B).

%% RFC 6544: with UDP blocked both ways, ICE-TCP connects the peers;
%% DTLS, SCTP and SRTP run over the TCP connection (RFC 4571 framing).
ice_tcp_only(_Config) ->
    NoUdp = fun() -> webrtc_impair:filter(#{only_to => []}) end,
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, ice_tcp => true, outbound_filter => NoUdp()}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, ice_tcp => true, outbound_filter => NoUdp()}),
    {ok, _} = webrtc:add_transceiver(A, audio, #{}),
    {ok, _} = webrtc:add_transceiver(B, audio, #{}),
    ok = webrtc:create_data_channel(A, <<"tcp">>, #{}),
    ?S:connect(A, B, 20000),
    IdA = channel_id(A, <<"tcp">>),
    ok = webrtc:send_data(A, IdA, text, <<"over tcp">>),
    _ = message(B, <<"over tcp">>),
    ok = webrtc:send_rtp(A, <<"0">>, <<"rtp over tcp">>, #{timestamp => 1}),
    _ = rtp(B, <<"0">>, <<"rtp over tcp">>),
    [{L, R}] = wait_selected(A, 50),
    ?assertEqual({tcp, tcp}, {element(4, L), element(4, R)}),
    webrtc:close(A),
    webrtc:close(B).

selected_pair(Pc) ->
    #{transport := #{ice := #{pairs := Pairs}}} = webrtc:get_stats(Pc),
    [{L, R} || #{selected := true, local := L, remote := R} <- Pairs].

%% Data may flow before nomination (RFC 8445 §12.1): wait for it.
wait_selected(Pc, Tries) ->
    case selected_pair(Pc) of
        [] when Tries > 0 -> timer:sleep(100), wait_selected(Pc, Tries - 1);
        Sel -> Sel
    end.

ufrag(Sdp) ->
    {match, [U]} = re:run(Sdp, <<"a=ice-ufrag:([^\r]*)">>, [{capture, all_but_first, binary}]),
    U.

%% RFC 8841 §6: the max-message-size we announce is what SCTP accepts;
%% the peer honours the one it was given.
max_message_size_wired(_Config) ->
    {error, {badarg, max_message_size}} = webrtc:new_peer_connection(#{loopback => true, max_message_size => 0}),
    {error, {badarg, congestion_control}} = webrtc:new_peer_connection(#{loopback => true, congestion_control => false}),
    {ok, A} = webrtc:new_peer_connection(#{loopback => true, max_message_size => 10000}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true, max_message_size => 300000}),
    ok = webrtc:create_data_channel(A, <<"m">>, #{}),
    ?S:connect(A, B),
    IdA = channel_id(A, <<"m">>),
    IdB = channel_id(B, <<"m">>),
    %% A may send B up to 300000 bytes, more than the 262144 SCTP default.
    Big = crypto:strong_rand_bytes(290000),
    ok = webrtc:send_data(A, IdA, binary, Big),
    {_, binary, Big} = message(B, Big),
    %% B may only send A 10000 bytes.
    ?assertEqual({error, message_too_large}, webrtc:send_data(B, IdB, binary, crypto:strong_rand_bytes(10001))),
    Small = crypto:strong_rand_bytes(10000),
    ok = webrtc:send_data(B, IdB, binary, Small),
    {_, binary, Small} = message(A, Small),
    webrtc:close(A),
    webrtc:close(B).
