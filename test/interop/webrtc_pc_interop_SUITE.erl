%% Peer connection interoperability: an Erlang peer connection against
%% independent implementations (Pion, aiortc, Chromium, Firefox) through
%% the adapters of interop/. Both offer/answer roles, data channels and
%% media. Missing or unstartable peers are reported as skipped.
-module(webrtc_pc_interop_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_ice.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2,
         init_per_testcase/2, end_per_testcase/2]).
-export([
    erlang_offers_datachannel/1,
    peer_offers_datachannel/1,
    unreliable_datachannel/1,
    binary_and_large_messages/1,
    erlang_sends_media/1,
    peer_sends_media/1,
    peer_closes/1,
    erlang_renegotiates_adds_audio/1,
    erlang_ice_restart/1,
    peer_ice_restart/1,
    erlang_ice_lite/1,
    peer_sends_simulcast/1,
    erlang_sends_simulcast/1,
    peer_offers_mdns_candidates/1,
    erlang_offers_mdns_candidates/1,
    erlang_offers_ice_tcp/1,
    peer_offers_ice_tcp/1,
    erlang_offers_unbundled/1
]).

-define(P, webrtc_interop_peer).

cases() ->
    [
        erlang_offers_datachannel,
        peer_offers_datachannel,
        unreliable_datachannel,
        binary_and_large_messages,
        erlang_sends_media,
        peer_sends_media,
        peer_closes,
        erlang_renegotiates_adds_audio,
        erlang_ice_restart,
        peer_ice_restart,
        erlang_ice_lite,
        peer_sends_simulcast,
        erlang_sends_simulcast,
        erlang_offers_unbundled
    ].

all() -> [{group, pion}, {group, aiortc}, {group, chromium}, {group, firefox}, {group, chromium_mdns},
          {group, chromium_tcp}, {group, firefox_tcp}].

groups() ->
    [{G, [], cases()} || G <- [pion, aiortc, chromium, firefox]] ++
        [{chromium_mdns, [], [peer_offers_mdns_candidates, erlang_offers_mdns_candidates]}] ++
        [{G, [], [erlang_offers_ice_tcp, peer_offers_ice_tcp]} || G <- [chromium_tcp, firefox_tcp]].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    %% Peer side diagnostics go to the adapter's log file.
    os:putenv("PION_LOG_DEBUG", "sctp,datachannel,dtls,pc"),
    Config.

end_per_suite(_) -> ok.

%% Chromium with its default mDNS host candidates: resolving them needs
%% IPv4 multicast on the test host.
init_per_group(chromium_mdns, Config) ->
    case webrtc_test_mdns:multicast_works() of
        ok ->
            case ?P:probe(chromium_mdns, ?config(priv_dir, Config)) of
                ok -> [{peer, chromium_mdns} | Config];
                {skip, R} -> {skip, R}
            end;
        {skip, R} ->
            {skip, R}
    end;
init_per_group(G, Config) when G =:= chromium_tcp; G =:= firefox_tcp ->
    Peer = case G of chromium_tcp -> chromium; firefox_tcp -> firefox end,
    init_per_group(Peer, Config);
init_per_group(Peer, Config) ->
    case ?P:probe(Peer, ?config(priv_dir, Config)) of
        ok -> [{peer, Peer} | Config];
        {skip, R} -> {skip, R}
    end.

end_per_group(_, _) -> ok.

init_per_testcase(_, Config) ->
    flush(),
    erase(peer_candidates),
    Config.

end_per_testcase(_, Config) ->
    case get(peer) of
        undefined -> ok;
        P -> ?P:stop(P)
    end,
    erase(peer),
    case get(pc) of
        undefined -> ok;
        Pc -> webrtc:close(Pc)
    end,
    erase(pc),
    flush(),
    Config.

flush() ->
    receive {webrtc, _, _} -> flush() after 0 -> ok end.

%%--------------------------------------------------------------------
%% Setup helpers
%%--------------------------------------------------------------------

start(Config) ->
    start(Config, #{}).

start(Config, PcOpts) ->
    Peer = ?config(peer, Config),
    {ok, P} = ?P:start(Peer, ?config(priv_dir, Config)),
    put(peer, P),
    %% Pion is restricted to loopback; the others gather on every
    %% interface and need a routable host candidate from us.
    Opts = case Peer of pion -> #{loopback => true}; _ -> #{} end,
    {ok, Pc} = webrtc:new_peer_connection(maps:merge(Opts, PcOpts)),
    put(pc, Pc),
    {Pc, P}.

%% Erlang offers, the peer answers.
erlang_offer(Pc, P0, Init) ->
    P1 = ?P:cmd(P0, Init#{cmd => init}),
    {ok, Offer} = webrtc:create_offer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, offer, Offer),
    P2 = ?P:cmd(P1, #{cmd => remote_description, type => offer, sdp => Offer}),
    {ok, P3, #{<<"sdp">> := Answer} = Ev} = ?P:wait_event(P2, <<"local_description">>, #{}),
    ct:log("offer:~n~s~nanswer:~n~s", [Offer, Answer]),
    ok = webrtc:set_remote_description(Pc, answer, Answer),
    connected(Pc, consume(P3, Ev)).

%% The peer offers, Erlang answers.
peer_offer(Pc, P0, Init) ->
    P1 = ?P:cmd(P0, Init#{cmd => init}),
    P2 = ?P:cmd(P1, #{cmd => create_offer}),
    {ok, P3, #{<<"sdp">> := Offer} = Ev} = ?P:wait_event(P2, <<"local_description">>, #{}),
    ok = webrtc:set_remote_description(Pc, offer, Offer),
    {ok, Answer} = webrtc:create_answer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, answer, Answer),
    ct:log("offer:~n~s~nanswer:~n~s", [Offer, Answer]),
    P4 = ?P:cmd(consume(P3, Ev), #{cmd => remote_description, type => answer, sdp => Answer}),
    connected(Pc, P4).

%% Trickle candidates both ways until both sides are connected.
connected(Pc, P) ->
    Deadline = erlang:monotonic_time(millisecond) + 20000,
    pump(Pc, P, false, false, Deadline).

pump(_Pc, P, true, true, _Deadline) ->
    P;
pump(Pc, P0, Ours, Theirs, Deadline) ->
    case erlang:monotonic_time(millisecond) > Deadline of
        true -> ct:fail({not_connected, #{erlang => Ours, peer => Theirs, events => ?P:events(P0)}});
        false -> ok
    end,
    {P1, Theirs1} = forward_peer(Pc, P0, Theirs),
    Ours1 = forward_erlang(Pc, P1, Ours),
    pump(Pc, P1, Ours1, Theirs1, Deadline).

forward_peer(Pc, P0, Theirs) ->
    case ?P:wait(P0, fun(#{<<"event">> := E}) ->
                         E =:= <<"local_candidate">> orelse E =:= <<"connection_state">> orelse
                             E =:= <<"error">>;
                        (_) -> false
                     end, 50) of
        {ok, P1, #{<<"event">> := <<"local_candidate">>, <<"candidate">> := C} = Ev} ->
            put(peer_candidates, [C || C =/= <<>>] ++ peer_candidates()),
            Mid = maps:get(<<"mid">>, Ev, undefined),
            ok = case C of
                     <<>> -> webrtc:add_ice_candidate(Pc, end_of_candidates, Mid);
                     _ -> webrtc:add_ice_candidate(Pc, C, Mid)
                 end,
            {consume(P1, Ev), Theirs};
        {ok, P1, #{<<"event">> := <<"connection_state">>, <<"state">> := S} = Ev} ->
            {consume(P1, Ev), Theirs orelse S =:= <<"connected">>};
        {ok, _P1, #{<<"event">> := <<"error">>, <<"message">> := M}} ->
            ct:fail({peer_error, M});
        {error, P1, timeout} ->
            {P1, Theirs}
    end.

peer_candidates() ->
    case get(peer_candidates) of
        undefined -> [];
        L -> L
    end.

%% wait/3 searches the history; drop handled events from it.
consume(P, Ev) -> ?P:forget(P, Ev).

forward_erlang(Pc, P, Ours) ->
    receive
        {webrtc, Pc, {ice_candidate, end_of_candidates, Mid}} ->
            _ = ?P:cmd(P, #{cmd => remote_candidate, candidate => <<>>, mid => Mid}),
            forward_erlang(Pc, P, Ours);
        {webrtc, Pc, {ice_candidate, C, Mid}} ->
            _ = ?P:cmd(P, #{cmd => remote_candidate, candidate => C, mid => Mid}),
            forward_erlang(Pc, P, Ours);
        {webrtc, Pc, {connection_state, connected}} ->
            forward_erlang(Pc, P, true);
        {webrtc, Pc, {connection_state, failed}} ->
            ct:fail(erlang_connection_failed)
    after 0 ->
        Ours
    end.

wait_erlang(Pc, Pred) ->
    {ok, E} = webrtc_test_signal:wait(Pc, Pred, 15000),
    E.

channel_open(Pc, Label) ->
    {datachannel_open, Id, _, _, Opts} =
        wait_erlang(Pc, fun({datachannel_open, _, L, _, _}) -> L =:= Label; (_) -> false end),
    {Id, Opts}.

erlang_message(Pc, Data) ->
    wait_erlang(Pc, fun({channel_message, _, _, D}) -> D =:= Data; (_) -> false end).

%%--------------------------------------------------------------------
%% Cases
%%--------------------------------------------------------------------

erlang_offers_datachannel(Config) ->
    {Pc, P0} = start(Config),
    ok = webrtc:create_data_channel(Pc, <<"chat">>, #{}),
    P1 = erlang_offer(Pc, P0, #{}),
    {Id, _} = channel_open(Pc, <<"chat">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"chat">>}),
    %% Regression: the channel must survive Pion's padded ACK.
    timer:sleep(200),
    ok = webrtc:send_data(Pc, Id, text, <<"ping">>),
    {ok, P3, _} = ?P:wait_event(P2, <<"message">>, #{<<"data">> => <<"ping">>}),
    _ = erlang_message(Pc, <<"echo:ping">>),
    put(peer, P3).

peer_offers_datachannel(Config) ->
    {Pc, P0} = start(Config),
    P1 = peer_offer(Pc, P0, #{channels => [#{label => <<"from-peer">>}]}),
    {Id, _} = channel_open(Pc, <<"from-peer">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"from-peer">>}),
    P3 = ?P:cmd(P2, #{cmd => send, label => <<"from-peer">>, data => <<"hello erlang">>}),
    {channel_message, Id, text, _} = erlang_message(Pc, <<"hello erlang">>),
    ok = webrtc:send_data(Pc, Id, text, <<"hello peer">>),
    {ok, P4, _} = ?P:wait_event(P3, <<"message">>, #{<<"data">> => <<"hello peer">>}),
    put(peer, P4).

unreliable_datachannel(Config) ->
    {Pc, P0} = start(Config),
    Spec = #{label => <<"game">>, ordered => false, max_retransmits => 0},
    P1 = peer_offer(Pc, P0, #{channels => [Spec]}),
    {Id, Opts} = channel_open(Pc, <<"game">>),
    ?assertMatch(#{ordered := false, max_retransmits := 0}, Opts),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"game">>}),
    ok = webrtc:send_data(Pc, Id, text, <<"tick">>),
    {ok, P3, _} = ?P:wait_event(P2, <<"message">>, #{<<"data">> => <<"tick">>}),
    _ = erlang_message(Pc, <<"echo:tick">>),
    put(peer, P3).

binary_and_large_messages(Config) ->
    {Pc, P0} = start(Config),
    ok = webrtc:create_data_channel(Pc, <<"bin">>, #{}),
    P1 = erlang_offer(Pc, P0, #{}),
    {Id, _} = channel_open(Pc, <<"bin">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"bin">>}),
    Big = crypto:strong_rand_bytes(60000),
    ok = webrtc:send_data(Pc, Id, binary, Big),
    {ok, P3, _} = ?P:wait_event(P2, <<"message">>, #{<<"data">> => base64:encode(Big)}),
    _ = erlang_message(Pc, <<"echo", Big/binary>>),
    put(peer, P3).

%% Erlang sends RTP; Pion echoes it back unchanged, decoding peers
%% (aiortc, browsers) only count it.
erlang_sends_media(Config) ->
    {Pc, P0} = start(Config),
    {ok, _} = webrtc:add_transceiver(Pc, audio, #{}),
    {ok, _} = webrtc:add_transceiver(Pc, video, #{}),
    Media = [<<"audio">>, <<"video">>],
    P1 = erlang_offer(Pc, P0, #{media => Media}),
    %% Valid Opus frames (20 ms CELT silence, RFC 6716) so decoding
    %% peers accept them; a counter octet makes each one unique for the
    %% echo check (the decoder ignores padding after a code 0 frame).
    Payloads = [<<16#F8, 16#FF, 16#FE>> || _ <- lists:seq(1, 50)],
    lists:foreach(
        fun({N, Pl}) -> ok = webrtc:send_rtp(Pc, <<"0">>, Pl, #{timestamp => N * 960}) end,
        lists:zip(lists:seq(1, 50), Payloads)
    ),
    {ok, P2, _} = ?P:wait_event(P1, <<"rtp">>, #{<<"kind">> => <<"audio">>}),
    case ?config(peer, Config) of
        pion ->
            {rtp, <<"0">>, #rtp{}} = wait_erlang(Pc, fun({rtp, <<"0">>, #rtp{payload = Pl}}) ->
                                                         lists:member(Pl, Payloads);
                                                    (_) -> false end);
        _ ->
            ok
    end,
    put(peer, P2).

%% Without BUNDLE (RFC 9143) audio, video and data each get their own
%% ICE and DTLS transport, and all of them carry their traffic.
erlang_offers_unbundled(Config) ->
    case ?config(peer, Config) of
        pion -> {skip, "Pion has one ICE transport per peer connection"};
        aiortc -> {skip, "aiortc 1.16 answers an unbundled offer with a BUNDLE group (RFC 9143 7.3)"};
        _ -> erlang_offers_unbundled1(Config)
    end.

erlang_offers_unbundled1(Config) ->
    {Pc, P0} = start(Config, #{bundle => false}),
    {ok, _} = webrtc:add_transceiver(Pc, audio, #{}),
    {ok, _} = webrtc:add_transceiver(Pc, video, #{}),
    ok = webrtc:create_data_channel(Pc, <<"solo">>, #{}),
    %% max-bundle (the adapter's default) refuses offers without BUNDLE.
    P1 = erlang_offer(Pc, P0, #{media => [<<"audio">>, <<"video">>], bundle_policy => <<"balanced">>}),
    {Id, _} = channel_open(Pc, <<"solo">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"solo">>}),
    ok = webrtc:send_data(Pc, Id, text, <<"ping">>),
    {ok, P3, _} = ?P:wait_event(P2, <<"message">>, #{<<"data">> => <<"ping">>}),
    Opus = <<16#F8, 16#FF, 16#FE>>,
    [ok = webrtc:send_rtp(Pc, <<"0">>, Opus, #{timestamp => N * 960}) || N <- lists:seq(1, 50)],
    {ok, P4, _} = ?P:wait_event(P3, <<"rtp">>, #{<<"kind">> => <<"audio">>}),
    #{transports := Ts} = webrtc:get_stats(Pc),
    ?assertEqual(2, map_size(Ts)),
    put(peer, P4).

%% The peer sends media from its own encoders; Erlang receives it,
%% forwards every packet back, and decoding peers report decoded frames.
peer_sends_media(Config) ->
    {Pc, P0} = start(Config),
    %% Our transceivers are associated with the offered m= sections
    %% (RFC 9429 §5.10), so we answer sendrecv and can echo.
    {ok, _} = webrtc:add_transceiver(Pc, audio, #{}),
    {ok, _} = webrtc:add_transceiver(Pc, video, #{}),
    Media = [<<"audio">>, <<"video">>],
    P1 = peer_offer(Pc, P0, #{media => Media}),
    case ?config(peer, Config) of
        pion ->
            %% Pion only echoes, it has no media of its own.
            put(peer, P1),
            {skip, "pion adapter sends no media of its own"};
        _ ->
            Loop = spawn_link(fun() -> echo_loop(Pc, 0) end),
            ok = webrtc:controlling_process(Pc, Loop),
            case ?P:wait(P1, fun(#{<<"event">> := <<"rtp">>, <<"kind">> := <<"video">>,
                                     <<"count">> := N}) -> N >= 10;
                                  (_) -> false end, 20000) of
                {ok, P2, _} ->
                    put(peer, P2);
                {error, P2, R} ->
                    log_rtp_stats(Pc, P2),
                    ct:fail({no_decoded_video, R})
            end
    end.

%% Diagnostics: RTP statistics of both sides.
log_rtp_stats(Pc, P0) ->
    P1 = ?P:cmd(P0, #{cmd => stats}),
    case ?P:wait_event(P1, <<"stats">>, #{}) of
        {ok, _, #{<<"stats">> := Stats}} ->
            Rtp = [maps:with([<<"type">>, <<"kind">>, <<"packetsReceived">>, <<"packetsSent">>,
                              <<"framesDecoded">>, <<"framesEncoded">>, <<"keyFramesDecoded">>,
                              <<"pliCount">>, <<"nackCount">>, <<"firCount">>, <<"packetsLost">>,
                              <<"codecId">>, <<"decoderImplementation">>], S)
                   || S <- maps:values(Stats), is_map(S),
                      lists:member(maps:get(<<"type">>, S, undefined), [<<"inbound-rtp">>, <<"outbound-rtp">>])],
            ct:log("peer rtp stats: ~p", [Rtp]);
        Other ->
            ct:log("no peer stats: ~p", [Other])
    end,
    ct:log("erlang media stats: ~p", [maps:get(media, maps:get(transport, webrtc:get_stats(Pc)))]).

echo_loop(Pc, N) ->
    receive
        {webrtc, Pc, {rtp, Mid, Pkt}} ->
            _ = webrtc:send_rtp_packet(Pc, Mid, Pkt),
            echo_loop(Pc, N + 1);
        {webrtc, Pc, {keyframe_request, Mid}} ->
            _ = webrtc:request_keyframe(Pc, Mid),
            echo_loop(Pc, N);
        _ ->
            echo_loop(Pc, N)
    end.

peer_closes(Config) ->
    {Pc, P0} = start(Config),
    ok = webrtc:create_data_channel(Pc, <<"x">>, #{}),
    P1 = erlang_offer(Pc, P0, #{}),
    _ = channel_open(Pc, <<"x">>),
    ?P:stop(P1),
    erase(peer),
    {connection_state, S} =
        wait_erlang(Pc, fun({connection_state, S}) -> S =:= closed orelse S =:= failed
                                                      orelse S =:= disconnected;
                           (_) -> false end),
    ct:log("state after peer close: ~p", [S]).

%%--------------------------------------------------------------------
%% Renegotiation, ICE restart, ICE-Lite
%%--------------------------------------------------------------------

%% A subsequent Erlang offer, answered by the peer; candidates are
%% relayed for a moment since the connection is already up.
erlang_reoffer(Pc, P0) ->
    {ok, Offer} = webrtc:create_offer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, offer, Offer),
    P1 = ?P:cmd(P0, #{cmd => remote_description, type => offer, sdp => Offer}),
    {ok, P2, #{<<"sdp">> := Answer} = Ev} = ?P:wait_event(P1, <<"local_description">>, #{}),
    ct:log("re-offer:~n~s~nanswer:~n~s", [Offer, Answer]),
    ok = webrtc:set_remote_description(Pc, answer, Answer),
    relay_for(Pc, consume(P2, Ev), 3000).

relay_for(Pc, P, Ms) ->
    Deadline = erlang:monotonic_time(millisecond) + Ms,
    relay_until(Pc, P, Deadline).

relay_until(Pc, P0, Deadline) ->
    case erlang:monotonic_time(millisecond) > Deadline of
        true ->
            P0;
        false ->
            {P1, _} = forward_peer(Pc, P0, true),
            _ = forward_erlang(Pc, P1, true),
            relay_until(Pc, P1, Deadline)
    end.

echo_check(Pc, P0, Id, Text) ->
    ok = webrtc:send_data(Pc, Id, text, Text),
    {ok, P1, Ev} = ?P:wait_event(P0, <<"message">>, #{<<"data">> => Text}),
    _ = erlang_message(Pc, <<"echo:", Text/binary>>),
    consume(P1, Ev).

erlang_renegotiates_adds_audio(Config) ->
    {Pc, P0} = start(Config),
    ok = webrtc:create_data_channel(Pc, <<"r">>, #{}),
    %% Pion needs a local track to echo. Decoding peers only receive:
    %% aiortc 1.16 crashes answering a re-offer while a local transceiver
    %% from before the first negotiation is still unassociated.
    Init = case ?config(peer, Config) of
        pion -> #{media => [<<"audio">>]};
        _ -> #{}
    end,
    P1 = erlang_offer(Pc, P0, Init),
    {Id, _} = channel_open(Pc, <<"r">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"r">>}),
    {ok, _} = webrtc:add_transceiver(Pc, audio, #{}),
    P3 = erlang_reoffer(Pc, P2),
    [ok = webrtc:send_rtp(Pc, <<"1">>, <<16#F8, 16#FF, 16#FE>>, #{timestamp => N * 960})
     || N <- lists:seq(1, 50)],
    {ok, P4, _} = ?P:wait_event(P3, <<"rtp">>, #{<<"kind">> => <<"audio">>}),
    %% The data channel survived the renegotiation.
    put(peer, echo_check(Pc, P4, Id, <<"after renegotiation">>)).

erlang_ice_restart(Config) ->
    {Pc, P0} = start(Config),
    ok = webrtc:create_data_channel(Pc, <<"i">>, #{}),
    P1 = erlang_offer(Pc, P0, #{}),
    {Id, _} = channel_open(Pc, <<"i">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"i">>}),
    ok = webrtc:restart_ice(Pc),
    P3 = erlang_reoffer(Pc, P2),
    put(peer, echo_check(Pc, P3, Id, <<"after erlang restart">>)).

peer_ice_restart(Config) ->
    {Pc, P0} = start(Config),
    P1 = peer_offer(Pc, P0, #{channels => [#{label => <<"j">>}]}),
    {Id, _} = channel_open(Pc, <<"j">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"j">>}),
    P3 = ?P:cmd(P2, #{cmd => create_offer, ice_restart => true}),
    {ok, P4, #{<<"sdp">> := Offer} = Ev} = ?P:wait_event(P3, <<"local_description">>, #{}),
    ok = webrtc:set_remote_description(Pc, offer, Offer),
    {ok, Answer} = webrtc:create_answer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, answer, Answer),
    P5 = ?P:cmd(consume(P4, Ev), #{cmd => remote_description, type => answer, sdp => Answer}),
    P6 = relay_for(Pc, P5, 3000),
    put(peer, echo_check(Pc, P6, Id, <<"after peer restart">>)).

%% Erlang as an ICE-Lite agent (RFC 8445 §2.5) answering a full agent.
erlang_ice_lite(Config) ->
    Peer = ?config(peer, Config),
    {ok, P} = ?P:start(Peer, ?config(priv_dir, Config)),
    put(peer, P),
    Opts = case Peer of pion -> #{loopback => true}; _ -> #{} end,
    {ok, Pc} = webrtc:new_peer_connection(Opts#{ice_lite => true}),
    put(pc, Pc),
    P1 = peer_offer(Pc, P, #{channels => [#{label => <<"lite">>}]}),
    {ok, Answer} = {ok, webrtc:local_description(Pc)},
    ?assertNotEqual(nomatch, binary:match(Answer, <<"a=ice-lite">>)),
    {Id, _} = channel_open(Pc, <<"lite">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"lite">>}),
    put(peer, echo_check(Pc, P2, Id, <<"lite">>)).

%%--------------------------------------------------------------------
%% Simulcast (RFC 8853, RFC 8852)
%%--------------------------------------------------------------------

-define(RIDS, [<<"q">>, <<"h">>, <<"f">>]).

%% The peer sends three simulcast layers from its encoder; Erlang
%% answers, receives every layer with its rid, and asks one layer for a
%% keyframe, which the peer reports on that layer.
peer_sends_simulcast(Config) ->
    case ?config(peer, Config) of
        Browser when Browser =:= chromium; Browser =:= firefox -> peer_sends_simulcast_(Config);
        _ -> {skip, "adapter sends no simulcast"}
    end.

peer_sends_simulcast_(Config) ->
    {Pc, P0} = start(Config),
    P1 = peer_offer(Pc, P0, #{media => [<<"video">>], simulcast => true}),
    Answer = webrtc:local_description(Pc),
    ?assertNotEqual(nomatch, binary:match(Answer, <<"a=simulcast:recv q;h;f">>)),
    Counts = count_layers(Pc, #{}, erlang:monotonic_time(millisecond) + 20000),
    {P2, Before, Outbound} = pli_counts(P1),
    ct:log("packets per rid: ~p~npeer outbound streams: ~p~nstats: ~p", [Counts, Outbound, webrtc:get_stats(Pc)]),
    ?assertEqual(lists:sort(?RIDS), lists:sort(maps:keys(Counts))),
    [?assert(N >= 50) || N <- maps:values(Counts)],
    ok = webrtc:request_keyframe(Pc, <<"0">>, #{rid => <<"h">>}),
    put(peer, wait_pli(P2, Before, erlang:monotonic_time(millisecond) + 10000)).

%% Erlang offers three layers; the peer answers with simulcast recv and
%% receives every layer, telling them apart by their rid extension.
%% Browsers cannot receive simulcast (RFC 9429 §3.7).
erlang_sends_simulcast(Config) ->
    case ?config(peer, Config) of
        pion -> erlang_sends_simulcast_(Config);
        _ -> {skip, "peer does not receive simulcast"}
    end.

erlang_sends_simulcast_(Config) ->
    {Pc, P0} = start(Config),
    {ok, _} = webrtc:add_transceiver(Pc, video, #{
        direction => sendonly,
        send_encodings => [#{rid => R} || R <- ?RIDS]
    }),
    P1 = erlang_offer(Pc, P0, #{simulcast => true}),
    Answer = webrtc:remote_description(Pc),
    ?assertNotEqual(nomatch, binary:match(Answer, <<"a=simulcast:recv q;h;f">>)),
    [ok = webrtc:send_rtp(Pc, <<"0">>, <<R/binary, N:16>>, #{rid => R, timestamp => N * 3000, marker => true})
     || N <- lists:seq(1, 60), R <- ?RIDS],
    P2 = lists:foldl(
        fun(Rid, P) ->
            {ok, P3, _} = ?P:wait(P, fun(#{<<"event">> := <<"rtp">>, <<"rid">> := R, <<"count">> := N}) ->
                                             R =:= Rid andalso N >= 50;
                                        (_) -> false
                                     end, 10000),
            P3
        end,
        P1,
        ?RIDS
    ),
    Tracks = [R || #{<<"event">> := <<"track">>, <<"rid">> := R} <- ?P:events(P2)],
    ?assertEqual(lists:sort(?RIDS), lists:sort(Tracks)),
    put(peer, P2).

%% Until every layer has delivered 50 packets.
count_layers(Pc, Counts, Deadline) ->
    Done = lists:all(fun(R) -> maps:get(R, Counts, 0) >= 50 end, ?RIDS),
    Left = Deadline - erlang:monotonic_time(millisecond),
    case Done orelse Left =< 0 of
        true ->
            Counts;
        false ->
            receive
                {webrtc, Pc, {rtp, <<"0">>, Rid, #rtp{}}} ->
                    count_layers(Pc, maps:update_with(Rid, fun(N) -> N + 1 end, 1, Counts), Deadline);
                {webrtc, Pc, {rtp, Mid, #rtp{}}} ->
                    ct:fail({packet_without_rid, Mid})
            after Left ->
                Counts
            end
    end.

%% pliCount of the peer's outbound streams, by rid.
pli_counts(P0) ->
    P1 = ?P:cmd(P0, #{cmd => stats}),
    {ok, P2, #{<<"stats">> := Stats} = Ev} = ?P:wait_event(P1, <<"stats">>, #{}),
    Outbound = [S || S <- maps:values(Stats), maps:get(<<"type">>, S, undefined) =:= <<"outbound-rtp">>],
    Counts = maps:from_list([{Rid, maps:get(<<"pliCount">>, S, 0)} || #{<<"rid">> := Rid} = S <- Outbound]),
    {consume(P2, Ev), Counts, Outbound}.

wait_pli(P0, Before, Deadline) ->
    {P1, Now, _} = pli_counts(P0),
    Asked = maps:get(<<"h">>, Now, 0) > maps:get(<<"h">>, Before, 0),
    case Asked orelse erlang:monotonic_time(millisecond) > Deadline of
        true ->
            ct:log("pliCount before ~p after ~p", [Before, Now]),
            ?assert(Asked),
            P1;
        false ->
            timer:sleep(250),
            wait_pli(P1, Before, Deadline)
    end.

%% Chromium hides its host addresses behind <uuid>.local names
%% (draft-ietf-mmusic-mdns-ice-candidates); Erlang resolves them with
%% multicast DNS and connects.
peer_offers_mdns_candidates(Config) ->
    {Pc, P0} = start(Config),
    P1 = peer_offer(Pc, P0, #{channels => [#{label => <<"mdns">>}]}),
    %% Chromium (controlling) may complete ICE through the peer-reflexive
    %% candidate its own checks create before the names resolve; once
    %% complete, our agent does not check the late pairs (RFC 8445 §8.3).
    mdns_only(Pc, resolved),
    {Id, _} = channel_open(Pc, <<"mdns">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"mdns">>}),
    P3 = ?P:cmd(P2, #{cmd => send, label => <<"mdns">>, data => <<"from chromium">>}),
    {channel_message, Id, text, _} = erlang_message(Pc, <<"from chromium">>),
    ok = webrtc:send_data(Pc, Id, text, <<"from erlang">>),
    {ok, P4, _} = ?P:wait_event(P3, <<"message">>, #{<<"data">> => <<"from erlang">>}),
    put(peer, P4).

erlang_offers_mdns_candidates(Config) ->
    {Pc, P0} = start(Config),
    ok = webrtc:create_data_channel(Pc, <<"mdns">>, #{}),
    P1 = erlang_offer(Pc, P0, #{}),
    mdns_only(Pc, answered),
    {Id, _} = channel_open(Pc, <<"mdns">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"mdns">>}),
    ok = webrtc:send_data(Pc, Id, text, <<"ping">>),
    {ok, P3, _} = ?P:wait_event(P2, <<"message">>, #{<<"data">> => <<"ping">>}),
    _ = erlang_message(Pc, <<"echo:ping">>),
    put(peer, P3).

%% Every host candidate Chromium signaled was an mDNS name, and the
%% names resolved: there are pairs with a remote host candidate (only
%% created from a resolved name; one learned from Chromium's checks
%% would be peer-reflexive). With `answered', our checks to one of them
%% got a response.
mdns_only(Pc, Need) ->
    Cands = peer_candidates(),
    ct:log("chromium candidates: ~p", [Cands]),
    Host = [C || C <- Cands, binary:match(C, <<" typ host">>) =/= nomatch],
    ?assertNotEqual([], Host),
    [?assertNotEqual(nomatch, binary:match(C, <<".local ">>)) || C <- Host],
    resolved_pair(Pc, Need, 50).

resolved_pair(Pc, Need, Tries) ->
    #{transport := #{ice := #{pairs := Pairs}}} = webrtc:get_stats(Pc),
    Resolved = lists:usort([
        R#ice_cand.address
     || #{remote := #ice_cand{type = host} = R, responses_received := N} <- Pairs, N > 0 orelse Need =:= resolved
    ]),
    case Resolved of
        [_ | _] ->
            ct:log("pairs to resolved host candidates (~p): ~p", [Need, Resolved]);
        [] when Tries > 0 ->
            timer:sleep(100),
            resolved_pair(Pc, Need, Tries - 1);
        [] ->
            ct:fail({no_resolved_pair, [{T#ice_cand.type, T#ice_cand.address, St, N} ||
                #{remote := T, state := St, responses_received := N} <- Pairs]})
    end.

%%--------------------------------------------------------------------
%% ICE-TCP (RFC 6544): no UDP leaves our side, the browser reaches our
%% TCP candidates.
%%--------------------------------------------------------------------

tcp_opts() ->
    #{ice_tcp => true, outbound_filter => webrtc_impair:filter(#{only_to => []})}.

erlang_offers_ice_tcp(Config) ->
    {Pc, P0} = start(Config, tcp_opts()),
    ok = webrtc:create_data_channel(Pc, <<"tcp">>, #{}),
    P1 = erlang_offer(Pc, P0, #{}),
    {Id, _} = channel_open(Pc, <<"tcp">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"tcp">>}),
    ok = webrtc:send_data(Pc, Id, text, <<"ping">>),
    {ok, P3, _} = ?P:wait_event(P2, <<"message">>, #{<<"data">> => <<"ping">>}),
    _ = erlang_message(Pc, <<"echo:ping">>),
    tcp_selected(Pc),
    put(peer, P3).

peer_offers_ice_tcp(Config) ->
    {Pc, P0} = start(Config, tcp_opts()),
    P1 = peer_offer(Pc, P0, #{channels => [#{label => <<"tcp">>}]}),
    {Id, _} = channel_open(Pc, <<"tcp">>),
    {ok, P2, _} = ?P:wait_event(P1, <<"channel_open">>, #{<<"label">> => <<"tcp">>}),
    P3 = ?P:cmd(P2, #{cmd => send, label => <<"tcp">>, data => <<"from browser">>}),
    {channel_message, Id, text, _} = erlang_message(Pc, <<"from browser">>),
    tcp_selected(Pc),
    put(peer, P3).

%% Data may flow before nomination (RFC 8445 §12.1): wait for it.
tcp_selected(Pc) ->
    tcp_selected(Pc, 50).

tcp_selected(Pc, Tries) ->
    #{transport := #{ice := #{pairs := Pairs}}} = webrtc:get_stats(Pc),
    case [{L, R} || #{selected := true, local := L, remote := R} <- Pairs] of
        [] when Tries > 0 ->
            timer:sleep(100),
            tcp_selected(Pc, Tries - 1);
        Sel ->
            ct:log("selected: ~p", [Sel]),
            ?assertMatch([{#ice_cand{transport = tcp}, #ice_cand{transport = tcp}}], Sel)
    end.
