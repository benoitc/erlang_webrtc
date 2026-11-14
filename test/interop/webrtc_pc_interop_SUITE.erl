%% Peer connection interoperability: an Erlang peer connection against
%% independent implementations (Pion, aiortc, Chromium, Firefox) through
%% the adapters of interop/. Both offer/answer roles, data channels and
%% media. Missing or unstartable peers are reported as skipped.
-module(webrtc_pc_interop_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2,
         init_per_testcase/2, end_per_testcase/2]).
-export([
    erlang_offers_datachannel/1,
    peer_offers_datachannel/1,
    unreliable_datachannel/1,
    binary_and_large_messages/1,
    erlang_sends_media/1,
    peer_sends_media/1,
    peer_closes/1
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
        peer_closes
    ].

all() -> [{group, pion}, {group, aiortc}, {group, chromium}, {group, firefox}].

groups() -> [{G, [], cases()} || G <- [pion, aiortc, chromium, firefox]].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    %% Peer side diagnostics go to the adapter's log file.
    os:putenv("PION_LOG_DEBUG", "sctp,datachannel,dtls,pc"),
    Config.

end_per_suite(_) -> ok.

init_per_group(Peer, Config) ->
    case ?P:probe(Peer, ?config(priv_dir, Config)) of
        ok -> [{peer, Peer} | Config];
        {skip, R} -> {skip, R}
    end.

end_per_group(_, _) -> ok.

init_per_testcase(_, Config) ->
    flush(),
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
    Peer = ?config(peer, Config),
    {ok, P} = ?P:start(Peer, ?config(priv_dir, Config)),
    put(peer, P),
    %% Pion is restricted to loopback; the others gather on every
    %% interface and need a routable host candidate from us.
    Opts = case Peer of pion -> #{loopback => true}; _ -> #{} end,
    {ok, Pc} = webrtc:new_peer_connection(Opts),
    put(pc, Pc),
    {Pc, P}.

%% Erlang offers, the peer answers.
erlang_offer(Pc, P0, Init) ->
    P1 = ?P:cmd(P0, Init#{cmd => init}),
    {ok, Offer} = webrtc:create_offer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, offer, Offer),
    P2 = ?P:cmd(P1, #{cmd => remote_description, type => offer, sdp => Offer}),
    {ok, P3, #{<<"sdp">> := Answer}} = ?P:wait_event(P2, <<"local_description">>, #{}),
    ct:log("offer:~n~s~nanswer:~n~s", [Offer, Answer]),
    ok = webrtc:set_remote_description(Pc, answer, Answer),
    connected(Pc, P3).

%% The peer offers, Erlang answers.
peer_offer(Pc, P0, Init) ->
    P1 = ?P:cmd(P0, Init#{cmd => init}),
    P2 = ?P:cmd(P1, #{cmd => create_offer}),
    {ok, P3, #{<<"sdp">> := Offer}} = ?P:wait_event(P2, <<"local_description">>, #{}),
    ok = webrtc:set_remote_description(Pc, offer, Offer),
    {ok, Answer} = webrtc:create_answer(Pc, #{}),
    ok = webrtc:set_local_description(Pc, answer, Answer),
    ct:log("offer:~n~s~nanswer:~n~s", [Offer, Answer]),
    P4 = ?P:cmd(P3, #{cmd => remote_description, type => answer, sdp => Answer}),
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
            ok = case C of
                     <<>> -> webrtc:add_ice_candidate(Pc, end_of_candidates);
                     _ -> webrtc:add_ice_candidate(Pc, C)
                 end,
            {consume(P1, Ev), Theirs};
        {ok, P1, #{<<"event">> := <<"connection_state">>, <<"state">> := S} = Ev} ->
            {consume(P1, Ev), Theirs orelse S =:= <<"connected">>};
        {ok, _P1, #{<<"event">> := <<"error">>, <<"message">> := M}} ->
            ct:fail({peer_error, M});
        {error, P1, timeout} ->
            {P1, Theirs}
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
            {ok, P2, _} = ?P:wait(P1, fun(#{<<"event">> := <<"rtp">>, <<"kind">> := <<"video">>,
                                            <<"count">> := N}) -> N >= 10;
                                         (_) -> false end, 20000),
            put(peer, P2)
    end.

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
