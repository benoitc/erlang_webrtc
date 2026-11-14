%% Tests of the DCEP codec (RFC 8832) and the data channel manager
%% (RFC 8831) over the in-memory network.
-module(webrtc_dcep_tests).
-include_lib("eunit/include/eunit.hrl").

-define(D, webrtc_dcep).
-define(S, webrtc_sctp_assoc).
-define(NET, webrtc_sctp_net).
-define(MINUTE, 60000).

-include("webrtc_sctp.hrl").

%%====================================================================
%% Codec
%%====================================================================

open_vector_test() ->
    Msg =
        {open, #{
            ordered => false,
            reliability => {max_retransmits, 3},
            priority => 512,
            label => <<"chat">>,
            protocol => <<"x">>
        }},
    Bin = ?D:encode(Msg),
    ?assertEqual(<<3, 16#81, 2, 0, 0, 0, 0, 3, 0, 4, 0, 1, "chat", "x">>, Bin),
    ?assertEqual({ok, Msg}, ?D:decode(Bin)).

ack_test() ->
    ?assertEqual(<<2>>, ?D:encode(ack)),
    ?assertEqual({ok, ack}, ?D:decode(<<2>>)),
    ?assertEqual({error, bad_length}, ?D:decode(<<2, 0>>)).

all_channel_types_test() ->
    Rels = [reliable, {max_retransmits, 0}, {max_packet_life_time, 150}],
    lists:foreach(
        fun({Ordered, Rel}) ->
            Msg =
                {open, #{
                    ordered => Ordered,
                    reliability => Rel,
                    priority => 256,
                    label => <<"l"/utf8>>,
                    protocol => <<>>
                }},
            ?assertEqual({ok, Msg}, ?D:decode(?D:encode(Msg)))
        end,
        [{O, R} || O <- [true, false], R <- Rels]
    ),
    Types = [binary:at(?D:encode(open(O, R)), 1) || O <- [true, false], R <- Rels],
    ?assertEqual([16#00, 16#01, 16#02, 16#80, 16#81, 16#82], Types).

open(O, R) ->
    {open, #{ordered => O, reliability => R, priority => 0, label => <<>>, protocol => <<>>}}.

codec_errors_test() ->
    Bin = ?D:encode(open(true, reliable)),
    [?assertMatch({error, _}, ?D:decode(binary:part(Bin, 0, N))) || N <- lists:seq(0, byte_size(Bin) - 1)],
    ?assertMatch({error, _}, ?D:decode(<<Bin/binary, 0>>)),
    ?assertEqual({error, {bad_channel_type, 16#03}}, ?D:decode(<<3, 3, 0:16, 0:32, 0:16, 0:16>>)),
    ?assertEqual({error, bad_utf8}, ?D:decode(<<3, 0, 0:16, 0:32, 1:16, 0:16, 255>>)),
    ?assertEqual({error, {unknown_message_type, 9}}, ?D:decode(<<9>>)),
    ?assertEqual({error, empty}, ?D:decode(<<>>)).

%%====================================================================
%% Manager
%%====================================================================

opts(Role, Seed) ->
    opts(Role, Seed, #{}).

opts(Role, Seed, Extra) ->
    maps:merge(
        #{role => Role, sctp => #{random_seed => Seed, heartbeat_interval => infinity}}, Extra
    ).

pair() -> pair(#{}, #{}, #{}).

pair(ExtraA, ExtraB, NetOpts) ->
    A = ?D:new(opts(client, 1, ExtraA)),
    B = ?D:new(opts(server, 2, ExtraB)),
    N0 = ?NET:new(?D, {A, B}, maps:merge(#{seed => 9, mtu => 1200}, NetOpts)),
    N1 = ?NET:call(a, fun(E, Now) -> ?D:connect(Now, E) end, N0),
    N2 = ?NET:call(b, fun(E, Now) -> ?D:connect(Now, E) end, N1),
    {ok, N} = ?NET:run_until(fun(X) -> up(a, X) andalso up(b, X) end, ?MINUTE, N2),
    N.

up(Side, N) -> lists:any(fun({connected, _}) -> true; (_) -> false end, ?NET:events(Side, N)).

open_ch(Side, Label, Opts, N) ->
    Self = self(),
    N1 = ?NET:call(
        Side,
        fun(E, Now) ->
            {ok, Id, E1, Acts} = ?D:open_channel(Label, Opts, Now, E),
            Self ! {id, Id},
            {E1, Acts}
        end,
        N
    ),
    receive
        {id, Id} -> {Id, N1}
    end.

send(Side, Id, Type, Data, N) ->
    case ?NET:call(Side, fun(E, Now) -> ?D:send(Id, Type, Data, Now, E) end, N) of
        {error, R} -> error({send, R});
        N1 -> N1
    end.

close(Side, Id, N) ->
    ?NET:call(Side, fun(E, Now) -> ?D:close_channel(Id, Now, E) end, N).

evs(Side, N) ->
    [E || E <- ?NET:events(Side, N), element(1, E) =/= connected, element(1, E) =/= buffered_amount_low].

msgs(Side, N) ->
    [{Id, T, D} || {channel_message, Id, T, D} <- ?NET:events(Side, N)].

wait(Pred, N) ->
    {ok, N1} = ?NET:run_until(Pred, ?MINUTE, N),
    N1.

has(Side, Ev) -> fun(X) -> lists:member(Ev, ?NET:events(Side, X)) end.

open_ack_test() ->
    N0 = pair(),
    {Id, N1} = open_ch(a, <<"chat">>, #{protocol => <<"json">>}, N0),
    ?assertEqual(0, Id),
    N2 = wait(fun(X) -> evs(b, X) =/= [] end, N1),
    ?assertMatch(
        [{channel_open, 0, <<"chat">>, <<"json">>, #{initiator := remote, ordered := true, negotiated := false}}],
        evs(b, N2)
    ),
    ?assertMatch([{channel_open, 0, <<"chat">>, <<"json">>, #{initiator := local}}], evs(a, N2)),
    N3 = send(a, 0, text, <<"hello"/utf8>>, N2),
    N4 = send(b, 0, binary, <<1, 2, 3>>, N3),
    N5 = wait(fun(X) -> msgs(a, X) =/= [] andalso msgs(b, X) =/= [] end, N4),
    ?assertEqual([{0, text, <<"hello">>}], msgs(b, N5)),
    ?assertEqual([{0, binary, <<1, 2, 3>>}], msgs(a, N5)),
    ?assertMatch(#{0 := #{state := open, label := <<"chat">>}}, ?D:channels(?NET:engine(a, N5))).

open_before_connect_test() ->
    A = ?D:new(opts(client, 1)),
    {ok, 0, A1, []} = ?D:open_channel(<<"early">>, #{}, 0, A),
    B = ?D:new(opts(server, 2)),
    N0 = ?NET:new(?D, {A1, B}, #{seed => 1}),
    N1 = ?NET:call(a, fun(E, Now) -> ?D:connect(Now, E) end, N0),
    N2 = wait(fun(X) -> evs(b, X) =/= [] andalso evs(a, X) =/= [] end, N1),
    ?assertMatch([{channel_open, 0, <<"early">>, <<>>, _}], evs(b, N2)),
    ?assertMatch([{channel_open, 0, <<"early">>, <<>>, #{initiator := local}}], evs(a, N2)).

id_parity_test() ->
    N0 = pair(),
    {I0, N1} = open_ch(a, <<"a0">>, #{}, N0),
    {I1, N2} = open_ch(a, <<"a1">>, #{}, N1),
    {J0, N3} = open_ch(b, <<"b0">>, #{}, N2),
    {J1, N4} = open_ch(b, <<"b1">>, #{}, N3),
    ?assertEqual({0, 2, 1, 3}, {I0, I1, J0, J1}),
    ?assertEqual({error, wrong_parity}, ?D:open_channel(<<"x">>, #{id => 7}, 0, ?NET:engine(a, N4))),
    ?assertEqual({error, id_in_use}, ?D:open_channel(<<"x">>, #{id => 2}, 0, ?NET:engine(a, N4))),
    ?assertMatch({ok, 8, _, _}, ?D:open_channel(<<"x">>, #{id => 8}, 0, ?NET:engine(a, N4))),
    N5 = wait(fun(X) -> length(evs(a, X)) =:= 4 andalso length(evs(b, X)) =:= 4 end, N4),
    ?assertEqual([0, 1, 2, 3], lists:sort(maps:keys(?D:channels(?NET:engine(b, N5))))).

negotiated_test() ->
    N0 = pair(),
    {5, N1} = open_ch(a, <<"neg">>, #{negotiated => true, id => 5, ordered => false}, N0),
    {5, N2} = open_ch(b, <<"neg">>, #{negotiated => true, id => 5, ordered => false}, N1),
    ?assertMatch([{channel_open, 5, <<"neg">>, <<>>, #{negotiated := true, ordered := false}}], evs(a, N2)),
    ?assertMatch([{channel_open, 5, <<"neg">>, <<>>, #{negotiated := true}}], evs(b, N2)),
    N3 = send(b, 5, text, <<"x">>, send(a, 5, text, <<"y">>, N2)),
    N4 = wait(fun(X) -> msgs(a, X) =/= [] andalso msgs(b, X) =/= [] end, N3),
    ?assertEqual([{5, text, <<"y">>}], msgs(b, N4)),
    ?assertEqual([{5, text, <<"x">>}], msgs(a, N4)),
    ?assertEqual(
        {error, missing_id}, ?D:open_channel(<<"n">>, #{negotiated => true}, 0, ?NET:engine(a, N4))
    ).

empty_messages_test() ->
    N0 = pair(),
    {Id, N1} = open_ch(a, <<"e">>, #{}, N0),
    N2 = send(a, Id, binary, <<>>, send(a, Id, text, <<>>, N1)),
    N3 = wait(fun(X) -> length(msgs(b, X)) =:= 2 end, N2),
    ?assertEqual([{Id, text, <<>>}, {Id, binary, <<>>}], msgs(b, N3)).

max_message_size_test() ->
    N0 = pair(#{max_message_size => 1000}, #{max_message_size => 0}, #{}),
    {Id, N1} = open_ch(a, <<"m">>, #{}, N0),
    A = ?NET:engine(a, N1),
    ?assertEqual({error, message_too_large}, ?D:send(Id, binary, binary:copy(<<1>>, 1001), 0, A)),
    N2 = send(a, Id, binary, binary:copy(<<1>>, 1000), N1),
    N3 = wait(fun(X) -> evs(b, X) =/= [] end, N2),
    %% The other side has no limit (0).
    N4 = send(b, Id, binary, binary:copy(<<2>>, 200000), N3),
    N5 = wait(fun(X) -> msgs(b, X) =/= [] andalso msgs(a, X) =/= [] end, N4),
    ?assertEqual([{Id, binary, binary:copy(<<1>>, 1000)}], msgs(b, N5)),
    ?assertEqual([{Id, binary, binary:copy(<<2>>, 200000)}], msgs(a, N5)).

close_test() ->
    N0 = pair(),
    {Id, N1} = open_ch(a, <<"c">>, #{}, N0),
    N2 = send(a, Id, text, <<"last">>, N1),
    N3 = close(a, Id, N2),
    ?assertEqual({error, not_open}, ?D:send(Id, text, <<"x">>, 0, ?NET:engine(a, N3))),
    N4 = wait(fun(X) -> (has(a, {channel_closed, Id}))(X) andalso (has(b, {channel_closed, Id}))(X) end, N3),
    %% Data sent before the close is delivered first.
    ?assertEqual([{channel_open, Id, <<"c">>, <<>>}, {channel_message, Id, text, <<"last">>}, {channel_closed, Id}],
        [strip(E) || E <- evs(b, N4)]),
    ?assertEqual(#{}, ?D:channels(?NET:engine(a, N4))),
    ?assertEqual(#{}, ?D:channels(?NET:engine(b, N4))),
    %% The id can be used again.
    {Id2, N5} = open_ch(a, <<"again">>, #{}, N4),
    ?assertEqual(Id, Id2),
    N6 = wait(fun(X) -> length([x || {channel_open, _, <<"again">>, _, _} <- evs(b, X)]) =:= 1 end, N5),
    N7 = wait(fun(X) -> msgs(b, X) =/= [{Id, text, <<"last">>}] end, send(a, Id, text, <<"new">>, N6)),
    ?assertEqual([{Id, text, <<"last">>}, {Id, text, <<"new">>}], msgs(b, N7)).

%% RFC 8832 §6: before the peer answered, user data is sent ordered even
%% on an unordered channel.
ordered_until_ack_test() ->
    Tab = ets:new(cap, [ordered_set, public]),
    Filter = fun
        (a, Bin, _) ->
            ets:insert(Tab, {erlang:unique_integer([monotonic]), Bin}),
            keep;
        (_, _, _) ->
            keep
    end,
    N0 = ?NET:set(filter, Filter, pair()),
    {Id, N1} = open_ch(a, <<"u">>, #{ordered => false}, N0),
    N2 = send(a, Id, binary, <<"early">>, N1),
    N3 = wait(fun(X) -> length(msgs(b, X)) =:= 1 end, N2),
    N4 = send(a, Id, binary, <<"late">>, ?NET:run(1000, N3)),
    _ = wait(fun(X) -> length(msgs(b, X)) =:= 2 end, N4),
    Flags = [
        {D, U}
     || {_, Bin} <- ets:tab2list(Tab),
        {ok, #sctp_packet{chunks = Cs}} <- [webrtc_sctp_chunk:decode(Bin)],
        #sctp_data{ppid = 53, data = D, unordered = U} <- Cs
    ],
    ets:delete(Tab),
    ?assertEqual([{<<"early">>, false}, {<<"late">>, true}], lists:usort(Flags)).

strip({channel_open, Id, L, P, _}) -> {channel_open, Id, L, P};
strip(E) -> E.

remote_close_test() ->
    N0 = pair(),
    {Id, N1} = open_ch(a, <<"r">>, #{}, N0),
    N2 = wait(fun(X) -> evs(b, X) =/= [] end, N1),
    N3 = close(b, Id, N2),
    N4 = wait(fun(X) -> (has(a, {channel_closed, Id}))(X) andalso (has(b, {channel_closed, Id}))(X) end, N3),
    ?assertEqual(#{}, ?D:channels(?NET:engine(a, N4))).

close_lossy_test() ->
    N0 = pair(#{}, #{}, #{loss => 0.2, seed => 77}),
    {Id, N1} = open_ch(a, <<"l">>, #{}, N0),
    N2 = lists:foldl(fun(I, Acc) -> send(a, Id, binary, <<I:32>>, Acc) end, N1, lists:seq(1, 50)),
    N3 = close(a, Id, N2),
    {ok, N4} = ?NET:run_until(
        fun(X) -> (has(a, {channel_closed, Id}))(X) andalso (has(b, {channel_closed, Id}))(X) end,
        10 * ?MINUTE,
        N3
    ),
    ?assertEqual([{Id, binary, <<I:32>>} || I <- lists:seq(1, 50)], msgs(b, N4)).

partial_reliability_channel_test() ->
    N0 = pair(#{}, #{}, #{loss => 0.3, seed => 5}),
    {Id, N1} = open_ch(a, <<"pr">>, #{ordered => false, max_retransmits => 0}, N0),
    N2 = wait(fun(X) -> evs(b, X) =/= [] end, N1),
    ?assertMatch([{channel_open, Id, _, _, #{ordered := false, max_retransmits := 0}}], evs(b, N2)),
    Msg = fun(I) -> binary:copy(<<I:32>>, 250) end,
    N3 = lists:foldl(fun(I, Acc) -> send(a, Id, binary, Msg(I), Acc) end, ?NET:run(1000, N2), lists:seq(1, 100)),
    N4 = ?NET:run(?MINUTE, N3),
    Got = msgs(b, N4),
    ?assert(length(Got) < 100),
    ?assert(length(Got) > 0),
    ?assertEqual([], Got -- [{Id, binary, Msg(I)} || I <- lists:seq(1, 100)]),
    {_, T} = ?D:open_channel(<<"t">>, #{max_retransmits => 1, max_packet_life_time => 1}, 0, ?NET:engine(a, N4)),
    ?assertEqual(badarg, T).

shutdown_closes_channels_test() ->
    N0 = pair(),
    {Id, N1} = open_ch(a, <<"s">>, #{}, N0),
    N2 = wait(fun(X) -> evs(b, X) =/= [] end, N1),
    S = ?D:sctp(?NET:engine(a, N2)),
    ?assertEqual(established, ?S:state(S)),
    N3 = ?NET:call(a, fun(E, Now) ->
        {S1, Acts} = ?S:abort(Now, ?D:sctp(E)),
        _ = S1,
        %% Deliver the ABORT to b only; a is discarded.
        {E, [A || {send, _} = A <- Acts]}
    end, N2),
    N4 = ?NET:run(1000, N3),
    ?assertMatch([{channel_open, Id, _, _, _}, {channel_closed, Id}, {closed, {peer_abort, []}}], evs(b, N4)).

%%====================================================================
%% Against a raw SCTP peer
%%====================================================================

raw_pair() ->
    A = ?S:new(#{random_seed => 1, heartbeat_interval => infinity}),
    B = ?D:new(opts(server, 2)),
    N0 = ?NET:new({?S, ?D}, {A, B}, #{seed => 3}),
    N1 = ?NET:call(a, fun(E, Now) -> ?S:connect(Now, E) end, N0),
    {ok, N} = ?NET:run_until(fun(X) -> up(a, X) andalso up(b, X) end, ?MINUTE, N1),
    N.

raw_send(Sid, Ppid, Data, N) ->
    ?NET:call(a, fun(E, Now) -> ?S:send(Sid, Ppid, Data, #{}, Now, E) end, N).

open_label(Label) ->
    {open, #{ordered => true, reliability => reliable, priority => 0, label => Label, protocol => <<>>}}.

legacy_partial_ppid_test() ->
    N0 = raw_pair(),
    N1 = raw_send(0, 50, ?D:encode(open_label(<<"legacy">>)), N0),
    N2 = raw_send(0, 54, <<"hel">>, N1),
    N3 = raw_send(0, 54, <<"lo ">>, N2),
    N4 = raw_send(0, 51, <<"world">>, N3),
    N5 = raw_send(0, 52, <<1, 2>>, N4),
    N6 = raw_send(0, 53, <<3>>, N5),
    N7 = wait(
        fun(X) -> length(msgs(b, X)) =:= 2 andalso lists:keymember(message, 1, ?NET:events(a, X)) end, N6
    ),
    ?assertEqual([{0, text, <<"hello world">>}, {0, binary, <<1, 2, 3>>}], msgs(b, N7)),
    %% The ACK went back on the same stream with PPID 50.
    ?assertMatch([{message, 0, 50, <<2>>}], [E || {message, _, _, _} = E <- ?NET:events(a, N7)]).

wrong_parity_open_test() ->
    %% b is the DTLS server: a client peer must use even ids.
    N0 = raw_pair(),
    N1 = raw_send(1, 50, ?D:encode(open_label(<<"odd">>)), N0),
    N2 = wait(fun(X) -> lists:member({stream_reset, [1]}, ?NET:events(a, X)) end, N1),
    ?assertEqual([], evs(b, N2)),
    ?assertEqual([], [E || {message, _, 50, _} = E <- ?NET:events(a, N2)]).

data_on_unused_stream_test() ->
    N0 = raw_pair(),
    N1 = raw_send(4, 53, <<"stray">>, N0),
    N2 = wait(fun(X) -> lists:member({stream_reset, [4]}, ?NET:events(a, X)) end, N1),
    ?assertEqual([], evs(b, N2)).

unknown_ppid_closes_test() ->
    N0 = raw_pair(),
    N1 = raw_send(0, 50, ?D:encode(open_label(<<"u">>)), N0),
    N2 = raw_send(0, 99, <<"?">>, N1),
    N3 = wait(fun(X) -> lists:member({stream_reset, [0]}, ?NET:events(a, X)) end, N2),
    ?assertMatch([{channel_open, 0, <<"u">>, _, _}], evs(b, N3)),
    %% The raw peer completes the close from its side.
    N4 = ?NET:call(a, fun(E, Now) -> ?S:reset_streams([0], Now, E) end, N3),
    N5 = wait(has(b, {channel_closed, 0}), N4),
    ?assertEqual(#{}, ?D:channels(?NET:engine(b, N5))).

duplicate_open_test() ->
    N0 = raw_pair(),
    N1 = raw_send(0, 50, ?D:encode(open_label(<<"one">>)), N0),
    N2 = raw_send(0, 50, ?D:encode(open_label(<<"two">>)), N1),
    N3 = wait(fun(X) -> lists:member({stream_reset, [0]}, ?NET:events(a, X)) end, N2),
    ?assertMatch([{channel_open, 0, <<"one">>, _, _}], evs(b, N3)).

bad_options_test() ->
    ?assertError({badarg, role}, ?D:new(#{})),
    ?assertError({badarg, max_message_size}, ?D:new(#{role => client, max_message_size => -1})),
    D = ?D:new(opts(client, 1)),
    ?assertEqual({error, badarg}, ?D:open_channel(<<"x">>, #{priority => 70000}, 0, D)),
    ?assertEqual({error, unknown_channel}, ?D:send(3, text, <<"x">>, 0, D)),
    ?assertEqual({error, unknown_channel}, ?D:close_channel(3, 0, D)).
