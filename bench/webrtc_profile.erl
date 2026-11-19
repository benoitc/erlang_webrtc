%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Profiling of a peer connection: where connection setup time goes,
%% raw RTP send capacity, and tprof call time and allocation profiles of
%% the data channel, RTP and handshake paths. Run with `make profile'.
%%
%% The relayed setup uses the pion/turn interop server
%% (interop/turn/bin/turn-server, built by `make -C interop turn'); it is
%% skipped when the binary is missing.
-module(webrtc_profile).

-export([run/0, run/1, setup/2, rtp_capacity/1, profile/2]).

-define(S, webrtc_test_signal).

run() ->
    run(#{}).

%% Options: `runs' (setup samples, default 15), `top' (profile rows,
%% default 20), `profiles' (default true).
run(Opts) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Runs = maps:get(runs, Opts, 15),
    io:format("== Connection setup: median ms from create_offer, ~p runs ==~n", [Runs]),
    setup(direct, Runs),
    case turn_server() of
        {ok, Turn, Port} ->
            setup({relay, Turn}, Runs),
            true = port_close(Port);
        {skip, Why} ->
            io:format("relayed: skipped (~s)~n", [Why])
    end,
    io:format("~n== RTP send capacity ==~n"),
    rtp_capacity(50000),
    case maps:get(profiles, Opts, true) of
        true ->
            Top = maps:get(top, Opts, 20),
            io:format("~n== Profiles (tprof, webrtc modules and the calls they make) ==~n"),
            profile(data_channel, fun() -> data(8 * 1024 * 1024) end, Top),
            profile(rtp, fun() -> rtp(10000) end, Top),
            profile(handshake, fun() -> [handshake() || _ <- lists:seq(1, 5)] end, Top);
        false ->
            ok
    end,
    ok.

%%--------------------------------------------------------------------
%% Connection setup timeline
%%--------------------------------------------------------------------

%% First occurrence of every event on each side, median over N runs.
setup(Mode, N) ->
    Samples = [setup_once(Mode) || _ <- lists:seq(1, N)],
    Keys = lists:usort(lists:append([maps:keys(S) || S <- Samples])),
    Rows = lists:keysort(2, [{K, median([maps:get(K, S) || S <- Samples, is_map_key(K, S)])} || K <- Keys]),
    io:format("~p:~n", [case Mode of direct -> direct; {relay, _} -> one_side_relayed end]),
    [io:format("  ~-42s ~8.1f~n", [label(K), V]) || {K, V} <- Rows],
    ok.

setup_once(Mode) ->
    {ok, A} = webrtc:new_peer_connection(setup_opts(Mode)),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"p">>, #{}),
    T0 = erlang:monotonic_time(microsecond),
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    ok = webrtc:set_remote_description(B, offer, Offer),
    {ok, Answer} = webrtc:create_answer(B, #{}),
    ok = webrtc:set_local_description(B, answer, Answer),
    ok = webrtc:set_remote_description(A, answer, Answer),
    Sdp = (erlang:monotonic_time(microsecond) - T0) / 1000,
    Ev = timeline(A, B, T0, #{{a, sdp_exchanged} => Sdp}),
    close(A, B),
    Ev.

%% One side reaches only the TURN server, the other is on loopback.
setup_opts(direct) ->
    #{loopback => true};
setup_opts({relay, Turn}) ->
    #{
        loopback => true,
        turn_servers => [#{address => Turn, username => <<"bench">>, password => <<"bench">>}],
        outbound_filter => {fun(Dest, Bin, S) when Dest =:= Turn -> {[{0, Bin}], S};
                               (_, _, S) -> {[], S} end, undefined}
    }.

timeline(A, B, T0, Acc) ->
    case is_map_key({a, datachannel_open}, Acc) andalso is_map_key({b, datachannel_open}, Acc) of
        true ->
            Acc;
        false ->
            receive
                {webrtc, P, Ev} when P =:= A; P =:= B ->
                    {Side, Peer} = case P of A -> {a, B}; B -> {b, A} end,
                    case Ev of
                        {ice_candidate, C, _} -> _ = webrtc:add_ice_candidate(Peer, C);
                        _ -> ok
                    end,
                    K = {Side, event_key(Ev)},
                    T = (erlang:monotonic_time(microsecond) - T0) / 1000,
                    timeline(A, B, T0, maps:put(K, maps:get(K, Acc, T), Acc))
            after 15000 ->
                Acc#{timeout => 15000.0}
            end
    end.

event_key({ice_candidate, end_of_candidates, _}) -> end_of_candidates;
event_key({ice_candidate, C, _}) ->
    case binary:match(C, <<"typ relay">>) of
        nomatch -> first_candidate;
        _ -> relay_candidate
    end;
event_key({K, V}) when K =:= connection_state; K =:= ice_connection_state; K =:= ice_gathering_state -> {K, V};
event_key(Ev) when is_tuple(Ev) -> element(1, Ev);
event_key(Ev) -> Ev.

label({Side, K}) -> lists:flatten(io_lib:format("~p ~p", [Side, K]));
label(K) -> lists:flatten(io_lib:format("~p", [K])).

median(L) -> lists:nth((length(L) + 1) div 2, lists:sort(L)).

%%--------------------------------------------------------------------
%% Workloads
%%--------------------------------------------------------------------

%% send_rtp as fast as the caller can, pacing off: the cost of one call
%% and the packet rate one transport sustains.
rtp_capacity(N) ->
    {A, B} = media_pair(#{congestion_control => #{pacing => false}}),
    Payload = crypto:strong_rand_bytes(1100),
    T0 = erlang:monotonic_time(microsecond),
    [ok = webrtc:send_rtp(A, <<"0">>, Payload, #{timestamp => I * 3000}) || I <- lists:seq(1, N)],
    Us = erlang:monotonic_time(microsecond) - T0,
    Got = count_rtp(B, 0),
    io:format("send_rtp, 1100 byte payloads: ~.1f us per call, ~b packets/s (~.1f Mbps), received ~p of ~p~n",
              [Us / N, round(N / (Us / 1.0e6)), N * 1100 * 8 / Us, Got, N]),
    close(A, B).

data(Bytes) ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"bulk">>, #{}),
    ?S:connect(A, B),
    Id = open_id(A),
    _ = open_id(B),
    Msg = crypto:strong_rand_bytes(16384),
    N = Bytes div 16384,
    Self = self(),
    _ = spawn_link(fun() -> [send_retry(A, Id, Msg) || _ <- lists:seq(1, N)], Self ! sent end),
    ok = recv_n(B, N),
    receive sent -> ok end,
    close(A, B).

rtp(N) ->
    {A, B} = media_pair(#{}),
    Payload = crypto:strong_rand_bytes(1100),
    [ok = webrtc:send_rtp(A, <<"0">>, Payload, #{timestamp => I * 3000}) || I <- lists:seq(1, N)],
    _ = count_rtp(B, 0),
    close(A, B).

handshake() ->
    {ok, A} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    ok = webrtc:create_data_channel(A, <<"h">>, #{}),
    ?S:connect(A, B),
    _ = open_id(A),
    close(A, B).

media_pair(Opts) ->
    {ok, A} = webrtc:new_peer_connection(Opts#{loopback => true}),
    {ok, B} = webrtc:new_peer_connection(#{loopback => true}),
    {ok, _} = webrtc:add_transceiver(A, video, #{direction => sendonly}),
    ?S:connect(A, B),
    {A, B}.

open_id(Pc) ->
    {ok, {datachannel_open, Id, _, _, _}} =
        ?S:wait(Pc, fun({datachannel_open, _, _, _, _}) -> true; (_) -> false end, 15000),
    Id.

send_retry(Pc, Id, M) ->
    case webrtc:send_data(Pc, Id, binary, M) of
        ok -> ok;
        {error, buffer_full} -> timer:sleep(1), send_retry(Pc, Id, M)
    end.

recv_n(_B, 0) -> ok;
recv_n(B, N) ->
    receive
        {webrtc, B, {channel_message, _, _, _}} -> recv_n(B, N - 1)
    after 20000 -> {error, {missing, N}}
    end.

count_rtp(B, N) ->
    receive
        {webrtc, B, {rtp, _, _}} -> count_rtp(B, N + 1)
    after 1000 -> N
    end.

close(A, B) ->
    webrtc:close(A),
    webrtc:close(B),
    ?S:flush().

%%--------------------------------------------------------------------
%% tprof
%%--------------------------------------------------------------------

%% Call time and allocated words per function, for the webrtc modules
%% and the library calls they make, across every process.
profile(Name, Fun) ->
    profile(Name, Fun, 20).

profile(Name, Fun, Top) ->
    Mods = [M || {M, _} <- code:all_loaded(), lists:prefix("webrtc", atom_to_list(M))] ++
        [crypto, gen_udp, inet_udp, prim_inet, maps, lists, queue, gb_sets, erlang],
    lists:foreach(
        fun(Type) ->
            {ok, _} = tprof:start(#{type => Type}),
            [tprof:set_pattern(M, '_', '_') || M <- Mods],
            _ = tprof:enable_trace(all),
            Fun(),
            _ = tprof:disable_trace(all),
            Sample = tprof:collect(),
            ok = tprof:stop(),
            #{all := {Type, Total, Rows}} = tprof:inspect(Sample, total, measurement),
            Unit = case Type of call_time -> "us"; call_memory -> "words" end,
            io:format("~n-- ~p, ~p: ~b ~s in total --~n", [Name, Type, Total, Unit]),
            [io:format("  ~5.1f%  ~10b ~-5s ~9b calls  ~p:~p/~p~n", [Pct, Meas, Unit, Calls, M, F, A])
             || {M, {F, A}, Calls, Meas, _PerCall, Pct} <- lists:sublist(lists:reverse(lists:keysort(4, Rows)), Top)]
        end,
        [call_time, call_memory]
    ).

%%--------------------------------------------------------------------
%% TURN server
%%--------------------------------------------------------------------

turn_server() ->
    Bin = filename:absname("interop/turn/bin/turn-server"),
    case filelib:is_regular(Bin) of
        false ->
            {skip, "build it with make -C interop turn"};
        true ->
            Port = open_port({spawn_executable, Bin},
                             [{args, ["-listen", "127.0.0.1:0", "-user", "bench=bench"]}, binary, {line, 1024}]),
            receive
                {Port, {data, {eol, <<"listening ", Addr/binary>>}}} ->
                    [Ip, P] = string:split(Addr, ":", trailing),
                    {ok, IP} = inet:parse_address(binary_to_list(Ip)),
                    {ok, {IP, binary_to_integer(P)}, Port}
            after 5000 ->
                {skip, "TURN server did not start"}
            end
    end.
