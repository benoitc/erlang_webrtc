%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Control experiment for the interop harness: two instances of the
%% same independent implementation talk through the Erlang controller.
%% If this suite fails, interop failures elsewhere are harness bugs.
-module(webrtc_harness_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_group/2, end_per_group/2, init_per_testcase/2, end_per_testcase/2]).
-export([pion_to_pion_datachannel/1, pion_to_pion_media/1, pion_to_aiortc_datachannel/1,
         browser_to_pion_datachannel/1, browser_to_browser_media/1]).

all() -> [pion_to_pion_datachannel, pion_to_pion_media, pion_to_aiortc_datachannel,
          {group, chromium}, {group, firefox}].

groups() ->
    Cases = [browser_to_pion_datachannel, browser_to_browser_media],
    [{chromium, [], Cases}, {firefox, [], Cases}].

init_per_group(B, Config) ->
    case webrtc_interop_peer:probe(B, ?config(priv_dir, Config)) of
        ok -> [{browser, B} | Config];
        {skip, R} -> {skip, R}
    end.

end_per_group(_, _) -> ok.

init_per_testcase(TC, Config) ->
    Needed = case TC of pion_to_aiortc_datachannel -> [pion, aiortc]; _ -> [pion] end,
    case [R || N <- Needed, {skip, R} <- [webrtc_interop_peer:find(N)]] of
        [] -> Config;
        [R | _] -> {skip, R}
    end.

end_per_testcase(_TC, _Config) ->
    ok.

%% Relay descriptions and candidates between two peers until both are
%% connected.
connect(A0, B0, InitA, InitB) ->
    A1 = webrtc_interop_peer:cmd(A0, InitA#{cmd => init}),
    B1 = webrtc_interop_peer:cmd(B0, InitB#{cmd => init}),
    A2 = webrtc_interop_peer:cmd(A1, #{cmd => create_offer}),
    {ok, A3, Offer} = webrtc_interop_peer:wait_event(A2, <<"local_description">>, #{}),
    B2 = webrtc_interop_peer:cmd(B1, #{cmd => remote_description, type => offer,
                                       sdp => maps:get(<<"sdp">>, Offer)}),
    {ok, B3, Answer} = webrtc_interop_peer:wait_event(B2, <<"local_description">>, #{}),
    A4 = webrtc_interop_peer:cmd(A3, #{cmd => remote_description, type => answer,
                                       sdp => maps:get(<<"sdp">>, Answer)}),
    webrtc_interop_peer:pump(A4, B3, fun(Ev) ->
        lists:member(#{<<"event">> => <<"connection_state">>, <<"state">> => <<"connected">>}, Ev)
    end, 20000).

pion_to_pion_datachannel(Config) ->
    Dir = ?config(priv_dir, Config),
    {ok, A} = webrtc_interop_peer:start(pion, filename:join(Dir, "a")),
    {ok, B} = webrtc_interop_peer:start(pion, filename:join(Dir, "b")),
    {A1, B1} = connect(A, B, #{channels => [#{label => <<"chat">>}]}, #{}),
    {ok, A2, _} = webrtc_interop_peer:wait_event(A1, <<"channel_open">>, #{<<"label">> => <<"chat">>}),
    A3 = webrtc_interop_peer:cmd(A2, #{cmd => send, label => <<"chat">>, data => <<"hi">>}),
    {ok, B2, _} = webrtc_interop_peer:wait_event(B1, <<"message">>, #{<<"data">> => <<"hi">>}),
    {ok, A4, _} = webrtc_interop_peer:wait_event(A3, <<"message">>, #{<<"data">> => <<"echo:hi">>}),
    webrtc_interop_peer:stop(A4),
    webrtc_interop_peer:stop(B2).

pion_to_pion_media(Config) ->
    %% Pion only echoes media it receives, so with two Pion peers no
    %% RTP flows; this checks that tracks negotiate.
    Dir = ?config(priv_dir, Config),
    {ok, A} = webrtc_interop_peer:start(pion, filename:join(Dir, "a")),
    {ok, B} = webrtc_interop_peer:start(pion, filename:join(Dir, "b")),
    {A1, B1} = connect(A, B, #{media => [<<"audio">>, <<"video">>]}, #{media => [<<"audio">>, <<"video">>]}),
    webrtc_interop_peer:stop(A1),
    webrtc_interop_peer:stop(B1).

pion_to_aiortc_datachannel(Config) ->
    Dir = ?config(priv_dir, Config),
    {ok, A} = webrtc_interop_peer:start(pion, filename:join(Dir, "a")),
    {ok, B} = webrtc_interop_peer:start(aiortc, filename:join(Dir, "b")),
    {A1, B1} = connect(A, B, #{channels => [#{label => <<"chat">>}]}, #{}),
    {ok, A2, _} = webrtc_interop_peer:wait_event(A1, <<"channel_open">>, #{<<"label">> => <<"chat">>}),
    A3 = webrtc_interop_peer:cmd(A2, #{cmd => send, label => <<"chat">>, data => <<"hi">>}),
    {ok, B2, _} = webrtc_interop_peer:wait_event(B1, <<"message">>, #{<<"data">> => <<"hi">>}),
    {ok, A4, _} = webrtc_interop_peer:wait_event(A3, <<"message">>, #{<<"data">> => <<"echo:hi">>}),
    webrtc_interop_peer:stop(A4),
    webrtc_interop_peer:stop(B2).

browser_to_pion_datachannel(Config) ->
    Dir = ?config(priv_dir, Config),
    {ok, A} = webrtc_interop_peer:start(?config(browser, Config), filename:join(Dir, "a")),
    {ok, B} = webrtc_interop_peer:start(pion, filename:join(Dir, "b")),
    {A1, B1} = connect(A, B, #{channels => [#{label => <<"chat">>}]}, #{}),
    {ok, A2, _} = webrtc_interop_peer:wait_event(A1, <<"channel_open">>, #{<<"label">> => <<"chat">>}),
    A3 = webrtc_interop_peer:cmd(A2, #{cmd => send, label => <<"chat">>, data => <<"hi">>}),
    {ok, B2, _} = webrtc_interop_peer:wait_event(B1, <<"message">>, #{<<"data">> => <<"hi">>}),
    {ok, A4, _} = webrtc_interop_peer:wait_event(A3, <<"message">>, #{<<"data">> => <<"echo:hi">>}),
    webrtc_interop_peer:stop(A4),
    webrtc_interop_peer:stop(B2).

%% Two browsers send fake camera/microphone media to each other and
%% both report decoded frames: validates the adapter's media reporting.
browser_to_browser_media(Config) ->
    Dir = ?config(priv_dir, Config),
    B = ?config(browser, Config),
    {ok, P1} = webrtc_interop_peer:start(B, filename:join(Dir, "a")),
    {ok, P2} = webrtc_interop_peer:start(B, filename:join(Dir, "b")),
    Media = #{media => [<<"audio">>, <<"video">>]},
    {Q1, Q2} = connect(P1, P2, Media, Media),
    Frames = fun(#{<<"event">> := <<"rtp">>, <<"kind">> := <<"video">>, <<"count">> := N}) -> N >= 10;
                (_) -> false end,
    {ok, R1, _} = webrtc_interop_peer:wait(Q1, Frames, 20000),
    {ok, R2, _} = webrtc_interop_peer:wait(Q2, Frames, 20000),
    webrtc_interop_peer:stop(R1),
    webrtc_interop_peer:stop(R2).
