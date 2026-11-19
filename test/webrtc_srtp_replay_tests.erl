%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Boundary tests for the SRTP replay window (RFC 3711 §3.3.2).
-module(webrtc_srtp_replay_tests).
-include_lib("eunit/include/eunit.hrl").

-define(R, webrtc_srtp_replay).

min_size_test() ->
    ?assertError(badarg, ?R:new(63)),
    ?assertError(badarg, ?R:new(0)),
    ?assertEqual(64, ?R:window_size(?R:new(64))).

empty_window_accepts_anything_test() ->
    W = ?R:new(64),
    ?assertEqual(-1, ?R:top(W)),
    ?assertEqual(ok, ?R:check(0, W)),
    ?assertEqual(ok, ?R:check(1 bsl 47, W)).

check_does_not_modify_test() ->
    W = ?R:update(10, ?R:new(64)),
    ok = ?R:check(11, W),
    ?assertEqual(ok, ?R:check(11, W)),
    ?assertEqual(10, ?R:top(W)).

replay_test() ->
    W = ?R:update(100, ?R:new(64)),
    ?assertEqual({error, replay}, ?R:check(100, W)),
    ?assertEqual(ok, ?R:check(99, W)),
    W2 = ?R:update(99, W),
    ?assertEqual({error, replay}, ?R:check(99, W2)),
    ?assertEqual(100, ?R:top(W2)).

%% Top - (Size - 1) is the oldest index still inside the window.
window_edge_test() ->
    W = ?R:update(100, ?R:new(64)),
    ?assertEqual(ok, ?R:check(37, W)),
    ?assertEqual({error, too_old}, ?R:check(36, W)),
    ?assertEqual({error, too_old}, ?R:check(0, W)),
    W2 = ?R:update(37, W),
    ?assertEqual({error, replay}, ?R:check(37, W2)).

shift_by_window_size_clears_test() ->
    W = ?R:update(100, ?R:new(64)),
    %% Moving exactly Size ahead drops 100 out of the window.
    W2 = ?R:update(164, W),
    ?assertEqual({error, too_old}, ?R:check(100, W2)),
    ?assertEqual(ok, ?R:check(101, W2)),
    %% Moving far ahead keeps only the new top.
    W3 = ?R:update(100000, W2),
    ?assertEqual({error, replay}, ?R:check(100000, W3)),
    ?assertEqual(ok, ?R:check(99999, W3)),
    ?assertEqual({error, too_old}, ?R:check(100000 - 64, W3)).

shift_keeps_history_test() ->
    W0 = lists:foldl(fun(I, W) -> ?R:update(I, W) end, ?R:new(64), [1, 3, 5]),
    W = ?R:update(40, W0),
    [?assertEqual({error, replay}, ?R:check(I, W)) || I <- [1, 3, 5, 40]],
    [?assertEqual(ok, ?R:check(I, W)) || I <- [2, 4, 6, 39]],
    %% 1 is 63 behind 64, still in the window; 0 is 64 behind.
    W2 = ?R:update(64, W),
    ?assertEqual({error, replay}, ?R:check(1, W2)),
    ?assertEqual({error, too_old}, ?R:check(0, W2)),
    W3 = ?R:update(65, W2),
    ?assertEqual({error, too_old}, ?R:check(1, W3)),
    ?assertEqual({error, replay}, ?R:check(3, W3)).

large_window_test() ->
    W = ?R:update(5000, ?R:new(1024)),
    ?assertEqual(ok, ?R:check(5000 - 1023, W)),
    ?assertEqual({error, too_old}, ?R:check(5000 - 1024, W)),
    All = lists:foldl(fun(I, Acc) -> ?R:update(I, Acc) end, W, lists:seq(3977, 4999)),
    ?assert(lists:all(fun(I) -> ?R:check(I, All) =:= {error, replay} end, lists:seq(3977, 5000))),
    ?assertEqual(ok, ?R:check(5001, All)).

%% Random sequences against a reference set model.
model_test() ->
    rand:seed(exsss, {1, 2, 3}),
    Size = 64,
    {_, _} = lists:foldl(
        fun(_, {W, Seen}) ->
            Top = ?R:top(W),
            I = max(0, Top + rand:uniform(80) - 70),
            Expected =
                if
                    I > Top ->
                        ok;
                    Top - I >= Size ->
                        {error, too_old};
                    true ->
                        case sets:is_element(I, Seen) of
                            true -> {error, replay};
                            false -> ok
                        end
                end,
            ?assertEqual(Expected, ?R:check(I, W)),
            case Expected of
                ok -> {?R:update(I, W), sets:add_element(I, Seen)};
                _ -> {W, Seen}
            end
        end,
        {?R:new(Size), sets:new()},
        lists:seq(1, 5000)
    ).
