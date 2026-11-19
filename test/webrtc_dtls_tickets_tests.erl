%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% The DTLS 1.3 ticket table: its key lives and dies with it, and it
%% holds at most 10,000 entries (RFC 8446 §8).
-module(webrtc_dtls_tickets_tests).
-include_lib("eunit/include/eunit.hrl").

-define(T, webrtc_dtls_tickets).
-define(MAX, 10000).

fresh() ->
    drop(),
    ok = ?T:ensure().

drop() ->
    case ets:whereis(?T) of
        undefined -> ok;
        _ -> true = ets:delete(?T), ok
    end.

%% Each test leaves no table behind for the next module.
tickets_test_() ->
    {foreach, fun fresh/0, fun(_) -> drop() end,
     [fun restart/0, fun first_use/0, fun capacity/0, fun expired_room/0, fun client_eviction/0]}.

restart() ->
    Ticket = ?T:seal(secret),
    ?assertEqual({ok, secret}, ?T:open(Ticket)),
    %% The application restarts: a new table, a new key.
    fresh(),
    ?assertEqual(error, ?T:open(Ticket)),
    ?assertEqual({ok, again}, ?T:open(?T:seal(again))).

first_use() ->
    Later = erlang:system_time(millisecond) + 60000,
    ?assert(?T:first_use(<<"a">>, Later)),
    ?assertNot(?T:first_use(<<"a">>, Later)).

%% Full of unexpired replay entries: early data is refused rather than
%% an entry forgotten, and the table does not grow.
capacity() ->
    Later = erlang:system_time(millisecond) + 60000,
    [true = ?T:first_use(<<I:32>>, Later) || I <- lists:seq(1, ?MAX)],
    Size = ets:info(?T, size),
    ?assertNot(?T:first_use(<<"new">>, Later)),
    ?assertEqual(Size, ets:info(?T, size)),
    %% The replay entries stay: a used ticket is still refused.
    ?assertNot(?T:first_use(<<1:32>>, Later)).

%% Expired entries make room again.
expired_room() ->
    Past = erlang:system_time(millisecond) - 1,
    [true = ?T:first_use(<<I:32>>, Past) || I <- lists:seq(1, ?MAX)],
    ?assert(?T:first_use(<<"new">>, Past + 60000)),
    ?assert(ets:info(?T, size) < 100).

%% A full table takes a new client ticket in place of the oldest.
client_eviction() ->
    Later = erlang:system_time(millisecond) + 60000,
    Now = erlang:system_time(millisecond),
    ok = ?T:put_client(old, #{received => Now - 1000, lifetime => 3600}),
    [true = ?T:first_use(<<I:32>>, Later) || I <- lists:seq(1, ?MAX - 1)],
    Size = ets:info(?T, size),
    ok = ?T:put_client(new, #{received => Now, lifetime => 3600}),
    ?assertEqual(Size, ets:info(?T, size)),
    ?assertEqual(error, ?T:take_client(old)),
    ?assertMatch({ok, _}, ?T:take_client(new)).
