%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private Owner of the `webrtc_transports' table: rows
%% `{PeerConnection, Transport}' and `{{PeerConnection, Key}, Transport}'
%% that let the API reach a transport without a call to its peer
%% connection. Reads go straight to the table. Every peer connection
%% that writes a row is monitored, and its rows go when it ends, however
%% it ends: `terminate/2' does not run after `kill'.
-module(webrtc_registry).
-behaviour(gen_server).

-export([start_link/0, insert/2, delete/1, lookup/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(TAB, webrtc_transports).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Store the rows of `Pc' and have them removed when it ends.
-spec insert(pid(), [{term(), pid()}]) -> ok.
insert(Pc, Rows) ->
    true = ets:insert(?TAB, Rows),
    gen_server:cast(?MODULE, {watch, Pc}).

%% @doc Remove every row of `Pc'.
-spec delete(pid()) -> ok.
delete(Pc) ->
    true = ets:delete(?TAB, Pc),
    true = ets:match_delete(?TAB, {{Pc, '_'}, '_'}),
    ok.

%% @doc The transport of `Key', when the row exists and the transport is
%% alive; a row naming a dead transport is removed.
-spec lookup(term()) -> {ok, pid()} | error.
lookup(Key) ->
    %% No table on a node where the application does not run: the
    %% caller then asks the peer connection.
    try ets:lookup(?TAB, Key) of
        Rows -> found(Key, Rows)
    catch
        error:badarg -> error
    end.

found(Key, Rows) ->
    case Rows of
        [{_, T}] ->
            case node(T) =/= node() orelse is_process_alive(T) of
                true -> {ok, T};
                false -> true = ets:delete_object(?TAB, {Key, T}), error
            end;
        [] ->
            error
    end.

init([]) ->
    ?TAB = ets:new(?TAB, [set, public, named_table, {read_concurrency, true}]),
    {ok, #{}}.

handle_call(_, _From, Watched) ->
    {reply, {error, badarg}, Watched}.

handle_cast({watch, Pc}, Watched) when is_map_key(Pc, Watched) ->
    {noreply, Watched};
handle_cast({watch, Pc}, Watched) ->
    {noreply, Watched#{Pc => monitor(process, Pc)}};
handle_cast(_, Watched) ->
    {noreply, Watched}.

handle_info({'DOWN', _, process, Pc, _}, Watched) ->
    ok = delete(Pc),
    {noreply, maps:remove(Pc, Watched)};
handle_info(_, Watched) ->
    {noreply, Watched}.
