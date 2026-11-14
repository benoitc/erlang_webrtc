%% @doc Controller side of the interop peer protocol (interop/PROTOCOL.md).
%% Starts an adapter as a port, sends commands, waits for events.
-module(webrtc_interop_peer).

-export([start/2, cmd/2, wait/3, wait_event/3, events/1, stop/1, find/1, pump/4, probe/2]).

-record(peer, {port, name, buf = <<>>, events = [], log, forwarded = 0}).

%% @doc Locate an adapter executable. Returns `{ok, Cmd}' or
%% `{skip, Reason}' so suites report missing peers as skipped.
-spec find(pion | aiortc | chromium | firefox | webkit) -> {ok, string()} | {skip, string()}.
find(pion) ->
    Bin = filename:join([root(), "interop", "pion", "bin", "pion-peer"]),
    case filelib:is_regular(Bin) of
        true -> {ok, Bin};
        false -> {skip, "pion adapter not built: run make -C interop pion"}
    end;
find(aiortc) ->
    Py = filename:join([root(), "interop", "aiortc", ".venv", "bin", "python"]),
    Script = filename:join([root(), "interop", "aiortc", "peer.py"]),
    case filelib:is_regular(Py) of
        true -> {ok, Py ++ " -I " ++ Script};
        false -> {skip, "aiortc venv missing: run make -C interop aiortc"}
    end;
find(Browser) when Browser =:= chromium; Browser =:= firefox; Browser =:= webkit ->
    Dir = filename:join([root(), "interop", "browser"]),
    Node = os:find_executable("node"),
    case Node =/= false andalso filelib:is_dir(filename:join(Dir, "node_modules/playwright")) of
        true -> {ok, Node ++ " " ++ filename:join(Dir, "peer.js") ++ " " ++ atom_to_list(Browser)};
        false -> {skip, "playwright missing: run npm ci in interop/browser"}
    end.

root() ->
    {ok, Cwd} = file:get_cwd(),
    up_to_root(Cwd).

up_to_root("/") -> error(no_project_root);
up_to_root(Dir) ->
    case filelib:is_regular(filename:join(Dir, "rebar.config")) andalso
         filelib:is_dir(filename:join(Dir, "interop")) of
        true -> Dir;
        false -> up_to_root(filename:dirname(Dir))
    end.

start(Name, LogDir) ->
    {ok, Cmd} = find(Name),
    Log = filename:join(LogDir, atom_to_list(Name) ++ "_peer.log"),
    ok = filelib:ensure_dir(Log),
    Wrapped = Cmd ++ " 2>>" ++ Log,
    Port = open_port({spawn, Wrapped}, [binary, {line, 1 bsl 20}, exit_status, use_stdio]),
    P = #peer{port = Port, name = Name, log = Log},
    P1 = case wait(P, fun(#{<<"event">> := E}) -> E =:= <<"ready">> orelse E =:= <<"error">>; (_) -> false end, 30000) of
        {ok, Ready, #{<<"event">> := <<"ready">>}} -> Ready;
        {ok, _, #{<<"message">> := Msg}} -> error({peer_start_failed, Name, Msg});
        {error, _, R} -> error({peer_start_failed, Name, R})
    end,
    {ok, P1}.

cmd(#peer{port = Port} = P, Map) ->
    true = port_command(Port, [json:encode(Map), $\n]),
    P.

%% @doc Wait until an event satisfies Pred. Returns the peer with every
%% event seen so far recorded, and the matching event.
wait(#peer{} = P, Pred, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    case lists:search(Pred, lists:reverse(P#peer.events)) of
        {value, E} -> {ok, P, E};
        false -> wait_loop(P, Pred, Deadline)
    end.

wait_loop(#peer{port = Port} = P, Pred, Deadline) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {Port, {data, {eol, Line}}} ->
            Line1 = <<(P#peer.buf)/binary, Line/binary>>,
            Ev = json:decode(Line1),
            P1 = P#peer{buf = <<>>, events = [Ev | P#peer.events]},
            case Pred(Ev) of
                true -> {ok, P1, Ev};
                false -> wait_loop(P1, Pred, Deadline)
            end;
        {Port, {data, {noeol, Part}}} ->
            wait_loop(P#peer{buf = <<(P#peer.buf)/binary, Part/binary>>}, Pred, Deadline);
        {Port, {exit_status, S}} ->
            {error, P, {peer_exited, S}}
    after Left ->
        {error, P, timeout}
    end.

%% @doc Wait for an event of the given name whose fields include Fields.
wait_event(P, Name, Fields) when is_map(Fields) ->
    wait(P, fun(E) ->
        maps:get(<<"event">>, E, undefined) =:= Name andalso
            maps:fold(fun(K, V, Acc) -> Acc andalso maps:get(K, E, undefined) =:= V end, true, Fields)
    end, 15000).

events(#peer{events = E}) -> lists:reverse(E).

stop(#peer{port = Port} = P) ->
    try cmd(P, #{cmd => close}) catch error:badarg -> ok end,
    receive
        {Port, {exit_status, _}} -> ok
    after 2000 ->
        try port_close(Port) catch error:badarg -> ok end,
        ok
    end.

%% @doc Forward trickled candidates between two adapters until Done is
%% true for the event lists of both, or Timeout.
pump(A, B, Done, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    pump_loop(A, B, Done, Deadline).

pump_loop(A0, B0, Done, Deadline) ->
    {A1, B1} = forward(A0, B0),
    {B2, A2} = forward(B1, A1),
    case Done(events(A2)) andalso Done(events(B2)) of
        true ->
            {A2, B2};
        false ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> error({pump_timeout, events(A2), events(B2)});
                false -> pump_loop(drain(A2), drain(B2), Done, Deadline)
            end
    end.

drain(P) ->
    case wait_loop(P, fun(_) -> false end, erlang:monotonic_time(millisecond) + 50) of
        {error, P1, timeout} -> P1;
        {error, P1, Other} -> error({peer_failed, P1#peer.name, Other})
    end.

forward(#peer{forwarded = N} = From, To) ->
    Cands = [E || E = #{<<"event">> := <<"local_candidate">>} <- events(From)],
    New = lists:nthtail(N, Cands),
    To1 = lists:foldl(fun(C, T) ->
        cmd(T, #{cmd => remote_candidate, candidate => maps:get(<<"candidate">>, C),
                 mid => maps:get(<<"mid">>, C)})
    end, To, New),
    {From#peer{forwarded = length(Cands)}, To1}.

%% @doc Check that an adapter is installed and starts. Suites call this
%% in init_per_group so an unavailable peer is reported as skipped with
%% the reason, never counted as passed.
-spec probe(atom(), file:filename()) -> ok | {skip, string()}.
probe(Name, LogDir) ->
    case find(Name) of
        {skip, _} = Skip ->
            Skip;
        {ok, _} ->
            try start(Name, filename:join(LogDir, "probe")) of
                {ok, P} -> stop(P), ok
            catch
                error:{peer_start_failed, _, Why} ->
                    {skip, lists:flatten(io_lib:format("~p failed to start: ~ts", [Name, short(Why)]))}
            end
    end.

short(B) when is_binary(B) -> string:slice(B, 0, 200);
short(T) -> io_lib:format("~p", [T]).
