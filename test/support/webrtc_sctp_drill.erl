%% Test-only interpreter for the packetdrill scripts of the ETSI SCTP
%% conformance tests (ETSI TS 102 369, test/sctp_etsi), run against the
%% sans-IO association webrtc_sctp_assoc on a fake clock.
%%
%% Supported: `> sctp:' (a packet the association must send) and
%% `< sctp:' (a packet to inject) lines with the chunks and parameters the
%% suite uses, `...' wildcards, `*' times, `--tolerance_usecs', `#ifdef'
%% blocks (one platform is chosen), and the socket calls connect, listen,
%% accept, close, shutdown, write, read, getsockopt SO_ERROR and the
%% SCTP_RTOINFO, SCTP_INITMSG and SCTP_PEER_ADDR_PARAMS options. Packets
%% are encoded and decoded here, independently of webrtc_sctp_chunk.
%%
%% As in packetdrill, the association's verification tag and TSNs are
%% bound on first sight (`tag=1', `tsn=0' in its INIT or INIT-ACK) and
%% translated afterwards; the peer's values are the script's.
-module(webrtc_sctp_drill).

-export([run/1, run/2, parse_file/2]).

-define(PORT, 5000).
-define(DEFAULT_TOLERANCE_US, 4000).

%%====================================================================
%% Entry points
%%====================================================================

%% @doc Run a script; `ok' or `{fail, Line, Reason}'.
run(File) -> run(File, #{}).

run(File, Opts) ->
    {Tol, Events} = parse_file(File, maps:get(platform, Opts, "FreeBSD")),
    St = #{
        tol => Tol,
        now => 0,
        last => 0,
        opts => maps:merge(#{mtu => 1480, random_seed => 7, cookie_secret => <<"drill">>,
                             local_port => ?PORT, remote_port => ?PORT, sack_delay => 200}, maps:get(engine, Opts, #{})),
        assoc => undefined,
        pending => [],
        messages => [],
        events => [],
        local_tag => undefined,
        peer_tag => 0,
        peer_tags => [],
        tsn_off => undefined,
        sut_cookie => undefined,
        peer_cookie => undefined,
        listening => false
    },
    try lists:foldl(fun step/2, St, Events) of
        _ -> ok
    catch
        throw:{fail, Line, Reason} -> {fail, Line, Reason}
    end.

%%====================================================================
%% Parsing
%%====================================================================

%% @doc {ToleranceUs, [{Line, Time, Event}]} of a script.
parse_file(File, Platform) ->
    {ok, Bin} = file:read_file(File),
    Lines = lists:enumerate(string:split(binary_to_list(Bin), "\n", all)),
    {Tol, Kept} = preprocess(Lines, Platform, ?DEFAULT_TOLERANCE_US, [], [true]),
    {Tol, [parse_line(N, L) || {N, L} <- Kept]}.

%% Comments, options, #ifdef blocks, and lines continued until their
%% brackets close.
preprocess([], _P, Tol, Acc, _Stack) ->
    {Tol, join(lists:reverse(Acc))};
preprocess([{N, L0} | Rest], P, Tol, Acc, Stack) ->
    L = string:trim(strip_comment(L0)),
    case L of
        "" -> preprocess(Rest, P, Tol, Acc, Stack);
        "--tolerance_usecs=" ++ V -> preprocess(Rest, P, list_to_integer(V), Acc, Stack);
        "--" ++ _ -> preprocess(Rest, P, Tol, Acc, Stack);
        "#ifdef " ++ Name -> preprocess(Rest, P, Tol, Acc, [hd(Stack) andalso string:trim(Name) =:= P | Stack]);
        "#ifndef " ++ Name -> preprocess(Rest, P, Tol, Acc, [hd(Stack) andalso string:trim(Name) =/= P | Stack]);
        "#else" ++ _ -> [Top, Parent | More] = Stack, preprocess(Rest, P, Tol, Acc, [Parent andalso not Top, Parent | More]);
        "#endif" ++ _ -> preprocess(Rest, P, Tol, Acc, tl(Stack));
        _ when hd(Stack) -> preprocess(Rest, P, Tol, [{N, L} | Acc], Stack);
        _ -> preprocess(Rest, P, Tol, Acc, Stack)
    end.

strip_comment(L) ->
    case string:find(L, "//") of
        nomatch -> L;
        Pos -> string:slice(L, 0, length(L) - length(Pos))
    end.

%% A line whose brackets do not balance continues on the next one.
join([]) -> [];
join([{N, L} | Rest]) -> join(N, L, Rest).

join(N, L, Rest) ->
    case depth(L) of
        0 when Rest =/= [] ->
            %% Bundled chunks: `;' ends a chunk that the next line follows.
            case lists:last(string:trim(L)) of
                $; -> [{_, L2} | Rest2] = Rest, join(N, L ++ " " ++ L2, Rest2);
                _ -> [{N, L} | join(Rest)]
            end;
        0 -> [{N, L} | join(Rest)];
        _ when Rest =:= [] -> [{N, L}];
        _ -> [{_, L2} | Rest2] = Rest, join(N, L ++ " " ++ L2, Rest2)
    end.

depth(L) ->
    lists:foldl(fun(C, D) when C =:= $[; C =:= ${; C =:= $( -> D + 1;
                   (C, D) when C =:= $]; C =:= $}; C =:= $) -> D - 1;
                   (_, D) -> D end, 0, L).

parse_line(N, L) ->
    {Time, Rest} = parse_time(L),
    Event =
        case string:trim(Rest) of
            "> sctp: " ++ Chunks -> {out, parse_chunks(N, Chunks)};
            "< sctp: " ++ Chunks -> {in, #{}, parse_chunks(N, Chunks)};
            "< sctp(" ++ More ->
                %% Packet options: tag=N (verification tag), bad_crc32c.
                {OptS, "): " ++ Chunks} = lists:splitwith(fun(C) -> C =/= $) end, More),
                Opts = maps:from_list([packet_opt(O) || O <- string:split(OptS, ",", all)]),
                case string:trim(Chunks) of
                    "[" ++ _ = Raw -> {in, Opts#{raw => raw_bytes(Raw)}, []};
                    _ -> {in, Opts, parse_chunks(N, Chunks)}
                end;
            "<" ++ _ = Addr -> {skip, {addresses, Addr}};
            "`" ++ _ = Shell -> {skip, {shell, Shell}};
            Call -> {call, parse_call(N, Call)}
        end,
    {N, Time, Event}.

packet_opt(O) ->
    case string:trim(O) of
        "tag=" ++ T -> {tag, list_to_integer(T)};
        "bad_crc32c" -> {bad_crc32c, true}
    end.

raw_bytes(S) ->
    {list, Bytes} = element(1, value(tokens(S))),
    list_to_binary(Bytes).

parse_time("`" ++ _ = S) -> {any, S};
parse_time("*" ++ Rest) -> {any, Rest};
parse_time("+" ++ Rest) -> {T, R} = number(Rest), {{rel, T}, R};
parse_time(L) -> {T, R} = number(L), {{abs, T}, R}.

number(S) ->
    {Num, Rest} = lists:splitwith(fun(C) -> (C >= $0 andalso C =< $9) orelse C =:= $. end, string:trim(S, leading)),
    F = case lists:member($., Num) of true -> list_to_float(fix_float(Num)); false -> float(list_to_integer(Num)) end,
    {round(F * 1000000), Rest}.

fix_float("." ++ _ = S) -> "0" ++ S;
fix_float(S) -> case lists:last(S) of $. -> S ++ "0"; _ -> S end.

%% Chunk lists: NAME[items], items: key=value, nested NAME[...], `...'.
parse_chunks(N, S) ->
    case items(tokens(S)) of
        {Items, []} -> Items;
        {_, Left} -> throw({fail, N, {parse, Left}})
    end.

tokens([]) -> [];
tokens([C | R]) when C =:= $\s; C =:= $\t -> tokens(R);
tokens("..." ++ R) -> [dots | tokens(R)];
tokens([$; | R]) -> [$, | tokens(R)];
tokens([C | R]) when C =:= $[; C =:= $]; C =:= $,; C =:= $=; C =:= $|; C =:= ${; C =:= $} -> [C | tokens(R)];
tokens([$" | R]) -> {Str, [$" | R1]} = lists:splitwith(fun(C) -> C =/= $" end, R), [{str, Str} | tokens(R1)];
tokens(S) ->
    {W, R} = lists:splitwith(fun(C) -> not lists:member(C, " \t[],=|{}\";") end, S),
    [{w, W} | tokens(R)].

items(Ts) -> items(Ts, []).

items([dots | R], Acc) -> sep(R, [dots | Acc]);
items([{w, K}, $= | R], Acc) -> {V, R1} = value(R), sep(R1, [{K, V} | Acc]);
items([{w, Name}, $[ | R], Acc) ->
    {Sub, [$] | R1]} = items(R, []),
    sep(R1, [{term, Name, Sub} | Acc]);
items(R, Acc) -> {lists:reverse(Acc), R}.

sep([$, | R], Acc) -> items(R, Acc);
sep(R, Acc) -> {lists:reverse(Acc), R}.

value([dots | R]) -> {any, R};
value([$[ | R]) -> list(R, []);
value([{str, S} | R]) -> {{str, S}, R};
value([{w, W}, $| | R]) -> {V2, R1} = value(R), {{'bor', W, V2}, R1};
value([{w, Name}, $[ | R]) -> {Sub, [$] | R1]} = items(R, []), {{term, Name, Sub}, R1};
value([{w, W} | R]) -> {word(W), R}.

list([$] | R], Acc) -> {{list, lists:reverse(Acc)}, R};
list([$, | R], Acc) -> list(R, Acc);
list([{w, Name}, $[ | R], Acc) -> {Sub, [$] | R1]} = items(R, []), list(R1, [{term, Name, Sub} | Acc]);
list([{w, K}, $= | R], Acc) -> {V, R1} = value(R), list(R1, [{K, V} | Acc]);
list([{w, W} | R], Acc) -> list(R, [word(W) | Acc]);
list([dots | R], Acc) -> list(R, [any | Acc]).

word("0x" ++ H) -> list_to_integer(H, 16);
word(W) ->
    case string:to_integer(W) of
        {I, ""} -> I;
        {I, ":" ++ J} -> {range, I, list_to_integer(J)};
        _ -> W
    end.

%% Socket calls: name, raw arguments, the return value and errno.
parse_call(N, S) ->
    {Name, "(" ++ Rest} = lists:splitwith(fun(C) -> C =/= $( end, S),
    {Args, After} = close_paren(Rest, 1, []),
    Ret =
        case string:trim(After) of
            "= " ++ R -> string:trim(R);
            "=" ++ R -> string:trim(R);
            _ -> throw({fail, N, {parse, S}})
        end,
    {Name, Args, Ret}.

close_paren([$) | R], 1, Acc) -> {lists:reverse(Acc), R};
close_paren([$) | R], D, Acc) -> close_paren(R, D - 1, [$) | Acc]);
close_paren([$( | R], D, Acc) -> close_paren(R, D + 1, [$( | Acc]);
close_paren([C | R], D, Acc) -> close_paren(R, D, [C | Acc]).

%%====================================================================
%% Running
%%====================================================================

step({N, Time, Event}, St0) ->
    T = event_time(Time, St0),
    case Event of
        {out, Chunks} ->
            expect_out(N, Time, T, Chunks, St0);
        {in, Opts, Chunks} ->
            St1 = quiet_until(N, T, St0),
            inject(N, Opts, Chunks, St1#{last := T});
        {skip, _} ->
            St0;
        {call, Call} ->
            St1 = quiet_until(N, T, St0),
            call(N, Call, St1#{last := T})
    end.

event_time({abs, T}, _St) -> T;
event_time({rel, D}, #{last := L}) -> L + D;
event_time(any, #{last := L}) -> L.

%% Run the clock to Us. Packets sent meanwhile wait for the next `>'
%% line, which checks their time (as packetdrill matches sent packets
%% only against outbound lines).
quiet_until(_N, Us, St) ->
    advance(Us, St).

%% Fire timers up to Us (milliseconds for the engine).
advance(Us, #{assoc := undefined} = St) ->
    St#{now := max(maps:get(now, St), Us)};
advance(Us, #{assoc := A} = St) ->
    case webrtc_sctp_assoc:next_timeout(A) of
        At when At =/= infinity, At * 1000 =< Us ->
            {A1, Acts} = webrtc_sctp_assoc:handle_timeout(At, A),
            advance(Us, actions(At * 1000, Acts, St#{assoc := A1, now := max(maps:get(now, St), At * 1000)}));
        _ ->
            St#{now := max(maps:get(now, St), Us)}
    end.

actions(T, Acts, St) ->
    lists:foldl(
        fun({send, Bin}, S) -> S#{pending := maps:get(pending, S) ++ [{T, Bin}]};
           ({event, {message, _Sid, _Ppid, Data}}, S) -> S#{messages := maps:get(messages, S) ++ [Data]};
           ({event, E}, S) -> S#{events := maps:get(events, S) ++ [E]}
        end, St, Acts).

%% The next packet the association sends must match, at the scripted
%% time within the tolerance (`*': any time).
expect_out(N, Time, T, Chunks, St0) ->
    Tol = maps:get(tol, St0),
    Limit = case Time of any -> T + 600000000; _ -> T + Tol end,
    St = next_packet(Limit, St0),
    case maps:get(pending, St) of
        [] ->
            throw({fail, N, {missing_packet, Chunks}});
        [{At, Bin} | Rest] ->
            Time =:= any orelse abs(At - T) =< Tol orelse
                throw({fail, N, {late_or_early, At - T, describe(Bin)}}),
            St1 = match_packet(N, Bin, Chunks, St#{pending := Rest}),
            St1#{last := case Time of any -> At; _ -> T end}
    end.

next_packet(_Limit, #{pending := [_ | _]} = St) ->
    St;
next_packet(_Limit, #{assoc := undefined} = St) ->
    St;
next_packet(Limit, #{assoc := A} = St) ->
    case webrtc_sctp_assoc:next_timeout(A) of
        At when At =/= infinity, At * 1000 =< Limit ->
            {A1, Acts} = webrtc_sctp_assoc:handle_timeout(At, A),
            next_packet(Limit, actions(At * 1000, Acts, St#{assoc := A1, now := max(maps:get(now, St), At * 1000)}));
        _ ->
            St
    end.

ms(#{now := Us}) -> Us div 1000.

%%--------------------------------------------------------------------
%% Socket calls
%%--------------------------------------------------------------------

call(N, {"socket", _, _}, St) -> ok_ret(N, St);
call(_N, {"bind", _, _}, St) -> St;
call(_N, {"fcntl", _, _}, St) -> St;
call(_N, {"listen", _, _}, St) ->
    St#{assoc := webrtc_sctp_assoc:new(maps:get(opts, St)), listening := true};
call(N, {C, _, Ret}, #{opts := O} = St) when C =:= "connect"; C =:= "sctp_connectx" ->
    lists:prefix("-1 EINPROGRESS", Ret) orelse throw({fail, N, {unexpected_return, Ret}}),
    A0 = webrtc_sctp_assoc:new(O),
    {A, Acts} = webrtc_sctp_assoc:connect(ms(St), A0),
    actions(maps:get(now, St), Acts, St#{assoc := A});
call(N, {"accept", _, Ret}, #{assoc := A} = St) ->
    Up = established =:= webrtc_sctp_assoc:state(A),
    case lists:prefix("-1", Ret) of
        false -> Up orelse throw({fail, N, {not_established, webrtc_sctp_assoc:state(A), Ret}});
        true -> (not Up) orelse throw({fail, N, {established, Ret}})
    end,
    St;
call(N, {"getsockopt", Args, _Ret}, St) ->
    case string:find(Args, "SO_ERROR") of
        nomatch -> St;
        _ -> check_so_error(N, Args, St)
    end;
call(N, {"setsockopt", Args, _}, St) ->
    setsockopt(N, Args, St);
call(N, {"write", Args, Ret}, St) ->
    write(N, Args, Ret, St);
call(N, {"read", Args, Ret}, St) ->
    read(N, Args, Ret, St);
call(_N, {"close", Args, _}, St) ->
    close(string:trim(Args), St);
call(_N, {"shutdown", _, _}, St) ->
    shut(St);
call(N, {Name, _, _}, _St) ->
    throw({fail, N, {unsupported_call, Name}}).

ok_ret(_N, St) -> St.

%% The listening socket (3) closing once an association was accepted (4)
%% leaves the association alone.
close("3", #{listening := true} = St) -> St;
close(_, St) -> shut(St).

shut(#{assoc := undefined} = St) ->
    St;
shut(#{assoc := A} = St) ->
    {A1, Acts} =
        case webrtc_sctp_assoc:state(A) of
            established -> webrtc_sctp_assoc:shutdown(ms(St), A);
            closed -> {A, []};
            S when S =:= shutdown_pending; S =:= shutdown_sent; S =:= shutdown_received; S =:= shutdown_ack_sent -> {A, []};
            _ -> webrtc_sctp_assoc:abort(ms(St), A)
        end,
    actions(maps:get(now, St), Acts, St#{assoc := A1}).

check_so_error(N, Args, #{assoc := A} = St) ->
    State = case A of undefined -> closed; _ -> webrtc_sctp_assoc:state(A) end,
    Closed = [R || {closed, R} <- maps:get(events, St)],
    Ok = case so_error(Args) of
        "0" -> State =:= established;
        "ECONNREFUSED" -> State =:= closed andalso lists:any(fun({peer_abort, _}) -> true; ({protocol_violation, _}) -> true; (_) -> false end, Closed);
        "ECONNRESET" -> State =:= closed andalso lists:any(fun({peer_abort, _}) -> true; (_) -> false end, Closed);
        "ETIMEDOUT" -> State =:= closed andalso lists:any(fun(R) -> R =:= handshake_timeout orelse R =:= max_retransmissions end, Closed);
        Other -> throw({fail, N, {unsupported_so_error, Other}})
    end,
    Ok orelse throw({fail, N, {so_error, so_error(Args), State, Closed}}),
    St.

so_error(Args) ->
    [_, After] = string:split(Args, "SO_ERROR, ["),
    [V | _] = string:split(After, "]"),
    V.

setsockopt(_N, Args, #{opts := O} = St) ->
    Kv = fun(K) ->
        case string:find(Args, K ++ "=") of
            nomatch -> undefined;
            S -> {I, _} = string:to_integer(string:slice(S, length(K) + 1)), I
        end
    end,
    O1 =
        case {string:find(Args, "SCTP_RTOINFO"), string:find(Args, "SCTP_INITMSG"), string:find(Args, "SPP_HB_DISABLE")} of
            {[_ | _], _, _} ->
                O#{rto_initial => Kv("srto_initial"), rto_min => Kv("srto_min"), rto_max => Kv("srto_max")};
            {_, [_ | _], _} ->
                put_nonzero(max_init_retransmissions, Kv("sinit_max_attempts"), -1,
                            put_nonzero(outbound_streams, Kv("sinit_num_ostreams"), 0,
                                        O#{inbound_streams => max(1, Kv("sinit_max_instreams"))}));
            {_, _, [_ | _]} ->
                O#{heartbeat_interval => infinity};
            _ ->
                O
        end,
    St#{opts := O1}.

%% 0 in SCTP_INITMSG means "keep the default".
put_nonzero(_K, 0, _Adj, O) -> O;
put_nonzero(max_init_retransmissions, V, Adj, O) -> O#{max_init_retransmissions => V + Adj};
put_nonzero(K, V, _Adj, O) -> O#{K => V}.

write(N, Args, Ret, #{assoc := A} = St) ->
    {Len, _} = string:to_integer(string:trim(lists:last(string:split(Args, ",", all)))),
    case {webrtc_sctp_assoc:send(0, 0, binary:copy(<<0>>, Len), #{}, ms(St), A), string:to_integer(Ret)} of
        {{ok, A1, Acts}, {Len, _}} -> actions(maps:get(now, St), Acts, St#{assoc := A1});
        {{error, _}, {-1, _}} -> St;
        {Got, _} -> throw({fail, N, {write, element(1, Got), Ret}})
    end.

read(N, _Args, Ret, #{messages := Msgs} = St) ->
    case {string:to_integer(Ret), Msgs} of
        {{0, _}, []} ->
            %% End of file: the peer shut the association down.
            webrtc_sctp_assoc:state(maps:get(assoc, St)) =/= established orelse
                throw({fail, N, {read_eof_expected, Msgs}}),
            St;
        {{-1, _}, []} ->
            St;
        {{Len, _}, [M | Rest]} when byte_size(M) =:= Len ->
            St#{messages := Rest};
        {_, _} ->
            throw({fail, N, {read, Ret, [byte_size(M) || M <- Msgs]}})
    end.

%%--------------------------------------------------------------------
%% Packets
%%--------------------------------------------------------------------

inject(N, Opts, Chunks, #{assoc := A} = St0) ->
    St = case A of undefined -> St0#{assoc := webrtc_sctp_assoc:new(maps:get(opts, St0))}; _ -> St0 end,
    {Bins, St1} = lists:mapfoldl(fun(C, S) -> encode_chunk(N, C, S) end, St, Chunks),
    Vtag = case maps:find(tag, Opts) of
        {ok, ScriptTag} -> script_tag(ScriptTag, St1);
        error -> inbound_vtag(Chunks, St1)
    end,
    Body = case maps:find(raw, Opts) of {ok, Raw} -> Raw; error -> iolist_to_binary(Bins) end,
    Hdr = <<?PORT:16, ?PORT:16, Vtag:32>>,
    Crc0 = webrtc_sctp_crc32c:crc32c([Hdr, <<0:32>>, Body]),
    Crc = case maps:is_key(bad_crc32c, Opts) of true -> Crc0 bxor 1; false -> Crc0 end,
    Pkt = <<Hdr/binary, Crc:32/little, Body/binary>>,
    {A1, Acts} = webrtc_sctp_assoc:handle_packet(Pkt, ms(St1), maps:get(assoc, St1)),
    actions(maps:get(now, St1), Acts, St1#{assoc := A1}).

%% INIT carries 0; a T bit means the sender's own tag; otherwise the
%% association's.
inbound_vtag([{term, "INIT", _} | _], _St) -> 0;
inbound_vtag([{term, Name, Items} | _], St) when Name =:= "ABORT"; Name =:= "SHUTDOWN_COMPLETE" ->
    case proplists:get_value("flgs", Items) of
        "T" -> maps:get(peer_tag, St);
        _ -> local_tag(St)
    end;
inbound_vtag(_, St) -> local_tag(St).

%% A tag the script names: the association's if bound to that script
%% value, the value itself otherwise.
script_tag(T, #{local_tag := {T, Actual}}) -> Actual;
script_tag(T, _St) -> T.

local_tag(#{local_tag := undefined}) -> 0;
local_tag(#{local_tag := {_, Actual}}) -> Actual.

chunk_bin(Type, Flags, Body) ->
    Len = 4 + byte_size(Body),
    <<Type, Flags, Len:16, Body/binary, 0:(pad(Len) * 8)>>.

pad(L) -> (4 - L rem 4) rem 4.

param_bin(Type, Body) ->
    Len = 4 + byte_size(Body),
    <<Type:16, Len:16, Body/binary, 0:(pad(Len) * 8)>>.

get(K, Items) -> proplists:get_value(K, [I || {_, _} = I <- Items]).

int(K, Items, Def) ->
    case get(K, Items) of
        V when is_integer(V) -> V;
        _ -> Def
    end.

flags_data(Items) ->
    F = case get("flgs", Items) of V when is_list(V) -> V; V when is_integer(V) -> integer_to_list(V); _ -> "" end,
    lists:foldl(fun($B, Acc) -> Acc bor 2; ($E, Acc) -> Acc bor 1; ($U, Acc) -> Acc bor 4; ($I, Acc) -> Acc bor 8;
                   (_, Acc) -> Acc end, 0, F).

flags_t(Items) ->
    case get("flgs", Items) of "T" -> 1; V when is_integer(V) -> V; _ -> 0 end.

encode_chunk(_N, {term, "DATA", I}, St) ->
    Len = int("len", I, 16),
    Payload = binary:copy(<<0>>, max(0, Len - 16)),
    {chunk_bin(0, flags_data(I), <<(int("tsn", I, 0)):32, (int("sid", I, 0)):16, (int("ssn", I, 0)):16,
                                  (int("ppid", I, 0)):32, Payload/binary>>), St};
encode_chunk(N, {term, Name, I}, St) when Name =:= "INIT"; Name =:= "INIT_ACK" ->
    Tag = int("tag", I, 1),
    {Params, St1} = lists:mapfoldl(fun(P, S) -> encode_param(N, P, S) end, St, [T || {term, _, _} = T <- I]),
    Type = case Name of "INIT" -> 1; "INIT_ACK" -> 2 end,
    Body = <<Tag:32, (int("a_rwnd", I, 1500)):32, (int("os", I, 1)):16, (int("is", I, 1)):16, (int("tsn", I, 0)):32,
             (iolist_to_binary(Params))/binary>>,
    {chunk_bin(Type, int("flgs", I, 0), Body),
     St1#{peer_tag := Tag, peer_tags := lists:usort([Tag | maps:get(peer_tags, St1)])}};
encode_chunk(_N, {term, "SACK", I}, St) ->
    Cum = sut_tsn(int("cum_tsn", I, 0), St),
    Gaps = case get("gaps", I) of {list, G} -> [X || {range, _, _} = X <- G]; _ -> [] end,
    Dups = case get("dups", I) of {list, D} -> [X || X <- D, is_integer(X)]; _ -> [] end,
    Body = <<Cum:32, (int("a_rwnd", I, 1500)):32, (length(Gaps)):16, (length(Dups)):16,
             (<< <<S:16, E:16>> || {range, S, E} <- Gaps >>)/binary, (<< <<(sut_tsn(D0, St)):32>> || D0 <- Dups >>)/binary>>,
    {chunk_bin(3, 0, Body), St};
encode_chunk(_N, {term, Name, I}, St) when Name =:= "HEARTBEAT"; Name =:= "HEARTBEAT_ACK" ->
    Info = case [V || {term, "HEARTBEAT_INFORMATION", V} <- I] of
        [HI | _] -> param_bin(1, binary:copy(<<1>>, max(0, int("len", HI, 8) - 4)));
        [] -> param_bin(1, <<1, 2, 3, 4>>)
    end,
    {chunk_bin(case Name of "HEARTBEAT" -> 4; _ -> 5 end, 0, Info), St};
encode_chunk(N, {term, "ABORT", I}, St) ->
    {Causes, St1} = lists:mapfoldl(fun(C, S) -> encode_cause(N, C, S) end, St, [T || {term, _, _} = T <- I]),
    {chunk_bin(6, flags_t(I), iolist_to_binary(Causes)), St1};
encode_chunk(_N, {term, "SHUTDOWN", I}, St) ->
    {chunk_bin(7, 0, <<(sut_tsn(int("cum_tsn", I, 0), St)):32>>), St};
encode_chunk(_N, {term, "SHUTDOWN_ACK", _}, St) ->
    {chunk_bin(8, 0, <<>>), St};
encode_chunk(N, {term, "ERROR", I}, St) ->
    {Causes, St1} = lists:mapfoldl(fun(C, S) -> encode_cause(N, C, S) end, St, [T || {term, _, _} = T <- I]),
    {chunk_bin(9, 0, iolist_to_binary(Causes)), St1};
encode_chunk(_N, {term, "COOKIE_ECHO", I}, St) ->
    Cookie =
        case get("val", I) of
            {list, Bytes} -> list_to_binary(Bytes);
            _ ->
                case {maps:get(sut_cookie, St), int("len", I, undefined)} of
                    {undefined, L} -> binary:copy(<<0>>, case L of undefined -> 4; _ -> L end);
                    {C, _} -> C
                end
        end,
    {chunk_bin(10, 0, Cookie), St};
encode_chunk(_N, {term, "COOKIE_ACK", _}, St) ->
    {chunk_bin(11, 0, <<>>), St};
encode_chunk(_N, {term, "SHUTDOWN_COMPLETE", I}, St) ->
    {chunk_bin(14, flags_t(I), <<>>), St};
encode_chunk(_N, {term, "CHUNK", I}, St) ->
    Type = chunk_type(get("type", I)),
    Val = case get("val", I) of {list, B} -> list_to_binary(B); _ -> <<>> end,
    Len = int("len", I, 4 + byte_size(Val)),
    {<<Type, (int("flgs", I, 0)), Len:16, Val/binary, 0:(pad(4 + byte_size(Val)) * 8)>>, St};
encode_chunk(N, Other, _St) ->
    throw({fail, N, {unsupported_inbound_chunk, Other}}).

chunk_type(T) when is_integer(T) -> T;
chunk_type("DATA") -> 0;
chunk_type("INIT") -> 1;
chunk_type("INIT_ACK") -> 2;
chunk_type("SACK") -> 3;
chunk_type("HEARTBEAT") -> 4;
chunk_type("ABORT") -> 6;
chunk_type("SHUTDOWN") -> 7;
chunk_type("COOKIE_ECHO") -> 10;
chunk_type("COOKIE_ACK") -> 11.

encode_param(_N, {term, "STATE_COOKIE", I}, St) ->
    Cookie = case get("val", I) of {list, B} -> list_to_binary(B); _ -> binary:copy(<<16#AB>>, max(0, int("len", I, 8) - 4)) end,
    {param_bin(7, Cookie), St#{peer_cookie := Cookie}};
encode_param(_N, {term, "IPV4_ADDRESS", I}, St) ->
    {ok, {A, B, C, D}} = inet:parse_ipv4strict_address(case get("addr", I) of {str, S} -> S; S -> S end),
    {param_bin(5, <<A, B, C, D>>), St};
encode_param(_N, {term, "HOSTNAME_ADDRESS", I}, St) ->
    {str, Host} = get("addr", I),
    {param_bin(11, <<(list_to_binary(Host))/binary, 0>>), St};
encode_param(_N, {term, "SUPPORTED_ADDRESS_TYPES", I}, St) ->
    {list, Types} = get("types", I),
    Codes = << <<(case T of "IPv4" -> 5; "IPv6" -> 6; "HOSTNAME" -> 11 end):16>> || T <- Types >>,
    {param_bin(12, Codes), St};
encode_param(_N, {term, "COOKIE_PRESERVATIVE", I}, St) ->
    {param_bin(9, <<(int("incr", I, 0)):32>>), St};
encode_param(_N, {term, "IPV6_ADDRESS", I}, St) ->
    {ok, Addr} = inet:parse_ipv6strict_address(case get("addr", I) of {str, S} -> S; S -> S end),
    {param_bin(6, << <<W:16>> || W <- tuple_to_list(Addr) >>), St};
encode_param(_N, {term, "ECN_CAPABLE", _}, St) ->
    {param_bin(16#8000, <<>>), St};
encode_param(_N, {term, "PARAMETER", I}, St) ->
    {raw_param(I), St};
encode_param(N, Other, _St) ->
    throw({fail, N, {unsupported_param, Other}}).

encode_cause(_N, {term, "INVALID_STREAM_IDENTIFIER", I}, St) -> {param_bin(1, <<(int("sid", I, 0)):16, 0:16>>), St};
encode_cause(_N, {term, "NO_USER_DATA", I}, St) -> {param_bin(9, <<(int("tsn", I, 0)):32>>), St};
encode_cause(_N, {term, "PROTOCOL_VIOLATION", _}, St) -> {param_bin(13, <<>>), St};
encode_cause(_N, {term, "STALE_COOKIE_ERROR", I}, St) -> {param_bin(3, <<(int("staleness", I, 0)):32>>), St};
encode_cause(_N, {term, "USER_INITIATED_ABORT", _}, St) -> {param_bin(12, <<>>), St};
encode_cause(_N, {term, "UNRECOGNIZED_PARAMETERS", I}, St) ->
    {list, Ps} = get("params", I),
    {param_bin(8, iolist_to_binary([raw_param(P) || {term, "PARAMETER", P} <- Ps])), St};
encode_cause(N, Other, _St) -> throw({fail, N, {unsupported_cause, Other}}).

%% PARAMETER[type=T, len=L, val=[bytes]]: as written, padding added.
raw_param(I) ->
    Val = case get("val", I) of {list, B} -> list_to_binary([X || X <- B, is_integer(X)]); _ -> <<>> end,
    Len = int("len", I, 4 + byte_size(Val)),
    <<(int("type", I, 0)):16, Len:16, Val/binary, 0:(pad(4 + byte_size(Val)) * 8)>>.

%% Script TSNs of the association, to and from its actual TSNs.
sut_tsn(V, #{tsn_off := undefined}) -> V;
sut_tsn(V, #{tsn_off := Off}) -> (V + Off) band 16#FFFFFFFF.

%%--------------------------------------------------------------------
%% Matching what the association sent
%%--------------------------------------------------------------------

match_packet(N, Bin, Want, St0) ->
    <<_:16, _:16, Vtag:32, _:32, Body/binary>> = Bin,
    Got = decode_chunks(Body),
    length(Got) =:= length(Want) orelse throw({fail, N, {chunk_count, describe(Bin), Want}}),
    St = lists:foldl(fun({G, W}, S) -> match_chunk(N, G, W, S) end, St0, lists:zip(Got, Want)),
    check_vtag(N, Vtag, Got, St),
    St.

check_vtag(N, Vtag, [{1, _, _} | _], _St) ->
    Vtag =:= 0 orelse throw({fail, N, {vtag, Vtag, expected, 0}});
check_vtag(_N, _Vtag, [{T, F, _} | _], _St) when (T =:= 6 orelse T =:= 14), F band 1 =:= 1 ->
    %% A reflected tag (RFC 9260 §8.5.1), from the packet that caused it.
    ok;
check_vtag(N, Vtag, _, #{peer_tags := Ps}) ->
    %% The tag of the association, or of an INIT the peer sent since
    %% (an INIT ACK goes to the INIT's tag, RFC 9260 §5.2).
    lists:member(Vtag, Ps) orelse throw({fail, N, {vtag, Vtag, expected, Ps}}).

decode_chunks(<<>>) -> [];
decode_chunks(<<T, F, L:16, Rest/binary>>) when L >= 4 ->
    BLen = L - 4,
    <<Body:BLen/binary, Rest1/binary>> = Rest,
    P = pad(L),
    <<_:P/binary, Rest2/binary>> = Rest1,
    [{T, F, Body} | decode_chunks(Rest2)].

decode_params(<<>>) -> [];
decode_params(<<T:16, L:16, Rest/binary>>) when L >= 4 ->
    BLen = L - 4,
    <<Body:BLen/binary, Rest1/binary>> = Rest,
    P = min(pad(L), byte_size(Rest1)),
    <<_:P/binary, Rest2/binary>> = Rest1,
    [{T, Body} | decode_params(Rest2)];
decode_params(_) -> [].

name(0) -> "DATA"; name(1) -> "INIT"; name(2) -> "INIT_ACK"; name(3) -> "SACK"; name(4) -> "HEARTBEAT";
name(5) -> "HEARTBEAT_ACK"; name(6) -> "ABORT"; name(7) -> "SHUTDOWN"; name(8) -> "SHUTDOWN_ACK";
name(9) -> "ERROR"; name(10) -> "COOKIE_ECHO"; name(11) -> "COOKIE_ACK"; name(14) -> "SHUTDOWN_COMPLETE";
name(T) -> integer_to_list(T).

describe(Bin) ->
    <<_:96, Body/binary>> = Bin,
    [{name(T), F, byte_size(B)} || {T, F, B} <- decode_chunks(Body)].

eq(_N, _What, _Got, any) -> ok;
eq(_N, _What, _Got, undefined) -> ok;
eq(_N, _What, Got, Got) -> ok;
eq(N, What, Got, Want) -> throw({fail, N, {mismatch, What, Got, Want}}).

match_chunk(N, {T, F, B}, {term, Name, I}, St) ->
    name(T) =:= Name orelse (Name =:= "CHUNK") orelse throw({fail, N, {chunk, name(T), expected, Name}}),
    match_flags(N, Name, F, get("flgs", I)),
    match_body(N, Name, B, I, St).

match_flags(_N, _Name, _F, undefined) -> ok;
match_flags(_N, _Name, _F, any) -> ok;
match_flags(N, "DATA", F, Want) when is_list(Want) ->
    eq(N, flags, F band 16#0F, flags_data([{"flgs", Want}]));
match_flags(N, _Name, F, "T") -> eq(N, flags, F, 1);
match_flags(N, _Name, F, Want) when is_integer(Want) -> eq(N, flags, F, Want);
match_flags(_N, _Name, _F, _) -> ok.

match_body(N, Name, <<Tag:32, Rwnd:32, Os:16, Is:16, Tsn:32, Params/binary>>, I, St0) when
    Name =:= "INIT"; Name =:= "INIT_ACK"
->
    eq(N, a_rwnd, Rwnd, get("a_rwnd", I)),
    eq(N, os, Os, get("os", I)),
    eq(N, is, Is, get("is", I)),
    %% Bind the association's tag and TSN to the script's values.
    %% A wildcard tag or TSN (an INIT ACK to an INIT of an existing
    %% association, RFC 9260 §5.2) leaves the association's bindings.
    St1 = case {get("tag", I), maps:get(local_tag, St0)} of
        {ST, _} when is_integer(ST) -> St0#{local_tag := {ST, Tag}};
        {_, undefined} -> St0#{local_tag := {any, Tag}};
        _ -> St0
    end,
    St2 = case {get("tsn", I), maps:get(tsn_off, St1)} of
        {STsn, _} when is_integer(STsn) -> St1#{tsn_off := (Tsn - STsn) band 16#FFFFFFFF};
        {_, undefined} -> St1#{tsn_off := 0};
        _ -> St1
    end,
    Ps = decode_params(Params),
    case lists:keyfind(7, 1, Ps) of
        {7, Cookie} -> St2#{sut_cookie := Cookie};
        false -> St2
    end;
match_body(N, "DATA", <<Tsn:32, Sid:16, Ssn:16, Ppid:32, Data/binary>>, I, St) ->
    eq(N, len, 16 + byte_size(Data), get("len", I)),
    eq(N, tsn, Tsn, sut_tsn_want(get("tsn", I), St)),
    eq(N, sid, Sid, get("sid", I)),
    eq(N, ssn, Ssn, get("ssn", I)),
    eq(N, ppid, Ppid, get("ppid", I)),
    St;
match_body(N, "SACK", <<Cum:32, Rwnd:32, NG:16, ND:16, Rest/binary>>, I, St) ->
    eq(N, cum_tsn, Cum, get("cum_tsn", I)),
    eq(N, a_rwnd, Rwnd, get("a_rwnd", I)),
    <<GapBin:(NG * 4)/binary, DupBin:(ND * 4)/binary, _/binary>> = Rest,
    Gaps = [{range, S, E} || <<S:16, E:16>> <= GapBin],
    Dups = [D || <<D:32>> <= DupBin],
    case get("gaps", I) of
        {list, WG} -> eq(N, gaps, Gaps, WG);
        _ -> ok
    end,
    case get("dups", I) of
        {list, WD} -> eq(N, dups, Dups, WD);
        _ -> ok
    end,
    St;
match_body(N, "SHUTDOWN", <<Cum:32>>, I, St) ->
    eq(N, cum_tsn, Cum, get("cum_tsn", I)),
    St;
match_body(N, "COOKIE_ECHO", Cookie, I, St) ->
    eq(N, cookie, Cookie, case get("val", I) of any -> maps:get(peer_cookie, St); V -> V end),
    St;
match_body(N, Name, Causes, I, St) when Name =:= "ABORT"; Name =:= "ERROR" ->
    Want = [W || {term, _, _} = W <- I],
    Got = decode_params(Causes),
    lists:member(dots, I) orelse length(Got) =:= length(Want) orelse
        throw({fail, N, {causes, [cause_name(C) || {C, _} <- Got], Want}}),
    lists:foreach(fun({{C, B}, {term, WName, WI}}) ->
                          cause_name(C) =:= WName orelse throw({fail, N, {cause, cause_name(C), expected, WName}}),
                          match_cause(N, WName, B, WI, St)
                  end, lists:zip(lists:sublist(Got, length(Want)), Want)),
    St;
match_body(N, Name, B, I, St) when Name =:= "HEARTBEAT"; Name =:= "HEARTBEAT_ACK" ->
    case [V || {term, "HEARTBEAT_INFORMATION", V} <- I] of
        [HI | _] ->
            [{1, Info} | _] = decode_params(B),
            eq(N, info_len, 4 + byte_size(Info), get("len", HI));
        [] -> ok
    end,
    St;
match_body(_N, _Name, _B, _I, St) ->
    St.

sut_tsn_want(V, St) when is_integer(V) -> sut_tsn(V, St);
sut_tsn_want(V, _St) -> V.

cause_name(1) -> "INVALID_STREAM_IDENTIFIER";
cause_name(2) -> "MISSING_MANDATORY_PARAMETER";
cause_name(3) -> "STALE_COOKIE_ERROR";
cause_name(5) -> "UNRESOLVABLE_ADDRESS";
cause_name(6) -> "UNRECOGNIZED_CHUNK_TYPE";
cause_name(7) -> "INVALID_MANDATORY_PARAMETER";
cause_name(8) -> "UNRECOGNIZED_PARAMETERS";
cause_name(9) -> "NO_USER_DATA";
cause_name(12) -> "USER_INITIATED_ABORT";
cause_name(13) -> "PROTOCOL_VIOLATION";
cause_name(C) -> integer_to_list(C).

match_cause(N, "INVALID_STREAM_IDENTIFIER", <<Sid:16, _:16>>, I, _St) -> eq(N, sid, Sid, get("sid", I));
match_cause(N, "NO_USER_DATA", <<Tsn:32>>, I, _St) -> eq(N, tsn, Tsn, get("tsn", I));
match_cause(_N, _Name, _B, _I, _St) -> ok.
