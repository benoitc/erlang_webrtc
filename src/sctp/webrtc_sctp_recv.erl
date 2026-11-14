%% @doc SCTP receive side: TSN tracking, SACK generation, reassembly and
%% ordered delivery (RFC 9260 §6.2, §6.6, §6.7, §6.9, RFC 3758 §3.6,
%% RFC 8260 §2.2.3, RFC 6525 §5.2.2).
%%
%% Internal module of `webrtc_sctp_assoc'. The state is a `#rcv{}'
%% record. Complete messages are returned as `{message, Sid, Ppid, Data}'
%% events as soon as they can be delivered, so the receive buffer only
%% holds fragments and ordered messages waiting for an earlier one. The
%% advertised window is the configured buffer minus those bytes.
-module(webrtc_sctp_recv).

-include("webrtc_sctp_assoc.hrl").

-export([
    new/1,
    start/2,
    handle_data/2,
    handle_forward_tsn/2,
    packet_done/2,
    sack_wanted/2,
    ack_pending/1,
    build_sack/2,
    cum_tsn/1,
    a_rwnd/1,
    reset_incoming/4,
    check_deferred/1,
    deferred_seq/2,
    add_streams/2,
    next_timeout/1
]).

-type event() ::
    {message, 0..65535, 0..16#FFFFFFFF, binary()}
    | {message_too_large, 0..65535}
    | {stream_reset, [0..65535]}.
-export_type([event/0]).

%% Gap Ack Block offsets are 16-bit: data further ahead is not accepted.
-define(MAX_AHEAD, 65535).
-define(MAX_DUPS, 32).

-spec new(#cfg{}) -> #rcv{}.
new(#cfg{} = C) ->
    Max = C#cfg.max_message_size,
    #rcv{
        rbuf = max(C#cfg.rbuf, Max),
        max_msg = Max,
        mis = C#cfg.mis,
        sack_delay = C#cfg.sack_delay,
        sack_freq = C#cfg.sack_freq
    }.

-spec start(map(), #rcv{}) -> #rcv{}.
start(#{tsn := PeerItsn, idata := IData, mis := Mis}, R) ->
    Base = PeerItsn + (1 bsl 32),
    R#rcv{cum = Base - 1, highest = Base - 1, idata = IData, mis = Mis}.

-spec cum_tsn(#rcv{}) -> 0..16#FFFFFFFF.
cum_tsn(#rcv{cum = C}) -> ?TSN(C).

-spec a_rwnd(#rcv{}) -> non_neg_integer().
a_rwnd(#rcv{rbuf = B, bytes = Used}) when B > Used -> B - Used;
a_rwnd(_) -> 0.

-spec add_streams(non_neg_integer(), #rcv{}) -> #rcv{}.
add_streams(N, #rcv{mis = M} = R) -> R#rcv{mis = M + N}.

%%====================================================================
%% DATA / I-DATA
%%====================================================================

-spec handle_data(#sctp_data{}, #rcv{}) ->
    {ok, #rcv{}, [event()], [webrtc_sctp_param:cause()]} | {abort, webrtc_sctp_param:cause()}.
handle_data(#sctp_data{data = <<>>, tsn = T}, _R) ->
    {abort, {no_user_data, T}};
handle_data(#sctp_data{idata = I}, #rcv{idata = I2}) when I =/= I2 ->
    {abort, {protocol_violation, <<"DATA and I-DATA mixed">>}};
handle_data(#sctp_data{tsn = W, data = D} = C, #rcv{cum = Cum} = R0) ->
    U = webrtc_sctp_ack:unwrap(W, Cum),
    R = R0#rcv{got_data = true},
    Len = byte_size(D),
    Dup = U =< Cum orelse gb_sets:is_member(U, R#rcv.seen),
    if
        Dup ->
            {ok, add_dup(W, R), [], []};
        U > Cum + ?MAX_AHEAD ->
            {ok, R#rcv{sack_now = true, only_dups = false}, [], []};
        R#rcv.bytes + Len > R#rcv.rbuf, U > R#rcv.highest ->
            %% Window closed: drop data beyond the highest TSN (§6.2).
            {ok, bump(dropped_chunks, R#rcv{sack_now = true, only_dups = false}), [], []};
        R#rcv.bytes + Len > 2 * R#rcv.rbuf ->
            {ok, bump(dropped_chunks, R#rcv{sack_now = true, only_dups = false}), [], []};
        true ->
            R1 = mark(U, R#rcv{only_dups = false}),
            R2 =
                case U =/= Cum + 1 orelse C#sctp_data.immediate of
                    true -> R1#rcv{sack_now = true};
                    false -> R1
                end,
            accept(U, C, R2)
    end.

accept(_U, #sctp_data{sid = Sid}, #rcv{mis = Mis} = R) when Sid >= Mis ->
    %% §6.5: report the invalid stream, the TSN is still acknowledged.
    {ok, R, [], [{invalid_stream, Sid}]};
accept(U, #sctp_data{sid = Sid} = C, #rcv{deferred = Def} = R) ->
    case lists:any(fun({L, Sids, _}) -> U > L andalso affects(Sid, Sids) end, Def) of
        true ->
            {ok, R#rcv{held = [{U, C} | R#rcv.held], bytes = R#rcv.bytes + dsize(C)}, [], []};
        false ->
            {ok, R1, Evs} = deliver(U, C, R),
            {ok, R1, Evs, []}
    end.

affects(_Sid, []) -> true;
affects(Sid, Sids) -> lists:member(Sid, Sids).

dsize(#sctp_data{data = D}) -> byte_size(D).

add_dup(W, #rcv{dups = Ds} = R) when length(Ds) < ?MAX_DUPS ->
    bump(duplicate_tsns, R#rcv{dups = [W | Ds]});
add_dup(_W, R) ->
    bump(duplicate_tsns, R).

mark(U, #rcv{cum = Cum} = R) when U =:= Cum + 1 ->
    advance(R#rcv{cum = U, highest = max(U, R#rcv.highest)});
mark(U, R) ->
    R#rcv{seen = gb_sets:add(U, R#rcv.seen), highest = max(U, R#rcv.highest)}.

advance(#rcv{seen = Seen, cum = Cum} = R) ->
    case gb_sets:is_empty(Seen) of
        true ->
            R;
        false ->
            {Min, Rest} = gb_sets:take_smallest(Seen),
            if
                Min =< Cum -> advance(R#rcv{seen = Rest});
                Min =:= Cum + 1 -> advance(R#rcv{seen = Rest, cum = Min});
                true -> R
            end
    end.

%% Reassembly. Keys: I-DATA {Sid, U, MID} by FSN; ordered DATA
%% {Sid, false, SSN} by TSN; unordered DATA one bucket per stream by TSN
%% where a message is a run of consecutive TSNs from B to E.
deliver(_U, #sctp_data{sid = Sid}, #rcv{discard = D} = R) when is_map_key(Sid, D) ->
    {ok, bump(discarded_chunks, R), []};
deliver(_U, #sctp_data{beginning = true, ending = true, sid = Sid, data = Data}, #rcv{max_msg = Max} = R) when
    byte_size(Data) > Max
->
    too_large(Sid, none, R);
deliver(_U, #sctp_data{beginning = true, ending = true} = C, R) ->
    complete(
        C#sctp_data.sid,
        C#sctp_data.unordered,
        C#sctp_data.mid,
        C#sctp_data.ppid,
        C#sctp_data.data,
        R
    );
deliver(U, #sctp_data{idata = false, unordered = true, sid = Sid} = C, R) ->
    Key = {Sid, true, bucket},
    Ra0 = maps:get(Key, R#rcv.ra, #ra{}),
    Ra = add_frag(U, C, Ra0),
    R1 = R#rcv{ra = (R#rcv.ra)#{Key => Ra}, bytes = R#rcv.bytes + dsize(C)},
    case find_run(U, Ra#ra.frags) of
        _ when Ra#ra.bytes > R#rcv.max_msg ->
            too_large(Sid, Key, R1);
        none ->
            {ok, R1, []};
        {First, Last} ->
            {Ppid, Data, Frags} = take_run(First, Last, Ra#ra.frags),
            Ra1 = Ra#ra{frags = Frags, bytes = Ra#ra.bytes - byte_size(Data)},
            R2 = R1#rcv{bytes = R1#rcv.bytes - byte_size(Data)},
            R3 =
                case map_size(Frags) of
                    0 -> R2#rcv{ra = maps:remove(Key, R2#rcv.ra)};
                    _ -> R2#rcv{ra = (R2#rcv.ra)#{Key => Ra1}}
                end,
            complete(Sid, true, 0, Ppid, Data, R3)
    end;
deliver(U, #sctp_data{sid = Sid, unordered = Un, mid = Mid} = C, R) ->
    {Key, Pos} =
        case C#sctp_data.idata of
            true -> {{Sid, Un, Mid}, C#sctp_data.fsn};
            false -> {{Sid, false, Mid}, U}
        end,
    Ra0 = maps:get(Key, R#rcv.ra, #ra{}),
    case maps:is_key(Pos, Ra0#ra.frags) of
        true ->
            {ok, R, []};
        false ->
            Ra = add_frag(Pos, C, Ra0),
            R1 = R#rcv{bytes = R#rcv.bytes + dsize(C)},
            if
                Ra#ra.bytes > R#rcv.max_msg ->
                    too_large(Sid, Key, R1#rcv{ra = (R1#rcv.ra)#{Key => Ra}});
                Ra#ra.first =/= undefined,
                Ra#ra.last =/= undefined,
                map_size(Ra#ra.frags) =:= Ra#ra.last - Ra#ra.first + 1 ->
                    {Ppid, Data, _} = take_run(Ra#ra.first, Ra#ra.last, Ra#ra.frags),
                    R2 = R1#rcv{
                        ra = maps:remove(Key, R1#rcv.ra),
                        bytes = R1#rcv.bytes - Ra#ra.bytes
                    },
                    complete(Sid, Un, Mid, Ppid, Data, R2);
                true ->
                    {ok, R1#rcv{ra = (R1#rcv.ra)#{Key => Ra}}, []}
            end
    end.

%% A message over the local max-message-size: drop what was buffered for
%% it and every later chunk of the stream until the stream is reset, and
%% tell the data channel layer, which closes the channel (RFC 8841 §6).
too_large(Sid, Key, R) ->
    {Ra, Bytes} =
        case maps:take(Key, R#rcv.ra) of
            {#ra{bytes = B}, Rest} -> {Rest, B};
            error -> {R#rcv.ra, 0}
        end,
    R1 = R#rcv{ra = Ra, bytes = R#rcv.bytes - Bytes, discard = (R#rcv.discard)#{Sid => true}},
    {ok, bump(oversized_messages, R1), [{message_too_large, Sid}]}.

add_frag(Pos, #sctp_data{beginning = B, ending = E, ppid = P, data = D}, Ra) ->
    Ra#ra{
        frags = (Ra#ra.frags)#{Pos => {B, E, P, D}},
        first =
            case B of
                true -> Pos;
                false -> Ra#ra.first
            end,
        last =
            case E of
                true -> Pos;
                false -> Ra#ra.last
            end,
        bytes = Ra#ra.bytes + byte_size(D)
    }.

find_run(U, Frags) ->
    case {run_down(U, Frags), run_up(U, Frags)} of
        {{ok, F}, {ok, L}} -> {F, L};
        _ -> none
    end.

run_down(P, Frags) ->
    case Frags of
        #{P := {true, _, _, _}} -> {ok, P};
        #{P := _} -> run_down(P - 1, Frags);
        _ -> none
    end.

run_up(P, Frags) ->
    case Frags of
        #{P := {_, true, _, _}} -> {ok, P};
        #{P := _} -> run_up(P + 1, Frags);
        _ -> none
    end.

take_run(First, Last, Frags) ->
    {_, _, Ppid, _} = maps:get(First, Frags),
    Parts = [element(4, maps:get(P, Frags)) || P <- lists:seq(First, Last)],
    Rest = maps:without(lists:seq(First, Last), Frags),
    {Ppid, iolist_to_binary(Parts), Rest}.

%% A complete message: deliver now (unordered, or next in sequence) or
%% hold it until the earlier messages of its stream arrive.
complete(Sid, true, _Mid, Ppid, Data, R) ->
    {ok, received(Data, R), [{message, Sid, Ppid, Data}]};
complete(Sid, false, Mid, Ppid, Data, R) ->
    Str = istream(Sid, R),
    Next = Str#istream.next,
    Bits = bits(R),
    if
        Mid =:= Next ->
            R1 = received(Data, R),
            Str1 = Str#istream{next = inc(Next, Bits)},
            {Str2, R2, Evs} = drain(Sid, Str1, R1, [{message, Sid, Ppid, Data}]),
            {ok, put_istream(Sid, Str2, R2), Evs};
        true ->
            case serial_gt(Mid, Next, Bits) of
                true ->
                    Str1 = Str#istream{pending = (Str#istream.pending)#{Mid => {Ppid, Data}}},
                    {ok, put_istream(Sid, Str1, R#rcv{bytes = R#rcv.bytes + byte_size(Data)}), []};
                false ->
                    %% Older than the next expected message: skipped by a
                    %% FORWARD TSN.
                    {ok, bump(stale_messages, R), []}
            end
    end.

drain(Sid, #istream{next = Next, pending = P} = Str, R, Acc) ->
    case maps:take(Next, P) of
        {{Ppid, Data}, P1} ->
            R1 = received(Data, R#rcv{bytes = R#rcv.bytes - byte_size(Data)}),
            drain(Sid, Str#istream{next = inc(Next, bits(R)), pending = P1}, R1, [
                {message, Sid, Ppid, Data} | Acc
            ]);
        error ->
            {Str, R, lists:reverse(Acc)}
    end.

received(Data, #rcv{stats = St} = R) ->
    St1 = maps:update_with(messages_received, fun(V) -> V + 1 end, 1, St),
    St2 = maps:update_with(bytes_received, fun(V) -> V + byte_size(Data) end, byte_size(Data), St1),
    R#rcv{stats = St2}.

bits(#rcv{idata = true}) -> 32;
bits(#rcv{idata = false}) -> 16.

inc(V, Bits) -> (V + 1) band ((1 bsl Bits) - 1).

serial_gt(A, B, Bits) ->
    Mod = 1 bsl Bits,
    A =/= B andalso ((A - B + Mod) rem Mod) < (Mod bsr 1).

istream(Sid, #rcv{streams = M}) ->
    case M of
        #{Sid := S} -> S;
        _ -> #istream{}
    end.

put_istream(Sid, S, #rcv{streams = M} = R) -> R#rcv{streams = M#{Sid => S}}.

%%====================================================================
%% FORWARD TSN / I-FORWARD-TSN (RFC 3758 §3.6, RFC 8260 §2.3.1)
%%====================================================================

-spec handle_forward_tsn(tuple(), #rcv{}) ->
    {ok, #rcv{}, [event()]} | {abort, webrtc_sctp_param:cause()}.
handle_forward_tsn({forward_tsn, _, _}, #rcv{idata = true}) ->
    {abort, {protocol_violation, <<"FORWARD TSN with I-DATA">>}};
handle_forward_tsn({i_forward_tsn, _, _}, #rcv{idata = false}) ->
    {abort, {protocol_violation, <<"I-FORWARD-TSN without I-DATA">>}};
handle_forward_tsn({_, NewW, Entries}, #rcv{cum = Cum} = R0) ->
    U = webrtc_sctp_ack:unwrap(NewW, Cum),
    R = R0#rcv{got_data = true, only_dups = false},
    case U =< Cum of
        true ->
            {ok, R#rcv{sack_now = true}, []};
        false ->
            R1 = advance(R#rcv{cum = U, highest = max(U, R#rcv.highest)}),
            R2 = drop_stranded(U, Entries, R1),
            skip_streams(Entries, R2, [])
    end.

drop_stranded(U, Entries, #rcv{idata = false} = R) ->
    Ordered = maps:from_list(Entries),
    maps:fold(
        fun
            ({Sid, true, bucket} = K, #ra{frags = F} = Ra, Acc) ->
                Drop = [P || P <- maps:keys(F), P =< U],
                drop_positions(K, Ra, Drop, Acc, Sid);
            ({Sid, false, Ssn} = K, Ra, Acc) ->
                case Ordered of
                    #{Sid := Skip} ->
                        case serial_gt(Ssn, Skip, 16) of
                            false -> drop_key(K, Ra, Acc);
                            true -> Acc
                        end;
                    _ ->
                        Acc
                end
        end,
        R,
        R#rcv.ra
    );
drop_stranded(_U, Entries, #rcv{idata = true} = R) ->
    Skips = maps:from_list([{{Sid, Un}, Mid} || {Sid, Un, Mid} <- Entries]),
    maps:fold(
        fun({Sid, Un, Mid} = K, Ra, Acc) ->
            case Skips of
                #{{Sid, Un} := Skip} ->
                    case serial_gt(Mid, Skip, 32) of
                        false -> drop_key(K, Ra, Acc);
                        true -> Acc
                    end;
                _ ->
                    Acc
            end
        end,
        R,
        R#rcv.ra
    ).

drop_key(K, #ra{bytes = B}, R) ->
    R#rcv{ra = maps:remove(K, R#rcv.ra), bytes = R#rcv.bytes - B}.

drop_positions(_K, _Ra, [], R, _Sid) ->
    R;
drop_positions(K, #ra{frags = F} = Ra, Ps, R, _Sid) ->
    Bytes = lists:sum([byte_size(element(4, maps:get(P, F))) || P <- Ps]),
    F1 = maps:without(Ps, F),
    R1 = R#rcv{bytes = R#rcv.bytes - Bytes},
    case map_size(F1) of
        0 -> R1#rcv{ra = maps:remove(K, R1#rcv.ra)};
        _ -> R1#rcv{ra = (R1#rcv.ra)#{K => Ra#ra{frags = F1, bytes = Ra#ra.bytes - Bytes}}}
    end.

%% Ordered streams listed in the chunk skip to the reported sequence
%% number; complete messages up to it are delivered first.
skip_streams([], R, Acc) ->
    {ok, R, lists:append(lists:reverse(Acc))};
skip_streams([{_Sid, true, _Mid} | Rest], R, Acc) ->
    skip_streams(Rest, R, Acc);
skip_streams([Entry | Rest], R, Acc) ->
    {Sid, Skip} =
        case Entry of
            {S, false, M} -> {S, M};
            {S, M} -> {S, M}
        end,
    Bits = bits(R),
    Str = istream(Sid, R),
    case Skip =:= Str#istream.next orelse serial_gt(Skip, Str#istream.next, Bits) of
        false ->
            skip_streams(Rest, R, Acc);
        true ->
            {Str1, R1, Evs} = flush_upto(Sid, Skip, Str, R, []),
            Str2 = Str1#istream{next = inc(Skip, Bits)},
            {Str3, R2, Evs2} = drain(Sid, Str2, R1, []),
            skip_streams(Rest, put_istream(Sid, Str3, R2), [Evs ++ Evs2 | Acc])
    end.

flush_upto(Sid, Skip, #istream{next = Next, pending = P} = Str, R, _Acc) ->
    Mod = 1 bsl bits(R),
    Dist = fun(K) -> (K - Next + Mod) rem Mod end,
    Max = Dist(Skip),
    Keys = lists:sort([{Dist(K), K} || K <- maps:keys(P), Dist(K) =< Max]),
    {R1, P1, Evs} =
        lists:foldl(
            fun({_, K}, {RAcc, PAcc, EAcc}) ->
                {{Ppid, Data}, PAcc1} = maps:take(K, PAcc),
                RAcc1 = received(Data, RAcc#rcv{bytes = RAcc#rcv.bytes - byte_size(Data)}),
                {RAcc1, PAcc1, [{message, Sid, Ppid, Data} | EAcc]}
            end,
            {R, P, []},
            Keys
        ),
    {Str#istream{pending = P1}, R1, lists:reverse(Evs)}.

%%====================================================================
%% SACK (RFC 9260 §6.2)
%%====================================================================

%% @doc Called once all chunks of a packet were processed: decide
%% between an immediate and a delayed SACK.
-spec packet_done(integer(), #rcv{}) -> #rcv{}.
packet_done(_Now, #rcv{got_data = false} = R) ->
    R;
packet_done(Now, #rcv{} = R) ->
    N = R#rcv.packets + 1,
    Now1 =
        R#rcv.sack_now orelse R#rcv.only_dups orelse
            not gb_sets:is_empty(R#rcv.seen) orelse N >= R#rcv.sack_freq orelse
            R#rcv.sack_delay =:= 0,
    R1 = R#rcv{packets = N, got_data = false, only_dups = true},
    case Now1 of
        true ->
            R1#rcv{sack_now = true};
        false when R1#rcv.sack_at =:= undefined ->
            R1#rcv{sack_at = Now + R1#rcv.sack_delay};
        false ->
            R1
    end.

-spec sack_wanted(integer(), #rcv{}) -> boolean().
sack_wanted(_Now, #rcv{sack_now = true}) -> true;
sack_wanted(_Now, #rcv{sack_at = undefined}) -> false;
sack_wanted(Now, #rcv{sack_at = At}) -> Now >= At.

%% @doc True when received data was not acknowledged yet (a SACK should
%% be bundled with outgoing DATA, §6.1).
-spec ack_pending(#rcv{}) -> boolean().
ack_pending(#rcv{sack_now = N, sack_at = At}) -> N orelse At =/= undefined.

%% @doc Build a SACK that fits in `Room' bytes (chunk included).
-spec build_sack(pos_integer(), #rcv{}) -> {#rcv{}, #sctp_sack{}}.
build_sack(Room, #rcv{cum = Cum, seen = Seen, dups = Dups0} = R) ->
    Dups = lists:reverse(Dups0),
    MaxBlocks = max(0, (Room - 16 - 4 * length(Dups)) div 4),
    Gaps = gaps(gb_sets:to_list(Seen), Cum, MaxBlocks),
    Sack = #sctp_sack{cum_tsn = ?TSN(Cum), a_rwnd = a_rwnd(R), gaps = Gaps, dups = Dups},
    {bump(sacks_sent, R#rcv{dups = [], packets = 0, sack_at = undefined, sack_now = false}), Sack}.

gaps([], _Cum, _Max) ->
    [];
gaps([First | Rest], Cum, Max) ->
    gaps(Rest, Cum, Max, First, First, []).

gaps(_, _Cum, Max, _S, _E, Acc) when length(Acc) >= Max ->
    lists:reverse(Acc);
gaps([U | Rest], Cum, Max, S, E, Acc) when U =:= E + 1 ->
    gaps(Rest, Cum, Max, S, U, Acc);
gaps([U | Rest], Cum, Max, S, E, Acc) ->
    gaps(Rest, Cum, Max, U, U, [{S - Cum, E - Cum} | Acc]);
gaps([], Cum, _Max, S, E, Acc) ->
    lists:reverse([{S - Cum, E - Cum} | Acc]).

-spec next_timeout(#rcv{}) -> integer() | infinity.
next_timeout(#rcv{sack_at = undefined}) -> infinity;
next_timeout(#rcv{sack_at = At}) -> At.

%%====================================================================
%% Incoming stream reset (RFC 6525 §5.2.2)
%%====================================================================

%% @doc Reset incoming streams once every TSN up to the sender's last
%% assigned TSN was received; defer otherwise (E2).
-spec reset_incoming([0..65535], 0..16#FFFFFFFF, non_neg_integer(), #rcv{}) ->
    {done, #rcv{}} | {deferred, #rcv{}}.
reset_incoming(Sids, LastW, Seq, #rcv{cum = Cum} = R) ->
    L = webrtc_sctp_ack:unwrap(LastW, Cum),
    case L =< Cum of
        true -> {done, do_reset(Sids, R)};
        false -> {deferred, R#rcv{deferred = R#rcv.deferred ++ [{L, Sids, Seq}]}}
    end.

%% @doc Is the request `Seq' still deferred?
-spec deferred_seq(non_neg_integer(), #rcv{}) -> boolean().
deferred_seq(Seq, #rcv{deferred = D}) -> lists:keymember(Seq, 3, D).

%% @doc Complete deferred resets whose last TSN is now cumulatively
%% received, then process the chunks held back for them (E4).
-spec check_deferred(#rcv{}) -> {#rcv{}, [non_neg_integer()], [event()]}.
check_deferred(#rcv{deferred = []} = R) ->
    {R, [], []};
check_deferred(#rcv{deferred = D, cum = Cum} = R) ->
    {Ready, Wait} = lists:partition(fun({L, _, _}) -> L =< Cum end, D),
    lists:foldl(
        fun({L, Sids, Seq}, {Acc, Seqs, Evs}) ->
            Acc1 = do_reset(Sids, Acc),
            {Mine, Others} = lists:partition(
                fun({U, #sctp_data{sid = Sid}}) -> U > L andalso affects(Sid, Sids) end,
                Acc1#rcv.held
            ),
            Acc2 = Acc1#rcv{held = Others},
            {Acc3, Evs1} = replay(lists:keysort(1, Mine), Acc2, []),
            {Acc3, Seqs ++ [Seq], Evs ++ [{stream_reset, Sids} | Evs1]}
        end,
        {R#rcv{deferred = Wait}, [], []},
        Ready
    ).

replay([], R, Acc) ->
    {R, Acc};
replay([{U, C} | Rest], R, Acc) ->
    R0 = R#rcv{bytes = R#rcv.bytes - dsize(C)},
    {ok, R1, Evs} = deliver(U, C, R0),
    replay(Rest, R1, Acc ++ Evs).

%% RFC 6525 §5.2.2 E3: an empty list means every incoming stream. It is
%% expanded once into the streams that have state (possibly none), never
%% re-entered with an empty list.
do_reset([], #rcv{streams = M} = R) ->
    reset_streams(maps:keys(M) ++ [Sid || {Sid, _, _} <- maps:keys(R#rcv.ra)], R);
do_reset(Sids, R) ->
    reset_streams(Sids, R).

reset_streams(Sids, R0) ->
    R = R0#rcv{discard = maps:without(Sids, R0#rcv.discard)},
    lists:foldl(
        fun(Sid, Acc) ->
            #istream{pending = P} = istream(Sid, Acc),
            Bytes = lists:sum([byte_size(D) || {_, D} <- maps:values(P)]),
            Ra = maps:filter(fun({S, _, _}, _) -> S =:= Sid end, Acc#rcv.ra),
            RaBytes = lists:sum([B || #ra{bytes = B} <- maps:values(Ra)]),
            Acc#rcv{
                streams = maps:remove(Sid, Acc#rcv.streams),
                ra = maps:without(maps:keys(Ra), Acc#rcv.ra),
                bytes = Acc#rcv.bytes - Bytes - RaBytes
            }
        end,
        R,
        lists:usort(Sids)
    ).

bump(K, #rcv{stats = St} = R) ->
    R#rcv{stats = maps:update_with(K, fun(V) -> V + 1 end, 1, St)}.
