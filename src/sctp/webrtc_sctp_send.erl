%% @doc SCTP send side: per stream queues, scheduler, fragmentation and
%% transmission (RFC 9260 §6.1, §6.9, RFC 8260 §2.2.2 and §3.2).
%%
%% Internal module of `webrtc_sctp_assoc'. The state is a `#snd{}'
%% record. Messages wait in per stream queues; TSNs are assigned when a
%% fragment is first transmitted ("late TSN assignment"), which lets
%% I-DATA interleave fragments of messages from different streams.
%%
%% The scheduler is weighted fair queueing (RFC 8260 §3.6): every stream
%% has a weight (`set_priority/3', the data channel priority of RFC 8831
%% §6.4, 256 by default) and a virtual time that grows by the bytes it
%% sends divided by its weight; the active stream with the smallest
%% virtual time goes next, ties in activation order. Streams of equal
%% weight share the link equally by bytes. A stream that becomes active
%% starts at the virtual time of the stream served last, so idling earns
%% it nothing. With DATA chunks the scheduler stays on one message until
%% its last fragment so that fragments get consecutive TSNs, as RFC 9260
%% §6.9 requires.
%%
%% Acknowledgement processing, congestion control and the retransmission
%% timer live in `webrtc_sctp_ack'.
-module(webrtc_sctp_send).

-include("webrtc_sctp_assoc.hrl").

-export([
    new/1,
    start/2,
    enqueue/6,
    transmit/2,
    buffered_amount/2,
    set_low_threshold/3,
    set_priority/3,
    pause_streams/2,
    drained/2,
    reset_streams/2,
    resume_streams/2,
    last_assigned_tsn/1,
    idle/1,
    next_timeout/1,
    max_payload/1
]).

-type event() :: {buffered_amount_low, 0..65535}.
-export_type([event/0]).

%% Initial cwnd constant for IPv4 (RFC 9260 §7.2.1).
-define(INIT_CWND_BYTES, 4404).

%%====================================================================
%% Setup
%%====================================================================

-spec new(#cfg{}) -> #snd{}.
new(#cfg{} = C) ->
    #snd{
        mtu = C#cfg.mtu,
        max_burst = C#cfg.max_burst,
        buffer_limit = C#cfg.send_buffer,
        os = C#cfg.os,
        rto = C#cfg.rto_initial,
        rto_min = C#cfg.rto_min,
        rto_max = C#cfg.rto_max
    }.

%% @doc Enter the established state: initial TSN, peer window and
%% negotiated features.
-spec start(map(), #snd{}) -> #snd{}.
start(#{tsn := Itsn, rwnd := Rwnd, idata := IData, pr := PR, os := OS}, S0) ->
    S = drop_beyond(OS, S0),
    Mtu = S#snd.mtu,
    Next = Itsn + (1 bsl 32),
    S#snd{
        idata = IData,
        pr = PR,
        os = OS,
        next_tsn = Next,
        cum = Next - 1,
        adv = Next - 1,
        out = #{},
        rtx_count = 0,
        fast_list = [],
        flight = 0,
        flight_len = 0,
        rwnd = Rwnd,
        cwnd = min(4 * Mtu, max(2 * Mtu, ?INIT_CWND_BYTES)),
        ssthresh = max(Rwnd, 4 * Mtu),
        pba = 0,
        fr_exit = undefined,
        t3 = undefined,
        zwp = undefined,
        current = undefined
    }.

%% Largest user data in one DATA / I-DATA chunk so that a packet with
%% this single chunk fits the MTU.
-spec max_payload(#snd{}) -> pos_integer().
max_payload(#snd{mtu = Mtu, idata = IData}) ->
    Hdr =
        case IData of
            true -> ?SCTP_IDATA_HEADER_SIZE;
            false -> ?SCTP_DATA_HEADER_SIZE
        end,
    max(4, (Mtu - ?SCTP_COMMON_HEADER_SIZE - Hdr) band (bnot 3)).

%%====================================================================
%% User messages
%%====================================================================

-spec enqueue(0..65535, 0..16#FFFFFFFF, binary(), map(), integer(), #snd{}) ->
    {ok, #snd{}} | {error, atom()}.
enqueue(Sid, Ppid, Data, Opts, Now, S) ->
    case msg_opts(Opts, Now) of
        {ok, Unordered, MaxRtx, Expires} when Data =/= <<>> ->
            check_enqueue(Sid, Ppid, Data, Unordered, MaxRtx, Expires, S);
        {ok, _, _, _} ->
            {error, empty_message};
        {error, _} = E ->
            E
    end.

check_enqueue(Sid, _Ppid, _Data, _U, _MaxRtx, _Exp, #snd{os = OS}) when Sid >= OS ->
    {error, invalid_stream};
check_enqueue(_Sid, _Ppid, Data, _U, _MaxRtx, _Exp, #snd{buffered = B, buffer_limit = L}) when
    B + byte_size(Data) > L
->
    {error, buffer_full};
check_enqueue(Sid, Ppid, Data, Unordered, MaxRtx, Expires, #snd{next_msg = Id} = S) ->
    Msg = #omsg{
        id = Id,
        sid = Sid,
        ppid = Ppid,
        data = Data,
        unordered = Unordered,
        max_rtx = MaxRtx,
        expires = Expires
    },
    Str0 = stream(Sid, S),
    Size = byte_size(Data),
    Str1 = Str0#ostream{bytes = Str0#ostream.bytes + Size},
    S1 = S#snd{next_msg = Id + 1, buffered = S#snd.buffered + Size},
    case Str1#ostream.reset of
        none ->
            Str2 = Str1#ostream{queue = queue:in(Msg, Str1#ostream.queue)},
            {ok, activate(Sid, Str2, S1)};
        _ ->
            Str2 = Str1#ostream{held = queue:in(Msg, Str1#ostream.held)},
            {ok, put_stream(Sid, Str2, S1)}
    end.

msg_opts(Opts, Now) when is_map(Opts) ->
    Unordered = not maps:get(ordered, Opts, true),
    MaxRtx = maps:get(max_retransmits, Opts, infinity),
    Life = maps:get(max_lifetime, Opts, infinity),
    case {MaxRtx, Life} of
        {M, _} when M =/= infinity, not (is_integer(M) andalso M >= 0) ->
            {error, badarg};
        {_, L} when L =/= infinity, not (is_integer(L) andalso L >= 0) ->
            {error, badarg};
        {_, infinity} ->
            {ok, Unordered, MaxRtx, infinity};
        {_, L} ->
            {ok, Unordered, MaxRtx, Now + L}
    end;
msg_opts(_, _) ->
    {error, badarg}.

-spec buffered_amount(0..65535, #snd{}) -> non_neg_integer().
buffered_amount(Sid, #snd{streams = M}) ->
    case M of
        #{Sid := #ostream{bytes = B}} -> B;
        _ -> 0
    end.

-spec set_low_threshold(0..65535, non_neg_integer(), #snd{}) -> #snd{}.
set_low_threshold(Sid, Low, S) ->
    put_stream(Sid, (stream(Sid, S))#ostream{low = Low}, S).

%% @doc The scheduling weight of a stream (RFC 8260 §3.6); 0 counts as 1.
-spec set_priority(0..65535, 0..65535, #snd{}) -> #snd{}.
set_priority(Sid, W, S) when is_integer(W), W >= 0, W =< 65535 ->
    put_stream(Sid, (stream(Sid, S))#ostream{weight = max(1, W)}, S).

%% @doc True when nothing is queued and nothing is outstanding.
-spec idle(#snd{}) -> boolean().
idle(#snd{buffered = 0, out = Out}) -> map_size(Out) =:= 0;
idle(_) -> false.

%%====================================================================
%% Stream reset support (RFC 6525 §5.1.2)
%%====================================================================

-spec pause_streams([0..65535], #snd{}) -> #snd{}.
pause_streams(Sids, S) ->
    lists:foldl(
        fun(Sid, Acc) ->
            Str = stream(Sid, Acc),
            case Str#ostream.reset of
                none -> put_stream(Sid, Str#ostream{reset = pending}, Acc);
                _ -> Acc
            end
        end,
        S,
        Sids
    ).

%% @doc Streams among `Sids' whose queued messages all have TSNs.
-spec drained([0..65535], #snd{}) -> [0..65535].
drained(Sids, #snd{current = Cur} = S) ->
    [
        Sid
     || Sid <- Sids,
        Sid =/= Cur,
        queue:is_empty((stream(Sid, S))#ostream.queue)
    ].

%% @doc Reset succeeded: sequence numbers restart at 0 and held messages
%% become eligible.
-spec reset_streams([0..65535], #snd{}) -> #snd{}.
reset_streams(Sids, S) ->
    release(Sids, true, S).

%% @doc Reset failed: keep sequence numbers, release held messages.
-spec resume_streams([0..65535], #snd{}) -> #snd{}.
resume_streams(Sids, S) ->
    release(Sids, false, S).

release(Sids, Zero, S) ->
    lists:foldl(
        fun(Sid, Acc) ->
            Str0 = stream(Sid, Acc),
            Str1 =
                case Zero of
                    true -> Str0#ostream{ssn = 0, umid = 0};
                    false -> Str0
                end,
            Q = queue:join(Str1#ostream.queue, Str1#ostream.held),
            Str2 = Str1#ostream{queue = Q, held = queue:new(), reset = none},
            activate(Sid, Str2, Acc)
        end,
        S,
        Sids
    ).

-spec last_assigned_tsn(#snd{}) -> 0..16#FFFFFFFF.
last_assigned_tsn(#snd{next_tsn = N}) -> ?TSN(N - 1).

%%====================================================================
%% Transmission (RFC 9260 §6.1 rules A to E)
%%====================================================================

%% @doc Produce the chunks to send now: FORWARD TSN, fast
%% retransmissions, retransmissions and new data, in that order.
-spec transmit(integer(), #snd{}) -> {#snd{}, [term()], [event()]}.
transmit(Now, S0) ->
    {S1, Fast} = fast_retransmit(Now, S0),
    Limit = burst_limit(S1),
    {S2, Rtx} = retransmit(Now, Limit, S1),
    {S3, New, Evs} = send_new(Now, Limit, S2, [], []),
    {S4, Fwd} = webrtc_sctp_pr:forward_tsn(Now, S3),
    {S4, Fwd ++ Fast ++ Rtx ++ New, Evs}.

%% Rule D: limit a burst to Max.Burst packets beyond the flight size.
burst_limit(#snd{cwnd = Cwnd, flight = F, max_burst = MB, mtu = Mtu}) ->
    min(Cwnd, F + MB * Mtu).

%% RFC 9260 §7.2.4 step 3: one packet of fast retransmissions, ignoring
%% cwnd. Chunks that do not fit stay marked for retransmission.
fast_retransmit(_Now, #snd{fast_list = []} = S) ->
    {S, []};
fast_retransmit(Now, #snd{fast_list = L, mtu = Mtu} = S) ->
    Sorted = lists:usort(L),
    fast_loop(Now, Sorted, Mtu - ?SCTP_COMMON_HEADER_SIZE, S#snd{fast_list = []}, []).

fast_loop(_Now, [], _Room, S, Acc) ->
    {S, lists:reverse(Acc)};
fast_loop(Now, [U | Rest], Room, #snd{out = Out} = S, Acc) ->
    case Out of
        #{U := #oc{state = rtx, size = Size}} when Size =< Room ->
            case send_rtx(Now, U, S) of
                {S1, abandoned} -> fast_loop(Now, Rest, Room, S1, Acc);
                {S1, Chunk} -> fast_loop(Now, Rest, Room - Size, S1, [Chunk | Acc])
            end;
        #{U := #oc{state = rtx}} ->
            {S, lists:reverse(Acc)};
        _ ->
            fast_loop(Now, Rest, Room, S, Acc)
    end.

%% Rule C: chunks marked for retransmission go before new data.
retransmit(_Now, _Limit, #snd{rtx_count = 0} = S) ->
    {S, []};
retransmit(Now, Limit, #snd{cum = Cum, next_tsn = Next} = S) ->
    rtx_loop(Now, Limit, Cum + 1, Next, S, []).

rtx_loop(_Now, _Limit, U, Next, S, Acc) when U >= Next ->
    {S, lists:reverse(Acc)};
rtx_loop(_Now, _Limit, _U, _Next, #snd{rtx_count = 0} = S, Acc) ->
    {S, lists:reverse(Acc)};
rtx_loop(_Now, Limit, _U, _Next, #snd{flight = F} = S, Acc) when F >= Limit ->
    {S, lists:reverse(Acc)};
rtx_loop(Now, Limit, U, Next, #snd{out = Out} = S, Acc) ->
    case Out of
        #{U := #oc{state = rtx}} ->
            case send_rtx(Now, U, S) of
                {S1, abandoned} -> rtx_loop(Now, Limit, U + 1, Next, S1, Acc);
                {S1, Chunk} -> rtx_loop(Now, Limit, U + 1, Next, S1, [Chunk | Acc])
            end;
        _ ->
            rtx_loop(Now, Limit, U + 1, Next, S, Acc)
    end.

%% Retransmit one chunk unless its partial reliability policy says to
%% abandon it (RFC 3758 §4, RFC 7496).
send_rtx(Now, U, #snd{out = Out} = S) ->
    #oc{chunk = C, tx = Tx, msg = Msg, size = Size, len = Len} = Oc = maps:get(U, Out),
    case expired(Oc, Now) orelse exceeded(Oc) of
        true ->
            {webrtc_sctp_pr:abandon(Msg, Now, S), abandoned};
        false ->
            Oc1 = Oc#oc{state = inflight, tx = Tx + 1, sent_at = Now},
            Probe =
                case S#snd.rtt_probe of
                    {PU, _} when PU >= U -> undefined;
                    P -> P
                end,
            S1 = S#snd{
                out = Out#{U := Oc1},
                rtx_count = S#snd.rtx_count - 1,
                flight = S#snd.flight + Size,
                flight_len = S#snd.flight_len + Len,
                rwnd = sub0(S#snd.rwnd, Len),
                rtt_probe = Probe,
                last_data_sent = Now
            },
            S2 =
                case S1#snd.t3 =:= undefined orelse U =:= lowest_outstanding(S1) of
                    true -> S1#snd{t3 = Now + S1#snd.rto};
                    false -> S1
                end,
            {bump(retransmissions, S2), C}
    end.

expired(#oc{expires = infinity}, _Now) -> false;
expired(#oc{expires = E}, Now) -> Now >= E.

exceeded(#oc{max_rtx = infinity}) -> false;
exceeded(#oc{max_rtx = M, tx = Tx}) -> Tx > M.

lowest_outstanding(#snd{cum = Cum, next_tsn = Next, out = Out}) ->
    lowest_loop(Cum + 1, Next, Out).

lowest_loop(U, Next, _Out) when U >= Next -> undefined;
lowest_loop(U, Next, Out) ->
    case Out of
        #{U := #oc{state = inflight}} -> U;
        _ -> lowest_loop(U + 1, Next, Out)
    end.

%% Rules A, B and E for new data, with zero window probing.
send_new(_Now, Limit, #snd{flight = F} = S, Acc, Evs) when F >= Limit ->
    {S, lists:reverse(Acc), lists:reverse(Evs)};
send_new(Now, Limit, S0, Acc, Evs) ->
    case prepare(Now, S0, Evs) of
        {S, none, Evs1} ->
            {S#snd{zwp = undefined}, lists:reverse(Acc), lists:reverse(Evs1)};
        {S, {Sid, Len}, Evs1} when Len =< S#snd.rwnd ->
            {S1, Chunk, Evs2} = commit(Now, Sid, S#snd{zwp = undefined, zwp_interval = 0}, Evs1),
            send_new(Now, Limit, S1, [Chunk | Acc], Evs2);
        {S, {Sid, _Len}, Evs1} when S#snd.flight =:= 0, S#snd.rtx_count =:= 0 ->
            %% The peer window is closed and nothing is in flight: probe
            %% after one RTO, then back off exponentially.
            case S#snd.zwp of
                undefined ->
                    Ival = max(S#snd.rto, S#snd.zwp_interval),
                    {
                        S#snd{zwp = Now + Ival, zwp_interval = Ival},
                        lists:reverse(Acc),
                        lists:reverse(Evs1)
                    };
                At when Now >= At ->
                    {S1, Chunk, Evs2} = commit(Now, Sid, S#snd{zwp = undefined}, Evs1),
                    Ival = min(2 * S1#snd.zwp_interval, S1#snd.rto_max),
                    S2 = bump(zero_window_probes, S1#snd{zwp_interval = Ival}),
                    {S2, lists:reverse([Chunk | Acc]), lists:reverse(Evs2)};
                _ ->
                    {S, lists:reverse(Acc), lists:reverse(Evs1)}
            end;
        {S, _, Evs1} ->
            {S, lists:reverse(Acc), lists:reverse(Evs1)}
    end.

%% Pick the stream for the next fragment and its length, without
%% removing it from the round robin queue. Messages whose lifetime
%% expired before any fragment was sent are dropped here.
prepare(Now, #snd{current = Cur} = S, Evs) when Cur =/= undefined ->
    head_len(Now, Cur, S, Evs);
prepare(Now, S, Evs) ->
    case pick(S) of
        none ->
            {S, none, Evs};
        Sid ->
            case head_len(Now, Sid, S, Evs) of
                {S1, none, Evs1} ->
                    Str = stream(Sid, S1),
                    S2 = put_stream(Sid, Str#ostream{active = false}, S1#snd{
                        active = queue:delete(Sid, S1#snd.active)
                    }),
                    prepare(Now, S2, Evs1);
                Found ->
                    Found
            end
    end.

%% The active stream with the smallest virtual time, the first activated
%% on a tie.
pick(#snd{active = Act} = S) ->
    case queue:to_list(Act) of
        [] ->
            none;
        Sids ->
            {_, _, Sid} = lists:min([{(stream(Sid, S))#ostream.vtime, I, Sid} || {I, Sid} <- lists:enumerate(Sids)]),
            Sid
    end.

head_len(Now, Sid, S, Evs) ->
    Str = stream(Sid, S),
    case queue:peek(Str#ostream.queue) of
        empty ->
            {S, none, Evs};
        {value, #omsg{offset = 0, expires = E} = M} when E =/= infinity, Now >= E ->
            Size = byte_size(M#omsg.data),
            Str1 = Str#ostream{queue = queue:drop(Str#ostream.queue)},
            {S1, Evs1} = dec_bytes(Sid, Size, put_stream(Sid, Str1, S), Evs),
            head_len(Now, Sid, bump(expired_messages, S1), Evs1);
        {value, #omsg{data = D, offset = Off}} ->
            {S, {Sid, min(byte_size(D) - Off, max_payload(S))}, Evs}
    end.

%% Cut the next fragment of the head message of `Sid', assign its TSN
%% and record it as outstanding.
commit(Now, Sid, #snd{idata = IData, next_tsn = U, active = Act} = S, Evs) ->
    Str = stream(Sid, S),
    {value, M} = queue:peek(Str#ostream.queue),
    #omsg{data = D, offset = Off, unordered = Unord} = M,
    Total = byte_size(D),
    Len = min(Total - Off, max_payload(S)),
    B = Off =:= 0,
    E = Off + Len =:= Total,
    {Mid, Str1} =
        case {B, Unord, IData} of
            {false, _, _} ->
                {M#omsg.mid, Str};
            {true, false, false} ->
                {Str#ostream.ssn band 16#FFFF, Str#ostream{ssn = Str#ostream.ssn + 1}};
            {true, false, true} ->
                {Str#ostream.ssn band ?U32, Str#ostream{ssn = Str#ostream.ssn + 1}};
            {true, true, false} ->
                {0, Str};
            {true, true, true} ->
                {Str#ostream.umid band ?U32, Str#ostream{umid = Str#ostream.umid + 1}}
        end,
    Fsn =
        case B of
            true -> 0;
            false -> M#omsg.fsn
        end,
    Chunk = #sctp_data{
        idata = IData,
        tsn = ?TSN(U),
        sid = Sid,
        mid = Mid,
        fsn = Fsn band ?U32,
        ppid =
            case IData andalso not B of
                true -> 0;
                false -> M#omsg.ppid
            end,
        unordered = Unord,
        beginning = B,
        ending = E,
        data = binary:part(D, Off, Len)
    },
    Size = webrtc_sctp_chunk:chunk_size(Chunk),
    Oc = #oc{
        chunk = Chunk,
        size = Size,
        len = Len,
        sent_at = Now,
        msg = M#omsg.id,
        max_rtx = M#omsg.max_rtx,
        expires = M#omsg.expires
    },
    Q1 = queue:drop(Str1#ostream.queue),
    Q2 =
        case E of
            true -> Q1;
            false -> queue:in_r(M#omsg{offset = Off + Len, mid = Mid, fsn = Fsn + 1}, Q1)
        end,
    VStart = Str1#ostream.vtime,
    Str2 = Str1#ostream{queue = Q2, vtime = VStart + Len * 65536 div Str1#ostream.weight},
    More = not queue:is_empty(Q2),
    %% Scheduling: DATA keeps the stream until the end of the message,
    %% I-DATA picks again after every fragment (RFC 8260 §3.2). Unless
    %% the stream is the current DATA stream it is in the active queue.
    Act0 =
        case S#snd.current of
            Sid -> Act;
            _ -> queue:delete(Sid, Act)
        end,
    {Cur, Act1, Active} =
        case {IData, E, More} of
            {false, false, _} -> {Sid, Act0, false};
            {_, _, true} -> {undefined, queue:in(Sid, Act0), true};
            {_, _, false} -> {undefined, Act0, false}
        end,
    Probe =
        case S#snd.rtt_probe of
            undefined -> {U, Now};
            P -> P
        end,
    S1 = S#snd{
        next_tsn = U + 1,
        out = (S#snd.out)#{U => Oc},
        flight = S#snd.flight + Size,
        flight_len = S#snd.flight_len + Len,
        rwnd = sub0(S#snd.rwnd, Len),
        current = Cur,
        active = Act1,
        vclock = VStart,
        rtt_probe = Probe,
        last_data_sent = Now,
        t3 =
            case S#snd.t3 of
                undefined -> Now + S#snd.rto;
                T -> T
            end
    },
    S2 = put_stream(Sid, Str2#ostream{active = Active}, S1),
    {S3, Evs1} = dec_bytes(Sid, Len, S2, Evs),
    S4 = bump(data_chunks_sent, S3),
    S5 =
        case E of
            true -> bump(messages_sent, S4);
            false -> S4
        end,
    {S5, Chunk, Evs1}.

%%====================================================================
%% Timers
%%====================================================================

-spec next_timeout(#snd{}) -> integer() | infinity.
next_timeout(#snd{t3 = T3, zwp = Z}) ->
    min_t(T3, Z).

min_t(undefined, undefined) -> infinity;
min_t(undefined, B) -> B;
min_t(A, undefined) -> A;
min_t(A, B) -> min(A, B).

%%====================================================================
%% Helpers
%%====================================================================

%% Messages queued before the association came up on streams the peer
%% did not grant are dropped: those streams do not exist (RFC 9260
%% §6.5). The owner learns it from the negotiated stream counts.
drop_beyond(OS, #snd{streams = M} = S) ->
    Drop = maps:filter(fun(Sid, _) -> Sid >= OS end, M),
    Bytes = lists:sum([B || _ := #ostream{bytes = B} <- Drop]),
    S#snd{
        streams = maps:without(maps:keys(Drop), M),
        buffered = S#snd.buffered - Bytes,
        active = queue:filter(fun(Sid) -> Sid < OS end, S#snd.active),
        current =
            case S#snd.current of
                C when is_integer(C), C >= OS -> undefined;
                C -> C
            end
    }.

stream(Sid, #snd{streams = M}) ->
    case M of
        #{Sid := Str} -> Str;
        _ -> #ostream{}
    end.

put_stream(Sid, Str, #snd{streams = M} = S) ->
    S#snd{streams = M#{Sid => Str}}.

activate(Sid, #ostream{active = true} = Str, S) ->
    put_stream(Sid, Str, S);
activate(Sid, Str, #snd{current = Sid} = S) ->
    put_stream(Sid, Str, S);
activate(Sid, Str, S) ->
    case queue:is_empty(Str#ostream.queue) of
        true ->
            put_stream(Sid, Str, S);
        false ->
            %% No credit for the time it was idle.
            Str1 = Str#ostream{active = true, vtime = max(Str#ostream.vtime, S#snd.vclock)},
            put_stream(Sid, Str1, S#snd{active = queue:in(Sid, S#snd.active)})
    end.

dec_bytes(Sid, N, S, Evs) ->
    Str = stream(Sid, S),
    Old = Str#ostream.bytes,
    New = Old - N,
    S1 = put_stream(Sid, Str#ostream{bytes = New}, S#snd{buffered = S#snd.buffered - N}),
    case Old > Str#ostream.low andalso New =< Str#ostream.low of
        true -> {S1, [{buffered_amount_low, Sid} | Evs]};
        false -> {S1, Evs}
    end.

sub0(A, B) when A > B -> A - B;
sub0(_, _) -> 0.

bump(K, #snd{stats = St} = S) ->
    S#snd{stats = maps:update_with(K, fun(V) -> V + 1 end, 1, St)}.
