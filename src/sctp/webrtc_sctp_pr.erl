%% @doc SCTP partial reliability on the send side (RFC 3758 §3.5,
%% RFC 8260 §2.3.1): abandoning messages, the Advanced.Peer.Ack.Point
%% and FORWARD TSN / I-FORWARD-TSN generation.
%%
%% Internal module of `webrtc_sctp_assoc' working on the `#snd{}'
%% record of `webrtc_sctp_send'.
-module(webrtc_sctp_pr).

-include("webrtc_sctp_assoc.hrl").

-export([abandon/3, advance_adv/1, forward_tsn/2]).

%% @doc Abandon every fragment of message `Msg' (rule A3), including
%% fragments not yet sent, then advance the Advanced.Peer.Ack.Point.
-spec abandon(non_neg_integer(), integer(), #snd{}) -> #snd{}.
abandon(Msg, _Now, #snd{out = Out} = S) ->
    {Out1, S1, Sid} =
        maps:fold(
            fun
                (U, #oc{msg = M, state = St} = Oc, {O, Acc, _}) when
                    M =:= Msg, St =/= abandoned, St =/= acked
                ->
                    Acc1 =
                        case St of
                            inflight ->
                                Acc#snd{
                                    flight = Acc#snd.flight - Oc#oc.size,
                                    flight_len = Acc#snd.flight_len - Oc#oc.len
                                };
                            rtx ->
                                Acc#snd{rtx_count = Acc#snd.rtx_count - 1}
                        end,
                    {O#{U := Oc#oc{state = abandoned}}, Acc1, (Oc#oc.chunk)#sctp_data.sid};
                (_, #oc{msg = M} = Oc, {O, Acc, _}) when M =:= Msg ->
                    {O, Acc, (Oc#oc.chunk)#sctp_data.sid};
                (_, _, Acc) ->
                    Acc
            end,
            {Out, S, undefined},
            Out
        ),
    S2 = drop_unsent(Msg, Sid, S1#snd{out = Out1}),
    advance_adv(bump(abandoned_messages, S2)).

%% A message partly fragmented is at the head of its stream queue.
drop_unsent(_Msg, undefined, S) ->
    S;
drop_unsent(Msg, Sid, S) ->
    Str = stream(Sid, S),
    case queue:peek(Str#ostream.queue) of
        {value, #omsg{id = Msg, data = D, offset = Off}} ->
            Rest = byte_size(D) - Off,
            Q = queue:drop(Str#ostream.queue),
            Cur =
                case S#snd.current of
                    Sid -> undefined;
                    C -> C
                end,
            Str1 = Str#ostream{queue = Q, bytes = Str#ostream.bytes - Rest},
            S1 = S#snd{current = Cur, buffered = S#snd.buffered - Rest},
            case Cur =:= undefined andalso S#snd.current =:= Sid of
                true -> reactivate(Sid, Str1, S1);
                false -> put_stream(Sid, Str1, S1)
            end;
        _ ->
            S
    end.

reactivate(Sid, Str, S) ->
    case queue:is_empty(Str#ostream.queue) of
        true ->
            put_stream(Sid, Str#ostream{active = false}, S);
        false ->
            put_stream(Sid, Str#ostream{active = true}, S#snd{active = queue:in(Sid, S#snd.active)})
    end.

%% @doc Rule C2: move the Advanced.Peer.Ack.Point over abandoned (and
%% already gap acknowledged) chunks; request a FORWARD TSN if it is now
%% beyond the cumulative ack.
-spec advance_adv(#snd{}) -> #snd{}.
advance_adv(#snd{pr = false} = S) ->
    S;
advance_adv(#snd{adv = Adv0, cum = Cum, out = Out} = S) ->
    Adv = adv_loop(max(Adv0, Cum), Out),
    S1 = S#snd{adv = Adv},
    case Adv > Cum andalso Adv > Adv0 of
        true -> S1#snd{fwd_pending = true};
        false -> S1
    end.

adv_loop(A, Out) ->
    case Out of
        #{(A + 1) := #oc{state = abandoned}} -> adv_loop(A + 1, Out);
        _ -> A
    end.

%% @doc Build the FORWARD TSN or I-FORWARD-TSN (RFC 8260 §2.3.1) chunk.
-spec forward_tsn(integer(), #snd{}) -> {#snd{}, [term()]}.
forward_tsn(_Now, #snd{fwd_pending = false} = S) ->
    {S, []};
forward_tsn(Now, #snd{adv = Adv, cum = Cum} = S) when Adv =< Cum ->
    {S#snd{fwd_pending = false, fwd_last = {Adv, Now}}, []};
forward_tsn(Now, #snd{adv = Adv, cum = Cum, out = Out, idata = IData} = S) ->
    Entries = fwd_entries(Cum + 1, Adv, Out, IData, #{}),
    Chunk =
        case IData of
            false ->
                {forward_tsn, ?TSN(Adv),
                    lists:sort([{Sid, Ssn} || {Sid, Ssn} <- maps:to_list(Entries)])};
            true ->
                {i_forward_tsn, ?TSN(Adv),
                    lists:sort([{Sid, U, Mid} || {{Sid, U}, Mid} <- maps:to_list(Entries)])}
        end,
    T3 =
        case S#snd.t3 of
            undefined -> Now + S#snd.rto;
            T -> T
        end,
    S1 = S#snd{fwd_pending = false, fwd_last = {Adv, Now}, t3 = T3},
    {bump(forward_tsn_sent, S1), [Chunk]}.

fwd_entries(U, Adv, _Out, _IData, Acc) when U > Adv ->
    Acc;
fwd_entries(U, Adv, Out, IData, Acc) ->
    Acc1 =
        case Out of
            #{
                U := #oc{
                    state = abandoned, chunk = #sctp_data{sid = Sid, mid = Mid, unordered = Un}
                }
            } ->
                case IData of
                    false when Un -> Acc;
                    false -> max_entry(Sid, Mid, 16, Acc);
                    true -> max_entry({Sid, Un}, Mid, 32, Acc)
                end;
            _ ->
                Acc
        end,
    fwd_entries(U + 1, Adv, Out, IData, Acc1).

max_entry(K, V, Bits, Acc) ->
    case Acc of
        #{K := Old} ->
            case serial_gt(V, Old, Bits) of
                true -> Acc#{K := V};
                false -> Acc
            end;
        _ ->
            Acc#{K => V}
    end.

serial_gt(A, B, Bits) ->
    Half = 1 bsl (Bits - 1),
    Mod = 1 bsl Bits,
    A =/= B andalso ((A - B + Mod) rem Mod) < Half.

stream(Sid, #snd{streams = M}) ->
    case M of
        #{Sid := Str} -> Str;
        _ -> #ostream{}
    end.

put_stream(Sid, Str, #snd{streams = M} = S) ->
    S#snd{streams = M#{Sid => Str}}.

bump(K, #snd{stats = St} = S) ->
    S#snd{stats = maps:update_with(K, fun(V) -> V + 1 end, 1, St)}.
