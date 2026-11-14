%% @doc SCTP acknowledgement processing, congestion control and
%% retransmission timer (RFC 9260 §6.2.1, §6.3, §7.2, RFC 3758 §3.5).
%%
%% Internal module of `webrtc_sctp_assoc' working on the `#snd{}'
%% record of `webrtc_sctp_send'. There is a single destination address
%% (SCTP over DTLS is never multi-homed), so cwnd, ssthresh,
%% partial_bytes_acked and the RTO are kept once per association.
-module(webrtc_sctp_ack).

-include("webrtc_sctp_assoc.hrl").

-export([handle_sack/3, handle_cum_ack/3, handle_t3/2, rtt_sample/2, unwrap/2]).

%% @doc Map a 32-bit wire TSN to the unwrapped TSN closest to `Ref'
%% (serial number arithmetic, RFC 1982 with SERIAL_BITS = 32).
-spec unwrap(0..16#FFFFFFFF, integer()) -> integer().
unwrap(Wire, Ref) ->
    D = (Wire - (Ref band ?U32)) band ?U32,
    case D >= (1 bsl 31) of
        true -> Ref + D - (1 bsl 32);
        false -> Ref + D
    end.

%% @doc Process a SACK chunk. Returns whether new data was acknowledged
%% (which resets the association error counter, RFC 9260 §8.1).
-spec handle_sack(#sctp_sack{}, integer(), #snd{}) ->
    {ok, #snd{}, boolean()} | {error, protocol_violation}.
handle_sack(#sctp_sack{cum_tsn = CumW, a_rwnd = Arwnd, gaps = Gaps}, Now, S) ->
    process(unwrap(CumW, S#snd.cum), Arwnd, Gaps, Now, S).

%% @doc Process the Cumulative TSN Ack of a SHUTDOWN chunk (RFC 9260
%% §9.2): like a SACK without gap blocks that does not change the peer
%% window.
-spec handle_cum_ack(0..16#FFFFFFFF, integer(), #snd{}) ->
    {ok, #snd{}, boolean()} | {error, protocol_violation}.
handle_cum_ack(CumW, Now, #snd{rwnd = R, flight_len = FL} = S) ->
    process(unwrap(CumW, S#snd.cum), R + FL, [], Now, S).

process(Cum, _Arwnd, _Gaps, _Now, #snd{cum = Old} = S) when Cum < Old ->
    %% Out of order SACK (§6.2.1 D i).
    {ok, S, false};
process(Cum, _Arwnd, _Gaps, _Now, #snd{next_tsn = Next}) when Cum >= Next ->
    %% Acknowledges a TSN never sent (RFC 9260 §12.2.4.2 note).
    {error, protocol_violation};
process(Cum, Arwnd, Gaps0, Now, S0) ->
    FlightBefore = S0#snd.flight,
    Advanced = Cum > S0#snd.cum,
    %% 1. Cumulative ack.
    {S1, Bytes1, Htna1} = cum_loop(S0#snd.cum + 1, Cum, Now, S0, 0, undefined),
    S2 = S1#snd{cum = Cum, adv = max(S1#snd.adv, Cum)},
    %% 2. Gap ack blocks, as absolute unwrapped ranges.
    Gaps = valid_gaps(Gaps0, Cum, S2#snd.next_tsn),
    {S3, Bytes2, Htna} = gap_loop(Gaps, Now, S2, Bytes1, Htna1),
    %% 3. Reneged chunks (§6.2.1 D iii).
    S4 = renege(Gaps, Now, S3),
    %% 4. Miss indications (§7.2.4, HTNA).
    HighestGap =
        case Gaps of
            [] -> Cum;
            _ -> element(2, lists:last(Gaps))
        end,
    InFR = S4#snd.fr_exit =/= undefined,
    Bound =
        case {InFR andalso Advanced, Htna} of
            {true, _} -> HighestGap + 1;
            {false, undefined} -> Cum + 1;
            {false, H} -> min(H, HighestGap + 1)
        end,
    {S5, Fast} = miss_loop(Cum + 1, Bound, S4, []),
    %% 5. cwnd growth (§7.2.1, §7.2.2) before any loss reaction.
    Bytes = Bytes1 + Bytes2,
    S6 = grow_cwnd(Bytes, FlightBefore, S5),
    %% 6. Fast recovery exit (§6.2.1 D iv).
    S7 =
        case S6#snd.fr_exit of
            E when E =/= undefined, Cum >= E -> S6#snd{fr_exit = undefined};
            _ -> S6
        end,
    %% 7. Fast retransmit (§7.2.4).
    S8 = fast_mark(Fast, S7),
    %% 8. Peer window (§6.2.1 D ii).
    S9 = S8#snd{rwnd = sub0(Arwnd, S8#snd.flight_len), last_sack = Now},
    %% 9. T3-rtx rules R2 and R3.
    S10 =
        case S9#snd.flight of
            0 ->
                S9#snd{t3 = undefined};
            _ when Advanced -> S9#snd{t3 = Now + S9#snd.rto};
            _ when S9#snd.t3 =:= undefined -> S9#snd{t3 = Now + S9#snd.rto};
            _ ->
                S9
        end,
    S11 =
        case map_size(S10#snd.out) of
            0 -> S10#snd{pba = 0};
            _ -> S10
        end,
    %% 10. PR-SCTP rules C1 to C3.
    S12 = pr_after_sack(Now, webrtc_sctp_pr:advance_adv(S11)),
    {ok, S12, Advanced orelse Bytes > 0}.

cum_loop(U, Cum, _Now, S, Bytes, Htna) when U > Cum ->
    {S, Bytes, Htna};
cum_loop(U, Cum, Now, #snd{out = Out} = S, Bytes, Htna) ->
    case maps:take(U, Out) of
        {#oc{state = St} = Oc, Out1} ->
            S1 = S#snd{out = Out1},
            case St of
                inflight ->
                    S2 = rtt_check(U, Oc, Now, S1),
                    S3 = S2#snd{
                        flight = S2#snd.flight - Oc#oc.size,
                        flight_len = S2#snd.flight_len - Oc#oc.len
                    },
                    cum_loop(U + 1, Cum, Now, S3, Bytes + Oc#oc.size, U);
                rtx ->
                    S2 = S1#snd{rtx_count = S1#snd.rtx_count - 1},
                    cum_loop(U + 1, Cum, Now, S2, Bytes + Oc#oc.size, U);
                _ ->
                    cum_loop(U + 1, Cum, Now, S1, Bytes, Htna)
            end;
        error ->
            cum_loop(U + 1, Cum, Now, S, Bytes, Htna)
    end.

%% Gap blocks relative to Cum, sorted, validated and bounded by the TSNs
%% actually sent.
valid_gaps(Gaps, Cum, Next) ->
    Abs = [
        {Cum + St, min(Cum + En, Next - 1)}
     || {St, En} <- Gaps, St >= 1, En >= St, Cum + St < Next
    ],
    lists:usort(Abs).

gap_loop([], _Now, S, Bytes, Htna) ->
    {S, Bytes, Htna};
gap_loop([{A, B} | Rest], Now, S, Bytes, Htna) ->
    {S1, Bytes1, Htna1} = gap_range(A, B, Now, S, Bytes, Htna),
    gap_loop(Rest, Now, S1, Bytes1, Htna1).

gap_range(U, B, _Now, S, Bytes, Htna) when U > B ->
    {S, Bytes, Htna};
gap_range(U, B, Now, #snd{out = Out} = S, Bytes, Htna) ->
    case Out of
        #{U := #oc{state = inflight} = Oc} ->
            S1 = rtt_check(U, Oc, Now, S),
            S2 = S1#snd{
                out = Out#{U := Oc#oc{state = acked}},
                flight = S1#snd.flight - Oc#oc.size,
                flight_len = S1#snd.flight_len - Oc#oc.len
            },
            gap_range(U + 1, B, Now, S2, Bytes + Oc#oc.size, U);
        #{U := #oc{state = rtx} = Oc} ->
            S1 = S#snd{
                out = Out#{U := Oc#oc{state = acked}},
                rtx_count = S#snd.rtx_count - 1
            },
            gap_range(U + 1, B, Now, S1, Bytes + Oc#oc.size, U);
        _ ->
            gap_range(U + 1, B, Now, S, Bytes, Htna)
    end.

%% A chunk previously gap acked but missing from this SACK was reneged:
%% treat it as outstanding again with one miss indication.
renege(Gaps, Now, #snd{out = Out} = S) ->
    maps:fold(
        fun
            (U, #oc{state = acked} = Oc, Acc) ->
                case covered(U, Gaps) of
                    true ->
                        Acc;
                    false ->
                        Acc#snd{
                            out = (Acc#snd.out)#{
                                U := Oc#oc{state = inflight, missing = Oc#oc.missing + 1}
                            },
                            flight = Acc#snd.flight + Oc#oc.size,
                            flight_len = Acc#snd.flight_len + Oc#oc.len,
                            t3 =
                                case Acc#snd.t3 of
                                    undefined -> Now + Acc#snd.rto;
                                    T -> T
                                end
                        }
                end;
            (_, _, Acc) ->
                Acc
        end,
        S,
        Out
    ).

covered(_U, []) -> false;
covered(U, [{A, B} | _]) when U >= A, U =< B -> true;
covered(U, [_ | R]) -> covered(U, R).

miss_loop(U, Bound, S, Fast) when U >= Bound ->
    {S, lists:reverse(Fast)};
miss_loop(U, Bound, #snd{out = Out} = S, Fast) ->
    case Out of
        #{U := #oc{state = inflight, fast = false, missing = M} = Oc} ->
            M1 = M + 1,
            S1 = S#snd{out = Out#{U := Oc#oc{missing = M1}}},
            case M1 >= 3 of
                true -> miss_loop(U + 1, Bound, S1, [U | Fast]);
                false -> miss_loop(U + 1, Bound, S1, Fast)
            end;
        _ ->
            miss_loop(U + 1, Bound, S, Fast)
    end.

grow_cwnd(0, _FlightBefore, S) ->
    S;
grow_cwnd(Bytes, FlightBefore, #snd{cwnd = Cwnd, ssthresh = Ss, mtu = Mtu} = S) when Cwnd =< Ss ->
    %% Slow start: only when the window was fully used and not in fast
    %% recovery; at most one MTU per SACK (L = 1).
    case S#snd.fr_exit =:= undefined andalso FlightBefore + Mtu > Cwnd of
        true -> S#snd{cwnd = Cwnd + min(Bytes, Mtu)};
        false -> S
    end;
grow_cwnd(Bytes, FlightBefore, #snd{cwnd = Cwnd, mtu = Mtu, pba = Pba0} = S) ->
    Pba = Pba0 + Bytes,
    if
        Pba >= Cwnd, FlightBefore + Mtu > Cwnd ->
            S#snd{pba = Pba - Cwnd, cwnd = Cwnd + Mtu};
        Pba > Cwnd ->
            S#snd{pba = Cwnd};
        true ->
            S#snd{pba = Pba}
    end.

%% Mark chunks with three miss indications for fast retransmission and
%% reduce the window once per recovery period.
fast_mark([], S) ->
    S;
fast_mark(Tsns, #snd{out = Out0} = S0) ->
    S1 =
        case S0#snd.fr_exit of
            undefined ->
                Ss = max(S0#snd.cwnd div 2, 4 * S0#snd.mtu),
                bump(fast_recoveries, S0#snd{
                    ssthresh = Ss,
                    cwnd = Ss,
                    pba = 0,
                    fr_exit = S0#snd.next_tsn - 1
                });
            _ ->
                S0
        end,
    {Out, S2} =
        lists:foldl(
            fun(U, {O, Acc}) ->
                Oc = maps:get(U, O),
                Acc1 = Acc#snd{
                    flight = Acc#snd.flight - Oc#oc.size,
                    flight_len = Acc#snd.flight_len - Oc#oc.len,
                    rwnd = Acc#snd.rwnd + Oc#oc.len,
                    rtx_count = Acc#snd.rtx_count + 1
                },
                {O#{U := Oc#oc{state = rtx, fast = true}}, Acc1}
            end,
            {Out0, S1},
            Tsns
        ),
    S3 = S2#snd{out = Out, fast_list = Tsns ++ S2#snd.fast_list},
    S4 = cancel_probe(lists:min(Tsns), S3),
    lists:foldl(fun(_, Acc) -> bump(fast_retransmits, Acc) end, S4, Tsns).

%% RFC 3758 C3 with the duplicate limiting of the F2 implementation
%% note: repeat an unchanged FORWARD TSN at most once per RTT. Until the
%% peer acknowledges it, T3-rtx keeps running even with nothing in
%% flight (A5): a lost FORWARD TSN that the limit held back is then sent
%% again on expiry.
pr_after_sack(_Now, #snd{pr = false} = S) ->
    S;
pr_after_sack(Now, #snd{adv = Adv, cum = Cum} = S0) when Adv > Cum ->
    S =
        case S0#snd.t3 of
            undefined -> S0#snd{t3 = Now + S0#snd.rto};
            _ -> S0
        end,
    case S#snd.fwd_last of
        {Adv, At} when Now - At < S#snd.rto -> S;
        _ -> S#snd{fwd_pending = true}
    end;
pr_after_sack(_Now, S) ->
    S.

%%====================================================================
%% T3-rtx expiry (RFC 9260 §6.3.3)
%%====================================================================

%% @doc Handle a T3-rtx expiry. Returns whether the expiry counts
%% toward the association error counter: probes of a closed window that
%% keep being answered by SACKs do not (§6.1 A).
-spec handle_t3(integer(), #snd{}) -> {#snd{}, boolean()}.
handle_t3(Now, #snd{flight = 0, rtx_count = 0, adv = Adv, cum = Cum} = S) when Adv > Cum ->
    %% Only a FORWARD TSN is outstanding (RFC 3758 A5).
    {S#snd{t3 = Now + S#snd.rto, fwd_pending = true}, true};
handle_t3(_Now, #snd{flight = 0, rtx_count = 0} = S) ->
    {S#snd{t3 = undefined}, false};
handle_t3(Now, #snd{mtu = Mtu} = S0) ->
    Probing = S0#snd.zwp_interval > 0,
    Answered =
        case S0#snd.last_sack of
            undefined -> false;
            T -> Now - T < S0#snd.rto
        end,
    Ss = max(S0#snd.cwnd div 2, 4 * Mtu),
    S1 = S0#snd{
        ssthresh = Ss,
        cwnd = Mtu,
        pba = 0,
        fr_exit = undefined,
        rto = min(S0#snd.rto * 2, S0#snd.rto_max),
        rtt_probe = undefined,
        t3 = undefined
    },
    %% Mark every chunk in flight for retransmission (E3).
    {Out, S2} =
        maps:fold(
            fun
                (U, #oc{state = inflight} = Oc, {O, Acc}) ->
                    {O#{U := Oc#oc{state = rtx}}, Acc#snd{
                        flight = Acc#snd.flight - Oc#oc.size,
                        flight_len = Acc#snd.flight_len - Oc#oc.len,
                        rwnd = Acc#snd.rwnd + Oc#oc.len,
                        rtx_count = Acc#snd.rtx_count + 1
                    }};
                (_, _, Acc) ->
                    Acc
            end,
            {S1#snd.out, S1},
            S1#snd.out
        ),
    S3 = S2#snd{out = Out, fast_list = []},
    %% Partial reliability: abandon what may not be retransmitted (A5).
    S4 = abandon_expired(Now, S3),
    S5 =
        case S4#snd.pr andalso S4#snd.adv > S4#snd.cum of
            true -> S4#snd{fwd_pending = true};
            false -> S4
        end,
    {bump(t3_expirations, S5), not (Probing andalso Answered)}.

abandon_expired(Now, #snd{out = Out} = S) ->
    Msgs = lists:usort([
        M
     || #oc{state = rtx, msg = M} = Oc <- maps:values(Out),
        expired(Oc, Now) orelse exceeded(Oc)
    ]),
    lists:foldl(fun(M, Acc) -> webrtc_sctp_pr:abandon(M, Now, Acc) end, S, Msgs).

expired(#oc{expires = infinity}, _Now) -> false;
expired(#oc{expires = E}, Now) -> Now >= E.

exceeded(#oc{max_rtx = infinity}) -> false;
exceeded(#oc{max_rtx = M, tx = Tx}) -> Tx > M.

%%====================================================================
%% RTO (RFC 9260 §6.3.1)
%%====================================================================

rtt_check(U, #oc{tx = 1}, Now, #snd{rtt_probe = {U, Sent}} = S) ->
    rtt_sample(Now - Sent, S#snd{rtt_probe = undefined});
rtt_check(U, _Oc, _Now, #snd{rtt_probe = {U, _}} = S) ->
    S#snd{rtt_probe = undefined};
rtt_check(_U, _Oc, _Now, S) ->
    S.

cancel_probe(U, #snd{rtt_probe = {P, _}} = S) when U =< P -> S#snd{rtt_probe = undefined};
cancel_probe(_U, S) -> S.

%% @doc Feed a round trip measurement in milliseconds (rules C2, C3, C6,
%% C7 and G1 with a 1 ms clock granularity).
-spec rtt_sample(integer(), #snd{}) -> #snd{}.
rtt_sample(R0, #snd{srtt = undefined} = S) ->
    R = max(R0, 0),
    Var = max(R div 2, 1),
    set_rto(S#snd{srtt = R, rttvar = Var});
rtt_sample(R0, #snd{srtt = Srtt, rttvar = Var0} = S) ->
    R = max(R0, 0),
    %% RTO.Beta = 1/4, RTO.Alpha = 1/8.
    Var = max((3 * Var0 + abs(Srtt - R)) div 4, 1),
    NewSrtt = (7 * Srtt + R) div 8,
    set_rto(S#snd{srtt = NewSrtt, rttvar = Var}).

set_rto(#snd{srtt = Srtt, rttvar = Var, rto_min = Min, rto_max = Max} = S) ->
    S#snd{rto = min(max(Srtt + 4 * Var, Min), Max)}.

sub0(A, B) when A > B -> A - B;
sub0(_, _) -> 0.

bump(K, #snd{stats = St} = S) ->
    S#snd{stats = maps:update_with(K, fun(V) -> V + 1 end, 1, St)}.
