%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Test-only TCP flow for the congestion control simulations (RFC 8867
%% §5.6, §5.7): RFC 5681 congestion control (slow start, congestion
%% avoidance, a halved window on loss) with SACK based loss recovery
%% (RFC 6675) and the RFC 6298 retransmission timer, and a receiver
%% with delayed ACKs (RFC 5681 §4.2). The receiver reports every
%% out-of-order range (SACK without the four block limit of RFC 2018).
%% Sequence numbers count bytes; times are milliseconds.
%%
%% The application is `long' (always data to send) or `{short, Opts}'
%% (RFC 8868 §5.1): files of 30 to 50 KB, each on a fresh connection
%% (initial window, no RTT estimate), separated by idle times drawn from
%% an exponential distribution of mean 10 s; `start => on | off'.
-module(webrtc_cc_tcp).

-export([new/2, output/2, ack/3, timeout/2, next_timeout/1, delivered/1]).
-export([receiver/0, recv/4, rtimeout/2]).

-define(MSS, 1460).
%% RFC 5681 §3.1: IW for an SMSS between 1095 and 2190 bytes.
-define(IW, 3 * ?MSS).
%% RFC 6675 DupThresh, in bytes SACKed above a hole.
-define(DUP_BYTES, 3 * ?MSS).
-define(MIN_RTO, 1000).
-define(DELACK, 200).

%%====================================================================
%% Sender
%%====================================================================

new(App, Seed) ->
    S0 = #{
        app => App,
        rand => rand:seed_s(exsss, {Seed, 17, 31}),
        una => 0,
        nxt => 0,
        %% End of the data the application has given (infinity: long).
        limit => 0,
        cwnd => ?IW,
        ssthresh => 1 bsl 30,
        dupacks => 0,
        %% Loss recovery (RFC 6675 §5): the recovery point and the
        %% highest byte retransmitted, undefined outside recovery.
        recover => undefined,
        high_rxt => 0,
        %% SACKed ranges above una, from the latest ACK.
        sacked => [],
        srtt => undefined,
        rttvar => undefined,
        rto => ?MIN_RTO,
        rto_at => infinity,
        %% One timed segment at a time, never a retransmitted one (Karn).
        timed => undefined,
        retx_high => 0,
        idle_until => 0,
        files => 0
    },
    case App of
        long ->
            S0#{limit := infinity};
        {short, Opts} ->
            case maps:get(start, Opts, on) of
                on -> new_file(S0);
                off -> idle(0, S0)
            end
    end.

%% Segments to send now: [{Seq, Len}].
output(Now, S0) ->
    send(Now, wake(Now, S0), []).

send(Now, S, Acc) ->
    case next_segment(S) of
        {new, Seq, Len} ->
            S1 = time_segment(Seq, Len, Now, S#{nxt := Seq + Len}),
            send(Now, arm(Now, S1), [{Seq, Len} | Acc]);
        {rxt, Seq, Len} ->
            send(Now, arm(Now, S#{high_rxt := Seq + Len}), [{Seq, Len} | Acc]);
        none ->
            {lists:reverse(Acc), S}
    end.

%% RFC 6675 §5 (NextSeg) during recovery, the window otherwise.
next_segment(#{recover := undefined, una := Una, nxt := Nxt, cwnd := W} = S) ->
    new_data(Nxt, Una + W - Nxt, S);
next_segment(#{cwnd := W, nxt := Nxt} = S) ->
    case W - pipe(S) >= ?MSS of
        true ->
            case first_lost(S) of
                {Seq, End} -> {rxt, Seq, min(?MSS, End - Seq)};
                none -> new_data(Nxt, ?MSS, S)
            end;
        false ->
            none
    end.

new_data(Nxt, Room, #{limit := Lim}) ->
    Left = case Lim of infinity -> ?MSS; _ -> Lim - Nxt end,
    Len = min(?MSS, min(Room, Left)),
    case Len > 0 andalso (Len =:= ?MSS orelse Left =< ?MSS) of
        true -> {new, Nxt, Len};
        false -> none
    end.

time_segment(Seq, Len, Now, #{timed := undefined, retx_high := H} = S) when Seq >= H ->
    S#{timed := {Seq + Len, Now}};
time_segment(_, _, _, S) ->
    S.

arm(Now, #{rto_at := infinity, rto := Rto} = S) -> S#{rto_at := Now + Rto};
arm(_Now, S) -> S.

%% Holes below the highest SACKed byte, those with DupThresh bytes
%% SACKed above them being lost (RFC 6675 §4 IsLost).
holes(#{una := Una, sacked := Sacked}) ->
    holes(Una, Sacked, []).

holes(From, [{S, E} | Rest], Acc) when S > From -> holes(E, Rest, [{From, S} | Acc]);
holes(_From, [{_, E} | Rest], Acc) -> holes(E, Rest, Acc);
holes(_From, [], Acc) -> lists:reverse(Acc).

lost(#{sacked := Sacked} = S) ->
    [{A, B} || {A, B} <- holes(S), sacked_above(A, Sacked) >= ?DUP_BYTES].

sacked_above(X, Sacked) -> lists:sum([E - max(S, X) || {S, E} <- Sacked, E > X]).

first_lost(#{high_rxt := H} = S) ->
    case [{max(A, H), B} || {A, B} <- lost(S), B > H] of
        [L | _] -> L;
        [] -> none
    end.

%% RFC 6675 §4 SetPipe: bytes in flight, a lost byte counting only once
%% it is retransmitted.
pipe(#{una := Una, nxt := Nxt, sacked := Sacked, high_rxt := H} = S) ->
    NotSacked = Nxt - Una - lists:sum([E - St || {St, E} <- Sacked]),
    LostAbove = lists:sum([B - max(A, H) || {A, B} <- lost(S), B > H]),
    NotSacked - LostAbove.

%% An ACK: {Cumulative, SACK ranges}.
ack({Ack, Sacks}, Now, #{una := Una} = S0) ->
    S = S0#{sacked := merge([{A, B} || {A, B} <- Sacks, B > Ack])},
    if
        Ack > Una -> new_ack(Ack, Now, S);
        Ack =:= Una, map_get(nxt, S) > Una -> dup_ack(S);
        true -> S
    end.

new_ack(Ack, Now, #{una := Una} = S0) ->
    S1 = rtt_sample(Ack, Now, S0#{una := Ack, nxt := max(Ack, maps:get(nxt, S0)),
                                  high_rxt := max(Ack, maps:get(high_rxt, S0))}),
    S2 =
        case maps:get(recover, S1) of
            undefined -> grow(Ack - Una, S1#{dupacks := 0});
            %% RFC 6675 §5 step (A) is over: back to congestion avoidance.
            Rec when Ack >= Rec -> S1#{recover := undefined, dupacks := 0, cwnd := maps:get(ssthresh, S1)};
            _ -> S1
        end,
    RtoAt = case Ack >= maps:get(nxt, S2) of true -> infinity; false -> Now + maps:get(rto, S2) end,
    S2#{rto_at := RtoAt}.

dup_ack(#{recover := undefined} = S) ->
    D = maps:get(dupacks, S) + 1,
    case D >= 3 orelse sacked_above(maps:get(una, S), maps:get(sacked, S)) >= ?DUP_BYTES of
        true ->
            %% RFC 6675 §5 step (4): halve, enter recovery.
            Ss = max(flight(S) div 2, 2 * ?MSS),
            S#{dupacks := D, ssthresh := Ss, cwnd := Ss, recover := maps:get(nxt, S), high_rxt := maps:get(una, S),
               timed := undefined, retx_high := maps:get(nxt, S)};
        false ->
            S#{dupacks := D}
    end;
dup_ack(S) ->
    S.

grow(Acked, #{cwnd := W, ssthresh := Ss} = S) when W < Ss ->
    S#{cwnd := W + min(Acked, ?MSS)};
grow(_Acked, #{cwnd := W} = S) ->
    S#{cwnd := W + max(1, ?MSS * ?MSS div W)}.

flight(#{nxt := Nxt, una := Una}) -> Nxt - Una.

merge(Ranges) -> merge(lists:sort(Ranges), []).

merge([{S, E} | Rest], [{PS, PE} | Acc]) when S =< PE -> merge(Rest, [{PS, max(E, PE)} | Acc]);
merge([R | Rest], Acc) -> merge(Rest, [R | Acc]);
merge([], Acc) -> lists:reverse(Acc).

%% RFC 6298 §2.
rtt_sample(Ack, Now, #{timed := {End, At}} = S) when Ack >= End ->
    R = Now - At,
    {Srtt, Var} =
        case maps:get(srtt, S) of
            undefined -> {R, R / 2};
            S0 -> {0.875 * S0 + 0.125 * R, 0.75 * maps:get(rttvar, S) + 0.25 * abs(S0 - R)}
        end,
    S#{srtt := Srtt, rttvar := Var, rto := max(?MIN_RTO, round(Srtt + max(1, 4 * Var))), timed := undefined};
rtt_sample(_, _, S) ->
    S.

%% The retransmission timer (RFC 6298 §5, RFC 5681 §3.1): one segment
%% window, everything after una sent again.
timeout(Now, #{rto_at := At} = S) when At =/= infinity, Now >= At ->
    Una = maps:get(una, S),
    Rto = min(60000, 2 * maps:get(rto, S)),
    S#{
        ssthresh := max(flight(S) div 2, 2 * ?MSS),
        cwnd := ?MSS,
        retx_high := maps:get(nxt, S),
        nxt := Una,
        high_rxt := Una,
        sacked := [],
        dupacks := 0,
        recover := undefined,
        timed := undefined,
        rto := Rto,
        rto_at := Now + Rto
    };
timeout(_Now, S) ->
    S.

next_timeout(#{rto_at := At}) -> At.

%% Bytes acknowledged so far.
delivered(#{una := Una}) -> Una.

%% Short flows: a finished file starts an idle period, an idle period
%% that ended starts the next file.
wake(Now, #{app := {short, _}, limit := L, una := Una} = S) when Una >= L ->
    case maps:get(idle_until, S) of
        undefined -> idle(Now, S);
        I when Now >= I -> new_file(S);
        _ -> S
    end;
wake(_Now, S) ->
    S.

idle(Now, #{rand := R0} = S) ->
    {U, R} = rand:uniform_s(R0),
    S#{rand := R, idle_until := Now + round(-10000 * math:log(U))}.

new_file(#{rand := R0, nxt := Nxt} = S) ->
    {U, R} = rand:uniform_s(R0),
    Size = 30000 + round(20000 * U),
    %% A fresh connection: initial window and no RTT estimate.
    S#{rand := R, limit := Nxt + Size, una := Nxt, idle_until := undefined, cwnd := ?IW, ssthresh := 1 bsl 30,
       srtt := undefined, rttvar := undefined, rto := ?MIN_RTO, dupacks := 0, recover := undefined,
       high_rxt := Nxt, sacked := [], retx_high := Nxt, files := maps:get(files, S) + 1}.

%%====================================================================
%% Receiver
%%====================================================================

receiver() ->
    #{next => 0, ooo => [], unacked => 0, ack_at => infinity, bytes => 0}.

%% A segment arrives: the ACKs to send now, as {Cumulative, SACKs}.
recv(Seq, Len, Now, #{next := Next} = R) when Seq =< Next, Seq + Len > Next ->
    {Next1, Ooo} = fill(Seq + Len, maps:get(ooo, R)),
    R1 = R#{next := Next1, ooo := Ooo, bytes := maps:get(bytes, R) + (Next1 - Next)},
    case maps:get(ooo, R) =/= [] orelse maps:get(unacked, R1) >= 1 of
        %% Every second full segment, and at once when a hole is filled.
        true -> {[{Next1, Ooo}], R1#{unacked := 0, ack_at := infinity}};
        false -> {[], R1#{unacked := 1, ack_at := Now + ?DELACK}}
    end;
recv(Seq, Len, _Now, #{next := Next} = R) when Seq > Next ->
    %% Out of order: an immediate duplicate ACK (RFC 5681 §4.2).
    Ooo = merge([{Seq, Seq + Len} | maps:get(ooo, R)]),
    {[{Next, Ooo}], R#{ooo := Ooo, unacked := 0, ack_at := infinity}};
recv(_Seq, _Len, _Now, #{next := Next, ooo := Ooo} = R) ->
    {[{Next, Ooo}], R}.

fill(Next, [{S, E} | Rest]) when S =< Next -> fill(max(Next, E), Rest);
fill(Next, Ooo) -> {Next, Ooo}.

rtimeout(Now, #{ack_at := At, next := Next, ooo := Ooo} = R) when Now >= At ->
    {[{Next, Ooo}], R#{unacked := 0, ack_at := infinity}};
rtimeout(_Now, R) ->
    {[], R}.
