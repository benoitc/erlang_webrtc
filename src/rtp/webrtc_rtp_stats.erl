%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc RTP receiver and sender statistics (RFC 3550 §6.4, Appendix A).
%%
%% Receiver side, one state per remote source:
%% <ul>
%% <li>`rx_packet/4' runs the sequence number validation of Appendix
%% A.1 (probation of `min_sequential' packets, `max_dropout',
%% `max_misorder', 16-bit cycle counting) and, for packets it accepts,
%% the interarrival jitter estimate of Appendix A.8.</li>
%% <li>`report_block/2' builds a reception report block with the
%% cumulative and interval loss of Appendix A.3 and LSR / DLSR from the
%% last SR passed to `rx_sender_report/3'.</li>
%% </ul>
%% Times (`Now') are integers in `time_unit' ticks per second (default
%% 1000, i.e. milliseconds) on any monotonic clock. The jitter needs the
%% media clock rate.
%%
%% Sender side: `tx_packet/2' counts packets and payload octets for the
%% SR sender info (§6.4.1); `sender_report/5' builds the SR.
%%
%% `rtt/3' computes the round-trip time from a report block's LSR and
%% DLSR (§6.4.1) or an XR DLRR sub-block (RFC 3611 §4.5). NTP helpers
%% convert between Unix microseconds and 64-bit NTP timestamps.
-module(webrtc_rtp_stats).

-include("webrtc_rtp_rtcp.hrl").

-export([
    rx_new/2,
    rx_packet/4,
    rx_sender_report/3,
    report_block/2,
    rx_info/1,
    tx_new/0,
    tx_packet/2,
    tx_info/1,
    sender_report/5,
    rtt/3,
    ntp_from_us/1,
    ntp_to_us/1,
    ntp_middle/1
]).

-export_type([rx/0, tx/0, rx_opts/0]).

-define(SEQ_MOD, 16#10000).
%% Seconds between 1900-01-01 and 1970-01-01.
-define(NTP_UNIX_OFFSET, 2208988800).

-record(rx, {
    ssrc :: 0..16#FFFFFFFF,
    clock_rate :: pos_integer(),
    time_unit :: pos_integer(),
    min_sequential :: non_neg_integer(),
    max_dropout :: pos_integer(),
    max_misorder :: pos_integer(),
    started = false :: boolean(),
    probation = 0 :: non_neg_integer(),
    max_seq = 0 :: 0..65535,
    base_seq = 0 :: 0..65535,
    bad_seq = ?SEQ_MOD + 1 :: 0..65537,
    cycles = 0 :: non_neg_integer(),
    received = 0 :: non_neg_integer(),
    expected_prior = 0 :: integer(),
    received_prior = 0 :: non_neg_integer(),
    transit = undefined :: undefined | integer(),
    %% Jitter scaled by 16 (Appendix A.8 integer form).
    jitter = 0 :: non_neg_integer(),
    last_sr = undefined :: undefined | {Lsr :: 0..16#FFFFFFFF, Arrival :: integer()}
}).

-record(tx, {
    packets = 0 :: non_neg_integer(),
    octets = 0 :: non_neg_integer()
}).

-opaque rx() :: #rx{}.
-opaque tx() :: #tx{}.
-type rx_opts() :: #{
    clock_rate := pos_integer(),
    time_unit => pos_integer(),
    min_sequential => non_neg_integer(),
    max_dropout => pos_integer(),
    max_misorder => pos_integer()
}.

%%====================================================================
%% Receiver
%%====================================================================

%% @doc New receiver state for `Ssrc'. Defaults are the values of RFC
%% 3550 Appendix A.1: `min_sequential' 2, `max_dropout' 3000,
%% `max_misorder' 100.
-spec rx_new(0..16#FFFFFFFF, rx_opts()) -> rx().
rx_new(Ssrc, #{clock_rate := Rate} = Opts) when is_integer(Rate), Rate > 0 ->
    #rx{
        ssrc = Ssrc,
        clock_rate = Rate,
        time_unit = maps:get(time_unit, Opts, 1000),
        min_sequential = maps:get(min_sequential, Opts, 2),
        max_dropout = maps:get(max_dropout, Opts, 3000),
        max_misorder = maps:get(max_misorder, Opts, 100)
    }.

%% @doc Account for a received packet. Returns `valid' when Appendix A.1
%% accepts the sequence number (the packet can be delivered) and
%% `invalid' during probation or after a large jump.
-spec rx_packet(0..65535, 0..16#FFFFFFFF, integer(), rx()) -> {valid | invalid, rx()}.
rx_packet(Seq, Ts, Now, #rx{started = false, min_sequential = MinSeq} = S0) ->
    %% First packet: init_seq(s, seq); max_seq = seq - 1; probation = MIN_SEQUENTIAL.
    S1 = init_seq(S0#rx{started = true}, Seq),
    S2 = S1#rx{max_seq = (Seq - 1) band 16#FFFF, probation = MinSeq},
    case MinSeq of
        0 -> accept(Seq, Ts, Now, S1#rx{received = 1});
        _ -> rx_packet(Seq, Ts, Now, S2)
    end;
rx_packet(Seq, Ts, Now, #rx{probation = P, max_seq = Max} = S) when P > 0 ->
    case Seq =:= ((Max + 1) band 16#FFFF) of
        true when P =:= 1 ->
            S1 = init_seq(S, Seq),
            accept(Seq, Ts, Now, S1#rx{probation = 0, received = S1#rx.received + 1});
        true ->
            {invalid, S#rx{probation = P - 1, max_seq = Seq}};
        false ->
            {invalid, S#rx{probation = S#rx.min_sequential - 1, max_seq = Seq}}
    end;
rx_packet(Seq, Ts, Now, #rx{max_seq = Max, max_dropout = Drop, max_misorder = Mis} = S) ->
    UDelta = (Seq - Max) band 16#FFFF,
    if
        UDelta < Drop ->
            Cycles =
                case Seq < Max of
                    true -> S#rx.cycles + ?SEQ_MOD;
                    false -> S#rx.cycles
                end,
            accept(Seq, Ts, Now, S#rx{max_seq = Seq, cycles = Cycles, received = S#rx.received + 1});
        UDelta =< ?SEQ_MOD - Mis ->
            case Seq =:= S#rx.bad_seq of
                true ->
                    %% Two sequential packets after a jump: the source
                    %% restarted, resynchronise.
                    S1 = init_seq(S, Seq),
                    accept(Seq, Ts, Now, S1#rx{received = S1#rx.received + 1, transit = undefined});
                false ->
                    {invalid, S#rx{bad_seq = (Seq + 1) band 16#FFFF}}
            end;
        true ->
            %% Duplicate or reordered packet.
            accept(Seq, Ts, Now, S#rx{received = S#rx.received + 1})
    end.

init_seq(S, Seq) ->
    S#rx{
        base_seq = Seq,
        max_seq = Seq,
        bad_seq = ?SEQ_MOD + 1,
        cycles = 0,
        received = 0,
        received_prior = 0,
        expected_prior = 0
    }.

%% Appendix A.8, integer form: jitter += |d| - ((jitter + 8) >> 4).
accept(_Seq, Ts, Now, #rx{clock_rate = Rate, time_unit = Unit, transit = Prev, jitter = J} = S) ->
    Arrival = (Now * Rate) div Unit,
    Transit = Arrival - Ts,
    J1 =
        case Prev of
            undefined ->
                J;
            _ ->
                D = abs(webrtc_rtp_seq:ts_diff(Transit band 16#FFFFFFFF, Prev band 16#FFFFFFFF)),
                max(0, J + D - ((J + 8) bsr 4))
        end,
    {valid, S#rx{transit = Transit, jitter = J1}}.

%% @doc Remember an SR received from this source, for LSR and DLSR.
-spec rx_sender_report(#rtcp_sr{}, integer(), rx()) -> rx().
rx_sender_report(#rtcp_sr{ntp = Ntp}, Now, S) ->
    S#rx{last_sr = {ntp_middle(Ntp), Now}}.

%% @doc Build a reception report block and start a new reporting
%% interval (Appendix A.3).
-spec report_block(integer(), rx()) -> {#rtcp_rb{}, rx()}.
report_block(Now, #rx{} = S) ->
    ExtMax = S#rx.cycles + S#rx.max_seq,
    Expected = expected(S),
    Lost = Expected - S#rx.received,
    ExpectedInterval = Expected - S#rx.expected_prior,
    ReceivedInterval = S#rx.received - S#rx.received_prior,
    LostInterval = ExpectedInterval - ReceivedInterval,
    Fraction =
        case ExpectedInterval =:= 0 orelse LostInterval =< 0 of
            true -> 0;
            false -> min(255, (LostInterval bsl 8) div ExpectedInterval)
        end,
    {Lsr, Dlsr} =
        case S#rx.last_sr of
            undefined ->
                {0, 0};
            {L, At} ->
                {L, min(16#FFFFFFFF, max(0, ((Now - At) * 65536) div S#rx.time_unit))}
        end,
    Block = #rtcp_rb{
        ssrc = S#rx.ssrc,
        fraction_lost = Fraction,
        lost = clamp_lost(Lost),
        ext_seq = ExtMax band 16#FFFFFFFF,
        jitter = min(16#FFFFFFFF, S#rx.jitter bsr 4),
        lsr = Lsr,
        dlsr = Dlsr
    },
    {Block, S#rx{expected_prior = Expected, received_prior = S#rx.received}}.

expected(#rx{started = false}) ->
    0;
expected(#rx{probation = P}) when P > 0 ->
    0;
expected(#rx{cycles = C, max_seq = M, base_seq = B}) ->
    C + M - B + 1.

%% 24-bit signed, clamped rather than wrapped (Appendix A.3).
clamp_lost(L) when L > 16#7FFFFF -> 16#7FFFFF;
clamp_lost(L) when L < -16#800000 -> -16#800000;
clamp_lost(L) -> L.

%% @doc Current receiver statistics. `jitter' is in RTP timestamp units.
-spec rx_info(rx()) ->
    #{
        ssrc := 0..16#FFFFFFFF,
        valid := boolean(),
        received := non_neg_integer(),
        expected := integer(),
        lost := integer(),
        ext_max_seq := non_neg_integer(),
        cycles := non_neg_integer(),
        jitter := non_neg_integer()
    }.
rx_info(#rx{} = S) ->
    Expected = expected(S),
    #{
        ssrc => S#rx.ssrc,
        valid => S#rx.started andalso S#rx.probation =:= 0,
        received => S#rx.received,
        expected => Expected,
        lost => Expected - S#rx.received,
        ext_max_seq => S#rx.cycles + S#rx.max_seq,
        cycles => S#rx.cycles div ?SEQ_MOD,
        jitter => S#rx.jitter bsr 4
    }.

%%====================================================================
%% Sender
%%====================================================================

-spec tx_new() -> tx().
tx_new() ->
    #tx{}.

%% @doc Count one sent RTP packet carrying `PayloadOctets' octets of
%% payload (header and padding excluded, RFC 3550 §6.4.1).
-spec tx_packet(non_neg_integer(), tx()) -> tx().
tx_packet(PayloadOctets, #tx{packets = P, octets = O}) when
    is_integer(PayloadOctets), PayloadOctets >= 0
->
    #tx{packets = P + 1, octets = O + PayloadOctets}.

-spec tx_info(tx()) -> #{packets := non_neg_integer(), octets := non_neg_integer()}.
tx_info(#tx{packets = P, octets = O}) ->
    #{packets => P, octets => O}.

%% @doc Build an SR. `RtpTs' is the RTP timestamp corresponding to the
%% same instant as `Ntp'. Counts wrap modulo 2^32 as on the wire.
-spec sender_report(0..16#FFFFFFFF, 0..16#FFFFFFFFFFFFFFFF, 0..16#FFFFFFFF, tx(), [#rtcp_rb{}]) ->
    #rtcp_sr{}.
sender_report(Ssrc, Ntp, RtpTs, #tx{packets = P, octets = O}, Blocks) ->
    #rtcp_sr{
        ssrc = Ssrc,
        ntp = Ntp,
        rtp_ts = RtpTs,
        packets = P band 16#FFFFFFFF,
        octets = O band 16#FFFFFFFF,
        reports = Blocks
    }.

%%====================================================================
%% Round-trip time and NTP
%%====================================================================

%% @doc Round-trip time in microseconds from the LSR and DLSR of a
%% report block (or the LRR and DLRR of an XR DLRR sub-block) and the
%% 64-bit NTP time at which the report arrived: `A - LSR - DLSR' in
%% 1/65536 s (RFC 3550 §6.4.1). `undefined' when LSR is 0 (no SR
%% received yet by the reporter). A negative result, caused by clock
%% drift, is reported as 0.
-spec rtt(0..16#FFFFFFFF, 0..16#FFFFFFFF, 0..16#FFFFFFFFFFFFFFFF) ->
    {ok, non_neg_integer()} | undefined.
rtt(0, _Dlsr, _Arrival) ->
    undefined;
rtt(Lsr, Dlsr, ArrivalNtp) ->
    A = ntp_middle(ArrivalNtp),
    Units = (A - Lsr - Dlsr) band 16#FFFFFFFF,
    case Units >= 16#80000000 of
        true -> {ok, 0};
        false -> {ok, (Units * 1000000) div 65536}
    end.

%% @doc 64-bit NTP timestamp from microseconds since the Unix epoch.
-spec ntp_from_us(non_neg_integer()) -> 0..16#FFFFFFFFFFFFFFFF.
ntp_from_us(Us) when is_integer(Us), Us >= 0 ->
    Secs = Us div 1000000 + ?NTP_UNIX_OFFSET,
    Frac = ((Us rem 1000000) bsl 32) div 1000000,
    ((Secs band 16#FFFFFFFF) bsl 32) bor Frac.

%% @doc Microseconds since the Unix epoch from a 64-bit NTP timestamp
%% (era 0).
-spec ntp_to_us(0..16#FFFFFFFFFFFFFFFF) -> integer().
ntp_to_us(Ntp) ->
    Secs = (Ntp bsr 32) - ?NTP_UNIX_OFFSET,
    Frac = Ntp band 16#FFFFFFFF,
    Secs * 1000000 + ((Frac * 1000000 + (1 bsl 31)) bsr 32).

%% @doc The middle 32 bits of a 64-bit NTP timestamp (LSR format).
-spec ntp_middle(0..16#FFFFFFFFFFFFFFFF) -> 0..16#FFFFFFFF.
ntp_middle(Ntp) ->
    (Ntp bsr 16) band 16#FFFFFFFF.
