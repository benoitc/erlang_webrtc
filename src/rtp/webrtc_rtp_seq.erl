%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Wrapping arithmetic for RTP sequence numbers (16 bits) and
%% timestamps (32 bits), RFC 3550 §5.1 and Appendix A.1.
%%
%% Comparisons use serial number arithmetic: `A' is before `B' when the
%% forward distance from `A' to `B' is less than half the space. A
%% distance of exactly half the space counts as negative, so that
%% `seq_diff/2' stays in `-32768..32767'.
%%
%% `seq_unwrap/2' and `ts_unwrap/2' extend a wrapped value to the
%% unbounded integer closest to a previous extended value, which is how
%% receivers keep a monotonic index across wraparound.
-module(webrtc_rtp_seq).

-export([
    seq_add/2,
    seq_diff/2,
    seq_lt/2,
    seq_le/2,
    seq_gt/2,
    seq_unwrap/2,
    ts_add/2,
    ts_diff/2,
    ts_lt/2,
    ts_gt/2,
    ts_unwrap/2
]).

-export_type([seq/0, ts/0]).

-type seq() :: 0..65535.
-type ts() :: 0..16#FFFFFFFF.

-define(SEQ_MOD, 16#10000).
-define(TS_MOD, 16#100000000).

%% @doc `Seq + N' modulo 2^16 (`N' may be negative).
-spec seq_add(seq(), integer()) -> seq().
seq_add(Seq, N) ->
    mod(Seq + N, ?SEQ_MOD).

%% @doc Signed distance from `B' to `A' (`A - B'), in `-32768..32767'.
-spec seq_diff(seq(), seq()) -> -32768..32767.
seq_diff(A, B) ->
    signed(A - B, ?SEQ_MOD).

%% @doc True when `A' comes strictly before `B'.
-spec seq_lt(seq(), seq()) -> boolean().
seq_lt(A, B) ->
    seq_diff(A, B) < 0.

-spec seq_le(seq(), seq()) -> boolean().
seq_le(A, B) ->
    seq_diff(A, B) =< 0.

-spec seq_gt(seq(), seq()) -> boolean().
seq_gt(A, B) ->
    seq_diff(A, B) > 0.

%% @doc Extend `Seq' to the extended sequence number closest to `Last'
%% (itself extended). Use `undefined' for the first packet.
-spec seq_unwrap(seq(), integer() | undefined) -> integer().
seq_unwrap(Seq, undefined) ->
    Seq;
seq_unwrap(Seq, Last) ->
    Last + seq_diff(Seq, mod(Last, ?SEQ_MOD)).

-spec ts_add(ts(), integer()) -> ts().
ts_add(Ts, N) ->
    mod(Ts + N, ?TS_MOD).

%% @doc Signed distance `A - B' modulo 2^32.
-spec ts_diff(ts(), ts()) -> integer().
ts_diff(A, B) ->
    signed(A - B, ?TS_MOD).

-spec ts_lt(ts(), ts()) -> boolean().
ts_lt(A, B) ->
    ts_diff(A, B) < 0.

-spec ts_gt(ts(), ts()) -> boolean().
ts_gt(A, B) ->
    ts_diff(A, B) > 0.

-spec ts_unwrap(ts(), integer() | undefined) -> integer().
ts_unwrap(Ts, undefined) ->
    Ts;
ts_unwrap(Ts, Last) ->
    Last + ts_diff(Ts, mod(Last, ?TS_MOD)).

mod(X, M) ->
    ((X rem M) + M) rem M.

signed(X, M) ->
    V = mod(X, M),
    case V >= M div 2 of
        true -> V - M;
        false -> V
    end.
