%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Receiver side of RTP Control Protocol feedback for congestion
%% control (RFC 8888), as a sans-IO engine.
%%
%% `packet/5' records the arrival time and ECN mark of an RTP packet.
%% Every `interval' milliseconds (default 100) after the first
%% unreported arrival, `handle_timeout/2' emits one `#rtcp_ccfb{}' with,
%% per source, the run of sequence numbers from the first one not
%% reported yet to the highest received: each received packet with its
%% ECN codepoint and its arrival time offset before the report
%% timestamp (1/1024 s, 0x1FFE for that much or more), the others as not
%% received (RFC 8888 §3.1). A source reports at most MAX_PER_SOURCE
%% packets per message; older ones are skipped. At most MAX_SOURCES
%% sources are tracked.
-module(webrtc_ccfb_receiver).

-include("webrtc_rtp_rtcp.hrl").

-export([new/1, packet/5, handle_timeout/2, next_timeout/1, stats/1]).

-export_type([state/0]).

-define(MAX_PER_SOURCE, 16384).
-define(MAX_SOURCES, 64).
-define(ATO_MAX, 16#1FFE).

-record(src, {
    highest :: integer(),
    %% First unwrapped sequence number not reported yet.
    base :: integer(),
    got = #{} :: #{integer() => {integer(), 0..3}}
}).

-record(rx, {
    sender_ssrc :: 0..16#FFFFFFFF,
    interval :: pos_integer(),
    sources = #{} :: #{0..16#FFFFFFFF => #src{}},
    next_at = infinity :: integer() | infinity,
    sent = 0 :: non_neg_integer(),
    ce = 0 :: non_neg_integer()
}).

-opaque state() :: #rx{}.

-spec new(map()) -> state().
new(Opts) ->
    #rx{sender_ssrc = maps:get(sender_ssrc, Opts, 0), interval = maps:get(interval, Opts, 100)}.

%% @doc Packet `Seq' of `Ssrc' arrived at `Now' (ms) with ECN codepoint
%% `Ecn' (0 not-ECT, 1 ECT(1), 2 ECT(0), 3 CE).
-spec packet(0..16#FFFFFFFF, 0..65535, 0..3, integer(), state()) -> state().
packet(Ssrc, Seq, Ecn, Now, #rx{sources = Ss} = S) when is_map_key(Ssrc, Ss); map_size(Ss) < ?MAX_SOURCES ->
    Src =
        case maps:find(Ssrc, Ss) of
            {ok, #src{highest = H} = Src0} ->
                Ext = webrtc_rtp_seq:seq_unwrap(Seq, H),
                case Ext >= Src0#src.base of
                    true -> Src0#src{highest = max(H, Ext), got = (Src0#src.got)#{Ext => {Now, Ecn}}};
                    false -> Src0
                end;
            error ->
                #src{highest = Seq, base = Seq, got = #{Seq => {Now, Ecn}}}
        end,
    Next = case S#rx.next_at of infinity -> Now + S#rx.interval; At -> At end,
    S#rx{sources = Ss#{Ssrc => Src}, next_at = Next, ce = S#rx.ce + case Ecn of 3 -> 1; _ -> 0 end};
packet(_Ssrc, _Seq, _Ecn, _Now, S) ->
    S.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#rx{next_at = At}) -> At.

-spec handle_timeout(integer(), state()) -> {[#rtcp_ccfb{}], state()}.
handle_timeout(Now, #rx{next_at = At} = S) when At =/= infinity, Now >= At ->
    %% The report timestamp on the same clock as the arrivals (the
    %% sender only uses differences): compact NTP of `Now'.
    Ts = (Now * 65536 div 1000) band 16#FFFFFFFF,
    {Reports, Sources} = maps:fold(
        fun(Ssrc, #src{highest = H, base = B0, got = Got} = Src, {Acc, SAcc}) when map_size(Got) > 0 ->
                B = max(B0, H - ?MAX_PER_SOURCE + 1),
                Metrics = [metric(maps:get(E, Got, undefined), Now) || E <- lists:seq(B, H)],
                {[{Ssrc, B band 16#FFFF, Metrics} | Acc], SAcc#{Ssrc => Src#src{base = H + 1, got = #{}}}};
           (Ssrc, Src, {Acc, SAcc}) ->
                {Acc, SAcc#{Ssrc => Src}}
        end,
        {[], #{}},
        S#rx.sources
    ),
    S1 = S#rx{sources = Sources, next_at = infinity},
    case Reports of
        [] -> {[], S1};
        _ -> {[#rtcp_ccfb{sender_ssrc = S#rx.sender_ssrc, reports = lists:sort(Reports), timestamp = Ts}],
              S1#rx{sent = S#rx.sent + 1}}
    end;
handle_timeout(_Now, S) ->
    {[], S}.

metric(undefined, _Now) -> not_received;
metric({At, Ecn}, Now) -> {Ecn, min(?ATO_MAX, ((Now - At) * 1024 + 999) div 1000)}.

-spec stats(state()) -> map().
stats(#rx{} = S) ->
    #{feedback_sent => S#rx.sent, sources => map_size(S#rx.sources), ce_received => S#rx.ce}.
