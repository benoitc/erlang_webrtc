%% @doc RTP media circuit breakers (RFC 8083 §4), as a sans-IO engine.
%%
%% Streams are identified by an opaque key (the media session uses the
%% mid). `sent/4' records every RTP packet sent, `report/5' every RTCP
%% report block about the stream, with the round-trip time when known.
%% Three breakers are implemented; each reports
%% `{circuit_breaker, Key, Reason}' once when it triggers, and is
%% re-armed when the condition clears:
%%
%% <ul>
%% <li>`rtcp_timeout' (§4.1): packets were sent but no report block
%%     arrived for `rtcp_timeout' ms, three times the deterministic
%%     reporting interval with Tmin = 5 s (default 15000).</li>
%% <li>`media_timeout' (§4.2): MEDIA_TIMEOUT consecutive reports show a
%%     non-increasing extended highest sequence number while packets were
%%     sent, MEDIA_TIMEOUT = ceil(k x max(Tr, Tdr) / Tdr) with k = 5. The
%%     frame interval Tf is not known to this layer and is left out.</li>
%% <li>`congestion' (§4.3): over the last CB_INTERVAL reports (fraction
%%     lost weighted by the reporting intervals), the sending rate is
%%     more than ten times the simplified TCP throughput
%%     X = s / (Tr sqrt(2 b p / 3)) with b = 1. CB_INTERVAL =
%%     ceil(3 min(max(10 Tr, 3 Tdr), max(15, 3 Td)) / (3 Tdr)), the 10 G
%%     Tf term being unknown. Only checked when the RTT is known and a
%%     packet was sent in every reporting interval.</li>
%% </ul>
%%
%% RFC 8083 says the sender SHOULD then cease transmission: this module
%% detects, `webrtc_cc' acts (rate cut by ten then halt for congestion,
%% halt for the timeouts).
-module(webrtc_circuit_breaker).

-include("webrtc_rtp_rtcp.hrl").

-export([new/1, sent/4, report/5, rearm_congestion/2, handle_timeout/2, next_timeout/1, stats/1]).

-export_type([state/0, event/0]).

-type reason() :: rtcp_timeout | media_timeout | congestion.
-type event() :: {circuit_breaker, term(), reason()}.

-define(K, 5).
-define(MAX_REPORTS, 64).

-record(s, {
    first_sent :: integer(),
    last_sent :: integer(),
    packets = 0 :: non_neg_integer(),
    bytes = 0 :: non_neg_integer(),
    total_packets = 0 :: non_neg_integer(),
    total_bytes = 0 :: non_neg_integer(),
    last_report :: undefined | integer(),
    last_ext_seq :: undefined | non_neg_integer(),
    stalled = 0 :: non_neg_integer(),
    %% Newest first: {IntervalMs, FractionLost, Bytes, Packets}.
    reports = [] :: [{pos_integer(), float(), non_neg_integer(), non_neg_integer()}],
    tripped = [] :: [reason()]
}).

-record(cb, {
    rtcp_timeout :: pos_integer(),
    %% Our own deterministic RTCP interval Td, ms.
    td :: pos_integer(),
    streams = #{} :: #{term() => #s{}}
}).

-opaque state() :: #cb{}.

-spec new(map()) -> state().
new(Opts) ->
    #cb{rtcp_timeout = maps:get(rtcp_timeout, Opts, 15000), td = maps:get(td, Opts, 1000)}.

-spec sent(term(), non_neg_integer(), integer(), state()) -> state().
sent(Key, Size, Now, #cb{streams = Ss} = Cb) ->
    S0 =
        case maps:find(Key, Ss) of
            {ok, #s{packets = 0, last_sent = L} = S} when Now - L >= Cb#cb.rtcp_timeout ->
                %% Sending again after a long pause: start over.
                S#s{first_sent = Now, last_report = undefined, stalled = 0};
            {ok, S} ->
                S;
            error ->
                #s{first_sent = Now, last_sent = Now}
        end,
    S1 = S0#s{
        last_sent = Now,
        packets = S0#s.packets + 1,
        bytes = S0#s.bytes + Size,
        total_packets = S0#s.total_packets + 1,
        total_bytes = S0#s.total_bytes + Size
    },
    Cb#cb{streams = Ss#{Key => S1}}.

%% @doc RFC 8083 §4.3: after the sender cut its rate by ten, the
%% congestion breaker is evaluated afresh over the next CB_INTERVAL
%% reports; a new trigger then means the sender must cease.
-spec rearm_congestion(term(), state()) -> state().
rearm_congestion(Key, #cb{streams = Ss} = Cb) ->
    case maps:find(Key, Ss) of
        {ok, S} -> Cb#cb{streams = Ss#{Key => (untrip(congestion, S))#s{reports = []}}};
        error -> Cb
    end.

-spec report(term(), #rtcp_rb{}, non_neg_integer() | undefined, integer(), state()) -> {[event()], state()}.
report(Key, #rtcp_rb{} = Rb, Rtt, Now, #cb{streams = Ss} = Cb) ->
    case maps:find(Key, Ss) of
        error ->
            {[], Cb};
        {ok, S0} ->
            Since =
                case S0#s.last_report of
                    undefined -> S0#s.first_sent;
                    L -> L
                end,
            Interval = max(1, Now - Since),
            S1 = S0#s{
                reports = lists:sublist(
                    [{Interval, Rb#rtcp_rb.fraction_lost / 256, S0#s.bytes, S0#s.packets} | S0#s.reports],
                    ?MAX_REPORTS
                )
            },
            S2 = untrip(rtcp_timeout, S1),
            {E1, S3} = media_timeout(Key, Rb#rtcp_rb.ext_seq, Rtt, Interval, S2),
            {E2, S4} = congestion(Key, Rtt, Cb#cb.td, S3),
            S5 = S4#s{last_report = Now, last_ext_seq = Rb#rtcp_rb.ext_seq, packets = 0, bytes = 0},
            {E1 ++ E2, Cb#cb{streams = Ss#{Key := S5}}}
    end.

%% RFC 8083 §4.2.
media_timeout(_Key, _Ext, _Rtt, _Tdr, #s{packets = 0} = S) ->
    %% Not sending: the media timeout breaker is cancelled.
    {[], untrip(media_timeout, S#s{stalled = 0})};
media_timeout(Key, Ext, Rtt, Tdr, #s{last_ext_seq = Last} = S) when is_integer(Last), Ext =< Last ->
    Stalled = S#s.stalled + 1,
    Limit = ceil(?K * max(rtt_or(Rtt, 0), Tdr) / Tdr),
    case Stalled >= Limit of
        true -> trip(Key, media_timeout, S#s{stalled = Stalled});
        false -> {[], S#s{stalled = Stalled}}
    end;
media_timeout(_Key, _Ext, _Rtt, _Tdr, S) ->
    {[], untrip(media_timeout, S#s{stalled = 0})}.

%% RFC 8083 §4.3.
congestion(_Key, undefined, _Td, S) ->
    {[], S};
congestion(Key, Rtt, Td, #s{reports = Reports} = S) ->
    Tdr = lists:sum([I || {I, _, _, _} <- Reports]) / length(Reports) / 1000,
    Tr = max(Rtt, 1) / 1000,
    CbInterval = ceil(3 * min(max(10 * Tr, 3 * Tdr), max(15, 3 * Td / 1000)) / (3 * Tdr)),
    case length(Reports) > CbInterval of
        false ->
            {[], S};
        true ->
            Window = lists:sublist(Reports, CbInterval),
            Duration = lists:sum([I || {I, _, _, _} <- Window]),
            P = lists:sum([F * I || {I, F, _, _} <- Window]) / Duration,
            Bytes = lists:sum([B || {_, _, B, _} <- Window]),
            Packets = lists:sum([N || {_, _, _, N} <- Window]),
            Sending = lists:all(fun({_, _, _, N}) -> N > 0 end, Window),
            case Sending andalso P > 0 andalso Packets > 0 of
                false ->
                    {[], untrip(congestion, S)};
                true ->
                    Size = Bytes / Packets,
                    X = Size / (Tr * math:sqrt(2 * P / 3)),
                    Rate = Bytes * 1000 / Duration,
                    case Rate > 10 * X of
                        true -> trip(Key, congestion, S);
                        false -> {[], untrip(congestion, S)}
                    end
            end
    end.

rtt_or(undefined, D) -> D;
rtt_or(R, _) -> R.

trip(Key, Reason, #s{tripped = T} = S) ->
    case lists:member(Reason, T) of
        true -> {[], S};
        false -> {[{circuit_breaker, Key, Reason}], S#s{tripped = [Reason | T]}}
    end.

untrip(Reason, #s{tripped = T} = S) ->
    S#s{tripped = lists:delete(Reason, T)}.

%% RFC 8083 §4.1: packets sent since the last report (or since the
%% stream started) and no report for rtcp_timeout.
-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#cb{streams = Ss, rtcp_timeout = T}) ->
    maps:fold(
        fun(_, S, Acc) ->
            case rtcp_deadline(S, T) of
                infinity -> Acc;
                D when Acc =:= infinity -> D;
                D -> min(D, Acc)
            end
        end,
        infinity,
        Ss
    ).

rtcp_deadline(#s{packets = 0}, _T) ->
    infinity;
rtcp_deadline(#s{tripped = Tr} = S, T) ->
    case lists:member(rtcp_timeout, Tr) of
        true -> infinity;
        false -> since(S) + T
    end.

since(#s{last_report = undefined, first_sent = F}) -> F;
since(#s{last_report = L}) -> L.

-spec handle_timeout(integer(), state()) -> {[event()], state()}.
handle_timeout(Now, #cb{streams = Ss, rtcp_timeout = T} = Cb) ->
    {Events, Ss1} = maps:fold(
        fun(Key, S, {Es, Acc}) ->
            case rtcp_deadline(S, T) of
                D when D =/= infinity, Now >= D, Now - S#s.last_sent < T ->
                    {E, S1} = trip(Key, rtcp_timeout, S),
                    {E ++ Es, Acc#{Key => S1}};
                D when D =/= infinity, Now >= D ->
                    %% The stream stopped sending long ago: the breaker
                    %% is cancelled until it sends again.
                    {Es, Acc#{Key => S#s{packets = 0, bytes = 0}}};
                _ ->
                    {Es, Acc#{Key => S}}
            end
        end,
        {[], #{}},
        Ss
    ),
    {Events, Cb#cb{streams = Ss1}}.

-spec stats(state()) -> map().
stats(#cb{streams = Ss}) ->
    maps:map(fun(_, S) -> #{tripped => S#s.tripped, packets => S#s.total_packets, bytes => S#s.total_bytes} end, Ss).
