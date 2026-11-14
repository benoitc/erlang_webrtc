%% @doc Receiver-side NACK generator (sans-IO).
%%
%% Feed every received RTP sequence number of one stream with
%% `packet/3' (for RTX packets, the original sequence number). Gaps are
%% remembered as missing; each missing packet is requested with a NACK
%% after `reorder_delay', then again every max(RTT, `min_interval') until
%% it arrives, `max_retries' requests have been sent or it is older than
%% `max_age'. The owner arms one timer at `next_timeout/1' and calls
%% `handle_timeout/2'.
%%
%% Actions:
%% <ul>
%% <li>`{nack, [Seq]}': send a generic NACK for these sequence numbers
%% (see `webrtc_rtcp_fb:nack_items/1');</li>
%% <li>`{give_up, [Seq]}': these packets will not be requested again;</li>
%% <li>`request_keyframe': the gap is too large to recover with NACK
%% (more than `max_missing' packets); send a PLI or FIR.</li>
%% </ul>
%% Times are integers in milliseconds on a monotonic clock.
-module(webrtc_nack).

-export([new/1, packet/3, handle_timeout/2, next_timeout/1, set_rtt/2, missing/1]).

-export_type([state/0, action/0, opts/0]).

-record(nack, {
    newest = undefined :: undefined | integer(),
    %% Extended seq => {FirstSeenAt, Retries, LastSentAt}
    missing = #{} :: #{integer() => {integer(), non_neg_integer(), integer() | undefined}},
    rtt :: non_neg_integer(),
    max_retries :: pos_integer(),
    max_age :: pos_integer(),
    max_missing :: pos_integer(),
    min_interval :: non_neg_integer(),
    reorder_delay :: non_neg_integer()
}).

-opaque state() :: #nack{}.
-type action() :: {nack, [0..65535]} | {give_up, [0..65535]} | request_keyframe.
-type opts() :: #{
    rtt => non_neg_integer(),
    max_retries => pos_integer(),
    max_age => pos_integer(),
    max_missing => pos_integer(),
    min_interval => non_neg_integer(),
    reorder_delay => non_neg_integer()
}.

%% @doc Defaults: rtt 100 ms, max_retries 10, max_age 1000 ms,
%% max_missing 1000, min_interval 5 ms, reorder_delay 0.
-spec new(opts()) -> state().
new(Opts) ->
    #nack{
        rtt = maps:get(rtt, Opts, 100),
        max_retries = maps:get(max_retries, Opts, 10),
        max_age = maps:get(max_age, Opts, 1000),
        max_missing = maps:get(max_missing, Opts, 1000),
        min_interval = maps:get(min_interval, Opts, 5),
        reorder_delay = maps:get(reorder_delay, Opts, 0)
    }.

-spec set_rtt(non_neg_integer(), state()) -> state().
set_rtt(Rtt, S) when is_integer(Rtt), Rtt >= 0 ->
    S#nack{rtt = Rtt}.

%% @doc Sequence numbers currently missing, oldest first.
-spec missing(state()) -> [0..65535].
missing(#nack{missing = M}) ->
    [E band 16#FFFF || E <- lists:sort(maps:keys(M))].

-spec packet(0..65535, integer(), state()) -> {state(), [action()]}.
packet(Seq, _Now, #nack{newest = undefined} = S) ->
    {S#nack{newest = Seq}, []};
packet(Seq, Now, #nack{newest = Newest, missing = M} = S) ->
    Ext = webrtc_rtp_seq:seq_unwrap(Seq, Newest),
    if
        Ext > Newest + 1 + S#nack.max_missing ->
            {S1, A1} = handle_timeout(Now, S#nack{newest = Ext, missing = #{}}),
            {S1, [request_keyframe | A1]};
        Ext > Newest ->
            M1 = lists:foldl(
                fun(E, Acc) -> Acc#{E => {Now, 0, undefined}} end,
                M,
                lists:seq(Newest + 1, Ext - 1)
            ),
            {M2, Trimmed} = trim(M1, S#nack.max_missing),
            {S1, A1} = handle_timeout(Now, S#nack{newest = Ext, missing = M2}),
            case Trimmed of
                true -> {S1, [request_keyframe | A1]};
                false -> {S1, A1}
            end;
        true ->
            handle_timeout(Now, S#nack{missing = maps:remove(Ext, M)})
    end.

trim(M, Max) when map_size(M) =< Max ->
    {M, false};
trim(M, Max) ->
    Drop = lists:sublist(lists:sort(maps:keys(M)), map_size(M) - Max),
    {maps:without(Drop, M), true}.

%% @doc Send due NACKs and drop expired entries.
-spec handle_timeout(integer(), state()) -> {state(), [action()]}.
handle_timeout(Now, #nack{missing = M} = S) ->
    Interval = max(S#nack.rtt, S#nack.min_interval),
    {Nack, GiveUp, M1} = maps:fold(
        fun(E, {First, Retries, _Last} = V, {N, G, Acc}) ->
            Due = due(V, S#nack.reorder_delay, Interval),
            if
                Now - First > S#nack.max_age ->
                    {N, [E | G], Acc};
                Now >= Due, Retries >= S#nack.max_retries ->
                    {N, [E | G], Acc};
                Now >= Due ->
                    {[E | N], G, Acc#{E => {First, Retries + 1, Now}}};
                true ->
                    {N, G, Acc#{E => V}}
            end
        end,
        {[], [], #{}},
        M
    ),
    Actions =
        [{nack, seqs(Nack)} || Nack =/= []] ++ [{give_up, seqs(GiveUp)} || GiveUp =/= []],
    {S#nack{missing = M1}, Actions}.

due({First, _, undefined}, Delay, _) -> First + Delay;
due({_, _, Last}, _, Interval) -> Last + Interval.

seqs(Ext) ->
    [E band 16#FFFF || E <- lists:sort(Ext)].

%% @doc Absolute time of the next NACK or expiry, or `infinity'.
-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#nack{missing = M}) when map_size(M) =:= 0 ->
    infinity;
next_timeout(#nack{missing = M} = S) ->
    Interval = max(S#nack.rtt, S#nack.min_interval),
    maps:fold(
        fun(_, {First, _, _} = V, Min) ->
            T = min(due(V, S#nack.reorder_delay, Interval), First + S#nack.max_age + 1),
            min(T, Min)
        end,
        infinity,
        M
    ).
