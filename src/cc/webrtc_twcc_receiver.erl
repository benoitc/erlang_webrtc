%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Receiver side of transport-wide congestion control
%% (draft-holmer-rmcat-transport-wide-cc-extensions-01 §3), as a sans-IO
%% engine.
%%
%% `packet/4' records the arrival time of a packet carrying a
%% transport-wide sequence number. Feedback (`#rtcp_twcc{}') is emitted
%% by `handle_timeout/2' every `interval' milliseconds (default 100)
%% after the first unreported arrival, and by `flush/2' on demand.
%%
%% Each feedback message starts right after the highest sequence number
%% of the previous one, so a packet lost between two messages is still
%% reported as `not_received'. A packet arriving after feedback already
%% covered its sequence number (reordering) is reported in the next
%% message, which then covers everything from it on again, as libwebrtc
%% does: the arrivals already reported are repeated from a bounded
%% history (the sender ignores repeated reports). A gap of more
%% than `max_gap' (default 1000) sequence numbers is treated as a
%% restart of the sequence: not reported as losses, and packets that
%% much older than reported ones are dropped and counted as late.
%%
%% Pending arrivals are bounded by `max_pending' (default 1000): when
%% reached, feedback is due at once; at twice that, new arrivals are
%% dropped and counted until the next feedback.
-module(webrtc_twcc_receiver).

-include("webrtc_rtp_rtcp.hrl").

-export([new/1, packet/4, handle_timeout/2, next_timeout/1, flush/2, stats/1]).

-export_type([state/0]).

-record(rx, {
    sender_ssrc :: 0..16#FFFFFFFF,
    media_ssrc = undefined :: undefined | 0..16#FFFFFFFF,
    interval :: pos_integer(),
    max_pending :: pos_integer(),
    max_gap :: pos_integer(),
    fb_count = 0 :: non_neg_integer(),
    highest :: undefined | integer(),
    %% First unwrapped sequence number not covered by feedback yet.
    next_base :: undefined | integer(),
    pending = [] :: [{integer(), integer()}],
    %% Arrivals already reported, for repeating them after a late one.
    history = #{} :: #{integer() => integer()},
    count = 0 :: non_neg_integer(),
    next_at = infinity :: integer() | infinity,
    late = 0 :: non_neg_integer(),
    overflow = 0 :: non_neg_integer(),
    sent = 0 :: non_neg_integer()
}).

-opaque state() :: #rx{}.

-spec new(map()) -> state().
new(Opts) ->
    #rx{
        sender_ssrc = maps:get(sender_ssrc, Opts, 0),
        interval = maps:get(interval, Opts, 100),
        max_pending = maps:get(max_pending, Opts, 1000),
        max_gap = maps:get(max_gap, Opts, 1000)
    }.

%% @doc Record that the packet with transport-wide sequence number `Seq'
%% from `Ssrc' arrived at `Now' (milliseconds).
-spec packet(0..65535, 0..16#FFFFFFFF, integer(), state()) -> state().
packet(_Seq, _Ssrc, _Now, #rx{count = C, max_pending = Max} = S) when C >= 2 * Max ->
    S#rx{overflow = S#rx.overflow + 1};
packet(Seq, Ssrc, Now, #rx{highest = H, next_base = B} = S) ->
    Ext = webrtc_rtp_seq:seq_unwrap(Seq, H),
    case B =/= undefined andalso Ext < B - S#rx.max_gap of
        true ->
            S#rx{late = S#rx.late + 1, highest = max(Ext, H)};
        false ->
            C = S#rx.count + 1,
            NextAt =
                if
                    C >= S#rx.max_pending -> Now;
                    S#rx.next_at =:= infinity -> Now + S#rx.interval;
                    true -> S#rx.next_at
                end,
            S#rx{
                media_ssrc = case S#rx.media_ssrc of undefined -> Ssrc; M -> M end,
                highest = case H of undefined -> Ext; _ -> max(Ext, H) end,
                pending = [{Ext, Now * 1000} | S#rx.pending],
                count = C,
                next_at = NextAt
            }
    end.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#rx{next_at = T}) -> T.

-spec handle_timeout(integer(), state()) -> {[#rtcp_twcc{}], state()}.
handle_timeout(Now, #rx{next_at = T} = S) when T =/= infinity, Now >= T ->
    flush(Now, S);
handle_timeout(_Now, S) ->
    {[], S}.

%% @doc Feedback for every pending arrival, now.
-spec flush(integer(), state()) -> {[#rtcp_twcc{}], state()}.
flush(_Now, #rx{pending = []} = S) ->
    {[], S#rx{next_at = infinity}};
flush(_Now, #rx{pending = Pending, media_ssrc = Media, history = H} = S) ->
    {MinExt, _} = hd(lists:keysort(1, Pending)),
    Repeat =
        case S#rx.next_base of
            B0 when is_integer(B0), MinExt < B0 -> [{E, A} || {E, A} <- maps:to_list(H), E > MinExt];
            _ -> []
        end,
    Sorted = lists:ukeysort(1, Pending ++ Repeat),
    {MaxExt, _} = lists:last(Sorted),
    Msgs0 = webrtc_rtcp_twcc:from_arrivals(
        S#rx.sender_ssrc, Media, S#rx.fb_count band 255, [{E band 16#FFFF, A} || {E, A} <- Sorted]
    ),
    Msgs = prepend_losses(S#rx.next_base, MinExt, Msgs0, S#rx.max_gap),
    NextBase = case S#rx.next_base of undefined -> MaxExt + 1; B -> max(B, MaxExt + 1) end,
    {Msgs, S#rx{
        pending = [],
        history = prune_history(NextBase - S#rx.max_gap, maps:merge(H, maps:from_list(Pending))),
        count = 0,
        next_base = NextBase,
        next_at = infinity,
        fb_count = S#rx.fb_count + length(Msgs),
        sent = S#rx.sent + length(Msgs)
    }}.

prune_history(Floor, H) ->
    case map_size(H) > 64 of
        true -> maps:filter(fun(E, _) -> E >= Floor end, H);
        false -> H
    end.

%% Report the sequence numbers between the previous feedback and the
%% first arrival of this one as not received.
prepend_losses(undefined, _Min, Msgs, _MaxGap) ->
    Msgs;
prepend_losses(Base, Min, [#rtcp_twcc{packets = Pkts} = First | Rest] = Msgs, MaxGap) ->
    Gap = Min - Base,
    case Gap > 0 andalso Gap =< MaxGap andalso Gap + length(Pkts) =< 16#FFFF of
        true ->
            Lost = [{E band 16#FFFF, not_received} || E <- lists:seq(Base, Min - 1)],
            [First#rtcp_twcc{base_seq = Base band 16#FFFF, packets = Lost ++ Pkts} | Rest];
        false ->
            Msgs
    end.

-spec stats(state()) -> map().
stats(#rx{} = S) ->
    #{feedback_sent => S#rx.sent, late => S#rx.late, overflow => S#rx.overflow, pending => S#rx.count}.
