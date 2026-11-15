%% @private Media session side of RTP stream pause and resume (RFC 7728):
%% PAUSE-RESUME feedback in and out, the requests we make, the PAUSED
%% repeats of regular reports and the events for the application.
%% Internal module of `webrtc_media'; the state machines are in
%% `webrtc_rtp_pause'.
-module(webrtc_media_pause).

-include("webrtc_rtp_rtcp.hrl").
-include("webrtc_media.hrl").

-export([is_paused/1, request/4, rtcp/3, rtp/2, report/1, timeouts/2, next_timeout/1]).

-define(P, webrtc_rtp_pause).

%% A stream we send that the remote asked to pause.
-spec is_paused(#snd{}) -> boolean().
is_paused(#snd{pause = undefined}) -> false;
is_paused(#snd{pause = P}) -> ?P:is_paused(P).

%%====================================================================
%% Requests for streams we receive
%%====================================================================

request(Key, Type, Now, M) ->
    Mid = case Key of {Mi, _} -> Mi; Mi -> Mi end,
    case maps:get(pause, maps:get(Mid, M#media.recv, #{}), undefined) of
        undefined ->
            {error, pause_not_negotiated};
        _ ->
            case sources(Key, M) of
                [] ->
                    {error, unknown_stream};
                Ssrcs ->
                    {Entries, M1} = lists:mapfoldl(
                        fun(Ssrc, Acc) ->
                            R0 = maps:get(Ssrc, Acc#media.pause_req, ?P:requester()),
                            {R1, Msgs} = ?P:request(Type, {Now, undefined}, R0),
                            {[entry(Ssrc, Msg) || Msg <- Msgs], Acc#media{pause_req = (Acc#media.pause_req)#{Ssrc => R1}}}
                        end,
                        M,
                        Ssrcs
                    ),
                    {Sends, M2} = webrtc_media_out:send_feedback(packets(lists:append(Entries), M1), Now, M1),
                    {ok, Sends, M2}
            end
    end.

sources({Mid, Rid}, M) ->
    [S || {ok, S} <- [webrtc_media_rid:source(Mid, Rid, M#media.rids)]];
sources(Mid, M) ->
    lists:sort([S || S := #rcv{mid = Mi} <- M#media.receivers, Mi =:= Mid]).

%% @doc A packet of a stream we asked to pause or resume.
-spec rtp(non_neg_integer(), #media{}) -> {#media{}, list()}.
rtp(Ssrc, #media{pause_req = Reqs} = M) when is_map_key(Ssrc, Reqs) ->
    {R, Ev} = ?P:requester_rtp(maps:get(Ssrc, Reqs)),
    M1 = M#media{pause_req = Reqs#{Ssrc := R}},
    {M1, events(remote, Ev, Ssrc, M1)};
rtp(_Ssrc, M) ->
    {M, []}.

%%====================================================================
%% Feedback received
%%====================================================================

rtcp(#rtcp_pause{entries = Entries}, Now, M) ->
    {M1, Replies, Events} = lists:foldl(
        fun(E, {Acc, Rs, Evs}) ->
            {Acc1, R, Ev} = entry_in(E, Now, Acc),
            {Acc1, Rs ++ R, Evs ++ Ev}
        end,
        {M, [], []},
        Entries
    ),
    {Sends, M2} = webrtc_media_out:send_feedback(packets(Replies, M1), Now, M1),
    {M2, Events ++ Sends}.

%% PAUSE and RESUME target a stream we send; PAUSED and REFUSED one we
%% asked about.
entry_in({Target, Type, Id, _}, Now, M) when Type =:= pause; Type =:= resume ->
    case webrtc_media_in:sender_by_ssrc(Target, M) of
        {ok, #snd{pause = undefined}} ->
            {M, [], []};
        {ok, #snd{pause = P0} = S} ->
            {P1, Msgs, Ev} = ?P:sender_in(Type, Id, ext_seq(S), {Now, S#snd.hold_off}, P0),
            M1 = put_sender(S#snd{pause = P1}, M),
            {M1, [entry(Target, Msg) || Msg <- Msgs], events(local, Ev, S)};
        error ->
            {M, [], []}
    end;
entry_in({Target, Type, Id, Seq}, Now, #media{pause_req = Reqs} = M) when is_map_key(Target, Reqs) ->
    Msg = case Type of paused -> {paused, Id, Seq}; refused -> {refused, Id} end,
    {R, Ev} = ?P:requester_in(Msg, Now, maps:get(Target, Reqs)),
    M1 = M#media{pause_req = Reqs#{Target := R}},
    {M1, [], events(remote, Ev, Target, M1)};
entry_in({Target, paused, _Id, _Seq} = E, Now, M) ->
    %% The sender paused a stream we never asked about (a paused layer
    %% of the answer, or a local pause): track it.
    entry_in(E, Now, M#media{pause_req = (M#media.pause_req)#{Target => ?P:requester()}});
entry_in(_, _Now, M) ->
    {M, [], []}.

%%====================================================================
%% Timers and regular reports
%%====================================================================

%% @doc PAUSED to repeat in the regular report (RFC 7728 §6.2).
-spec report(#media{}) -> {list(), #media{}}.
report(M) ->
    {Entries, M1} = maps:fold(
        fun
            (_K, #snd{pause = undefined}, Acc) ->
                Acc;
            (_K, #snd{pause = P0, ssrc = Ssrc} = S, {Es, MAcc}) ->
                {P1, Msgs} = ?P:sender_report(ext_seq(S), P0),
                {Es ++ [entry(Ssrc, Msg) || Msg <- Msgs], put_sender(S#snd{pause = P1}, MAcc)}
        end,
        {[], M},
        M#media.senders
    ),
    {packets(Entries, M1), M1}.

%% @doc Hold-offs that ended and requests to retransmit: feedback to
%% send and events.
-spec timeouts(integer(), #media{}) -> {list(), list(), #media{}}.
timeouts(Now, M0) ->
    {Paused, Events, M1} = maps:fold(
        fun
            (_K, #snd{pause = undefined}, Acc) ->
                Acc;
            (_K, #snd{pause = P0, ssrc = Ssrc} = S, {Es, Evs, MAcc}) ->
                {P1, Msgs, Ev} = ?P:sender_timeout({Now, ext_seq(S)}, P0),
                {Es ++ [entry(Ssrc, Msg) || Msg <- Msgs], Evs ++ events(local, Ev, S), put_sender(S#snd{pause = P1}, MAcc)}
        end,
        {[], [], M0},
        M0#media.senders
    ),
    {Retx, Reqs} = maps:fold(
        fun(Ssrc, R0, {Es, Rs}) ->
            {R1, Msgs} = ?P:requester_timeout(Now, undefined, R0),
            {Es ++ [entry(Ssrc, Msg) || Msg <- Msgs], Rs#{Ssrc => R1}}
        end,
        {[], #{}},
        M1#media.pause_req
    ),
    M2 = M1#media{pause_req = Reqs},
    {packets(Paused ++ Retx, M2), Events, M2}.

-spec next_timeout(#media{}) -> integer() | infinity.
next_timeout(#media{senders = Ss, pause_req = Reqs}) ->
    T1 = lists:foldl(
        fun
            (#snd{pause = undefined}, Acc) -> Acc;
            (#snd{pause = P}, Acc) -> webrtc_media_out:tmin(?P:sender_next_timeout(P), Acc)
        end,
        infinity,
        maps:values(Ss)
    ),
    lists:foldl(fun(R, Acc) -> webrtc_media_out:tmin(?P:requester_next_timeout(R), Acc) end, T1, maps:values(Reqs)).

%%====================================================================
%% Helpers
%%====================================================================

entry(Ssrc, {paused, Id, Seq}) -> {Ssrc, paused, Id, Seq};
entry(Ssrc, {Type, Id}) -> {Ssrc, Type, Id, undefined}.

packets([], _M) -> [];
packets(Entries, M) -> [#rtcp_pause{sender_ssrc = M#media.rtcp_ssrc, entries = Entries}].

%% Extended sequence number of the last packet sent (RFC 3550 §6.4.1).
ext_seq(#snd{seq = Next, cycles = C}) ->
    Last = (Next - 1) band 16#FFFF,
    Cycles = case Next of 0 when C > 0 -> C - 1; _ -> C end,
    (Cycles bsl 16) bor Last.

put_sender(#snd{mid = Mid, rid = undefined} = S, M) -> M#media{senders = (M#media.senders)#{Mid := S}};
put_sender(#snd{mid = Mid, rid = Rid} = S, M) -> M#media{senders = (M#media.senders)#{{Mid, Rid} := S}}.

%% Our stream: the remote asked us to pause or resume it.
events(local, paused, #snd{mid = Mid, rid = undefined}) -> [{event, {stream_paused, Mid}}];
events(local, paused, #snd{mid = Mid, rid = Rid}) -> [{event, {stream_paused, Mid, Rid}}];
events(local, resumed, #snd{mid = Mid, rid = undefined}) -> [{event, {stream_resumed, Mid}}];
events(local, resumed, #snd{mid = Mid, rid = Rid}) -> [{event, {stream_resumed, Mid, Rid}}];
events(local, _, _) -> [].

%% A stream we receive: its sender paused, resumed or refused.
events(remote, none, _Ssrc, _M) ->
    [];
events(remote, Ev, Ssrc, M) ->
    Name = case Ev of paused -> remote_paused; resumed -> remote_resumed; refused -> pause_refused end,
    Mid = maps:get(Ssrc, M#media.ssrc_mid, undefined),
    case webrtc_media_rid:rid(Ssrc, M#media.rids) of
        undefined -> [{event, {Name, Mid}}];
        Rid -> [{event, {Name, Mid, Rid}}]
    end.
