%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc TMMBR and TMMBN in the media engine (RFC 5104 §4.2, required by
%% RFC 8834 §5.1.6), when `ccm tmmbr' is negotiated.
%%
%% As media sender: each TMMBR entry for one of our streams updates its
%% bounding set (webrtc_tmmbr) and is answered with a TMMBN. The stream
%% then follows the limit: its packets go through a token bucket
%% (webrtc_rate_limit) at the net media rate the set allows at the
%% stream's packet rate, and the owner gets `{max_bitrate, Mid, Bps}'
%% (`{max_bitrate, Mid, Rid, Bps}' for a simulcast layer) to adapt the
%% encoder. An owner that sends BYE or is silent for 25 s (five
%% regular intervals of at least 5 s, RFC 3550 §6.3.5) is removed and a
%% new TMMBN sent.
%%
%% As media receiver: `request/4' sends TMMBR to the senders of a
%% transceiver, repeated with the regular reports until a TMMBN arrives
%% that lists us, or that is already more limiting than our tuple.
%% Bit rates and overheads are at the RTP layer: headers and payload.
-module(webrtc_media_limit).
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include("webrtc_media.hrl").

-export([
    negotiated/1,
    tmmbr/4,
    tmmbn/2,
    bye/3,
    touch/3,
    admit/3,
    charge/4,
    limited/1,
    next_timeout/1,
    timeouts/2,
    request/4,
    repeats/1
]).

-define(OWNER_TIMEOUT, 25000).
%% Hold-off while no RTT is known (RFC 5104 §4.2.1.2).
-define(HOLD_OFF, 500).

%% @doc True when the codecs we send with negotiated `ccm tmmbr'.
-spec negotiated([map()]) -> boolean().
negotiated(Codecs) ->
    lists:any(fun(#{rtcp_fb := Fb}) -> lists:any(fun webrtc_jsep_caps:is_tmmbr/1, Fb); (_) -> false end, Codecs).

%%====================================================================
%% Media sender
%%====================================================================

%% @doc A TMMBR from `From'. Entries for streams that did not negotiate
%% TMMBR are ignored and counted (RFC 5104 §7).
-spec tmmbr(non_neg_integer(), [webrtc_tmmbr:tuple_()], integer(), #media{}) -> {#media{}, list()}.
tmmbr(From, Entries, Now, M0) ->
    {Fb, Events, M} = lists:foldl(
        fun({Ssrc, Br, Oh}, {FbA, EvA, MA}) ->
            case sender(Ssrc, MA) of
                {ok, Key, #snd{tmmbr = undefined}} ->
                    _ = Key,
                    {FbA, EvA, webrtc_media_out:count(tmmbr_ignored, MA)};
                {ok, Key, #snd{tmmbr = T} = S} ->
                    T1 = webrtc_tmmbr:request(From, Br, Oh, Now, hold_off(S, MA), T),
                    {Ev, MA1} = apply_limit(Key, Now, put(Key, S#snd{tmmbr = T1}, MA)),
                    {[notification(S, T1) | FbA], EvA ++ Ev, webrtc_media_out:count(tmmbr_received, MA1)};
                error ->
                    {FbA, EvA, MA}
            end
        end,
        {[], [], M0},
        Entries
    ),
    {Sends, M1} = webrtc_media_out:send_feedback(lists:reverse(Fb), Now, M),
    {M1, Sends ++ Events}.

%% @doc Owners that left (RTCP BYE): a new TMMBN for every stream whose
%% bounding set they were in.
-spec bye([non_neg_integer()], integer(), #media{}) -> {#media{}, list()}.
bye(Ssrcs, Now, M) ->
    owners_gone(fun(T, S, MA) ->
                    lists:foldl(fun(O, {Ch, TA}) -> {Ch1, TA1} = webrtc_tmmbr:leave(O, Now, hold_off(S, MA), TA), {Ch orelse Ch1, TA1} end,
                                {false, T}, Ssrcs)
                end, Now, M).

%% @doc A packet from `Ssrc': it is still in the session.
-spec touch(non_neg_integer(), integer(), #media{}) -> #media{}.
touch(Ssrc, Now, M) ->
    Ss = maps:map(fun(_, #snd{tmmbr = undefined} = S) -> S;
                     (_, #snd{tmmbr = T} = S) -> S#snd{tmmbr = webrtc_tmmbr:touch(Ssrc, Now, T)}
                  end, M#media.senders),
    M#media{senders = Ss}.

%% @doc Pass paced items `[{Class, {Key, Pkt, Rtx}}]' through the
%% limiters of their streams; returns the items that may go on.
-spec admit([{atom(), tuple()}], integer(), #media{}) -> {[{atom(), tuple()}], #media{}}.
admit(Items, Now, M) ->
    lists:foldl(
        fun({_, {Key, Pkt, _}} = Item, {Acc, MA}) ->
            case maps:find(Key, MA#media.senders) of
                {ok, #snd{limiter = L} = S} when L =/= undefined ->
                    L1 = webrtc_rate_limit:set_rate(rate(S, Now), Now, L),
                    {Out, L2} = webrtc_rate_limit:enqueue(Item, bits(Pkt), Now, L1),
                    {Acc ++ Out, put(Key, S#snd{limiter = L2}, MA)};
                _ ->
                    {Acc ++ [Item], MA}
            end
        end,
        {[], M},
        Items
    ).

%% @doc FEC sent for a stream counts against its limit.
-spec charge(term(), [#rtp{}], integer(), #media{}) -> #media{}.
charge(Key, Pkts, Now, M) ->
    case maps:find(Key, M#media.senders) of
        {ok, #snd{limiter = L} = S} when L =/= undefined ->
            Bits = lists:sum([bits(P) || P <- Pkts]),
            put(Key, S#snd{limiter = webrtc_rate_limit:charge(Bits, Now, L)}, M);
        _ ->
            M
    end.

%% @doc True while a stream follows a limit: no probes on it.
-spec limited(#snd{}) -> boolean().
limited(#snd{limiter = L}) -> L =/= undefined.

-spec next_timeout(#media{}) -> integer() | infinity.
next_timeout(M) ->
    lists:foldl(
        fun(#snd{tmmbr = T, limiter = L}, Acc) ->
            A1 = case T of undefined -> Acc; _ -> webrtc_media_out:tmin(webrtc_tmmbr:next_timeout(T), Acc) end,
            case L of undefined -> A1; _ -> webrtc_media_out:tmin(webrtc_rate_limit:next_timeout(L), A1) end
        end,
        infinity,
        maps:values(M#media.senders)
    ).

%% @doc Hold-offs that ended, silent owners, and the packets the
%% limiters release, which go on to the pacer.
-spec timeouts(integer(), #media{}) -> {[{atom(), tuple()}], list(), #media{}}.
timeouts(Now, M0) ->
    {M1, Acts} = owners_gone(fun(T, S, MA) ->
                                 {Gone, T1} = webrtc_tmmbr:expire(Now, ?OWNER_TIMEOUT, hold_off(S, MA), T),
                                 {Gone =/= [], T1}
                             end, Now, M0),
    {Items, Events, M2} = maps:fold(
        fun(Key, #snd{tmmbr = T, limiter = L} = S, {IA, EA, MA}) ->
            Due = T =/= undefined andalso webrtc_tmmbr:next_timeout(T) =< Now,
            {Ev, MA1} = case Due of
                            true -> apply_limit(Key, Now, put(Key, S#snd{tmmbr = webrtc_tmmbr:handle_timeout(Now, T)}, MA));
                            false -> {[], MA}
                        end,
            case maps:get(Key, MA1#media.senders) of
                #snd{limiter = L1} = S1 when L1 =/= undefined ->
                    _ = L,
                    {Out, L2} = webrtc_rate_limit:handle_timeout(Now, webrtc_rate_limit:set_rate(rate(S1, Now), Now, L1)),
                    L3 = case webrtc_rate_limit:rate(L2) =:= infinity andalso webrtc_rate_limit:queue_length(L2) =:= 0 of
                             true -> undefined;
                             false -> L2
                         end,
                    {IA ++ Out, EA ++ Ev, put(Key, S1#snd{limiter = L3}, MA1)};
                #snd{limiter = undefined} ->
                    {IA, EA ++ Ev, MA1}
            end
        end,
        {[], [], M1},
        M1#media.senders
    ),
    {Items, Acts ++ Events, M2}.

%%====================================================================
%% Media receiver
%%====================================================================

%% @doc Ask the senders of `Mid' to keep under `Bps' (bits per second,
%% RTP headers and payload) or, with `infinity', lift our limit.
-spec request(binary(), pos_integer() | infinity, integer(), #media{}) ->
    {ok, [{send, binary()}], #media{}} | {error, not_negotiated}.
request(Mid, Bps, Now, M) ->
    case negotiated(maps:get(recv_codecs, maps:get(Mid, M#media.recv, #{}), [])) of
        false ->
            {error, not_negotiated};
        true ->
            M1 = M#media{limit_req = (M#media.limit_req)#{Mid => {Bps, []}}},
            {Sends, M2} = webrtc_media_out:send_feedback(requests([Mid], M1), Now, M1),
            {ok, Sends, M2}
    end.

%% @doc A TMMBN from a sender we asked: done when it lists us, or when
%% its set already limits more than our tuple would (RFC 5104 §4.2.1.2).
-spec tmmbn(#rtcp_tmmbn{}, #media{}) -> #media{}.
tmmbn(#rtcp_tmmbn{sender_ssrc = From, entries = Set}, M) ->
    case maps:find(From, M#media.ssrc_mid) of
        {ok, Mid} when is_map_key(Mid, M#media.limit_req) ->
            {Bps, Done} = maps:get(Mid, M#media.limit_req),
            Ours = {M#media.rtcp_ssrc, wire_bps(Bps), overhead(From, M)},
            Listed = lists:keymember(M#media.rtcp_ssrc, 1, Set),
            Needed = Bps =/= infinity andalso lists:member(Ours, webrtc_tmmbr:bounding_set([Ours | Set])),
            Done1 = case Listed orelse not Needed of
                        true -> lists:usort([From | Done]);
                        false -> Done -- [From]
                    end,
            M#media{limit_req = (M#media.limit_req)#{Mid := {Bps, Done1}}};
        _ ->
            M
    end.

%% @doc The TMMBR to repeat with a regular report (RFC 5104 §4.2.1.2).
-spec repeats(#media{}) -> [#rtcp_tmmbr{}].
repeats(M) ->
    requests(maps:keys(M#media.limit_req), M).

requests(Mids, M) ->
    Entries = [{Ssrc, wire_bps(Bps), overhead(Ssrc, M)}
               || Mid <- Mids, {Bps, Done} <- [maps:get(Mid, M#media.limit_req)],
                  Ssrc := #rcv{mid = Mi} <- M#media.receivers, Mi =:= Mid,
                  not lists:member(Ssrc, Done), not is_map_key(Ssrc, M#media.rtx_ssrc)],
    [#rtcp_tmmbr{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = 0, entries = Entries} || Entries =/= []].

%% Lifting a limit is asked with the largest value the format holds.
wire_bps(infinity) -> 16#1FFFF bsl 63;
wire_bps(Bps) -> Bps.

%% The average RTP header size of the stream (RFC 5104 §4.2.1.2 asks
%% for a running average; the mean is as good for a steady header).
overhead(Ssrc, M) ->
    St = maps:get({in, Ssrc}, M#media.streams, #{}),
    case {maps:get(header_bytes_received, St, 0), maps:get(packets_received, St, 0)} of
        {_, 0} -> 12;
        {H, N} -> min(511, round(H / N))
    end.

%%====================================================================
%% Internal
%%====================================================================

sender(Ssrc, M) ->
    case [{K, S} || K := #snd{ssrc = X} = S <- M#media.senders, X =:= Ssrc] of
        [{K, S} | _] -> {ok, K, S};
        [] -> error
    end.

put(Key, S, M) ->
    M#media{senders = (M#media.senders)#{Key := S}}.

notification(#snd{ssrc = Ssrc}, T) ->
    #rtcp_tmmbn{sender_ssrc = Ssrc, media_ssrc = 0, entries = webrtc_tmmbr:set(T)}.

%% RFC 5104 §4.2.1.2: 2 x RTT + T_dither_max, which is 0 point to point
%% (RFC 4585 §3.4).
hold_off(#snd{ssrc = Ssrc}, M) ->
    case maps:get(rtt, maps:get({out, Ssrc}, M#media.streams, #{}), undefined) of
        Rtt when is_integer(Rtt) -> 2 * Rtt;
        _ -> ?HOLD_OFF
    end.

%% Remove owners with `Fun(T, S, M) -> {Changed, T1}' and send TMMBN
%% for the streams that changed.
owners_gone(Fun, Now, M0) ->
    {Fb, Events, M} = maps:fold(
        fun(_Key, #snd{tmmbr = undefined}, Acc) ->
                Acc;
           (Key, #snd{tmmbr = T} = S, {FbA, EvA, MA}) ->
                case Fun(T, S, MA) of
                    {true, T1} ->
                        {Ev, MA1} = apply_limit(Key, Now, put(Key, S#snd{tmmbr = T1}, MA)),
                        {[notification(S, T1) | FbA], EvA ++ Ev, MA1};
                    {false, T1} ->
                        {FbA, EvA, put(Key, S#snd{tmmbr = T1}, MA)}
                end
        end,
        {[], [], M0},
        M0#media.senders
    ),
    {Sends, M1} = webrtc_media_out:send_feedback(lists:reverse(Fb), Now, M),
    {M1, Sends ++ Events}.

%% Set the stream's limiter from the enforced set and tell the owner
%% when the limit changed. A lifted limit keeps its limiter, at no
%% rate limit, until the packets it holds are gone.
apply_limit(Key, Now, M) ->
    #snd{tmmbr = T, limiter = L0, limit = Old} = S = maps:get(Key, M#media.senders),
    L = case {webrtc_tmmbr:enforced(Now, T), L0} of
            {[], undefined} -> undefined;
            {_, undefined} -> webrtc_rate_limit:new(#{});
            _ -> L0
        end,
    S1 = S#snd{limiter = L},
    New = case L of undefined -> infinity; _ -> rate(S1, Now) end,
    S2 = case L of undefined -> S1; _ -> S1#snd{limiter = webrtc_rate_limit:set_rate(New, Now, L)} end,
    M1 = put(Key, S2#snd{limit = New}, M),
    case New =:= Old of
        true -> {[], M1};
        false -> {[{event, event(S2, New)}], M1}
    end.

event(#snd{mid = Mid, rid = undefined}, Bps) -> {max_bitrate, Mid, Bps};
event(#snd{mid = Mid, rid = Rid}, Bps) -> {max_bitrate, Mid, Rid, Bps}.

%% The net media rate the stream may use at its current packet rate.
rate(#snd{tmmbr = T, limiter = L}, Now) ->
    Pr = case L of undefined -> 0; _ -> webrtc_rate_limit:packet_rate(Now, L) end,
    webrtc_tmmbr:net_rate(webrtc_tmmbr:enforced(Now, T), Pr).

bits({raw, Bin}) -> max(8, (byte_size(Bin) - 12) * 8);
bits(#rtp{payload = P}) -> max(8, byte_size(P) * 8).
