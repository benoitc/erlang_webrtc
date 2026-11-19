%% @doc Rapid synchronisation of RTP streams (RFC 6051, RECOMMENDED by
%% RFC 8834 §5.2.1).
%%
%% As sender, when `urn:ietf:params:rtp-hdrext:ntp-64' is negotiated, a
%% packet carries the NTP time of its RTP timestamp, from the clock and
%% the mapping our SR use (§3.3): the wall clock when the packet is made,
%% which is also the point SR extrapolate from. It is added:
%% <ul>
%% <li>to every packet until a report block from the peer has a non-zero
%%     LSR for the stream, so it has an SR;</li>
%% <li>to the first packet of each video keyframe, and to the next packet
%%     of each audio stream after it (§3.3);</li>
%% <li>to the packets that follow an RTCP-SR-REQ until our next SR; the
%%     request is also answered with an SR as early as the feedback rules
%%     allow (§3.2).</li>
%% </ul>
%%
%% As receiver, each stream keeps `{NtpUs, RtpTs}' from SR and from
%% either extension (`ntp-56' once an SR gave its upper 8 bits of
%% seconds), so frames get `ntp_time' (the capture time on the sender's
%% clock, microseconds since the Unix epoch). A stream that has carried
%% media for a reporting interval without a mapping asks for an SR with
%% RTCP-SR-REQ, once per regular report.
-module(webrtc_media_sync).
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include("webrtc_media.hrl").

-export([
    sender_ext/3,
    acked/2,
    sr_sent/2,
    srreq/3,
    rtp_in/4,
    sr_in/2,
    requests/2,
    ntp_time/3
]).

-define(URI_NTP64, <<"urn:ietf:params:rtp-hdrext:ntp-64">>).
-define(URI_NTP56, <<"urn:ietf:params:rtp-hdrext:ntp-56">>).
%% Media without a mapping for this long asks for an SR.
-define(NO_SYNC_MS, 1000).
-define(MAX_SRREQ, 4).

%%====================================================================
%% Sender
%%====================================================================

%% @doc The extension elements for a packet of `Key' about to be sent,
%% with `Hints' (`keyframe'); the senders' state is updated.
-spec sender_ext(term(), #{keyframe => boolean(), ts := non_neg_integer()}, #media{}) ->
    {[webrtc_rtp_ext:element()], #media{}}.
sender_ext(Key, Hints, M) ->
    S = maps:get(Key, M#media.senders),
    case ntp_id(S, M) of
        undefined ->
            {[], M};
        Id ->
            Ts = maps:get(ts, Hints),
            NewKey = S#snd.kind =:= video andalso maps:get(keyframe, Hints, false) andalso Ts =/= S#snd.sync_key_ts,
            case not S#snd.sync_acked orelse S#snd.sync_next orelse NewKey of
                false ->
                    {[], M};
                true ->
                    Ntp = webrtc_rtp_stats:ntp_from_us(erlang:system_time(microsecond)),
                    S1 = S#snd{sync_next = S#snd.sync_req,
                               sync_key_ts = case NewKey of true -> Ts; false -> S#snd.sync_key_ts end},
                    M1 = M#media{senders = (M#media.senders)#{Key := S1}},
                    M2 = case NewKey of
                             true -> audio_next(M1);
                             false -> M1
                         end,
                    {[{Id, webrtc_rtp_ext:ntp64(Ntp)}], M2}
            end
    end.

%% The audio streams carry it on their next packet.
audio_next(M) ->
    M#media{senders = maps:map(fun(_, #snd{kind = audio} = S) -> S#snd{sync_next = true}; (_, S) -> S end,
                               M#media.senders)}.

%% @doc A report block for `Ssrc' with a non-zero LSR: the peer has an
%% SR for it.
-spec acked(non_neg_integer(), #media{}) -> #media{}.
acked(Ssrc, M) ->
    on_sender(Ssrc, fun(S) -> S#snd{sync_acked = true} end, M).

%% @doc Our SR for `Ssrc' went out: an SR-REQ is answered.
-spec sr_sent(non_neg_integer(), #media{}) -> #media{}.
sr_sent(Ssrc, M) ->
    on_sender(Ssrc, fun(S) -> S#snd{sync_req = false, sync_next = false} end, M).

%% @doc An RTCP-SR-REQ (RFC 6051 §3.2) for one of our streams: send an SR
%% as early as the feedback rules allow, the extension meanwhile.
-spec srreq(#rtcp_srreq{}, integer(), #media{}) -> {#media{}, list()}.
srreq(#rtcp_srreq{media_ssrc = Ssrc}, Now, M) ->
    case webrtc_media_in:sender_by_ssrc(Ssrc, M) of
        {ok, _} ->
            M1 = webrtc_media_out:count(srreq_received,
                                        on_sender(Ssrc, fun(S) -> S#snd{sync_req = true, sync_next = true} end, M)),
            {Sends, M2} = webrtc_media_out:early_sr(Ssrc, Now, M1),
            {M2, Sends};
        error ->
            {M, []}
    end.

on_sender(Ssrc, Fun, M) ->
    M#media{senders = maps:map(fun(_, #snd{ssrc = X} = S) when X =:= Ssrc -> Fun(S); (_, S) -> S end,
                               M#media.senders)}.

ntp_id(#snd{ntp_ext = Id}, _M) -> Id.

%%====================================================================
%% Receiver
%%====================================================================

%% @doc A packet of stream `Ssrc' on `Mid': start the no-sync clock and
%% take the mapping from either extension.
-spec rtp_in(binary(), #rtp{}, integer(), #media{}) -> #media{}.
rtp_in(Mid, #rtp{ssrc = Ssrc, ts = Ts, ext = Ext}, Now, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, #rcv{} = R0} ->
            R = case R0#rcv.sync_from of undefined -> R0#rcv{sync_from = Now}; _ -> R0 end,
            Ids = maps:get(recv_extensions, maps:get(Mid, M#media.recv, #{}), #{}),
            Sync = case is_list(Ext) of
                       true -> from_ext(Ids, Ext, Ts, R);
                       false -> R#rcv.sync
                   end,
            M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{sync = Sync}}};
        error ->
            M
    end.

from_ext(Ids, Ext, Ts, R) ->
    case {find(?URI_NTP64, Ids, Ext), find(?URI_NTP56, Ids, Ext)} of
        {{ok, <<Ntp:64>>}, _} ->
            {webrtc_rtp_stats:ntp_to_us(Ntp), Ts};
        {_, {ok, <<Low:56>>}} ->
            %% RFC 6051 §3.3: the upper 8 bits of seconds come from SR.
            case R#rcv.sr_ntp of
                undefined -> R#rcv.sync;
                SrNtp -> {webrtc_rtp_stats:ntp_to_us(((SrNtp bsr 56) bsl 56) bor Low), Ts}
            end;
        _ ->
            R#rcv.sync
    end.

find(Uri, Ids, Ext) ->
    case maps:find(Uri, Ids) of
        {ok, Id} -> webrtc_rtp_ext:find(Id, Ext);
        error -> error
    end.

%% @doc An SR from the sender of `Ssrc': its mapping.
-spec sr_in(#rtcp_sr{}, #media{}) -> #media{}.
sr_in(#rtcp_sr{ssrc = Ssrc, ntp = Ntp, rtp_ts = Ts}, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, R} ->
            M#media{receivers = (M#media.receivers)#{Ssrc := R#rcv{sync = {webrtc_rtp_stats:ntp_to_us(Ntp), Ts}, sr_ntp = Ntp}}};
        error ->
            M
    end.

%% @doc SR-REQ for the streams that carried media for a while without a
%% mapping (RFC 6051 §3.2), sent with a regular report.
%% At most ?MAX_SRREQ per report, so report blocks keep their room.
-spec requests(integer(), #media{}) -> [#rtcp_srreq{}].
requests(Now, M) ->
    Waiting = lists:sort([Ssrc || Ssrc := #rcv{sync = undefined, sync_from = From} <- M#media.receivers,
                                  is_integer(From), Now - From >= ?NO_SYNC_MS,
                                  not is_map_key(Ssrc, M#media.rtx_ssrc)]),
    [#rtcp_srreq{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = Ssrc} || Ssrc <- lists:sublist(Waiting, ?MAX_SRREQ)].

%% @doc The sender's NTP time of RTP timestamp `Ts' on stream `Ssrc', in
%% microseconds since the Unix epoch, when a mapping is known.
-spec ntp_time(non_neg_integer(), non_neg_integer(), #media{}) -> integer() | undefined.
ntp_time(Ssrc, Ts, M) ->
    case maps:find(Ssrc, M#media.receivers) of
        {ok, #rcv{sync = {NtpUs, RefTs}, clock_rate = Rate}} ->
            %% The signed 32-bit distance between the timestamps.
            D = ((Ts - RefTs + 16#80000000) band 16#FFFFFFFF) - 16#80000000,
            NtpUs + D * 1000000 div Rate;
        _ ->
            undefined
    end.
