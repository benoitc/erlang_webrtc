%% @doc Receive side of RTP stream identifiers (RFC 8852) for
%% `webrtc_media': which simulcast layer (rid) an incoming SSRC carries.
%%
%% Simulcast senders usually announce no SSRCs. A layer is recognised by
%% the MID and RtpStreamId header extensions of its first packets, and
%% its RTX stream by the RepairedRtpStreamId extension (RFC 8852 §3.2,
%% RFC 9143 §9.2); RTCP SDES chunks carrying the same items teach the
%% mapping too (RFC 8852 §4). The mapping is learned once per SSRC: later
%% packets may omit the extensions. Only rids negotiated for the m=
%% section are accepted (RFC 8853 §5.2).
-module(webrtc_media_rid).

-include("webrtc_rtp.hrl").

-export([new/0, configure/2, classify/3, rid/2, source/3, sdes/3, forget/2]).

-export_type([state/0]).

-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).
-define(URI_RRID, <<"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>).

-type ssrc() :: 0..16#FFFFFFFF.

-record(rids, {
    %% Negotiated receive rids and extension ids per mid.
    mids = #{} :: #{binary() => [binary()]},
    rid_ext = #{} :: #{binary() => pos_integer()},
    rrid_ext = #{} :: #{binary() => pos_integer()},
    %% Learned source streams, both ways.
    ssrc_rid = #{} :: #{ssrc() => binary()},
    source = #{} :: #{{binary(), binary()} => ssrc()}
}).

-opaque state() :: #rids{}.

-spec new() -> state().
new() -> #rids{}.

%% @doc Apply negotiated sections (`recv_rids', `recv_extensions').
%% Learned SSRCs are kept across renegotiations.
-spec configure([map()], state()) -> state().
configure(Sections, R) ->
    Simulcast = [S || #{recv_rids := [_ | _]} = S <- Sections],
    R#rids{
        mids = maps:from_list([{Mid, [Rid || #{rid := Rid} <- Rids]} || #{mid := Mid, recv_rids := Rids} <- Simulcast]),
        rid_ext = ext(?URI_RID, Simulcast),
        rrid_ext = ext(?URI_RRID, Simulcast)
    }.

ext(Uri, Sections) ->
    maps:from_list([{Mid, Id} || #{mid := Mid, recv_extensions := #{Uri := Id}} <- Sections]).

%% @doc Classify a packet of a known mid. `plain': the section has no
%% layers. `{source, Rid}': a layer. `{repair, Ssrc}': the RTX stream of
%% the layer sent with `Ssrc'. `drop': the stream cannot be attributed
%% to a negotiated layer (yet).
-spec classify(binary(), #rtp{}, state()) ->
    {plain | {source, binary()} | {repair, ssrc()} | drop, state()}.
classify(Mid, #rtp{ssrc = Ssrc, ext = Ext}, #rids{mids = Mids} = R) ->
    case maps:find(Mid, Mids) of
        error ->
            {plain, R};
        {ok, Rids} ->
            case maps:find(Ssrc, R#rids.ssrc_rid) of
                {ok, Rid} ->
                    {{source, Rid}, R};
                error ->
                    case {value(R#rids.rid_ext, Mid, Ext, Rids), value(R#rids.rrid_ext, Mid, Ext, Rids)} of
                        {{ok, Rid}, _} ->
                            {{source, Rid}, learn(Mid, Rid, Ssrc, R)};
                        {_, {ok, Rid}} ->
                            case maps:find({Mid, Rid}, R#rids.source) of
                                {ok, Source} -> {{repair, Source}, R};
                                error -> {drop, R}
                            end;
                        _ ->
                            {drop, R}
                    end
            end
    end.

value(Ids, Mid, Elems, Rids) when is_list(Elems) ->
    maybe
        {ok, Id} ?= maps:find(Mid, Ids),
        {ok, Raw} ?= webrtc_rtp_ext:find(Id, Elems),
        {ok, Rid} ?= webrtc_rtp_ext:decode_sdes(Raw),
        true ?= lists:member(Rid, Rids),
        {ok, Rid}
    else
        _ -> error
    end;
value(_, _, _, _) ->
    error.

learn(Mid, Rid, Ssrc, R) ->
    R#rids{ssrc_rid = (R#rids.ssrc_rid)#{Ssrc => Rid}, source = (R#rids.source)#{{Mid, Rid} => Ssrc}}.

%% @doc Forget a source stream that ended.
-spec forget(ssrc(), state()) -> state().
forget(Ssrc, R) ->
    R#rids{
        ssrc_rid = maps:remove(Ssrc, R#rids.ssrc_rid),
        source = maps:filter(fun(_, S) -> S =/= Ssrc end, R#rids.source)
    }.

%% @doc Rid of a learned source SSRC.
-spec rid(ssrc(), state()) -> binary() | undefined.
rid(Ssrc, R) -> maps:get(Ssrc, R#rids.ssrc_rid, undefined).

%% @doc Source SSRC of a layer, once learned.
-spec source(binary(), binary(), state()) -> {ok, ssrc()} | error.
source(Mid, Rid, R) -> maps:find({Mid, Rid}, R#rids.source).

%% @doc Learn layers from RTCP SDES chunks with an RtpStreamId item
%% (RFC 8852 §4). `SsrcMid' gives the mid of SSRCs whose chunk carries
%% no MID item.
-spec sdes([{ssrc(), [{atom() | integer() | tuple(), binary()}]}], #{ssrc() => binary()}, state()) -> state().
sdes(Chunks, SsrcMid, R) ->
    lists:foldl(
        fun({Ssrc, Items}, Acc) ->
            Mid = proplists:get_value(mid, Items, maps:get(Ssrc, SsrcMid, undefined)),
            Rid = proplists:get_value(rid, Items),
            case lists:member(Rid, maps:get(Mid, Acc#rids.mids, [])) of
                true -> learn(Mid, Rid, Ssrc, Acc);
                false -> Acc
            end
        end,
        R,
        Chunks
    ).
