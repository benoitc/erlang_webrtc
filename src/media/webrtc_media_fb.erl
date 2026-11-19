%% @doc Slice loss (SLI) and reference picture selection (RPSI)
%% indications, RFC 4585 §6.3.2 and §6.3.3, used as RFC 8834 §5.1.3 and
%% §5.1.4 ask once `nack sli' or `nack rpsi' is negotiated.
%%
%% The library does not encode or decode, so:
%% <ul>
%% <li>As media sender, an indication for one of our streams goes to the
%%     owner, `{slice_loss, Mid, Entries}' or `{reference_picture, Mid,
%%     Pt, Bits}' (with the rid for a simulcast layer), and to the
%%     stream's encoding codec plugin through its optional `feedback/2'
%%     callback, which repairs or changes its reference picture.</li>
%% <li>As media receiver, the application (`send/4') or the decoding
%%     plugin (the feedback `decode/2' returns) sends them.</li>
%% </ul>
%% Indications on a stream that did not negotiate them are ignored and
%% counted (`sli_ignored', `rpsi_ignored').
-module(webrtc_media_fb).
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include("webrtc_media.hrl").

-export([received/2, receiver_kinds/1, send/4, packets/3]).

-type indication() :: {slice_loss, [{0..8191, 0..8191, 0..63}]} | {reference_picture, 0..127, bitstring()}.
-export_type([indication/0]).

%% @doc An SLI or RPSI from the peer.
-spec received(#rtcp_sli{} | #rtcp_rpsi{}, #media{}) -> {#media{}, list()}.
received(P, M) ->
    {Ssrc, Kind, Fb} = case P of
                           #rtcp_sli{media_ssrc = S, entries = E} -> {S, sli, {slice_loss, E}};
                           #rtcp_rpsi{media_ssrc = S, pt = Pt, bits = B} -> {S, rpsi, {reference_picture, Pt, B}}
                       end,
    case webrtc_media_in:sender_by_ssrc(Ssrc, M) of
        {ok, #snd{codecs = Cs} = S0} ->
            case lists:member(Kind, kinds(Cs)) of
                true ->
                    {Plugin, M1} = to_plugin(Fb, S0, M),
                    {M1, [{event, event(Fb, S0)} | Plugin]};
                false ->
                    {webrtc_media_out:count(ignored(Kind), M), []}
            end;
        error ->
            {M, []}
    end.

%% @doc The indications a receive stream negotiated with its codecs.
-spec receiver_kinds([map()]) -> [sli | rpsi].
receiver_kinds(Codecs) -> kinds(Codecs).

%% @doc Send an indication to the senders of a transceiver (`Mid') or of
%% one simulcast layer (`{Mid, Rid}').
-spec send(term(), indication(), integer(), #media{}) ->
    {ok, [{send, binary()}], #media{}} | {error, not_negotiated}.
send(Key, Fb, Now, M) ->
    Ssrcs = case Key of
                {Mid, Rid} -> [S || {ok, S} <- [webrtc_media_rid:source(Mid, Rid, M#media.rids)]];
                Mid -> [S || S := #rcv{mid = Mi} <- M#media.receivers, Mi =:= Mid]
            end,
    Recv = maps:get(recv_codecs, maps:get(mid(Key), M#media.recv, #{}), []),
    case lists:member(kind(Fb), kinds(Recv)) of
        false ->
            {error, not_negotiated};
        true ->
            Pkts = lists:append([packets(S, [Fb], M) || S <- Ssrcs]),
            {Sends, M1} = webrtc_media_out:send_feedback(Pkts, Now, M),
            {ok, Sends, M1}
    end.

%% @doc RTCP for the indications a decoding plugin returned on stream
%% `Ssrc', those the stream negotiated.
-spec packets(non_neg_integer(), [indication()], #media{}) -> [#rtcp_sli{} | #rtcp_rpsi{}].
packets(Ssrc, Fbs, M) ->
    Kinds = case maps:find(Ssrc, M#media.receivers) of
                {ok, #rcv{loss_fb = K}} -> K;
                error -> []
            end,
    [packet(Ssrc, Fb, M) || Fb <- Fbs, lists:member(kind(Fb), Kinds)].

%%====================================================================
%% Internal
%%====================================================================

kinds(Codecs) ->
    Fbs = lists:append([Fb || #{rtcp_fb := Fb} <- Codecs]),
    [K || {K, P} <- [{sli, <<"sli">>}, {rpsi, <<"rpsi">>}],
          lists:any(fun(#{type := T, param := Pa}) when is_binary(Pa) ->
                            string:lowercase(T) =:= <<"nack">> andalso string:lowercase(Pa) =:= P;
                       (_) -> false
                    end, Fbs)].

kind({slice_loss, _}) -> sli;
kind({reference_picture, _, _}) -> rpsi.

ignored(sli) -> sli_ignored;
ignored(rpsi) -> rpsi_ignored.

mid({Mid, _}) -> Mid;
mid(Mid) -> Mid.

packet(Ssrc, {slice_loss, E}, M) ->
    #rtcp_sli{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = Ssrc, entries = E};
packet(Ssrc, {reference_picture, Pt, Bits}, M) ->
    #rtcp_rpsi{sender_ssrc = M#media.rtcp_ssrc, media_ssrc = Ssrc, pt = Pt, bits = Bits}.

event({slice_loss, E}, #snd{mid = Mid, rid = undefined}) -> {slice_loss, Mid, E};
event({slice_loss, E}, #snd{mid = Mid, rid = Rid}) -> {slice_loss, Mid, Rid, E};
event({reference_picture, Pt, B}, #snd{mid = Mid, rid = undefined}) -> {reference_picture, Mid, Pt, B};
event({reference_picture, Pt, B}, #snd{mid = Mid, rid = Rid}) -> {reference_picture, Mid, Rid, Pt, B}.

%% The encoding plugin acts on it when it has `feedback/2'; a crash or
%% an error turns it off, as for `encode/2'.
to_plugin(Fb, #snd{plugin = {Mod, St}, mid = Mid} = S, M) when is_atom(Mod) ->
    case erlang:function_exported(Mod, feedback, 2) of
        false ->
            {[], M};
        true ->
            case webrtc_media:plugin_call(fun() -> Mod:feedback(Fb, St) end) of
                {ok, St1} -> {[], store(S#snd{plugin = {Mod, St1}}, M)};
                {error, R} -> {[{event, {codec_plugin_error, Mid, R}}], store(S#snd{plugin = {off, R}}, M)}
            end
    end;
to_plugin(_Fb, _S, M) ->
    {[], M}.

store(#snd{} = S, M) ->
    Key = case S#snd.rid of undefined -> S#snd.mid; Rid -> {S#snd.mid, Rid} end,
    M#media{senders = (M#media.senders)#{Key := S}}.
