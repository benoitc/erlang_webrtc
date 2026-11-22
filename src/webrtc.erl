%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc WebRTC peer connections in pure Erlang.
%%
%% A peer connection is a process. The process that creates it (or the
%% `owner' option) receives every event as `{webrtc, Pc, Event}':
%% signaling and ICE (`negotiation_needed', `{ice_candidate, Candidate,
%% Mid}', ...), connection state, data channels (`{channel_message, Id,
%% Type, Data}', ...), media (`{rtp, Mid, Packet}', `{frame, Mid,
%% Frame}', ...) and congestion (`{bandwidth_estimate, Bps}', ...).
%%
%% Signaling is the application's business: exchange the SDP returned by
%% `create_offer/2' and `create_answer/2' and the candidates of
%% `ice_candidate' events by any means, and pass the mid of each
%% candidate to `add_ice_candidate/3' on the other side.
%%
%% This module and the `webrtc_media_codec' behaviour are the public
%% API. See docs/REFERENCE.md for every option and event.
-module(webrtc).

-export([
    new_peer_connection/0,
    new_peer_connection/1,
    default_codecs/1,
    prefer_codec/2,
    add_transceiver/3,
    set_direction/3,
    stop_transceiver/2,
    transceivers/1,
    create_data_channel/3,
    create_offer/2,
    create_answer/2,
    set_local_description/3,
    set_remote_description/3,
    add_ice_candidate/2,
    add_ice_candidate/3,
    restart_ice/1,
    send_rtp/4,
    send_frame/4,
    send_media/3,
    send_media/4,
    report_media_stats/4,
    send_rtp_packet/3,
    send_rtp_packet/4,
    request_keyframe/2,
    request_keyframe/3,
    send_slice_loss/3,
    send_slice_loss/4,
    send_reference_picture/4,
    send_reference_picture/5,
    request_max_bitrate/3,
    set_target_bitrate/3,
    set_target_bitrate/4,
    request_pause/2,
    request_pause/3,
    request_resume/2,
    request_resume/3,
    set_congestion_control/2,
    resume_stream/2,
    send_data/4,
    close_data_channel/2,
    local_description/1,
    remote_description/1,
    signaling_state/1,
    connection_state/1,
    get_stats/1,
    get_stats/2,
    close/1,
    controlling_process/2
]).

-export_type([pc/0, sdp_type/0]).

-type pc() :: pid().
-type sdp_type() :: offer | answer | pranswer | rollback.

-define(TIMEOUT, 10000).

%% @equiv new_peer_connection(#{})
-spec new_peer_connection() -> {ok, pc()} | {error, term()}.
new_peer_connection() ->
    new_peer_connection(#{}).

%% @doc Create a peer connection. Every option is optional: `owner',
%% the ICE servers (`stun_servers', `turn_servers', `ice_servers'),
%% local addresses, DTLS, codecs and extensions, congestion control,
%% `frames' and `codec_plugins', and more. See docs/REFERENCE.md
%% ("Peer connection options") for every key, its type and default.
-spec new_peer_connection(map()) -> {ok, pc()} | {error, term()}.
new_peer_connection(Opts) ->
    maybe
        {ok, Frames} ?= webrtc_jsep:frames_opts(maps:get(frames, Opts, false)),
        ok ?= plugins(maps:get(codec_plugins, Opts, #{}), Frames),
        servers(Opts)
    end.

plugins(#{} = Ps, Frames) ->
    case [P || K := P <- Ps, not lists:member(K, [audio, video]) orelse
                                 element(1, webrtc_jsep:plugin_opts(P, Frames)) =/= ok] of
        [] -> ok;
        [Bad | _] -> {error, {badarg, {codec_plugins, Bad}}}
    end;
plugins(Other, _Frames) ->
    {error, {badarg, {codec_plugins, Other}}}.

servers(#{ice_servers := Servers} = Opts) ->
    case webrtc_ice_uri:servers(Servers) of
        {ok, _, _} -> new_pc(Opts);
        {error, _} -> {error, {badarg, ice_servers}}
    end;
servers(Opts) ->
    new_pc(Opts).

new_pc(#{max_message_size := M}) when not is_integer(M); M =< 0 ->
    %% RFC 8841 §6 gives 0 the meaning "any size"; we always have a
    %% memory bound, so a positive limit is required.
    {error, {badarg, max_message_size}};
new_pc(#{ice_pacing := Ta}) when not is_integer(Ta); Ta < 5; Ta > 9999999999 ->
    %% RFC 8445 §14.2: no more than one check every 5 ms.
    {error, {badarg, ice_pacing}};
new_pc(#{congestion_control := C}) when not is_map(C) ->
    {error, {badarg, congestion_control}};
new_pc(#{codecs := Codecs} = Opts) when is_map(Codecs) ->
    %% RFC 5761 §4: with RTP and RTCP on one port, payload types 64..95
    %% would read as RTCP packet types.
    case [Pt || _ := Cs <- Codecs, is_list(Cs), #{pt := Pt} <- Cs, Pt >= 64, Pt =< 95] of
        [] -> start_pc(Opts);
        [Pt | _] -> {error, {badarg, {payload_type, Pt}}}
    end;
new_pc(Opts) ->
    start_pc(Opts).

start_pc(Opts) ->
    case valid_sctp(maps:get(sctp, Opts, #{})) of
        true -> webrtc_pc_sup:start_child(maps:merge(#{owner => self()}, Opts));
        false -> {error, {badarg, sctp}}
    end.

%% The SCTP settings an application may change (docs/REFERENCE.md,
%% "SCTP options"); the transport fills in the others.
valid_sctp(S) when is_map(S) ->
    Pos = fun(V) -> is_integer(V) andalso V > 0 end,
    Check = #{rto_initial => Pos, rto_min => Pos, rto_max => Pos,
              max_backoff => fun(V) -> V =:= infinity orelse Pos(V) end,
              max_retransmissions => fun(V) -> V =:= infinity orelse (is_integer(V) andalso V >= 0) end,
              max_init_retransmissions => fun(V) -> is_integer(V) andalso V >= 0 end},
    lists:all(fun({K, V}) -> case Check of #{K := F} -> F(V); _ -> false end end, maps:to_list(S));
valid_sctp(_) ->
    false.

%% @doc The codecs a peer connection offers when the `codecs' option is
%% not given, in their order of preference. See docs/REFERENCE.md
%% ("Codecs").
-spec default_codecs(audio | video) -> [map()].
default_codecs(Kind) when Kind =:= audio; Kind =:= video ->
    webrtc_jsep_caps:default_codecs(Kind).

%% @doc `Codecs' with codec `Name' (`<<"AV1">>', `<<"H264">>', ...) moved
%% first, with its rtx entries; the others follow in their order, so the
%% peer can still fall back on them. For the `codecs' option:
%% `#{video => V}' with `{ok, V} = prefer_codec(<<"AV1">>,
%% default_codecs(video))'. It sets the order of our offers; an answer
%% keeps the order of the offer it answers.
-spec prefer_codec(binary(), [map()]) -> {ok, [map()]} | {error, {unknown_codec, binary()}}.
prefer_codec(Name, Codecs) when is_binary(Name), is_list(Codecs) ->
    webrtc_jsep_caps:prefer(Name, Codecs).

%% @doc Add a transceiver. `Opts': `direction' (default `sendrecv'),
%% `stream_id', `track_id', the simulcast layers `send_encodings' and
%% `recv_rids', `frames', `codec_plugin', `priority' and `interactive'.
%% See docs/REFERENCE.md ("Transceiver options").
-spec add_transceiver(pc(), audio | video, map()) -> {ok, pos_integer()} | {error, term()}.
add_transceiver(Pc, Kind, Opts) ->
    call(Pc, {add_transceiver, Kind, Opts}).

%% @doc Change the direction of transceiver `Id'; renegotiate to apply it.
-spec set_direction(pc(), pos_integer(), sendrecv | sendonly | recvonly | inactive) -> ok | {error, term()}.
set_direction(Pc, Id, Dir) ->
    call(Pc, {set_direction, Id, Dir}).

%% @doc Stop transceiver `Id'; renegotiate to apply it.
-spec stop_transceiver(pc(), pos_integer()) -> ok | {error, term()}.
stop_transceiver(Pc, Id) ->
    call(Pc, {stop_transceiver, Id}).

%% @doc Transceivers with their mid, directions and SSRCs.
-spec transceivers(pc()) -> [map()].
transceivers(Pc) ->
    call(Pc, transceivers).

%% @doc Create a data channel. `Opts': `ordered', `max_retransmits',
%% `max_packet_life_time', `protocol', `negotiated', `id' and
%% `priority' (see docs/REFERENCE.md, "Data channel options"). Returns
%% `{ok, Id}' when the id is known (association up, or a negotiated
%% channel); otherwise `ok', and the `datachannel_open' event carries
%% the id.
-spec create_data_channel(pc(), binary(), map()) -> ok | {ok, non_neg_integer()} | {error, term()}.
create_data_channel(Pc, Label, Opts) ->
    call(Pc, {create_data_channel, Label, Opts}).

%% @doc Create an offer (SDP binary). `Opts' is not read yet.
-spec create_offer(pc(), map()) -> {ok, binary()} | {error, term()}.
create_offer(Pc, Opts) ->
    call(Pc, {create_offer, Opts}).

%% @doc Create an answer (SDP binary) to the remote offer. `Opts' is
%% not read yet.
-spec create_answer(pc(), map()) -> {ok, binary()} | {error, term()}.
create_answer(Pc, Opts) ->
    call(Pc, {create_answer, Opts}).

%% @doc Apply a local description (`rollback' takes `undefined').
-spec set_local_description(pc(), sdp_type(), binary() | undefined) -> ok | {error, term()}.
set_local_description(Pc, Type, Sdp) ->
    call(Pc, {set_local_description, Type, Sdp}).

%% @doc Apply the peer's description (`rollback' takes `undefined').
-spec set_remote_description(pc(), sdp_type(), binary() | undefined) -> ok | {error, term()}.
set_remote_description(Pc, Type, Sdp) ->
    call(Pc, {set_remote_description, Type, Sdp}).

%% @doc Add a trickled remote candidate (`<<"candidate:...">>') or
%% `end_of_candidates'.
-spec add_ice_candidate(pc(), binary() | end_of_candidates) -> ok | {error, term()}.
add_ice_candidate(Pc, Cand) ->
    call(Pc, {add_ice_candidate, Cand}).

%% @doc The same for the transport of m= section `Mid' (the sdpMid of the
%% candidate): needed when the sections are not all bundled, every
%% transport having its own candidates.
-spec add_ice_candidate(pc(), binary() | end_of_candidates, binary() | undefined) -> ok | {error, term()}.
add_ice_candidate(Pc, Cand, Mid) ->
    call(Pc, {add_ice_candidate, Cand, Mid}).

%% @doc New ICE credentials; renegotiate to complete the restart.
-spec restart_ice(pc()) -> ok.
restart_ice(Pc) ->
    call(Pc, restart_ice).

%% @doc Send an RTP payload on a transceiver. `Opts': `timestamp',
%% `marker', `codec' (name) or `pt', `rid' to send on one simulcast
%% layer of the transceiver, and `audio_level' (`{Voice, Level}',
%% RFC 6464, level in -dBov 0..127) added when the extension is
%% negotiated, encrypted when negotiated so (RFC 6904).
-spec send_rtp(pc(), binary(), binary(), map()) -> ok | {error, term()}.
send_rtp(Pc, Mid, Payload, Opts) ->
    transport(Pc, Mid, fun(T) -> webrtc_transport:send_rtp(T, Mid, Payload, Opts) end).

%% @doc Send an encoded frame on a transceiver: split into RTP payloads
%% by the codec's payload format, the marker bit on the last. `Frame' is
%% a VP8 or VP9 frame, an H.264 access unit in Annex B, an AV1 temporal
%% unit, or an audio payload. `Opts': `timestamp', `keyframe' (VP9 and
%% AV1 signal it in the payload), `codec', `rid'.
-spec send_frame(pc(), binary(), binary(), map()) -> ok | {error, term()}.
send_frame(Pc, Mid, Frame, Opts) ->
    transport(Pc, Mid, fun(T) -> webrtc_transport:send_frame(T, Mid, Frame, Opts) end).

%% @equiv send_media(Pc, Mid, Raw, #{})
-spec send_media(pc(), binary(), term()) -> ok | {error, term()}.
send_media(Pc, Mid, Raw) ->
    send_media(Pc, Mid, Raw, #{}).

%% @doc Encode raw media with the transceiver's codec plugin
%% (`codec_plugin', see `webrtc_media_codec') and send the frames.
%% `Opts': `rid'.
-spec send_media(pc(), binary(), term(), map()) -> ok | {error, term()}.
send_media(Pc, Mid, Raw, Opts) ->
    transport(Pc, Mid, fun(T) -> webrtc_transport:send_media(T, Mid, Raw, Opts) end).

%% @doc Report W3C statistics of media you code yourself: `inbound'
%% (decoder members of the transceiver's received streams, such as
%% `framesDecoded' or `totalDecodeTime'), `outbound' (encoder members
%% such as `framesEncoded' or `qualityLimitationReason'), `source' (the
%% media-source object: `audioLevel', `width', `frames', ...) or
%% `playout' (the media-playout object of received audio). Keys are W3C
%% member names; counters add up across reports, other members replace
%% the previous value; an unknown member or a value of the wrong type
%% is dropped. Any process can call it; it does not wait.
-spec report_media_stats(pc(), binary(), inbound | outbound | source | playout, map()) -> ok.
report_media_stats(Pc, Mid, Dir, Report) when Dir =:= inbound; Dir =:= outbound; Dir =:= source; Dir =:= playout ->
    case webrtc_registry:lookup({Pc, Mid}) of
        {ok, T} -> webrtc_transport:report_media_stats(T, Mid, Dir, Report);
        error ->
            case webrtc_registry:lookup(Pc) of
                {ok, T} -> webrtc_transport:report_media_stats(T, Mid, Dir, Report);
                error -> ok
            end
    end.

%% @doc Forward an RTP packet (`#rtp{}') on a transceiver: SSRC and
%% sequence number are replaced by the transceiver's.
-spec send_rtp_packet(pc(), binary(), tuple()) -> ok | {error, term()}.
send_rtp_packet(Pc, Mid, Pkt) ->
    send_rtp_packet(Pc, Mid, Pkt, #{}).

%% @doc Forward an RTP packet. `Opts': `rid' to send it on one simulcast
%% layer, with that layer's SSRC and sequence numbers.
-spec send_rtp_packet(pc(), binary(), tuple(), map()) -> ok | {error, term()}.
send_rtp_packet(Pc, Mid, Pkt, Opts) ->
    Key = layer(Mid, Opts),
    transport(Pc, Mid, fun(T) -> webrtc_transport:send_rtp_packet(T, Key, Pkt) end).

%% @doc Ask the remote sender of a transceiver for a keyframe (PLI on
%% every stream it sends).
-spec request_keyframe(pc(), binary()) -> ok | {error, term()}.
request_keyframe(Pc, Mid) ->
    request_keyframe(Pc, Mid, #{}).

%% @doc `Opts': `rid' to ask for a keyframe on one simulcast layer only.
%% Returns `ok' and sends nothing while the SSRC of that layer is unknown.
-spec request_keyframe(pc(), binary(), map()) -> ok | {error, term()}.
request_keyframe(Pc, Mid, Opts) ->
    Key = layer(Mid, Opts),
    transport(Pc, Mid, fun(T) -> webrtc_transport:request_keyframe(T, Key) end).

%% @doc Give the encoder of a transceiver's codec plugin a bit rate, in
%% bits per second: its `control/2' gets `{target_bitrate, Bps}', now or
%% when it starts. Split `{bandwidth_estimate, Bps}' between your encoders
%% and call this for each. Returns `{error, no_codec_plugin}' without a
%% plugin on the transceiver, `{error, not_sending}' when it does not send.
-spec set_target_bitrate(pc(), binary(), non_neg_integer()) -> ok | {error, term()}.
set_target_bitrate(Pc, Mid, Bps) ->
    set_target_bitrate(Pc, Mid, Bps, #{}).

%% @doc `Opts': `rid' for the encoder of one simulcast layer.
-spec set_target_bitrate(pc(), binary(), non_neg_integer(), map()) -> ok | {error, term()}.
set_target_bitrate(Pc, Mid, Bps, Opts) when is_integer(Bps), Bps >= 0 ->
    Key = layer(Mid, Opts),
    transport(Pc, Mid, fun(T) -> webrtc_transport:set_target_bitrate(T, Key, Bps) end).

%% @doc Ask the remote sender of a transceiver to keep its streams under
%% `Bps' bits per second, RTP headers and payload, with TMMBR (RFC 5104
%% §4.2.1), or to lift the limit with `infinity'. Needs `ccm tmmbr'
%% negotiated on both sides, `{error, not_negotiated}' otherwise. The
%% request is repeated until the sender acknowledges it.
-spec request_max_bitrate(pc(), binary(), pos_integer() | infinity) -> ok | {error, term()}.
request_max_bitrate(Pc, Mid, Bps) when is_integer(Bps), Bps > 0; Bps =:= infinity ->
    transport(Pc, Mid, fun(T) -> webrtc_transport:request_max_bitrate(T, Mid, Bps) end).

%% @doc Tell the remote encoder of a transceiver that slices were lost
%% (SLI, RFC 4585 §6.3.2, RFC 8834 §5.1.3): `Entries' are
%% `{First, Number, PictureId}' (13, 13 and 6 bits). Needs `nack sli'
%% negotiated, `{error, not_negotiated}' otherwise.
-spec send_slice_loss(pc(), binary(), [{0..8191, 0..8191, 0..63}, ...]) -> ok | {error, term()}.
send_slice_loss(Pc, Mid, Entries) ->
    send_slice_loss(Pc, Mid, Entries, #{}).

%% @doc `Opts': `rid' for one simulcast layer.
-spec send_slice_loss(pc(), binary(), [{0..8191, 0..8191, 0..63}, ...], map()) -> ok | {error, term()}.
send_slice_loss(Pc, Mid, [_ | _] = Entries, Opts) ->
    Valid = lists:all(fun({F, N, P}) -> is_integer(F) andalso F >= 0 andalso F < 8192 andalso
                                           is_integer(N) andalso N >= 0 andalso N < 8192 andalso
                                           is_integer(P) andalso P >= 0 andalso P < 64;
                         (_) -> false
                      end, Entries),
    case Valid of
        true -> loss_indication(Pc, Mid, Opts, {slice_loss, Entries});
        false -> {error, badarg}
    end.

%% @doc Ask the remote encoder of a transceiver to use a reference
%% picture the decoder has (RPSI, RFC 4585 §6.3.3, RFC 8834 §5.1.4).
%% `Bits' is the codec's native RPSI bit string for payload type `Pt'.
%% Needs `nack rpsi' negotiated.
-spec send_reference_picture(pc(), binary(), 0..127, bitstring()) -> ok | {error, term()}.
send_reference_picture(Pc, Mid, Pt, Bits) ->
    send_reference_picture(Pc, Mid, Pt, Bits, #{}).

%% @doc `Opts': `rid' for one simulcast layer.
-spec send_reference_picture(pc(), binary(), 0..127, bitstring(), map()) -> ok | {error, term()}.
send_reference_picture(Pc, Mid, Pt, Bits, Opts)
  when is_integer(Pt), Pt >= 0, Pt =< 127, is_bitstring(Bits), bit_size(Bits) > 0 ->
    loss_indication(Pc, Mid, Opts, {reference_picture, Pt, Bits});
send_reference_picture(_Pc, _Mid, _Pt, _Bits, _Opts) ->
    {error, badarg}.

loss_indication(Pc, Mid, Opts, Fb) ->
    Key = layer(Mid, Opts),
    transport(Pc, Mid, fun(T) -> webrtc_transport:send_loss_indication(T, Key, Fb) end).

%% @doc Ask the remote sender of a transceiver to pause its stream
%% (RFC 7728 PAUSE), when both sides negotiated `ccm pause'. The answer
%% comes as `{remote_paused, Mid}' or `{pause_refused, Mid}' (with the
%% rid for a simulcast layer); the request is repeated until then.
-spec request_pause(pc(), binary()) -> ok | {error, term()}.
request_pause(Pc, Mid) ->
    request_pause(Pc, Mid, #{}).

%% @doc `Opts': `rid' to pause one simulcast layer only.
-spec request_pause(pc(), binary(), map()) -> ok | {error, term()}.
request_pause(Pc, Mid, Opts) ->
    transport(Pc, Mid, fun(T) -> webrtc_transport:request_pause(T, layer(Mid, Opts), pause) end).

%% @doc Ask the remote sender to resume a paused stream (RFC 7728
%% RESUME). `{remote_resumed, Mid}' follows with its first packet.
-spec request_resume(pc(), binary()) -> ok | {error, term()}.
request_resume(Pc, Mid) ->
    request_resume(Pc, Mid, #{}).

-spec request_resume(pc(), binary(), map()) -> ok | {error, term()}.
request_resume(Pc, Mid, Opts) ->
    transport(Pc, Mid, fun(T) -> webrtc_transport:request_pause(T, layer(Mid, Opts), resume) end).

layer(Mid, #{rid := Rid}) when is_binary(Rid) -> {Mid, Rid};
layer(Mid, _) -> Mid.

%% @doc Configure congestion control of the connection's media, once
%% the transport exists (after the first description is set). `Opts':
%% `pacing' (boolean, default true; false sends every packet at once),
%% `pacing_factor' (default 2.5), `min_bitrate' and `max_bitrate'
%% (bits per second).
-spec set_congestion_control(pc(), map()) -> ok | {error, term()}.
set_congestion_control(Pc, Opts) when is_map(Opts) ->
    transport(Pc, fun(T) -> webrtc_transport:set_congestion_control(T, Opts) end).

%% @doc Restart the streams of a transceiver that a circuit breaker
%% halted (`{circuit_breaker, Mid, Reason}' event). RFC 8083 §4.5 asks
%% for a human or a sign that the congestion is gone before restarting;
%% the call is refused with `{error, {retry_after, Ms}}' during the hold
%% time (`circuit_breaker_hold', default 15 s).
-spec resume_stream(pc(), binary()) -> ok | {error, term()}.
resume_stream(Pc, Mid) when is_binary(Mid) ->
    transport(Pc, Mid, fun(T) -> webrtc_transport:resume_stream(T, Mid) end).

%% @doc Send a text or binary message on data channel `Id'.
-spec send_data(pc(), non_neg_integer(), text | binary, iodata()) -> ok | {error, term()}.
send_data(Pc, Id, Type, Data) ->
    transport(Pc, data, fun(T) -> webrtc_transport:send_data(T, Id, Type, iolist_to_binary(Data)) end).

%% @doc Close data channel `Id'.
-spec close_data_channel(pc(), non_neg_integer()) -> ok | {error, term()}.
close_data_channel(Pc, Id) ->
    transport(Pc, data, fun(T) -> webrtc_transport:close_channel(T, Id) end).

%% @doc The current local description, or `undefined'.
-spec local_description(pc()) -> binary() | undefined.
local_description(Pc) -> call(Pc, local_description).

%% @doc The current remote description, or `undefined'.
-spec remote_description(pc()) -> binary() | undefined.
remote_description(Pc) -> call(Pc, remote_description).

%% @doc The JSEP signaling state, as in `{signaling_state, State}' events.
-spec signaling_state(pc()) -> atom().
signaling_state(Pc) -> call(Pc, signaling_state).

%% @doc The connection state, as in `{connection_state, State}' events.
-spec connection_state(pc()) -> atom().
connection_state(Pc) -> call(Pc, connection_state).

%% @doc Internal statistics; see get_stats/2 for the W3C ones.
-spec get_stats(pc()) -> map().
get_stats(Pc) -> call(Pc, get_stats).

%% @doc Statistics. `#{format => w3c}' gives the W3C WebRTC statistics
%% (webrtc_stats): a map from stats id to a map of the dictionary's
%% members; `#{format => internal}' is get_stats/1.
-spec get_stats(pc(), #{format => w3c | internal}) -> map().
get_stats(Pc, #{format := w3c}) -> call(Pc, {get_stats, w3c});
get_stats(Pc, _) -> get_stats(Pc).

%% @doc Close the peer connection. Returns `ok' if it is already gone.
-spec close(pc()) -> ok.
close(Pc) ->
    try
        call(Pc, close)
    catch
        exit:{noproc, _} -> ok;
        exit:{normal, _} -> ok;
        exit:{shutdown, _} -> ok;
        exit:{{shutdown, _}, _} -> ok
    end.

call(Pc, Msg) ->
    gen_server:call(Pc, Msg, ?TIMEOUT).

%% Media and data go straight to the transport process, found in the
%% `webrtc_transports' table that the peer connection keeps up to date.
%% The transport of a mid (or of the data channel), when the sections
%% are not all bundled; otherwise the only one.
transport(Pc, Key, F) ->
    case webrtc_registry:lookup({Pc, Key}) of
        {ok, T} -> run_transport(Pc, T, F);
        error -> transport(Pc, F)
    end.

transport(Pc, F) ->
    case webrtc_registry:lookup(Pc) of
        {ok, T} ->
            run_transport(Pc, T, F);
        error ->
            %% No transport yet, or the peer connection is gone.
            try call(Pc, transport_pid) of
                {ok, T} -> run_transport(Pc, T, F);
                {error, _} = E -> E
            catch
                exit:{Reason, _} when Reason =:= noproc; Reason =:= normal; Reason =:= shutdown;
                                tuple_size(Reason) =:= 2, element(1, Reason) =:= shutdown ->
                    {error, closed}
            end
    end.

run_transport(Pc, T, F) ->
    try
        F(T)
    catch
        exit:{Reason, _} when Reason =:= noproc; Reason =:= normal; Reason =:= shutdown;
                                tuple_size(Reason) =:= 2, element(1, Reason) =:= shutdown ->
            ets:delete_object(webrtc_transports, {Pc, T}),
            {error, closed}
    end.

%% @doc Make `Pid' the owner: it receives every event from now on, and
%% the peer connection closes when it exits.
-spec controlling_process(pc(), pid()) -> ok | {error, term()}.
controlling_process(Pc, Pid) when is_pid(Pid) ->
    call(Pc, {controlling_process, Pid}).
