%% @doc WebRTC peer connections in pure Erlang.
%%
%% A peer connection is a process. The process that creates it (or the
%% `owner' option) receives every event as `{webrtc, Pc, Event}':
%%
%% <ul>
%% <li>`negotiation_needed'</li>
%% <li>`{signaling_state, State}'</li>
%% <li>`{ice_candidate, Candidate, Mid}': a local candidate to send to
%%     the peer (`Candidate' is `<<"candidate:...">>' or
%%     `end_of_candidates').</li>
%% <li>`{ice_gathering_state, new | gathering | complete}'</li>
%% <li>`{ice_connection_state, State}'</li>
%% <li>`{connection_state, new | connecting | connected | disconnected
%%     | failed | closed}'</li>
%% <li>`{ice_restart, disconnected | consent_lost}': the connection
%%     restarted ICE by itself (`ice_auto_restart'); a
%%     `negotiation_needed' follows, so send the new offer, unless the
%%     `signaling' option sends it for you.</li>
%% <li>`{track, Mid, audio | video}': the remote side sends media on
%%     this transceiver.</li>
%% <li>`{ssrc_changed, Mid, Old, New}': the peer sent with one of our
%%     SSRCs, so ours changed (RFC 3550 §8.2); a BYE went out for the old
%%     one.</li>
%% <li>`{rtp, Mid, #rtp{}}': an RTP packet (see `webrtc_rtp.hrl').</li>
%% <li>`{rtp, Mid, Rid, #rtp{}}': an RTP packet of the simulcast layer
%%     `Rid' (RFC 8853) of a transceiver that receives several layers.
%%     Retransmissions arrive already decapsulated on their layer.</li>
%% <li>`{keyframe_request, Mid}': the remote side asked for a keyframe.</li>
%% <li>`{keyframe_request, Mid, Rid}': the same, for one simulcast layer
%%     we send.</li>
%% <li>`{stream_paused, Mid}', `{stream_resumed, Mid}': the remote side
%%     asked us to pause or resume what we send on the transceiver
%%     (RFC 7728); `send_rtp' returns `{error, paused}' meanwhile. With a
%%     rid for one simulcast layer.</li>
%% <li>`{remote_paused, Mid}', `{remote_resumed, Mid}',
%%     `{pause_refused, Mid}': answers to `request_pause/2,3' and
%%     `request_resume/2,3', with a rid for one simulcast layer.</li>
%% <li>`{rtcp, Mid, Packet}': congestion feedback (REMB, TWCC).</li>
%% <li>`{slice_loss, Mid, Entries}', `{reference_picture, Mid, Pt, Bits}'
%%     (with the rid after `Mid' for a simulcast layer): the remote
%%     decoder lost slices (SLI) or asks for a reference picture (RPSI),
%%     RFC 8834 §5.1.3, §5.1.4. Repair or change the reference in your
%%     encoder; a codec plugin gets them in `feedback/2'.</li>
%% <li>`{dscp_disabled, Dscp}': the path drops packets marked `Dscp'
%%     (RFC 8835 §4.2): the flows that used it now go unmarked.</li>
%% <li>`{bandwidth_estimate, Bps}': the congestion controller changed
%%     the target bitrate for all media sent on the connection; adapt
%%     the encoders to it.</li>
%% <li>`{max_bitrate, Mid, Bps}', `{max_bitrate, Mid, Rid, Bps}': the
%%     peer limited what the stream may send with TMMBR (RFC 5104), in
%%     payload bits per second, or lifted the limit (`infinity'). The
%%     connection holds the stream to it, queuing and at worst dropping
%%     packets; keep the encoder under it.</li>
%% <li>`{circuit_breaker, Mid, Reason}': an RTP circuit breaker of
%%     RFC 8083 triggered for the stream (`rtcp_timeout',
%%     `media_timeout' or `congestion'). The transceiver's RTP streams
%%     are halted (RFC 8083 §4.5): `send_rtp' returns
%%     `{error, {circuit_breaker, Reason}}' until `resume_stream/2'.
%%     RTCP keeps flowing.</li>
%% <li>`{datachannel_open, Id, Label, Protocol, Opts}'</li>
%% <li>`{channel_message, Id, text | binary, Data}'</li>
%% <li>`{datachannel_closed, Id}', `{buffered_amount_low, Id}'</li>
%% <li>`{datachannel_error, Id, message_too_large}': the peer sent a
%%     message over our `max_message_size'; the channel is closed.</li>
%% <li>`{datachannel_error, Id, invalid_stream_id}': a channel created
%%     before the connection on an id beyond the streams negotiated
%%     with the peer; it is closed.</li>
%% <li>`{datachannel_open_failed, Label, Reason}': a channel created
%%     before the connection could not be opened once it came up.</li>
%% <li>`{dtls_error, Reason}'</li>
%% </ul>
%%
%% Simulcast: a transceiver added with `send_encodings' offers one layer
%% per encoding; send on a layer with the `rid' option of `send_rtp/4'
%% and `send_rtp_packet/4'. When the remote side offers simulcast, the
%% answer accepts its layers and each one is delivered with its rid. The
%% negotiated layers are in `transceivers/1' (`send_encodings') and in
%% the `{rtp, Mid, Rid, _}' events. A layer that the answer removed is
%% not sent: `send_rtp' returns `{error, not_sending}' for it.
%%
%% Signaling is the application's business: exchange the SDP returned by
%% `create_offer/2' and `create_answer/2' and the candidates of
%% `ice_candidate' events by any means. Pass the mid of the event to
%% `add_ice_candidate/3' on the other side: when the sections are not
%% all bundled, it names the transport of the candidate.
-module(webrtc).

-export([
    new_peer_connection/0,
    new_peer_connection/1,
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

%% @doc Create a peer connection. Options:
%% <ul>
%% <li>`owner': pid receiving events (default: the caller).</li>
%% <li>`stun_servers': `[{IP, Port}]'.</li>
%% <li>`turn_servers': `[#{address => {IP, Port}, username => U,
%%     password => P}]', reached over UDP. With `transport => tcp' or
%%     `tls' the server is reached over a TCP or TLS connection
%%     (RFC 8656 §3.1; the relay itself is UDP). For TLS the server
%%     certificate is verified against the system CA store and
%%     `hostname' (default: the IP address); `tls_options' (`ssl'
%%     client options) replace these defaults, for example
%%     `[{cacerts, [Der]}]'.</li>
%% <li>`ice_servers': the W3C RTCIceServer list, `[#{urls => [Uri],
%%     username => U, credential => C}]', with `stun:', `turn:' and
%%     `turns:' URIs (RFC 7064, RFC 7065), for example
%%     `<<"turn:turn.example.com?transport=tcp">>'. Names are resolved
%%     when the peer connection starts (SRV records first when the URI
%%     has no port, RFC 5928), within `ice_server_timeout' ms (default
%%     2000); a URI that cannot be used is reported as
%%     `{ice_server_error, Url, Reason}'. The servers are added to
%%     `stun_servers' and `turn_servers', eight in all at most.</li>
%% <li>`ice_lite': run as an ICE-Lite agent (servers with a public
%%     address).</li>
%% <li>`ice_pacing': the interval between connectivity checks (Ta) in
%%     ms, at least 5, default 50. Another value is announced with
%%     `a=ice-pacing', and both sides use the higher of the two (RFC
%%     8445 §14.2).</li>
%% <li>`rtcp_mux_policy': `negotiate' (default) or `require', which
%%     adds `a=rtcp-mux-only' to offers (RFC 8858). RTP and RTCP are
%%     always multiplexed; codecs on payload types 64..95 are refused
%%     (RFC 5761 §4).</li>
%% <li>`ice_auto_restart': restart ICE when the selected path stops
%%     working, since RFC 8445 §8.1.1 allows no second nomination in an
%%     ICE session. `disconnected' (default) restarts after
%%     `ice_restart_delay' ms (default 2000) of consent trouble,
%%     `failed' only once consent is lost (30 s), `false' never. The
%%     controlling side restarts first, the controlled side after three
%%     times the delay if no restart offer came. Up to 3 restarts per
%%     incident; meanwhile the connection is reported `disconnected'
%%     rather than `failed'. DTLS and data channels survive the restart
%%     (RFC 8842).</li>
%% <li>`signaling': `fun((offer | answer, Sdp) -> any())' that sends a
%%     description to the peer. When set, the connection runs ICE
%%     restarts without you: it creates and applies the offer of an
%%     automatic restart, answers every restart offer you pass to
%%     `set_remote_description/3', and hands each description to the
%%     function. Only pass the peer's descriptions to
%%     `set_remote_description/3' and relay candidates as usual; they
%%     arrive after the description they belong to. On glare the
%%     controlled side rolls its own offer back. The function runs in a
%%     helper process and may call either peer connection.</li>
%% <li>`addresses': local `[{IP, Port}]' to bind, default every
%%     interface; `loopback' (boolean) to use only 127.0.0.1.</li>
%% <li>`certificate': `webrtc_dtls_cert:generate/1' result, default a
%%     fresh ECDSA P-256 certificate.</li>
%% <li>`max_message_size': data channel limit announced in SDP.</li>
%% <li>`congestion_control': initial options of the estimator, pacer and
%%     circuit breakers (`start_bitrate', `min_bitrate', `max_bitrate',
%%     `pacing', `probing', `pacing_factor', `rtcp_timeout',
%%     `circuit_breaker_hold', ...), see `webrtc_cc'.</li>
%% <li>`ice_tcp': also gather TCP host candidates (RFC 6544), default
%%     `false': a passive one listening next to every UDP host address
%%     and an active one, both below the UDP candidates in priority.
%%     They connect peers whose UDP is blocked; DTLS, SRTP and SCTP then
%%     run over the TCP connection.</li>
%% <li>`rtcp_report_interval': the shortest interval between regular
%%     RTCP reports in ms (the local T_rr_interval of RFC 4585 §3.5.3,
%%     default 1000, 0 for the RFC 3550 interval alone). Feedback is not
%%     bound by it.</li>
%% <li>`codecs', `extensions': the codecs and RTP header extensions to
%%     negotiate, as maps keyed by `audio' and `video' (default
%%     `webrtc_jsep_caps:default_codecs/1' and
%%     `webrtc_jsep_caps:default_extensions/1').</li>
%% <li>`mdns_host_candidates': signal host candidates with a random
%%     `<uuid>.local' name answered by multicast DNS instead of the
%%     address (draft-ietf-mmusic-mdns-ice-candidates), default
%%     `false'. Remote `.local' and DNS names are always resolved.</li>
%% <li>`mdns_expose_public': with `mdns_host_candidates', a host address
%%     a STUN server mapped to itself is public and later gatherings
%%     signal it as it is (draft-ietf-mmusic-mdns-ice-candidates
%%     §3.1.2.2), default `true'; the finding is dropped when the STUN
%%     servers change.</li>
%% <li>`mdns': resolver options, see `webrtc_mdns' (`max_pending',
%%     `schedule', `group', `listen', `group6', `listen6', ...).</li>
%% <li>`bundle': offer every m= section in one BUNDLE group (RFC 9143),
%%     default `true'. With `false' every section gets its own ICE and
%%     DTLS transport; relay candidates with `add_ice_candidate/3' and
%%     the mid of their `ice_candidate' event. Answers follow the offer
%%     whatever this option says, and later offers keep the transports
%%     the last answer set.</li>
%% <li>`dtls': DTLS options; `connection_id' (`true' or a binary) offers
%%     and accepts a connection ID (DTLS 1.3, RFC 9147 §9; DTLS 1.2,
%%     RFC 9146), default off: ICE already follows address changes and
%%     browsers do not use it. With DTLS 1.3, records move to a spare CID
%%     of the peer after an ICE restart or a new selected pair (RFC 9146
%%     §8); DTLS 1.2 has no way to change it.
%%     `resumption' (default false) issues DTLS 1.3 tickets and resumes
%%     with them the next association between the same certificates,
%%     skipping the certificate messages (each side's certificate is the
%%     one of the ticket, checked against the SDP fingerprints);
%%     `ticket_lifetime' (s, default 7200).</li>
%% <li>`encrypt_header_extensions': RFC 6904 encrypted header extension
%%     elements (the audio level, RFC 8834 §5.2.2). `accept' (default)
%%     answers an encrypted offer encrypted but offers the clear form
%%     only, as aiortc and Chromium mishandle the encrypted one; `offer'
%%     offers both forms; `false' neither offers nor accepts them.
%%     `transceivers/1' reports the negotiated ids.</li>
%% <li>`srtp_profiles': SRTP protection profile ids offered in DTLS,
%%     most preferred first (default AES-GCM 128 and 256, then
%%     AES-CM 80 and 32).</li>
%% <li>`cryptex': offer and accept encrypted CSRC lists and RTP header
%%     extensions (RFC 9335), default `true'. Media is sent that way
%%     when every section of the connection negotiated it.</li>
%% <li>`video_fec': FEC packets sent per video packet, FlexFEC (RFC
%%     8627) or ULPFEC in RED (RFC 5109, RFC 8854 §5.2), whichever the
%%     peer negotiates, FlexFEC first: `auto'
%%     (default: twice the fraction lost the peer reports, at most 0.5,
%%     none without loss) or a number, 0.0 to send none.</li>
%% <li>`frames': the `frames' option of transceivers added without it,
%%     those a remote offer creates included (see
%%     `add_transceiver/3'), default `false'.</li>
%% </ul>
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
        [] -> webrtc_pc_sup:start_child(maps:merge(#{owner => self()}, Opts));
        [Pt | _] -> {error, {badarg, {payload_type, Pt}}}
    end;
new_pc(Opts) ->
    webrtc_pc_sup:start_child(maps:merge(#{owner => self()}, Opts)).

%% @doc Add a transceiver. `Opts': `direction' (default `sendrecv'),
%% `stream_id', `track_id' and `send_encodings', the simulcast layers to
%% send (RFC 8853), most preferred first: a list of `#{rid => Rid,
%% restrictions => [{Name, Value}]}' where `restrictions' are RFC 8851
%% §5 restrictions such as `{<<"max-width">>, <<"640">>}'. Returns
%% `{error, invalid_encodings}' for duplicate or malformed rids.
%% `recv_rids' lists the simulcast layers to ask the peer for, as rids
%% or `#{rid => Rid, paused => true}' for a layer that starts paused
%% (resume it with `request_resume/3'). A transceiver without
%% `send_encodings' answering an offer that asks to receive simulcast
%% sends the offered layers.
%%
%% `frames': `true' or `#{min_delay => Ms, max_delay => Ms}' delivers
%% `{frame, Mid, Frame}' (`{frame, Mid, Rid, Frame}' for a simulcast
%% layer) instead of `{rtp, Mid, Packet}': the packets of each frame put
%% in order, joined and released at their playout time, a key frame
%% asked for when one is lost (see `webrtc_frame_buffer'). `Frame' is
%% `#{timestamp, keyframe, data, codec}', with `width' and `height' for
%% video. `data' is the encoded frame: VP8 and VP9 frames, H.264 in
%% Annex B, AV1 temporal units in the low overhead bitstream format.
%% With RFC 6051 negotiated, `ntp_time' is the capture time on the
%% sender's clock (microseconds since the Unix epoch).
%%
%% `priority' (`very_low', `low' (default), `medium', `high'), also per
%% encoding in `send_encodings', marks the packets with the DSCP of
%% RFC 8837 (EF for audio, AF4x for video, LE at `very_low', none at
%% `low'); `interactive => false' uses AF3x for video nobody answers
%% live. The packets of a key frame get the lower drop precedence.
-spec add_transceiver(pc(), audio | video, map()) -> {ok, pos_integer()} | {error, term()}.
add_transceiver(Pc, Kind, Opts) ->
    call(Pc, {add_transceiver, Kind, Opts}).

-spec set_direction(pc(), pos_integer(), sendrecv | sendonly | recvonly | inactive) -> ok | {error, term()}.
set_direction(Pc, Id, Dir) ->
    call(Pc, {set_direction, Id, Dir}).

-spec stop_transceiver(pc(), pos_integer()) -> ok | {error, term()}.
stop_transceiver(Pc, Id) ->
    call(Pc, {stop_transceiver, Id}).

%% @doc Transceivers with their mid, directions and SSRCs.
-spec transceivers(pc()) -> [map()].
transceivers(Pc) ->
    call(Pc, transceivers).

%% @doc Create a data channel. `Opts': `ordered', `max_retransmits',
%% `max_packet_life_time', `protocol', `negotiated', `id' and
%% `priority' (`very_low', `low' (default), `medium', `high' or a DCEP
%% value 0..65535): channels share the association in proportion to
%% it (RFC 8831 §6.4), and the peer is told it. Returns
%% `{ok, Id}' when the id is known (association up, or a pre-negotiated
%% channel); otherwise `ok', the channel is opened as soon as the
%% association is up and the `datachannel_open' event carries its id.
-spec create_data_channel(pc(), binary(), map()) -> ok | {ok, non_neg_integer()} | {error, term()}.
create_data_channel(Pc, Label, Opts) ->
    call(Pc, {create_data_channel, Label, Opts}).

%% @doc Create an offer (SDP binary). `Opts': none yet.
-spec create_offer(pc(), map()) -> {ok, binary()} | {error, term()}.
create_offer(Pc, Opts) ->
    call(Pc, {create_offer, Opts}).

-spec create_answer(pc(), map()) -> {ok, binary()} | {error, term()}.
create_answer(Pc, Opts) ->
    call(Pc, {create_answer, Opts}).

-spec set_local_description(pc(), sdp_type(), binary() | undefined) -> ok | {error, term()}.
set_local_description(Pc, Type, Sdp) ->
    call(Pc, {set_local_description, Type, Sdp}).

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

-spec send_data(pc(), non_neg_integer(), text | binary, iodata()) -> ok | {error, term()}.
send_data(Pc, Id, Type, Data) ->
    transport(Pc, data, fun(T) -> webrtc_transport:send_data(T, Id, Type, iolist_to_binary(Data)) end).

-spec close_data_channel(pc(), non_neg_integer()) -> ok | {error, term()}.
close_data_channel(Pc, Id) ->
    transport(Pc, data, fun(T) -> webrtc_transport:close_channel(T, Id) end).

-spec local_description(pc()) -> binary() | undefined.
local_description(Pc) -> call(Pc, local_description).

-spec remote_description(pc()) -> binary() | undefined.
remote_description(Pc) -> call(Pc, remote_description).

-spec signaling_state(pc()) -> atom().
signaling_state(Pc) -> call(Pc, signaling_state).

-spec connection_state(pc()) -> atom().
connection_state(Pc) -> call(Pc, connection_state).

-spec get_stats(pc()) -> map().
get_stats(Pc) -> call(Pc, get_stats).

%% @doc Statistics. `#{format => w3c}' gives the W3C WebRTC statistics
%% (webrtc_stats): a map from stats id to a map of the dictionary's
%% members; `#{format => internal}' is get_stats/1.
-spec get_stats(pc(), #{format => w3c | internal}) -> map().
get_stats(Pc, #{format := w3c}) -> call(Pc, {get_stats, w3c});
get_stats(Pc, _) -> get_stats(Pc).

-spec close(pc()) -> ok.
close(Pc) ->
    try
        call(Pc, close)
    catch
        exit:{noproc, _} -> ok;
        exit:{normal, _} -> ok
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
                exit:{Reason, _} when Reason =:= noproc; Reason =:= normal; Reason =:= shutdown ->
                    {error, closed}
            end
    end.

run_transport(Pc, T, F) ->
    try
        F(T)
    catch
        exit:{Reason, _} when Reason =:= noproc; Reason =:= normal; Reason =:= shutdown ->
            ets:delete_object(webrtc_transports, {Pc, T}),
            {error, closed}
    end.

%% @doc Make `Pid' the owner: it receives every event from now on, and
%% the peer connection closes when it exits.
-spec controlling_process(pc(), pid()) -> ok | {error, term()}.
controlling_process(Pc, Pid) when is_pid(Pid) ->
    call(Pc, {controlling_process, Pid}).
