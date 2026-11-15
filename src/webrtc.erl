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
%% <li>`{track, Mid, audio | video}': the remote side sends media on
%%     this transceiver.</li>
%% <li>`{rtp, Mid, #rtp{}}': an RTP packet (see `webrtc_rtp.hrl').</li>
%% <li>`{rtp, Mid, Rid, #rtp{}}': an RTP packet of the simulcast layer
%%     `Rid' (RFC 8853) of a transceiver that receives several layers.
%%     Retransmissions arrive already decapsulated on their layer.</li>
%% <li>`{keyframe_request, Mid}': the remote side asked for a keyframe.</li>
%% <li>`{keyframe_request, Mid, Rid}': the same, for one simulcast layer
%%     we send.</li>
%% <li>`{rtcp, Mid, Packet}': congestion feedback (REMB, TWCC).</li>
%% <li>`{bandwidth_estimate, Bps}': the congestion controller changed
%%     the target bitrate for all media sent on the connection; adapt
%%     the encoders to it.</li>
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
%% `ice_candidate' events by any means.
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
    restart_ice/1,
    send_rtp/4,
    send_rtp_packet/3,
    send_rtp_packet/4,
    request_keyframe/2,
    request_keyframe/3,
    set_congestion_control/2,
    resume_stream/2,
    send_data/4,
    close_data_channel/2,
    local_description/1,
    remote_description/1,
    signaling_state/1,
    connection_state/1,
    get_stats/1,
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
%%     password => P}]'.</li>
%% <li>`ice_lite': run as an ICE-Lite agent (servers with a public
%%     address).</li>
%% <li>`addresses': local `[{IP, Port}]' to bind, default every
%%     interface; `loopback' (boolean) to use only 127.0.0.1.</li>
%% <li>`certificate': `webrtc_dtls_cert:generate/1' result, default a
%%     fresh ECDSA P-256 certificate.</li>
%% <li>`max_message_size': data channel limit announced in SDP.</li>
%% <li>`congestion_control': initial options of the estimator, pacer and
%%     circuit breakers (`start_bitrate', `min_bitrate', `max_bitrate',
%%     `pacing', `pacing_factor', `rtcp_timeout',
%%     `circuit_breaker_hold', ...), see `webrtc_cc'.</li>
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
%% <li>`mdns': resolver options, see `webrtc_mdns' (`max_pending',
%%     `schedule', `group', `listen', ...).</li>
%% </ul>
-spec new_peer_connection(map()) -> {ok, pc()} | {error, term()}.
new_peer_connection(#{max_message_size := M}) when not is_integer(M); M =< 0 ->
    %% RFC 8841 §6 gives 0 the meaning "any size"; we always have a
    %% memory bound, so a positive limit is required.
    {error, {badarg, max_message_size}};
new_peer_connection(#{congestion_control := C}) when not is_map(C) ->
    {error, {badarg, congestion_control}};
new_peer_connection(Opts) ->
    webrtc_pc_sup:start_child(maps:merge(#{owner => self()}, Opts)).

%% @doc Add a transceiver. `Opts': `direction' (default `sendrecv'),
%% `stream_id', `track_id' and `send_encodings', the simulcast layers to
%% send (RFC 8853), most preferred first: a list of `#{rid => Rid,
%% restrictions => [{Name, Value}]}' where `restrictions' are RFC 8851
%% §5 restrictions such as `{<<"max-width">>, <<"640">>}'. Returns
%% `{error, invalid_encodings}' for duplicate or malformed rids.
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
%% `max_packet_life_time', `protocol', `negotiated' and `id'. Returns
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

%% @doc New ICE credentials; renegotiate to complete the restart.
-spec restart_ice(pc()) -> ok.
restart_ice(Pc) ->
    call(Pc, restart_ice).

%% @doc Send an RTP payload on a transceiver. `Opts': `timestamp',
%% `marker', `codec' (name) or `pt', and `rid' to send on one simulcast
%% layer of the transceiver.
-spec send_rtp(pc(), binary(), binary(), map()) -> ok | {error, term()}.
send_rtp(Pc, Mid, Payload, Opts) ->
    transport(Pc, fun(T) -> webrtc_transport:send_rtp(T, Mid, Payload, Opts) end).

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
    transport(Pc, fun(T) -> webrtc_transport:send_rtp_packet(T, Key, Pkt) end).

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
    transport(Pc, fun(T) -> webrtc_transport:request_keyframe(T, Key) end).

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
    transport(Pc, fun(T) -> webrtc_transport:resume_stream(T, Mid) end).

-spec send_data(pc(), non_neg_integer(), text | binary, iodata()) -> ok | {error, term()}.
send_data(Pc, Id, Type, Data) ->
    transport(Pc, fun(T) -> webrtc_transport:send_data(T, Id, Type, iolist_to_binary(Data)) end).

-spec close_data_channel(pc(), non_neg_integer()) -> ok | {error, term()}.
close_data_channel(Pc, Id) ->
    transport(Pc, fun(T) -> webrtc_transport:close_channel(T, Id) end).

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
transport(Pc, F) ->
    case ets:lookup(webrtc_transports, Pc) of
        [{_, T}] ->
            run_transport(Pc, T, F);
        [] ->
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
