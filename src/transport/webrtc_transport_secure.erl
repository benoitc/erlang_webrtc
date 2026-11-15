%% @private Secure side of the transport process: the DTLS association
%% (created from the negotiated parameters, started once ICE has a
%% valid pair, ended when the remote identity changes or DTLS closes),
%% SRTP keyed from it, the media engine's actions, and SCTP with the data
%% channels on top of it. Internal module of `webrtc_transport', working
%% on its state.
-module(webrtc_transport_secure).

-include("webrtc_transport.hrl").

-export([
    configure_engines/2,
    start_dtls_if_ready/1,
    flush_dtls/1,
    secure_datagram/4,
    secure_datagram/5,
    secure_relayed/3,
    transmit_dtls/2,
    dtls_actions/2,
    path_changed/3,
    media_actions/2,
    do_open_channel/3,
    dcep_actions/2
]).

configure_engines(Neg, St0) ->
    #{dtls := #{role := Role, remote_fingerprints := FPs} = Dtls, media := Media, data := Data} = Neg,
    TlsId = maps:get(remote_tls_id, Dtls, undefined),
    %% RFC 8842 §5: changed fingerprints or tls-id mean a new DTLS
    %% association (JSEP only accepts that with an ICE restart).
    St00 =
        case St0#st.dtls =/= undefined andalso
                 (lists:sort(FPs) =/= lists:sort(St0#st.remote_fps) orelse
                      tls_id_changed(St0#st.remote_tls_id, TlsId)) of
            true -> end_association(dtls_identity_changed, St0);
            false -> St0
        end,
    St1 = St00#st{
        media = webrtc_media:configure(Media, St00#st.media),
        data = Data,
        remote_fps = FPs,
        remote_tls_id = TlsId
    },
    St2 =
        case St1#st.dtls of
            undefined when Role =/= undefined ->
                D = webrtc_dtls:new((St1#st.dtls_opts)#{
                    role => Role,
                    cert => St1#st.cert,
                    remote_fingerprints => FPs,
                    srtp_profiles => St1#st.srtp_profiles
                }),
                start_dtls_if_ready(St1#st{dtls = D, dtls_role = Role});
            _ ->
                St1
        end,
    case St2#st.connected andalso St2#st.dcep =:= undefined andalso Data =/= undefined of
        true -> start_sctp(St2);
        false -> St2
    end.

%% A peer that never sent a tls-id (older stacks) is compared on its
%% fingerprints only.
tls_id_changed(undefined, _) -> false;
tls_id_changed(_, undefined) -> false;
tls_id_changed(Old, New) -> Old =/= New.

%% Close the DTLS association and everything keyed or carried by it:
%% SRTP contexts and the SCTP association (its channels are reported
%% closed). ICE is kept.
end_association(Reason, #st{dtls = D} = St0) ->
    St1 =
        case D of
            undefined ->
                St0;
            _ ->
                {_, Acts} = webrtc_dtls:close(D),
                transmit_dtls(Acts, St0)
        end,
    St2 =
        case St1#st.dcep of
            undefined ->
                St1;
            Dc ->
                _ = [webrtc_transport:to_pc({datachannel, {channel_closed, Id}}, St1) || Id <- maps:keys(webrtc_dcep:channels(Dc))],
                webrtc_transport:to_pc({datachannel, {closed, Reason}}, St1),
                St1
        end,
    St2#st{
        dtls = undefined,
        dtls_role = undefined,
        dcep = undefined,
        connected = false,
        early_dtls = [],
        dtls_out = [],
        media = webrtc_media:clear_srtp(St2#st.media)
    }.

%% The client starts the handshake once ICE has a valid pair: data may
%% use any valid pair before nomination (RFC 8445 §12.1), so DTLS does
%% not wait for it. Buffered early DTLS datagrams are replayed for the
%% server.
start_dtls_if_ready(#st{dtls = undefined} = St) ->
    St;
start_dtls_if_ready(#st{dtls = D} = St) ->
    case St#st.ice_usable orelse webrtc_ice_agent:selected_pair(St#st.ice) =/= undefined of
        false ->
            St;
        true ->
            Now = webrtc_transport:now_ms(),
            {D1, A} = webrtc_dtls:start(Now, D),
            St1 = dtls_actions(A, St#st{dtls = D1}),
            lists:foldl(
                fun(Bin, S) -> dtls_in(Bin, Now, S) end,
                St1#st{early_dtls = []},
                lists:reverse(St1#st.early_dtls)
            )
    end.

%% ICE moved to another pair: with DTLS 1.3 connection IDs the records
%% take a fresh one, so the new path cannot be linked to the old one by
%% its CID (RFC 9146 §8, RFC 9147 §9).
path_changed(Old, New, #st{dtls = D} = St) when Old =/= undefined, Old =/= New, D =/= undefined ->
    Now = webrtc_transport:now_ms(),
    St1 =
        case webrtc_dtls:rotate_connection_id(Now, D) of
            {ok, D1, A} -> dtls_actions(A, St#st{dtls = D1});
            {error, _} -> St
        end,
    %% SCTP: base path MTU and fresh congestion state on the new path
    %% (RFC 8261 §6.1).
    case St1#st.dcep of
        undefined ->
            St1;
        Dc ->
            {Dc1, DActs} = webrtc_dcep:path_changed(Now, Dc),
            dcep_actions(DActs, St1#st{dcep = Dc1})
    end;
path_changed(_Old, _New, St) ->
    St.

secure_datagram(Class, Bin, Now, St) ->
    secure_datagram(Class, Bin, Now, St, 0).

secure_datagram(dtls, Bin, Now, St, _Ecn) ->
    dtls_in(Bin, Now, St);
secure_datagram(rtp, Bin, Now, St, Ecn) ->
    {M1, Acts} = webrtc_media:handle_packet(Bin, Now, St#st.media, Ecn),
    media_actions(Acts, St#st{media = M1});
secure_datagram(_, _Bin, _Now, St, _Ecn) ->
    St.

dtls_in(Bin, _Now, #st{dtls = undefined, early_dtls = E} = St) when length(E) < ?MAX_EARLY_DTLS ->
    St#st{early_dtls = [Bin | E]};
dtls_in(_Bin, _Now, #st{dtls = undefined} = St) ->
    St;
dtls_in(Bin, Now, #st{dtls = D} = St) ->
    {D1, Acts} = webrtc_dtls:handle_packet(Bin, Now, D),
    dtls_actions(Acts, St#st{dtls = D1}).

secure_relayed(_Peer, Bin, St) ->
    case webrtc_demux:classify(Bin) of
        dtls -> dtls_in(Bin, webrtc_transport:now_ms(), St);
        rtp ->
            {M1, Acts} = webrtc_media:handle_packet(Bin, webrtc_transport:now_ms(), St#st.media),
            media_actions(Acts, St#st{media = M1});
        _ -> St
    end.

transmit_dtls(Acts, St) ->
    lists:foldl(fun({send, B}, S) -> dtls_send(B, S) end, St, [A || {send, _} = A <- Acts]).

%% A DTLS server never retransmits on its own: a reply ICE cannot send
%% yet is kept (bounded) instead of waiting for the client's next
%% retransmission.
dtls_send(Bin, St) ->
    case webrtc_ice_agent:send(Bin, webrtc_transport:now_ms(), St#st.ice) of
        {ok, I1, Acts} ->
            webrtc_transport_net:ice_actions(Acts, St#st{ice = I1});
        {error, no_valid_pair} when length(St#st.dtls_out) < ?MAX_EARLY_DTLS ->
            St#st{dtls_out = St#st.dtls_out ++ [Bin]};
        {error, _} ->
            St
    end.

flush_dtls(#st{dtls_out = []} = St) ->
    St;
flush_dtls(#st{dtls_out = Out} = St) ->
    lists:foldl(fun dtls_send/2, St#st{dtls_out = []}, Out).

dtls_actions(Acts, St) ->
    lists:foldl(fun dtls_action/2, St, Acts).

dtls_action({send, Bin}, St) ->
    dtls_send(Bin, St);
dtls_action({event, {connected, Info}}, St) ->
    St1 = setup_srtp(Info, St#st{connected = true}),
    webrtc_transport:to_pc({dtls_connected, Info}, St1),
    case St1#st.data of
        undefined -> St1;
        _ -> start_sctp(St1)
    end;
dtls_action({event, {data, Bin}}, #st{dcep = D} = St) when D =/= undefined ->
    {D1, Acts} = webrtc_dcep:handle_packet(Bin, webrtc_transport:now_ms(), D),
    dcep_actions(Acts, St#st{dcep = D1});
dtls_action({event, {data, _}}, St) ->
    St;
dtls_action({event, {closed, R}}, St) ->
    webrtc_transport:to_pc({dtls_closed, R}, St),
    finish(R, St);
dtls_action({event, {failed, R}}, St) ->
    webrtc_transport:to_pc({dtls_failed, R}, St),
    finish(R, St);
dtls_action({event, _}, St) ->
    St.

%% DTLS closed (close_notify) or failed: nothing can be sent or received
%% securely any more. Drop SRTP keys and SCTP, stop ICE (consent checks
%% end, TURN allocations are deleted); the peer connection reports the
%% state and the application closes it.
finish(Reason, St0) ->
    St1 = end_association(Reason, St0),
    {Ice, Acts} = webrtc_ice_agent:close(webrtc_transport:now_ms(), St1#st.ice),
    St2 = webrtc_transport_net:ice_actions([A || A <- Acts, element(1, A) =:= send orelse element(1, A) =:= close_stream],
                                           St1#st{ice = Ice}),
    St2#st{finished = true}.

setup_srtp(#{srtp_profile := undefined}, St) ->
    St;
setup_srtp(#{srtp_profile := Id}, #st{dtls = D} = St) ->
    {ok, Profile} = webrtc_srtp:profile_from_id(Id),
    Len = webrtc_srtp:key_material_length(Profile),
    {ok, Material} = webrtc_dtls:export_keying_material(webrtc_srtp:exporter_label(), no_context, Len, D),
    St#st{media = webrtc_media:set_srtp(Profile, Material, St#st.dtls_role, webrtc_transport:now_ms(), St#st.media)}.

media_actions(Acts, St) ->
    lists:foldl(
        fun
            ({send, B}, S) -> webrtc_transport_net:send_out(B, S);
            %% The peer connection keeps the new SSRC for later offers.
            ({event, {ssrc_changed, _, _, _} = E}, S) -> webrtc_transport:to_pc(E, S), webrtc_transport:to_app(E, S), S;
            ({send_ect, B}, S) -> webrtc_transport_net:send_out_ect(B, S);
            ({event, E}, S) -> webrtc_transport:to_app(E, S), S
        end,
        St,
        Acts
    ).

%% RFC 8841: SCTP runs over the DTLS association once it is up.
start_sctp(#st{data = Data, dtls_role = Role} = St) ->
    LocalMax = maps:get(local_max_message_size, Data, 262144),
    Overhead = webrtc_dtls:record_overhead(St#st.dtls),
    D0 = webrtc_dcep:new(#{
        role => Role,
        max_message_size => maps:get(remote_max_message_size, Data, 65536),
        sctp => #{
            local_port => maps:get(local_port, Data, 5000),
            remote_port => maps:get(remote_port, Data, 5000),
            %% The limit we announced in SDP bounds incoming messages
            %% (RFC 8841 §6); the window holds at least two of them.
            max_message_size => LocalMax,
            receive_buffer => max(1048576, 2 * LocalMax),
            %% 1200 byte datagrams minus the DTLS record overhead of the
            %% negotiated version and suite are safe on any path (RFC 8261
            %% §5); PLPMTUD probes up to what fits a 1500 byte IPv6
            %% packet (40 byte IP and 8 byte UDP headers, RFC 8899).
            mtu => 1200 - Overhead,
            max_mtu => 1500 - 48 - Overhead,
            %% DTLS protects every packet: CRC32c may be skipped with
            %% peers that accept it (RFC 9653 §5.1).
            zero_checksum => true
        }
    }),
    {D1, Acts} = webrtc_dcep:connect(webrtc_transport:now_ms(), D0),
    St1 = dcep_actions(Acts, St#st{dcep = D1}),
    lists:foldl(
        fun({From, Label, Opts}, S) ->
            {Reply, S1} = do_open_channel(Label, Opts, S),
            gen_server:reply(From, Reply),
            S1
        end,
        St1#st{pending_channels = []},
        St1#st.pending_channels
    ).

do_open_channel(Label, Opts, #st{dcep = D} = St) ->
    case webrtc_dcep:open_channel(Label, Opts, webrtc_transport:now_ms(), D) of
        {ok, Id, D1, Acts} -> {{ok, Id}, dcep_actions(Acts, St#st{dcep = D1})};
        {error, _} = E -> {E, St}
    end.

dcep_actions(Acts, St) ->
    lists:foldl(fun dcep_action/2, St, Acts).

dcep_action({send, Bin}, #st{dtls = D} = St) ->
    case webrtc_dtls:send(Bin, D) of
        {ok, D1, Out} -> webrtc_transport_net:transmit(Out, St#st{dtls = D1});
        {error, _} -> St
    end;
dcep_action({event, {channel_message, _, _, _} = E}, St) ->
    webrtc_transport:to_app(E, St),
    St;
dcep_action({event, E}, St) ->
    webrtc_transport:to_pc({datachannel, E}, St),
    St.
