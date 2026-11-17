%% @doc The W3C WebRTC statistics (https://www.w3.org/TR/webrtc-stats/)
%% of a peer connection, built from the engines' own statistics.
%%
%% The report maps each stats id to a map whose keys are the members
%% of the W3C dictionary (`packetsSent', `roundTripTime', ...), with
%% `id', `type' and `timestamp' (ms since the Unix epoch, as
%% DOMHighResTimeStamp). Times are in seconds and rates in bits per
%% second, as the dictionaries define them. Types: codec, inbound-rtp,
%% outbound-rtp, remote-inbound-rtp, remote-outbound-rtp,
%% peer-connection, data-channel, transport, candidate-pair,
%% local-candidate, remote-candidate and certificate. Frame members of
%% received streams come from the frame buffer (`frames' on the
%% transceiver), those of sent streams from the packets sent. This
%% library does not capture, encode, decode or play media, so
%% media-source, media-playout and the encoder and decoder members are
%% left out (docs/compliance/stats.md lists each member).
-module(webrtc_stats).

-include("webrtc_ice.hrl").

-export([report/1]).

%% Input: `timestamp', `certificate' (DER), `ufrag', `media' (the
%% negotiated media sections) and `transports' ([{Key, Stats}] from
%% webrtc_transport:stats/1).
-spec report(map()) -> #{binary() => map()}.
report(#{timestamp := Ts, certificate := Der, transports := Transports} = In) ->
    Media = maps:get(media, In, []),
    Kinds = maps:from_list([{Mid, K} || #{mid := Mid, kind := K} <- Media, Mid =/= undefined]),
    Local = certificate(<<"CF">>, Der),
    Objs = lists:append([transport_objects(Key, T, In, Kinds, Media, Local) || {Key, T} <- Transports]),
    Counts = lists:foldl(
        fun({_, T}, Acc) -> maps:merge_with(fun(_, A, B) -> A + B end, Acc, maps:get(channel_counts, T, #{})) end,
        #{opened => 0, closed => 0}, Transports),
    Pc = #{id => <<"P">>, type => <<"peer-connection">>,
           dataChannelsOpened => maps:get(opened, Counts), dataChannelsClosed => maps:get(closed, Counts)},
    maps:from_list([{maps:get(id, O), O#{timestamp => Ts}} || O <- [Pc, Local | Objs]]).

%%====================================================================
%% Transport, ICE and certificates
%%====================================================================

transport_objects(Key, T, In, Kinds, Media, Local) ->
    Tid = <<"T", (id_part(Key))/binary>>,
    Ice = maps:get(ice, T, #{}),
    Pairs = maps:get(pairs, Ice, []),
    Dtls = maps:get(dtls, T, undefined),
    Io = maps:get(io, T, #{}),
    Remote =
        case maps:get(peer_certificate, T, undefined) of
            undefined -> [];
            Der -> [certificate(<<"CR", Tid/binary>>, Der)]
        end,
    Selected = [P || #{selected := true} = P <- Pairs],
    MediaStats = maps:get(media, T, #{}),
    Cc = maps:get(congestion_control, MediaStats, #{}),
    Counters = maps:get(counters, MediaStats, #{}),
    PairObjs = [pair(Tid, P, Io, Cc) || P <- Pairs],
    Servers = maps:get(servers, In, #{}),
    Ufrags = #{local => maps:get(ufrag, In, undefined), remote => maps:get(remote_ufrag, Ice, undefined)},
    Cands = maps:values(maps:from_list(
        [{cand_id(local, C), candidate(local, Tid, C, Ufrags, Servers)} || #{local := C} <- Pairs, is_record(C, ice_cand)] ++
        [{cand_id(remote, C), candidate(remote, Tid, C, Ufrags, Servers)} || #{remote := C} <- Pairs, is_record(C, ice_cand)])),
    Transport = compact(#{
        id => Tid,
        type => <<"transport">>,
        packetsSent => maps:get(packets_sent, Io, 0),
        packetsReceived => maps:get(packets_received, Io, 0),
        bytesSent => maps:get(bytes_sent, Io, 0),
        bytesReceived => maps:get(bytes_received, Io, 0),
        iceRole => enum(maps:get(role, Ice, undefined)),
        iceLocalUsernameFragment => maps:get(ufrag, In, undefined),
        dtlsState => dtls_state(Dtls),
        iceState => ice_state(maps:get(state, Ice, undefined)),
        selectedCandidatePairId => case Selected of [S | _] -> pair_id(Tid, S); [] -> undefined end,
        selectedCandidatePairChanges => maps:get(selected_changes, maps:get(counters, Ice, #{}), 0),
        ccfbMessagesSent => maps:get(ccfb_sent, Counters, 0),
        ccfbMessagesReceived => maps:get(ccfb_received, Counters, 0),
        localCertificateId => maps:get(id, Local),
        remoteCertificateId => case Remote of [#{id := Rid}] -> Rid; [] -> undefined end,
        tlsVersion => tls_version(Dtls),
        dtlsCipher => dtls_cipher(Dtls),
        dtlsRole => case Dtls of #{role := R} -> enum(R); _ -> undefined end,
        srtpCipher => srtp_cipher(Dtls)
    }),
    [Transport | Remote] ++ PairObjs ++ Cands ++ rtp_objects(Tid, maps:get(media, T, #{}), Kinds, Media) ++
        channels(maps:get(channels, T, #{})).

pair(Tid, #{local := L, remote := R} = P, Io, Cc) ->
    Rtt = maps:get(rtt, P, undefined),
    Selected = maps:get(selected, P, false),
    %% Application data goes on the selected pair: the transport's
    %% counters are its own.
    Data =
        case Selected of
            true -> maps:with([packets_sent, packets_received, bytes_sent, bytes_received, last_sent, last_received], Io);
            false -> #{}
        end,
    compact(#{
        id => pair_id(Tid, P),
        type => <<"candidate-pair">>,
        transportId => Tid,
        localCandidateId => cand_id(local, L),
        remoteCandidateId => cand_id(remote, R),
        state => pair_state(maps:get(state, P, frozen)),
        nominated => maps:get(nominated, P, false),
        packetsSent => maps:get(packets_sent, Data, undefined),
        packetsReceived => maps:get(packets_received, Data, undefined),
        bytesSent => maps:get(bytes_sent, Data, undefined),
        bytesReceived => maps:get(bytes_received, Data, undefined),
        currentRoundTripTime => seconds(Rtt),
        totalRoundTripTime => maps:get(total_rtt, P, 0) / 1000,
        consentRequestsSent => maps:get(consent_requests_sent, P, 0),
        lastPacketSentTimestamp => maps:get(last_sent, Data, undefined),
        lastPacketReceivedTimestamp => maps:get(last_received, Data, undefined),
        packetsDiscardedOnSend => case Selected of true -> maps:get(packets_discarded_on_send, Io, 0); false -> undefined end,
        bytesDiscardedOnSend => case Selected of true -> maps:get(bytes_discarded_on_send, Io, 0); false -> undefined end,
        availableOutgoingBitrate => case Selected of true -> maps:get(target_bitrate, Cc, undefined); false -> undefined end,
        requestsSent => maps:get(requests_sent, P, 0),
        requestsReceived => maps:get(requests_received, P, 0),
        responsesSent => maps:get(responses_sent, P, 0),
        responsesReceived => maps:get(responses_received, P, 0)
    }).

pair_id(Tid, #{local := L, remote := R}) ->
    <<"CP", Tid/binary, "_", (cand_id(local, L))/binary, "_", (cand_id(remote, R))/binary>>.

cand_id(Side, #ice_cand{address = A, port = P, transport = Tr, type = Ty}) ->
    Prefix = case Side of local -> <<"IL">>; remote -> <<"IR">> end,
    H = erlang:phash2({A, P, Tr, Ty}),
    <<Prefix/binary, (integer_to_binary(H))/binary>>;
cand_id(Side, _) ->
    case Side of local -> <<"IL">>; remote -> <<"IR">> end.

candidate(Side, Tid, #ice_cand{} = C, Ufrags, Servers) ->
    Server = case Side of local -> maps:get(C#ice_cand.server, Servers, #{}); remote -> #{} end,
    compact(#{
        usernameFragment => maps:get(Side, Ufrags),
        %% The STUN or TURN URI of a server reflexive or relay candidate.
        url => case C#ice_cand.type of T when T =:= srflx; T =:= relay -> maps:get(url, Server, undefined); _ -> undefined end,
        relayProtocol => case C#ice_cand.type of relay -> enum(maps:get(protocol, Server, undefined)); _ -> undefined end,
        id => cand_id(Side, C),
        type => case Side of local -> <<"local-candidate">>; remote -> <<"remote-candidate">> end,
        transportId => Tid,
        address => ntoa(C#ice_cand.address),
        port => C#ice_cand.port,
        protocol => atom_to_binary(C#ice_cand.transport),
        candidateType => atom_to_binary(C#ice_cand.type),
        priority => C#ice_cand.priority,
        foundation => C#ice_cand.foundation,
        relatedAddress => ntoa(C#ice_cand.related_address),
        relatedPort => C#ice_cand.related_port,
        tcpType => case C#ice_cand.tcptype of undefined -> undefined; T -> atom_to_binary(T) end
    }).

certificate(Id, Der) ->
    %% As SDP writes it (RFC 8122 §5): upper-case hex pairs and colons.
    <<"sha-256 ", Hex/binary>> = webrtc_dtls_cert:format_fingerprint(webrtc_dtls_cert:fingerprint(sha256, Der)),
    #{
        id => Id,
        type => <<"certificate">>,
        fingerprint => Hex,
        fingerprintAlgorithm => <<"sha-256">>,
        base64Certificate => base64:encode(Der)
    }.

%% RTCDtlsTransportState.
dtls_state(undefined) -> <<"new">>;
dtls_state(#{state := connected}) -> <<"connected">>;
dtls_state(#{state := failed}) -> <<"failed">>;
dtls_state(#{state := closed}) -> <<"closed">>;
dtls_state(_) -> <<"connecting">>.

ice_state(undefined) -> undefined;
ice_state(S) when is_atom(S) -> atom_to_binary(S).

pair_state(in_progress) -> <<"in-progress">>;
pair_state(S) -> atom_to_binary(S).

%% The TLS version as four upper-case hex digits.
tls_version(#{version := 'dtlsv1.3'}) -> <<"FEFC">>;
tls_version(#{version := 'dtlsv1.2'}) -> <<"FEFD">>;
tls_version(_) -> undefined.

%% IANA TLS cipher suite names.
dtls_cipher(#{suite := S}) when is_atom(S) -> string:uppercase(atom_to_binary(S));
dtls_cipher(_) -> undefined.

%% IANA DTLS-SRTP protection profile names (RFC 5764, RFC 7714).
srtp_cipher(#{srtp_profile := 1}) -> <<"AES_CM_128_HMAC_SHA1_80">>;
srtp_cipher(#{srtp_profile := 2}) -> <<"AES_CM_128_HMAC_SHA1_32">>;
srtp_cipher(#{srtp_profile := 7}) -> <<"AEAD_AES_128_GCM">>;
srtp_cipher(#{srtp_profile := 8}) -> <<"AEAD_AES_256_GCM">>;
srtp_cipher(_) -> undefined.

%%====================================================================
%% RTP streams
%%====================================================================

rtp_objects(Tid, MediaStats, Kinds, Media) ->
    Streams = maps:get(streams, MediaStats, #{}),
    Senders = maps:get(senders, MediaStats, #{}),
    Receivers = maps:get(receivers, MediaStats, #{}),
    Out = lists:append([outbound(Tid, Key, S, Streams, Kinds, Media) || Key := S <- Senders]),
    In = lists:append([inbound(Tid, Ssrc, R, Streams, Kinds, Media) || Ssrc := R <- Receivers]),
    Codecs = lists:usort([C || #{codec := C} <- Out ++ In, C =/= undefined]),
    [maps:remove(codec, O) || O <- Out ++ In] ++ Codecs.

outbound(Tid, Key, #{ssrc := Ssrc} = Tx, Streams, Kinds, Media) ->
    {Mid, Rid} = case Key of {M, R} -> {M, R}; M -> {M, undefined} end,
    S = maps:get({out, Ssrc}, Streams, #{}),
    Kind = maps:get(Mid, Kinds, undefined),
    Codec = codec(Tid, Mid, send, Media),
    CodecId = codec_id(Codec),
    Oid = <<"OT", (integer_to_binary(Ssrc))/binary>>,
    Rate = case Codec of #{clockRate := CR} -> CR; _ -> 90000 end,
    Base = compact(#{
        id => Oid, type => <<"outbound-rtp">>, ssrc => Ssrc, kind => kind(Kind), transportId => Tid,
        codecId => CodecId,
        %% Retransmissions included, on the RTX stream or not (the RTCP
        %% sender report counts this SSRC's packets only).
        packetsSent => maps:get(packets, Tx, 0) + maps:get(retransmitted_packets_sent, S, 0),
        bytesSent => maps:get(octets, Tx, 0) + maps:get(retransmitted_bytes_sent, S, 0),
        mid => Mid,
        rid => Rid,
        retransmittedPacketsSent => maps:get(retransmitted_packets_sent, S, 0),
        retransmittedBytesSent => maps:get(retransmitted_bytes_sent, S, 0),
        headerBytesSent => maps:get(header_bytes_sent, S, 0),
        totalPacketSendDelay => maps:get(total_packet_send_delay_ms, S, 0) / 1000,
        rtxSsrc => maps:get(rtx_ssrc, Tx, undefined),
        encodingIndex => maps:get(encoding_index, Tx, undefined),
        framesSent => video(Kind, maps:get(frames_sent, S, 0)),
        hugeFramesSent => video(Kind, maps:get(huge_frames_sent, S, 0)),
        frameWidth => video(Kind, maps:get(frame_width, S, undefined)),
        frameHeight => video(Kind, maps:get(frame_height, S, undefined)),
        framesPerSecond => video(Kind, length(maps:get(frame_times, S, []))),
        nackCount => maps:get(nack_count, S, 0),
        firCount => maps:get(fir_count, S, 0),
        pliCount => maps:get(pli_count, S, 0),
        active => true,
        remoteId => case maps:is_key(remote_reports, S) of true -> <<"RI", (integer_to_binary(Ssrc))/binary>>; false -> undefined end,
        codec => Codec
    }),
    Remote =
        case S of
            #{remote_reports := _} ->
                [compact(#{
                    id => <<"RI", (integer_to_binary(Ssrc))/binary>>, type => <<"remote-inbound-rtp">>, ssrc => Ssrc,
                    kind => kind(Kind), transportId => Tid, codecId => CodecId,
                    packetsLost => maps:get(remote_packets_lost, S, 0),
                    jitter => maps:get(remote_jitter, S, 0) / Rate,
                    localId => Oid,
                    roundTripTime => seconds(maps:get(rtt, S, undefined)),
                    totalRoundTripTime => maps:get(total_rtt, S, 0) / 1000,
                    roundTripTimeMeasurements => maps:get(rtt_measurements, S, 0),
                    fractionLost => maps:get(remote_fraction_lost, S, 0) / 256
                })];
            _ ->
                []
        end,
    [Base | Remote].

inbound(Tid, Ssrc, Rx, Streams, Kinds, Media) ->
    Mid = maps:get(mid, Rx, undefined),
    S = maps:get({in, Ssrc}, Streams, #{}),
    Kind = maps:get(Mid, Kinds, undefined),
    Codec = codec(Tid, Mid, recv, Media),
    CodecId = codec_id(Codec),
    Iid = <<"IT", (integer_to_binary(Ssrc))/binary>>,
    Rate = case Codec of #{clockRate := CR} -> CR; _ -> 90000 end,
    Remote =
        case S of
            #{reports_received := N} ->
                [compact(#{
                    id => <<"RO", (integer_to_binary(Ssrc))/binary>>, type => <<"remote-outbound-rtp">>, ssrc => Ssrc,
                    kind => kind(Kind), transportId => Tid,
                    codecId => CodecId,
                    packetsSent => maps:get(remote_packets_sent, S, 0),
                    bytesSent => maps:get(remote_bytes_sent, S, 0),
                    localId => Iid,
                    remoteTimestamp => maps:get(remote_timestamp, S, undefined),
                    reportsSent => N,
                    %% From DLRR blocks answering our RRTR (RFC 3611).
                    roundTripTime => seconds(maps:get(remote_rtt, S, undefined)),
                    totalRoundTripTime => case S of #{remote_total_rtt := T} -> T / 1000; _ -> undefined end,
                    roundTripTimeMeasurements => maps:get(remote_rtt_measurements, S, undefined)
                })];
            _ ->
                []
        end,
    Base = compact(#{
        id => Iid, type => <<"inbound-rtp">>, ssrc => Ssrc, kind => kind(Kind), transportId => Tid,
        codecId => CodecId,
        %% No MediaStreamTrack here: the receiving section's mid names it.
        trackIdentifier => Mid,
        mid => Mid,
        packetsReceived => maps:get(packets_received, S, 0),
        bytesReceived => maps:get(bytes_received, S, 0),
        packetsLost => maps:get(lost, Rx, 0),
        jitter => maps:get(jitter, Rx, 0) / Rate,
        lastPacketReceivedTimestamp => maps:get(last_packet_received, S, undefined),
        nackCount => maps:get(nack_count, S, 0),
        firCount => maps:get(fir_count, S, 0),
        pliCount => maps:get(pli_count, S, 0),
        retransmittedPacketsReceived => maps:get(retransmitted_packets_received, S, 0),
        retransmittedBytesReceived => maps:get(retransmitted_bytes_received, S, 0),
        headerBytesReceived => maps:get(header_bytes_received, S, 0),
        rtxSsrc => maps:get(rtx_ssrc, S, undefined),
        remoteId => case Remote of [#{id := Rid}] -> Rid; [] -> undefined end,
        codec => Codec
    }),
    [maps:merge(Base, compact(maps:merge(audio_members(Kind, S), frame_members(Kind, maps:get(frames, Rx, undefined)))))
     | Remote].

%% From the RFC 6464 level of each packet, when negotiated.
audio_members(audio, #{audio_level := L} = S) ->
    #{audioLevel => L, totalAudioEnergy => maps:get(total_audio_energy, S, 0.0),
      totalSamplesDuration => maps:get(total_samples_duration, S, 0.0)};
audio_members(_, _) ->
    #{}.

%% From the frame buffer (`frames' on the transceiver).
frame_members(_Kind, undefined) ->
    #{};
frame_members(Kind, F) ->
    Buffer = #{
        jitterBufferDelay => maps:get(jitter_buffer_delay, F, 0.0),
        jitterBufferTargetDelay => maps:get(jitter_buffer_target_delay, F, 0.0),
        jitterBufferMinimumDelay => maps:get(jitter_buffer_minimum_delay, F, 0.0),
        jitterBufferEmittedCount => maps:get(jitter_buffer_emitted_count, F, 0),
        packetsDiscarded => maps:get(packets_discarded, F, 0)
    },
    case Kind of
        video ->
            Buffer#{
                framesReceived => maps:get(frames_received, F, 0),
                framesDropped => maps:get(frames_dropped, F, 0),
                framesAssembledFromMultiplePackets => maps:get(frames_assembled_from_multiple_packets, F, 0),
                totalAssemblyTime => maps:get(total_assembly_time, F, 0.0),
                frameWidth => maps:get(frame_width, F, undefined),
                frameHeight => maps:get(frame_height, F, undefined),
                framesPerSecond => maps:get(frames_per_second, F, undefined)
            };
        _ ->
            Buffer
    end.

video(video, V) -> V;
video(_, _) -> undefined.

%% The section's first codec: the one sent by preference, and the one a
%% receiver most likely gets (RFC 9429 §5.3.1).
codec(Tid, Mid, Dir, Media) ->
    Key = case Dir of send -> send_codecs; recv -> recv_codecs end,
    case [C || #{mid := M} = Sec <- Media, M =:= Mid, C <- maps:get(Key, Sec, []), not is_repair(C)] of
        [#{pt := Pt, name := Name, clock_rate := Rate} = C | _] ->
            compact(#{
                id => <<"C", Tid/binary, "_", (integer_to_binary(Pt))/binary, "_", (atom_to_binary(Dir))/binary>>,
                type => <<"codec">>,
                payloadType => Pt,
                transportId => Tid,
                mimeType => <<(kind(maps:get(kind, hd([S || #{mid := M} = S <- Media, M =:= Mid]), video)))/binary, "/",
                              Name/binary>>,
                clockRate => Rate,
                channels => maps:get(channels, C, undefined),
                sdpFmtpLine => fmtp(maps:get(fmtp, C, []))
            });
        [] ->
            undefined
    end.

codec_id(#{id := Id}) -> Id;
codec_id(_) -> undefined.

is_repair(#{name := N}) -> lists:member(string:lowercase(N), [<<"rtx">>, <<"red">>, <<"ulpfec">>, <<"flexfec-03">>]);
is_repair(_) -> false.

fmtp([]) -> undefined;
fmtp(Params) ->
    iolist_to_binary(lists:join(<<";">>, [case P of {K, V} -> [K, $=, V]; B when is_binary(B) -> B end || P <- Params])).

kind(audio) -> <<"audio">>;
kind(video) -> <<"video">>;
kind(_) -> undefined.

%%====================================================================
%% Data channels
%%====================================================================

channels(Chs) ->
    [compact(#{
        id => <<"D", (integer_to_binary(Id))/binary>>,
        type => <<"data-channel">>,
        label => maps:get(label, Ch, <<>>),
        protocol => maps:get(protocol, Ch, <<>>),
        dataChannelIdentifier => Id,
        state => atom_to_binary(maps:get(state, Ch, connecting)),
        messagesSent => maps:get(messages_sent, Ch, 0),
        bytesSent => maps:get(bytes_sent, Ch, 0),
        messagesReceived => maps:get(messages_received, Ch, 0),
        bytesReceived => maps:get(bytes_received, Ch, 0)
    }) || Id := Ch <- Chs].

%%====================================================================
%% Helpers
%%====================================================================

%% Enum members are strings.
enum(undefined) -> undefined;
enum(A) when is_atom(A) -> atom_to_binary(A).

seconds(undefined) -> undefined;
seconds(Ms) -> Ms / 1000.

ntoa(undefined) -> undefined;
ntoa(IP) -> list_to_binary(inet:ntoa(IP)).

id_part(K) when is_binary(K) -> K;
id_part(K) when is_integer(K) -> integer_to_binary(K);
id_part(K) when is_atom(K) -> atom_to_binary(K);
id_part(K) -> integer_to_binary(erlang:phash2(K)).

%% Members that do not apply are left out, as browsers do.
compact(M) -> maps:filter(fun(_, V) -> V =/= undefined end, M).
