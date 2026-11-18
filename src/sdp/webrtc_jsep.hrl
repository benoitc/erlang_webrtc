%% Private state of the JSEP engine (webrtc_jsep, webrtc_jsep_build).

-record(tr, {
    %% Stable handle given to the application.
    id :: pos_integer(),
    kind :: audio | video,
    mid :: undefined | binary(),
    mline :: undefined | non_neg_integer(),
    %% Desired direction (RTCRtpTransceiver.direction).
    direction = sendrecv :: webrtc_sdp_rtp:direction(),
    %% Negotiated direction (RTCRtpTransceiver.currentDirection).
    current_direction :: undefined | webrtc_sdp_rtp:direction(),
    stopped = false :: boolean(),
    codecs :: [webrtc_sdp_media:codec()],
    extensions :: [webrtc_jsep_caps:extension()],
    ssrc :: 0..16#FFFFFFFF,
    rtx_ssrc :: 0..16#FFFFFFFF,
    %% The FlexFEC repair stream (RFC 8627), grouped with ssrc by FEC-FR.
    fec_ssrc :: 0..16#FFFFFFFF,
    %% Simulcast encodings (RFC 8853); the first one uses ssrc/rtx_ssrc.
    %% Empty when the transceiver sends a single stream without a rid.
    encodings = [] :: [webrtc_jsep_simulcast:encoding()],
    %% Simulcast layers we ask to receive, paused or not (RFC 8853).
    recv_rids = [] :: [{binary(), boolean()}],
    stream_id :: binary(),
    track_id :: binary(),
    %% Created by applying a remote offer (RFC 9429 §5.10).
    from_remote = false :: boolean(),
    %% Deliver assembled frames (webrtc_frame_buffer) instead of packets:
    %% false, or the buffer options.
    frames = false :: false | map(),
    %% A codec plugin (webrtc_media_codec) for the frames: {Module, Opts}.
    codec_plugin :: undefined | {module(), term()}
}).

-record(jsep, {
    signaling = stable ::
        stable
        | have_local_offer
        | have_remote_offer
        | have_local_pranswer
        | have_remote_pranswer
        | closed,
    ice_ufrag :: binary(),
    ice_pwd :: binary(),
    ice_lite = false :: boolean(),
    %% Our Ta in ms, announced with a=ice-pacing when not 50.
    ice_pacing = 50 :: pos_integer(),
    fingerprints :: [webrtc_dtls_cert:fingerprint()],
    cname :: binary(),
    session_id :: non_neg_integer(),
    session_version = 0 :: non_neg_integer(),
    caps :: #{audio := {list(), list()}, video := {list(), list()}},
    transceivers = [] :: [#tr{}],
    next_id = 1 :: pos_integer(),
    %% Data channel m= section.
    want_data = false :: boolean(),
    data_mid :: undefined | binary(),
    data_mline :: undefined | non_neg_integer(),
    sctp_port = 5000 :: inet:port_number(),
    max_message_size = 262144 :: non_neg_integer(),
    %% Descriptions (RFC 9429 §4.1.14 - §4.1.17).
    current_local :: undefined | tuple(),
    current_remote :: undefined | tuple(),
    pending_local :: undefined | tuple(),
    pending_remote :: undefined | tuple(),
    %% Remote descriptions as received; pending_remote and current_remote
    %% hold the bundle view (see webrtc_jsep:bundle_view/1).
    pending_remote_orig :: undefined | tuple(),
    current_remote_orig :: undefined | tuple(),
    %% DTLS role once negotiated (RFC 8842 §5).
    dtls_role :: undefined | client | server,
    local_candidates = [] :: list(),
    local_eoc = false :: boolean(),
    %% State saved when an offer/answer exchange starts, for rollback.
    snapshot :: undefined | map(),
    %% Our a=tls-id (RFC 8842 §5), new for every DTLS association.
    tls_id :: binary(),
    %% Remote ICE credentials of the current remote description.
    remote_ice :: undefined | #{ufrag := binary(), pwd := binary()},
    ice_restart = false :: boolean(),
    %% Offer one BUNDLE group (RFC 9143); false gives every section its
    %% own transport.
    bundle = true :: boolean(),
    %% `frames' of transceivers created without the option, those of a
    %% remote offer included, and their codec plugin by kind.
    frames = false :: false | map(),
    codec_plugins = #{} :: #{audio | video => {module(), term()}},
    %% ICE credentials and local candidates of the transports after the
    %% first (which uses ice_ufrag, ice_pwd and local_candidates), by
    %% transport key (webrtc_jsep_transport).
    ice_extra = #{} :: #{binary() => {binary(), binary()}},
    local_cands = #{} :: #{binary() => {list(), boolean()}},
    %% Transports of the last answer: later offers keep them (RFC 9429
    %% §5.2.2, RFC 9143 §7.5).
    groups = [] :: [webrtc_jsep_transport:group()],
    %% The local description of the negotiation is the answer.
    answerer = false :: boolean(),
    %% Offer and accept encrypted CSRCs and header extensions (RFC 9335).
    cryptex = true :: boolean(),
    %% RFC 8858: offers say rtcp-mux-only (`rtcp_mux_policy => require').
    rtcp_mux_only = false :: boolean(),
    %% Offer the encrypted forms of header extensions (RFC 6904).
    encrypt_offer = false :: boolean()
}).
