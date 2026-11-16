%% Private state of the DTLS engine (webrtc_dtls, webrtc_dtls_hs,
%% webrtc_dtls13, webrtc_dtls13_hs).

-define(DTLS12, 16#FEFD).
-define(DTLS10, 16#FEFF).
-define(DTLS13, 16#FEFC).

%% Alert descriptions (RFC 5246 §7.2).
-define(ALERT_CLOSE_NOTIFY, 0).
-define(ALERT_UNEXPECTED_MESSAGE, 10).
-define(ALERT_RECORD_OVERFLOW, 22).
-define(ALERT_HANDSHAKE_FAILURE, 40).
-define(ALERT_BAD_CERTIFICATE, 42).
-define(ALERT_UNSUPPORTED_CERTIFICATE, 43).
-define(ALERT_ILLEGAL_PARAMETER, 47).
-define(ALERT_DECODE_ERROR, 50).
-define(ALERT_DECRYPT_ERROR, 51).
-define(ALERT_PROTOCOL_VERSION, 70).
-define(ALERT_INSUFFICIENT_SECURITY, 71).
-define(ALERT_INTERNAL_ERROR, 80).
-define(ALERT_NO_RENEGOTIATION, 100).
%% RFC 8446 §6.
-define(ALERT_MISSING_EXTENSION, 109).
-define(ALERT_UNSUPPORTED_EXTENSION, 110).
-define(ALERT_CERTIFICATE_REQUIRED, 116).

-record(dtls, {
    role :: client | server,
    %% client: idle | wait_server_hello | wait_server_hello_done |
    %%         wait_server_finished | connected
    %% server: wait_client_hello | wait_client_finished | connected
    %% both:   closed | failed
    state :: atom(),
    %% Negotiated version (undefined until the hello exchange decides it)
    %% and the versions this endpoint accepts.
    version :: undefined | dtls12 | dtls13,
    versions = [dtls13, dtls12] :: [dtls12 | dtls13],
    cert_der :: binary(),
    key :: public_key:private_key(),
    remote_fps :: undefined | [webrtc_dtls_cert:fingerprint()],
    peer_cert :: undefined | binary(),
    peer_key :: undefined | {ecdsa | rsa | eddsa, term()},
    verified = false :: boolean(),
    handshake_done = false :: boolean(),
    srtp_profiles = [] :: [0..16#FFFF],
    srtp_profile :: undefined | 0..16#FFFF,
    suites :: [0..16#FFFF],
    suites13 = [] :: [0..16#FFFF],
    groups :: [webrtc_dtls_crypto:group()],
    require_ems = true :: boolean(),
    use_cookie = true :: boolean(),
    cookie_secret :: binary(),
    mtu :: pos_integer(),
    %% Handshake parameters.
    client_random :: undefined | binary(),
    server_random :: undefined | binary(),
    cookie = <<>> :: binary(),
    suite :: undefined | webrtc_dtls_crypto:suite(),
    group :: undefined | webrtc_dtls_crypto:group(),
    ecdh_priv :: undefined | binary(),
    peer_ecdh :: undefined | binary(),
    peer_schemes = [] :: [0..16#FFFF],
    cert_requested = false :: boolean(),
    cv_ok = false :: boolean(),
    announced = false :: boolean(),
    hvr_count = 0 :: non_neg_integer(),
    ems = false :: boolean(),
    master :: undefined | binary(),
    keys :: undefined | {binary(), binary(), binary(), binary()},
    %% Full handshake messages in reverse order (RFC 6347 §4.2.6).
    transcript = [] :: [binary()],
    %% Handshake message sequence numbers.
    send_msg_seq = 0 :: non_neg_integer(),
    recv_msg_seq = 0 :: non_neg_integer(),
    %% Reassembly: Seq => {Type, Len, #{Offset => Bin}}.
    reasm = #{} :: map(),
    %% Record layer.
    write_epoch = 0 :: non_neg_integer(),
    write_seq = #{0 => 0} :: #{non_neg_integer() => non_neg_integer()},
    write_ciphers = #{} :: #{non_neg_integer() => webrtc_dtls_record:cipher() | webrtc_dtls13_keys:keys()},
    read_epoch = 0 :: non_neg_integer(),
    read_cipher :: undefined | webrtc_dtls_record:cipher(),
    pending_read :: undefined | webrtc_dtls_record:cipher(),
    replay = #{} :: #{non_neg_integer() => webrtc_dtls_record:replay()},
    %% Records of the next epoch received before ChangeCipherSpec.
    early = [] :: [webrtc_dtls_record:dtls_record()],
    %% A server's ChangeCipherSpec received before CertificateVerify.
    ccs_held = false :: boolean(),
    %% Flight being built and the last flight sent (for retransmission).
    building = [] :: [flight_item()],
    last_flight = [] :: [flight_item()],
    rtx_at = infinity :: integer() | infinity,
    rtx_interval :: pos_integer(),
    rtx_initial :: pos_integer(),
    rtx_max_interval :: pos_integer(),
    rtx_count = 0 :: non_neg_integer(),
    rtx_limit :: non_neg_integer(),
    last_peer_rtx = undefined :: undefined | integer(),
    %% DTLS 1.3 timer (RFC 9147 §5.8.2): the value new flights start
    %% with, 1.5 times the RTT of a flight acknowledged without
    %% retransmission, and when the current flight was sent.
    rtx_base :: undefined | pos_integer(),
    flight_at :: undefined | integer(),
    %% Amplification limit (RFC 9147 §5.1): until a cookie exchange or
    %% the end of the handshake validates the client's address, a server
    %% sends at most three times what it received; the rest waits.
    addr_valid = false :: boolean(),
    %% Post-handshake authentication (webrtc_dtls13_pha): the client
    %% offers it, or the server saw it offered; the server's request in
    %% progress.
    pha = false :: boolean(),
    pha_state :: undefined | {wait_cert | wait_cv | wait_finished, binary(), [binary()]},
    amp_in = 0 :: non_neg_integer(),
    amp_out = 0 :: non_neg_integer(),
    amp_held = [] :: [binary()],
    %% Application data received before the fingerprint is verified.
    held = [] :: [binary()],
    %% DTLS 1.3 (RFC 9147). Client key share {Group, Public, Private}, HRR
    %% state, the negotiated suite and the key schedule secrets.
    kx :: undefined | {webrtc_dtls_crypto:group(), binary(), binary()},
    hrr = false :: boolean(),
    cookie13 :: undefined | binary(),
    suite13 :: undefined | webrtc_dtls13_keys:suite(),
    cr_context :: undefined | binary(),
    secrets = #{} :: #{atom() => binary()},
    exporter :: undefined | binary(),
    peer_finished = false :: boolean(),
    %% Read keys per epoch; record numbers of the current outgoing
    %% flight (RecordNumber => {MsgSeq, Offset, Length}) and the ranges
    %% the peer acknowledged (MsgSeq => [{Start, End}]).
    read_keys = #{} :: #{non_neg_integer() => map()},
    %% Records of the flight sent: {Epoch, Seq} => the fragments
    %% {MessageSeq, Offset, Length} each carries.
    sent_recs = #{} :: #{{non_neg_integer(), non_neg_integer()} => [{non_neg_integer(), non_neg_integer(), non_neg_integer()}]},
    acked = #{} :: #{non_neg_integer() => [{non_neg_integer(), non_neg_integer()}]},
    %% Handshake records of the current incoming flight to acknowledge,
    %% the ACK timer and whether an ACK must be sent now.
    rcv_recs = [] :: [{non_neg_integer(), non_neg_integer()}],
    ack_at = infinity :: integer() | infinity,
    ack_now = false :: boolean(),
    %% KeyUpdate (RFC 9147 §8): our KeyUpdate waiting for its ACK.
    ku_pending = false :: boolean(),
    rekey_records :: pos_integer(),
    cookie_lifetime :: pos_integer(),
    %% Connection ID (RFC 9147 §9, RFC 9146): the one we offered to
    %% receive and the one the peer asked us to send, once negotiated.
    cid :: undefined | binary(),
    peer_cid :: undefined | binary(),
    %% After the handshake (webrtc_dtls13_cid): the CIDs we receive on,
    %% the peer's spare CIDs, a rotation waiting for one, and the CID
    %% messages waiting for the current flight to be acknowledged.
    cids = [] :: [binary()],
    %% The CID of ours the peer's records carry now, and those it moved
    %% away from (dropped from `cids' when a request needs room).
    cid_in_use :: undefined | binary(),
    cid_retired = [] :: [binary()],
    peer_spares = [] :: [binary()],
    rotate = false :: boolean(),
    cid_queue = [] :: [{request, pos_integer()} | {spares, pos_integer()}],
    %% Resumption and 0-RTT (RFC 8446 §2.2, §2.3): enabled, the ticket
    %% offered (client) or accepted (server), whether this handshake
    %% resumed, and early data: offered, accepted, rejected or done.
    resumption = false :: boolean(),
    early_data = false :: boolean(),
    ticket_lifetime = 7200 :: pos_integer(),
    ticket_nonce = 0 :: non_neg_integer(),
    psk :: undefined | map(),
    resumed = false :: boolean(),
    zero_rtt :: undefined | offered | accepted | rejected,
    early_sent = 0 :: non_neg_integer(),
    out = [] :: [term()]
}).

-type flight_item() ::
    {handshake, Epoch :: non_neg_integer(), webrtc_dtls_msg:msg_type(), Seq :: non_neg_integer(),
        Body :: binary()}
    | {change_cipher_spec, Epoch :: non_neg_integer()}.
