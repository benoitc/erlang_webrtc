%% SCTP packet and chunk records (RFC 9260, RFC 3758, RFC 6525, RFC 8260).
%%
%% Chunks without a record are plain tuples, see the `chunk()' type in
%% webrtc_sctp_chunk.
-ifndef(WEBRTC_SCTP_HRL).
-define(WEBRTC_SCTP_HRL, true).

%% SCTP packet: common header (RFC 9260 §3.1) and decoded chunks.
-record(sctp_packet, {
    src_port = 5000 :: 0..65535,
    dst_port = 5000 :: 0..65535,
    vtag = 0 :: 0..16#FFFFFFFF,
    %% Checksum as found on the wire (decode only, ignored on encode).
    checksum = 0 :: 0..16#FFFFFFFF,
    chunks = [] :: [term()]
}).

%% DATA (RFC 9260 §3.3.1) and I-DATA (RFC 8260 §2.1) chunks.
%%
%% `mid' holds the 16-bit Stream Sequence Number for DATA and the 32-bit
%% Message Identifier for I-DATA. `fsn' is only used by I-DATA: it is 0
%% when `beginning' is set (the wire field then carries the PPID) and the
%% Fragment Sequence Number otherwise (the wire field then carries the
%% FSN and `ppid' is 0 after decode).
-record(sctp_data, {
    idata = false :: boolean(),
    tsn = 0 :: 0..16#FFFFFFFF,
    sid = 0 :: 0..65535,
    mid = 0 :: 0..16#FFFFFFFF,
    fsn = 0 :: 0..16#FFFFFFFF,
    ppid = 0 :: 0..16#FFFFFFFF,
    unordered = false :: boolean(),
    beginning = true :: boolean(),
    ending = true :: boolean(),
    immediate = false :: boolean(),
    data = <<>> :: binary()
}).

%% INIT (§3.3.2) when `ack' is false, INIT ACK (§3.3.3) when true.
-record(sctp_init, {
    ack = false :: boolean(),
    tag = 0 :: 0..16#FFFFFFFF,
    a_rwnd = 0 :: 0..16#FFFFFFFF,
    os = 0 :: 0..65535,
    mis = 0 :: 0..65535,
    tsn = 0 :: 0..16#FFFFFFFF,
    params = [] :: [term()]
}).

%% SACK (§3.3.4). Gap blocks are {Start, End} offsets from cum_tsn.
-record(sctp_sack, {
    cum_tsn = 0 :: 0..16#FFFFFFFF,
    a_rwnd = 0 :: 0..16#FFFFFFFF,
    gaps = [] :: [{0..65535, 0..65535}],
    dups = [] :: [0..16#FFFFFFFF]
}).

%% Chunk types.
-define(SCTP_DATA, 0).
-define(SCTP_INIT, 1).
-define(SCTP_INIT_ACK, 2).
-define(SCTP_SACK, 3).
-define(SCTP_HEARTBEAT, 4).
-define(SCTP_HEARTBEAT_ACK, 5).
-define(SCTP_ABORT, 6).
-define(SCTP_SHUTDOWN, 7).
-define(SCTP_SHUTDOWN_ACK, 8).
-define(SCTP_ERROR, 9).
-define(SCTP_COOKIE_ECHO, 10).
-define(SCTP_COOKIE_ACK, 11).
-define(SCTP_SHUTDOWN_COMPLETE, 14).
-define(SCTP_IDATA, 64).
-define(SCTP_RECONFIG, 130).
-define(SCTP_PAD, 132).
-define(SCTP_FORWARD_TSN, 192).
-define(SCTP_IFORWARD_TSN, 194).

%% Error Detection Method Identifier for SCTP over DTLS (RFC 9653 §10).
-define(SCTP_EDMID_DTLS, 1).

%% DATA header 16 bytes, I-DATA header 20 bytes, common header 12 bytes.
-define(SCTP_COMMON_HEADER_SIZE, 12).
-define(SCTP_DATA_HEADER_SIZE, 16).
-define(SCTP_IDATA_HEADER_SIZE, 20).

-endif.
