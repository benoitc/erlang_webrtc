%% Private state of the transport process, shared by webrtc_transport
%% (the process), webrtc_transport_net (sockets and ICE) and
%% webrtc_transport_secure (DTLS, SRTP and SCTP).

%% Datagrams delivered per {active, N} round.
-define(ACTIVE_N, 100).
%% DTLS datagrams kept while they cannot be processed or sent yet.
-define(MAX_EARLY_DTLS, 16).

-record(st, {
    pc :: pid(),
    app :: pid(),
    sockets = [] :: [{gen_udp:socket(), {inet:ip_address(), inet:port_number()}}],
    ice :: term(),
    dtls :: undefined | term(),
    dtls_role :: undefined | client | server,
    cert :: map(),
    remote_fps = [] :: list(),
    remote_tls_id :: undefined | binary(),
    %% DTLS closed or failed: the transport is finished, only stats and
    %% stop are served.
    finished = false :: boolean(),
    %% DTLS datagrams received before the DTLS role is known.
    early_dtls = [] :: [binary()],
    %% ICE has a valid pair with consent (connected or completed).
    ice_usable = false :: boolean(),
    %% DTLS datagrams produced before ICE could send them (the peer's
    %% check reached us before ours succeeded); sent once it can.
    dtls_out = [] :: [binary()],
    media :: term(),
    data :: undefined | map(),
    dcep :: undefined | term(),
    %% Channels requested before SCTP is up: [{From, Label, Opts}].
    pending_channels = [] :: list(),
    timer :: undefined | {reference(), integer()},
    srtp_profiles :: [non_neg_integer()],
    connected = false :: boolean(),
    %% Optional outbound filter used by impairment tests:
    %% fun((Dest, Bin, FState) -> {[{DelayMs, Bin}], FState}).
    filter :: undefined | {fun(), term()},
    %% Stream connections to TURN servers (TCP, TLS):
    %% {stream, N} => #{sock, kind, server, buf}.
    streams = #{} :: #{{stream | tcp, term()} => map()},
    %% ICE-TCP listeners (RFC 6544): [{ListenRef, ListenSocket, Addr}],
    %% and the number of the next accepted connection.
    tcp_listeners = [] :: [{reference(), term(), {inet:ip_address(), inet:port_number()}}],
    next_accept = 1 :: pos_integer(),
    %% Host name candidates (mDNS, FQDN) being resolved.
    mdns :: webrtc_mdns_client:client()
}).
