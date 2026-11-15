%% Internal records of the SCTP association engine. Not a public API.
%%
%% TSNs are kept "unwrapped" (64-bit monotonic integers) inside the
%% engine; only the codec boundary uses 32-bit wire values. See
%% webrtc_sctp_assoc:unwrap/2.
-include("webrtc_sctp.hrl").

-define(U32, 16#FFFFFFFF).
-define(TSN(U), ((U) band ?U32)).

%% Configuration, fixed after new/1.
-record(cfg, {
    local_port = 5000 :: 0..65535,
    remote_port = 5000 :: 0..65535,
    mtu = 1200 :: pos_integer(),
    os = 65535 :: 1..65535,
    mis = 65535 :: 1..65535,
    rbuf = 1048576 :: pos_integer(),
    send_buffer = 8388608 :: pos_integer(),
    max_message_size = 262144 :: pos_integer(),
    rto_initial = 1000 :: pos_integer(),
    rto_min = 1000 :: pos_integer(),
    rto_max = 60000 :: pos_integer(),
    max_burst = 4 :: pos_integer(),
    assoc_max_retrans = 10 :: non_neg_integer(),
    max_init_retrans = 8 :: non_neg_integer(),
    cookie_life = 60000 :: pos_integer(),
    hb_interval = 30000 :: pos_integer() | infinity,
    sack_delay = 200 :: 0..500,
    sack_freq = 2 :: pos_integer(),
    interleaving = false :: boolean(),
    zero_checksum = false :: boolean(),
    secret = <<>> :: binary()
}).

%% Outgoing user message.
-record(omsg, {
    id :: non_neg_integer(),
    sid :: 0..65535,
    ppid :: 0..16#FFFFFFFF,
    data :: binary(),
    offset = 0 :: non_neg_integer(),
    unordered = false :: boolean(),
    mid :: undefined | non_neg_integer(),
    fsn = 0 :: non_neg_integer(),
    max_rtx = infinity :: infinity | non_neg_integer(),
    expires = infinity :: infinity | integer()
}).

%% Outgoing stream.
-record(ostream, {
    queue = queue:new() :: queue:queue(#omsg{}),
    %% Messages sent by the user after a reset was requested; they wait
    %% until the reset completes (RFC 6525 §5.1.2 A1).
    held = queue:new() :: queue:queue(#omsg{}),
    bytes = 0 :: non_neg_integer(),
    low = 0 :: non_neg_integer(),
    ssn = 0 :: non_neg_integer(),
    umid = 0 :: non_neg_integer(),
    reset = none :: none | pending | requested,
    active = false :: boolean(),
    %% Weighted fair queueing (RFC 8260 §3.6): the stream's weight (the
    %% data channel priority, RFC 8831 §6.4) and its virtual time.
    weight = 256 :: pos_integer(),
    vtime = 0 :: non_neg_integer()
}).

%% Outstanding (TSN assigned) chunk.
-record(oc, {
    chunk :: #sctp_data{},
    size :: pos_integer(),
    len :: non_neg_integer(),
    state = inflight :: inflight | acked | rtx | abandoned,
    tx = 1 :: pos_integer(),
    sent_at = 0 :: integer(),
    missing = 0 :: non_neg_integer(),
    fast = false :: boolean(),
    msg :: non_neg_integer(),
    max_rtx = infinity :: infinity | non_neg_integer(),
    expires = infinity :: infinity | integer()
}).

%% Send side and path state (single destination).
-record(snd, {
    mtu :: pos_integer(),
    idata = false :: boolean(),
    pr = false :: boolean(),
    max_burst = 4 :: pos_integer(),
    buffer_limit :: pos_integer(),
    os = 65535 :: non_neg_integer(),
    streams = #{} :: #{0..65535 => #ostream{}},
    active = queue:new() :: queue:queue(0..65535),
    %% Virtual time of the last stream served (WFQ).
    vclock = 0 :: non_neg_integer(),
    %% DATA mode: stream whose message is being fragmented.
    current = undefined :: undefined | 0..65535,
    buffered = 0 :: non_neg_integer(),
    next_msg = 0 :: non_neg_integer(),
    %% TSN state, unwrapped. Outstanding holds cum+1 .. next_tsn-1.
    next_tsn = 0 :: non_neg_integer(),
    cum = 0 :: non_neg_integer(),
    adv = 0 :: non_neg_integer(),
    out = #{} :: #{non_neg_integer() => #oc{}},
    rtx_count = 0 :: non_neg_integer(),
    fast_list = [] :: [non_neg_integer()],
    flight = 0 :: non_neg_integer(),
    flight_len = 0 :: non_neg_integer(),
    rwnd = 0 :: non_neg_integer(),
    cwnd = 0 :: non_neg_integer(),
    ssthresh = 0 :: non_neg_integer(),
    pba = 0 :: non_neg_integer(),
    fr_exit = undefined :: undefined | non_neg_integer(),
    %% RTO (RFC 9260 §6.3.1), milliseconds.
    srtt = undefined :: undefined | non_neg_integer(),
    rttvar = 0 :: non_neg_integer(),
    rto :: pos_integer(),
    rto_min :: pos_integer(),
    rto_max :: pos_integer(),
    rtt_probe = undefined :: undefined | {non_neg_integer(), integer()},
    t3 = undefined :: undefined | integer(),
    %% Zero window probing (RFC 9260 §6.1 A).
    zwp = undefined :: undefined | integer(),
    zwp_interval = 0 :: non_neg_integer(),
    last_sack = undefined :: undefined | integer(),
    fwd_pending = false :: boolean(),
    fwd_last = undefined :: undefined | {non_neg_integer(), integer()},
    last_data_sent = undefined :: undefined | integer(),
    stats = #{} :: #{atom() => non_neg_integer()}
}).

%% Reassembly of one incoming message.
-record(ra, {
    frags = #{} :: #{integer() => {boolean(), boolean(), non_neg_integer(), binary()}},
    first = undefined :: undefined | integer(),
    last = undefined :: undefined | integer(),
    bytes = 0 :: non_neg_integer()
}).

%% Incoming stream (ordered delivery state).
-record(istream, {
    next = 0 :: non_neg_integer(),
    pending = #{} :: #{non_neg_integer() => {non_neg_integer(), binary()}}
}).

%% Receive side.
-record(rcv, {
    idata = false :: boolean(),
    mis = 65535 :: non_neg_integer(),
    rbuf :: pos_integer(),
    max_msg :: pos_integer(),
    cum = 0 :: integer(),
    highest = 0 :: integer(),
    seen = gb_sets:empty() :: gb_sets:set(integer()),
    dups = [] :: [non_neg_integer()],
    bytes = 0 :: non_neg_integer(),
    streams = #{} :: #{0..65535 => #istream{}},
    ra = #{} :: #{term() => #ra{}},
    %% Deferred incoming resets (RFC 6525 §5.2.2 E2): {LastTsnU, Sids, ReqSeq}.
    deferred = [] :: [{integer(), [0..65535], non_neg_integer()}],
    held = [] :: [{integer(), #sctp_data{}}],
    %% Streams that received a message over max_msg: their user data is
    %% dropped until the stream is reset (RFC 8841 §6).
    discard = #{} :: #{0..65535 => true},
    %% SACK scheduling.
    got_data = false :: boolean(),
    only_dups = true :: boolean(),
    sack_now = false :: boolean(),
    packets = 0 :: non_neg_integer(),
    sack_at = undefined :: undefined | integer(),
    sack_delay = 200 :: non_neg_integer(),
    sack_freq = 2 :: pos_integer(),
    stats = #{} :: #{atom() => non_neg_integer()}
}).

%% Stream reconfiguration (RFC 6525).
-record(rcf, {
    enabled = false :: boolean(),
    my_seq = 0 :: non_neg_integer(),
    peer_seq = 0 :: non_neg_integer(),
    %% Streams waiting for an outgoing reset request, with the response
    %% sequence to carry when answering an incoming reset request.
    pending = [] :: [0..65535],
    resp_for = undefined :: undefined | non_neg_integer(),
    inflight = undefined ::
        undefined
        | #{
            seq := non_neg_integer(),
            param := term(),
            sids := [0..65535],
            deadline := integer(),
            rto := pos_integer(),
            counted := boolean()
        },
    last_resp = undefined :: undefined | {non_neg_integer(), term()},
    out = [] :: [term()]
}).

%% Association (TCB).
-record(assoc, {
    cfg :: #cfg{},
    state = closed ::
        closed
        | cookie_wait
        | cookie_echoed
        | established
        | shutdown_pending
        | shutdown_sent
        | shutdown_received
        | shutdown_ack_sent,
    terminated = false :: boolean(),
    my_vtag = 0 :: 0..16#FFFFFFFF,
    peer_vtag = 0 :: 0..16#FFFFFFFF,
    my_itsn = 0 :: 0..16#FFFFFFFF,
    peer_itsn = 0 :: 0..16#FFFFFFFF,
    init = undefined :: undefined | #sctp_init{},
    cookie = undefined :: undefined | binary(),
    peer = #{} :: map(),
    %% T1 (init / cookie) and T2 (shutdown) timers.
    t1 = undefined :: undefined | {init | cookie, integer(), pos_integer(), non_neg_integer()},
    t2 = undefined :: undefined | {integer(), pos_integer()},
    stale_retries = 0 :: non_neg_integer(),
    preservative = 0 :: non_neg_integer(),
    error_count = 0 :: non_neg_integer(),
    snd :: #snd{},
    rcv :: #rcv{},
    rcf = #rcf{} :: #rcf{},
    hb_at = undefined :: undefined | integer(),
    hb_out = undefined :: undefined | {binary(), integer()},
    acts = [] :: [term()],
    ctrl = [] :: [term()],
    rand :: crypto | rand:state(),
    connected_at = undefined :: undefined | integer(),
    stats = #{} :: #{atom() => non_neg_integer()}
}).
