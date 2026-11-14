%% Internal state shared by the webrtc_ice_* modules. Not part of the
%% public API: use the accessors of webrtc_ice_agent.
-include("webrtc_ice.hrl").
-include("webrtc_stun.hrl").

%% Candidate pair (RFC 8445 §6.1.2.6). `id' is {LocalId, RemoteId}. Pairs
%% in the checklist always have a host or relayed local candidate; valid
%% pairs built from a mapped address (§7.2.5.3.2) may have a reflexive
%% local candidate and are kept with `in_checklist = false'.
-record(pair, {
    id :: {pos_integer(), pos_integer()},
    local :: pos_integer(),
    remote :: pos_integer(),
    component :: 1..256,
    foundation :: {binary(), binary()},
    priority :: non_neg_integer(),
    state = frozen :: frozen | waiting | in_progress | succeeded | failed,
    in_checklist = true :: boolean(),
    valid = false :: boolean(),
    nominated = false :: boolean(),
    %% Controlling agent: the next check on this pair carries USE-CANDIDATE.
    use_candidate = false :: boolean(),
    %% Controlled agent: nominate the valid pair once this pair's
    %% triggered check succeeds (§7.3.1.5).
    nominate_on_success = false :: boolean(),
    %% Valid pairs: the pair whose check produced them.
    generated_by :: {pos_integer(), pos_integer()} | undefined,
    txid :: binary() | undefined,
    rtt :: non_neg_integer() | undefined,
    requests_sent = 0 :: non_neg_integer(),
    responses_received = 0 :: non_neg_integer(),
    requests_received = 0 :: non_neg_integer(),
    responses_sent = 0 :: non_neg_integer(),
    last_sent :: integer() | undefined,
    %% Consent freshness (RFC 7675).
    consent_expires :: integer() | undefined,
    consent_ok :: integer() | undefined,
    consent_next :: integer() | undefined,
    consent_txids = [] :: [{binary(), integer()}],
    consent_lost = false :: boolean()
}).

%% Credentials of the session preceding an ICE restart, with the pairs
%% that stay usable until the new session selects its own (RFC 8445 §9).
-record(prev, {
    ufrag :: binary(),
    pwd :: binary(),
    remote_ufrag :: binary(),
    remote_pwd :: binary(),
    pairs = #{} :: #{1..256 => {#pair{}, #ice_cand{}}}
}).

-record(ice, {
    %% Configuration.
    lite = false :: boolean(),
    remote_lite = false :: boolean(),
    role = controlling :: controlling | controlled,
    tiebreaker :: non_neg_integer(),
    rand :: rand:state(),
    components = [1] :: [1..256],
    ta = 50 :: pos_integer(),
    rc = 7 :: pos_integer(),
    rm = 16 :: pos_integer(),
    min_rto = 500 :: pos_integer(),
    max_check_rto = 2500 :: pos_integer() | infinity,
    max_rto = infinity :: pos_integer() | infinity,
    max_pairs = 100 :: pos_integer(),
    pac_timeout = 39500 :: non_neg_integer(),
    eoc_timeout = 39500 :: non_neg_integer(),
    nomination = best :: best | first,
    nomination_timeout = 1000 :: non_neg_integer(),
    consent = true :: boolean(),
    consent_interval = 5000 :: pos_integer(),
    consent_expiry = 30000 :: pos_integer(),
    disconnect_timeout = 10000 :: pos_integer(),
    keepalive_interval = 15000 :: pos_integer(),
    stun_keepalive = 15000 :: pos_integer(),
    stun_servers = [] :: [{inet:ip_address(), inet:port_number()}],
    turn_servers = [] :: [map()],
    %% Credentials.
    ufrag :: binary(),
    pwd :: binary(),
    remote_ufrag :: binary() | undefined,
    remote_pwd :: binary() | undefined,
    prev :: #prev{} | undefined,
    %% Candidates, keyed by an internal id.
    next_id = 1 :: pos_integer(),
    local = #{} :: #{pos_integer() => #ice_cand{}},
    base_of = #{} :: #{pos_integer() => pos_integer()},
    host_rank = 0 :: non_neg_integer(),
    remote = #{} :: #{pos_integer() => #ice_cand{}},
    remote_eoc = false :: boolean(),
    %% Checklist (one data stream).
    pairs = #{} :: #{{pos_integer(), pos_integer()} => #pair{}},
    triggered = [] :: [{pos_integer(), pos_integer()}],
    cl_state = running :: running | completed | failed,
    started_at :: integer() | undefined,
    first_valid_at :: integer() | undefined,
    nominating :: {pos_integer(), pos_integer()} | undefined,
    nomination_failed = false :: boolean(),
    selected = #{} :: #{1..256 => {pos_integer(), pos_integer()}},
    %% Client transactions (checks and STUN server bindings).
    tx :: webrtc_stun_tx:table(),
    last_paced :: integer() | undefined,
    %% Gathering.
    gather_state = new :: new | gathering | complete,
    gather_queue = [] :: [term()],
    gather_pending = [] :: [term()],
    stun_refresh = #{} :: #{{pos_integer(), term()} => integer()},
    turn = #{} :: #{{term(), {inet:ip_address(), inet:port_number()}} => map()},
    %% Binding requests received before the remote credentials.
    early = [] :: [tuple()],
    %% Status.
    state = new :: new | checking | connected | completed | failed | disconnected | closed,
    recheck_at = infinity :: integer() | infinity,
    ta_at = infinity :: integer() | infinity,
    counters = #{} :: #{atom() => non_neg_integer()}
}).

-define(INC(Key, S), (S)#ice{counters = maps:update_with(Key, fun(V) -> V + 1 end, 1, (S)#ice.counters)}).
