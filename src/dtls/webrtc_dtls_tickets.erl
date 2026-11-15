%% @private DTLS 1.3 session tickets (RFC 8446 §4.6.1, §8): the client
%% cache, the server's ticket protection and the 0-RTT anti-replay set.
%%
%% Everything lives in one public ETS table, created by the application
%% supervisor (or on first use, owned by the caller, in tests):
%%
%% <ul>
%% <li>`{{client, Key}, Entry}': a ticket the client may resume with,
%%     keyed by the remote fingerprints of the association it came
%%     from. Each ticket is used once (RFC 8446 §C.4).</li>
%% <li>`{{used, Id}, Expires}': tickets whose early data a server
%%     already accepted (single use anti-replay, RFC 8446 §8.1).</li>
%% </ul>
%%
%% Server tickets are stateless: the PSK, suite, issue time, age_add,
%% the peer certificate verified in the full handshake and the early
%% data limit, sealed with AES-256-GCM under a key held for the life of
%% the node.
-module(webrtc_dtls_tickets).

-export([ensure/0, put_client/2, take_client/1, seal/1, open/1, first_use/2]).

-define(TAB, webrtc_dtls_tickets).
-define(KEY, {?MODULE, ticket_key}).
-define(MAX_ENTRIES, 10000).

%% @doc Create the table and the ticket key when they do not exist yet.
-spec ensure() -> ok.
ensure() ->
    _ = key(),
    case ets:whereis(?TAB) of
        undefined ->
            try
                _ = ets:new(?TAB, [named_table, public, set, {read_concurrency, true}]),
                ok
            catch
                error:badarg -> ok
            end;
        _ ->
            ok
    end.

%% @doc Store a ticket for later resumption with the same peer.
-spec put_client(term(), map()) -> ok.
put_client(Key, Entry) ->
    ok = ensure(),
    prune(),
    true = ets:insert(?TAB, {{client, Key}, Entry}),
    ok.

%% @doc Take (and remove) the ticket stored for `Key', if still valid.
-spec take_client(term()) -> {ok, map()} | error.
take_client(Key) ->
    ok = ensure(),
    Now = erlang:system_time(millisecond),
    case ets:take(?TAB, {client, Key}) of
        [{_, #{received := R, lifetime := L} = E}] when Now - R < L * 1000 -> {ok, E};
        _ -> error
    end.

%% @doc Protect a server ticket.
-spec seal(term()) -> binary().
seal(Term) ->
    IV = crypto:strong_rand_bytes(12),
    {Ct, Tag} = crypto:crypto_one_time_aead(aes_256_gcm, key(), IV, term_to_binary(Term), <<"dtls13 ticket">>, 16, true),
    <<IV/binary, Tag/binary, Ct/binary>>.

%% @doc Open a server ticket; `error' for a ticket we did not seal.
-spec open(binary()) -> {ok, term()} | error.
open(<<IV:12/binary, Tag:16/binary, Ct/binary>>) ->
    case crypto:crypto_one_time_aead(aes_256_gcm, key(), IV, Ct, <<"dtls13 ticket">>, Tag, false) of
        Bin when is_binary(Bin) ->
            try {ok, binary_to_term(Bin, [safe])}
            catch _:_ -> error
            end;
        error ->
            error
    end;
open(_) ->
    error.

%% @doc True the first time a ticket's early data is accepted, false
%% after (RFC 8446 §8.1); entries expire with the ticket.
-spec first_use(binary(), integer()) -> boolean().
first_use(Ticket, Expires) ->
    ok = ensure(),
    prune(),
    ets:insert_new(?TAB, {{used, crypto:hash(sha256, Ticket)}, Expires}).

key() ->
    case persistent_term:get(?KEY, undefined) of
        undefined ->
            K = crypto:strong_rand_bytes(32),
            persistent_term:put(?KEY, K),
            K;
        K ->
            K
    end.

%% Expired entries go when the table grows.
prune() ->
    case ets:info(?TAB, size) of
        N when is_integer(N), N > ?MAX_ENTRIES ->
            Now = erlang:system_time(millisecond),
            _ = ets:select_delete(?TAB, [{{{used, '_'}, '$1'}, [{'<', '$1', Now}], [true]}]),
            _ = ets:select_delete(?TAB, [{{{client, '_'}, #{received => '$1', lifetime => '$2'}},
                                          [{'<', '$1', {'-', Now, {'*', '$2', 1000}}}], [true]}]),
            ok;
        _ ->
            ok
    end.
