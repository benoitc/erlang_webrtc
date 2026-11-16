%% @doc SCTP association setup (RFC 9260 §5, §8.4, §8.5.1).
%%
%% Internal module of `webrtc_sctp_assoc': four-way handshake with a
%% stateless State Cookie, INIT collisions (simultaneous open, §5.2.1),
%% unexpected INIT in an existing association (§5.2.2), COOKIE ECHO with
%% an existing TCB and tie-tags (§5.2.4, including peer restart), stale
%% cookies (§5.2.6) and "Out of the Blue" packets (§8.4).
-module(webrtc_sctp_handshake).

-include("webrtc_sctp_assoc.hrl").

%% Upper bound of the lifetime extension granted to a Cookie
%% Preservative (§5.2.6 leaves it to the implementation).
-define(MAX_PRESERVATIVE, 60000).

-export([
    connect/2,
    handle_init/3,
    handle_init_ack/3,
    handle_cookie_echo/4,
    handle_cookie_ack/2,
    handle_stale_cookie/3,
    ootb/3,
    t1_expired/2,
    rand32/1
]).

%%====================================================================
%% Active open
%%====================================================================

-spec connect(integer(), #assoc{}) -> #assoc{}.
connect(Now, #assoc{state = closed, terminated = false, cfg = C} = A0) ->
    {Tag, A1} = rand_nonzero(A0),
    {Itsn, A2} = rand32(A1),
    Init = #sctp_init{
        tag = Tag,
        a_rwnd = (A2#assoc.rcv)#rcv.rbuf,
        os = C#cfg.os,
        mis = C#cfg.mis,
        tsn = Itsn,
        params = local_params(C)
    },
    Rto = C#cfg.rto_initial,
    A3 = A2#assoc{
        my_vtag = Tag,
        my_itsn = Itsn,
        init = Init,
        state = cookie_wait,
        t1 = {init, Now + Rto, Rto, 0}
    },
    webrtc_sctp_out:raw(0, [Init], crc32c, A3);
connect(_Now, A) ->
    A.

local_params(#cfg{interleaving = IL, zero_checksum = Z}) ->
    Ext =
        [?SCTP_RECONFIG, ?SCTP_FORWARD_TSN] ++
            case IL of
                true -> [?SCTP_IDATA, ?SCTP_IFORWARD_TSN];
                false -> []
            end,
    [{supported_extensions, Ext}, forward_tsn_supported] ++
        case Z of
            true -> [{zero_checksum_acceptable, ?SCTP_EDMID_DTLS}];
            false -> []
        end.

%% Parameters of a received INIT or INIT ACK, following the rules for
%% unrecognized parameters (§3.2.1).
peer_params(Params) ->
    peer_params(Params, #{
        ext => [], fwd => false, zero => false, unrec => [], cookie => undefined, prsv => 0
    }).

peer_params([], Acc) ->
    finish_params(Acc);
peer_params([P | Rest], Acc) ->
    case P of
        {supported_extensions, L} ->
            peer_params(Rest, Acc#{ext := L});
        forward_tsn_supported ->
            peer_params(Rest, Acc#{fwd := true});
        {zero_checksum_acceptable, ?SCTP_EDMID_DTLS} ->
            peer_params(Rest, Acc#{zero := true});
        {state_cookie, Cookie} ->
            peer_params(Rest, Acc#{cookie := Cookie});
        {cookie_preservative, Ms} ->
            peer_params(Rest, Acc#{prsv := Ms});
        {unknown_param, T, _} ->
            {Action, Report} = webrtc_sctp_param:unrecognized_param_action(T),
            Acc1 =
                case Report of
                    true ->
                        Acc#{unrec := maps:get(unrec, Acc) ++ [webrtc_sctp_param:encode_param(P)]};
                    false ->
                        Acc
                end,
            case Action of
                stop -> finish_params(Acc1);
                skip -> peer_params(Rest, Acc1)
            end;
        _ ->
            peer_params(Rest, Acc)
    end.

finish_params(#{ext := Ext, fwd := Fwd, zero := Z} = Acc) ->
    Features = #{
        idata => lists:member(?SCTP_IDATA, Ext),
        ifwd => lists:member(?SCTP_IFORWARD_TSN, Ext),
        pr => Fwd orelse lists:member(?SCTP_FORWARD_TSN, Ext),
        reconfig => lists:member(?SCTP_RECONFIG, Ext),
        zero_checksum => Z
    },
    Acc#{features => Features}.

%%====================================================================
%% INIT (§5.1, §5.2.1, §5.2.2)
%%====================================================================

-spec handle_init(#sctp_init{}, integer(), #assoc{}) -> #assoc{}.
handle_init(#sctp_init{tag = PeerTag, params = Ps} = Init, Now, A) when PeerTag =/= 0 ->
    %% §5.1.2: an INIT with a Host Name Address is answered with an ABORT.
    case host_name(Ps) of
        {ok, Param} -> webrtc_sctp_out:raw(PeerTag, [{abort, false, [{unresolvable_address, Param}]}], crc32c, A);
        none -> init(Init, Now, A)
    end;
handle_init(Init, Now, A) ->
    init(Init, Now, A).

%% The Host Name Address parameter, encoded, if the chunk has one.
host_name(Ps) ->
    case [H || {host_name, H} <- Ps] of
        [H | _] -> {ok, iolist_to_binary(webrtc_sctp_param:encode_param({host_name, H}))};
        [] -> none
    end.

init(#sctp_init{tag = 0}, _Now, A) ->
    A;
init(#sctp_init{tag = PeerTag, os = OS, mis = MIS}, _Now, A) when OS =:= 0; MIS =:= 0 ->
    webrtc_sctp_out:raw(PeerTag, [{abort, false, [invalid_mandatory_param]}], crc32c, A);
init(#sctp_init{tag = PeerTag}, _Now, #assoc{state = closed, terminated = true} = A) ->
    webrtc_sctp_out:raw(PeerTag, [{abort, false, []}], crc32c, A);
init(Init, Now, #assoc{state = closed} = A0) ->
    {Tag, A1} = rand_nonzero(A0),
    {Itsn, A2} = rand32(A1),
    respond(Init, Tag, Itsn, 0, 0, Now, A2);
init(Init, Now, #assoc{state = cookie_wait} = A) ->
    respond(Init, A#assoc.my_vtag, A#assoc.my_itsn, 0, 0, Now, A);
init(Init, Now, #assoc{state = cookie_echoed} = A) ->
    respond(Init, A#assoc.my_vtag, A#assoc.my_itsn, A#assoc.my_vtag, A#assoc.peer_vtag, Now, A);
init(_Init, _Now, #assoc{state = shutdown_ack_sent} = A) ->
    %% §9.2: the SHUTDOWN COMPLETE was probably lost.
    webrtc_sctp_out:ctrl(shutdown_ack, A);
init(Init, Now, A0) ->
    {Tag, A1} = rand_nonzero(A0),
    {Itsn, A2} = rand32(A1),
    respond(Init, Tag, Itsn, A0#assoc.my_vtag, A0#assoc.peer_vtag, Now, A2).

respond(#sctp_init{} = Init, Tag, Itsn, LTie, PTie, Now, #assoc{cfg = C} = A) ->
    P = peer_params(Init#sctp_init.params),
    Life = C#cfg.cookie_life + min(maps:get(prsv, P), ?MAX_PRESERVATIVE),
    Cookie = webrtc_sctp_cookie:make(
        #{
            my_tag => Tag,
            peer_tag => Init#sctp_init.tag,
            my_itsn => Itsn,
            peer_itsn => Init#sctp_init.tsn,
            peer_rwnd => Init#sctp_init.a_rwnd,
            peer_os => Init#sctp_init.os,
            peer_mis => Init#sctp_init.mis,
            local_tie => LTie,
            peer_tie => PTie,
            created => Now,
            life => Life,
            features => maps:get(features, P)
        },
        C#cfg.secret
    ),
    Unrec = [{unrecognized_param, U} || U <- maps:get(unrec, P)],
    Ack = #sctp_init{
        ack = true,
        tag = Tag,
        a_rwnd = (A#assoc.rcv)#rcv.rbuf,
        %% The streams the association will use: no more than the
        %% peer can receive (§5.1.1).
        os = min(C#cfg.os, Init#sctp_init.mis),
        mis = C#cfg.mis,
        tsn = Itsn,
        params = [{state_cookie, Cookie} | local_params(C)] ++ Unrec
    },
    webrtc_sctp_out:raw(Init#sctp_init.tag, [Ack], crc32c, A).

%%====================================================================
%% INIT ACK (§5.1 C, §5.2.3)
%%====================================================================

-spec handle_init_ack(#sctp_init{}, integer(), #assoc{}) -> {continue | stop, #assoc{}}.
handle_init_ack(#sctp_init{} = Ack, Now, #assoc{state = cookie_wait} = A) ->
    #sctp_init{tag = Tag, os = OS, mis = MIS, params = Params} = Ack,
    P = peer_params(Params),
    HostName = host_name(Params),
    if
        Tag =:= 0; OS =:= 0; MIS =:= 0 ->
            %% §3.3.3: the association is destroyed; an ABORT tells the
            %% peer why (it MAY be sent). A zero tag cannot address the
            %% peer, the ABORT then reflects our own (T bit).
            Abort = case Tag of
                0 -> webrtc_sctp_out:raw(A#assoc.my_vtag, [{abort, true, [invalid_mandatory_param]}], crc32c, A);
                _ -> webrtc_sctp_out:raw(Tag, [{abort, false, [invalid_mandatory_param]}], crc32c, A)
            end,
            {stop, webrtc_sctp_out:terminate({protocol_violation, invalid_init_ack}, Abort)};
        HostName =/= none ->
            %% §5.1.2: a Host Name Address is answered with an ABORT.
            {ok, HParam} = HostName,
            A1 = webrtc_sctp_out:raw(Tag, [{abort, false, [{unresolvable_address, HParam}]}], crc32c, A),
            {stop, webrtc_sctp_out:terminate({protocol_violation, host_name_address}, A1)};
        map_get(cookie, P) =:= undefined ->
            A1 = webrtc_sctp_out:raw(Tag, [{abort, false, [{missing_param, [7]}]}], crc32c, A),
            {stop, webrtc_sctp_out:terminate({protocol_violation, missing_state_cookie}, A1)};
        true ->
            Cookie = maps:get(cookie, P),
            Rto = (A#assoc.cfg)#cfg.rto_initial,
            A1 = A#assoc{
                state = cookie_echoed,
                peer_vtag = Tag,
                peer_itsn = Ack#sctp_init.tsn,
                cookie = Cookie,
                peer = #{
                    features => maps:get(features, P),
                    rwnd => Ack#sctp_init.a_rwnd,
                    os => OS,
                    mis => MIS
                },
                t1 = {cookie, Now + Rto, Rto, 0}
            },
            Errors =
                case maps:get(unrec, P) of
                    [] -> [];
                    U -> [{op_error, [{unrecognized_params, iolist_to_binary(U)}]}]
                end,
            {continue, webrtc_sctp_out:raw(Tag, [{cookie_echo, Cookie} | Errors], crc32c, A1)}
    end;
handle_init_ack(_Ack, _Now, A) ->
    {continue, A}.

%%====================================================================
%% COOKIE ECHO (§5.1 D, §5.1.5, §5.2.4)
%%====================================================================

-spec handle_cookie_echo(binary(), 0..16#FFFFFFFF, integer(), #assoc{}) ->
    {continue | stop, #assoc{}}.
handle_cookie_echo(Cookie, Vtag, Now, #assoc{cfg = C} = A) ->
    case webrtc_sctp_cookie:open(Cookie, C#cfg.secret) of
        {ok, #{my_tag := Vtag} = F} ->
            echo(F, Now, A);
        _ ->
            {stop, webrtc_sctp_out:bump(bad_cookies, A)}
    end.

echo(_F, _Now, #assoc{state = closed, terminated = true} = A) ->
    {stop, A};
echo(F, Now, #assoc{state = closed} = A) ->
    case stale(F, Now) of
        true -> {stop, stale_error(F, Now, A)};
        false -> {continue, webrtc_sctp_out:ctrl(cookie_ack, establish(F, Now, connected, A))}
    end;
echo(F, Now, #assoc{state = St, my_vtag = My, peer_vtag = Peer} = A) ->
    #{my_tag := CMy, peer_tag := CPeer, local_tie := LTie, peer_tie := PTie} = F,
    LT = CMy =:= My,
    PT = CPeer =:= Peer,
    Setup = St =:= cookie_wait orelse St =:= cookie_echoed,
    case stale(F, Now) andalso not (LT andalso PT) of
        true ->
            {stop, stale_error(F, Now, A)};
        false when LT, PT ->
            %% Case D.
            A1 =
                case Setup of
                    true -> establish(F, Now, connected, A);
                    false -> A
                end,
            {continue, webrtc_sctp_out:ctrl(cookie_ack, A1)};
        false when LT ->
            %% Case B: the peer picked a new tag after answering our INIT.
            A1 =
                case Setup of
                    true -> establish(F, Now, connected, A);
                    false -> A#assoc{peer_vtag = CPeer}
                end,
            {continue, webrtc_sctp_out:ctrl(cookie_ack, A1)};
        false when PT, LTie =:= 0, PTie =:= 0 ->
            %% Case C: a late cookie of ours.
            {stop, A};
        false when not LT, not PT, LTie =:= My, PTie =:= Peer, LTie =/= 0, PTie =/= 0 ->
            %% Case A: peer restart.
            case St of
                shutdown_ack_sent ->
                    A1 = webrtc_sctp_out:ctrl(shutdown_ack, A),
                    {stop, webrtc_sctp_out:ctrl({op_error, [cookie_while_shutting_down]}, A1)};
                _ ->
                    {continue, webrtc_sctp_out:ctrl(cookie_ack, restart(F, Now, A))}
            end;
        false ->
            {stop, A}
    end.

stale(#{created := Created, life := Life}, Now) ->
    Now - Created > Life.

stale_error(#{created := Created, life := Life, peer_tag := PeerTag}, Now, A) ->
    Usec = min((Now - Created - Life) * 1000, ?U32),
    A1 = webrtc_sctp_out:bump(stale_cookies, A),
    webrtc_sctp_out:raw(PeerTag, [{op_error, [{stale_cookie, Usec}]}], crc32c, A1).

restart(F, Now, #assoc{cfg = C} = A) ->
    A1 = A#assoc{
        snd = webrtc_sctp_send:new(C),
        rcv = webrtc_sctp_recv:new(C),
        rcf = #rcf{},
        t2 = undefined,
        hb_out = undefined,
        ctrl = []
    },
    establish(F, Now, restarted, webrtc_sctp_out:bump(restarts, A1)).

%% Build the TCB from cookie fields and enter ESTABLISHED.
establish(F, Now, Event, #assoc{cfg = C} = A) ->
    #{features := PF} = F,
    IData =
        C#cfg.interleaving andalso maps:get(idata, PF, false) andalso
            maps:get(ifwd, PF, false),
    PR = maps:get(pr, PF, false),
    Reconfig = maps:get(reconfig, PF, false),
    Zero = C#cfg.zero_checksum andalso maps:get(zero_checksum, PF, false),
    OS = min(C#cfg.os, maps:get(peer_mis, F)),
    MIS = min(C#cfg.mis, maps:get(peer_os, F)),
    MyItsn = maps:get(my_itsn, F),
    PeerItsn = maps:get(peer_itsn, F),
    Rwnd = maps:get(peer_rwnd, F),
    Snd = webrtc_sctp_send:start(
        #{tsn => MyItsn, rwnd => Rwnd, idata => IData, pr => PR, os => OS}, A#assoc.snd
    ),
    Rcv = webrtc_sctp_recv:start(#{tsn => PeerItsn, idata => IData, mis => MIS}, A#assoc.rcv),
    Rcf = webrtc_sctp_reconfig:start(MyItsn, PeerItsn, Reconfig, A#assoc.rcf),
    Peer = #{
        idata => IData,
        pr => PR,
        reconfig => Reconfig,
        zero_checksum => Zero,
        rwnd => Rwnd
    },
    HbAt =
        case C#cfg.hb_interval of
            infinity -> undefined;
            Ival -> Now + Ival + Snd#snd.rto
        end,
    A1 = webrtc_sctp_pmtu:start(Now, A#assoc{
        state = established,
        my_vtag = maps:get(my_tag, F),
        peer_vtag = maps:get(peer_tag, F),
        my_itsn = MyItsn,
        peer_itsn = PeerItsn,
        peer = Peer,
        snd = Snd,
        rcv = Rcv,
        rcf = Rcf,
        t1 = undefined,
        error_count = 0,
        hb_at = HbAt,
        connected_at = Now
    }),
    Info = #{
        message_interleaving => IData,
        partial_reliability => PR,
        stream_reconfig => Reconfig,
        zero_checksum => Zero,
        outbound_streams => OS,
        inbound_streams => MIS,
        peer_rwnd => Rwnd
    },
    webrtc_sctp_out:event({Event, Info}, A1).

%%====================================================================
%% COOKIE ACK, stale cookie, T1 (§5.1 E, §5.2.5, §5.2.6)
%%====================================================================

-spec handle_cookie_ack(integer(), #assoc{}) -> #assoc{}.
handle_cookie_ack(Now, #assoc{state = cookie_echoed, peer = P} = A) ->
    F = #{
        my_tag => A#assoc.my_vtag,
        peer_tag => A#assoc.peer_vtag,
        my_itsn => A#assoc.my_itsn,
        peer_itsn => A#assoc.peer_itsn,
        peer_rwnd => maps:get(rwnd, P),
        peer_os => maps:get(os, P),
        peer_mis => maps:get(mis, P),
        features => maps:get(features, P)
    },
    establish(F, Now, connected, A);
handle_cookie_ack(_Now, A) ->
    A.

%% Alternative 3 of §5.2.6: new INIT with a Cookie Preservative.
-spec handle_stale_cookie(non_neg_integer(), integer(), #assoc{}) -> #assoc{}.
handle_stale_cookie(Usec, Now, #assoc{state = cookie_echoed, cfg = C} = A) ->
    case A#assoc.stale_retries + 1 > C#cfg.max_init_retrans of
        true ->
            webrtc_sctp_out:terminate(stale_cookie, A);
        false ->
            Rtt =
                case A#assoc.t1 of
                    {cookie, D, R, _} -> max(0, Now - (D - R));
                    _ -> 0
                end,
            Inc = min(Usec div 1000 + Rtt + 1, ?U32),
            Init0 = A#assoc.init,
            Params = [
                P
             || P <- Init0#sctp_init.params,
                not is_tuple(P) orelse element(1, P) =/= cookie_preservative
            ],
            Init = Init0#sctp_init{params = Params ++ [{cookie_preservative, Inc}]},
            Rto = C#cfg.rto_initial,
            A1 = A#assoc{
                state = cookie_wait,
                init = Init,
                peer_vtag = 0,
                cookie = undefined,
                peer = #{},
                stale_retries = A#assoc.stale_retries + 1,
                t1 = {init, Now + Rto, Rto, 0}
            },
            webrtc_sctp_out:raw(0, [Init], crc32c, A1)
    end;
handle_stale_cookie(_Usec, _Now, A) ->
    A.

%% @doc T1-init / T1-cookie expiry (§5.1 A, C).
-spec t1_expired(integer(), #assoc{}) -> #assoc{}.
t1_expired(Now, #assoc{t1 = {Kind, D, Rto, N}, cfg = C} = A) when Now >= D ->
    case N + 1 > C#cfg.max_init_retrans of
        true ->
            %% Giving up on a COOKIE ECHO: the peer's tag is known, tell it.
            A1 = case Kind of cookie -> webrtc_sctp_out:abort_peer(A); init -> A end,
            webrtc_sctp_out:terminate(handshake_timeout, A1);
        false ->
            Rto1 = min(2 * Rto, C#cfg.rto_max),
            A1 = webrtc_sctp_out:bump(init_retransmissions, A#assoc{
                t1 = {Kind, Now + Rto1, Rto1, N + 1}
            }),
            case Kind of
                init ->
                    webrtc_sctp_out:raw(0, [A#assoc.init], crc32c, A1);
                cookie ->
                    webrtc_sctp_out:raw(
                        A#assoc.peer_vtag, [{cookie_echo, A#assoc.cookie}], crc32c, A1
                    )
            end
    end;
t1_expired(_Now, A) ->
    A.

%%====================================================================
%% Out of the blue (§8.4)
%%====================================================================

-spec ootb(#sctp_packet{}, integer(), #assoc{}) -> #assoc{}.
ootb(#sctp_packet{vtag = Vtag, chunks = Chunks}, _Now, A) ->
    Has = fun(F) -> lists:any(F, Chunks) end,
    IsAbort = fun(C) -> element(1, C) =:= abort end,
    IsShutdownAck = fun(C) -> C =:= shutdown_ack end,
    IsComplete = fun(C) -> is_tuple(C) andalso element(1, C) =:= shutdown_complete end,
    IsQuiet = fun
        (cookie_ack) -> true;
        ({op_error, Causes}) -> lists:any(fun(X) -> element(1, X) =:= stale_cookie end, Causes);
        (_) -> false
    end,
    Tuple = [C || C <- Chunks, is_tuple(C)],
    A1 = webrtc_sctp_out:bump(ootb_packets, A),
    case {lists:any(IsAbort, Tuple), Has(IsShutdownAck), Has(IsComplete), Has(IsQuiet)} of
        {true, _, _, _} -> A1;
        {_, true, _, _} -> webrtc_sctp_out:raw(Vtag, [{shutdown_complete, true}], crc32c, A1);
        {_, _, true, _} -> A1;
        {_, _, _, true} -> A1;
        _ -> webrtc_sctp_out:raw(Vtag, [{abort, true, []}], crc32c, A1)
    end.

%%====================================================================
%% Random values
%%====================================================================

%% @doc 32-bit random value from crypto, or from the seeded generator
%% when `random_seed' was given to `webrtc_sctp_assoc:new/1'.
-spec rand32(#assoc{}) -> {0..16#FFFFFFFF, #assoc{}}.
rand32(#assoc{rand = crypto} = A) ->
    <<N:32>> = crypto:strong_rand_bytes(4),
    {N, A};
rand32(#assoc{rand = S} = A) ->
    {V, S1} = rand:uniform_s(1 bsl 32, S),
    {V - 1, A#assoc{rand = S1}}.

rand_nonzero(A) ->
    case rand32(A) of
        {0, A1} -> rand_nonzero(A1);
        R -> R
    end.
