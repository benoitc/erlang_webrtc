%% BoGo shim: runs BoringSSL's DTLS tests (ssl/test/runner) against the
%% webrtc_dtls engine. The runner starts this program with the flags of
%% a test; the shim connects back over TCP, sends its shim id and runs
%% one DTLS connection over the packet adaptor of
%% ssl/test/packeted_bio.cc, on a clock the runner advances. Flags it
%% does not implement make it exit 89, which the runner reports as
%% unimplemented, never as a pass. See interop/bogo/README.md.
-module(webrtc_bogo_shim).

-export([start/0, main/1]).

-define(UNIMPLEMENTED, 89).

%% Flags with a value, and flags without one, that the shim handles.
-define(VALUE_FLAGS, ["-port", "-shim-id", "-key-file", "-cert-file", "-trust-cert", "-mtu", "-min-version",
                      "-max-version", "-expect-version", "-srtp-profiles", "-export-keying-material",
                      "-export-label", "-export-context", "-curves", "-expect-curve-id", "-shim-initial-write", "-initial-timeout-duration-ms",
                      "-read-size"]).
-define(BOOL_FLAGS, ["-dtls", "-server", "-ipv6", "-async", "-implicit-handshake", "-verify-peer",
                     "-require-any-client-certificate", "-use-export-context", "-shim-writes-first",
                     "-shim-shuts-down", "-check-close-notify"]).

%% Started by bogo_shim with the runner's flags after -extra.
start() ->
    main(init:get_plain_arguments()).

main(Args) ->
    try run(Args) of
        _ -> halt(0)
    catch
        throw:done ->
            halt(0);
        throw:{unimplemented, What} ->
            io:format(standard_error, "unimplemented: ~s~n", [What]),
            %% BOGO_SHIM_LOG: one line per unimplemented feature, to see
            %% which ones keep the most tests from running.
            case os:getenv("BOGO_SHIM_LOG") of
                false -> ok;
                Log -> file:write_file(Log, [What, $\n], [append])
            end,
            halt(?UNIMPLEMENTED);
        throw:{fail, Fmt, FArgs} ->
            io:format(standard_error, Fmt ++ "~n", FArgs),
            halt(1);
        C:R:Stack ->
            io:format(standard_error, "shim crashed: ~p:~p ~p~n", [C, R, Stack]),
            halt(1)
    end.

run(["-is-handshaker-supported" | _]) ->
    io:format("No~n");
run(Args) ->
    Cfg = parse(Args, #{curves => []}),
    maps:is_key(dtls, Cfg) orelse throw({unimplemented, "TLS (only DTLS is supported)"}),
    Server = maps:is_key(server, Cfg),
    %% RFC 8827: a WebRTC DTLS server always authenticates the client.
    not Server orelse maps:is_key('require-any-client-certificate', Cfg) orelse
        throw({unimplemented, "a server that does not require a client certificate"}),
    Opts = engine_opts(Server, Cfg),
    Addr = case maps:is_key(ipv6, Cfg) of true -> {0, 0, 0, 0, 0, 0, 0, 1}; false -> {127, 0, 0, 1} end,
    {ok, Sock} = gen_tcp:connect(Addr, list_to_integer(maps:get(port, Cfg)), [binary, {active, false}, {nodelay, true}]),
    ok = gen_tcp:send(Sock, <<(list_to_integer(maps:get('shim-id', Cfg))):64/little>>),
    D0 = webrtc_dtls:new(Opts),
    St0 = #{sock => Sock, cfg => Cfg, now => 0, pinned => false, connected => false, closing => false},
    {D1, Acts} = webrtc_dtls:start(0, D0),
    loop(actions(Acts, St0#{dtls => D1})).

parse([], Cfg) ->
    Cfg;
parse(["-curves", V | Rest], #{curves := Cs} = Cfg) ->
    parse(Rest, Cfg#{curves := Cs ++ [list_to_integer(V)]});
parse([F, V | Rest], Cfg) ->
    case lists:member(F, ?VALUE_FLAGS) of
        true -> parse(Rest, Cfg#{key(F) => V});
        false -> parse_bool([F, V | Rest], Cfg)
    end;
parse(Rest, Cfg) ->
    parse_bool(Rest, Cfg).

parse_bool([F | Rest], Cfg) ->
    case lists:member(F, ?BOOL_FLAGS) of
        true -> parse(Rest, Cfg#{key(F) => true});
        false -> throw({unimplemented, "flag " ++ F})
    end.

key("-" ++ Name) -> list_to_atom(Name).

engine_opts(Server, Cfg) ->
    Cert = load_cert(Cfg),
    %% No remote fingerprints yet: pin() sets them from the handshake.
    Opts0 = #{role => case Server of true -> server; false -> client end, cert => Cert},
    Opts1 = case versions(Cfg) of all -> Opts0; Vs -> Opts0#{versions => Vs} end,
    Opts2 = case maps:find(mtu, Cfg) of {ok, M} -> Opts1#{mtu => list_to_integer(M)}; error -> Opts1 end,
    Opts25 = case maps:find('initial-timeout-duration-ms', Cfg) of
        {ok, T} -> Opts2#{rtx_initial => list_to_integer(T)};
        error -> Opts2
    end,
    Opts3 = case maps:find('srtp-profiles', Cfg) of {ok, P} -> Opts25#{srtp_profiles => srtp(P)}; error -> Opts25 end,
    case maps:get(curves, Cfg) of
        [] -> Opts3;
        Ids -> Opts3#{groups => [group(I) || I <- Ids]}
    end.

load_cert(Cfg) ->
    case {maps:find('cert-file', Cfg), maps:find('key-file', Cfg)} of
        {{ok, CF}, {ok, KF}} ->
            {ok, CPem} = file:read_file(CF),
            {ok, KPem} = file:read_file(KF),
            [{'Certificate', Der, _} | _] = public_key:pem_decode(CPem),
            [KEntry | _] = public_key:pem_decode(KPem),
            #{der => Der, key => public_key:pem_entry_decode(KEntry)};
        _ ->
            webrtc_dtls_cert:generate()
    end.

%% DTLS 1.2 is 0xfefd, DTLS 1.3 0xfefc.
versions(Cfg) ->
    Min = version_bound(maps:get('min-version', Cfg, undefined), 16#fefd),
    Max = version_bound(maps:get('max-version', Cfg, undefined), 16#fefc),
    case [V || {N, V} <- [{16#fefc, 'dtlsv1.3'}, {16#fefd, 'dtlsv1.2'}], N =< Min, N >= Max] of
        [] -> throw({unimplemented, "only DTLS 1.0 in the version range"});
        [_, _] -> all;
        Vs -> Vs
    end.

version_bound(undefined, Default) -> Default;
version_bound(V, _) -> list_to_integer(V).

srtp(Names) ->
    [srtp_id(N) || N <- string:split(Names, ":", all)].

srtp_id("SRTP_AES128_CM_SHA1_80") -> 16#0001;
srtp_id("SRTP_AES128_CM_SHA1_32") -> 16#0002;
srtp_id("SRTP_AEAD_AES_128_GCM") -> 16#0007;
srtp_id("SRTP_AEAD_AES_256_GCM") -> 16#0008;
srtp_id(N) -> throw({unimplemented, "SRTP profile " ++ N}).

group(23) -> secp256r1;
group(24) -> secp384r1;
group(29) -> x25519;
group(N) -> throw({unimplemented, "group " ++ integer_to_list(N)}).

%%====================================================================
%% Connection
%%====================================================================

loop(#{sock := Sock} = St) ->
    case gen_tcp:recv(Sock, 1, 30000) of
        {ok, <<"P">>} ->
            {ok, <<Len:32>>} = gen_tcp:recv(Sock, 4),
            {ok, Pkt} = recv_exact(Sock, Len),
            {D, Acts} = webrtc_dtls:handle_packet(Pkt, ms(St), maps:get(dtls, St)),
            loop(actions(Acts, St#{dtls := D}));
        {ok, <<"T">>} ->
            {ok, <<Ns:64>>} = gen_tcp:recv(Sock, 8),
            ok = gen_tcp:send(Sock, <<"t">>),
            St1 = St#{now := maps:get(now, St) + Ns div 1000},
            loop(timeouts(St1));
        {ok, <<"M">>} ->
            throw({unimplemented, "changing the MTU during a connection"});
        {ok, <<"E">>} ->
            {ok, <<Ns:64>>} = gen_tcp:recv(Sock, 8),
            expect_timeout(Ns, St),
            loop(St);
        {ok, <<"U">>} ->
            throw({unimplemented, "setting the initial retransmission timeout"});
        {ok, <<Op>>} ->
            throw({fail, "unknown packet adaptor opcode ~p", [Op]});
        {error, closed} ->
            %% The runner is done: stop as on a close_notify.
            finish(St);
        {error, R} ->
            throw({fail, "transport error ~p", [R]})
    end.

recv_exact(_Sock, 0) -> {ok, <<>>};
recv_exact(Sock, Len) -> gen_tcp:recv(Sock, Len).

ms(#{now := Us}) -> Us div 1000.

%% The runner advanced the clock: fire the timer if it is due.
timeouts(#{dtls := D} = St) ->
    Now = ms(St),
    case webrtc_dtls:next_timeout(D) of
        At when At =/= infinity, At =< Now ->
            {D1, Acts} = webrtc_dtls:handle_timeout(Now, D),
            actions(Acts, St#{dtls := D1});
        _ ->
            St
    end.

%% The runner checks the retransmission timer against its own schedule.
expect_timeout(Ns, #{dtls := D} = St) ->
    case {Ns, webrtc_dtls:next_timeout(D)} of
        {16#FFFFFFFFFFFFFFFF, infinity} ->
            ok;
        {16#FFFFFFFFFFFFFFFF, At} ->
            throw({fail, "expected no timeout, but got ~b ms", [At - ms(St)]});
        {_, infinity} ->
            throw({fail, "expected a timeout of ~b us, but got none", [Ns div 1000]});
        {_, At} ->
            Ours = At * 1000 - maps:get(now, St),
            abs(Ours - Ns div 1000) < 1000 orelse
                throw({fail, "expected a timeout of ~b us, but got ~b us", [Ns div 1000, Ours]})
    end.

actions(Acts, St0) ->
    trace(Acts, St0),
    St = lists:foldl(fun action/2, St0, Acts),
    pin(St).

%% BOGO_SHIM_TRACE: the engine's actions, to debug a single test.
trace(Acts, #{now := Now}) ->
    case os:getenv("BOGO_SHIM_TRACE") of
        false -> ok;
        File ->
            Lines = [case A of
                         {send, B} -> io_lib:format("~b send ~b ~s~n", [Now, byte_size(B), binary:encode_hex(binary:part(B, 0, min(8, byte_size(B))))]);
                         {event, E} -> io_lib:format("~b event ~P~n", [Now, E, 8])
                     end || A <- Acts],
            file:write_file(File, Lines, [append])
    end.

action({send, Bin}, #{sock := Sock} = St) ->
    case gen_tcp:send(Sock, [<<"P", (byte_size(Bin)):32>>, Bin]) of
        ok -> St;
        {error, R} -> throw({fail, "the runner closed the connection (~p)", [R]})
    end;
action({event, {connected, Info}}, St) ->
    connected(Info, St#{connected := true});
action({event, {data, Bin}}, #{cfg := Cfg} = St) ->
    case maps:is_key('shim-shuts-down', Cfg) of
        true -> St;
        false -> write(<< <<(B bxor 16#ff)>> || <<B>> <= Bin >>, St)
    end;
action({event, {closed, _}}, St) ->
    finish(St);
action({event, {failed, Reason}}, _St) ->
    throw({fail, "connection failed: ~p", [Reason]});
action({event, _}, St) ->
    St.

%% WebRTC pins the peer certificate by fingerprint; the runner's
%% certificates are made at run time, so the shim pins the one the
%% handshake brought, as an application does when the answer arrives
%% late.
pin(#{pinned := false, dtls := D} = St) ->
    case webrtc_dtls:peer_certificate(D) of
        undefined ->
            St;
        Der ->
            {D1, Acts} = webrtc_dtls:set_remote_fingerprints([webrtc_dtls_cert:fingerprint(sha256, Der)], D),
            actions(Acts, St#{dtls := D1, pinned := true})
    end;
pin(St) ->
    St.

connected(Info, #{cfg := Cfg} = St) ->
    check_version(Info, Cfg),
    check_curve(Info, Cfg),
    St1 =
        case maps:find('export-keying-material', Cfg) of
            {ok, N} ->
                Context = case maps:is_key('use-export-context', Cfg) of
                    true -> list_to_binary(maps:get('export-context', Cfg, ""));
                    false -> no_context
                end,
                Label = list_to_binary(maps:get('export-label', Cfg, "")),
                {ok, Km} = webrtc_dtls:export_keying_material(Label, Context, list_to_integer(N), maps:get(dtls, St)),
                write(Km, St);
            error ->
                St
        end,
    St2 =
        case maps:is_key('shim-writes-first', Cfg) of
            true -> write(list_to_binary(maps:get('shim-initial-write', Cfg, "hello")), St1);
            false -> St1
        end,
    case maps:is_key('shim-shuts-down', Cfg) of
        true ->
            {D, Acts} = webrtc_dtls:close(maps:get(dtls, St2)),
            St3 = actions(Acts, St2#{dtls := D, closing := true}),
            case maps:is_key('check-close-notify', Cfg) of
                true -> St3;
                false -> throw(done)
            end;
        false ->
            St2
    end.

check_version(Info, Cfg) ->
    case maps:find('expect-version', Cfg) of
        {ok, V} ->
            Got = case maps:get(version, Info) of 'dtlsv1.3' -> 16#fefc; 'dtlsv1.2' -> 16#fefd; O -> O end,
            Got =:= list_to_integer(V) orelse throw({fail, "expected version ~s, got ~p", [V, Got]});
        error ->
            ok
    end.

check_curve(Info, Cfg) ->
    case maps:find('expect-curve-id', Cfg) of
        {ok, V} ->
            Want = group(list_to_integer(V)),
            maps:get(group, Info) =:= Want orelse throw({fail, "expected group ~p, got ~p", [Want, maps:get(group, Info)]});
        error ->
            ok
    end.

write(Bin, #{dtls := D} = St) ->
    case webrtc_dtls:send(Bin, D) of
        {ok, D1, Acts} -> actions(Acts, St#{dtls := D1});
        {error, R} -> throw({fail, "write failed: ~p", [R]})
    end.

%% A close_notify or the end of the runner's connection: answer with
%% ours unless we sent it already, then stop.
finish(#{closing := true}) ->
    throw(done);
finish(#{dtls := D} = St) ->
    {_, Acts} = webrtc_dtls:close(D),
    _ = lists:foldl(fun action/2, St#{closing := true}, [A || {send, _} = A <- Acts]),
    throw(done).
