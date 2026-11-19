%% DTLS endpoint for DTLS-Fuzzer (state machine learning, see README.md):
%% the webrtc_dtls engine as a UDP server or client. The server gives every
%% client address a fresh engine, and forgets them all when `reset'
%% arrives on the next port (reset.sh, which the fuzzer runs before each
%% test), so every test starts from the initial state even when the
%% fuzzer reuses a client port. The client runs one connection.
%%
%% `webrtc_dtls_sut server Port CertFile KeyFile' or
%% `webrtc_dtls_sut client Port CertFile KeyFile'.
-module(webrtc_dtls_sut).

-export([start/0]).

-define(TICK, 10).

start() ->
    [Role, Port, CertFile, KeyFile] = init:get_plain_arguments(),
    Cert = load_cert(CertFile, KeyFile),
    Opts = #{
        role => list_to_atom(Role),
        cert => Cert,
        versions => ['dtlsv1.2'],
        %% DTLS-Fuzzer's TLS-Attacker configuration leaves extended master
        %% secret out, as it makes key derivation diverge while fuzzing.
        require_ems => false,
        %% No retransmission within a test: the fuzzer waits a fixed time
        %% for each answer, and a resent flight would look like a
        %% different answer to the same input.
        rtx_initial => 30000
    },
    case list_to_atom(Role) of
        server ->
            {ok, Sock} = gen_udp:open(list_to_integer(Port), [binary, {active, true}, {ip, {127, 0, 0, 1}}]),
            {ok, _Ctrl} = gen_udp:open(list_to_integer(Port) + 1, [binary, {active, true}, {ip, {127, 0, 0, 1}}]),
            erlang:send_after(?TICK, self(), tick),
            server(Sock, Opts, #{});
        client ->
            {ok, Sock} = gen_udp:open(0, [binary, {active, true}, {ip, {127, 0, 0, 1}}]),
            Peer = {{127, 0, 0, 1}, list_to_integer(Port)},
            {D, Acts} = webrtc_dtls:start(now_ms(), webrtc_dtls:new(Opts)),
            erlang:send_after(?TICK, self(), tick),
            server(Sock, Opts, #{Peer => act(Sock, Peer, Acts, #{dtls => D, pinned => false})})
    end.

load_cert(CertFile, KeyFile) ->
    {ok, CPem} = file:read_file(CertFile),
    {ok, KPem} = file:read_file(KeyFile),
    [{'Certificate', Der, _} | _] = public_key:pem_decode(CPem),
    [K | _] = public_key:pem_decode(KPem),
    #{der => Der, key => public_key:pem_entry_decode(K)}.

now_ms() -> erlang:monotonic_time(millisecond).

server(Sock, Opts, Conns) ->
    receive
        {udp, Other, _, _, <<"reset", _/binary>>} when Other =/= Sock ->
            server(Sock, Opts, #{});
        {udp, Sock, IP, P, Bin} ->
            Peer = {IP, P},
            C0 = case maps:find(Peer, Conns) of
                {ok, C} -> C;
                error -> #{dtls => webrtc_dtls:new(Opts), pinned => false}
            end,
            {D, Acts} = webrtc_dtls:handle_packet(Bin, now_ms(), maps:get(dtls, C0)),
            server(Sock, Opts, keep(Peer, act(Sock, Peer, Acts, C0#{dtls := D}), Conns));
        tick ->
            erlang:send_after(?TICK, self(), tick),
            Now = now_ms(),
            Conns1 = maps:fold(
                fun(Peer, C, Acc) ->
                    D = maps:get(dtls, C),
                    case webrtc_dtls:next_timeout(D) of
                        At when At =/= infinity, At =< Now ->
                            {D1, Acts} = webrtc_dtls:handle_timeout(Now, D),
                            keep(Peer, act(Sock, Peer, Acts, C#{dtls := D1}), Acc);
                        _ ->
                            Acc#{Peer => C}
                    end
                end, #{}, Conns),
            server(Sock, Opts, Conns1)
    end.

%% A connection that failed or closed is forgotten: the next datagram from
%% that address starts a new one.
keep(Peer, #{dtls := D} = C, Conns) ->
    case webrtc_dtls:status(D) of
        S when S =:= failed; S =:= closed -> maps:remove(Peer, Conns);
        _ -> Conns#{Peer => C}
    end.

act(Sock, {IP, P} = Peer, Acts, C0) ->
    C = lists:foldl(
        fun({send, B}, Acc) ->
                ok = gen_udp:send(Sock, IP, P, B),
                Acc;
           ({event, {data, Data}}, #{dtls := D} = Acc) ->
                %% Echo application data, as the other SUTs do.
                case webrtc_dtls:send(Data, D) of
                    {ok, D1, A} -> act(Sock, Peer, A, Acc#{dtls := D1});
                    {error, _} -> Acc
                end;
           ({event, _}, Acc) ->
                Acc
        end, C0, Acts),
    pin(Sock, Peer, C).

%% WebRTC pins the peer certificate by fingerprint; here the one the
%% handshake brought is pinned, as an application does when the remote
%% description arrives late.
pin(Sock, Peer, #{pinned := false, dtls := D} = C) ->
    case webrtc_dtls:peer_certificate(D) of
        undefined ->
            C;
        Der ->
            {D1, Acts} = webrtc_dtls:set_remote_fingerprints([webrtc_dtls_cert:fingerprint(sha256, Der)], D),
            act(Sock, Peer, Acts, C#{dtls := D1, pinned := true})
    end;
pin(_Sock, _Peer, C) ->
    C.
