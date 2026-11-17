%% @private Network side of the transport process: the UDP sockets and
%% host addresses, the demultiplexing of received datagrams, and the
%% actions of the ICE agent (datagrams to send, through the optional
%% test filter, and its events). DTLS and SRTP only receive what ICE
%% validated (RFC 8445 §12.2, RFC 8826 §4.2). Internal module of
%% `webrtc_transport', working on its state.
-module(webrtc_transport_net).

-include("webrtc_transport.hrl").

-export([
    open_socket/1,
    io/3,
    local_addresses/1,
    family/1,
    datagram/5,
    datagram/6,
    ecn_capable/1,
    ice_actions/2,
    local_candidate/2,
    udp_send/3,
    udp_send/4,
    send_out/2,
    send_out_ect/2,
    transmit/2,
    stream_opened/3,
    stream_data/3,
    stream_closed/3,
    stream_passive/2,
    close_streams/1,
    tcp_listen/2,
    tcp_accepted/3
]).

%% Time allowed to open a stream connection to a TURN server.
-define(CONNECT_TIMEOUT, 5000).

open_socket({IP, Port}) ->
    Family =
        case tuple_size(IP) of
            4 -> inet;
            8 -> inet6
        end,
    case gen_udp:open(Port, [binary, Family, {ip, IP}, {active, ?ACTIVE_N}, {recbuf, 1 bsl 20}, {sndbuf, 1 bsl 20}]) of
        {ok, S} ->
            %% Report the ECN codepoint of received datagrams (RFC 6679),
            %% where the platform can.
            _ = inet:setopts(S, [case Family of inet -> {recvtos, true}; inet6 -> {recvtclass, true} end]),
            {ok, {_, P}} = inet:sockname(S),
            {ok, {S, {IP, P}}};
        {error, _} = E ->
            E
    end.

%% Host candidates: every up, non-loopback interface address, unless
%% `loopback' is set (tests, local interop), and IPv6 link-local
%% addresses are skipped (RFC 8445 §5.1.1.1).
local_addresses(Opts) ->
    case maps:get(loopback, Opts, false) of
        true ->
            [{{127, 0, 0, 1}, 0}];
        false ->
            {ok, Ifs} = inet:getifaddrs(),
            lists:usort([
                {A, 0}
             || {_Name, Props} <- Ifs,
                lists:member(up, proplists:get_value(flags, Props, [])),
                not lists:member(loopback, proplists:get_value(flags, Props, [])),
                {addr, A} <- Props,
                usable(A)
            ])
    end.

family(IP) when tuple_size(IP) =:= 4 -> inet;
family(_) -> inet6.

usable({169, 254, _, _}) -> false;
usable({A, _, _, _, _, _, _, _}) when A band 16#FFC0 =:= 16#FE80 -> false;
usable(_) -> true.

%% @doc Whether the socket reports ECN codepoints.
-spec ecn_capable(gen_udp:socket()) -> boolean().
ecn_capable(Sock) ->
    case inet:getopts(Sock, [recvtos, recvtclass]) of
        {ok, Opts} -> lists:member({recvtos, true}, Opts) orelse lists:member({recvtclass, true}, Opts);
        _ -> false
    end.

datagram(Sock, Src, Bin, Now, St0) ->
    datagram(Sock, Src, Bin, Now, St0, 0).

datagram(Sock, Src, Bin, Now, St0, Ecn) ->
    Class0 = webrtc_demux:classify(Bin),
    St = St0#st{received = maps:update_with(Class0, fun(N) -> N + 1 end, 1, St0#st.received)},
    case Class0 of
        C when C =:= stun; C =:= turn_channel ->
            {I1, Acts} = webrtc_ice_agent:handle_packet(Sock, Src, Bin, Now, St#st.ice),
            ice_actions(Acts, St#st{ice = I1});
        Class ->
            case webrtc_ice_agent:is_valid_remote(Sock, Src, St#st.ice) of
                true -> webrtc_transport_secure:secure_datagram(Class, Bin, Now, io(received, Bin, St), Ecn);
                false -> drop(unvalidated_source, St#st{dropped_last = {Class, Sock, Src}})
            end
    end.

drop(Reason, #st{dropped = D} = St) ->
    St#st{dropped = maps:update_with(Reason, fun(N) -> N + 1 end, 1, D)}.

ice_actions(Acts, St) ->
    lists:foldl(fun ice_action/2, St, Acts).

ice_action({send, {Kind, _} = Ref, _Dest, Bin}, St) when Kind =:= stream; Kind =:= tcp ->
    stream_send(Ref, Bin, St);
ice_action({connect, Ref, Params}, St) ->
    connect(Ref, Params),
    St;
ice_action({open_udp, Ref, #{local := IP}}, St) ->
    %% A TURN allocation retried from a new local port (RFC 8656 §7.4).
    case open_socket({IP, 0}) of
        {ok, {Sock, _}} -> ice(fun(Now, I) -> webrtc_ice_agent:udp_socket_up(Ref, Sock, Now, I) end, St);
        {error, R} -> ice(fun(Now, I) -> webrtc_ice_agent:udp_socket_down(Ref, R, Now, I) end, St)
    end;
ice_action({close_stream, Ref}, St) ->
    close_stream(Ref, St);
ice_action({send, Sock, {IP, Port}, Bin}, #st{filter = undefined} = St) ->
    _ = gen_udp:send(Sock, IP, Port, Bin),
    St;
ice_action({send_ect, Sock, {IP, Port} = Dest, Bin}, #st{filter = undefined} = St) when is_port(Sock) ->
    %% ECT(0) in the IP header (RFC 3168 §5).
    Anc = case tuple_size(IP) of 4 -> [{tos, 2}]; 8 -> [{tclass, 2}] end,
    _ = case gen_udp:send(Sock, Dest, Anc, Bin) of
        ok -> ok;
        {error, _} -> gen_udp:send(Sock, IP, Port, Bin)
    end,
    St;
ice_action({send_ect, Sock, Dest, Bin}, #st{filter = {_, _}} = St) when is_port(Sock) ->
    filtered(Sock, Dest, Bin, 2, St);
ice_action({send_ect, Sock, Dest, Bin}, St) ->
    ice_action({send, Sock, Dest, Bin}, St);
ice_action({send, Sock, Dest, Bin}, #st{filter = {_, _}} = St) ->
    filtered(Sock, Dest, Bin, 0, St);
ice_action({event, {data, Via, Peer, Bin}}, St) ->
    %% Relayed non-STUN data: demultiplex as if received from Peer, under
    %% the same rule as direct traffic. TURN permissions are per IP
    %% (RFC 8656 §9), so any port of a permitted host gets through the
    %% relay; only a validated candidate pair may reach DTLS and SRTP
    %% (RFC 8445 §12.2, RFC 8826 §4.2).
    case webrtc_ice_agent:is_valid_remote(Via, Peer, St#st.ice) of
        true -> webrtc_transport_secure:secure_relayed(Peer, Bin, io(received, Bin, St));
        false -> drop(unvalidated_relayed, St)
    end;
ice_action({event, {connection_state, S} = E}, St) when S =:= connected; S =:= completed ->
    webrtc_transport:to_pc(E, St),
    webrtc_transport_secure:start_dtls_if_ready(webrtc_transport_secure:flush_dtls(St#st{ice_usable = true}));
ice_action({event, {connection_state, _} = E}, St) ->
    webrtc_transport:to_pc(E, St),
    St#st{ice_usable = false};
ice_action({event, {selected_pair, L, R}}, St) ->
    webrtc_transport:to_pc({selected_pair, L, R}, St),
    St1 = webrtc_transport_secure:path_changed(St#st.pair, {L, R}, St#st{pair = {L, R}}),
    webrtc_transport_secure:start_dtls_if_ready(webrtc_transport_secure:flush_dtls(St1));
ice_action({event, {local_candidate, C}}, St) ->
    local_candidate(C, St);
ice_action({event, {consent_lost, _, _} = E}, St) ->
    webrtc_transport:to_pc(E, St),
    St;
ice_action({event, E}, St) ->
    webrtc_transport:to_pc(E, St),
    St.

%% Signaled as a candidate-attribute value, with an mDNS name in place
%% of the host address when `mdns_host_candidates' is set.
local_candidate(C, St) ->
    {Value, M} = webrtc_mdns_client:local_candidate(C, St#st.mdns),
    webrtc_transport:to_pc({local_candidate, Value}, St),
    St#st{mdns = M}.

%% @doc Count an application datagram sent or received.
-spec io(sent | received, binary(), #st{}) -> #st{}.
io(sent, Bin, #st{io = #{packets_sent := P, bytes_sent := B} = Io} = St) ->
    St#st{io = Io#{packets_sent := P + 1, bytes_sent := B + byte_size(Bin)}};
io(received, Bin, #st{io = #{packets_received := P, bytes_received := B} = Io} = St) ->
    St#st{io = Io#{packets_received := P + 1, bytes_received := B + byte_size(Bin)}}.

udp_send(Sock, {IP, Port}, Bin) ->
    _ = gen_udp:send(Sock, IP, Port, Bin),
    ok.

%% @doc The same with an ECN codepoint in the IP header (0: none).
-spec udp_send(term(), webrtc_ice_candidate:address(), binary(), 0..3) -> ok.
udp_send(Sock, Dest, Bin, 0) ->
    udp_send(Sock, Dest, Bin);
udp_send(Sock, {IP, Port} = Dest, Bin, Ecn) ->
    Anc = case tuple_size(IP) of 4 -> [{tos, Ecn}]; 8 -> [{tclass, Ecn}] end,
    _ = case gen_udp:send(Sock, Dest, Anc, Bin) of
        ok -> ok;
        {error, _} -> gen_udp:send(Sock, IP, Port, Bin)
    end,
    ok.

%% Test hook (impairment): the filter runs in this process and must not
%% block; a crashing filter lets the datagram through. It returns
%% `{Delay, Bin}' or `{Delay, Bin, Ecn}': a router may mark an ECT
%% datagram CE (RFC 3168), never a not-ECT one.
filtered(Sock, Dest, Bin, Ecn, #st{filter = {F, FS}} = St) ->
    {Out, FS1} =
        try F(Dest, Bin, FS) of
            {O, S1} when is_list(O) -> {O, S1}
        catch
            _:_ -> {[{0, Bin}], FS}
        end,
    lists:foreach(
        fun(Item) ->
            {Delay, B, E} =
                case Item of
                    {D, B0} -> {D, B0, Ecn};
                    {D, B0, Mark} when Ecn =/= 0 -> {D, B0, Mark};
                    {D, B0, _} -> {D, B0, 0}
                end,
            case Delay of
                0 -> udp_send(Sock, Dest, B, E);
                _ -> erlang:send_after(Delay, self(), {delayed_send, Sock, Dest, B, E})
            end
        end,
        Out
    ),
    St#st{filter = {F, FS1}}.

%% Send a datagram on the selected pair.
send_out(Bin, St) ->
    case webrtc_ice_agent:send(Bin, webrtc_transport:now_ms(), St#st.ice) of
        {ok, I1, Acts} -> ice_actions(Acts, io(sent, Bin, St#st{ice = I1}));
        {error, _} -> St
    end.

%% The same with ECT(0) on the datagram sent to the peer (relayed and
%% stream sends go unmarked).
send_out_ect(Bin, St) ->
    case webrtc_ice_agent:send(Bin, webrtc_transport:now_ms(), St#st.ice) of
        {ok, I1, Acts} ->
            ice_actions([case A of {send, Sock, Dest, B} when is_port(Sock) -> {send_ect, Sock, Dest, B}; _ -> A end
                         || A <- Acts], io(sent, Bin, St#st{ice = I1}));
        {error, _} ->
            St
    end.

transmit(Acts, St) ->
    lists:foldl(fun({send, B}, S) -> send_out(B, S);
                   ({send_ect, B}, S) -> send_out_ect(B, S);
                   (_, S) -> S
                end, St, Acts).

%%====================================================================
%% Stream connections to TURN servers (RFC 8656 §3.1)
%%====================================================================

%% Opened from another process so the transport keeps serving packets;
%% the socket is handed over before the result is sent.
connect(Ref, #{transport := ice_tcp, remote := {IP, Port}, local := Local} = P) ->
    Self = self(),
    _ = spawn(fun() -> Self ! {turn_stream, Ref, open(tcp, IP, Port, Local, P, Self)} end),
    ok;
connect(Ref, #{server := {IP, Port}, transport := Kind, local := Local} = P) ->
    Self = self(),
    _ = spawn(fun() -> Self ! {turn_stream, Ref, open(Kind, IP, Port, Local, P, Self)} end),
    ok.

open(Kind, IP, Port, Local, P, Owner) ->
    Tcp = [binary, {active, false}, {nodelay, true}, {ip, Local}],
    case gen_tcp:connect(IP, Port, Tcp, ?CONNECT_TIMEOUT) of
        {ok, S} when Kind =:= tcp ->
            ok = gen_tcp:controlling_process(S, Owner),
            {ok, tcp, S};
        {ok, S} ->
            case ssl:connect(S, tls_options(IP, P), ?CONNECT_TIMEOUT) of
                {ok, T} ->
                    ok = ssl:controlling_process(T, Owner),
                    {ok, tls, T};
                {error, _} = E ->
                    _ = gen_tcp:close(S),
                    E
            end;
        {error, _} = E ->
            E
    end.

%% The server certificate is verified against the system CA store and
%% the configured `hostname' (or the server IP address); `tls_options'
%% replace these defaults.
tls_options(IP, P) ->
    Name =
        case maps:get(hostname, P, undefined) of
            undefined -> inet:ntoa(IP);
            H when is_binary(H) -> binary_to_list(H);
            H -> H
        end,
    Defaults = [
        {verify, verify_peer},
        {cacerts, public_key:cacerts_get()},
        {server_name_indication, Name},
        {customize_hostname_check, [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}
    ],
    User = maps:get(tls_options, P, []),
    User ++ [O || O <- Defaults, not lists:keymember(element(1, O), 1, User)].

%% @doc Result of a connection attempt.
-spec stream_opened({stream, pos_integer()}, {ok, tcp | tls, term()} | {error, term()}, #st{}) -> #st{}.
stream_opened(Ref, {ok, Kind, Sock}, St) ->
    case St#st.finished of
        true ->
            close_sock(Kind, Sock),
            St;
        false ->
            ok = setopts(Kind, Sock, [{active, ?ACTIVE_N}]),
            St1 = St#st{streams = (St#st.streams)#{Ref => conn(Ref, Kind, Sock)}},
            ice(fun(Now, I) -> webrtc_ice_agent:stream_up(Ref, Now, I) end, St1)
    end;
stream_opened(Ref, {error, Reason}, St) ->
    ice(fun(Now, I) -> webrtc_ice_agent:stream_down(Ref, Reason, Now, I) end, St).

%% @doc Bytes read from a stream: every complete message goes to the
%% ICE agent as if it were a datagram from the server.
-spec stream_data(term(), binary(), #st{}) -> #st{}.
stream_data(Sock, Data, St) ->
    case by_sock(Sock, St) of
        {Ref, #{buf := Buf} = C} ->
            case split(Ref, <<Buf/binary, Data/binary>>) of
                {ok, Msgs, Rest} ->
                    St1 = St#st{streams = (St#st.streams)#{Ref := C#{buf := Rest}}},
                    Server = source_of(Ref, C, St1),
                    Now = webrtc_transport:now_ms(),
                    lists:foldl(fun(M, S) -> datagram(Ref, Server, M, Now, S) end, St1, Msgs);
                {error, Reason} ->
                    down(Ref, Reason, close_stream(Ref, St))
            end;
        error ->
            St
    end.

%% @doc The connection closed or failed.
-spec stream_closed(term(), term(), #st{}) -> #st{}.
stream_closed(Sock, Reason, St) ->
    case by_sock(Sock, St) of
        {Ref, _} -> down(Ref, Reason, close_stream(Ref, St));
        error -> St
    end.

-spec stream_passive(term(), #st{}) -> #st{}.
stream_passive(Sock, St) ->
    case by_sock(Sock, St) of
        {_, #{kind := Kind}} -> ok = setopts(Kind, Sock, [{active, ?ACTIVE_N}]), St;
        error -> St
    end.

-spec close_streams(#st{}) -> #st{}.
close_streams(St) ->
    lists:foldl(fun close_stream/2, St, maps:keys(St#st.streams)).

down(Ref, Reason, St) ->
    ice(fun(Now, I) -> webrtc_ice_agent:stream_down(Ref, Reason, Now, I) end, St).

ice(F, St) ->
    {I1, Acts} = F(webrtc_transport:now_ms(), St#st.ice),
    ice_actions(Acts, St#st{ice = I1}).

stream_send({tcp, _} = Ref, Bin, St) when byte_size(Bin) =< 16#FFFF ->
    %% RFC 4571: every packet is preceded by its 16-bit length.
    raw_send(Ref, [<<(byte_size(Bin)):16>>, Bin], St);
stream_send({tcp, _}, _Bin, St) ->
    St;
stream_send(Ref, Bin, St) ->
    raw_send(Ref, Bin, St).

raw_send(Ref, Bin, St) ->
    case maps:find(Ref, St#st.streams) of
        {ok, #{kind := tcp, sock := S}} -> _ = gen_tcp:send(S, Bin), St;
        {ok, #{kind := tls, sock := S}} -> _ = ssl:send(S, Bin), St;
        error -> St
    end.

close_stream(Ref, St) ->
    case maps:take(Ref, St#st.streams) of
        {#{kind := Kind, sock := S}, Streams} ->
            close_sock(Kind, S),
            St#st{streams = Streams};
        error ->
            St
    end.

close_sock(tcp, S) -> _ = gen_tcp:close(S), ok;
close_sock(tls, S) -> _ = ssl:close(S), ok.

setopts(tcp, S, Opts) -> inet:setopts(S, Opts);
setopts(tls, S, Opts) -> ssl:setopts(S, Opts).

by_sock(Sock, #st{streams = Streams}) ->
    case [{Ref, C} || Ref := #{sock := S} = C <- Streams, S =:= Sock] of
        [Found] -> Found;
        [] -> error
    end.

%% Where the messages of a connection come from: the TURN server of a
%% stream, the peer of an ICE-TCP connection.
source_of({tcp, _}, #{peer := Peer}, _St) -> Peer;
source_of(Ref, _C, #st{ice = I}) -> webrtc_ice_agent:stream_server(Ref, I).

conn({tcp, _}, Kind, Sock) ->
    {ok, Peer} = peername(Kind, Sock),
    #{sock => Sock, kind => Kind, buf => <<>>, peer => Peer};
conn(_Ref, Kind, Sock) ->
    #{sock => Sock, kind => Kind, buf => <<>>}.

peername(tcp, S) -> inet:peername(S);
peername(tls, S) -> ssl:peername(S).

split({tcp, _}, Buf) -> rfc4571_split(Buf, []);
split(_Ref, Buf) -> webrtc_turn_stream:split(Buf).

rfc4571_split(<<Len:16, Msg:Len/binary, Rest/binary>>, Acc) -> rfc4571_split(Rest, [Msg | Acc]);
rfc4571_split(Rest, Acc) -> {ok, lists:reverse(Acc), Rest}.

%%====================================================================
%% ICE-TCP listeners (RFC 6544)
%%====================================================================

%% @doc With `ice_tcp', listen on TCP next to every UDP host address;
%% an acceptor process per listener hands accepted sockets over.
-spec tcp_listen(boolean(), #st{}) -> #st{}.
tcp_listen(false, St) ->
    St;
tcp_listen(true, #st{sockets = Socks} = St) ->
    Self = self(),
    Listeners = lists:filtermap(
        fun({_, {IP, _}}) ->
            case gen_tcp:listen(0, [binary, family(IP), {ip, IP}, {active, false}, {backlog, 8}, {nodelay, true}]) of
                {ok, L} ->
                    {ok, {_, Port}} = inet:sockname(L),
                    Ref = make_ref(),
                    _ = spawn_link(fun() -> accept_loop(Ref, L, Self) end),
                    {true, {Ref, L, {IP, Port}}};
                {error, _} ->
                    false
            end
        end,
        Socks
    ),
    St#st{tcp_listeners = Listeners}.

accept_loop(Ref, L, Owner) ->
    case gen_tcp:accept(L) of
        {ok, S} ->
            _ =
                case gen_tcp:controlling_process(S, Owner) of
                    ok -> Owner ! {ice_tcp_accept, Ref, S};
                    {error, _} -> gen_tcp:close(S)
                end,
            accept_loop(Ref, L, Owner);
        {error, closed} ->
            ok;
        {error, _} ->
            accept_loop(Ref, L, Owner)
    end.

%% @doc The peer connected to an ICE-TCP listener.
-spec tcp_accepted(reference(), term(), #st{}) -> #st{}.
tcp_accepted(ListenRef, Sock, #st{finished = true} = St) ->
    _ = {ListenRef, gen_tcp:close(Sock)},
    St;
tcp_accepted(ListenRef, Sock, St) ->
    case inet:peername(Sock) of
        {ok, Peer} ->
            Ref = {tcp, {in, St#st.next_accept}},
            ok = inet:setopts(Sock, [{active, ?ACTIVE_N}]),
            St1 = St#st{
                next_accept = St#st.next_accept + 1,
                streams = (St#st.streams)#{Ref => #{sock => Sock, kind => tcp, buf => <<>>, peer => Peer}}
            },
            ice(fun(Now, I) -> webrtc_ice_agent:tcp_accepted(Ref, ListenRef, Peer, Now, I) end, St1);
        {error, _} ->
            _ = gen_tcp:close(Sock),
            St
    end.
