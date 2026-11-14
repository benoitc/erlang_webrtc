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
    local_addresses/1,
    family/1,
    datagram/5,
    ice_actions/2,
    local_candidate/2,
    udp_send/3,
    send_out/2,
    transmit/2
]).

open_socket({IP, Port}) ->
    Family =
        case tuple_size(IP) of
            4 -> inet;
            8 -> inet6
        end,
    case gen_udp:open(Port, [binary, Family, {ip, IP}, {active, ?ACTIVE_N}, {recbuf, 1 bsl 20}, {sndbuf, 1 bsl 20}]) of
        {ok, S} ->
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

datagram(Sock, Src, Bin, Now, St) ->
    case webrtc_demux:classify(Bin) of
        C when C =:= stun; C =:= turn_channel ->
            {I1, Acts} = webrtc_ice_agent:handle_packet(Sock, Src, Bin, Now, St#st.ice),
            ice_actions(Acts, St#st{ice = I1});
        Class ->
            case webrtc_ice_agent:is_valid_remote(Sock, Src, St#st.ice) of
                true -> webrtc_transport:secure_datagram(Class, Bin, Now, St);
                false -> St
            end
    end.

ice_actions(Acts, St) ->
    lists:foldl(fun ice_action/2, St, Acts).

ice_action({send, Sock, {IP, Port}, Bin}, #st{filter = undefined} = St) ->
    _ = gen_udp:send(Sock, IP, Port, Bin),
    St;
ice_action({send, Sock, Dest, Bin}, #st{filter = {F, FS}} = St) ->
    %% Test hook (impairment): it runs in this process and must not
    %% block; a crashing filter lets the datagram through.
    {Out, FS1} =
        try F(Dest, Bin, FS) of
            {O, S1} when is_list(O) -> {O, S1}
        catch
            _:_ -> {[{0, Bin}], FS}
        end,
    lists:foreach(
        fun
            ({0, B}) -> udp_send(Sock, Dest, B);
            ({Delay, B}) -> erlang:send_after(Delay, self(), {delayed_send, Sock, Dest, B})
        end,
        Out
    ),
    St#st{filter = {F, FS1}};
ice_action({event, {data, Via, Peer, Bin}}, St) ->
    %% Relayed non-STUN data: demultiplex as if received from Peer, under
    %% the same rule as direct traffic. TURN permissions are per IP
    %% (RFC 8656 §9), so any port of a permitted host gets through the
    %% relay; only a validated candidate pair may reach DTLS and SRTP
    %% (RFC 8445 §12.2, RFC 8826 §4.2).
    case webrtc_ice_agent:is_valid_remote(Via, Peer, St#st.ice) of
        true -> webrtc_transport:secure_relayed(Peer, Bin, St);
        false -> St
    end;
ice_action({event, {connection_state, S} = E}, St) when S =:= connected; S =:= completed ->
    webrtc_transport:to_pc(E, St),
    webrtc_transport:start_dtls_if_ready(webrtc_transport:flush_dtls(St#st{ice_usable = true}));
ice_action({event, {connection_state, _} = E}, St) ->
    webrtc_transport:to_pc(E, St),
    St#st{ice_usable = false};
ice_action({event, {selected_pair, L, R}}, St) ->
    webrtc_transport:to_pc({selected_pair, L, R}, St),
    webrtc_transport:start_dtls_if_ready(webrtc_transport:flush_dtls(St));
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

udp_send(Sock, {IP, Port}, Bin) ->
    _ = gen_udp:send(Sock, IP, Port, Bin),
    ok.

%% Send a datagram on the selected pair.
send_out(Bin, St) ->
    case webrtc_ice_agent:send(Bin, webrtc_transport:now_ms(), St#st.ice) of
        {ok, I1, Acts} -> ice_actions(Acts, St#st{ice = I1});
        {error, _} -> St
    end.

transmit(Acts, St) ->
    lists:foldl(fun({send, B}, S) -> send_out(B, S) end, St, [A || {send, _} = A <- Acts]).
