%% Structured SDP (RFC 8866) as used by WebRTC.
%%
%% Field values are kept as binaries unless a typed form helps
%% negotiation. Attributes are `{Key, Value}' pairs in wire order, see
%% `webrtc_sdp:attribute()' for the typed keys.
-ifndef(WEBRTC_SDP_HRL).
-define(WEBRTC_SDP_HRL, true).

%% o= (RFC 8866 §5.2)
-record(sdp_origin, {
    username = <<"-">> :: binary(),
    sess_id = 0 :: non_neg_integer(),
    sess_version = 0 :: non_neg_integer(),
    nettype = <<"IN">> :: binary(),
    addrtype = <<"IP4">> :: binary(),
    %% unicast-address, as written (IPv4, IPv6 or FQDN)
    address = <<"127.0.0.1">> :: binary()
}).

%% c= (RFC 8866 §5.7). The address keeps any multicast /ttl/numaddr
%% suffix as written.
-record(sdp_connection, {
    nettype = <<"IN">> :: binary(),
    addrtype = <<"IP4">> :: binary(),
    address = <<"0.0.0.0">> :: binary()
}).

%% t= with its r= lines and the z= line that follows them
%% (RFC 8866 §5.9 to §5.11).
-record(sdp_time, {
    start = 0 :: non_neg_integer(),
    stop = 0 :: non_neg_integer(),
    %% each r= line as its fields, for example [<<"7d">>, <<"1h">>, <<"0">>]
    repeats = [] :: [[binary(), ...]],
    %% z= adjustments as {Time, Offset}, Offset like <<"-1h">>
    zones = [] :: [{non_neg_integer(), binary()}]
}).

%% m= section (RFC 8866 §5.14) and the lines that follow it.
-record(sdp_media, {
    %% <<"audio">>, <<"video">>, <<"application">>, ...
    media = <<"audio">> :: binary(),
    port = 9 :: inet:port_number(),
    port_count :: pos_integer() | undefined,
    %% <<"UDP/TLS/RTP/SAVPF">>, <<"UDP/DTLS/SCTP">>, ...
    proto = <<"UDP/TLS/RTP/SAVPF">> :: binary(),
    %% payload types for RTP, <<"webrtc-datachannel">> for SCTP
    fmts = [] :: [binary()],
    information :: binary() | undefined,
    connections = [] :: [#sdp_connection{}],
    %% b= lines as {BwType, Value}, for example {<<"AS">>, 64}
    bandwidths = [] :: [{binary(), non_neg_integer()}],
    key :: binary() | undefined,
    attributes = [] :: [webrtc_sdp:attribute()]
}).

-record(sdp, {
    version = 0 :: non_neg_integer(),
    origin = #sdp_origin{} :: #sdp_origin{},
    session_name = <<"-">> :: binary(),
    information :: binary() | undefined,
    uri :: binary() | undefined,
    emails = [] :: [binary()],
    phones = [] :: [binary()],
    connection :: #sdp_connection{} | undefined,
    bandwidths = [] :: [{binary(), non_neg_integer()}],
    times = [#sdp_time{}] :: [#sdp_time{}, ...],
    key :: binary() | undefined,
    attributes = [] :: [webrtc_sdp:attribute()],
    media = [] :: [#sdp_media{}]
}).

%% candidate attribute value (RFC 8839 §5.1, RFC 6544 tcptype).
-record(sdp_candidate, {
    foundation :: binary(),
    component = 1 :: 1..256,
    %% as written, compare case-insensitively (<<"udp">>, <<"UDP">>, <<"tcp">>)
    transport = <<"udp">> :: binary(),
    priority :: 1..2147483647,
    address :: webrtc_sdp_lex:address(),
    port :: inet:port_number(),
    type = host :: host | srflx | prflx | relay | binary(),
    raddr :: webrtc_sdp_lex:address() | undefined,
    rport :: inet:port_number() | undefined,
    tcptype :: active | passive | so | undefined,
    %% remaining extension attributes in order, for example
    %% [{<<"generation">>, <<"0">>}, {<<"network-id">>, <<"1">>}]
    extensions = [] :: [{binary(), binary()}]
}).

-endif.
