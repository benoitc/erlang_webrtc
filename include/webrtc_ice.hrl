%% ICE candidate representation (RFC 8445 §5, RFC 8839 §5.1).
-ifndef(WEBRTC_ICE_HRL).
-define(WEBRTC_ICE_HRL, true).

%% Extension marking a remote candidate whose address was resolved from
%% an mDNS name; it is never paired with a relayed local candidate
%% (draft-ietf-mmusic-mdns-ice-candidates-03 §3.3.2). Set by the
%% transport, stripped from what peers send.
-define(ICE_EXT_MDNS, <<"x-mdns-name">>).

%% Type preferences (RFC 8445 §5.1.2.2).
-define(ICE_TYPE_PREF_HOST, 126).
-define(ICE_TYPE_PREF_PRFLX, 110).
-define(ICE_TYPE_PREF_SRFLX, 100).
-define(ICE_TYPE_PREF_RELAY, 0).

-record(ice_cand, {
    foundation :: binary(),
    component = 1 :: 1..256,
    transport = udp :: udp | tcp,
    priority :: 1..16#7FFFFFFF,
    address :: inet:ip_address(),
    port :: inet:port_number(),
    type :: host | srflx | prflx | relay,
    related_address :: inet:ip_address() | undefined,
    related_port :: inet:port_number() | undefined,
    %% Only meaningful for TCP candidates (RFC 6544); unused for UDP.
    tcptype :: active | passive | so | undefined,
    %% Remaining candidate-attribute extensions, e.g. generation.
    extensions = [] :: [{binary(), binary()}],
    %% Local candidates only: the base transport address (RFC 8445 §4),
    %% the owner's socket the candidate sends through and the STUN or
    %% TURN server it was obtained from. Remote candidates leave these
    %% undefined.
    base :: {inet:ip_address(), inet:port_number()} | undefined,
    socket :: term(),
    server :: {inet:ip_address(), inet:port_number()} | undefined
}).

-endif.
