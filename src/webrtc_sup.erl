%% @private Top-level supervisor. Peer connections are started under
%% `webrtc_pc_sup' and are independent of each other. `webrtc_registry'
%% owns the `webrtc_transports' table (`{PeerConnection, Transport}'
%% rows that let the API reach a transport without a call to its peer
%% connection); the supervisor owns the DTLS session ticket table
%% (`webrtc_dtls_tickets').
-module(webrtc_sup).
-behaviour(supervisor).
-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    %% DTLS 1.3 session tickets (client cache, 0-RTT anti-replay).
    ok = webrtc_dtls_tickets:ensure(),
    %% Host addresses found public among mDNS-hidden candidates.
    ok = webrtc_mdns_public:ensure(),
    Children = [
        %% Owns webrtc_transports and removes the rows of a peer
        %% connection when it ends.
        #{id => webrtc_registry, start => {webrtc_registry, start_link, []}},
        #{
            id => webrtc_pc_sup,
            start => {webrtc_pc_sup, start_link, []},
            type => supervisor
        }
    ],
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, Children}}.
