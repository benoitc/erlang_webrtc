%% @private Top-level supervisor. Peer connections are started under
%% `webrtc_pc_sup' and are independent of each other. The supervisor
%% owns the `webrtc_transports' table: `{PeerConnection, Transport}'
%% and the DTLS session ticket table (`webrtc_dtls_tickets')
%% rows that let the API reach a transport without a call to its peer
%% connection.
-module(webrtc_sup).
-behaviour(supervisor).
-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    webrtc_transports = ets:new(webrtc_transports, [set, public, named_table, {read_concurrency, true}]),
    %% DTLS 1.3 session tickets (client cache, 0-RTT anti-replay).
    ok = webrtc_dtls_tickets:ensure(),
    Children = [
        #{
            id => webrtc_pc_sup,
            start => {webrtc_pc_sup, start_link, []},
            type => supervisor
        }
    ],
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, Children}}.
