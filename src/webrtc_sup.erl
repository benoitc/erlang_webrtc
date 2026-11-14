%% @private Top-level supervisor. Peer connections are started under
%% `webrtc_pc_sup' and are independent of each other.
-module(webrtc_sup).
-behaviour(supervisor).
-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Children = [
        #{
            id => webrtc_pc_sup,
            start => {webrtc_pc_sup, start_link, []},
            type => supervisor
        }
    ],
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, Children}}.
