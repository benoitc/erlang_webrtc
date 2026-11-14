%% @private Dynamic supervisor for peer connections. Each child is one
%% `webrtc_pc' process; a crash of one peer connection does not affect
%% the others.
-module(webrtc_pc_sup).
-behaviour(supervisor).
-export([start_link/0, start_child/1, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_child(Args) ->
    supervisor:start_child(?MODULE, [Args]).

init([]) ->
    Child = #{
        id => webrtc_pc,
        start => {webrtc_pc, start_link, []},
        restart => temporary,
        shutdown => 5000
    },
    {ok, {#{strategy => simple_one_for_one, intensity => 100, period => 1}, [Child]}}.
