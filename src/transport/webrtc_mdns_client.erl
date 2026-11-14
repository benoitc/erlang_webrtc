%% @private Host name candidates, on the transport side.
%%
%% Remote candidates whose address is a name (an mDNS `<uuid>.local'
%% name, draft-ietf-mmusic-mdns-ice-candidates §3.2, or another FQDN,
%% RFC 8839 §5.1) wait here, bounded, while a `webrtc_mdns' process
%% resolves the name. When it resolves, the candidate is given to the
%% ICE agent with the resolved address and its other fields unchanged.
%% Of several addresses the first IPv6 one is used when the transport
%% has an IPv6 socket, otherwise the first IPv4 one (draft §3.2,
%% RFC 8839 §5.1). A name that does not resolve drops its candidate
%% only. End-of-candidates is held back until no candidate is pending,
%% so the late ones are not ignored (RFC 8838 §14).
%%
%% With `hide_host' (option `mdns_host_candidates'), our host candidates
%% are signaled with a `<uuid>.local' name answered by the same process
%% (draft §3.1), and the related address of server-reflexive candidates
%% becomes the unspecified address, port 0 (draft §3.1), so the host
%% address is not revealed.
-module(webrtc_mdns_client).

-include("webrtc_ice.hrl").
-include("webrtc_sdp.hrl").

-export([new/2, remote_candidate/2, end_of_candidates/1, handle_info/2, restart/1, local_candidate/2, stop/1]).

-export_type([client/0]).

-record(c, {
    opts :: map(),
    families :: [inet | inet6],
    max_pending :: pos_integer(),
    hide_host :: boolean(),
    pid :: undefined | pid(),
    mon :: undefined | reference(),
    pending = #{} :: #{reference() => #sdp_candidate{}},
    eoc = false :: boolean()
}).

-opaque client() :: #c{}.

%% @doc `Opts' is the transport's `mdns' option map (passed to
%% `webrtc_mdns:start/1') plus `max_pending' (default 32) and
%% `hide_host'. `Families' are those of the transport's sockets.
-spec new(map(), [inet | inet6]) -> client().
new(Opts, Families) ->
    #c{
        opts = maps:without([max_pending, hide_host], Opts),
        families = Families,
        max_pending = maps:get(max_pending, Opts, 32),
        hide_host = maps:get(hide_host, Opts, false)
    }.

%% @doc Classify a remote candidate. `{add, Value}': give it to the ICE
%% agent now; `pending': its name is being resolved.
-spec remote_candidate(#sdp_candidate{} | binary(), client()) ->
    {add, binary(), client()} | {pending, client()} | {error, term(), client()}.
remote_candidate(Bin, C) when is_binary(Bin) ->
    case webrtc_sdp_candidate:parse(Bin) of
        {ok, Cand} -> remote_candidate(Cand, C);
        %% Let the ICE agent report the error.
        {error, _} -> {add, Bin, C}
    end;
remote_candidate(#sdp_candidate{address = A} = Cand0, C) ->
    %% A related address that is a name is informational only: drop it.
    Cand =
        case Cand0#sdp_candidate.raddr of
            R when is_binary(R) -> Cand0#sdp_candidate{raddr = undefined, rport = undefined};
            _ -> Cand0
        end,
    case is_binary(A) of
        false -> {add, webrtc_sdp_candidate:encode(Cand), C};
        true when map_size(C#c.pending) >= C#c.max_pending -> {error, too_many_pending, C};
        true -> resolve(A, Cand, C)
    end.

resolve(Name, Cand, C0) ->
    case ensure(C0) of
        {ok, #c{pid = Pid} = C} ->
            Ref = webrtc_mdns:resolve(Pid, Name),
            {pending, C#c{pending = (C#c.pending)#{Ref => Cand}}};
        {error, R} ->
            {error, R, C0}
    end.

ensure(#c{pid = undefined, opts = Opts} = C) ->
    case webrtc_mdns:start(Opts) of
        {ok, Pid} -> {ok, C#c{pid = Pid, mon = monitor(process, Pid)}};
        {error, _} = E -> E
    end;
ensure(C) ->
    {ok, C}.

%% @doc `now' when the ICE agent can be told, `deferred' while
%% candidates are pending.
-spec end_of_candidates(client()) -> {now | deferred, client()}.
end_of_candidates(#c{pending = P} = C) when map_size(P) =:= 0 -> {now, C};
end_of_candidates(C) -> {deferred, C#c{eoc = true}}.

%% @doc Handle a message from the resolver. Returns the candidates to
%% add and whether end-of-candidates is due now.
-spec handle_info(term(), client()) -> {ok, [binary()], boolean(), client()} | ignore.
handle_info({webrtc_mdns, Ref, Result}, #c{pending = P} = C) when is_map_key(Ref, P) ->
    {Cand, P1} = maps:take(Ref, P),
    Values =
        case Result of
            {ok, IPs} ->
                case choose(IPs, C#c.families) of
                    {ok, IP} -> [webrtc_sdp_candidate:encode(Cand#sdp_candidate{address = IP})];
                    error -> []
                end;
            {error, _} ->
                []
        end,
    done(Values, C#c{pending = P1});
handle_info({'DOWN', Mon, process, _, _}, #c{mon = Mon} = C) ->
    done([], C#c{pid = undefined, mon = undefined, pending = #{}});
handle_info(_, _) ->
    ignore.

done(Values, #c{eoc = true, pending = P} = C) when map_size(P) =:= 0 ->
    {ok, Values, true, C#c{eoc = false}};
done(Values, C) ->
    {ok, Values, false, C}.

choose(IPs, Families) ->
    V6 = [IP || IP <- IPs, tuple_size(IP) =:= 8],
    V4 = [IP || IP <- IPs, tuple_size(IP) =:= 4],
    case {lists:member(inet6, Families) andalso V6, lists:member(inet, Families) andalso V4} of
        {[IP | _], _} -> {ok, IP};
        {_, [IP | _]} -> {ok, IP};
        _ -> error
    end.

%% @doc An ICE restart: candidates of the previous generation still
%% resolving are dropped.
-spec restart(client()) -> client().
restart(C) ->
    C#c{pending = #{}, eoc = false}.

%% @doc The value to signal for a local candidate.
-spec local_candidate(#ice_cand{}, client()) -> {binary(), client()}.
local_candidate(Ice, #c{hide_host = false} = C) ->
    {webrtc_ice_candidate:to_sdp(Ice), C};
local_candidate(#ice_cand{type = host, address = IP} = Ice, C0) ->
    Value = webrtc_ice_candidate:to_sdp(Ice),
    case ensure(C0) of
        {ok, #c{pid = Pid} = C} ->
            case webrtc_mdns:register_name(Pid, IP) of
                {ok, Name} -> {with_address(Value, Name), C};
                {error, _} -> {Value, C}
            end;
        {error, _} ->
            {Value, C0}
    end;
local_candidate(#ice_cand{related_address = RA} = Ice, C) when RA =/= undefined ->
    Any =
        case tuple_size(RA) of
            4 -> {0, 0, 0, 0};
            8 -> {0, 0, 0, 0, 0, 0, 0, 0}
        end,
    {webrtc_ice_candidate:to_sdp(Ice#ice_cand{related_address = Any, related_port = 0}), C};
local_candidate(Ice, C) ->
    {webrtc_ice_candidate:to_sdp(Ice), C}.

with_address(Value, Name) ->
    {ok, S} = webrtc_sdp_candidate:parse(Value),
    webrtc_sdp_candidate:encode_attr(S#sdp_candidate{address = Name}).

-spec stop(client()) -> ok.
stop(#c{pid = undefined}) ->
    ok;
stop(#c{pid = Pid, mon = Mon}) ->
    demonitor(Mon, [flush]),
    webrtc_mdns:stop_async(Pid).
