%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private Host name candidates, on the transport side.
%%
%% Remote candidates whose address is a name wait here, bounded, while a
%% `webrtc_mdns' process resolves the name; then the candidate goes to
%% the ICE agent with the resolved address and its other fields
%% unchanged. A name that does not resolve drops its candidate only.
%% <ul>
%% <li>A `<uuid>.local' name (version 4 UUID,
%%     draft-ietf-mmusic-mdns-ice-candidates-03 §3.1.1) is resolved with
%%     multicast DNS (§3.2.1). It must resolve to exactly one address
%%     (§3.2.2). The candidate is marked with the `?ICE_EXT_MDNS'
%%     extension so that the agent never pairs it with a relayed local
%%     candidate (§3.3.2).</li>
%% <li>Other single-label `.local' names are not resolved and the
%%     candidate is ignored (§3.2.2).</li>
%% <li>Other names are DNS names (RFC 8839 §5.1): of the addresses, the
%%     first IPv6 one is used when the transport has an IPv6 socket,
%%     otherwise the first IPv4 one.</li>
%% </ul>
%% End-of-candidates is held back until no candidate is pending, so the
%% late ones are not ignored (RFC 8838 §14).
%%
%% With `hide_host' (option `mdns_host_candidates'), our host candidates
%% are signaled with a `<uuid>.local' name answered by the same process
%% (draft §3.1.1), and the related address of other candidates becomes
%% `0.0.0.0' or `::' port 9 (§3.1.2.2), so the host address is not
%% revealed.
%%
%% A server-reflexive candidate whose address is the one of its hidden
%% host shows that address is public (§3.1.2.2). It is remembered for
%% the current STUN servers (`webrtc_mdns_public') and, with
%% `expose_public' (default true), later gatherings signal it as it is.
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
    expose_public :: boolean(),
    stun :: [term()],
    pid :: undefined | pid(),
    mon :: undefined | reference(),
    pending = #{} :: #{reference() => {mdns | fqdn, #sdp_candidate{}}},
    eoc = false :: boolean()
}).

-opaque client() :: #c{}.

%% @doc `Opts' is the transport's `mdns' option map (passed to
%% `webrtc_mdns:start/1') plus `max_pending' (default 32) and
%% `hide_host', `expose_public' (default true) and `stun_servers'.
%% `Families' are those of the transport's sockets.
-spec new(map(), [inet | inet6]) -> client().
new(Opts, Families) ->
    #c{
        opts = maps:without([max_pending, hide_host, expose_public, stun_servers], Opts),
        families = Families,
        max_pending = maps:get(max_pending, Opts, 32),
        hide_host = maps:get(hide_host, Opts, false),
        expose_public = maps:get(expose_public, Opts, true),
        stun = maps:get(stun_servers, Opts, [])
    }.

%% @doc Classify a remote candidate. `{add, Value}': give it to the ICE
%% agent now; `pending': its name is being resolved; `ignored': not
%% usable.
-spec remote_candidate(#sdp_candidate{} | binary(), client()) ->
    {add, binary(), client()} | {pending | ignored, client()} | {error, term(), client()}.
remote_candidate(Bin, C) when is_binary(Bin) ->
    case webrtc_sdp_candidate:parse(Bin) of
        {ok, Cand} -> remote_candidate(Cand, C);
        %% Let the ICE agent report the error.
        {error, _} -> {add, Bin, C}
    end;
remote_candidate(#sdp_candidate{address = A, extensions = Exts} = Cand0, C) ->
    %% A related address that is a name is informational only: drop it.
    %% The mDNS mark is ours to set, never the peer's.
    Cand1 = Cand0#sdp_candidate{extensions = lists:keydelete(?ICE_EXT_MDNS, 1, Exts)},
    Cand =
        case Cand1#sdp_candidate.raddr of
            R when is_binary(R) -> Cand1#sdp_candidate{raddr = undefined, rport = undefined};
            _ -> Cand1
        end,
    case name_kind(A) of
        ip -> {add, webrtc_sdp_candidate:encode(Cand), C};
        ignored -> {ignored, C};
        _ when map_size(C#c.pending) >= C#c.max_pending -> {error, too_many_pending, C};
        Kind -> resolve(Kind, A, Cand, C)
    end.

name_kind(A) when not is_binary(A) ->
    ip;
name_kind(A) ->
    UUID = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.local\\.?$",
    case re:run(A, UUID, [caseless, {capture, none}]) of
        match ->
            mdns;
        nomatch ->
            case binary:split(webrtc_sdp_lex:lower(A), <<".">>, [global, trim]) of
                [_, <<"local">>] -> ignored;
                _ -> fqdn
            end
    end.

resolve(Kind, Name, Cand, C0) ->
    case ensure(C0) of
        {ok, #c{pid = Pid} = C} ->
            Ref = webrtc_mdns:resolve(Pid, Name),
            {pending, C#c{pending = (C#c.pending)#{Ref => {Kind, Cand}}}};
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
    {{Kind, Cand}, P1} = maps:take(Ref, P),
    Values =
        case {Kind, Result} of
            {mdns, {ok, [IP]}} ->
                Marked = Cand#sdp_candidate.extensions ++ [{?ICE_EXT_MDNS, Cand#sdp_candidate.address}],
                usable([IP], Cand#sdp_candidate{extensions = Marked}, C);
            {fqdn, {ok, IPs}} ->
                usable(IPs, Cand, C);
            _ ->
                []
        end,
    done(Values, C#c{pending = P1});
handle_info({'DOWN', Mon, process, _, _}, #c{mon = Mon} = C) ->
    done([], C#c{pid = undefined, mon = undefined, pending = #{}});
handle_info(_, _) ->
    ignore.

done(Values, C0) ->
    case idle(C0) of
        #c{eoc = true, pending = P} = C when map_size(P) =:= 0 -> {ok, Values, true, C#c{eoc = false}};
        C -> {ok, Values, false, C}
    end.

%% Nothing left to resolve and no name of ours to answer: stop the
%% resolver, so its group socket does not keep receiving the link's
%% mDNS traffic. The next name starts a new one.
idle(#c{pending = P, hide_host = false, pid = Pid} = C) when map_size(P) =:= 0, Pid =/= undefined ->
    ok = stop(C),
    C#c{pid = undefined, mon = undefined};
idle(C) ->
    C.

usable(IPs, Cand, C) ->
    case choose(IPs, C#c.families) of
        {ok, IP} -> [webrtc_sdp_candidate:encode(Cand#sdp_candidate{address = IP})];
        error -> []
    end.

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
local_candidate(#ice_cand{type = host, address = IP} = Ice, #c{expose_public = true, stun = [_ | _] = Stun} = C0)
  when is_tuple(IP) ->
    case webrtc_mdns_public:is_public(IP, Stun) of
        true -> {webrtc_ice_candidate:to_sdp(Ice), C0};
        false -> hide(Ice, C0)
    end;
local_candidate(#ice_cand{type = host} = Ice, C) ->
    hide(Ice, C);
local_candidate(#ice_cand{type = srflx, address = IP, related_address = IP} = Ice, #c{stun = Stun} = C) ->
    ok = webrtc_mdns_public:learn(IP, Stun),
    any_related(Ice, C);
local_candidate(Ice, C) ->
    any_related(Ice, C).

hide(#ice_cand{address = IP} = Ice, C0) ->
    Value = webrtc_ice_candidate:to_sdp(Ice),
    case ensure(C0) of
        {ok, #c{pid = Pid} = C} ->
            case webrtc_mdns:register_name(Pid, IP) of
                {ok, Name} -> {with_address(Value, Name), C};
                {error, _} -> {Value, C}
            end;
        {error, _} ->
            {Value, C0}
    end.

any_related(#ice_cand{related_address = RA} = Ice, C) when RA =/= undefined ->
    Any =
        case tuple_size(RA) of
            4 -> {0, 0, 0, 0};
            8 -> {0, 0, 0, 0, 0, 0, 0, 0}
        end,
    {webrtc_ice_candidate:to_sdp(Ice#ice_cand{related_address = Any, related_port = 9}), C};
any_related(Ice, C) ->
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
