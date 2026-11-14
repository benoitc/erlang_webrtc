%% @doc ICE candidates: priorities, foundations, pair priorities,
%% redundancy elimination and the RFC 8839 candidate-attribute syntax.
%%
%% Candidates are `#ice_cand{}' records (include/webrtc_ice.hrl).
%%
%% <ul>
%% <li>`priority/3' is the RFC 8445 §5.1.2.1 formula with the
%%     recommended type preferences of §5.1.2.2.</li>
%% <li>`local_preferences/1' orders the host addresses of a multihomed or
%%     dual-stack agent as RFC 8421 recommends (IPv6 first, then IPv4 and
%%     IPv6 intermingled) and gives each one a unique local preference.
%%     Derived candidates (server-reflexive, relayed) use
%%     `local_preference/2' so that different servers keep unique
%%     values.</li>
%% <li>`foundation/4' implements §5.1.1.3: equal type, base IP, server IP
%%     and transport give equal foundations.</li>
%% <li>`pair_priority/2' is the 64-bit §6.1.2.3 formula.</li>
%% <li>`to_sdp/1' and `from_sdp/1' encode and parse the value of an
%%     `a=candidate' attribute (RFC 8839 §5.1), as used by trickle ICE
%%     signaling.</li>
%% </ul>
-module(webrtc_ice_candidate).

-include("webrtc_ice.hrl").

-export([
    type_preference/1,
    priority/3,
    local_preference/2,
    local_preferences/1,
    foundation/4,
    pair_priority/2,
    pair_priority/3,
    eliminate_redundant/1,
    is_redundant/2,
    transport_address/1,
    family/1,
    is_link_local/1,
    can_pair/2,
    to_sdp/1,
    from_sdp/1,
    valid_ufrag/1,
    valid_pwd/1,
    random_ufrag/0,
    random_pwd/0
]).

-export_type([type/0, role/0, address/0]).

-type type() :: host | srflx | prflx | relay.
-type role() :: controlling | controlled.
-type address() :: {inet:ip_address(), inet:port_number()}.

%% Local preference spacing between host candidates; leaves room for
%% up to 8 STUN or TURN servers per host candidate.
-define(LP_STEP, 8).
-define(LP_MAX, 65535).

%%====================================================================
%% Priorities
%%====================================================================

-spec type_preference(type()) -> 0..126.
type_preference(host) -> ?ICE_TYPE_PREF_HOST;
type_preference(prflx) -> ?ICE_TYPE_PREF_PRFLX;
type_preference(srflx) -> ?ICE_TYPE_PREF_SRFLX;
type_preference(relay) -> ?ICE_TYPE_PREF_RELAY.

%% @doc RFC 8445 §5.1.2.1: (2^24)*type pref + (2^8)*local pref +
%% (256 - component).
-spec priority(type(), 0..65535, 1..256) -> 1..16#7FFFFFFF.
priority(Type, LocalPref, Component) when
    LocalPref >= 0, LocalPref =< 65535, Component >= 1, Component =< 256
->
    (type_preference(Type) bsl 24) + (LocalPref bsl 8) + (256 - Component).

%% @doc Local preference for the host candidate of rank `Rank' (0 is
%% the most preferred) and the server of index `ServerIdx' (0 for the
%% host candidate itself).
-spec local_preference(non_neg_integer(), 0..7) -> 0..65535.
local_preference(Rank, ServerIdx) when ServerIdx >= 0, ServerIdx < ?LP_STEP ->
    max(0, ?LP_MAX - Rank * ?LP_STEP - ServerIdx).

%% @doc Order host IP addresses as recommended by RFC 8421 §4 and give
%% each one a unique local preference. IPv6 addresses get a head start
%% of (N4 + N6) div N4 positions, then the families alternate. The
%% relative order within a family is kept, so callers list their
%% preferred interface first.
-spec local_preferences([inet:ip_address()]) -> [{inet:ip_address(), 0..65535}].
local_preferences(IPs) ->
    {V6, V4} = lists:partition(fun(IP) -> family(IP) =:= ipv6 end, IPs),
    Ordered = intermingle(V6, V4),
    lists:zip(Ordered, [local_preference(R, 0) || R <- lists:seq(0, length(Ordered) - 1)]).

intermingle(V6, []) ->
    V6;
intermingle([], V4) ->
    V4;
intermingle(V6, V4) ->
    Head = (length(V6) + length(V4)) div length(V4),
    {First, Rest6} = take(Head, V6),
    First ++ alternate(V4, Rest6).

take(N, L) when length(L) =< N -> {L, []};
take(N, L) -> lists:split(N, L).

alternate([A | As], [B | Bs]) -> [A, B | alternate(As, Bs)];
alternate(As, []) -> As;
alternate([], Bs) -> Bs.

%% @doc RFC 8445 §5.1.1.3 foundation. `ServerIP' is the IP address used
%% to reach the STUN or TURN server, `undefined' for host and
%% peer-reflexive candidates.
-spec foundation(type(), inet:ip_address(), inet:ip_address() | undefined, udp | tcp) ->
    binary().
foundation(Type, BaseIP, ServerIP, Transport) ->
    <<N:32, _/binary>> = crypto:hash(sha256, term_to_binary({Type, BaseIP, ServerIP, Transport})),
    integer_to_binary(N).

%% @doc RFC 8445 §6.1.2.3: 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0) where
%% G is the priority of the controlling agent's candidate.
-spec pair_priority(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
pair_priority(G, D) ->
    (min(G, D) bsl 32) + 2 * max(G, D) +
        case G > D of
            true -> 1;
            false -> 0
        end.

-spec pair_priority(non_neg_integer(), non_neg_integer(), role()) -> non_neg_integer().
pair_priority(Local, Remote, controlling) -> pair_priority(Local, Remote);
pair_priority(Local, Remote, controlled) -> pair_priority(Remote, Local).

%%====================================================================
%% Redundancy (RFC 8445 §5.1.3)
%%====================================================================

%% @doc A candidate is redundant if its transport address and base equal
%% those of another candidate; the one with the lower priority goes.
-spec eliminate_redundant([#ice_cand{}]) -> [#ice_cand{}].
eliminate_redundant(Cands) ->
    Sorted = lists:sort(fun(A, B) -> A#ice_cand.priority >= B#ice_cand.priority end, Cands),
    lists:reverse(
        lists:foldl(
            fun(C, Kept) ->
                case is_redundant(C, Kept) of
                    true -> Kept;
                    false -> [C | Kept]
                end
            end,
            [],
            Sorted
        )
    ).

%% @doc True when `Cand' has the same transport address, base and
%% component as one of `Others'.
-spec is_redundant(#ice_cand{}, [#ice_cand{}]) -> boolean().
is_redundant(#ice_cand{base = B, component = Co} = C, Others) ->
    Addr = transport_address(C),
    lists:any(
        fun(#ice_cand{base = B2, component = Co2} = O) ->
            Co2 =:= Co andalso B2 =:= B andalso transport_address(O) =:= Addr
        end,
        Others
    ).

-spec transport_address(#ice_cand{}) -> address().
transport_address(#ice_cand{address = A, port = P}) ->
    {A, P}.

-spec family(inet:ip_address()) -> ipv4 | ipv6.
family({_, _, _, _}) -> ipv4;
family({_, _, _, _, _, _, _, _}) -> ipv6.

-spec is_link_local(inet:ip_address()) -> boolean().
is_link_local({169, 254, _, _}) -> true;
is_link_local({A, _, _, _, _, _, _, _}) -> A band 16#FFC0 =:= 16#FE80;
is_link_local(_) -> false.

%% @doc RFC 8445 §6.1.2.2: same component, same address family, same
%% transport, and IPv6 link-local only with link-local.
-spec can_pair(#ice_cand{}, #ice_cand{}) -> boolean().
can_pair(#ice_cand{} = L, #ice_cand{} = R) ->
    L#ice_cand.component =:= R#ice_cand.component andalso
        L#ice_cand.transport =:= R#ice_cand.transport andalso
        family(L#ice_cand.address) =:= family(R#ice_cand.address) andalso
        (family(L#ice_cand.address) =:= ipv4 orelse
            is_link_local(L#ice_cand.address) =:= is_link_local(R#ice_cand.address)).

%%====================================================================
%% SDP candidate-attribute (RFC 8839 §5.1)
%%====================================================================

%% @doc Encode the value of an `a=candidate' attribute, prefixed with
%% `candidate:'.
-spec to_sdp(#ice_cand{}) -> binary().
to_sdp(#ice_cand{} = C) ->
    Rel =
        case C#ice_cand.related_address of
            undefined ->
                [];
            RA ->
                [<<" raddr ">>, ip_bin(RA), <<" rport ">>, integer_to_binary(C#ice_cand.related_port)]
        end,
    Tcp =
        case C#ice_cand.tcptype of
            undefined -> [];
            TT -> [<<" tcptype ">>, atom_to_binary(TT)]
        end,
    Ext = [[$\s, K, $\s, V] || {K, V} <- C#ice_cand.extensions],
    iolist_to_binary([
        <<"candidate:">>,
        C#ice_cand.foundation,
        $\s,
        integer_to_binary(C#ice_cand.component),
        $\s,
        string:uppercase(atom_to_binary(C#ice_cand.transport)),
        $\s,
        integer_to_binary(C#ice_cand.priority),
        $\s,
        ip_bin(C#ice_cand.address),
        $\s,
        integer_to_binary(C#ice_cand.port),
        <<" typ ">>,
        atom_to_binary(C#ice_cand.type),
        Rel,
        Tcp,
        Ext
    ]).

ip_bin(IP) -> list_to_binary(inet:ntoa(IP)).

%% @doc Parse a candidate attribute value. Accepts an optional `a=' and
%% `candidate:' prefix. Connection addresses must be IP literals; FQDN
%% (including mDNS) candidates are reported as `{error, {fqdn, Name}}'
%% because resolving them is the owner's job.
-spec from_sdp(binary() | string()) -> {ok, #ice_cand{}} | {error, term()}.
from_sdp(Str) when is_list(Str) ->
    from_sdp(unicode:characters_to_binary(Str));
from_sdp(<<"a=", Rest/binary>>) ->
    from_sdp(Rest);
from_sdp(<<"candidate:", Rest/binary>>) ->
    parse(string:trim(Rest));
from_sdp(Bin) when is_binary(Bin) ->
    parse(string:trim(Bin)).

parse(Bin) ->
    try
        parse_fields(binary:split(Bin, [<<" ">>], [global, trim_all]))
    catch
        throw:R -> {error, R}
    end.

parse_fields([F, Comp, Transport, Prio, Addr, Port, <<"typ">>, Type | Ext]) ->
    C0 = #ice_cand{
        foundation = check_foundation(F),
        component = int(Comp, 1, 256),
        transport = transport(Transport),
        priority = int(Prio, 1, 16#7FFFFFFF),
        address = addr(Addr),
        port = int(Port, 0, 65535),
        type = cand_type(Type)
    },
    {ok, extensions(Ext, C0)};
parse_fields(_) ->
    {error, bad_candidate}.

check_foundation(F) when byte_size(F) >= 1, byte_size(F) =< 32 ->
    case lists:all(fun is_ice_char/1, binary_to_list(F)) of
        true -> F;
        false -> throw(bad_foundation)
    end;
check_foundation(_) ->
    throw(bad_foundation).

int(B, Min, Max) ->
    try binary_to_integer(B) of
        N when N >= Min, N =< Max -> N;
        _ -> throw({bad_integer, B})
    catch
        error:badarg -> throw({bad_integer, B})
    end.

transport(T) ->
    case string:lowercase(T) of
        <<"udp">> -> udp;
        <<"tcp">> -> tcp;
        _ -> throw({unsupported_transport, T})
    end.

addr(A) ->
    case inet:parse_strict_address(binary_to_list(A)) of
        {ok, IP} -> IP;
        {error, _} -> throw({fqdn, A})
    end.

cand_type(<<"host">>) -> host;
cand_type(<<"srflx">>) -> srflx;
cand_type(<<"prflx">>) -> prflx;
cand_type(<<"relay">>) -> relay;
cand_type(T) -> throw({bad_type, T}).

extensions([<<"raddr">>, A | Rest], C) ->
    extensions(Rest, C#ice_cand{related_address = addr(A)});
extensions([<<"rport">>, P | Rest], C) ->
    extensions(Rest, C#ice_cand{related_port = int(P, 0, 65535)});
extensions([<<"tcptype">>, T | Rest], C) ->
    TT =
        case T of
            <<"active">> -> active;
            <<"passive">> -> passive;
            <<"so">> -> so;
            _ -> throw({bad_tcptype, T})
        end,
    extensions(Rest, C#ice_cand{tcptype = TT});
extensions([K, V | Rest], #ice_cand{extensions = E} = C) ->
    extensions(Rest, C#ice_cand{extensions = E ++ [{K, V}]});
extensions([], C) ->
    C;
extensions([_], _C) ->
    throw(bad_extension).

%%====================================================================
%% Credentials (RFC 8445 §5.3, RFC 8839 §5.4)
%%====================================================================

%% @doc ice-ufrag: 4 to 256 ice-chars.
-spec valid_ufrag(term()) -> boolean().
valid_ufrag(U) -> valid_chars(U, 4, 256).

%% @doc ice-pwd: 22 to 256 ice-chars.
-spec valid_pwd(term()) -> boolean().
valid_pwd(P) -> valid_chars(P, 22, 256).

valid_chars(B, Min, Max) when is_binary(B), byte_size(B) >= Min, byte_size(B) =< Max ->
    lists:all(fun is_ice_char/1, binary_to_list(B));
valid_chars(_, _, _) ->
    false.

is_ice_char(C) when C >= $a, C =< $z -> true;
is_ice_char(C) when C >= $A, C =< $Z -> true;
is_ice_char(C) when C >= $0, C =< $9 -> true;
is_ice_char($+) -> true;
is_ice_char($/) -> true;
is_ice_char(_) -> false.

%% @doc Random 8 character ufrag (48 bits, RFC 8445 §5.3 asks >= 24).
-spec random_ufrag() -> binary().
random_ufrag() -> random_chars(8).

%% @doc Random 24 character password (144 bits, RFC 8445 §5.3 asks >= 128).
-spec random_pwd() -> binary().
random_pwd() -> random_chars(24).

random_chars(N) ->
    Alphabet = <<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/">>,
    <<<<(binary:at(Alphabet, B band 63))>> || <<B>> <= crypto:strong_rand_bytes(N)>>.
