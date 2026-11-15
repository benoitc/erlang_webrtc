%% @private Transports of a session description (RFC 9143, RFC 9429
%% §5.2.1, §5.3.1): every BUNDLE group shares one transport, named by
%% its tag (the first of its mids), and every active m= section outside
%% the groups has its own, named by its mid. Takes the description as
%% `webrtc_jsep:bundle_view/1' gives it, so bundle-only sections count
%% as active.
-module(webrtc_jsep_transport).

-include("webrtc_sdp.hrl").

-export([groups/1, key_of/2, bundles/1]).

-export_type([group/0]).

%% {Key, Mids, Bundled}: `Bundled' for a BUNDLE group (an a=group line),
%% false for a section on its own.
-type group() :: {binary(), [binary()], boolean()}.

%% @doc Transports in m= line order of their first section.
-spec groups(#sdp{}) -> [group()].
groups(#sdp{media = Media} = Sdp) ->
    Order = [webrtc_sdp_media:mid(M) || M <- Media],
    Active = [webrtc_sdp_media:mid(M) || M <- Media, M#sdp_media.port =/= 0, webrtc_sdp_media:mid(M) =/= undefined],
    Bundles = [
        [Mid || Mid <- G, lists:member(Mid, Active)]
     || G <- webrtc_sdp_media:groups(<<"BUNDLE">>, Sdp)
    ],
    Grouped = [G || G <- Bundles, G =/= []],
    InGroups = lists:append(Grouped),
    All = [{hd(G), G, true} || G <- Grouped] ++
        [{Mid, [Mid], false} || Mid <- Active, not lists:member(Mid, InGroups)],
    Pos = fun({_, Ms, _}) -> lists:min([index(M, Order) || M <- Ms]) end,
    lists:sort(fun(A, B) -> Pos(A) =< Pos(B) end, All).

%% @doc The transport of `Mid', or `undefined' when it has none.
-spec key_of(binary() | undefined, [group()]) -> binary() | undefined.
key_of(Mid, Groups) ->
    case [K || {K, Ms, _} <- Groups, lists:member(Mid, Ms)] of
        [K | _] -> K;
        [] -> undefined
    end.

%% @doc The mids of the BUNDLE groups, for a=group lines.
-spec bundles([group()]) -> [[binary()]].
bundles(Groups) ->
    [Ms || {_, Ms, true} <- Groups].

index(X, L) -> index(X, L, 1).
index(_, [], N) -> N;
index(X, [X | _], N) -> N;
index(X, [_ | T], N) -> index(X, T, N + 1).
