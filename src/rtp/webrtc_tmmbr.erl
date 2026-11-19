%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Temporary maximum media stream bit rate limits of one media
%% stream we send (RFC 5104 §3.5.4, §4.2), as a sans-IO state.
%%
%% Each TMMBR tuple `{Owner, Bitrate, Overhead}' is the line
%% `NetRate = Bitrate - 8 x Overhead x PacketRate'. The bounding set is
%% the subset of tuples forming the lower envelope of those lines for
%% packet rates from 0 up to where the envelope meets zero: the most
%% limiting requests (§3.5.4.2, computed here with exact rationals).
%%
%% <ul>
%% <li>`request/6' adds or replaces the owner's tuple and recomputes the
%%     set from the previous set and the new tuple (§4.2.2.2): a tuple
%%     outside the set is not kept, its owner asks again after the TMMBN
%%     if it must.</li>
%% <li>`leave/4' removes an owner that sent BYE, `expire/4' the owners
%%     silent for the given time (RFC 3550 §6.3.5).</li>
%% <li>A limit never rises at once: the previous set stays enforced for
%%     the hold-off the caller gives, 2 x RTT + T_dither_max (§4.2.1.2),
%%     so other receivers can answer the TMMBN first. A lower limit
%%     applies immediately.</li>
%% </ul>
-module(webrtc_tmmbr).

-export([
    new/0,
    bounding_set/1,
    net_rate/2,
    request/6,
    leave/4,
    touch/3,
    expire/4,
    set/1,
    enforced/2,
    next_timeout/1,
    handle_timeout/2
]).
-export_type([state/0, tuple_/0]).

-type tuple_() :: {Owner :: 0..16#FFFFFFFF, Bitrate :: non_neg_integer(), Overhead :: 0..511}.

-record(tmmbr, {
    %% The bounding set, as the TMMBN reports it.
    set = [] :: [tuple_()],
    %% The set enforced before the last change, kept until hold_until.
    hold = [] :: [tuple_()],
    hold_until :: undefined | integer(),
    %% When each owner was last heard from (any RTP or RTCP packet).
    seen = #{} :: #{non_neg_integer() => integer()}
}).

-opaque state() :: #tmmbr{}.

-spec new() -> state().
new() -> #tmmbr{}.

%%====================================================================
%% Bounding set (RFC 5104 §3.5.4.2, initial algorithm)
%%====================================================================

%% @doc The bounding set of `Tuples', ordered by increasing overhead.
-spec bounding_set([tuple_()]) -> [tuple_()].
bounding_set([]) ->
    [];
bounding_set(Tuples) ->
    %% Steps 1 and 2: by increasing overhead, the lowest bitrate for each.
    ByOh = lists:foldl(
        fun({_, B, O} = T, Acc) ->
            case Acc of
                #{O := {_, B0, _}} when B0 =< B -> Acc;
                _ -> Acc#{O => T}
            end
        end,
        #{},
        Tuples
    ),
    X = lists:keysort(3, maps:values(ByOh)),
    %% Step 3: the lowest bitrate, the highest overhead among equals.
    First = lists:foldl(
        fun
            ({_, B, O} = T, {_, B0, O0}) when B < B0; B =:= B0, O > O0 -> T;
            (_, Best) -> Best
        end,
        hd(X),
        tl(X)
    ),
    %% Step 4: lower overheads cannot bound the polygon after it.
    {_, _, O1} = First,
    Candidates = [T || {_, _, O} = T <- X, O > O1],
    %% Y is kept newest first, each member with its intersection value.
    Y = lists:foldl(fun add/2, [{First, {0, 1}}], Candidates),
    [T || {T, _} <- lists:reverse(Y)].

%% Steps 5 to 9 for one candidate.
add(C, [{L, Ix} | Rest] = Y) ->
    Pr = intersection(L, C),
    case Rest =/= [] andalso le(Pr, Ix) of
        true ->
            %% Step 7: the last member no longer bounds the polygon.
            add(C, Rest);
        false ->
            %% Step 8.
            case lt(Pr, max_pr(L)) of
                true -> [{C, Pr} | Y];
                false -> Y
            end
    end.

%% Equation (3): the packet rate where the two lines meet; the
%% candidate has the higher overhead.
intersection({_, Bl, Ol}, {_, Bc, Oc}) ->
    {Bc - Bl, 8 * (Oc - Ol)}.

%% Equation (4): where the line meets the X axis (at 0 for a zero
%% bitrate, never for a zero overhead).
max_pr({_, 0, _}) -> {0, 1};
max_pr({_, _, 0}) -> infinity;
max_pr({_, B, O}) -> {B, 8 * O}.

le({A, B}, {C, D}) -> A * D =< C * B.

lt(_, infinity) -> true;
lt({A, B}, {C, D}) -> A * D < C * B.

%% @doc The net media bit rate (payload bits per second) the tuples
%% allow at `PacketRate' packets per second: the lowest of
%% `Bitrate - 8 x Overhead x PacketRate', at least 0.
-spec net_rate([tuple_()], number()) -> non_neg_integer() | infinity.
net_rate([], _PacketRate) ->
    infinity;
net_rate(Set, PacketRate) ->
    max(0, floor(lists:min([B - 8 * O * PacketRate || {_, B, O} <- Set]))).

%%====================================================================
%% State
%%====================================================================

%% @doc A TMMBR tuple from `Owner'. Returns the new state; the caller
%% sends a TMMBN with `set/1' whether or not the set changed.
-spec request(non_neg_integer(), non_neg_integer(), 0..511, integer(), non_neg_integer(), state()) -> state().
request(Owner, Bitrate, Overhead, Now, HoldOff, #tmmbr{set = Set} = S) ->
    Candidates = [T || {O, _, _} = T <- Set, O =/= Owner] ++ [{Owner, Bitrate, Overhead}],
    change(bounding_set(Candidates), Now, HoldOff, S#tmmbr{seen = (S#tmmbr.seen)#{Owner => Now}}).

%% @doc The owner left (RTCP BYE). `{true, S}' when it owned a tuple of
%% the set: send a TMMBN with what remains.
-spec leave(non_neg_integer(), integer(), non_neg_integer(), state()) -> {boolean(), state()}.
leave(Owner, Now, HoldOff, #tmmbr{set = Set} = S) ->
    S1 = S#tmmbr{seen = maps:remove(Owner, S#tmmbr.seen)},
    case lists:keymember(Owner, 1, Set) of
        true -> {true, change(lists:keydelete(Owner, 1, Set), Now, HoldOff, S1)};
        false -> {false, S1}
    end.

%% @doc A packet from `Ssrc' was received: an owner is still there.
%% Other SSRCs are not recorded.
-spec touch(non_neg_integer(), integer(), state()) -> state().
touch(Ssrc, Now, #tmmbr{seen = Seen} = S) when is_map_key(Ssrc, Seen) ->
    S#tmmbr{seen = Seen#{Ssrc := Now}};
touch(_Ssrc, _Now, S) ->
    S.

%% @doc Remove the owners not heard from for `Timeout' ms. Returns the
%% owners removed from the set.
-spec expire(integer(), pos_integer(), non_neg_integer(), state()) -> {[non_neg_integer()], state()}.
expire(Now, Timeout, HoldOff, #tmmbr{set = Set, seen = Seen} = S) ->
    Gone = [O || {O, _, _} <- Set, Now - maps:get(O, Seen, Now) >= Timeout],
    lists:foldl(
        fun(O, {Acc, SA}) ->
            {_, SA1} = leave(O, Now, HoldOff, SA),
            {[O | Acc], SA1}
        end,
        {[], S},
        Gone
    ).

change(Set, _Now, _HoldOff, #tmmbr{set = Set} = S) ->
    S#tmmbr{seen = maps:with([O || {O, _, _} <- Set], S#tmmbr.seen)};
change(Set, Now, HoldOff, S) ->
    %% Whatever is enforced now stays enforced during the hold-off, so a
    %% relaxed limit waits and a stricter one applies at once. Only the
    %% owners of the set are followed.
    S#tmmbr{set = Set, hold = enforced(Now, S), hold_until = Now + HoldOff,
            seen = maps:with([O || {O, _, _} <- Set], S#tmmbr.seen)}.

%% @doc The bounding set reported in TMMBN.
-spec set(state()) -> [tuple_()].
set(#tmmbr{set = Set}) -> Set.

%% @doc The tuples the sender follows at `Now'.
-spec enforced(integer(), state()) -> [tuple_()].
enforced(Now, #tmmbr{set = Set, hold = Hold, hold_until = Until}) when is_integer(Until), Now < Until ->
    bounding_set(Set ++ Hold);
enforced(_Now, #tmmbr{set = Set}) ->
    Set.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#tmmbr{hold_until = undefined}) -> infinity;
next_timeout(#tmmbr{hold_until = Until}) -> Until.

%% @doc End the hold-off once due.
-spec handle_timeout(integer(), state()) -> state().
handle_timeout(Now, #tmmbr{hold_until = Until} = S) when is_integer(Until), Now >= Until ->
    S#tmmbr{hold = [], hold_until = undefined};
handle_timeout(_Now, S) ->
    S.
