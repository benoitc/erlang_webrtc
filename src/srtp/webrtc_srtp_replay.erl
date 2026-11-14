%% @doc Sliding window replay list (RFC 3711 §3.3.2, RFC 2401 style
%% bitmap).
%%
%% The window remembers the highest accepted index `Top' and a bitmap of
%% the `Size' indices ending at `Top' (bit 0 is `Top', bit k is
%% `Top - k'). An index is accepted when it is ahead of `Top', or inside
%% the window and not yet seen. Indices at or below `Top - Size' are
%% rejected as `too_old'.
%%
%% `check/2' never changes the window. Call `update/2' only after the
%% packet has been authenticated, so forged packets cannot move it.
-module(webrtc_srtp_replay).

-export([new/1, check/2, update/2, top/1, window_size/1]).

-export_type([window/0]).

-record(window, {
    size :: pos_integer(),
    mask :: pos_integer(),
    top = -1 :: integer(),
    bits = 0 :: non_neg_integer()
}).

-opaque window() :: #window{}.

%% @doc Empty window of `Size' entries. RFC 3711 §3.3.2 requires at
%% least 64.
-spec new(pos_integer()) -> window().
new(Size) when is_integer(Size), Size >= 64 ->
    #window{size = Size, mask = (1 bsl Size) - 1};
new(Size) ->
    erlang:error(badarg, [Size]).

-spec window_size(window()) -> pos_integer().
window_size(#window{size = S}) -> S.

%% @doc Highest accepted index, or -1 when nothing has been accepted.
-spec top(window()) -> integer().
top(#window{top = T}) -> T.

-spec check(non_neg_integer(), window()) -> ok | {error, replay | too_old}.
check(Index, #window{top = Top}) when Index > Top ->
    ok;
check(Index, #window{size = Size, top = Top, bits = Bits}) ->
    Diff = Top - Index,
    if
        Diff >= Size -> {error, too_old};
        Bits band (1 bsl Diff) =/= 0 -> {error, replay};
        true -> ok
    end.

%% @doc Record `Index' as received. The caller must have checked it with
%% `check/2' first.
-spec update(non_neg_integer(), window()) -> window().
update(Index, #window{size = Size, mask = Mask, top = Top, bits = Bits} = W) when
    Index > Top
->
    Shift = Index - Top,
    NewBits =
        if
            Shift >= Size -> 1;
            true -> ((Bits bsl Shift) bor 1) band Mask
        end,
    W#window{top = Index, bits = NewBits};
update(Index, #window{top = Top, bits = Bits} = W) ->
    W#window{bits = Bits bor (1 bsl (Top - Index))}.
