%% @doc RTCP extended reports (RFC 3611), PT 207.
%%
%% Decoded blocks: Receiver Reference Time `{rrtr, Ntp64}' (§4.4) and
%% DLRR `{dlrr, [{Ssrc, LastRR, DelaySinceLastRR}]}' (§4.5), which
%% together give round-trip times to receivers that do not send RTP.
%% Other block types are kept as `{BlockType, TypeSpecific, Body}'.
%% Called by `webrtc_rtcp'.
-module(webrtc_rtcp_xr).

-include("webrtc_rtp_rtcp.hrl").

-export([decode/1, encode/1]).

-export_type([block/0]).

-type block() ::
    {rrtr, 0..16#FFFFFFFFFFFFFFFF}
    | {dlrr, [{0..16#FFFFFFFF, 0..16#FFFFFFFF, 0..16#FFFFFFFF}]}
    | {0..255, 0..255, binary()}.

-define(BT_RRTR, 4).
-define(BT_DLRR, 5).

-spec decode(binary()) -> {ok, #rtcp_xr{}} | {error, term()}.
decode(<<Ssrc:32, Rest/binary>>) ->
    case blocks(Rest, []) of
        {ok, Blocks} -> {ok, #rtcp_xr{ssrc = Ssrc, blocks = Blocks}};
        Err -> Err
    end;
decode(_) ->
    {error, truncated}.

blocks(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
blocks(<<BT, TS, Len:16, Rest/binary>>, Acc) ->
    Size = Len * 4,
    case Rest of
        <<Body:Size/binary, Rest1/binary>> ->
            case block(BT, TS, Body) of
                {ok, B} -> blocks(Rest1, [B | Acc]);
                Err -> Err
            end;
        _ ->
            {error, truncated}
    end;
blocks(_, _) ->
    {error, truncated}.

block(?BT_RRTR, _, <<Ntp:64>>) ->
    {ok, {rrtr, Ntp}};
block(?BT_RRTR, _, _) ->
    {error, bad_rrtr};
block(?BT_DLRR, _, Body) when byte_size(Body) rem 12 =:= 0 ->
    {ok, {dlrr, [{S, L, D} || <<S:32, L:32, D:32>> <= Body]}};
block(?BT_DLRR, _, _) ->
    {error, bad_dlrr};
block(BT, TS, Body) ->
    {ok, {BT, TS, Body}}.

%% @doc Encode the body of an XR packet (after the common header).
-spec encode(#rtcp_xr{}) -> binary().
encode(#rtcp_xr{ssrc = Ssrc, blocks = Blocks}) when
    is_integer(Ssrc), Ssrc >= 0, Ssrc =< 16#FFFFFFFF
->
    iolist_to_binary([<<Ssrc:32>> | [encode_block(B) || B <- Blocks]]);
encode(_) ->
    error(badarg).

encode_block({rrtr, Ntp}) when is_integer(Ntp), Ntp >= 0, Ntp =< 16#FFFFFFFFFFFFFFFF ->
    <<?BT_RRTR, 0, 2:16, Ntp:64>>;
encode_block({dlrr, Subs}) ->
    Body = <<<<(u32(S)):32, (u32(L)):32, (u32(D)):32>> || {S, L, D} <- Subs>>,
    block_bin(?BT_DLRR, 0, Body);
encode_block({BT, TS, Body}) when
    is_integer(BT), BT >= 0, BT =< 255, is_integer(TS), TS >= 0, TS =< 255, is_binary(Body)
->
    block_bin(BT, TS, Body);
encode_block(_) ->
    error(badarg).

block_bin(BT, TS, Body) when byte_size(Body) rem 4 =:= 0, byte_size(Body) div 4 =< 16#FFFF ->
    <<BT, TS, (byte_size(Body) div 4):16, Body/binary>>;
block_bin(_, _, _) ->
    error(badarg).

u32(V) when is_integer(V), V >= 0, V =< 16#FFFFFFFF -> V;
u32(_) -> error(badarg).
