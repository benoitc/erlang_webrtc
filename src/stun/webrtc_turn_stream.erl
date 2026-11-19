%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Framing of TURN over a stream transport (TCP, TLS over TCP,
%% RFC 8656 §3.1, §12.5): the messages on the stream are STUN messages
%% and ChannelData, each self-delimiting, ChannelData padded to a
%% multiple of four bytes.
%%
%% ```
%% {ok, Messages, Rest} = webrtc_turn_stream:split(<<Buffer/binary, Received/binary>>)
%% '''
%%
%% `Messages' are complete STUN messages and ChannelData frames (with
%% their padding removed), in order; `Rest' is the start of the next one.
%% Bytes that start neither a STUN message nor ChannelData mean the
%% stream is out of step: `{error, bad_frame}', the connection must be
%% closed (§3.1). `Rest' never exceeds one maximum size message.
%% Messages sent on the stream need no extra framing:
%% `webrtc_turn_channel:encode/2' already pads ChannelData.
-module(webrtc_turn_stream).

-export([split/1]).

%% A STUN message or ChannelData is at most this long.
-define(MAX_FRAME, (20 + 16#FFFF)).

-spec split(binary()) -> {ok, [binary()], binary()} | {error, bad_frame}.
split(Buf) ->
    split(Buf, []).

split(<<0:2, _:14, Len:16, 16#2112A442:32, _/binary>> = Buf, Acc) when Len rem 4 =:= 0 ->
    take(20 + Len, 20 + Len, Buf, Acc);
split(<<0:2, _:14, Len:16, Cookie/binary>> = Buf, Acc) when byte_size(Cookie) < 4, Len rem 4 =:= 0 ->
    %% The magic cookie (RFC 8489 §6) is not complete yet.
    case binary:longest_common_prefix([Cookie, <<16#2112A442:32>>]) =:= byte_size(Cookie) of
        true -> {ok, lists:reverse(Acc), Buf};
        false -> {error, bad_frame}
    end;
split(<<1:2, N:6, _:8, Len:16, _/binary>> = Buf, Acc) when N =< 16#0F ->
    take(4 + Len, 4 + pad(Len), Buf, Acc);
split(<<_, _/binary>> = Buf, Acc) when byte_size(Buf) < 4 ->
    case Buf of
        <<0:2, _/bitstring>> -> {ok, lists:reverse(Acc), Buf};
        <<1:2, N:6, _/binary>> when N =< 16#0F -> {ok, lists:reverse(Acc), Buf};
        _ -> {error, bad_frame}
    end;
split(<<>>, Acc) ->
    {ok, lists:reverse(Acc), <<>>};
split(_, _Acc) ->
    {error, bad_frame}.

%% `Keep' bytes are the message, `Size' with the padding.
take(Keep, Size, Buf, Acc) when byte_size(Buf) >= Size ->
    <<Msg:Keep/binary, _:(Size - Keep)/binary, Rest/binary>> = Buf,
    split(Rest, [Msg | Acc]);
take(_Keep, Size, Buf, Acc) when Size =< ?MAX_FRAME + 3 ->
    {ok, lists:reverse(Acc), Buf}.

pad(Len) -> (Len + 3) band (bnot 3).
