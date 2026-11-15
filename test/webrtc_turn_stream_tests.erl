%% Tests of TURN stream framing (RFC 8656 §3.1, §12.5).
-module(webrtc_turn_stream_tests).
-include_lib("eunit/include/eunit.hrl").

-define(F, webrtc_turn_stream).

stun() ->
    webrtc_stun:encode(webrtc_stun:request(binding, [{software, <<"abc">>}]), #{fingerprint => true}).

chan(Data) -> webrtc_turn_channel:encode(16#4001, Data).

whole_messages_test() ->
    S = stun(),
    C = chan(<<"hello">>),
    %% ChannelData padding is not part of the message given back.
    ?assertEqual({ok, [S, <<16#40, 1, 0, 5, "hello">>, S], <<>>}, ?F:split(<<S/binary, C/binary, S/binary>>)).

%% Any split of the stream gives the same messages.
byte_by_byte_test() ->
    S = stun(),
    C = chan(<<"x">>),
    Stream = <<S/binary, C/binary, S/binary>>,
    {Msgs, Rest} = lists:foldl(
        fun(B, {Acc, Buf}) ->
            {ok, M, R} = ?F:split(<<Buf/binary, B>>),
            {Acc ++ M, R}
        end,
        {[], <<>>},
        binary_to_list(Stream)
    ),
    ?assertEqual(<<>>, Rest),
    ?assertEqual([S, <<16#40, 1, 0, 1, "x">>, S], Msgs).

partial_test() ->
    S = stun(),
    Half = binary:part(S, 0, 10),
    ?assertEqual({ok, [], Half}, ?F:split(Half)),
    ?assertEqual({ok, [], <<16#40, 1>>}, ?F:split(<<16#40, 1>>)).

%% Bytes that start neither STUN nor ChannelData: out of step.
bad_frame_test_() ->
    [?_assertEqual({error, bad_frame}, ?F:split(B))
     || B <- [<<16#80, 0, 0, 0>>, <<16#50, 0, 0, 0>>, <<16#17, 3, 3, 0, 5, 1, 2, 3>>, <<16#C0>>,
              %% STUN with a length that is not a multiple of four.
              <<0, 1, 0, 3, 0:128>>]].

%% The buffer never holds more than one maximum size message.
bounded_test() ->
    Big = <<16#40, 0, 16#FF, 16#FF>>,
    {ok, [], Rest} = ?F:split(<<Big/binary, 0:8000>>),
    ?assert(byte_size(Rest) =< 20 + 16#FFFF + 3).
