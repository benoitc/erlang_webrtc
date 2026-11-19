%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Handshake reassembly under hostile fragmentation (RFC 6347 §4.2.3,
%% RFC 9147 §5.5): held memory and work stay bounded.
-module(webrtc_dtls_reasm_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("webrtc/src/dtls/webrtc_dtls.hrl").

st() ->
    #dtls{role = server, state = wait_client_finished, recv_msg_seq = 0}.

frag(Seq, Len, Off, Data) ->
    #{type => certificate, length => Len, seq => Seq, offset => Off, data => Data}.

%% Many overlapping fragments of an incomplete message: the bytes held
%% never exceed the advertised length.
overlap_flood_test() ->
    rand:seed(exsss, {3, 1, 4}),
    Len = 100000,
    Msg = crypto:strong_rand_bytes(Len),
    St = lists:foldl(
        fun(_, S) ->
            Off = rand:uniform(Len - 1001),
            webrtc_dtls_reasm:add(frag(1, Len, Off, binary:part(Msg, Off, 1000)), 0, S)
        end,
        st(),
        lists:seq(1, 20000)
    ),
    {Covered, Pieces, _} = webrtc_dtls_reasm:peek(1, St),
    ?assert(Covered =< Len),
    ?assert(Pieces =< 256),
    ?assert(erts_debug:flat_size(St) < 2 * Len div 8 + 100000).

%% Tiny distinct fragments: once the piece limit is reached further
%% fragments are dropped instead of growing the state.
tiny_fragments_capped_test() ->
    Len = 100000,
    St = lists:foldl(
        fun(I, S) -> webrtc_dtls_reasm:add(frag(1, Len, I * 2, <<I:8>>), 0, S) end,
        st(),
        lists:seq(0, 5000)
    ),
    {Covered, Pieces, incomplete} = webrtc_dtls_reasm:peek(1, St),
    ?assertEqual(256, Pieces),
    ?assertEqual(256, Covered).

%% Total held bytes across buffered messages are bounded.
held_bytes_bounded_test() ->
    Len = 131072,
    St = lists:foldl(
        fun(Seq, S) -> webrtc_dtls_reasm:add(frag(Seq, Len, 0, binary:copy(<<1>>, Len - 1)), 0, S) end,
        st(),
        lists:seq(1, 7)
    ),
    Held = lists:sum([C || Seq <- lists:seq(1, 7), {C, _, _} <- [webrtc_dtls_reasm:peek(Seq, St)]]),
    ?assert(Held =< 262144).

%% RFC 6347 §4.2.3 allows fragments of any size: a message sent one
%% byte at a time, in order or not, reassembles however many fragments
%% it takes, and its data stays compact.
one_byte_fragments_test() ->
    Len = 5000,
    Msg = crypto:strong_rand_bytes(Len),
    Frags = [{I, binary:part(Msg, I, 1)} || I <- lists:seq(0, Len - 1)],
    [begin
         St = lists:foldl(fun({Off, D}, S) -> webrtc_dtls_reasm:add(frag(1, Len, Off, D), 0, S) end, st(), Order),
         ?assertMatch({Len, 1, Msg}, webrtc_dtls_reasm:peek(1, St)),
         ?assert(erts_debug:flat_size(St) < Len)
     end || Order <- [Frags, lists:reverse(Frags)]].

%% Overlapping fragments in any order reassemble to the message.
overlapping_reassembly_test() ->
    rand:seed(exsss, {2, 7, 1}),
    [begin
         Len = rand:uniform(5000),
         Msg = crypto:strong_rand_bytes(Len),
         Frags = cover(Msg, Len),
         St = lists:foldl(fun({Off, D}, S) -> webrtc_dtls_reasm:add(frag(1, Len, Off, D), 0, S) end,
                          st(), shuffle(Frags)),
         ?assertMatch({Len, _, Msg}, webrtc_dtls_reasm:peek(1, St))
     end || _ <- lists:seq(1, 200)].

%% Random overlapping pieces that together cover the whole message.
cover(Msg, Len) ->
    cover(Msg, Len, 0, []).

cover(_Msg, Len, Pos, Acc) when Pos >= Len -> Acc;
cover(Msg, Len, Pos, Acc) ->
    Back = min(Pos, rand:uniform(50) - 1),
    Start = Pos - Back,
    Size = min(Len - Start, rand:uniform(400)),
    cover(Msg, Len, Start + Size, [{Start, binary:part(Msg, Start, Size)} | Acc]).

shuffle(L) -> [X || {_, X} <- lists:sort([{rand:uniform(), X} || X <- L])].

%% Messages up to six ahead of the next expected one are buffered (the
%% longest flight); further ones are not part of the flight and dropped.
window_test() ->
    St = st(),
    ?assertEqual(new, webrtc_dtls_reasm:classify(frag(6, 10, 0, <<0:80>>), St)),
    ?assertEqual(ignore, webrtc_dtls_reasm:classify(frag(7, 10, 0, <<0:80>>), St)).
