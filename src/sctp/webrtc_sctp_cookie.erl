%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc SCTP State Cookie (RFC 9260 §5.1.3, §5.1.5).
%%
%% The cookie carries everything needed to build the association when
%% the COOKIE ECHO arrives, so an endpoint answering an INIT keeps no
%% state. It is authenticated with HMAC-SHA256 under a per association
%% secret and holds its creation time and lifespan, in the caller's
%% millisecond clock.
-module(webrtc_sctp_cookie).

-export([make/2, open/2]).

-define(VERSION, 1).
-define(MAC_LEN, 32).

-type fields() :: #{
    my_tag := 0..16#FFFFFFFF,
    peer_tag := 0..16#FFFFFFFF,
    my_itsn := 0..16#FFFFFFFF,
    peer_itsn := 0..16#FFFFFFFF,
    peer_rwnd := 0..16#FFFFFFFF,
    peer_os := 0..65535,
    peer_mis := 0..65535,
    local_tie := 0..16#FFFFFFFF,
    peer_tie := 0..16#FFFFFFFF,
    created := integer(),
    life := 0..16#FFFFFFFF,
    features := #{atom() => boolean()}
}.
-export_type([fields/0]).

-define(FEATURES, [idata, ifwd, pr, reconfig, zero_checksum]).

-spec make(fields(), binary()) -> binary().
make(F, Secret) ->
    Flags = lists:foldl(
        fun({Bit, Name}, Acc) ->
            case maps:get(Name, maps:get(features, F), false) of
                true -> Acc bor (1 bsl Bit);
                false -> Acc
            end
        end,
        0,
        lists:zip(lists:seq(0, length(?FEATURES) - 1), ?FEATURES)
    ),
    Body =
        <<?VERSION:8, (maps:get(my_tag, F)):32, (maps:get(peer_tag, F)):32,
            (maps:get(my_itsn, F)):32, (maps:get(peer_itsn, F)):32, (maps:get(peer_rwnd, F)):32,
            (maps:get(peer_os, F)):16, (maps:get(peer_mis, F)):16, (maps:get(local_tie, F)):32,
            (maps:get(peer_tie, F)):32, (maps:get(created, F)):64/signed, (maps:get(life, F)):32,
            Flags:8>>,
    <<Body/binary, (mac(Secret, Body))/binary>>.

-spec open(binary(), binary()) -> {ok, fields()} | {error, bad_cookie}.
open(Cookie, Secret) when byte_size(Cookie) > ?MAC_LEN ->
    BodyLen = byte_size(Cookie) - ?MAC_LEN,
    <<Body:BodyLen/binary, Mac:?MAC_LEN/binary>> = Cookie,
    case crypto:hash_equals(Mac, mac(Secret, Body)) of
        true -> parse(Body);
        false -> {error, bad_cookie}
    end;
open(_, _) ->
    {error, bad_cookie}.

parse(
    <<?VERSION:8, MyTag:32, PeerTag:32, MyItsn:32, PeerItsn:32, Rwnd:32, OS:16, MIS:16, LTie:32,
        PTie:32, Created:64/signed, Life:32, Flags:8>>
) ->
    Features = maps:from_list([
        {Name, Flags band (1 bsl Bit) =/= 0}
     || {Bit, Name} <- lists:zip(lists:seq(0, length(?FEATURES) - 1), ?FEATURES)
    ]),
    {ok, #{
        my_tag => MyTag,
        peer_tag => PeerTag,
        my_itsn => MyItsn,
        peer_itsn => PeerItsn,
        peer_rwnd => Rwnd,
        peer_os => OS,
        peer_mis => MIS,
        local_tie => LTie,
        peer_tie => PTie,
        created => Created,
        life => Life,
        features => Features
    }};
parse(_) ->
    {error, bad_cookie}.

mac(Secret, Body) ->
    crypto:mac(hmac, sha256, Secret, Body).
