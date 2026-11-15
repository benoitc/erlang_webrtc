%% PropEr properties for webrtc_srtp: protect/unprotect round trips on
%% random packets, and unprotect never crashes on arbitrary input.
-module(prop_webrtc_srtp).
-include_lib("proper/include/proper.hrl").

-export([
    prop_rtp_roundtrip/0,
    prop_rtcp_roundtrip/0,
    prop_unprotect_random_binary/0,
    prop_unprotect_mutated/0
]).

%%--------------------------------------------------------------------
%% Generators
%%--------------------------------------------------------------------

profile() ->
    oneof([
        srtp_aes128_cm_hmac_sha1_80,
        srtp_aes128_cm_hmac_sha1_32,
        srtp_aead_aes_128_gcm,
        srtp_aead_aes_256_gcm
    ]).

u(Bits) -> integer(0, (1 bsl Bits) - 1).

%% Valid RTP packet with random CSRC count, optional header extension,
%% random marker, payload type and payload.
rtp_packet() ->
    ?LET(
        {P, M, PT, Seq, TS, SSRC, Csrcs, Ext, Payload},
        {u(1), u(1), u(7), u(16), u(32), u(32), resize(15, list(u(32))), ext(), binary()},
        begin
            CC = length(Csrcs),
            X =
                if
                    Ext =:= none -> 0;
                    true -> 1
                end,
            CsrcBin = <<<<C:32>> || C <- Csrcs>>,
            ExtBin =
                case Ext of
                    none ->
                        <<>>;
                    {Prof, Words} ->
                        <<Prof:16, (length(Words)):16, <<<<W:32>> || W <- Words>>/binary>>
                end,
            <<2:2, P:1, X:1, CC:4, M:1, PT:7, Seq:16, TS:32, SSRC:32, CsrcBin/binary, ExtBin/binary,
                Payload/binary>>
        end
    ).

ext() ->
    oneof([none, {u(16), resize(8, list(u(32)))}]).

%% RTCP compound packet: an 8-octet header followed by random octets.
rtcp_packet() ->
    ?LET(
        {P, RC, PT, SSRC, Body},
        {u(1), u(5), integer(192, 223), u(32), binary()},
        <<2:2, P:1, RC:5, PT:8, ((byte_size(Body) + 3) div 4):16, SSRC:32, Body/binary>>
    ).

ctx_pair(Profile, Opts) ->
    #{master_key_len := KL, master_salt_len := SL} = webrtc_srtp_profile:params(Profile),
    K = crypto:strong_rand_bytes(KL),
    S = crypto:strong_rand_bytes(SL),
    {webrtc_srtp:new(Profile, K, S, Opts), webrtc_srtp:new(Profile, K, S, Opts)}.

%%--------------------------------------------------------------------
%% Properties
%%--------------------------------------------------------------------

prop_rtp_roundtrip() ->
    ?FORALL(
        {Profile, Ids, Cryptex, Packets},
        {profile(), list(choose(1, 255)), boolean(), non_empty(list(rtp_packet()))},
        begin
            %% Any set of RFC 6904 encrypted elements, with or without
            %% cryptex, round trips.
            {Tx, Rx} = ctx_pair(Profile, #{encrypted_extensions => Ids, cryptex => Cryptex}),
            %% Sequence numbers in a list may repeat; protect refuses a
            %% reused index, which must also be refused on receive.
            {_, _, Ok} = lists:foldl(
                fun(Pkt, {T, R, Acc}) ->
                    case webrtc_srtp:protect_rtp(Pkt, T) of
                        {ok, S, T1} ->
                            Expected = expected(Pkt, Cryptex),
                            case webrtc_srtp:unprotect_rtp(S, R) of
                                {ok, Expected, R1} -> {T1, R1, Acc};
                                Other -> {T1, R, [{Pkt, Other} | Acc]}
                            end;
                        {error, E} when E =:= replay; E =:= too_old ->
                            {T, R, Acc};
                        {error, cryptex_unsupported} when Cryptex ->
                            %% An extension profile cryptex cannot carry.
                            {T, R, Acc};
                        {error, malformed} ->
                            %% Only for a profile reserved for cryptex.
                            case cryptex_profile(Pkt) of
                                true -> {T, R, Acc};
                                false -> {T, R, [{Pkt, malformed} | Acc]}
                            end;
                        Other ->
                            {T, R, [{Pkt, Other} | Acc]}
                    end
                end,
                {Tx, Rx, []},
                Packets
            ),
            ?WHENFAIL(io:format("failures: ~p~n", [Ok]), Ok =:= [])
        end
    ).

%% RFC 9335 §5.1: with cryptex, CSRCs without an extension travel with
%% an empty one, which the receiver keeps.
expected(<<V:2, P:1, 0:1, CC:4, Fixed:11/binary, Rest/binary>>, true) when CC > 0 ->
    CL = CC * 4,
    <<Csrcs:CL/binary, Tail/binary>> = Rest,
    <<V:2, P:1, 1:1, CC:4, Fixed/binary, Csrcs/binary, 16#BEDE:16, 0:16, Tail/binary>>;
expected(Pkt, _) ->
    Pkt.

cryptex_profile(<<_:3, 1:1, CC:4, _/binary>> = Pkt) ->
    Off = 12 + CC * 4,
    case Pkt of
        <<_:Off/binary, P:16, _/binary>> -> P =:= 16#C0DE orelse P =:= 16#C2DE;
        _ -> false
    end;
cryptex_profile(_) ->
    false.

prop_rtcp_roundtrip() ->
    ?FORALL(
        {Profile, Encrypt, Packets},
        {profile(), boolean(), non_empty(list(rtcp_packet()))},
        begin
            {Tx, Rx} = ctx_pair(Profile, #{encrypt_rtcp => Encrypt}),
            {_, _, Ok} = lists:foldl(
                fun(Pkt, {T, R, Acc}) ->
                    {ok, S, T1} = webrtc_srtp:protect_rtcp(Pkt, T),
                    case webrtc_srtp:unprotect_rtcp(S, R) of
                        {ok, Pkt, R1} -> {T1, R1, Acc};
                        Other -> {T1, R, [{Pkt, Other} | Acc]}
                    end
                end,
                {Tx, Rx, []},
                Packets
            ),
            ?WHENFAIL(io:format("failures: ~p~n", [Ok]), Ok =:= [])
        end
    ).

%% Arbitrary binaries, including ones that start like RTP or RTCP.
prop_unprotect_random_binary() ->
    ?FORALL(
        {Profile, Bin},
        {profile(), oneof([binary(), ?LET({L, B}, {u(6), binary()}, <<2:2, L:6, B/binary>>)])},
        begin
            {_, Rx} = ctx_pair(Profile, #{}),
            is_error(webrtc_srtp:unprotect_rtp(Bin, Rx)) andalso
                is_error(webrtc_srtp:unprotect_rtcp(Bin, Rx))
        end
    ).

%% Truncating, extending or flipping one octet of a valid protected
%% packet is always refused, never crashes.
prop_unprotect_mutated() ->
    ?FORALL(
        {Profile, Pkt, Mutation},
        {profile(), rtp_packet(), mutation()},
        begin
            {Tx, Rx} = ctx_pair(Profile, #{}),
            {ok, S, _} = webrtc_srtp:protect_rtp(Pkt, Tx),
            {ok, Pkt, _} = webrtc_srtp:unprotect_rtp(S, Rx),
            {ok, SR, _} = webrtc_srtp:protect_rtcp(<<16#80, 201, 1:16, 0:32, S/binary>>, Tx),
            is_error(webrtc_srtp:unprotect_rtp(mutate(Mutation, S), Rx)) andalso
                is_error(webrtc_srtp:unprotect_rtcp(mutate(Mutation, SR), Rx))
        end
    ).

mutation() ->
    oneof([{truncate, pos_integer()}, {append, non_empty(binary())}, {flip, nat(), integer(1, 255)}]).

mutate({truncate, N}, Bin) ->
    binary:part(Bin, 0, max(0, byte_size(Bin) - N));
mutate({append, Extra}, Bin) ->
    <<Bin/binary, Extra/binary>>;
mutate({flip, Pos0, Mask}, Bin) ->
    Pos = Pos0 rem byte_size(Bin),
    <<A:Pos/binary, B, C/binary>> = Bin,
    <<A/binary, (B bxor Mask), C/binary>>.

is_error({error, _}) -> true;
is_error(_) -> false.
