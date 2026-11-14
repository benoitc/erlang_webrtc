%% @doc RTCP compound packet codec (RFC 3550 §6).
%%
%% `decode/1' splits a compound packet into its individual packets and
%% returns them as records (see `webrtc_rtp_rtcp.hrl'): SR, RR, SDES,
%% BYE and APP here; the feedback messages of RFC 4585, RFC 5104,
%% RFC 8888, transport-wide CC and REMB in `webrtc_rtcp_fb'; extended
%% reports in `webrtc_rtcp_xr'. Packets of unknown type or feedback
%% format are returned as `#rtcp_raw{}' so they can be forwarded.
%%
%% By default any sequence of valid RTCP packets is accepted, which
%% covers reduced-size RTCP (RFC 5506). `decode/2' with
%% `#{mode => compound}' also applies the compound checks of RFC 3550
%% §6.1 and Appendix A.2: the first packet is an SR or RR and only the
%% last packet carries padding. In both modes every packet must have
%% version 2, a valid padding count and lengths that add up to the
%% datagram size.
%%
%% `encode/1' takes one record or a list of records and never adds
%% padding. It raises `badarg' on records that cannot be encoded.
-module(webrtc_rtcp).

-include("webrtc_rtp_rtcp.hrl").

-export([decode/1, decode/2, encode/1, validate_compound/1, has_cname/1]).

-export_type([packet/0, sdes_item/0, decode_error/0]).

-type packet() ::
    #rtcp_sr{}
    | #rtcp_rr{}
    | #rtcp_sdes{}
    | #rtcp_bye{}
    | #rtcp_app{}
    | #rtcp_nack{}
    | #rtcp_tmmbr{}
    | #rtcp_tmmbn{}
    | #rtcp_twcc{}
    | #rtcp_ccfb{}
    | #rtcp_pli{}
    | #rtcp_sli{}
    | #rtcp_fir{}
    | #rtcp_remb{}
    | #rtcp_xr{}
    | #rtcp_raw{}.
-type sdes_item() ::
    cname
    | name
    | email
    | phone
    | loc
    | tool
    | note
    | mid
    | rid
    | repaired_rid
    | {priv, Prefix :: binary()}
    | 1..255.
-type decode_error() ::
    truncated
    | bad_version
    | bad_padding
    | first_not_report
    | padding_not_last
    | {bad_packet, PT :: 0..255, term()}.

-define(is_u32(V), (is_integer(V) andalso V >= 0 andalso V =< 16#FFFFFFFF)).

%%====================================================================
%% Decoding
%%====================================================================

-spec decode(binary()) -> {ok, [packet()]} | {error, decode_error()}.
decode(Bin) ->
    decode(Bin, #{}).

-spec decode(binary(), #{mode => reduced_size | compound}) ->
    {ok, [packet()]} | {error, decode_error()}.
decode(Bin, Opts) ->
    Mode = maps:get(mode, Opts, reduced_size),
    case split(Bin, []) of
        {ok, Raw} ->
            case check_mode(Mode, Raw) of
                ok -> decode_all(Raw, []);
                Err -> Err
            end;
        Err ->
            Err
    end.

%% Split into {PT, Count, Padded, Body} with padding removed.
split(<<>>, []) ->
    {error, truncated};
split(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
split(<<2:2, P:1, C:5, PT:8, Len:16, Rest/binary>>, Acc) ->
    Size = Len * 4,
    case Rest of
        <<Body0:Size/binary, Rest1/binary>> ->
            case strip_padding(P, Body0) of
                {ok, Body} -> split(Rest1, [{PT, C, P =:= 1, Body} | Acc]);
                Err -> Err
            end;
        _ ->
            {error, truncated}
    end;
split(<<V:2, _/bitstring>>, _) when V =/= 2 ->
    {error, bad_version};
split(_, _) ->
    {error, truncated}.

strip_padding(0, Body) ->
    {ok, Body};
strip_padding(1, Body) ->
    Size = byte_size(Body),
    case Size > 0 andalso binary:last(Body) of
        N when is_integer(N), N > 0, N =< Size -> {ok, binary:part(Body, 0, Size - N)};
        _ -> {error, bad_padding}
    end.

check_mode(reduced_size, _) ->
    ok;
check_mode(compound, [{PT, _, _, _} | _]) when PT =/= ?RTCP_SR, PT =/= ?RTCP_RR ->
    {error, first_not_report};
check_mode(compound, Raw) ->
    {Init, _Last} = lists:split(length(Raw) - 1, Raw),
    case lists:any(fun({_, _, Padded, _}) -> Padded end, Init) of
        true -> {error, padding_not_last};
        false -> ok
    end.

decode_all([], Acc) ->
    {ok, lists:reverse(Acc)};
decode_all([{PT, C, _, Body} | Rest], Acc) ->
    case decode_packet(PT, C, Body) of
        {ok, Pkt} -> decode_all(Rest, [Pkt | Acc]);
        {error, R} -> {error, {bad_packet, PT, R}}
    end.

decode_packet(?RTCP_SR, C, <<Ssrc:32, Ntp:64, RtpTs:32, Pkts:32, Octets:32, Rest/binary>>) ->
    case report_blocks(C, Rest) of
        {ok, Blocks, Ext} ->
            {ok, #rtcp_sr{
                ssrc = Ssrc,
                ntp = Ntp,
                rtp_ts = RtpTs,
                packets = Pkts,
                octets = Octets,
                reports = Blocks,
                ext = Ext
            }};
        Err ->
            Err
    end;
decode_packet(?RTCP_RR, C, <<Ssrc:32, Rest/binary>>) ->
    case report_blocks(C, Rest) of
        {ok, Blocks, Ext} -> {ok, #rtcp_rr{ssrc = Ssrc, reports = Blocks, ext = Ext}};
        Err -> Err
    end;
decode_packet(?RTCP_SDES, C, Body) ->
    case sdes_chunks(C, Body, []) of
        {ok, Chunks} -> {ok, #rtcp_sdes{chunks = Chunks}};
        Err -> Err
    end;
decode_packet(?RTCP_BYE, C, Body) ->
    decode_bye(C, Body);
decode_packet(?RTCP_APP, C, <<Ssrc:32, Name:4/binary, Data/binary>>) ->
    {ok, #rtcp_app{subtype = C, ssrc = Ssrc, name = Name, data = Data}};
decode_packet(?RTCP_RTPFB, C, Body) ->
    webrtc_rtcp_fb:decode(?RTCP_RTPFB, C, Body);
decode_packet(?RTCP_PSFB, C, Body) ->
    webrtc_rtcp_fb:decode(?RTCP_PSFB, C, Body);
decode_packet(?RTCP_XR, _C, Body) ->
    webrtc_rtcp_xr:decode(Body);
decode_packet(PT, _C, _Body) when
    PT =:= ?RTCP_SR; PT =:= ?RTCP_RR; PT =:= ?RTCP_APP
->
    {error, truncated};
decode_packet(PT, C, Body) ->
    {ok, #rtcp_raw{pt = PT, count = C, body = Body}}.

report_blocks(C, Bin) ->
    Size = C * 24,
    case Bin of
        <<Blocks:Size/binary, Ext/binary>> ->
            {ok, [decode_rb(B) || <<B:24/binary>> <= Blocks], Ext};
        _ ->
            {error, truncated}
    end.

decode_rb(<<Ssrc:32, Frac:8, Lost:24/signed, Ext:32, Jitter:32, Lsr:32, Dlsr:32>>) ->
    #rtcp_rb{
        ssrc = Ssrc,
        fraction_lost = Frac,
        lost = Lost,
        ext_seq = Ext,
        jitter = Jitter,
        lsr = Lsr,
        dlsr = Dlsr
    }.

%% RFC 3550 §6.5: each chunk is an SSRC, a list of items ended by one or
%% more null octets, padded to a 32-bit boundary.
sdes_chunks(0, _Rest, Acc) ->
    {ok, lists:reverse(Acc)};
sdes_chunks(N, <<Ssrc:32, Rest/binary>>, Acc) ->
    case sdes_items(Rest, 0, []) of
        {ok, Items, Rest1} -> sdes_chunks(N - 1, Rest1, [{Ssrc, Items} | Acc]);
        Err -> Err
    end;
sdes_chunks(_, _, _) ->
    {error, truncated}.

%% Off is the number of bytes consumed in this chunk after the SSRC, used
%% to find the 32-bit boundary after the terminating null octet.
sdes_items(<<0, Rest/binary>>, Off, Acc) ->
    Pad = (4 - ((Off + 1) rem 4)) rem 4,
    case Rest of
        <<Zeros:Pad/binary, Rest1/binary>> ->
            case Zeros =:= <<0:(Pad * 8)>> of
                true -> {ok, lists:reverse(Acc), Rest1};
                false -> {error, bad_sdes_padding}
            end;
        _ ->
            {error, truncated}
    end;
sdes_items(<<Type, Len, Rest/binary>>, Off, Acc) ->
    case Rest of
        <<Value:Len/binary, Rest1/binary>> ->
            case sdes_item(Type, Value) of
                {ok, Item} -> sdes_items(Rest1, Off + 2 + Len, [Item | Acc]);
                Err -> Err
            end;
        _ ->
            {error, truncated}
    end;
sdes_items(_, _, _) ->
    {error, truncated}.

sdes_item(8, <<PLen, Prefix:PLen/binary, Value/binary>>) ->
    {ok, {{priv, Prefix}, Value}};
sdes_item(8, _) ->
    {error, bad_priv};
sdes_item(Type, Value) ->
    {ok, {sdes_name(Type), Value}}.

sdes_name(1) -> cname;
sdes_name(2) -> name;
sdes_name(3) -> email;
sdes_name(4) -> phone;
sdes_name(5) -> loc;
sdes_name(6) -> tool;
sdes_name(7) -> note;
sdes_name(12) -> rid;
sdes_name(13) -> repaired_rid;
sdes_name(15) -> mid;
sdes_name(N) -> N.

sdes_code(cname) -> 1;
sdes_code(name) -> 2;
sdes_code(email) -> 3;
sdes_code(phone) -> 4;
sdes_code(loc) -> 5;
sdes_code(tool) -> 6;
sdes_code(note) -> 7;
sdes_code(rid) -> 12;
sdes_code(repaired_rid) -> 13;
sdes_code(mid) -> 15;
sdes_code(N) when is_integer(N), N >= 1, N =< 255, N =/= 8 -> N.

decode_bye(C, Body) ->
    Size = C * 4,
    case Body of
        <<Ssrcs:Size/binary, Rest/binary>> ->
            List = [S || <<S:32>> <= Ssrcs],
            case Rest of
                <<>> ->
                    {ok, #rtcp_bye{ssrcs = List}};
                <<Len, Reason:Len/binary, _/binary>> ->
                    {ok, #rtcp_bye{ssrcs = List, reason = Reason}};
                _ ->
                    {error, truncated}
            end;
        _ ->
            {error, truncated}
    end.

%%====================================================================
%% Validation helpers
%%====================================================================

%% @doc Check a list of decoded packets against RFC 3550 §6.1: the first
%% packet is an SR or RR and an SDES packet carries a CNAME.
-spec validate_compound([packet()]) -> ok | {error, first_not_report | no_cname}.
validate_compound([First | _] = Pkts) when
    is_record(First, rtcp_sr); is_record(First, rtcp_rr)
->
    case has_cname(Pkts) of
        true -> ok;
        false -> {error, no_cname}
    end;
validate_compound(_) ->
    {error, first_not_report}.

-spec has_cname([packet()]) -> boolean().
has_cname(Pkts) ->
    lists:any(
        fun
            (#rtcp_sdes{chunks = Chunks}) ->
                lists:any(fun({_, Items}) -> lists:keymember(cname, 1, Items) end, Chunks);
            (_) ->
                false
        end,
        Pkts
    ).

%%====================================================================
%% Encoding
%%====================================================================

-spec encode(packet() | [packet()]) -> binary().
encode(Pkts) when is_list(Pkts) ->
    iolist_to_binary([encode_one(P) || P <- Pkts]);
encode(Pkt) ->
    encode_one(Pkt).

encode_one(Pkt) ->
    {Count, PT, Body0} = body(Pkt),
    Body = iolist_to_binary(Body0),
    Size = byte_size(Body),
    case Size rem 4 =:= 0 andalso Size div 4 =< 16#FFFF andalso Count =< 31 of
        true -> <<2:2, 0:1, Count:5, PT:8, (Size div 4):16, Body/binary>>;
        false -> error(badarg)
    end.

body(#rtcp_sr{
    ssrc = Ssrc, ntp = Ntp, rtp_ts = Ts, packets = P, octets = O, reports = R, ext = Ext
}) when ?is_u32(Ssrc), ?is_u32(Ts), ?is_u32(P), ?is_u32(O), is_integer(Ntp), is_binary(Ext) ->
    {length(R), ?RTCP_SR, [<<Ssrc:32, Ntp:64, Ts:32, P:32, O:32>>, [encode_rb(B) || B <- R], Ext]};
body(#rtcp_rr{ssrc = Ssrc, reports = R, ext = Ext}) when ?is_u32(Ssrc), is_binary(Ext) ->
    {length(R), ?RTCP_RR, [<<Ssrc:32>>, [encode_rb(B) || B <- R], Ext]};
body(#rtcp_sdes{chunks = Chunks}) ->
    {length(Chunks), ?RTCP_SDES, [encode_chunk(C) || C <- Chunks]};
body(#rtcp_bye{ssrcs = Ssrcs, reason = Reason}) ->
    Ids = [<<S:32>> || S <- Ssrcs, ?is_u32(S) orelse error(badarg)],
    R =
        case Reason of
            undefined -> <<>>;
            B when is_binary(B), byte_size(B) =< 255 -> pad4(<<(byte_size(B)), B/binary>>)
        end,
    {length(Ssrcs), ?RTCP_BYE, [Ids, R]};
body(#rtcp_app{subtype = Sub, ssrc = Ssrc, name = Name, data = Data}) when
    is_integer(Sub), Sub >= 0, Sub =< 31, ?is_u32(Ssrc), byte_size(Name) =:= 4, is_binary(Data)
->
    {Sub, ?RTCP_APP, [<<Ssrc:32>>, Name, Data]};
body(#rtcp_xr{} = X) ->
    {0, ?RTCP_XR, webrtc_rtcp_xr:encode(X)};
body(#rtcp_raw{pt = PT, count = C, body = B}) when
    is_integer(PT), PT >= 0, PT =< 255, is_integer(C), C >= 0, C =< 31, is_binary(B)
->
    {C, PT, B};
body(Pkt) ->
    webrtc_rtcp_fb:encode(Pkt).

encode_rb(#rtcp_rb{
    ssrc = Ssrc, fraction_lost = F, lost = L, ext_seq = E, jitter = J, lsr = Lsr, dlsr = Dlsr
}) when
    ?is_u32(Ssrc),
    is_integer(F),
    F >= 0,
    F =< 255,
    is_integer(L),
    L >= -16#800000,
    L =< 16#7FFFFF,
    ?is_u32(E),
    ?is_u32(J),
    ?is_u32(Lsr),
    ?is_u32(Dlsr)
->
    <<Ssrc:32, F:8, L:24/signed, E:32, J:32, Lsr:32, Dlsr:32>>;
encode_rb(_) ->
    error(badarg).

encode_chunk({Ssrc, Items}) when ?is_u32(Ssrc) ->
    Bin = iolist_to_binary([<<Ssrc:32>>, [encode_item(I) || I <- Items], 0]),
    pad4(Bin).

encode_item({{priv, Prefix}, Value}) ->
    Content = <<(byte_size(Prefix)), Prefix/binary, Value/binary>>,
    item(8, Content);
encode_item({Name, Value}) ->
    item(sdes_code(Name), Value).

item(Type, Value) when is_binary(Value), byte_size(Value) =< 255 ->
    <<Type, (byte_size(Value)), Value/binary>>.

pad4(B) ->
    case byte_size(B) rem 4 of
        0 -> B;
        R -> <<B/binary, 0:((4 - R) * 8)>>
    end.
