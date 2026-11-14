%% @doc RTP packet codec (RFC 3550 §5.1).
%%
%% `decode/1' parses a packet into an `#rtp{}' record and validates the
%% version, the CSRC list, the header extension length and the padding
%% count (RFC 3550 §5.1, Appendix A.1). The header extension is kept raw
%% as `{Profile, Data}'; `decode/2' with `#{extensions => parse}' turns
%% RFC 8285 extensions into `[{Id, Data}]'. `encode/1' accepts both forms.
%%
%% For forwarding, `peek/1' reads the fixed header fields and `rewrite/2'
%% patches seq, timestamp, SSRC, payload type or marker in place without
%% touching the rest of the packet.
%%
%% `classify/1' demultiplexes RTP and RTCP sharing one port by the
%% second octet (RFC 5761 §4): values 192..223 are RTCP.
%%
%% Sequence and timestamp arithmetic lives in `webrtc_rtp_seq'.
-module(webrtc_rtp).

-include("webrtc_rtp.hrl").

-define(is_uint(V, Bits), (is_integer(V) andalso V >= 0 andalso V < (1 bsl Bits))).

-export([
    decode/1,
    decode/2,
    encode/1,
    peek/1,
    rewrite/2,
    classify/1,
    is_rtcp/1,
    extensions/1,
    header_size/1
]).

-export_type([packet/0, decode_error/0, header/0, rewrite/0]).

-type packet() :: #rtp{}.
-type decode_error() ::
    truncated
    | bad_version
    | bad_padding
    | bad_extension
    | {bad_extension, term()}.
-type header() :: #{
    marker := boolean(),
    pt := 0..127,
    seq := 0..65535,
    ts := 0..16#FFFFFFFF,
    ssrc := 0..16#FFFFFFFF
}.
-type rewrite() :: #{
    marker => boolean(),
    pt => 0..127,
    seq => 0..65535,
    ts => 0..16#FFFFFFFF,
    ssrc => 0..16#FFFFFFFF
}.

%%====================================================================
%% Decoding
%%====================================================================

-spec decode(binary()) -> {ok, packet()} | {error, decode_error()}.
decode(Bin) ->
    decode(Bin, #{}).

%% @doc Decode with options. `#{extensions => parse}' decodes RFC 8285
%% header extensions into a list of elements; a packet whose extension
%% profile is not RFC 8285 keeps the raw form.
-spec decode(binary(), #{extensions => raw | parse}) ->
    {ok, packet()} | {error, decode_error()}.
decode(<<2:2, P:1, X:1, CC:4, M:1, PT:7, Seq:16, Ts:32, Ssrc:32, Rest0/binary>>, Opts) ->
    case Rest0 of
        <<CsrcBin:(CC * 4)/binary, Rest1/binary>> ->
            Csrcs = [C || <<C:32>> <= CsrcBin],
            case take_ext(X, Rest1) of
                {ok, Ext0, Rest2} ->
                    case strip_padding(P, Rest2) of
                        {ok, Pad, Payload} ->
                            case parse_ext(Ext0, maps:get(extensions, Opts, raw)) of
                                {ok, Ext} ->
                                    {ok, #rtp{
                                        padding = Pad,
                                        marker = M =:= 1,
                                        pt = PT,
                                        seq = Seq,
                                        ts = Ts,
                                        ssrc = Ssrc,
                                        csrcs = Csrcs,
                                        ext = Ext,
                                        payload = Payload
                                    }};
                                Err ->
                                    Err
                            end;
                        Err ->
                            Err
                    end;
                Err ->
                    Err
            end;
        _ ->
            {error, truncated}
    end;
decode(<<V:2, _/bitstring>>, _) when V =/= 2 ->
    {error, bad_version};
decode(Bin, _) when is_binary(Bin) ->
    {error, truncated}.

take_ext(0, Rest) ->
    {ok, undefined, Rest};
take_ext(1, <<Profile:16, Len:16, Rest/binary>>) ->
    Size = Len * 4,
    case Rest of
        <<Data:Size/binary, Rest1/binary>> -> {ok, {Profile, Data}, Rest1};
        _ -> {error, bad_extension}
    end;
take_ext(1, _) ->
    {error, truncated}.

%% RFC 3550 §5.1: the last octet of the padding is the count of padding
%% octets including itself, so it is at least 1 and fits in what is left
%% after the header.
strip_padding(0, Rest) ->
    {ok, 0, Rest};
strip_padding(1, Rest) ->
    Size = byte_size(Rest),
    case Size > 0 andalso binary:last(Rest) of
        N when is_integer(N), N > 0, N =< Size ->
            {ok, N, binary:part(Rest, 0, Size - N)};
        _ ->
            {error, bad_padding}
    end.

parse_ext({Profile, Data} = Raw, parse) ->
    case webrtc_rtp_ext:is_rfc8285(Profile) of
        true ->
            case webrtc_rtp_ext:decode(Profile, Data) of
                {ok, Elems} -> {ok, Elems};
                {error, R} -> {error, {bad_extension, R}}
            end;
        false ->
            {ok, Raw}
    end;
parse_ext(Ext, _) ->
    {ok, Ext}.

%% @doc Return the RFC 8285 elements of a decoded packet.
-spec extensions(packet()) -> {ok, [webrtc_rtp_ext:element()]} | {error, term()}.
extensions(#rtp{ext = undefined}) ->
    {ok, []};
extensions(#rtp{ext = L}) when is_list(L) ->
    {ok, L};
extensions(#rtp{ext = {Profile, Data}}) ->
    case webrtc_rtp_ext:is_rfc8285(Profile) of
        true -> webrtc_rtp_ext:decode(Profile, Data);
        false -> {error, {not_rfc8285, Profile}}
    end.

%%====================================================================
%% Encoding
%%====================================================================

%% @doc Encode a packet. An `ext' given as a list of elements is encoded
%% with `webrtc_rtp_ext:encode/1' (one-byte form when every element
%% fits, two-byte form otherwise). Raises `badarg' on out of range
%% fields, more than 15 CSRCs or an extension that is not a multiple of
%% 4 bytes.
-spec encode(packet()) -> binary().
encode(#rtp{
    padding = Pad,
    marker = M,
    pt = PT,
    seq = Seq,
    ts = Ts,
    ssrc = Ssrc,
    csrcs = Csrcs,
    ext = Ext,
    payload = Payload
}) when
    is_integer(Pad),
    Pad >= 0,
    Pad =< 255,
    is_boolean(M),
    ?is_uint(PT, 7),
    ?is_uint(Seq, 16),
    ?is_uint(Ts, 32),
    ?is_uint(Ssrc, 32),
    is_binary(Payload),
    length(Csrcs) =< 15
->
    _ = [error(badarg) || C <- Csrcs, not ?is_uint(C, 32)],
    CC = length(Csrcs),
    {X, ExtBin} = encode_ext(Ext),
    P =
        case Pad of
            0 -> 0;
            _ -> 1
        end,
    PadBin =
        case Pad of
            0 -> <<>>;
            _ -> <<0:((Pad - 1) * 8), Pad:8>>
        end,
    iolist_to_binary([
        <<2:2, P:1, X:1, CC:4, (bool(M)):1, PT:7, Seq:16, Ts:32, Ssrc:32>>,
        [<<C:32>> || C <- Csrcs],
        ExtBin,
        Payload,
        PadBin
    ]);
encode(_) ->
    error(badarg).

encode_ext(undefined) ->
    {0, <<>>};
encode_ext(L) when is_list(L) ->
    encode_ext(webrtc_rtp_ext:encode(L));
encode_ext({Profile, Data}) when
    is_integer(Profile), Profile >= 0, Profile =< 16#FFFF, byte_size(Data) rem 4 =:= 0
->
    Len = byte_size(Data) div 4,
    case Len =< 16#FFFF of
        true -> {1, <<Profile:16, Len:16, Data/binary>>};
        false -> error(badarg)
    end;
encode_ext(_) ->
    error(badarg).

bool(true) -> 1;
bool(false) -> 0.

%%====================================================================
%% Fast path
%%====================================================================

%% @doc Read the fixed header fields without decoding the packet.
-spec peek(binary()) -> {ok, header()} | {error, truncated | bad_version}.
peek(<<2:2, _:6, M:1, PT:7, Seq:16, Ts:32, Ssrc:32, _/binary>>) ->
    {ok, #{marker => M =:= 1, pt => PT, seq => Seq, ts => Ts, ssrc => Ssrc}};
peek(<<V:2, _/bitstring>>) when V =/= 2 ->
    {error, bad_version};
peek(B) when is_binary(B) ->
    {error, truncated}.

%% @doc Patch fixed header fields of an encoded packet in place. Only
%% the first 12 octets are rewritten; CSRCs, extensions, payload and
%% padding are copied unchanged.
-spec rewrite(binary(), rewrite()) -> {ok, binary()} | {error, truncated | bad_version}.
rewrite(<<2:2, B0:6, M0:1, PT0:7, Seq0:16, Ts0:32, Ssrc0:32, Rest/binary>>, Changes) ->
    M =
        case maps:find(marker, Changes) of
            {ok, true} -> 1;
            {ok, false} -> 0;
            error -> M0
        end,
    PT = maps:get(pt, Changes, PT0),
    Seq = maps:get(seq, Changes, Seq0),
    Ts = maps:get(ts, Changes, Ts0),
    Ssrc = maps:get(ssrc, Changes, Ssrc0),
    case ?is_uint(PT, 7) andalso ?is_uint(Seq, 16) andalso ?is_uint(Ts, 32) andalso ?is_uint(Ssrc, 32) of
        true -> {ok, <<2:2, B0:6, M:1, PT:7, Seq:16, Ts:32, Ssrc:32, Rest/binary>>};
        false -> error(badarg)
    end;
rewrite(<<V:2, _/bitstring>>, _) when V =/= 2 ->
    {error, bad_version};
rewrite(B, _) when is_binary(B) ->
    {error, truncated}.

%% @doc Size of the RTP header (fixed part, CSRCs and extension) of an
%% encoded packet, i.e. the offset of the payload.
-spec header_size(binary()) -> {ok, pos_integer()} | {error, decode_error()}.
header_size(<<2:2, _P:1, X:1, CC:4, _:88, Rest/binary>>) ->
    Fixed = ?RTP_HEADER_SIZE + CC * 4,
    case {X, Rest} of
        {0, <<_:(CC * 4)/binary, _/binary>>} ->
            {ok, Fixed};
        {1, <<_:(CC * 4)/binary, _Profile:16, Len:16, Ext/binary>>} when
            byte_size(Ext) >= Len * 4
        ->
            {ok, Fixed + 4 + Len * 4};
        {1, <<_:(CC * 4)/binary, _:32, _/binary>>} ->
            {error, bad_extension};
        _ ->
            {error, truncated}
    end;
header_size(<<V:2, _/bitstring>>) when V =/= 2 ->
    {error, bad_version};
header_size(B) when is_binary(B) ->
    {error, truncated}.

%%====================================================================
%% RTP/RTCP multiplexing (RFC 5761 §4)
%%====================================================================

%% @doc Classify a packet received on an rtcp-mux port. The second octet
%% holds the RTCP packet type, which overlaps the RTP marker bit and
%% payload type; RTCP types 192..223 map to RTP payload types 64..95,
%% which RFC 5761 forbids when multiplexing.
-spec classify(binary()) -> rtp | rtcp | unknown.
classify(<<2:2, _:6, B, _/binary>>) when B >= 192, B =< 223 -> rtcp;
classify(<<2:2, _:6, _, _/binary>>) -> rtp;
classify(_) -> unknown.

-spec is_rtcp(binary()) -> boolean().
is_rtcp(Bin) ->
    classify(Bin) =:= rtcp.
