%% @doc H.264 RTP payload format (RFC 6184), packetization-mode 1
%% (non-interleaved): single NAL unit packets, STAP-A and FU-A.
%%
%% `packetize/2' turns the NAL units of one access unit into RTP
%% payloads of at most `Mtu' bytes: consecutive small NAL units are
%% aggregated into STAP-A packets (§5.7.1), NAL units larger than the
%% MTU are fragmented into FU-A packets (§5.8), others are sent as
%% single NAL unit packets (§5.6). The caller sets the marker bit on the
%% last payload of the access unit.
%%
%% `depacketize/1' returns the NAL units of one payload, or a fragment
%% for FU-A. `depacketizer_new/0' and `depacketizer_push/3' reassemble
%% FU-A fragments across packets, dropping a fragmented NAL unit when a
%% sequence number is missing.
%%
%% STAP-B, MTAP and FU-B (interleaved mode) are rejected with
%% `{error, {unsupported, Type}}'. `split_annexb/1' extracts NAL units
%% from an Annex B byte stream. Nothing here decodes video; key frame
%% detection looks for an IDR slice (NAL type 5).
-module(webrtc_rtp_h264).

-export([
    nal_type/1,
    split_annexb/1,
    packetize/2,
    depacketize/1,
    depacketizer_new/0,
    depacketizer_push/3,
    nal_types/1,
    is_keyframe/1
]).

-export_type([depacketizer/0, fragment/0]).

-define(STAP_A, 24).
-define(STAP_B, 25).
-define(MTAP16, 26).
-define(MTAP24, 27).
-define(FU_A, 28).
-define(FU_B, 29).
-define(IDR, 5).

-type fragment() :: {fragment, start | middle | 'end', NalHeader :: byte(), Data :: binary()}.

-record(depack, {
    %% Expected next seq and the NAL being reassembled.
    next = undefined :: undefined | 0..65535,
    buf = undefined :: undefined | iodata()
}).

-opaque depacketizer() :: #depack{}.

%% @doc NAL unit type of a NAL unit or payload (low 5 bits of byte 0).
-spec nal_type(binary()) -> 0..31.
nal_type(<<_:3, T:5, _/binary>>) -> T.

%% @doc Split an Annex B byte stream on 3 and 4 byte start codes.
%% Bytes before the first start code are ignored.
-spec split_annexb(binary()) -> [binary()].
split_annexb(Bin) ->
    Starts = [{P + L, P} || {P, L} <- binary:matches(Bin, <<0, 0, 1>>)],
    split_at(Bin, Starts).

split_at(_Bin, []) ->
    [];
split_at(Bin, [{From, _} | Rest]) ->
    To =
        case Rest of
            [] -> byte_size(Bin);
            [{_, Next} | _] -> Next
        end,
    Nal = trim_zeros(binary:part(Bin, From, To - From)),
    case Nal of
        <<>> -> split_at(Bin, Rest);
        _ -> [Nal | split_at(Bin, Rest)]
    end.

%% A zero before the next 3-byte start code belongs to a 4-byte start
%% code (trailing_zero_8bits), not to the NAL unit.
trim_zeros(<<>>) ->
    <<>>;
trim_zeros(B) ->
    case binary:last(B) of
        0 -> trim_zeros(binary:part(B, 0, byte_size(B) - 1));
        _ -> B
    end.

%%====================================================================
%% Packetization
%%====================================================================

-spec packetize([binary()], pos_integer()) -> [binary()].
packetize(Nals, Mtu) when is_integer(Mtu), Mtu > 2 ->
    pack([N || N <- Nals, byte_size(N) > 0], Mtu).

pack([], _) ->
    [];
pack([Nal | Rest], Mtu) when byte_size(Nal) > Mtu ->
    fu_a(Nal, Mtu) ++ pack(Rest, Mtu);
pack([Nal | Rest], Mtu) ->
    case stap(Rest, Mtu, [Nal], 1 + 2 + byte_size(Nal)) of
        {[_], _} -> [Nal | pack(Rest, Mtu)];
        {Group, Rest1} -> [stap_a(Group) | pack(Rest1, Mtu)]
    end.

stap([Nal | Rest], Mtu, Acc, Size) when Size + 2 + byte_size(Nal) =< Mtu ->
    stap(Rest, Mtu, [Nal | Acc], Size + 2 + byte_size(Nal));
stap(Rest, _, Acc, _) ->
    {lists:reverse(Acc), Rest}.

%% §5.7.1: F is the OR of the aggregated F bits, NRI the maximum.
stap_a(Nals) ->
    F = lists:foldl(fun(<<Fb:1, _:7, _/binary>>, A) -> A bor Fb end, 0, Nals),
    Nri = lists:max([N || <<_:1, N:2, _:5, _/binary>> <- Nals]),
    iolist_to_binary([<<F:1, Nri:2, ?STAP_A:5>> | [[<<(byte_size(N)):16>>, N] || N <- Nals]]).

fu_a(<<F:1, Nri:2, Type:5, Data/binary>>, Mtu) ->
    Max = Mtu - 2,
    Ind = <<F:1, Nri:2, ?FU_A:5>>,
    fragments(Data, Max, Ind, Type, 1).

fragments(Data, Max, Ind, Type, S) when byte_size(Data) =< Max ->
    [<<Ind/binary, S:1, 1:1, 0:1, Type:5, Data/binary>>];
fragments(Data, Max, Ind, Type, S) ->
    <<C:Max/binary, Rest/binary>> = Data,
    [<<Ind/binary, S:1, 0:1, 0:1, Type:5, C/binary>> | fragments(Rest, Max, Ind, Type, 0)].

%%====================================================================
%% Depacketization
%%====================================================================

%% @doc NAL units carried by one payload, or a FU-A fragment.
-spec depacketize(binary()) -> {ok, [binary()]} | fragment() | {error, term()}.
depacketize(<<>>) ->
    {error, empty};
depacketize(<<_F:1, _Nri:2, ?STAP_A:5, Rest/binary>>) ->
    stap_units(Rest, []);
depacketize(<<F:1, Nri:2, ?FU_A:5, S:1, E:1, _R:1, Type:5, Data/binary>>) ->
    Hdr = (F bsl 7) bor (Nri bsl 5) bor Type,
    case {S, E} of
        {1, 1} -> {error, bad_fu_a};
        {1, 0} -> {fragment, start, Hdr, Data};
        {0, 0} -> {fragment, middle, Hdr, Data};
        {0, 1} -> {fragment, 'end', Hdr, Data}
    end;
depacketize(<<_:3, ?FU_A:5, _/binary>>) ->
    {error, truncated};
depacketize(<<_:3, T:5, _/binary>>) when
    T =:= ?STAP_B; T =:= ?MTAP16; T =:= ?MTAP24; T =:= ?FU_B
->
    {error, {unsupported, T}};
depacketize(<<_:3, T:5, _/binary>> = Nal) when T >= 1, T =< 23 ->
    {ok, [Nal]};
depacketize(<<_:3, T:5, _/binary>>) ->
    {error, {bad_nal_type, T}}.

stap_units(<<>>, []) ->
    {error, empty_stap_a};
stap_units(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
stap_units(<<Size:16, Nal:Size/binary, Rest/binary>>, Acc) when Size > 0 ->
    stap_units(Rest, [Nal | Acc]);
stap_units(_, _) ->
    {error, truncated}.

-spec depacketizer_new() -> depacketizer().
depacketizer_new() ->
    #depack{}.

%% @doc Push one payload with its RTP sequence number. Returns the
%% complete NAL units it yields. A malformed payload, or a fragment that
%% does not continue the NAL unit being reassembled, drops that NAL unit.
-spec depacketizer_push(0..65535, binary(), depacketizer()) ->
    {ok, [binary()], depacketizer()} | {error, term(), depacketizer()}.
depacketizer_push(Seq, Payload, #depack{next = Next, buf = Buf}) ->
    InOrder = Next =:= Seq,
    St = #depack{next = (Seq + 1) band 16#FFFF},
    case depacketize(Payload) of
        {ok, Nals} ->
            {ok, Nals, St};
        {fragment, start, Hdr, Data} ->
            {ok, [], St#depack{buf = [Hdr, Data]}};
        {fragment, middle, _, Data} when InOrder, Buf =/= undefined ->
            {ok, [], St#depack{buf = [Buf, Data]}};
        {fragment, 'end', _, Data} when InOrder, Buf =/= undefined ->
            {ok, [iolist_to_binary([Buf, Data])], St};
        {fragment, _, _, _} ->
            {error, lost_fragment, St};
        {error, R} ->
            {error, R, St}
    end.

%%====================================================================
%% Key frames
%%====================================================================

%% @doc NAL unit types present in a payload. For FU-A only the start
%% fragment reports its type.
-spec nal_types(binary()) -> [0..31].
nal_types(Payload) ->
    case depacketize(Payload) of
        {ok, Nals} -> [nal_type(N) || N <- Nals];
        {fragment, start, Hdr, _} -> [Hdr band 31];
        _ -> []
    end.

%% @doc True when the payload carries (the start of) an IDR slice.
-spec is_keyframe(binary()) -> boolean().
is_keyframe(Payload) ->
    lists:member(?IDR, nal_types(Payload)).
