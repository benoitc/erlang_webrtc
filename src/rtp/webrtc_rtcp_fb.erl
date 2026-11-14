%% @doc RTCP feedback messages (RFC 4585 §6): transport layer (RTPFB,
%% PT 205) and payload specific (PSFB, PT 206).
%%
%% RTPFB: generic NACK (FMT 1, RFC 4585 §6.2.1), TMMBR and TMMBN (FMT 3
%% and 4, RFC 5104 §4.2), RFC 8888 congestion control feedback (FMT 11,
%% `webrtc_rtcp_ccfb') and transport-wide CC feedback (FMT 15,
%% `webrtc_rtcp_twcc').
%%
%% PSFB: PLI (FMT 1), SLI (FMT 2), FIR (FMT 4, RFC 5104 §4.3.1) and REMB
%% (FMT 15 with the "REMB" identifier, draft-alvestrand-rmcat-remb).
%%
%% Other formats decode to `#rtcp_raw{}'. This module is called by
%% `webrtc_rtcp'; use that module to decode and encode packets. The NACK
%% helpers `nack_items/1' and `nack_seqs/1' convert between sequence
%% number lists and PID/BLP pairs.
-module(webrtc_rtcp_fb).

-include("webrtc_rtp_rtcp.hrl").

-export([decode/3, encode/1, nack_items/1, nack_seqs/1, bitrate_exp/2]).

-define(is_u32(V), (is_integer(V) andalso V >= 0 andalso V =< 16#FFFFFFFF)).

%%====================================================================
%% Decoding
%%====================================================================

-spec decode(205 | 206, 0..31, binary()) -> {ok, webrtc_rtcp:packet()} | {error, term()}.
decode(PT, Fmt, <<Sender:32, Media:32, Fci/binary>> = Body) ->
    case fci(PT, Fmt, Sender, Media, Fci) of
        unknown -> {ok, #rtcp_raw{pt = PT, count = Fmt, body = Body}};
        Res -> Res
    end;
decode(?RTCP_RTPFB, ?RTPFB_CCFB, Body) ->
    webrtc_rtcp_ccfb:decode(Body);
decode(_, _, _) ->
    {error, truncated}.

fci(?RTCP_RTPFB, ?RTPFB_NACK, S, M, Fci) ->
    case words(Fci, 4) of
        {ok, []} ->
            {error, empty_nack};
        {ok, Ws} ->
            {ok, #rtcp_nack{
                sender_ssrc = S, media_ssrc = M, items = [{P, B} || <<P:16, B:16>> <- Ws]
            }};
        Err ->
            Err
    end;
fci(?RTCP_RTPFB, Fmt, S, M, Fci) when Fmt =:= ?RTPFB_TMMBR; Fmt =:= ?RTPFB_TMMBN ->
    case words(Fci, 8) of
        {ok, Ws} ->
            Entries = [
                {Ssrc, Mant bsl Exp, Oh}
             || <<Ssrc:32, Exp:6, Mant:17, Oh:9>> <- Ws
            ],
            case Fmt of
                ?RTPFB_TMMBR ->
                    {ok, #rtcp_tmmbr{sender_ssrc = S, media_ssrc = M, entries = Entries}};
                ?RTPFB_TMMBN ->
                    {ok, #rtcp_tmmbn{sender_ssrc = S, media_ssrc = M, entries = Entries}}
            end;
        Err ->
            Err
    end;
fci(?RTCP_RTPFB, ?RTPFB_CCFB, S, M, Fci) ->
    webrtc_rtcp_ccfb:decode(<<S:32, M:32, Fci/binary>>);
fci(?RTCP_RTPFB, ?RTPFB_TWCC, S, M, Fci) ->
    webrtc_rtcp_twcc:decode(S, M, Fci);
fci(?RTCP_PSFB, ?PSFB_PLI, S, M, <<>>) ->
    {ok, #rtcp_pli{sender_ssrc = S, media_ssrc = M}};
fci(?RTCP_PSFB, ?PSFB_PLI, _, _, _) ->
    {error, bad_pli};
fci(?RTCP_PSFB, ?PSFB_SLI, S, M, Fci) ->
    case words(Fci, 4) of
        {ok, []} ->
            {error, empty_sli};
        {ok, Ws} ->
            {ok, #rtcp_sli{
                sender_ssrc = S,
                media_ssrc = M,
                entries = [{F, N, P} || <<F:13, N:13, P:6>> <- Ws]
            }};
        Err ->
            Err
    end;
fci(?RTCP_PSFB, ?PSFB_FIR, S, M, Fci) ->
    case words(Fci, 8) of
        {ok, []} ->
            {error, empty_fir};
        {ok, Ws} ->
            {ok, #rtcp_fir{
                sender_ssrc = S,
                media_ssrc = M,
                entries = [{Ssrc, Seq} || <<Ssrc:32, Seq:8, _:24>> <- Ws]
            }};
        Err ->
            Err
    end;
fci(?RTCP_PSFB, ?PSFB_AFB, S, M, <<"REMB", N:8, Exp:6, Mant:18, Rest/binary>>) ->
    case Rest of
        <<Ssrcs:(N * 4)/binary>> ->
            {ok, #rtcp_remb{
                sender_ssrc = S,
                media_ssrc = M,
                bitrate = Mant bsl Exp,
                ssrcs = [X || <<X:32>> <= Ssrcs]
            }};
        _ ->
            {error, bad_remb}
    end;
fci(?RTCP_PSFB, ?PSFB_AFB, _, _, <<"REMB", _/binary>>) ->
    {error, bad_remb};
fci(_, _, _, _, _) ->
    unknown.

words(Bin, Size) when byte_size(Bin) rem Size =:= 0 ->
    {ok, [W || <<W:Size/binary>> <= Bin]};
words(_, _) ->
    {error, bad_fci_length}.

%%====================================================================
%% Encoding
%%====================================================================

-spec encode(webrtc_rtcp:packet()) -> {0..31, 205 | 206, iodata()}.
encode(#rtcp_nack{sender_ssrc = S, media_ssrc = M, items = [_ | _] = Items}) ->
    Fci = [<<P:16, B:16>> || {P, B} <- Items, u16(P), u16(B)],
    length(Fci) =:= length(Items) orelse error(badarg),
    {?RTPFB_NACK, ?RTCP_RTPFB, [hdr(S, M), Fci]};
encode(#rtcp_tmmbr{sender_ssrc = S, media_ssrc = M, entries = E}) ->
    {?RTPFB_TMMBR, ?RTCP_RTPFB, [hdr(S, M), [tmmb_entry(X) || X <- E]]};
encode(#rtcp_tmmbn{sender_ssrc = S, media_ssrc = M, entries = E}) ->
    {?RTPFB_TMMBN, ?RTCP_RTPFB, [hdr(S, M), [tmmb_entry(X) || X <- E]]};
encode(#rtcp_ccfb{} = C) ->
    {?RTPFB_CCFB, ?RTCP_RTPFB, webrtc_rtcp_ccfb:encode(C)};
encode(#rtcp_twcc{sender_ssrc = S, media_ssrc = M} = T) ->
    {?RTPFB_TWCC, ?RTCP_RTPFB, [hdr(S, M), webrtc_rtcp_twcc:encode_fci(T)]};
encode(#rtcp_pli{sender_ssrc = S, media_ssrc = M}) ->
    {?PSFB_PLI, ?RTCP_PSFB, hdr(S, M)};
encode(#rtcp_sli{sender_ssrc = S, media_ssrc = M, entries = [_ | _] = E}) ->
    Fci = [
        <<F:13, N:13, P:6>>
     || {F, N, P} <- E,
        is_integer(F) andalso F >= 0 andalso F < 8192 orelse error(badarg),
        is_integer(N) andalso N >= 0 andalso N < 8192 orelse error(badarg),
        is_integer(P) andalso P >= 0 andalso P < 64 orelse error(badarg)
    ],
    {?PSFB_SLI, ?RTCP_PSFB, [hdr(S, M), Fci]};
encode(#rtcp_fir{sender_ssrc = S, media_ssrc = M, entries = [_ | _] = E}) ->
    Fci = [
        <<Ssrc:32, Seq:8, 0:24>>
     || {Ssrc, Seq} <- E,
        ?is_u32(Ssrc) orelse error(badarg),
        is_integer(Seq) andalso Seq >= 0 andalso Seq =< 255 orelse error(badarg)
    ],
    {?PSFB_FIR, ?RTCP_PSFB, [hdr(S, M), Fci]};
encode(#rtcp_remb{sender_ssrc = S, media_ssrc = M, bitrate = Br, ssrcs = Ssrcs}) when
    length(Ssrcs) =< 255
->
    {Exp, Mant} = bitrate_exp(Br, 18),
    Ids = [<<X:32>> || X <- Ssrcs, ?is_u32(X) orelse error(badarg)],
    {?PSFB_AFB, ?RTCP_PSFB, [hdr(S, M), <<"REMB", (length(Ssrcs)):8, Exp:6, Mant:18>>, Ids]};
encode(_) ->
    error(badarg).

hdr(S, M) when ?is_u32(S), ?is_u32(M) ->
    <<S:32, M:32>>;
hdr(_, _) ->
    error(badarg).

u16(V) -> (is_integer(V) andalso V >= 0 andalso V =< 16#FFFF) orelse error(badarg).

tmmb_entry({Ssrc, Br, Oh}) when ?is_u32(Ssrc), is_integer(Oh), Oh >= 0, Oh =< 511 ->
    {Exp, Mant} = bitrate_exp(Br, 17),
    <<Ssrc:32, Exp:6, Mant:17, Oh:9>>;
tmmb_entry(_) ->
    error(badarg).

%% @doc Split a bitrate into a 6-bit exponent and a `Bits'-bit mantissa
%% with the smallest exponent that fits (RFC 5104 §4.2.1.1). Bits below
%% the mantissa precision are dropped, so the encoded value never exceeds
%% the given bitrate.
-spec bitrate_exp(non_neg_integer(), pos_integer()) -> {0..63, non_neg_integer()}.
bitrate_exp(Br, Bits) when is_integer(Br), Br >= 0 ->
    bitrate_exp(Br, Bits, 0).

bitrate_exp(_Br, _Bits, Exp) when Exp > 63 ->
    error(badarg);
bitrate_exp(Br, Bits, Exp) ->
    case Br bsr Exp of
        M when M < (1 bsl Bits) -> {Exp, M};
        _ -> bitrate_exp(Br, Bits, Exp + 1)
    end.

%%====================================================================
%% NACK helpers
%%====================================================================

%% @doc Turn a list of lost sequence numbers into generic NACK items
%% (PID and a bitmask of the 16 following packets). The list may wrap
%% around 65535; order is taken relative to the first element.
-spec nack_items([0..65535]) -> [{0..65535, 0..65535}].
nack_items([]) ->
    [];
nack_items([First | _] = Seqs) ->
    Ext = lists:usort([webrtc_rtp_seq:seq_unwrap(S, First) || S <- Seqs]),
    group(Ext).

group([]) ->
    [];
group([Pid | Rest]) ->
    {Blp, Rest1} = blp(Pid, Rest, 0),
    [{Pid band 16#FFFF, Blp} | group(Rest1)].

blp(Pid, [S | Rest], Acc) when S - Pid =< 16 ->
    blp(Pid, Rest, Acc bor (1 bsl (S - Pid - 1)));
blp(_, Rest, Acc) ->
    {Acc, Rest}.

%% @doc Expand NACK items into the sequence numbers they request, in
%% item order.
-spec nack_seqs([{0..65535, 0..65535}]) -> [0..65535].
nack_seqs(Items) ->
    lists:append([
        [Pid | [(Pid + I + 1) band 16#FFFF || I <- lists:seq(0, 15), Blp band (1 bsl I) =/= 0]]
     || {Pid, Blp} <- Items
    ]).
