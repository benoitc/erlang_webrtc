%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc SCTP TLV codec: INIT / INIT ACK parameters (RFC 9260 §3.3.2.1,
%% RFC 3758, RFC 4820, RFC 5061, RFC 9653), RE-CONFIG parameters
%% (RFC 6525 §4) and error causes (RFC 9260 §3.3.10).
%%
%% All three share the same layout: a 16-bit type (or cause code), a
%% 16-bit length that covers the 4 byte header and the value but not the
%% padding, the value, then zero padding to a multiple of 4 bytes.
%%
%% Decoding is strict and never raises: every length must be at least 4
%% and fit in the remaining bytes, the padding after each TLV is skipped
%% (its content is ignored), a missing padding is accepted only after the
%% last TLV, and 1 to 3 leftover bytes are an error. Fixed-size TLVs with
%% the wrong length are errors. Unknown types are kept as
%% `{unknown_param, Type, Value}' or `{unknown_cause, Code, Value}', and
%% encode back to the original TLV, so the caller can report them.
%%
%% Error reasons: `{bad_param, Type}' for a parameter (INIT or RE-CONFIG)
%% with a bad length or value, `{bad_cause, Code}' for an error cause, and
%% `trailing_bytes' for leftover bytes that do not form a TLV.
%%
%% Encoders pad every TLV with zero bytes. Values that do not fit their
%% field (a value over 65531 bytes, an integer out of range) are caller
%% bugs and raise.
%%
%% INIT parameters, `param()':
%% <ul>
%% <li>`{ipv4_address, inet:ip4_address()}' (5), `{ipv6_address,
%% inet:ip6_address()}' (6), `{state_cookie, binary()}' (7)</li>
%% <li>`{unrecognized_param, binary()}' (8), the raw unrecognized TLV(s)</li>
%% <li>`{cookie_preservative, Ms}' (9), `{host_name, binary()}' (11),
%% `{supported_address_types, [Type]}' (12)</li>
%% <li>`ecn_capable' (16#8000), `{zero_checksum_acceptable, Edmid}'
%% (16#8001), `{padding, NBytes}' (16#8005), `{supported_extensions,
%% [ChunkType]}' (16#8008), `forward_tsn_supported' (16#C000)</li>
%% <li>`{unknown_param, Type, Value}'</li>
%% </ul>
%%
%% RE-CONFIG parameters, `reconf_param()':
%% `{out_reset, ReqSeq, RespSeq, SendersLastTsn, [Sid]}' (13),
%% `{in_reset, ReqSeq, [Sid]}' (14), `{tsn_reset, ReqSeq}' (15),
%% `{reconf_response, RespSeq, Result, undefined | {SendersNextTsn,
%% ReceiversNextTsn}}' (16), `{add_out_streams, ReqSeq, N}' (17),
%% `{add_in_streams, ReqSeq, N}' (18), `{unknown_param, Type, Value}'.
%%
%% Error causes, `cause()': see the type below (RFC 9260 §3.3.10).
-module(webrtc_sctp_param).

-export([
    decode_params/1,
    encode_params/1,
    encode_param/1,
    decode_causes/1,
    encode_causes/1,
    decode_reconf_params/1,
    encode_reconf_params/1,
    unrecognized_param_action/1
]).

-export_type([param/0, cause/0, reconf_param/0, reconf_result/0, error_reason/0]).

-type u16() :: 0..16#FFFF.
-type u32() :: 0..16#FFFFFFFF.

-type param() ::
    {ipv4_address, inet:ip4_address()}
    | {ipv6_address, inet:ip6_address()}
    | {state_cookie, binary()}
    | {unrecognized_param, binary()}
    | {cookie_preservative, u32()}
    | {host_name, binary()}
    | {supported_address_types, [u16()]}
    | ecn_capable
    | {zero_checksum_acceptable, Edmid :: u32()}
    | {padding, NBytes :: non_neg_integer()}
    | {supported_extensions, [0..255]}
    | forward_tsn_supported
    | {unknown_param, Type :: u16(), Value :: binary()}.

-type reconf_result() ::
    success_nothing_to_do
    | success_performed
    | denied
    | error_wrong_ssn
    | error_request_in_progress
    | error_bad_sequence_number
    | in_progress
    | u32().

-type reconf_param() ::
    {out_reset, ReqSeq :: u32(), RespSeq :: u32(), SendersLastTsn :: u32(), [u16()]}
    | {in_reset, ReqSeq :: u32(), [u16()]}
    | {tsn_reset, ReqSeq :: u32()}
    | {reconf_response, RespSeq :: u32(), reconf_result(),
        undefined | {SendersNextTsn :: u32(), ReceiversNextTsn :: u32()}}
    | {add_out_streams, ReqSeq :: u32(), N :: u16()}
    | {add_in_streams, ReqSeq :: u32(), N :: u16()}
    | {unknown_param, Type :: u16(), Value :: binary()}.

-type cause() ::
    {invalid_stream, Sid :: u16()}
    | {missing_param, [Type :: u16()]}
    | {stale_cookie, Usec :: u32()}
    | out_of_resource
    | {unresolvable_address, binary()}
    | {unrecognized_chunk, binary()}
    | invalid_mandatory_param
    | {unrecognized_params, binary()}
    | {no_user_data, Tsn :: u32()}
    | cookie_while_shutting_down
    | {restart_new_addresses, binary()}
    | {user_abort, binary()}
    | {protocol_violation, binary()}
    | {unknown_cause, Code :: u16(), Value :: binary()}.

-type error_reason() :: {bad_param, u16()} | {bad_cause, u16()} | trailing_bytes.

%% INIT parameter types.
-define(P_IPV4, 5).
-define(P_IPV6, 6).
-define(P_COOKIE, 7).
-define(P_UNRECOGNIZED, 8).
-define(P_PRESERVATIVE, 9).
-define(P_HOST_NAME, 11).
-define(P_ADDR_TYPES, 12).
-define(P_ECN, 16#8000).
-define(P_ZERO_CHECKSUM, 16#8001).
-define(P_PADDING, 16#8005).
-define(P_EXTENSIONS, 16#8008).
-define(P_FORWARD_TSN, 16#C000).

%% RE-CONFIG parameter types.
-define(R_OUT_RESET, 13).
-define(R_IN_RESET, 14).
-define(R_TSN_RESET, 15).
-define(R_RESPONSE, 16).
-define(R_ADD_OUT, 17).
-define(R_ADD_IN, 18).

-define(MAX_VALUE, 65531).

%%====================================================================
%% INIT parameters
%%====================================================================

%% @doc Decode a sequence of INIT / INIT ACK parameters.
-spec decode_params(binary()) -> {ok, [param()]} | {error, error_reason()}.
decode_params(Bin) when is_binary(Bin) ->
    decode_tlvs(Bin, bad_param, fun param/2).

%% @doc Encode parameters, each one padded to a multiple of 4 bytes.
-spec encode_params([param()]) -> binary().
encode_params(Params) ->
    <<<<(encode_param(P))/binary>> || P <- Params>>.

%% @doc Encode one parameter as a padded TLV.
-spec encode_param(param()) -> binary().
encode_param(P) ->
    pad(param_tlv(P)).

param(?P_IPV4, <<A, B, C, D>>) ->
    {ok, {ipv4_address, {A, B, C, D}}};
param(?P_IPV6, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {ok, {ipv6_address, {A, B, C, D, E, F, G, H}}};
param(?P_COOKIE, V) ->
    {ok, {state_cookie, V}};
param(?P_UNRECOGNIZED, V) ->
    {ok, {unrecognized_param, V}};
param(?P_PRESERVATIVE, <<Ms:32>>) ->
    {ok, {cookie_preservative, Ms}};
param(?P_HOST_NAME, V) ->
    {ok, {host_name, V}};
param(?P_ADDR_TYPES, V) when byte_size(V) rem 2 =:= 0 ->
    {ok, {supported_address_types, [T || <<T:16>> <= V]}};
param(?P_ECN, <<>>) ->
    {ok, ecn_capable};
param(?P_ZERO_CHECKSUM, <<Edmid:32>>) ->
    {ok, {zero_checksum_acceptable, Edmid}};
param(?P_PADDING, V) ->
    {ok, {padding, byte_size(V)}};
param(?P_EXTENSIONS, V) ->
    {ok, {supported_extensions, binary_to_list(V)}};
param(?P_FORWARD_TSN, <<>>) ->
    {ok, forward_tsn_supported};
param(T, _V) when
    T =:= ?P_IPV4;
    T =:= ?P_IPV6;
    T =:= ?P_PRESERVATIVE;
    T =:= ?P_ADDR_TYPES;
    T =:= ?P_ECN;
    T =:= ?P_ZERO_CHECKSUM;
    T =:= ?P_FORWARD_TSN
->
    {error, {bad_param, T}};
param(T, V) ->
    {ok, {unknown_param, T, V}}.

param_tlv({ipv4_address, {A, B, C, D}}) ->
    tlv(?P_IPV4, <<A, B, C, D>>);
param_tlv({ipv6_address, {A, B, C, D, E, F, G, H}}) ->
    tlv(?P_IPV6, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>);
param_tlv({state_cookie, V}) ->
    tlv(?P_COOKIE, V);
param_tlv({unrecognized_param, V}) ->
    tlv(?P_UNRECOGNIZED, V);
param_tlv({cookie_preservative, Ms}) ->
    tlv(?P_PRESERVATIVE, <<(u32(Ms)):32>>);
param_tlv({host_name, V}) ->
    tlv(?P_HOST_NAME, V);
param_tlv({supported_address_types, Ts}) ->
    tlv(?P_ADDR_TYPES, u16_list(Ts));
param_tlv(ecn_capable) ->
    tlv(?P_ECN, <<>>);
param_tlv({zero_checksum_acceptable, Edmid}) ->
    tlv(?P_ZERO_CHECKSUM, <<(u32(Edmid)):32>>);
param_tlv({padding, N}) ->
    tlv(?P_PADDING, binary:copy(<<0>>, N));
param_tlv({supported_extensions, Types}) ->
    tlv(?P_EXTENSIONS, list_to_binary(Types));
param_tlv(forward_tsn_supported) ->
    tlv(?P_FORWARD_TSN, <<>>);
param_tlv({unknown_param, T, V}) ->
    tlv(T, V).

%%====================================================================
%% RE-CONFIG parameters
%%====================================================================

%% @doc Decode the parameters of a RE-CONFIG chunk.
-spec decode_reconf_params(binary()) -> {ok, [reconf_param()]} | {error, error_reason()}.
decode_reconf_params(Bin) when is_binary(Bin) ->
    decode_tlvs(Bin, bad_param, fun reconf/2).

%% @doc Encode RE-CONFIG parameters, each one padded.
-spec encode_reconf_params([reconf_param()]) -> binary().
encode_reconf_params(Params) ->
    <<<<(pad(reconf_tlv(P)))/binary>> || P <- Params>>.

reconf(?R_OUT_RESET, <<Req:32, Resp:32, Last:32, Sids/binary>>) when
    byte_size(Sids) rem 2 =:= 0
->
    {ok, {out_reset, Req, Resp, Last, [S || <<S:16>> <= Sids]}};
reconf(?R_IN_RESET, <<Req:32, Sids/binary>>) when byte_size(Sids) rem 2 =:= 0 ->
    {ok, {in_reset, Req, [S || <<S:16>> <= Sids]}};
reconf(?R_TSN_RESET, <<Req:32>>) ->
    {ok, {tsn_reset, Req}};
reconf(?R_RESPONSE, <<Resp:32, R:32>>) ->
    {ok, {reconf_response, Resp, result(R), undefined}};
reconf(?R_RESPONSE, <<Resp:32, R:32, Snd:32, Rcv:32>>) ->
    {ok, {reconf_response, Resp, result(R), {Snd, Rcv}}};
reconf(?R_ADD_OUT, <<Req:32, N:16, _:16>>) ->
    {ok, {add_out_streams, Req, N}};
reconf(?R_ADD_IN, <<Req:32, N:16, _:16>>) ->
    {ok, {add_in_streams, Req, N}};
reconf(T, _V) when T >= ?R_OUT_RESET, T =< ?R_ADD_IN ->
    {error, {bad_param, T}};
reconf(T, V) ->
    {ok, {unknown_param, T, V}}.

reconf_tlv({out_reset, Req, Resp, Last, Sids}) ->
    tlv(?R_OUT_RESET, <<(u32(Req)):32, (u32(Resp)):32, (u32(Last)):32, (u16_list(Sids))/binary>>);
reconf_tlv({in_reset, Req, Sids}) ->
    tlv(?R_IN_RESET, <<(u32(Req)):32, (u16_list(Sids))/binary>>);
reconf_tlv({tsn_reset, Req}) ->
    tlv(?R_TSN_RESET, <<(u32(Req)):32>>);
reconf_tlv({reconf_response, Resp, R, undefined}) ->
    tlv(?R_RESPONSE, <<(u32(Resp)):32, (u32(result_code(R))):32>>);
reconf_tlv({reconf_response, Resp, R, {Snd, Rcv}}) ->
    tlv(
        ?R_RESPONSE,
        <<(u32(Resp)):32, (u32(result_code(R))):32, (u32(Snd)):32, (u32(Rcv)):32>>
    );
reconf_tlv({add_out_streams, Req, N}) ->
    tlv(?R_ADD_OUT, <<(u32(Req)):32, (u16(N)):16, 0:16>>);
reconf_tlv({add_in_streams, Req, N}) ->
    tlv(?R_ADD_IN, <<(u32(Req)):32, (u16(N)):16, 0:16>>);
reconf_tlv({unknown_param, T, V}) ->
    tlv(T, V).

result(0) -> success_nothing_to_do;
result(1) -> success_performed;
result(2) -> denied;
result(3) -> error_wrong_ssn;
result(4) -> error_request_in_progress;
result(5) -> error_bad_sequence_number;
result(6) -> in_progress;
result(N) -> N.

result_code(success_nothing_to_do) -> 0;
result_code(success_performed) -> 1;
result_code(denied) -> 2;
result_code(error_wrong_ssn) -> 3;
result_code(error_request_in_progress) -> 4;
result_code(error_bad_sequence_number) -> 5;
result_code(in_progress) -> 6;
result_code(N) when is_integer(N) -> N.

%%====================================================================
%% Error causes
%%====================================================================

%% @doc Decode the error causes of an ABORT or ERROR chunk.
-spec decode_causes(binary()) -> {ok, [cause()]} | {error, error_reason()}.
decode_causes(Bin) when is_binary(Bin) ->
    decode_tlvs(Bin, bad_cause, fun cause/2).

%% @doc Encode error causes, each one padded.
-spec encode_causes([cause()]) -> binary().
encode_causes(Causes) ->
    <<<<(pad(cause_tlv(C)))/binary>> || C <- Causes>>.

cause(1, <<Sid:16, _:16>>) ->
    {ok, {invalid_stream, Sid}};
cause(2, <<N:32, Types/binary>>) when byte_size(Types) =:= 2 * N ->
    {ok, {missing_param, [T || <<T:16>> <= Types]}};
cause(3, <<Usec:32>>) ->
    {ok, {stale_cookie, Usec}};
cause(4, <<>>) ->
    {ok, out_of_resource};
cause(5, V) ->
    {ok, {unresolvable_address, V}};
cause(6, V) ->
    {ok, {unrecognized_chunk, V}};
cause(7, <<>>) ->
    {ok, invalid_mandatory_param};
cause(8, V) ->
    {ok, {unrecognized_params, V}};
cause(9, <<Tsn:32>>) ->
    {ok, {no_user_data, Tsn}};
cause(10, <<>>) ->
    {ok, cookie_while_shutting_down};
cause(11, V) ->
    {ok, {restart_new_addresses, V}};
cause(12, V) ->
    {ok, {user_abort, V}};
cause(13, V) ->
    {ok, {protocol_violation, V}};
cause(C, _V) when
    C =:= 1; C =:= 2; C =:= 3; C =:= 4; C =:= 7; C =:= 9; C =:= 10
->
    {error, {bad_cause, C}};
cause(C, V) ->
    {ok, {unknown_cause, C, V}}.

cause_tlv({invalid_stream, Sid}) ->
    tlv(1, <<(u16(Sid)):16, 0:16>>);
cause_tlv({missing_param, Types}) ->
    tlv(2, <<(length(Types)):32, (u16_list(Types))/binary>>);
cause_tlv({stale_cookie, Usec}) ->
    tlv(3, <<(u32(Usec)):32>>);
cause_tlv(out_of_resource) ->
    tlv(4, <<>>);
cause_tlv({unresolvable_address, V}) ->
    tlv(5, V);
cause_tlv({unrecognized_chunk, V}) ->
    tlv(6, V);
cause_tlv(invalid_mandatory_param) ->
    tlv(7, <<>>);
cause_tlv({unrecognized_params, V}) ->
    tlv(8, V);
cause_tlv({no_user_data, Tsn}) ->
    tlv(9, <<(u32(Tsn)):32>>);
cause_tlv(cookie_while_shutting_down) ->
    tlv(10, <<>>);
cause_tlv({restart_new_addresses, V}) ->
    tlv(11, V);
cause_tlv({user_abort, V}) ->
    tlv(12, V);
cause_tlv({protocol_violation, V}) ->
    tlv(13, V);
cause_tlv({unknown_cause, C, V}) ->
    tlv(C, V).

%%====================================================================
%% Unrecognized parameter handling
%%====================================================================

%% @doc What to do with a parameter type this endpoint does not
%% understand (RFC 9260 §3.2.1, the upper two bits of the type):
%% `00' stop processing further parameters, `01' stop and report,
%% `10' skip and continue, `11' skip, continue and report.
-spec unrecognized_param_action(u16()) -> {stop | skip, Report :: boolean()}.
unrecognized_param_action(Type) when is_integer(Type), Type >= 0, Type =< 16#FFFF ->
    case Type bsr 14 of
        0 -> {stop, false};
        1 -> {stop, true};
        2 -> {skip, false};
        3 -> {skip, true}
    end.

%%====================================================================
%% Internal
%%====================================================================

decode_tlvs(Bin, Tag, Fun) ->
    decode_tlvs(Bin, Tag, Fun, []).

decode_tlvs(<<>>, _Tag, _Fun, Acc) ->
    {ok, lists:reverse(Acc)};
decode_tlvs(<<Type:16, Len:16, Rest/binary>>, Tag, Fun, Acc) when
    Len >= 4, Len - 4 =< byte_size(Rest)
->
    VLen = Len - 4,
    <<Value:VLen/binary, Rest1/binary>> = Rest,
    case Fun(Type, Value) of
        {ok, Term} ->
            Pad = (4 - Len rem 4) rem 4,
            case Rest1 of
                <<_:Pad/binary, Rest2/binary>> ->
                    decode_tlvs(Rest2, Tag, Fun, [Term | Acc]);
                <<>> ->
                    %% Missing padding after the last TLV.
                    {ok, lists:reverse([Term | Acc])};
                _ ->
                    %% 1..3 bytes left: a partial padding.
                    {error, trailing_bytes}
            end;
        {error, _} = Error ->
            Error
    end;
decode_tlvs(<<Type:16, _/binary>> = Bin, Tag, _Fun, _Acc) when byte_size(Bin) >= 4 ->
    {error, {Tag, Type}};
decode_tlvs(_Bin, _Tag, _Fun, _Acc) ->
    {error, trailing_bytes}.

tlv(Type, Value) when byte_size(Value) =< ?MAX_VALUE ->
    <<(u16(Type)):16, (byte_size(Value) + 4):16, Value/binary>>.

pad(Bin) ->
    case byte_size(Bin) rem 4 of
        0 -> Bin;
        R -> <<Bin/binary, 0:((4 - R) * 8)>>
    end.

u16_list(L) ->
    <<<<(u16(X)):16>> || X <- L>>.

u16(X) when is_integer(X), X >= 0, X =< 16#FFFF -> X.
u32(X) when is_integer(X), X >= 0, X =< 16#FFFFFFFF -> X.
