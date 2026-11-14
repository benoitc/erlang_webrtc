%% Every externally reachable decoder returns a value or an error tuple
%% on arbitrary input, and never raises.
-module(prop_webrtc_parsers).
-include_lib("proper/include/proper.hrl").

-define(DECODERS, [
    {stun, fun webrtc_stun:decode/1},
    {stun_integrity, fun(B) -> webrtc_stun:check_integrity(B, <<"key">>) end},
    {turn_channel, fun webrtc_turn_channel:decode/1},
    {dtls_record, fun webrtc_dtls_record:decode/1},
    {dtls_fragment, fun webrtc_dtls_msg:decode_fragment/1},
    {dtls_client_hello, fun(B) -> webrtc_dtls_msg:decode_body(client_hello, B) end},
    {dtls_server_hello, fun(B) -> webrtc_dtls_msg:decode_body(server_hello, B) end},
    {dtls_certificate, fun(B) -> webrtc_dtls_msg:decode_body(certificate, B) end},
    {dtls_ske, fun(B) -> webrtc_dtls_msg:decode_body(server_key_exchange, B) end},
    {rtp, fun webrtc_rtp:decode/1},
    {rtp_ext, fun(B) -> webrtc_rtp:decode(B, #{extensions => parse}) end},
    {rtcp, fun webrtc_rtcp:decode/1},
    {sctp, fun webrtc_sctp_chunk:decode/1},
    {dcep, fun webrtc_dcep:decode/1},
    {sdp, fun webrtc_sdp:parse/1},
    {candidate, fun webrtc_sdp_candidate:parse/1},
    {demux, fun webrtc_demux:classify/1}
]).

prop_decoders_never_raise() ->
    ?FORALL(
        {Bin, Prefix},
        {binary(), oneof([<<>>, <<0, 1>>, <<128>>, <<22, 254, 253>>, <<"v=0\r\n">>, <<"candidate:">>])},
        begin
            Input = <<Prefix/binary, Bin/binary>>,
            lists:all(
                fun({Name, F}) ->
                    try
                        _ = F(Input),
                        true
                    catch
                        C:R -> io:format("~p raised ~p:~p on ~p~n", [Name, C, R, Input]), false
                    end
                end,
                ?DECODERS
            )
        end
    ).
