%% @doc SRTP and SRTCP crypto contexts (RFC 3711, RFC 7714), keyed from
%% DTLS-SRTP (RFC 5764).
%%
%% == API ==
%%
%% A context protects or unprotects one direction of traffic: create one
%% for what you send and one for what you receive. Contexts are plain
%% values; every call returns the updated context, which you keep for
%% the next packet.
%%
%% ```
%% %% After the DTLS handshake, with the negotiated profile:
%% Len = webrtc_srtp:key_material_length(Profile),
%% %% export Len octets with label webrtc_srtp:exporter_label(), no context
%% {Tx, Rx} = webrtc_srtp:dtls_contexts(Profile, Material, client, #{}),
%%
%% {ok, Srtp, Tx1} = webrtc_srtp:protect_rtp(RtpPacket, Tx),
%% {ok, Rtp, Rx1} = webrtc_srtp:unprotect_rtp(SrtpPacket, Rx),
%% {ok, Srtcp, Tx2} = webrtc_srtp:protect_rtcp(RtcpCompound, Tx1),
%% {ok, Rtcp, Rx2} = webrtc_srtp:unprotect_rtcp(SrtcpPacket, Rx1).
%% '''
%%
%% Each function returns `{error, Reason}' and leaves the context
%% unchanged when the packet is refused:
%%
%% <ul>
%% <li>`malformed': not an RTP/RTCP packet, or too short for the
%%     header and tag.</li>
%% <li>`auth_failed': wrong tag (tampered packet or wrong key).</li>
%% <li>`replay': index already accepted (receive) or already used
%%     (send, which would reuse an IV).</li>
%% <li>`too_old': index behind the replay window.</li>
%% <li>`key_exhausted': 2^48 SRTP or 2^31 SRTCP indices used; the
%%     session must be rekeyed (RFC 3711 §9.2).</li>
%% <li>`too_many_streams': a packet of a new SSRC while ?MAX_RX_STREAMS
%%     SSRCs already have receive state (see `forget/2').</li>
%% </ul>
%%
%% Per-SSRC state (rollover counter, highest sequence number, replay
%% windows, SRTCP index) is created on the first packet of an SSRC that
%% passes authentication. Without cryptex only the payload is
%% encrypted: the RTP header, CSRC list and header extension are
%% authenticated in the clear (and are the AEAD associated data for
%% GCM). MKI is not supported, as
%% RFC 8827 §6.5 forbids it in WebRTC.
%%
%% Options (`new/4', `from_session_keys/3', `dtls_contexts/4'):
%%
%% <ul>
%% <li>`replay_window' (default 1024): SRTP replay window size, at
%%     least 64.</li>
%% <li>`rtcp_replay_window' (default 128): SRTCP replay window size, at
%%     least 64.</li>
%% <li>`encrypt_rtcp' (default `true'): set the SRTCP E flag and encrypt
%%     outgoing RTCP. Incoming RTCP is accepted with either flag.</li>
%% <li>`cryptex' (default `false'): encrypt the CSRC list and header
%%     extension of outgoing RTP too (RFC 9335; see `set_cryptex/2').
%%     Incoming cryptex packets are always accepted.</li>
%% </ul>
%%
%% `forget/2' drops the receive state of an SSRC (a stream that ended).
%% Its highest indices are kept, for the last ?MAX_RETIRED SSRCs
%% forgotten, so that packets sent before cannot be replayed; a stream
%% that comes back continues from them.
%%
%% Stream state helpers: `roc/3' reads the rollover counter of an SSRC,
%% `set_roc/4' sets it (a receiver joining a running stream, or keeping
%% the ROC across a rekey) and `set_rtcp_index/3' sets the next SRTCP
%% index to send. `estimate_index/3' is the RFC 3711 Appendix A index
%% estimate used for every packet.
%%
%% A context holds precomputed crypto states for the AEAD profiles: use
%% it from one process at a time.
-module(webrtc_srtp).

-include("webrtc_srtp.hrl").

-export([
    new/4,
    from_session_keys/3,
    dtls_contexts/4,
    protect_rtp/2,
    unprotect_rtp/2,
    protect_rtcp/2,
    unprotect_rtcp/2,
    profile/1,
    supported_profiles/0,
    profile_from_id/1,
    profile_id/1,
    exporter_label/0,
    key_material_length/1,
    split_dtls_keying_material/2,
    estimate_index/3,
    forget/2,
    roc/3,
    set_roc/4,
    set_rtcp_index/3,
    set_cryptex/2
]).

-export_type([ctx/0, profile/0, opts/0, error_reason/0]).

-type profile() :: webrtc_srtp_profile:profile().
-type ssrc() :: 0..16#FFFFFFFF.
-type opts() :: #{
    replay_window => pos_integer(),
    rtcp_replay_window => pos_integer(),
    encrypt_rtcp => boolean(),
    cryptex => boolean()
}.
-type error_reason() :: malformed | auth_failed | replay | too_old | key_exhausted | too_many_streams.

-record(rtp_stream, {
    roc :: non_neg_integer(),
    %% undefined until the first packet when the ROC was set by set_roc/4.
    s_l :: 0..16#FFFF | undefined,
    window :: webrtc_srtp_replay:window()
}).

-record(srtp, {
    profile :: profile(),
    rtp :: #srtp_keys{},
    rtcp :: #srtp_keys{},
    window :: pos_integer(),
    rtcp_window :: pos_integer(),
    encrypt_rtcp :: boolean(),
    %% Send with the CSRC list and header extension encrypted (RFC 9335).
    cryptex = false :: boolean(),
    rtp_tx = #{} :: #{ssrc() => #rtp_stream{}},
    rtp_rx = #{} :: #{ssrc() => #rtp_stream{}},
    %% Next SRTCP index to send, per SSRC.
    rtcp_tx = #{} :: #{ssrc() => non_neg_integer()},
    rtcp_rx = #{} :: #{ssrc() => webrtc_srtp_replay:window()},
    %% Receive state of forgotten SSRCs: the RTP rollover counter,
    %% highest sequence number and index, and the highest SRTCP index.
    retired = #{} ::
        #{ssrc() => {undefined | {non_neg_integer(), 0..16#FFFF, integer()}, undefined | integer()}},
    retired_order = queue:new() :: queue:queue(ssrc())
}).

-define(MAX_RETIRED, 1024).
-define(MAX_RX_STREAMS, 512).

-opaque ctx() :: #srtp{}.

%% Last usable indices (RFC 3711 §3.3.1, §9.2; RFC 7714 §10).
-define(MAX_RTP_INDEX, ((1 bsl 48) - 1)).
-define(MAX_RTCP_INDEX, ((1 bsl 31) - 1)).

%%====================================================================
%% Context creation
%%====================================================================

%% @doc Create a context from a master key and salt (RFC 3711 §4.3,
%% kdr = 0). Raises `badarg' on wrong key or salt length.
-spec new(profile(), binary(), binary(), opts()) -> ctx().
new(Profile, MasterKey, MasterSalt, Opts) ->
    Keys = webrtc_srtp_kdf:session_keys(Profile, MasterKey, MasterSalt),
    from_session_keys(Profile, Keys, Opts).

%% @doc Create a context from already derived session keys, as returned
%% by `webrtc_srtp_kdf:session_keys/3'. Used for test vectors that are
%% given as session keys (RFC 7714 §16, §17).
-spec from_session_keys(profile(), webrtc_srtp_kdf:session_keys(), opts()) -> ctx().
from_session_keys(Profile, Keys, Opts) when is_map(Opts) ->
    #{transform := T, rtp_tag_len := RtpTL, rtcp_tag_len := RtcpTL} =
        webrtc_srtp_profile:params(Profile),
    #{
        rtp_key := RK,
        rtp_salt := RS,
        rtp_auth_key := RA,
        rtcp_key := CK,
        rtcp_salt := CS,
        rtcp_auth_key := CA
    } = Keys,
    #srtp{
        profile = Profile,
        rtp = webrtc_srtp_cipher:keys(T, RK, RS, RA, RtpTL),
        rtcp = webrtc_srtp_cipher:keys(T, CK, CS, CA, RtcpTL),
        window = window_opt(replay_window, 1024, Opts),
        rtcp_window = window_opt(rtcp_replay_window, 128, Opts),
        encrypt_rtcp = bool_opt(encrypt_rtcp, true, Opts),
        cryptex = bool_opt(cryptex, false, Opts)
    }.

bool_opt(Key, Default, Opts) ->
    case maps:get(Key, Opts, Default) of
        B when is_boolean(B) -> B;
        Other -> erlang:error({badarg, {Key, Other}})
    end.

%% @doc Send the next packets with or without cryptex (RFC 9335), once
%% both sides announced it. Receiving accepts both forms.
-spec set_cryptex(boolean(), ctx()) -> ctx().
set_cryptex(On, #srtp{} = C) when is_boolean(On) ->
    C#srtp{cryptex = On}.

%% @doc Build the outbound and inbound contexts from DTLS-SRTP keying
%% material (RFC 5764 §4.2). `Role' is the local DTLS role: a client
%% sends with the client write key and receives with the server one.
-spec dtls_contexts(profile(), binary(), client | server, opts()) ->
    {Outbound :: ctx(), Inbound :: ctx()}.
dtls_contexts(Profile, Material, Role, Opts) ->
    {CK, CS, SK, SS} = webrtc_srtp_profile:split_keying_material(Profile, Material),
    Client = new(Profile, CK, CS, Opts),
    Server = new(Profile, SK, SS, Opts),
    case Role of
        client -> {Client, Server};
        server -> {Server, Client}
    end.

window_opt(Key, Default, Opts) ->
    case maps:get(Key, Opts, Default) of
        N when is_integer(N), N >= 64 -> N;
        Other -> erlang:error({badarg, {Key, Other}})
    end.

-spec profile(ctx()) -> profile().
profile(#srtp{profile = P}) -> P.

%%====================================================================
%% Profiles and keying (delegated to webrtc_srtp_profile)
%%====================================================================

-spec supported_profiles() -> [profile()].
supported_profiles() -> webrtc_srtp_profile:supported().

-spec profile_from_id(0..65535 | <<_:16>>) -> {ok, profile()} | {error, unsupported_profile}.
profile_from_id(Id) -> webrtc_srtp_profile:from_id(Id).

-spec profile_id(profile()) -> 0..65535.
profile_id(Profile) -> webrtc_srtp_profile:id(Profile).

-spec exporter_label() -> binary().
exporter_label() -> webrtc_srtp_profile:exporter_label().

-spec key_material_length(profile()) -> pos_integer().
key_material_length(Profile) -> webrtc_srtp_profile:key_material_length(Profile).

-spec split_dtls_keying_material(profile(), binary()) ->
    {ClientKey :: binary(), ClientSalt :: binary(), ServerKey :: binary(), ServerSalt :: binary()}.
split_dtls_keying_material(Profile, Bin) ->
    webrtc_srtp_profile:split_keying_material(Profile, Bin).

%%====================================================================
%% SRTP
%%====================================================================

-spec protect_rtp(binary(), ctx()) -> {ok, binary(), ctx()} | {error, error_reason()}.
protect_rtp(Packet, #srtp{rtp_tx = Tx} = C) when is_binary(Packet) ->
    case rtp_header(Packet) of
        {ok, HdrLen, Seq, SSRC} ->
            maybe
                {ok, V, Index, S} ?= rtp_index(SSRC, Seq, Tx, C#srtp.window),
                {ok, Out} ?= protect(Packet, HdrLen, SSRC, Index, C),
                {ok, Out, C#srtp{rtp_tx = Tx#{SSRC => advance(S, V, Seq, Index)}}}
            end;
        error ->
            {error, malformed}
    end;
protect_rtp(_, #srtp{}) ->
    {error, malformed}.

-spec unprotect_rtp(binary(), ctx()) -> {ok, binary(), ctx()} | {error, error_reason()}.
unprotect_rtp(Packet, #srtp{rtp = Keys} = C) when is_binary(Packet) ->
    case rtp_header(Packet) of
        {ok, HdrLen, Seq, SSRC} when byte_size(Packet) >= HdrLen + Keys#srtp_keys.tag_len ->
            Rx = revive_rtp(SSRC, C),
            maybe
                ok ?= room(SSRC, Rx),
                {ok, V, Index, S} ?= rtp_index(SSRC, Seq, Rx, C#srtp.window),
                {ok, Plain} ?= unprotect(Packet, HdrLen, SSRC, Index, Keys),
                {ok, Plain, C#srtp{rtp_rx = Rx#{SSRC => advance(S, V, Seq, Index)}}}
            end;
        _ ->
            {error, malformed}
    end;
unprotect_rtp(_, #srtp{}) ->
    {error, malformed}.

protect(Packet, HdrLen, SSRC, Index, #srtp{rtp = Keys, cryptex = Cryptex}) ->
    case Cryptex andalso cryptex_parts(Packet) of
        {ok, Parts} ->
            webrtc_srtp_cipher:rtp_protect_cryptex(Keys, SSRC, Index, Parts);
        _ ->
            <<Hdr:HdrLen/binary, Payload/binary>> = Packet,
            webrtc_srtp_cipher:rtp_protect(Keys, SSRC, Index, Hdr, Payload)
    end.

%% A receiver recognises cryptex by the extension profile (RFC 9335
%% §6.3).
unprotect(<<_:3, 1:1, CC:4, _/binary>> = Packet, HdrLen, SSRC, Index, Keys) ->
    Off = 12 + CC * 4,
    case Packet of
        <<_:Off/binary, Profile:16, _/binary>> when Profile =:= 16#C0DE; Profile =:= 16#C2DE ->
            webrtc_srtp_cipher:rtp_unprotect_cryptex(Keys, SSRC, Index, Packet, CC);
        _ ->
            webrtc_srtp_cipher:rtp_unprotect(Keys, SSRC, Index, Packet, HdrLen)
    end;
unprotect(Packet, HdrLen, SSRC, Index, Keys) ->
    webrtc_srtp_cipher:rtp_unprotect(Keys, SSRC, Index, Packet, HdrLen).

%% The parts of a packet that cryptex encrypts (RFC 9335 §5): CSRCs
%% without an extension get an empty one; extensions other than the
%% one-byte and two-byte forms (RFC 8285) are sent as plain SRTP, like
%% packets with neither CSRCs nor extensions.
cryptex_parts(<<B0, Fixed:11/binary, Rest/binary>>) ->
    CL = (B0 band 16#0F) * 4,
    case {B0 band 16#10, Rest} of
        {0, _} when CL =:= 0 ->
            none;
        {0, <<C:CL/binary, P/binary>>} ->
            {ok, {<<(B0 bor 16#10), Fixed/binary>>, C, <<16#C0DE:16, 0:16>>, <<>>, P}};
        {16#10, <<C:CL/binary, Profile:16, Len:16, E:Len/binary-unit:32, P/binary>>} ->
            case Profile of
                16#BEDE -> {ok, {<<B0, Fixed/binary>>, C, <<16#C0DE:16, Len:16>>, E, P}};
                16#1000 -> {ok, {<<B0, Fixed/binary>>, C, <<16#C2DE:16, Len:16>>, E, P}};
                _ -> none
            end;
        _ ->
            none
    end.

%% Fixed header, CSRC list and header extension (RFC 3550 §5.1, §5.3.1).
rtp_header(<<2:2, _P:1, X:1, CC:4, _M:1, _PT:7, Seq:16, _TS:32, SSRC:32, Rest/binary>>) ->
    CsrcLen = CC * 4,
    case Rest of
        <<_:CsrcLen/binary, _/binary>> when X =:= 0 ->
            {ok, 12 + CsrcLen, Seq, SSRC};
        <<_:CsrcLen/binary, _Profile:16, Words:16, Ext/binary>> when
            X =:= 1, byte_size(Ext) >= Words * 4
        ->
            {ok, 12 + CsrcLen + 4 + Words * 4, Seq, SSRC};
        _ ->
            error
    end;
rtp_header(_) ->
    error.

%% Index of a packet for an SSRC. A new SSRC starts with ROC = 0 and
%% s_l = SEQ (RFC 3711 §3.3.1). The returned stream is the state before
%% the packet; it is advanced only once the packet has been processed.
rtp_index(SSRC, Seq, Streams, WindowSize) ->
    case Streams of
        #{SSRC := #rtp_stream{roc = ROC, s_l = undefined} = S} ->
            case ROC * 65536 + Seq of
                Index when Index > ?MAX_RTP_INDEX -> {error, key_exhausted};
                Index -> {ok, ROC, Index, S}
            end;
        #{SSRC := #rtp_stream{roc = ROC, s_l = SL, window = W} = S} ->
            {V, Index} = estimate_index(Seq, ROC, SL),
            if
                Index < 0 ->
                    {error, too_old};
                Index > ?MAX_RTP_INDEX ->
                    {error, key_exhausted};
                true ->
                    case webrtc_srtp_replay:check(Index, W) of
                        ok -> {ok, V, Index, S};
                        {error, _} = E -> E
                    end
            end;
        #{} ->
            W = webrtc_srtp_replay:new(WindowSize),
            {ok, 0, Seq, #rtp_stream{roc = 0, s_l = Seq, window = W}}
    end.

%% @doc Estimate the packet index from SEQ, the rollover counter and the
%% highest sequence number seen, s_l (RFC 3711 §3.3.1, Appendix A).
%% Returns the chosen ROC value v (ROC - 1, ROC or ROC + 1) and
%% i = 2^16 * v + SEQ. v is not reduced modulo 2^32: a negative index
%% lies before the start of the stream and an index of 2^48 or more
%% means the key is exhausted.
-spec estimate_index(0..16#FFFF, non_neg_integer(), 0..16#FFFF) -> {integer(), integer()}.
estimate_index(Seq, ROC, SL) ->
    V =
        if
            SL < 32768, Seq - SL > 32768 -> ROC - 1;
            SL < 32768 -> ROC;
            SL - 32768 > Seq -> ROC + 1;
            true -> ROC
        end,
    {V, V * 65536 + Seq}.

%% ROC and s_l update rule of RFC 3711 §3.3.1, plus the replay list.
advance(#rtp_stream{s_l = undefined, window = W} = S, _V, Seq, Index) ->
    S#rtp_stream{s_l = Seq, window = webrtc_srtp_replay:update(Index, W)};
advance(#rtp_stream{roc = ROC, s_l = SL, window = W} = S, V, Seq, Index) ->
    W1 = webrtc_srtp_replay:update(Index, W),
    if
        V =:= ROC + 1 -> S#rtp_stream{roc = V, s_l = Seq, window = W1};
        V =:= ROC, Seq > SL -> S#rtp_stream{s_l = Seq, window = W1};
        true -> S#rtp_stream{window = W1}
    end.

%% @doc Rollover counter of an SSRC in the send (`tx') or receive (`rx')
%% direction.
-spec roc(tx | rx, ssrc(), ctx()) -> {ok, non_neg_integer()} | error.
roc(Dir, SSRC, #srtp{} = C) ->
    case rtp_streams(Dir, C) of
        #{SSRC := #rtp_stream{roc = ROC}} -> {ok, ROC};
        #{} -> error
    end.

%% @doc Set the rollover counter of an SSRC and reset its sequence and
%% replay state; s_l is taken from the next packet. Use it to join a
%% session whose ROC is signaled out of band, or to keep the ROC across
%% a rekey (RFC 3711 §3.3.1).
-spec set_roc(tx | rx, ssrc(), 0..16#FFFFFFFF, ctx()) -> ctx().
set_roc(Dir, SSRC, ROC, #srtp{window = Size} = C) when
    is_integer(SSRC), SSRC >= 0, SSRC =< 16#FFFFFFFF, is_integer(ROC), ROC >= 0, ROC =< 16#FFFFFFFF
->
    S = #rtp_stream{roc = ROC, s_l = undefined, window = webrtc_srtp_replay:new(Size)},
    case Dir of
        tx -> C#srtp{rtp_tx = (C#srtp.rtp_tx)#{SSRC => S}};
        rx -> C#srtp{rtp_rx = (C#srtp.rtp_rx)#{SSRC => S}}
    end.

%% @doc Set the next SRTCP index sent for an SSRC. The index must keep
%% increasing across a rekey (RFC 3711 §3.4); 2^31 means exhausted.
-spec set_rtcp_index(ssrc(), 0..16#80000000, ctx()) -> ctx().
set_rtcp_index(SSRC, Index, #srtp{rtcp_tx = Tx} = C) when
    is_integer(SSRC),
    SSRC >= 0,
    SSRC =< 16#FFFFFFFF,
    is_integer(Index),
    Index >= 0,
    Index =< ?MAX_RTCP_INDEX + 1
->
    C#srtp{rtcp_tx = Tx#{SSRC => Index}}.

%% @doc Drop the receive state (RTP and RTCP) of an SSRC. Packets of
%% that SSRC are accepted again only with higher indices than seen.
-spec forget(ssrc(), ctx()) -> ctx().
forget(SSRC, #srtp{rtp_rx = Rx, rtcp_rx = RRx} = C) ->
    Rtp =
        case Rx of
            #{SSRC := #rtp_stream{s_l = undefined}} -> undefined;
            #{SSRC := #rtp_stream{roc = ROC, s_l = SL, window = W}} -> {ROC, SL, webrtc_srtp_replay:top(W)};
            #{} -> undefined
        end,
    Rtcp =
        case RRx of
            #{SSRC := RW} -> webrtc_srtp_replay:top(RW);
            #{} -> undefined
        end,
    C1 = C#srtp{rtp_rx = maps:remove(SSRC, Rx), rtcp_rx = maps:remove(SSRC, RRx)},
    case {Rtp, Rtcp} of
        {undefined, undefined} -> C1;
        _ -> retire(SSRC, {Rtp, Rtcp}, C1)
    end.

retire(SSRC, Entry, #srtp{retired = R, retired_order = Q} = C) ->
    Q1 =
        case maps:is_key(SSRC, R) of
            true -> Q;
            false -> queue:in(SSRC, Q)
        end,
    trim_retired(C#srtp{retired = R#{SSRC => Entry}, retired_order = Q1}).

trim_retired(#srtp{retired = R, retired_order = Q} = C) when map_size(R) > ?MAX_RETIRED ->
    {{value, Old}, Q1} = queue:out(Q),
    trim_retired(C#srtp{retired = maps:remove(Old, R), retired_order = Q1});
trim_retired(C) ->
    C.

%% A forgotten SSRC continues from its last indices, every earlier
%% index counting as received.
revive_rtp(SSRC, #srtp{rtp_rx = Rx, retired = R, window = Size}) ->
    case {Rx, R} of
        {#{SSRC := _}, _} ->
            Rx;
        {#{}, #{SSRC := {{ROC, SL, Top}, _}}} ->
            Rx#{SSRC => #rtp_stream{roc = ROC, s_l = SL, window = webrtc_srtp_replay:seen(Size, Top)}};
        {#{}, _} ->
            Rx
    end.

rtp_streams(tx, #srtp{rtp_tx = Tx}) -> Tx;
rtp_streams(rx, #srtp{rtp_rx = Rx}) -> Rx.

%%====================================================================
%% SRTCP
%%====================================================================

-spec protect_rtcp(binary(), ctx()) -> {ok, binary(), ctx()} | {error, error_reason()}.
protect_rtcp(<<2:2, _:6, _PT:8, _Len:16, SSRC:32, _/binary>> = Packet, #srtp{} = C) ->
    #srtp{rtcp = Keys, rtcp_tx = Tx, encrypt_rtcp = Encrypt} = C,
    Index = maps:get(SSRC, Tx, 0),
    if
        Index > ?MAX_RTCP_INDEX ->
            {error, key_exhausted};
        true ->
            maybe
                {ok, Out} ?= webrtc_srtp_cipher:rtcp_protect(Keys, SSRC, Index, Encrypt, Packet),
                {ok, Out, C#srtp{rtcp_tx = Tx#{SSRC => Index + 1}}}
            end
    end;
protect_rtcp(_, #srtp{}) ->
    {error, malformed}.

-spec unprotect_rtcp(binary(), ctx()) -> {ok, binary(), ctx()} | {error, error_reason()}.
unprotect_rtcp(Packet, #srtp{rtcp = Keys} = C) when is_binary(Packet) ->
    TL = Keys#srtp_keys.tag_len,
    case Packet of
        <<2:2, _:6, _PT:8, _Len:16, SSRC:32, _/binary>> when byte_size(Packet) >= 12 + TL ->
            Index = srtcp_index(Keys, Packet),
            #srtp{rtcp_rx = Rx, rtcp_window = Size} = C,
            W =
                case {Rx, C#srtp.retired} of
                    {#{SSRC := W0}, _} -> W0;
                    {#{}, #{SSRC := {_, Top}}} when is_integer(Top) -> webrtc_srtp_replay:seen(Size, Top);
                    {#{}, _} -> webrtc_srtp_replay:new(Size)
                end,
            maybe
                ok ?= room(SSRC, Rx),
                ok ?= webrtc_srtp_replay:check(Index, W),
                {ok, Plain} ?= webrtc_srtp_cipher:rtcp_unprotect(Keys, SSRC, Index, Packet),
                W1 = webrtc_srtp_replay:update(Index, W),
                {ok, Plain, C#srtp{rtcp_rx = Rx#{SSRC => W1}}}
            end;
        _ ->
            {error, malformed}
    end;
unprotect_rtcp(_, #srtp{}) ->
    {error, malformed}.

room(SSRC, Rx) when is_map_key(SSRC, Rx); map_size(Rx) < ?MAX_RX_STREAMS -> ok;
room(_, _) -> {error, too_many_streams}.

%% The E flag and index word sits before the tag for AES-CM
%% (RFC 3711 §3.4) and at the very end for GCM (RFC 7714 §17).
srtcp_index(#srtp_keys{transform = cm, tag_len = TL}, Packet) ->
    Skip = byte_size(Packet) - TL - 4,
    <<_:Skip/binary, _E:1, Index:31, _/binary>> = Packet,
    Index;
srtcp_index(#srtp_keys{transform = gcm}, Packet) ->
    Skip = byte_size(Packet) - 4,
    <<_:Skip/binary, _E:1, Index:31>> = Packet,
    Index.
