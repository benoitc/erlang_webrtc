%% @doc SRTP protection profiles for DTLS-SRTP (RFC 5764 §4.1.2, RFC 7714
%% §14.2) and the layout of the exported keying material (RFC 5764 §4.2).
%%
%% Only profiles allowed in WebRTC are supported: the NULL cipher
%% profiles (0x0005, 0x0006) are rejected (RFC 8827 §6.5).
%%
%% The DTLS layer uses this module to:
%%
%% <ol>
%% <li>pick a profile from the peer's `use_srtp' list with
%%     `from_id/1' and `supported/0';</li>
%% <li>export `key_material_length(Profile)' bytes with the label
%%     returned by `exporter_label/0' and an empty context;</li>
%% <li>split the result with `split_keying_material/2'.</li>
%% </ol>
-module(webrtc_srtp_profile).

-export([
    supported/0,
    from_id/1,
    id/1,
    params/1,
    exporter_label/0,
    key_material_length/1,
    split_keying_material/2
]).

-export_type([profile/0, params/0]).

-type profile() ::
    srtp_aes128_cm_hmac_sha1_80
    | srtp_aes128_cm_hmac_sha1_32
    | srtp_aead_aes_128_gcm
    | srtp_aead_aes_256_gcm.

-type params() :: #{
    id := 0..65535,
    transform := cm | gcm,
    master_key_len := pos_integer(),
    master_salt_len := pos_integer(),
    auth_key_len := non_neg_integer(),
    rtp_tag_len := pos_integer(),
    rtcp_tag_len := pos_integer()
}.

%% @doc Supported profiles in preference order. AEAD profiles come first
%% (RFC 8827 §6.5: implementations SHOULD favor AEAD).
-spec supported() -> [profile()].
supported() ->
    [
        srtp_aead_aes_128_gcm,
        srtp_aead_aes_256_gcm,
        srtp_aes128_cm_hmac_sha1_80,
        srtp_aes128_cm_hmac_sha1_32
    ].

%% @doc Map a DTLS `use_srtp' protection profile id (2 octets) to a
%% profile. Unknown and NULL cipher profiles return
%% `{error, unsupported_profile}'.
-spec from_id(0..65535 | <<_:16>>) -> {ok, profile()} | {error, unsupported_profile}.
from_id(<<Id:16>>) -> from_id(Id);
from_id(16#0001) -> {ok, srtp_aes128_cm_hmac_sha1_80};
from_id(16#0002) -> {ok, srtp_aes128_cm_hmac_sha1_32};
from_id(16#0007) -> {ok, srtp_aead_aes_128_gcm};
from_id(16#0008) -> {ok, srtp_aead_aes_256_gcm};
from_id(_) -> {error, unsupported_profile}.

-spec id(profile()) -> 0..65535.
id(Profile) ->
    maps:get(id, params(Profile)).

%% @doc Transform parameters of a profile. Lengths are in octets.
-spec params(profile()) -> params().
params(srtp_aes128_cm_hmac_sha1_80) ->
    #{
        id => 16#0001,
        transform => cm,
        master_key_len => 16,
        master_salt_len => 14,
        auth_key_len => 20,
        rtp_tag_len => 10,
        rtcp_tag_len => 10
    };
params(srtp_aes128_cm_hmac_sha1_32) ->
    %% RFC 5764 §4.1.2: 32-bit tag for SRTP, 80-bit tag for SRTCP.
    #{
        id => 16#0002,
        transform => cm,
        master_key_len => 16,
        master_salt_len => 14,
        auth_key_len => 20,
        rtp_tag_len => 4,
        rtcp_tag_len => 10
    };
params(srtp_aead_aes_128_gcm) ->
    #{
        id => 16#0007,
        transform => gcm,
        master_key_len => 16,
        master_salt_len => 12,
        auth_key_len => 0,
        rtp_tag_len => 16,
        rtcp_tag_len => 16
    };
params(srtp_aead_aes_256_gcm) ->
    #{
        id => 16#0008,
        transform => gcm,
        master_key_len => 32,
        master_salt_len => 12,
        auth_key_len => 0,
        rtp_tag_len => 16,
        rtcp_tag_len => 16
    };
params(Other) ->
    erlang:error({unsupported_profile, Other}).

%% @doc TLS exporter label for DTLS-SRTP (RFC 5764 §4.2). The context
%% value is empty.
-spec exporter_label() -> binary().
exporter_label() ->
    <<"EXTRACTOR-dtls_srtp">>.

%% @doc Number of octets to export: 2 * (master_key_len + master_salt_len).
-spec key_material_length(profile()) -> pos_integer().
key_material_length(Profile) ->
    #{master_key_len := K, master_salt_len := S} = params(Profile),
    2 * (K + S).

%% @doc Split exported keying material laid out as
%% client_key | server_key | client_salt | server_salt (RFC 5764 §4.2).
%% Raises `badarg' when the size does not match the profile.
-spec split_keying_material(profile(), binary()) ->
    {ClientKey :: binary(), ClientSalt :: binary(), ServerKey :: binary(),
        ServerSalt :: binary()}.
split_keying_material(Profile, Bin) when is_binary(Bin) ->
    #{master_key_len := K, master_salt_len := S} = params(Profile),
    case Bin of
        <<CK:K/binary, SK:K/binary, CS:S/binary, SS:S/binary>> ->
            {CK, CS, SK, SS};
        _ ->
            erlang:error(badarg, [Profile, Bin])
    end.
