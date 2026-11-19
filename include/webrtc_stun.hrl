%% STUN message representation (RFC 8489).
-ifndef(WEBRTC_STUN_HRL).
-define(WEBRTC_STUN_HRL, true).

-define(STUN_MAGIC_COOKIE, 16#2112A442).
-define(STUN_HEADER_SIZE, 20).
-define(STUN_FINGERPRINT_XOR, 16#5354554E).

%% Methods (RFC 8489 §18.2, RFC 8656 §17).
-define(STUN_BINDING, 16#001).
-define(TURN_ALLOCATE, 16#003).
-define(TURN_REFRESH, 16#004).
-define(TURN_SEND, 16#006).
-define(TURN_DATA, 16#007).
-define(TURN_CREATE_PERMISSION, 16#008).
-define(TURN_CHANNEL_BIND, 16#009).

-record(stun, {
    class :: webrtc_stun:class(),
    method :: webrtc_stun:method(),
    txid :: <<_:96>>,
    %% Decoded attributes, in wire order. Attributes after
    %% MESSAGE-INTEGRITY (other than MESSAGE-INTEGRITY-SHA256 and
    %% FINGERPRINT) are dropped on decode, as required by RFC 8489 §14.5.
    attrs = [] :: [webrtc_stun:attr()],
    %% Comprehension-required attribute types we do not understand.
    unknown = [] :: [non_neg_integer()]
}).

-endif.
