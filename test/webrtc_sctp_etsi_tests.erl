%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% The ETSI SCTP conformance tests (ETSI TS 102 369, packetdrill scripts
%% of github.com/nplab/ETSI-SCTP-Conformance-Testsuite, test/sctp_etsi),
%% run by webrtc_sctp_drill against webrtc_sctp_assoc. Where the scripts
%% differ between Linux and FreeBSD, the FreeBSD lines are used.
%%
%% Every script must pass, except those below, which must keep failing
%% for the reason given (so a change of behaviour shows up here).
-module(webrtc_sctp_etsi_tests).
-include_lib("eunit/include/eunit.hrl").

-define(NOT_RUN, #{
    "sctp-as-o-1-9-2" =>
        "A restart INIT with new IP addresses: SCTP over DTLS carries no addresses (RFC 8261 §6)",
    "sctp-rt-i-11-3" =>
        "Dual homing: SCTP over DTLS is single-homed (RFC 8261 §6)",
    "sctp-e-i-6-3" =>
        "The script puts the ERROR before the SACK; RFC 9260 §6.5 asks for the ERROR after the SACK",
    "sctp-m-i-10-1" =>
        "The script puts the ERROR before the SACK; for an unknown chunk the RFC sets no order and we keep "
        "the one of RFC 9260 §6.5",
    "sctp-at-i-2-8" =>
        "A SACK goes with the SHUTDOWN answering DATA in SHUTDOWN-SENT (as Linux does); RFC 9260 §9.2 only "
        "requires the SHUTDOWN",
    "sctp-at-i-2-9" =>
        "DATA after the peer's SHUTDOWN is acknowledged; the suite notes that discarding it is not specified",
    "sctp-d-v-8-9" =>
        "Our congestion window lets the fifth message go before the timer, so the case the script checks "
        "(a retransmission waiting with new data) does not arise"
}).

dir() -> filename:join([filename:dirname(?FILE), "sctp_etsi"]).

scripts() -> lists:sort(filelib:wildcard(filename:join([dir(), "*", "*.pkt"]))).

etsi_test_() ->
    [{filename:basename(F, ".pkt"), fun() -> check(filename:basename(F, ".pkt"), F) end} || F <- scripts()].

check(Name, File) ->
    Result = webrtc_sctp_drill:run(File),
    case maps:find(Name, ?NOT_RUN) of
        error -> ?assertEqual(ok, Result);
        {ok, _Why} -> ?assertMatch({fail, _, _}, Result)
    end.

%% Every exception names a script that exists.
exceptions_exist_test() ->
    Names = [filename:basename(F, ".pkt") || F <- scripts()],
    ?assertEqual([], [N || N <- maps:keys(?NOT_RUN), not lists:member(N, Names)]),
    ?assertEqual(115, length(Names)).
