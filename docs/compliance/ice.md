# ICE (RFC 8445, RFC 8863, RFC 8838, RFC 7675, RFC 8839, mDNS candidates)

This page lists the ICE requirements tracked by the stack: the agent itself (RFC 8445, full and lite), the RFC 8863 failure timer, trickle ICE (RFC 8838), consent freshness (RFC 7675), the candidate semantics of RFC 8839 and mDNS host candidates (draft-ietf-mmusic-mdns-ice-candidates with RFC 6762). Read it to know what `webrtc_ice_agent` does before relying on a behavior. Tests named `webrtc_ice_net_tests:*` run two agents over the simulated network of `test/webrtc_ice_net.erl` (fake clock, seeded loss, NATs, test STUN and TURN servers); they are eunit tests, not tests over real sockets.

## RFC 8445

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| ICE-1 | 5.1.1.1 | Host candidates from the owner's sockets, one socket per candidate | webrtc_ice_gather | webrtc_ice_net_tests:host_host_test | Unit tested |
| ICE-2 | 5.1.1.2 | Server-reflexive candidates from unauthenticated Binding requests, MAPPED-ADDRESS accepted, ALTERNATE-SERVER ignored, response must come from the server | webrtc_ice_gather | webrtc_ice_agent_tests:stun_srflx_test, webrtc_ice_net_tests:srflx_candidate_test | Unit tested |
| ICE-3 | 5.1.1.2 | Relayed candidates from TURN Allocate, server-reflexive candidate from its XOR-MAPPED-ADDRESS, relay equal to a host candidate discarded | webrtc_ice_relay | webrtc_ice_net_tests:srflx_candidate_test, symmetric_needs_relay_test | Unit tested |
| ICE-4 | 5.1.1.2 | Allocate rejected for resources (486, 508): fall back to a Binding request to the same server | webrtc_ice_relay | webrtc_ice_net_tests:turn_quota_srflx_fallback_test | Unit tested |
| ICE-5 | 5.1.1.2, 14.3 | One new gathering transaction per Ta, RTO = MAX(500 ms, Ta * number of jobs), retransmissions per RFC 8489 | webrtc_ice_gather | webrtc_ice_agent_tests:stun_timeout_completes_gathering_test | Unit tested |
| ICE-6 | 5.1.1.3 | Foundation equal iff type, base IP, server IP and transport are equal | webrtc_ice_candidate | webrtc_ice_candidate_tests:foundation_test | Unit tested |
| ICE-7 | 5.1.1.4 | Server-reflexive bindings refreshed by Binding requests every 15 s until ICE completes | webrtc_ice_gather | | Implemented, untested |
| ICE-8 | 5.1.2.1, 5.1.2.2 | Priority formula, type preferences 126 / 110 / 100 / 0, unique priorities | webrtc_ice_candidate | webrtc_ice_candidate_tests:priority_test_, prop_webrtc_ice:prop_type_preference_dominates | Unit tested |
| ICE-9 | 5.1.2.1, RFC 8421 | Unique local preferences, IPv6 head start then IPv4/IPv6 intermingled; unique per STUN/TURN server | webrtc_ice_candidate | webrtc_ice_candidate_tests:local_preferences_test, prop_webrtc_ice:prop_local_preferences_unique, webrtc_ice_net_tests:dual_stack_test | Unit tested |
| ICE-10 | 5.1.3 | Redundant candidates (same transport address and base) eliminated | webrtc_ice_candidate, webrtc_ice_gather | webrtc_ice_candidate_tests:redundant_test, webrtc_ice_agent_tests:stun_srflx_test | Unit tested |
| ICE-11 | 5.2 | Lite agent uses host candidates only | webrtc_ice_gather | webrtc_ice_net_tests:full_lite_test | Unit tested |
| ICE-12 | 5.3 | ufrag with at least 24 random bits and password with at least 128 random bits | webrtc_ice_candidate | webrtc_ice_candidate_tests:credentials_test_ | Unit tested |
| ICE-13 | 6.1.1 | Lite agent is controlled against a full peer; a full agent is controlling against a lite peer | webrtc_ice_agent | webrtc_ice_net_tests:lite_forced_controlled_test | Unit tested |
| ICE-14 | 6.1.2.2 | Pairs only within a component, address family and transport; IPv6 link-local only with link-local | webrtc_ice_candidate, webrtc_ice_checklist | webrtc_ice_candidate_tests:can_pair_test_, webrtc_ice_agent_tests:remote_candidate_family_test, webrtc_ice_net_tests:dual_stack_test | Unit tested |
| ICE-15 | 6.1.2.3 | Pair priority 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0), same on both agents | webrtc_ice_candidate | webrtc_ice_candidate_tests:pair_priority_test_, prop_webrtc_ice:prop_pair_priority_agrees, prop_pair_priority_order | Unit tested |
| ICE-16 | 6.1.2.4 | Reflexive local candidates replaced by their base, redundant pairs pruned | webrtc_ice_checklist | webrtc_ice_net_tests:full_cone_test | Unit tested |
| ICE-17 | 6.1.2.5 | Pair limit (default 100, configurable) keeping the highest priorities | webrtc_ice_checklist | webrtc_ice_agent_tests:max_pairs_test | Unit tested |
| ICE-18 | 6.1.2.6 | Initial states: one Waiting pair per foundation, others Frozen | webrtc_ice_checklist | webrtc_ice_agent_tests:freezing_test | Unit tested |
| ICE-19 | 6.1.4.2 | Every Ta: triggered queue first, else best Waiting pair, else unfreeze one pair per idle foundation | webrtc_ice_checklist, webrtc_ice_agent | webrtc_ice_agent_tests:pacing_test, prop_webrtc_ice:prop_checks_by_priority | Unit tested |
| ICE-20 | 7.1.1 | PRIORITY computed with the peer-reflexive type preference | webrtc_ice_conncheck | webrtc_ice_agent_tests:valid_check_test | Unit tested |
| ICE-21 | 7.1.2 | USE-CANDIDATE sent only by the controlling agent, ignored when received by it | webrtc_ice_conncheck, webrtc_ice_responder | webrtc_ice_agent_tests:use_candidate_ignored_when_controlling_test | Unit tested |
| ICE-22 | 7.1.3 | ICE-CONTROLLING / ICE-CONTROLLED with a 64-bit tie-breaker | webrtc_ice_conncheck | webrtc_ice_agent_tests:valid_check_test, role_conflict_test_ | Unit tested |
| ICE-23 | 7.2.1 | TURN permissions created for remote candidates before checks from a relayed candidate | webrtc_ice_relay | webrtc_ice_net_tests:symmetric_needs_relay_test | Unit tested |
| ICE-24 | 7.2.2 | USERNAME "remote:local", MESSAGE-INTEGRITY keyed with the remote password | webrtc_ice_conncheck | webrtc_ice_agent_tests:valid_check_test | Unit tested |
| ICE-25 | 7.2.4 | FINGERPRINT on every check, no RFC 3489 compatibility | webrtc_ice_conncheck | webrtc_ice_agent_tests:valid_check_test | Unit tested |
| ICE-26 | 7.2.5 | Responses matched by transaction id; without valid integrity or FINGERPRINT discarded and retransmissions go on | webrtc_ice_conncheck | webrtc_ice_agent_tests:forged_response_ignored_test | Unit tested |
| ICE-27 | 7.2.5.1 | 487: switch role, new tie-breaker, recompute priorities, pair re-queued as triggered | webrtc_ice_conncheck | webrtc_ice_agent_tests:role_conflict_response_test, webrtc_ice_net_tests:both_controlling_test, both_controlled_test | Unit tested |
| ICE-28 | 7.2.5.2.1 | Non-symmetric source or destination fails the pair | webrtc_ice_conncheck | webrtc_ice_agent_tests:spoofed_source_test | Unit tested |
| ICE-29 | 7.2.5.2.2 | ICMP errors (optional) | | | Not implemented: the owner has no way to report ICMP errors |
| ICE-30 | 7.2.5.2.3 | Transaction timeout fails the pair | webrtc_ice_conncheck | webrtc_ice_agent_tests:check_timeout_test | Unit tested |
| ICE-31 | 7.2.5.2.4 | Unrecoverable error response fails the pair | webrtc_ice_conncheck | webrtc_ice_agent_tests:error_response_fails_pair_test | Unit tested |
| ICE-32 | 7.2.5.3.1 | Unknown mapped address becomes a peer-reflexive local candidate (priority from the request, base from the pair), not signaled | webrtc_ice_conncheck | webrtc_ice_agent_tests:peer_reflexive_local_test | Unit tested |
| ICE-33 | 7.2.5.3.2 | Valid pair built from the mapped address, possibly outside the checklist | webrtc_ice_conncheck | webrtc_ice_agent_tests:peer_reflexive_local_test, webrtc_ice_net_tests:symmetric_needs_relay_test | Unit tested |
| ICE-34 | 7.2.5.3.3 | Pair and valid pair Succeeded; Frozen pairs of the foundation become Waiting | webrtc_ice_conncheck, webrtc_ice_checklist | webrtc_ice_agent_tests:trickle_states_test | Unit tested |
| ICE-35 | 7.2.5.3.4 | Successful USE-CANDIDATE check nominates; a failed one removes the pair from the valid list and fails the checklist | webrtc_ice_conncheck | webrtc_ice_net_tests:host_host_test, webrtc_ice_agent_tests:nomination_failure_test | Unit tested |
| ICE-36 | 7.2.5.4 | Checklist Failed when all pairs are done without a valid pair for each component | webrtc_ice_session | webrtc_ice_net_tests:no_working_pair_fails_test, family_mismatch_fails_test | Unit tested |
| ICE-37 | 7.3 | Requests authenticated with the short-term credential: 400 without USERNAME or MESSAGE-INTEGRITY, 401 for a wrong ufrag or integrity | webrtc_ice_responder | webrtc_ice_agent_tests:reject_test_ | Unit tested |
| ICE-38 | 7.3 | Requests before the remote credentials are answered at once and processed when the credentials arrive | webrtc_ice_responder | webrtc_ice_agent_tests:early_check_test, early_check_other_session_test | Unit tested |
| ICE-39 | 7.3 | FINGERPRINT required, ALTERNATE-SERVER never used | webrtc_ice_responder | webrtc_ice_agent_tests:no_fingerprint_dropped_test | Unit tested |
| ICE-40 | 7.3, RFC 8489 6.3.1 | 420 with UNKNOWN-ATTRIBUTES; 400 without PRIORITY or with zero or two role attributes | webrtc_ice_responder | webrtc_ice_agent_tests:reject_test_ | Unit tested |
| ICE-41 | 7.3.1.1 | Role conflict repair on received requests (487 or role switch) | webrtc_ice_responder | webrtc_ice_agent_tests:role_conflict_test_, role_conflict_code_test | Unit tested |
| ICE-42 | 7.3.1.2 | XOR-MAPPED-ADDRESS of a relayed request is the peer address seen by the TURN server | webrtc_ice_relay, webrtc_ice_responder | webrtc_ice_net_tests:symmetric_needs_relay_test | Unit tested |
| ICE-43 | 7.3.1.3 | Unknown source becomes a peer-reflexive remote candidate with the request PRIORITY, not paired | webrtc_ice_responder | webrtc_ice_agent_tests:valid_check_test | Unit tested |
| ICE-44 | 7.3.1.4 | Triggered checks: Succeeded unchanged, In-Progress cancelled and re-queued, others Waiting and queued, new pairs inserted | webrtc_ice_responder | webrtc_ice_agent_tests:valid_check_test, webrtc_ice_net_tests:late_candidates_test | Unit tested |
| ICE-45 | 7.3.1.5 | Controlled agent: USE-CANDIDATE nominates a Succeeded pair's valid pair, or the pair once its triggered check succeeds | webrtc_ice_responder | webrtc_ice_agent_tests:use_candidate_on_succeeded_pair_test, early_check_test | Unit tested |
| ICE-46 | 7.3.2 | Lite agent: USE-CANDIDATE makes the pair valid and nominated; no checks sent | webrtc_ice_responder | webrtc_ice_agent_tests:lite_test, webrtc_ice_net_tests:full_lite_test | Unit tested |
| ICE-47 | 8.1.1 | Regular nomination: the check that produced the chosen valid pair is repeated with USE-CANDIDATE, one nomination per session; policy `best` waits for better pending pairs or `nomination_timeout`, policy `first` does not | webrtc_ice_session | webrtc_ice_agent_tests:nomination_best_waits_test, nomination_first_test | Unit tested |
| ICE-48 | 8.1.1 | Several nominations from an RFC 5245 peer: the highest priority nominated pair is selected | webrtc_ice_conncheck | | Implemented, untested |
| ICE-49 | 8.1.2 | After nomination the other pairs of the component leave the checklist, in-progress checks cancelled, checklist and session Completed | webrtc_ice_conncheck | webrtc_ice_net_tests:host_host_test, host_host_stats_test | Unit tested |
| ICE-50 | 8.2 | Lite agent Completed once nominated | webrtc_ice_responder | webrtc_ice_net_tests:full_lite_test | Unit tested |
| ICE-51 | 8.2 | Lite agent against a lite peer (lite agent controlling) | | | Not implemented: both lite is not supported, a lite agent is always controlled |
| ICE-52 | 8.3 | Freeing unused candidates 3 s after completion | | | Non-compliant / known limitation: candidates are kept and checks answered for the whole session (no protocol impact, uses resources) |
| ICE-53 | 9 | Restart: new ufrag and password, all state except the role flushed, previous selected pair kept usable until the new session selects one | webrtc_ice_session | webrtc_ice_net_tests:restart_test, restart_requires_new_credentials_test | Unit tested |
| ICE-54 | 10 | `ice2` option | | | Not implemented here: advertised by the SDP layer. The agent never uses aggressive nomination |
| ICE-55 | 11 | Keepalives: Binding indication with FINGERPRINT only, when nothing was sent for Tr = 15 s, on the selected pair, when consent freshness is off and for lite agents | webrtc_ice_consent | webrtc_ice_net_tests:consent_disabled_keepalive_test | Unit tested |
| ICE-56 | 12.1 | Data on any valid pair before nomination, on the selected pair afterwards | webrtc_ice_session | webrtc_ice_agent_tests:check_success_test, webrtc_ice_net_tests:host_host_test | Unit tested |
| ICE-57 | 12.2, RFC 8826 4.2 | Non-ICE traffic accepted only from validated addresses (`is_valid_remote/3`) | webrtc_ice_session | webrtc_ice_agent_tests:valid_check_test, spoofed_source_test, webrtc_ice_net_tests:remove_host_test | Unit tested |
| ICE-58 | 14.2 | Ta default 50 ms | webrtc_ice_agent | webrtc_ice_agent_tests:pacing_test | Unit tested |
| ICE-59 | 14.2 | Ta negotiation (higher of the proposed values) | | | Not implemented: the owner passes the negotiated `ta` option |
| ICE-60 | 14.3 | Check RTO = MAX(500 ms, Ta * N * (Waiting + In-Progress)), never below 500 ms | webrtc_ice_conncheck | webrtc_ice_agent_tests:check_rto_test | Unit tested; the value is capped by `max_check_rto` (2500 ms by default), a local choice the section allows |
| ICE-61 | 19.2 | Malformed, truncated or bit-flipped checks and responses never crash the agent | webrtc_ice_agent | webrtc_ice_agent_tests:malformed_check_test_, malformed_response_test, garbage_test | Unit tested |
| ICE-62 | 2.2 | Two agents conclude on the same pair under random loss below 50% | webrtc_ice_agent | prop_webrtc_ice:prop_lossy_network_connects, webrtc_ice_net_tests:lossy_checks_test | Unit tested (the property uses Rc = 40 to make transaction failure negligible) |
| ICE-63 | 5.1.1.1, 17.1 | Host, server-reflexive, peer-reflexive and relayed paths through full cone, restricted, port-restricted and symmetric NATs, IPv4, IPv6 and dual stack | webrtc_ice_agent | webrtc_ice_net_tests:full_cone_test, restricted_test, port_restricted_test, symmetric_needs_relay_test, ipv6_only_test, dual_stack_test | Unit tested |
| ICE-65 | 19.5.1 | Per-peer state bounded: pairs (`max_pairs`), remote candidates including peer-reflexive ones (`max_remote`, 100), checks remembered before the remote credentials (64), consent transactions (30 s window); unauthenticated requests get a small unprotected error and create no state | webrtc_ice_checklist, webrtc_ice_responder | webrtc_ice_agent_tests:remote_candidate_cap_test, max_pairs_test, reject_test_ | Unit tested |
| ICE-64 | 5.1.1.4 | Network change: removing a socket removes its candidates, pairs and transactions; a lost selected pair fails the session until a restart | webrtc_ice_gather | webrtc_ice_net_tests:remove_host_test | Unit tested |

## RFC 8863

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| PAC-1 | 4 | PAC timer (39.5 s) started with the remote credentials; no checklist failure before it expires | webrtc_ice_session | webrtc_ice_net_tests:no_working_pair_fails_test, symmetric_without_turn_fails_test, family_mismatch_fails_test | Unit tested |
| PAC-2 | 4 | Controlling agent waits before nominating | webrtc_ice_session | webrtc_ice_agent_tests:nomination_best_waits_test | Unit tested; the wait is `nomination_timeout` after the first valid pair, not the PAC timer |
| PAC-3 | 5 | With trickle ICE, failure also waits for end-of-candidates, with a timer (`eoc_timeout`, PAC by default) as fallback | webrtc_ice_session | webrtc_ice_net_tests:no_eoc_waits_test, webrtc_ice_agent_tests:check_timeout_test | Unit tested |

## RFC 8838

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| TRK-1 | 7, 8 | Checklist Running while empty; candidates paired as they arrive | webrtc_ice_checklist | webrtc_ice_net_tests:late_candidates_test | Unit tested |
| TRK-2 | 8 | Failure only after local gathering completed and remote end-of-candidates | webrtc_ice_session | webrtc_ice_agent_tests:check_timeout_test, webrtc_ice_net_tests:no_eoc_waits_test | Unit tested |
| TRK-3 | 9 | New local candidates trickled as events; a redundant one ignored regardless of priority | webrtc_ice_gather | webrtc_ice_agent_tests:stun_srflx_test, webrtc_ice_net_tests:host_host_test | Unit tested |
| TRK-4 | 10, 11 | New local or remote candidates paired with the known ones, reflexive locals replaced by their base | webrtc_ice_checklist | webrtc_ice_net_tests:late_candidates_test | Unit tested |
| TRK-5 | 11 | A signaled candidate already known as peer-reflexive | webrtc_ice_agent | webrtc_ice_net_tests:late_candidates_test | Unit tested; the remote candidate takes the signaled type, priority and foundation in place and pair priorities are recomputed, instead of discarding and re-sorting pairs |
| TRK-6 | 10, 11 | Pair limit: Failed pairs dropped first, then lower priority ones | webrtc_ice_checklist | webrtc_ice_agent_tests:max_pairs_test | Unit tested |
| TRK-7 | 12 | New pair Waiting when it tops its foundation or the foundation has a Succeeded pair, Frozen otherwise | webrtc_ice_checklist | webrtc_ice_agent_tests:trickle_states_test | Unit tested |
| TRK-8 | 13 | End of local gathering reported (`{gathering_state, complete}`) for the owner to signal end-of-candidates | webrtc_ice_gather | webrtc_ice_net_tests:host_host_test | Unit tested |
| TRK-9 | 14 | Candidates received after end-of-candidates ignored | webrtc_ice_agent | webrtc_ice_net_tests:candidates_after_eoc_ignored_test | Unit tested |
| TRK-10 | 9, 15 | Candidates for another session (ufrag extension) ignored | webrtc_ice_agent | webrtc_ice_net_tests:old_generation_candidate_ignored_test | Unit tested |
| TRK-11 | 16 | Half trickle | | | Not implemented here: signaling layer |

## RFC 7675

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| CNS-1 | 5 | Consent obtained when a pair succeeds | webrtc_ice_conncheck | webrtc_ice_agent_tests:check_success_test | Unit tested |
| CNS-2 | 5.1 | No application data without consent (`send/3,4` refuses) | webrtc_ice_session | webrtc_ice_agent_tests:spoofed_source_test, webrtc_ice_net_tests:no_working_pair_fails_test | Unit tested |
| CNS-3 | 5.1 | Consent request every 5 s randomized between 0.8 and 1.2, never under 4 s, on the selected pair or the best valid pair before nomination | webrtc_ice_consent | webrtc_ice_net_tests:consent_loss_test | Unit tested |
| CNS-4 | 5.1 | New transaction id per request, sent once; a response may answer any outstanding request | webrtc_ice_consent | webrtc_ice_net_tests:consent_loss_test | Unit tested |
| CNS-5 | 5.1 | Only an authenticated success response from the remote address on the same path refreshes consent | webrtc_ice_consent | webrtc_ice_agent_tests:forged_consent_response_test | Unit tested |
| CNS-6 | 5.1 | Consent expires 30 s after the last response: transmission stops, `{consent_lost, L, R}` | webrtc_ice_consent | webrtc_ice_net_tests:consent_loss_test | Unit tested |
| CNS-7 | 5.1 | Outstanding consent transactions dropped at expiry; no consent requests or data on the lost pair afterwards, a restart is needed | webrtc_ice_consent | webrtc_ice_net_tests:consent_loss_test | Unit tested |
| CNS-8 | 5.1 | Consent kept on the previous pair during an ICE restart | webrtc_ice_consent | webrtc_ice_net_tests:restart_test | Unit tested |
| CNS-9 | 5.1 | Response wait based on RTT | | | Non-compliant / known limitation: responses are accepted until consent expires, there is no per-request window |
| CNS-10 | 5.2 | Authenticated 403 revokes consent at once | webrtc_ice_consent | webrtc_ice_agent_tests:forbidden_revokes_consent_test | Unit tested |
| CNS-11 | 4 | No Binding indication keepalives where consent requests run | webrtc_ice_consent | webrtc_ice_net_tests:consent_disabled_keepalive_test | Unit tested |
| CNS-12 | 5.1 | Lite agent (sends no requests) | webrtc_ice_consent | webrtc_ice_net_tests:lite_consent_expiry_test | Unit tested; local policy: consent of a lite agent is refreshed by the peer's authenticated checks and expires 30 s after the last one |
| CNS-13 | | `disconnected` state after `disconnect_timeout` (10 s) without a consent response, back to `completed` on the next one | webrtc_ice_session | webrtc_ice_net_tests:consent_loss_test | Unit tested (local policy) |

## RFC 8839 candidate semantics

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-1 | 5.1 | candidate-attribute: foundation of 1 to 32 ice-chars, component 1 to 256, transport, priority 1 to 2^31-1, address, port, `typ`, `raddr`/`rport`, extension pairs kept | webrtc_ice_candidate | webrtc_ice_candidate_tests:sdp_roundtrip_test_, sdp_parse_test_, prop_webrtc_ice:prop_sdp_roundtrip | Unit tested |
| SDP-2 | 5.1 | Related address of a server-reflexive candidate is its base, of a relayed candidate the mapped address | webrtc_ice_gather, webrtc_ice_relay | webrtc_ice_net_tests:srflx_candidate_test | Unit tested |
| SDP-3 | 5.1 | FQDN connection addresses: looked up AAAA then A, one address chosen (IPv6 when the transport has an IPv6 socket), the candidate ignored when nothing resolves | webrtc_mdns_client, webrtc_mdns | webrtc_mdns_client_tests:fqdn_family_choice_test, webrtc_mdns_SUITE:fqdn_candidates | E2E tested. The agent itself still takes IP literals only (`{error, {fqdn, Name}}`); the transport resolves names before handing candidates to it |
| SDP-4 | 5.1 | TCP candidates (`tcptype`) | webrtc_ice_candidate | webrtc_ice_candidate_tests:sdp_roundtrip_test_ | Non-compliant / known limitation: parsed and encoded, never paired (UDP only) |
| SDP-5 | 5.4 | ice-ufrag 4 to 256 and ice-pwd 22 to 256 ice-chars, checked on input | webrtc_ice_candidate, webrtc_ice_agent | webrtc_ice_candidate_tests:credentials_test_, webrtc_ice_net_tests:restart_requires_new_credentials_test | Unit tested |
| SDP-6 | 5.5, 5.6 | `a=ice-lite`, `a=ice-options`, `a=ice-pacing` | | | Not implemented here: SDP layer; the agent takes `lite`, `remote_lite` and `ta` options |

## mDNS candidates (draft-ietf-mmusic-mdns-ice-candidates-03, RFC 6762)

Remote `.local` candidates are resolved by the transport with one-shot multicast DNS queries; our own host candidates can be hidden behind names with the `mdns_host_candidates` option (off by default: a server usually wants to expose its address).

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| MDNS-1 | draft 3.2.1 | A remote candidate whose address is a `<uuid>.local` name is resolved with mDNS and added with the resolved address, its other fields unchanged; a name that does not resolve drops that candidate only | webrtc_mdns_client, webrtc_transport | webrtc_mdns_client_tests:mdns_resolved_and_marked_test, webrtc_mdns_SUITE:remote_mdns_candidates, webrtc_pc_interop_SUITE:chromium_mdns | Interoperability tested (Chromium) |
| MDNS-2 | draft 3.2.2 | Names that are not a version 4 UUID followed by `.local` are not resolved; a name with more than one address is ignored | webrtc_mdns_client | webrtc_mdns_client_tests:non_uuid_local_name_ignored_test, mdns_several_addresses_ignored_test | Unit tested |
| MDNS-3 | draft 3.3.2 | Relayed local candidates are never paired with remote candidates resolved from an mDNS name | webrtc_ice_candidate | webrtc_ice_candidate_tests:can_pair_test_ | Unit tested |
| MDNS-4 | RFC 8838 14 | End-of-candidates received while names resolve is applied once they are done, so late candidates are kept | webrtc_mdns_client | webrtc_mdns_client_tests:unresolved_name_and_deferred_end_of_candidates_test, webrtc_mdns_SUITE:remote_mdns_candidates | E2E tested |
| MDNS-5 | | Bounded: at most 32 candidates waiting for a name (`{error, too_many_pending}` beyond), 32 queries, 64 cached names, 8 DNS lookups; resolution never blocks the transport process | webrtc_mdns_client, webrtc_mdns, webrtc_mdns_resolver | webrtc_mdns_SUITE:pending_candidates_bounded, webrtc_mdns_resolver_tests:max_queries_test, cache_bounded_test | E2E tested |
| MDNS-6 | RFC 6762 5.1, 5.4 | One-shot queries from an ephemeral port, one question per message (A, then AAAA), QU bit on the first query, QM on the retransmissions at 250 ms and 1.25 s, failure at 3.25 s | webrtc_mdns_resolver | webrtc_mdns_resolver_tests:query_test, retransmit_then_timeout_test | Unit tested |
| MDNS-7 | RFC 6762 6.7, 18.1 | Legacy unicast answers must echo the query ID and repeat the question; multicast answers (ID ignored) are received on a group socket shared through SO_REUSEPORT | webrtc_mdns_resolver, webrtc_mdns | webrtc_mdns_resolver_tests:legacy_answer_needs_id_and_question_test, multicast_answer_test, webrtc_mdns_tests | Unit tested |
| MDNS-8 | RFC 6762 6, 11 | Only class IN A/AAAA records naming a pending question are used, from the answer and additional sections; unsolicited answers are ignored and never cached; packets from outside the local subnets are dropped | webrtc_mdns_resolver, webrtc_mdns | webrtc_mdns_resolver_tests:unsolicited_ignored_test, additional_section_test | Unit tested |
| MDNS-9 | RFC 6762 10, 10.1 | Cache honors record TTLs (capped at one hour); goodbye records (TTL 0) are not used | webrtc_mdns_resolver | webrtc_mdns_resolver_tests:legacy_unicast_answer_test, ttl_capped_test, invalid_responses_ignored_test | Unit tested |
| MDNS-10 | RFC 1035 4.1.4, RFC 6762 18 | Codec: name compression with backward pointers only (no loops), at most 64 pointers and 255 octets per name, every count and length checked, never raises | webrtc_mdns_msg | webrtc_mdns_msg_tests, prop_webrtc_parsers:prop_decoders_never_raise, prop_mdns_roundtrip | Unit tested |
| MDNS-11 | draft 3.1.1 | With `mdns_host_candidates`, each host address gets a random version 4 UUID `.local` name (same address, same name), announced without probing | webrtc_mdns_responder, webrtc_mdns_client | webrtc_mdns_client_tests:hidden_local_candidates_test, webrtc_mdns_tests:responder_answers_queries | E2E tested (webrtc_mdns_SUITE:hidden_host_candidates) |
| MDNS-12 | draft 3.1.2.2 | The related address of our other candidates becomes `0.0.0.0` or `::`, port 9 | webrtc_mdns_client | webrtc_mdns_client_tests:hidden_local_candidates_test | Unit tested |
| MDNS-13 | RFC 6762 5.4, 6, 6.7, 7.1, 10.1 | Responder: legacy queries answered by unicast with ID and question and TTL 10, QU by unicast, QM by multicast at most once per second per name, known answers suppressed, goodbye on stop | webrtc_mdns_responder | webrtc_mdns_tests:responder_* | Unit tested |
| MDNS-14 | draft 3.1.2.2 | A STUN check to learn whether a hidden address is public | | | Not implemented: with the option on, every host candidate is hidden |
| MDNS-15 | RFC 6762 6.1 | Negative (NSEC) answers for the missing address family | | | Not implemented: such questions are not answered |
| MDNS-16 | RFC 6762 5, 6 | IPv6 multicast transport (ff02::fb) | | | Not implemented: queries and answers use IPv4 multicast only (AAAA records are still asked and served); gen_udp cannot pick the outgoing interface of a link-local IPv6 multicast send |

## Notes

- Specification status checked on 2026-11-14 at rfc-editor.org: RFC 8445 is updated only by RFC 8863; RFC 8838 is updated by RFC 8863; RFC 8489, RFC 8839, RFC 8863 and RFC 7675 have no update or obsoleting document. draft-ietf-mmusic-mdns-ice-candidates-03 (December 2021) is the latest revision and is expired; browsers implement it as written.
- Chromium's responder answers only queries with a single QM question, by multicast. The first (QU) query therefore gets no answer from it; the first retransmission, 250 ms later, does.

- Integration with TURN: the agent owns one `webrtc_turn_client` per (host socket, TURN server). See docs/compliance/turn.md.
- Selection of the pair to keep after a network change is not automatic: the owner calls `restart/2,3` and signals the new credentials and candidates.
