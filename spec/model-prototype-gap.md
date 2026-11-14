# Model assumptions and Android prototype gap

ProVerif establishes properties of the symbolic protocol under its assumptions.
It does not verify the Android source code or establish that the prototype
realizes every assumed OS guarantee. The device experiments provide evidence
for the tested paths, not a substitute for those assumptions.

## 1. Consistency of symbolic results and experimental evidence

The table compares the symbolic results with the available evidence.
*Consistent* means that observed decisions match the model in the tested cases,
not that experiments prove a universal property. *Partial* denotes narrower
coverage; *host only* excludes Android evidence. An untested entry is not a
failed test. An *assumption gap* identifies a model prerequisite that the
prototype does not fully realize. Latency and throughput have no symbolic
counterpart and are not security-consistency checks.

| Aspect | Model result or assumption | Available experimental evidence | Consistency assessment |
| --- | --- | --- | --- |
| Unauthorized direct issuer | Rogue connection and data-acceptance events are unreachable in both modes. | Each mode/configuration accepts 40 legitimate and rejects 40 controlled rogue attempts across hot/cold caches. | Consistent for both tested modes, not a universal implementation proof. |
| Token provenance | Successful $T_k/T_c$ verification implies matching signing events. | Valid device claim retrievals; host regressions verify real $T_c$ signatures under all four evaluated profiles. | Partial; not a parser or implementation proof. |
| Joint token freshness | Both tokens must be fresh; the earlier expiration bounds use. | Both modes expose the correct $exp_f$ and refuse use after either token independently expires under real-time waits. | Consistent for four bound fixtures; not trusted-clock security. |
| Highest-seen rollback state | Within each partition, $H_k/H_c$ never decrease; lower-$iat$ predecessors are rejected. | After reboot, separate lower-$iat$ $T_k$ and $T_c$ replays were rejected. | Consistent for ordinary reboot; no privileged-rollback evidence. |
| Cache isolation | Cross-owner, cross-delegated-key, and cross-claim-host cache reads are unreachable. | Cached and concurrent API queries succeeded; adversarial cache-crossing cases were not device-tested. | Partial; operation observed, isolation not established experimentally. |
| Cross-app target resolution | B's root authenticates B's policy; caller-root substitution is unreachable. | Both modes resolve B, reject caller-root substitution, and refuse missing or invisible B. | Consistent for tested cases; not concurrent package-update scheduling. |
| Shared-host multi-owner $T_k$ | List filtering preserves context-root and payload binding; co-signing alone cannot authorize lineage transfer. | Both modes accept the target's fourth-entry signature; host regressions also cover 64 entries. | Consistent for finite fixtures, not resource-exhaustion resistance. |
| Trusted time and storage | Rollback-resistant synchronized time and protected atomic state are assumed. | Android wall-clock time and service-private `AtomicFile`; neither resists privileged rollback. | Assumption gap; not established by robustness tests. |
| Certificate change | Leaf renewal and TLS-key replacement can reuse the same fresh policy. | Each mode accepts 20 connections per renewal/rekey stage with byte-identical $T_k/T_c$, unchanged Subject/SAN, and the same direct issuer CA certificate. | Consistent for the tested ES256 transitions, not a universal implementation proof. |
| Cross-signed direct issuers | Complete-set paths are accepted; omitted variants, same-name impostors, and extra-certificate bypasses are rejected. | Both modes pass 180 public-CA checks each; cross-signing occurs at ancestors, not their direct issuers. | Partial; direct-issuer variants remain model/host-only. |
| CA migration | Decisions are safe under the encoded full-$L_{\max}$ operator schedule. | Both modes pass six transition probes after at least 60 complete seconds of observed staging. | Partial; one client, not global lifetime-bound enforcement or cache drainage. |
| Claim-key rotation | One-retry success/failure is reachable; mixed pairs and below-floor acceptance are excluded. | Both modes reject mixed pairs, accept matching new pairs, and reject old-pair replay under forced refresh. | Partial; bounded cached-key retry remains unmeasured. |
| App-signing-key rotation | Dual signatures and trusted lineage permit modeled $H_k/H_c$ maximum transfer. | Android accepts a signing-lineage update; positions three/four, new-only use, and older replay have expected decisions. | Partial; not all maxima or cross-hostname transfer schedules. |
| Compatibility-mode $K_s$ | The authenticated manifest adds a root with independent state. | Both anchors work; a signed manifest-key update admits a fresh lower-$iat$ pair in its own context and excludes the old root. | Consistent for the tested update, not arbitrary installation schedules. |
| Fail-closed retrieval | With no usable policy and failed retrieval, protected connection/data events are unreachable. | Both modes pass cached-use, expiration, HTTP-503/timeout, expired-replay, and restoration cases. | Consistent conditional decisions; no availability guarantee. |

## 2. Time and persistent state

The models assume trusted, synchronized, rollback-resistant time and protected,
nondecreasing $H_k/H_c$ state with atomic updates. The prototype checks Android
wall-clock time and persists highest-seen values in a service-private
`AtomicFile`. This supports ordinary persistence and interrupted-write
handling, but not protection against privileged clock rollback or restoration
of an older valid state file. The reboot tests demonstrate ordinary state
retention. The ten-minute clock-rollback tests demonstrate rejection when the
test tokens become not-yet-valid; they do not prove that expired tokens cannot
become usable again after a different rollback. Production enforcement of the
stronger time and state assumptions remains outside this prototype, and
protected-state recovery remains future work.

## 3. Cryptography and trusted OS operations

The models assume perfect cryptography, correct native certificate validation,
authenticated target resolution, and authorized app installation and updates.
They abstract concrete JWS and X.509 parsing, certificate-path construction and
extraction, hostname normalization, hash encodings, APK formats, and native
downgrade protection. The implementation performs concrete checks, but the
symbolic proofs do not establish their correctness or resistance to
implementation flaws.

## 4. Publisher and migration assumptions

Private phase markers represent an honest operator waiting for a complete
$L_{\max}$ before the joint certificate/policy cutover. They do not implement
elapsed wall-clock time or show that clients received the overlap publication.
The prototype does not enforce the deployment-profile lifetime bound.
Nonoverlapping fresh Subject/SAN partitions for a hostname within one
policy-root collection likewise require publisher compliance. Different policy
roots may maintain independent collections for the same hostname.

## 5. Mode and lifecycle coverage

The models cover both modes and their distinct root-replacement semantics.
The fresh Internet cohort measures both modes, including API, concurrency,
and ordinary reboot/time checks after remote policy authentication. Functional
lifecycle evidence is case-specific and separate from latency measurements;
an uncompleted harness adds no experimental evidence. Neither successful
connections nor host regressions establish implementation-level
lineage-maximum correctness, and the bounded cached-key retry requires its own
device test.

## 6. Fail-closed safety versus availability

The failure outcome in the models abstracts a local retrieval timeout; network
silence does not itself generate that outcome in ProVerif. The results show
refusal when no usable policy remains and retrieval fails. Successful
restoration is a reachable trace, not a delivery or recovery guarantee. Neither
the proofs nor the device measurements establish availability under sustained
suppression.
