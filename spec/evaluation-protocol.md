# Evaluation protocol, controls, and measurement boundaries

This document preserves the experimental details moved from Appendix C.
The current reproduction session is `results/reproduction-20261114T094651Z/`.
Its `internet/` subtree contains the connection, functional, public-CA, and
complete API/robustness suites; `certificate-change/` contains independently
audited renewal/rekey observations. Functional lifecycle and cross-app cases are detailed in
[evaluation-scenarios.md](evaluation-scenarios.md).

## 1. Cohort and evidence

The reported cohort uses the ASPin-flashed Pixel 8, Wi-Fi Internet, and a remote
HTTPS endpoint. Policies were regenerated, experiment APKs rebuilt, and the
connection, lifecycle, cross-app, public-CA, and API/robustness suites rerun for
that cohort. The certificate-change suite uses the same flashed image and
Internet endpoint, with its own token pair, APKs, raw data, and evidence index.
No observations from earlier sessions enter the tables or summaries.
Raw observations, per-case request audits, public JWS fixtures, APK hashes,
and `evidence-sha256.json` identify the evidence. The same `api-robustness/`
session supplies the complete cached-API matrix and ordinary reboot/clock
observations. Selected driver sources, build configuration, and public inputs
are retained byte-for-byte in `source-snapshot/`, not represented by hashes
alone. The strict source-snapshot audit checks the complete recorded inventory.

The active app sources no longer contain the unused manual SCP/DCP verifiers,
app-side JWS verification stack, or old UI microbenchmarks. They retain the
OS client, CertClaimCheck, native TLS, and current experiment entry points.
The freshly rerun SCP/DCP observations use dedicated NSC APKs and native
trust-manager integration. The primary and compatible ASPin paths use
the OS service rather than an app-side policy-signature verifier.
The current cohort's 264-file source snapshot excludes those legacy
implementations. Only the latest complete experiment session is retained in
the project; its source snapshots and raw observations remain immutable.

Before testing, the reproduction runner verifies the installed system-partition
prefix against the local image SHA-256 and checks seven runtime component
hashes. It also archives changed AOSP sources and the patch bundle. This binds
measurements to the preserved image and selected sources; it is not a signed
build attestation or a reproducible rebuild of every toolchain byte. DNS uses
the explicitly requested `8.8.8.8` resolver, reapplied at preflights after
reboots. IP configuration and native certificate checks are unchanged.

The remote functional suite contains 98 observations, 49 per ASPin mode, with
95 matching request audits and three claim-only rollback refusals. Independent
checks re-evaluate four expiration bounds, two staging intervals, and the
replacement manifest root's lower-issuance-time namespace. Network failures
cannot count as policy rejections. The harness retains exact failure
classifications and per-case application-request audits; claim-only probes
invoke no business connection.

The documented consistency/audit commands do not perform device measurements:

```sh
python3 summarize-internet-evaluation.py results/reproduction-20261114T094651Z/internet --check-paper
python3 summarize-certificate-change-results.py results/reproduction-20261114T094651Z/certificate-change --check-paper
python3 check-implementation-consistency.py
python3 -m unittest test_internet_evaluation.py
```

See the repository README for the background-service build, full Internet
workflow, and independent cached-API completion workflow. The commands above
audit existing observations without rerunning measurements.

## 2. Prototype integration

The ASPin service resolves installed-app roots and manages policy state. The
independent DCP baseline extends Android Network Security Configuration (NSC).
Android's host-aware `checkServerTrusted` supplies the exact ordered path
accepted by the native trust manager to `CertClaimCheck`. A path, hostname,
or claim failure aborts the handshake. The API returns `exp_f` but does not
control TLS itself; the HTTPS layer performs hostname verification before
connection use or data.

Every latency artifact has one signature. The implementation accepts a
nonempty General JWS `T_k` signature array without a fixed count limit, while
retaining the 1 MiB response bound and single-signature `T_c` profile.
Context-key filtering searches for the selected owner's signature; lineage
transfer also searches for the required previous-key signature over the same
payload. Extracted-service host regressions accept up to 64 entries and verify
old-key lookup beyond entry two. Separate device functional cases exercise
four entries; those are not multi-signature latency measurements.

### Signature profiles

| Label | Key | Signature, digest, and parameters |
| --- | --- | --- |
| PS256 | 3,072-bit RSA | RSASSA-PSS, SHA-256, MGF1 with SHA-256, 32-byte salt |
| PS384 | 4,096-bit RSA | RSASSA-PSS, SHA-384, MGF1 with SHA-384, 48-byte salt |
| ES256 | P-256 | ECDSA with SHA-256 |
| ES384 | P-384 | ECDSA with SHA-384 |

RSASSA-PSS is Rivest-Shamir-Adleman Signature Scheme with Appendix-
Probabilistic Signature Scheme; ECDSA is Elliptic Curve Digital Signature
Algorithm; SHA is Secure Hash Algorithm; MGF1 is Mask Generation Function 1.
MGF1 uses the corresponding signature digest and PSS uses a digest-length
salt. The implementation adds no RSA-size floor beyond provider acceptance;
production profiles should define one. The tested profile follows the
algorithms cited in the paper, rather than treating JWS as a cryptographic
algorithm in its own right.

Issuer identifiers accept `sha256` or `sha384`; generation defaults to
`sha256`. Protected-header `kid` is unpadded base64url of SHA-256 over the
verification key's DER-encoded X.509 SubjectPublicKeyInfo (SPKI).

### Retrieval and state controls

The lookup hostname is untrusted egress input. The prototype bounds requests,
rejects redirects, resolves once, rejects mixed/special-use DNS answers, and
connects without a proxy to a validated numeric address while retaining the
HTTP `Host`. This prevents a second DNS resolution. A debug-only forced-refresh
diagnostic allows special-use destinations, but that exemption is not exercised
by the Internet cohort. Caller attribution, isolation, and rate limits remain
production concerns.

Forced refresh is debug-only and exercises retrieval, parsing, verification,
rollback checks, and persistent commit. Ordinary calls use cache when possible.
Unreadable persistent state fails closed. Android wall-clock time and
service-private `AtomicFile` are not rollback-resistant time or protected state.
Tests of issuance and expiration wait for the clock to reach signed boundaries;
lifecycle probes never advance time to bypass a wait.

## 3. Baseline fairness

All configurations use the same flashed device, HTTPS endpoint, presented
certificate, native trust anchors, and native trust manager. No measured path
uses a permissive trust manager. SCP and DCP apply supplementary checks through
NSC; ASPin applies its claim check to the native-validated path. Native TLS is
the supplementary-check-free control. Each measured attempt creates a new
connection and scheme-specific TLS context.

| Configuration | Supplementary policy | State and key source |
| --- | --- | --- |
| SCP | Bundled legitimate-leaf SPKI pin | Standard NSC static pin-set |
| Reduced independent DCP | Signed hostname-bound leaf-SPKI policy | Manifest verification key, signed issuance/expiration, in-process cache; no ASPin calls |
| Primary ASPin | Direct-issuer CA-certificate policy | Installed app-signing root and ASPin lifecycle |
| Compatible ASPin | Direct-issuer CA-certificate policy | Authenticated manifest root and ASPin lifecycle |

The DCP baseline is reduced, not a complete DCP lifecycle implementation. It
checks signed issuance and expiration but maintains no anti-rollback state.
The saved device experiments do not separately test DCP freshness or rollback
handling; the ASPin expiration and replay results do not validate DCP. Host
regressions exercise the DCP verifier's expiration and future-issuance checks,
not end-to-end device behavior. The baseline has no ASPin delegation, lineage
merge, or installed-target resolver. These policies are not security-equivalent.
An unchanged leaf SPKI can remain valid under SCP/DCP despite a CA
change, whereas ASPin requires issuer authorization. Leaf-key replacement
invalidates fixed SPKI policies but can leave ASPin's issuer claim unchanged.
Neither example establishes equal authorization or operator work. All reject
the controlled unauthorized-issuer profile, but that result and the number of
metadata transfers do not establish a general security or cost ranking. Results
for this verifier cannot establish the freshness, rollback resistance, lifecycle
guarantees, or performance of full DCP systems.

Compatible ASPin retains the installed app-signing anchor alongside the manifest
anchor, with independent state. Before compatible-mode measurement the phone
reboots to clear volatile tokens without deleting highest-seen values. Ordinary
cache hits then measure the manifest-rooted claim rather than a surviving
app-rooted claim. The phone remains awake while powered. DNS and native TLS
validation remain enabled. Every cell of the original connection matrix belongs
to the same cohort; the certificate-change experiment is identified separately.

## 4. Rogue-profile connection matrix

The controlled rogue profile uses a hostname-valid public-CA certificate whose
issuer is not authorized by the supplementary policy. It is not an actual CA
compromise. The separate public-CA chain suite uses system-roots-only APKs.

The matrix has 64 cells: four signature profiles, real/rogue certificate
profiles, native TLS and SCP once per profile, and DCP plus both ASPin modes
under hot and forced-cold policy caches. Each cell has three warmups and 20
measured attempts, for 1,280 measured attempts. The independent audit reports
acceptances, policy rejections, and transport failures separately. Network
failures remain failed observations and are never replaced or counted as
successful policy refusal; outcome-time summaries exclude those failures.

Each attempt runs the native trust manager before the ASPin, SCP, or DCP supplementary check.
Hostname verification gates connection use. A successful attempt reads the
response once and disconnects. A supplementary failure stops at rejection.
Connection/read timeouts are 15 seconds. Group order is fixed: DCP, TLS, SCP,
primary ASPin, compatible ASPin. Differences include integration and network
costs, not just cryptographic operations.

### Timing and request audits

- Hot-cache setup and three warmups are outside measured attempts. SCP's
  bundled pin does not require a metadata preload.
- Cold DCP retrieves one signed policy per handshake; cold ASPin forces both
  token downloads. The endpoint audit observes one DCP hot preload versus 23
  cold fetches per cell, including warmups, when every fetch reaches the server.
  With recorded transport failures, the auditor checks the corresponding
  bounded fetch count and the exact successful business-request tags.
- Each displayed outcome time stops after certificate checks allow the
  connection or reject it. HTTP response reading is recorded separately and
  excluded from those times.
- Every measured rejection has a scheme-specific policy error and no tagged
  business HTTP request. A transport failure is not a successful policy refusal.
- Rejection time is time to an unsuccessful connection outcome, not a speedup
  over a successful native-TLS connection.

Percentiles use the nearest-rank empirical definition. With 20 observations,
`P50` selects the lower middle value, `P95` the 19th sorted value, and `P99`
the observed maximum. These are not stable population-tail estimates. Small
samples, fixed order, uncontrolled WAN variability, no thermal controls, and
no confidence intervals preclude causal overhead or deployment-cost rankings.

## 5. Cache timings and artifact sizes

Forced-refresh totals include the API call, transfers, parsing, verification,
and commit. Service-reported `T_k` and `T_c` means are components, not additional
end-to-end measurements. DCP includes one transfer, parsing, and verification.
The cold comparison therefore includes different retrieval paths, not a
matched-operation cryptographic comparison.

Artifact sizes are serialized response-body bytes, excluding HTTP headers.
Both ASPin roots yield the same sizes for these fixtures. DCP signs one pin
policy, not a delegated two-token claim.

The complete cached-API session first authenticates policy from the remote
HTTPS endpoint. Both self and cross-app queries cover all four target profiles,
both ASPin roots, one/eight threads, and 2,000 operations per run. All 64,000
operations in 32 batches succeeded; 32 separate priming/cache-hit probes also
passed. The ES384 target uses an ES256-signed caller; the other three targets
use an ES384-signed caller, so every cross-app case has a different caller
signer. The two callers contain the same code, and independent APK-signature
checks confirm the target/caller certificates.

Each root group visits ES256, ES384, RSA-3072, and RSA-4096 in that order, with
self then cross-app batches for each target. A normal reboot between root
groups isolates volatile caches while preserving protected state. The same
session also runs the ordinary reboot and clock probes below. CSV rows record the
actual API, hostname, and target package, so an ES256 query cannot be relabeled
as a missing RSA/ES384 measurement. Server audits confirm zero business or
metadata requests during every timed batch.
The results are local OS-call costs after Internet authentication, not WAN
latency or shared-host multi-signature-filtering cost.

The paper's eight-thread table groups rows by target profile. `P99` is the
nearest-rank empirical 99th percentile and queries/s is completed operations
per measured wall time. All entries come from this one complete session rather
than mixing its cross-app cells with earlier self-query timings. Fixed order
does not isolate root-choice effects from scheduling, warmup, or thermal state.
No earlier API timing batches are used to fill missing cells.

## 6. API robustness and scope

For each mode, the suite accepts an earlier and a higher-issuance-time pair,
reboots without deleting protected state, separately replays the earlier
`T_c` and `T_k`, and checks the current pair. A separate ten-minute wall-clock
rollback places that pair before its signed issuance times, followed by time
restoration. This checks freshness, not trusted time or prevention of every
possible expired-claim resurrection. Parallel refreshes use two independently
rooted hostname contexts. The functional suite checks both token-expiration
bounds independently.

The complete API/robustness suite contains 80 cases: 32 timed cache batches,
32 priming/cache-hit probes, and 16 robustness observations. Older tokens are checked after reboot;
the not-yet-valid pair was refused after the clock rollback and accepted after
restoration. The two hostname refreshes overlapped in each mode. Each reboot,
clock-change, target-refresh, parallel-refresh, and expiration-bound probe is a
single observed run, not a latency distribution or reliability estimate.

The cohort uses one device and remote testbed. It does not measure multiple
devices, energy, operator costs, confidence intervals, thermal controls, a full
DCP lifecycle, authorized-CA compromise, or deployment-scale behavior.
Visibility provides no authorization, privacy guarantee, or quota. Reboot and
clock tests exercise ordinary paths, not privileged rollback resistance.

The bounded cached-key retry remains unmeasured. A separate isolated-link RTT
matrix is prepared but unmeasured; the WAN observations do not instantiate
those configured delays. The certificate-change suite adds 300 actual
Internet attempts across five configurations and three stages, with unchanged
Subject/SAN and exact direct-issuer DER. Both ASPin modes accept all 20 attempts
in each renewal/rekey stage with byte-identical tokens and no metadata fetches. This ES256
session does not establish behavior for every CA's renewal path or other
algorithm profiles, and its fixed-policy SCP/DCP refusals are not a full DCP
lifecycle evaluation.
