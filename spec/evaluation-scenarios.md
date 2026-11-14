# Functional Internet evaluation scenarios

This document retains detailed procedures moved out of Appendix C. Results
refer to `results/reproduction-20261114T062526Z/internet/` and the independently audited
`results/reproduction-20261114T062526Z/certificate-change/` subtree, not proposed
measurements. General controls and timing definitions are in
[evaluation-protocol.md](evaluation-protocol.md).

The functional suite records pass/fail observations separately from latency
distributions. It uses the remote comparison's public-CA profiles and a fixed
Subject/SAN partition. Transition claims have 60-second lifetimes. Real-time
waits retain highest-seen state and do not advance the clock to bypass expiry.
These are single-client transition observations, not enforcement of a global
lifetime ceiling or proof that an offline fleet drained its caches.

## 1. Cross-app connections

An ES256 self query supplies only its hostname. An initially differently signed
ES384 caller invokes the cross-app API with the ES256 target's package
identifier and hostname. Successful target-root verification checks that the
OS selected B's key rather than the caller's.

Both ASPin modes accept the target's fourth-entry signature, reject caller-root
substitution and the rogue issuer, and refuse a missing or invisible target
despite a primed cache. Caller and target are differently signed initially.
They share a signer after the primary app-key update; that new-only query tests
the update, not independent post-rotation isolation. Separate forced queries
and a cache-isolating reboot distinguish the installed-app and manifest
anchors. Request audits establish application-request decisions, not
packet-level non-leakage or business-access authorization.

The main functional groups include 11 target/root observations per mode and
two additional parallel-anchor observations in compatible mode. Those groups
must not be confused with the separate cached-API throughput batches.

## 2. Fail-closed availability

Metadata HTTP 503 and read-timeout faults leave the separate business TLS
control reachable. Fresh cached self and cross-app claims continue working.
An empty cache or expiration imposed separately by `T_k` and `T_c` makes
ordinary queries fail under suppression. Expired replay is refused; fresh,
nondecreasing-issuance-time artifacts restore use.

There are 22 expiration/suppression observations per mode. Four independent
bound fixtures span the two modes and both limiting tokens. Expiration and
migration probes leave the clock and protected state intact and use ordinary
retrieval from public destinations. The observations show conditional
fail-closed decisions, not availability under sustained suppression.

## 3. Certificate renewal and TLS-key replacement

### Fixture invariants

This supplementary session uses one ES256 profile, a remote public-CA HTTPS
endpoint, and the same ASPin image. Three distinct leaf certificates have
identical Subject/SAN and exactly the same direct issuer CA certificate DER.
The renewal leaf has a new serial and certificate fingerprint but the baseline
TLS SPKI; the rekey leaf has a new serial, fingerprint, and TLS SPKI. Both CSRs
and resulting certificates are retained. Native public trust, current validity,
hostname, and local private-key correspondence are checked before deployment.

The selected direct issuer is Let's Encrypt YE1. Two orders using the first
new TLS key returned YE2 instead, so those certificates fail the exact-issuer
invariant and are excluded from device testing. A second new TLS key produced
an eligible YE1 certificate. The issuance pool and unsuccessful issuer-matching
attempts remain archived. This eligibility selection occurs before device
results exist; it does not choose outcomes. The experiment does not assume
every future renewal preserves the direct CA certificate.

### Policies and device procedure

The runner generates one fresh signed `T_k` under each ASPin root and one shared
`T_c`, authorizing the exact baseline issuer and signed server identity. Every
serialized object remains byte-identical through baseline, renewal, and rekey.
Both signed intervals cover the complete run. SCP's NSC overlay pins the selected
baseline leaf SPKI, and independent NSC DCP retains an authenticated policy
pinning that same SPKI. DCP downloads its identical policy once per staged cell;
this is not a DCP pin-update experiment.

Five configurations run in fixed order: native TLS, SCP, DCP, primary ASPin,
and compatible ASPin. Each configuration visits baseline, renewal, then rekey,
with three warmups and 20 measured new TLS connections per cell. Each attempt
uses the native trust manager; no permissive trust manager is used. ASPin primes
its cache only at baseline. Subsequent cells request ordinary cached claims
without force-preloading; request audits require zero `T_k/T_c` transfers and
rows require zero token-download timings. A normal reboot before compatible
mode prevents the primary root's volatile entry from serving that group, while
preserving protected highest-seen state. The test does not model or measure
TLS resumption.

The harness temporarily changes only the existing isolated test origin's
certificate inventory and selected host profile. It verifies the endpoint's
presented leaf and immutable remote policy hashes for every cell, records
generation-tagged requests, and restores the original manifest, state, and
origin code afterward. DNS, clocks, and protected rollback state remain intact;
no app-signing, claim-signing, or manifest-root private key is uploaded.

### Observations and independent audit

All 300 measured attempts match expectations: 260 acceptances and 40 policy
rejections. All five configurations accept baseline and same-key renewal.
Native TLS and both ASPin modes accept rekeying; unchanged SCP and DCP SPKI
policies reject all 20 rekey attempts each. An updated DCP pin could accept the
new TLS key; that capability is not contradicted by these fixed-policy results.
Each ASPin mode accepts all 20 renewal and 20 rekey attempts with no metadata
fetch, supporting cached-policy continuity for this profile.

Server audits contain exactly one tagged business HTTP request per measured
acceptance and none per rejection. Warmups have separate tags and are excluded
from the 300 measurements. A network error cannot count as policy refusal.
`summarize-certificate-change-results.py` independently verifies raw rows,
signed-policy contents and freshness throughout the run, certificate
relationships, static NSC pin, request audits, and deployment restoration.
It can operate without TLS private keys. Its evidence index excludes private
keys and records public fixtures and observations. With `--check-paper` it
also checks the appendix's accepted/attempts table against the audited rows.

These are single-device, fixed-order functional observations, not latency
rankings, a deployment-availability study, or coverage of all signature
profiles. Existing CA-migration and key-rotation observations remain separate.

## 4. Public-CA and ancestor cross-sign-chain checks

### Certificate acquisition and native paths

One PKCS#10 CSR for a dedicated public hostname was submitted with identical
bytes to Let's Encrypt (LE) and ZeroSSL using Certbot DNS-01. The resulting
public certificates share the TLS public key and Subject/SAN, but have distinct
leaf certificates and direct issuers: LE YE2 and ZeroSSL ECC DV SSL CA 2.
Both debug APKs trust only Android system roots through NSC. The endpoint is
remote and reached over the device's normal Internet connection.

The supplied LE chain contains public cross-certificates for Root YE and ISRG
Root X2. The endpoint serves the full presentation and a shorter one omitting
the final X2 cross-certificate. Android selects the same path ending at trusted
ISRG Root X2 for both. The ZeroSSL path ends at Sectigo Public Server
Authentication Root E46.

This demonstrates compatibility with public ancestor cross-signing, not two
different selected LE paths. Dual issuance from one CSR is not two
cross-signed variants of one direct-issuer CA certificate. Direct-issuer
variants remain covered by symbolic models and host regressions, not these
device observations.

Relevant tools are [request-public-cross-certificates.py](../request-public-cross-certificates.py),
[run-public-cross-benchmark.py](../run-public-cross-benchmark.py), and
[summarize-public-cross-results.py](../summarize-public-cross-results.py).
Certificate/private-key files and account credentials are not embedded here.

### Policy sequence and negative controls

Nine cases per mode have 20 new TLS attempts each, for 360 attempts. Each case
forces actual OS retrieval and JWS verification under the installed-app or
manifest root. Publications advance `iat_c` through LE-only, dual-issuer,
ancestor-only, and ZeroSSL-only policies. Protected highest-seen state and the
clock remain intact, apart from normal monotone state updates.

| Policy / presented certificate | Expected decision |
| --- | --- |
| LE-only / LE | Accept |
| LE-only / ZeroSSL | Reject |
| LE-only / padded ZeroSSL | Reject |
| Dual / full LE presentation | Accept |
| Dual / short LE presentation | Accept |
| Dual / ZeroSSL | Accept |
| Ancestor-only / LE | Reject |
| ZeroSSL-only / ZeroSSL | Accept |
| ZeroSSL-only / LE | Reject |

The ancestor-only control deliberately authorizes a non-direct cross-signed CA
instead of YE2. The padding control presents ZeroSSL's native-valid chain plus
the authorized LE intermediate. Neither authorizes the direct issuer on the
actual selected native path.

### Audits and results

All 360 attempts passed native validation and made the expected supplementary
decision: 200 accepted and 160 rejected by issuer policy. The independent
checker verifies the recorded native-path DER and fingerprints against archived
Android roots, matches the actual peer input, authenticates both modes' JWS
objects, and checks the single-CSR/public-key relationship.

The origin records exactly 200 uniquely tagged measured application requests
and none for rejected attempts. All 40 padding attempts observe the extra
authorized certificate but reject the unauthorized direct issuer. Unlabeled
Internet requests are retained separately and never attributed to always-tagged
probes. This suite belongs to the same fresh cohort; no earlier chain
observations were reused. The harness restores the original app and leaves a
fresh dual-issuer policy at the endpoint. These are functional observations,
not latency distributions; timing tables use the separate connection matrix.

## 5. CA migration

| Window | Server/policy action | Expected observation |
| --- | --- | --- |
| `w1` | CurrCert with current-only policy | Accept CurrCert, reject alternate certificate |
| `w2` | Higher-`iat_c` dual-issuer policy; normally retain CurrCert | Accept current certificate; temporarily probe the alternate and restore CurrCert |
| `w3` | Joint NewCert/new-only policy cutover | Accept new certificate, reject retired issuer |

After overlap publication is observed, the harness waits at least 60 complete
seconds and beyond the claim's signed expiration. The recorded staging
intervals are 61.02487249299884 seconds for the primary root and
60.01759130600112 seconds for the compatible root. One atomic server-profile
change then selects NewCert and the new-only claim for subsequent handshakes.
Both modes pass six transition probes.

The temporary alternate-certificate probe checks dual-policy membership; it
does not redefine normal `w2` deployment as NewCert. This checks one server and
one observed client, not distributed publication atomicity, OS enforcement of
the deployment-profile maximum, or fleet-wide retirement.

## 6. Claim-key rotation

The experiment retains the policy root and changes the delegated key from
P-256 to P-384. Each mode has five checks:

| Retrieved pair / sequence | Observation |
| --- | --- |
| Matching old pair | Accept |
| Old delegation, new-key claim | Reject |
| New delegation, old-key claim | Reject |
| Matching new pair | Accept |
| Still-fresh old pair replay after higher versions | Reject |

These probes force token retrieval. They do not measure the bounded cached-key
refresh/retry path. The mixed-pair refusals are signature-policy outcomes, not
network failures.

## 7. App-signing-key and manifest-root changes

### Primary app-signing-key update

The suite updates the app from a P-256 signer to a P-384 signer through an
Android-authenticated signing lineage. The transitional delegation places the
required old/new signatures in positions three and four after two unrelated
signatures. The five checks cover transition and new-only acceptance, a
cross-app lookup after update, and lower-issuance-time transitional replay
refusal, with protected highest-seen state intact.

This is a concrete same-host transition, not all lineage-maximum merges or
cross-hostname transfer schedules. After the update the caller and target
share a signer, so the post-update cross-app observation is not independent
cross-signer-isolation evidence.

### Manifest-root replacement and parallel anchors

An authenticated update changes the manifest root without changing the app
signer. A fresh pair under the new manifest key has an issuance time below the
previous root's floor and is accepted in its independent namespace. A forced
lookup of the old-root pair is refused. The replacement group passes three
checks.

Separate forced queries also demonstrate that an app declaring the manifest
root can authenticate one pair under the installed app-signing root and
another under the manifest root. A cache-isolating reboot distinguishes the
roots. These are two eligible authorities with independent state, not a
two-signature requirement or cross-root rollback-floor transfer.

## 8. Scope of the evidence

Functional results are pass/fail observations, not latency distributions or
guarantees for untested schedules. API/robustness timing and lifecycle evidence
are separate. A single observed reboot, clock adjustment, or state transition
does not establish privileged rollback resistance. The separate ES256
certificate-change session covers same-issuer renewal and TLS-key replacement
with an unchanged pair; exact direct-issuer cross-sign variants remain
model/host-only.
