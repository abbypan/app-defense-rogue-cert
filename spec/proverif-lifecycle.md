# ASPin symbolic models: certificate and key lifecycles

These are the trace-level details moved from Appendix B. The
[model specification](proverif-models.md) defines the common trust roots,
adversarial channels, and query interpretation. All results below describe
the existing model instances and saved logs, not new Android measurements.

## 1. Certificate change

The two mode-specific models use explicit leaf serial numbers and TLS public
keys while retaining the same signed delegation and claim. They reach
acceptance of the original certificate, renewal with a new serial number, and
replacement with a new TLS key under the authorized direct issuer. Native
certificate-signature and hostname checks, leaf-private-key possession, and
joint token freshness precede the decision.

Wrong-hostname, invalid-signature, unauthorized-issuer, and expired-policy
acceptances are unreachable. X.509 validity and path construction are
abstracted by native-validation assumptions; this does not cover mis-issuance
by an already authorized CA certificate.

Sources: [primary](../proverif/aspin_certificate_change.pv),
[compatible](../proverif/aspin_compat_certificate_change.pv).

## 2. Cross-signed issuer certificates

Each model represents an intermediate CA with two distinct certificates that
have the same Subject and public key but different trusted signing roots. A
symbolic hash identifies the complete CA certificate, including its root
signature, so the identifiers differ. The leaf and its TLS key are unchanged.
All candidate JWS objects, leaf and direct-issuer certificates, extra peer
certificates, and challenge responses enter through the adversarial channel.
The verifier checks both token signatures and freshness, native hostname and
certificate signatures, and leaf-key possession before testing membership of
the selected direct issuer identifier.

Each mode accepts both variants under the complete set and the first variant
under an intentionally incomplete earlier policy. That earlier policy rejects
the omitted second variant. A native-valid leaf under a same-name CA with a
different key cannot be accepted, even when its peer list includes an
authorized intermediate. Additional witnesses separately reach native
validation and supplementary rejection with and without padding; refusal is
not explained by an unrelated TLS failure. Policy-publication and
native-validation correspondences hold, and expired-claim rejection is
reachable. The compatible instance also establishes manifest-root provenance.
All 15 primary and 18 compatibility queries have their expected outcomes.

This checks certificate identity and signed-set membership, not concrete DER
hashing, path construction, or discovery of all alternative issuers. The
publisher must obtain and list all supported direct-issuer variants. The
incomplete policy is a negative control, not permitted publication. Native TLS
may select either listed path; ASPin does not choose a root or search unrelated
peer certificates for an authorized match. These models add no availability
or rollback claim beyond the separate lifecycle models.

Sources: [primary](../proverif/aspin_cross_sign.pv),
[compatible](../proverif/aspin_compat_cross_sign.pv).

## 3. CA migration

The model encodes current-only $T_c^{(1)}$ in $w_1$, dual-issuer $T_c^{(2)}$
in $w_2$, and new-only $T_c^{(3)}$ in $w_3$, within one fixed Subject/SAN
partition, with $iat_c^{(1)}<iat_c^{(2)}<iat_c^{(3)}$. Every token is read from
the adversarial channel. Signatures authenticate policy, issuance, and
expiration. The private phase markers encode the trusted operator's compliance with the recommended schedule
rather than client-enforced elapsed time. $T_k$ freshness is rechecked in
every window. The migration model uses one symbolic step for $L_{\max}$.

Cutover requires prior NewCert acquisition, overlap publication, and the
full-$L_{\max}$ phase-elapsed event. At $w_3$, new-only claim publication and
NewCert deployment occur jointly. Acceptance then requires that fresh claim.
The incompatible pairs (NewCert/current-only and CurrCert/new-only) are
unreachable. A negated dual-policy query for NewCert is false, confirming that
the dual policy authorizes NewCA. The recommended schedule still retains
CurrCert during $w_2$ and expires the dual claim before $w_3$: this is ordering,
not rejection by the dual policy. All three windows and their scheduled valid
acceptances are reachable. No result shows that a client observed staging.

The dedicated model also reads peer certificates from the public channel and
checks the native-trusted issuer, certificate signature, and hostname before
issuer-set membership. Verification and freshness select the policy rather
than assuming the expected set for a window. Certificate-policy decisions
permit CurrCert in $w_1$, either authorized issuer under the dual $w_2$ policy,
and NewCert in $w_3$. An unauthorized issuer or either incompatible pair cannot
be accepted. Replaying the expired dual claim in $w_3$ reaches rejection.

Operator phase signals are independent of client receipt: advance requires no
client acknowledgement. One symbolic step abstracts a complete $L_{\max}$;
this dedicated model checks certificate-policy decisions, not another TLS
handshake. It does not establish distributed publication atomicity, suppression
resistance, fleet cache drainage, or OS enforcement of the profile ceiling.

Sources: [primary](../proverif/aspin_ca_migration.pv),
[compatible](../proverif/aspin_compat_ca_migration.pv).

## 4. Claim-key rotation

The model authenticates an old pair and records hostname-local $H_k$ and
Subject/SAN-local $H_c$. It then evicts the claim but retains its fresh
delegation. A new-key $T_c$ fails verification under the cached old key,
triggering one $T_k$ retrieval and one $T_c$ retry. Successful rotation and
rejection after unsuccessful retry are both reachable. Mixed old/new pairs
cannot be accepted; signing-provenance correspondences hold for both tokens.

After accepting the higher-$iat$ new pair, the model replays a still-fresh old
pair to exercise $H_k$. It separately re-signs the same old $T_c$ payload with
the new claim key to isolate $H_c$: the signature and $T_k$ remain valid, but
the lower $iat_c$ causes refusal. Both rollback branches are reachable, with no
below-floor acceptance. A fresh old pair is also reachable before newer policy
is authenticated, matching bounded adoption. The model abstracts eviction,
finite timestamps, and atomic state. It neither models a compromised claim
key nor forces every hostname context to refresh.

Sources: [primary](../proverif/aspin_claim_key_rotation.pv),
[compatible](../proverif/aspin_compat_claim_key_rotation.pv).

## 5. App-signing-key and manifest-root rotation

### 5.1 Primary same-host lineage transfer

The app-key model covers a three-key OS lineage for a same-host transition
with prior $H_k$, independent $H_k/H_c$ maxima, and dual $T_k$. Both $H_k/H_c$ maximum transfers
and new-only cutover are reachable. The negated old-only and nonmaximum-commit queries
are true, so both bad events are unreachable. In that trace, protected state transfers only if transitional $T_k^{(2)}$ also verifies under the old and new keys;
lineage alone moves no prior state. The transferred $H_k$ is the lineage maximum,
and $H_c$ is analogous. Acceptance atomically commits the maximum, and older
objects reach rollback refusal. This is the modeled prior-$H_k$ trace, not
every implementation-level $H_c$ merge.

Source: [primary lineage model](../proverif/aspin_key_rotation.pv).

### 5.2 Compatible-mode root replacement

The installed app's signing key verifies old and updated package abstractions
containing their manifest keys. That key differs from both $K_s$ roots. Only
the current manifest selects the compatibility root; primary $K_{apub}$ remains
independently available. A dual-signed transition supports old and updated
installations, each checking its own root entry. The updated installation does
not use the old $K_s$ signature to authorize its app update.

A wrongly signed replacement manifest and a token signed only by the replaced
$K_s$ cannot be accepted on this path. Replacement and new-only cutover are
reachable, as are $T_k/T_c$ replay refusals after higher versions under that
same root. There is no old-root floor transfer. A witness intentionally accepts
a fresh claim below the previous root's $H_c$, documenting independent
namespaces rather than cross-root rollback protection. Native app-update
authorization is assumed; no separate manifest-root archive is introduced.

Source: [compatible root model](../proverif/aspin_compat_root_rotation.pv).

### 5.3 Co-hosted primary-root rotation

The co-hosted model places the new and old app-key signatures in the third and fourth entries
after two unrelated co-host signatures. The updated verifier authenticates both
over the same payload, checks fresh $T_k/T_c$, and consults independent trusted
lineage and $H_k/H_c$ contexts. Context-maximum transfer is reachable; every
transfer implies both signature checks, a trusted-lineage event, and protected
source-state events. The same valid pair without trusted lineage reaches
refusal. Nonmaximum commits are unreachable. All 13 queries have their
expected outcomes. This complements the complete rotation/cutover/replay trace.

The shared-host and co-hosted models check policy authentication and
conditional transfer, not a new TLS handshake or a combined cache
implementation. Concrete JSON parsing, byte bounds, scan cost, and arbitrary
timestamp arithmetic are abstracted. Two required rotation signatures are a
minimum authorization condition, not an array-length maximum. Separate cache
and lifecycle models supply the state properties. Device fixtures exercise
four entries; larger-list tests remain host-only.

Source: [co-hosted rotation](../proverif/aspin_multisig_rotation.pv).

### 5.4 Cross-hostname H_c-only continuity

The first hostname authenticates a claim covering two hostnames. Protected
state contains its $H_k$ and the shared Subject/SAN $H_c$, but no $H_k$ for the
second hostname. The primary model follows an authenticated signing-lineage
transition; the compatible model retains the same current $K_s$ for both
hostnames.

The second hostname retrieves current-root-only $T_k$, accepts a claim at or
above the existing $H_c$, initializes its own $H_k$, and commits
$\max(iat_c,H_c)$. An unexpired below-floor claim reaches rejection.
Acceptance below the floor and reading the first hostname's $H_k$ as the
second's are unreachable. Continuity implies the earlier authenticated state
and either primary lineage or current APK-authenticated manifest binding.
This case has no prior $H_k$ for the second hostname and makes no cross-$K_s$
transfer claim.

Sources: [primary](../proverif/aspin_cross_hostname_hc.pv),
[compatible](../proverif/aspin_compat_cross_hostname_hc.pv).

## 6. Additional lifecycle boundaries

- Suppression cannot invalidate a fresh pair but causes fail-closed refusal once
  none remains. Migration offers no client acknowledgement, suppression
  protection, or cross-cutover cache bridge. Each client needs fresh
  $T_c^{(3)}$; skew can cause transient refusal.
- Native-TLS policy retrieval remains subject to suppression. Egress filtering
  does not supply caller attribution or rate limits.
- Corrupt state fails closed; recovery is future work, and deleting protected state is invalid.
- A compromised owner-wide $K_{cpriv}$ can forge any Subject/SAN while its
  delegation remains accepted. A replacement does not force refresh:
  controlled delivery can retain valid old-key $T_c$ until the cached old $T_k$ expires.
  Newer $T_k$ in one hostname-local partition does not revoke another.
- $T_c$ ordering is limited to canonical $(K_{apub},Subject,SAN)$. Changing
  that identity starts an independent partition. Publishers prohibit
  simultaneous fresh partitions covering one hostname within one owner
  collection, not across different owners.
- An unrelated signing lineage has independent state and no inherited floors;
  switching to it does not revoke the other owner's claims or existing
  sessions. Cross-lineage state transfer remains future work.

The prototype fixes trusted $K_{apub}$ by resolving the target package before
retrieval. A shared endpoint can return one General JWS $T_k$ with signatures
from multiple authorizing app keys over one delegation payload. The verifier
filters by the context key and verifies the matching entry; it does not derive
an owner from a hostname or an untrusted `kid`. The shared delegated key verifies
$T_c$, while each root retains its cache and rollback namespace. No server-side
owner selector is required. Joint signatures alone create neither a signing
lineage nor state-transfer authority. Distinct payloads cannot be represented
by adding signatures to one General JWS object.
