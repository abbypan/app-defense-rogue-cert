# ASPin symbolic models: setup and connection behavior

This specification retains the detailed explanations moved out of Appendix D.
It documents the current sources and saved results. Lifecycle traces and their
additional boundaries are specified in [proverif-lifecycle.md](proverif-lifecycle.md).

## 1. Model inventory and trust roots

The suite contains twenty-nine model instances:

| Group | Instances | Sources in `proverif/` |
| --- | ---: | --- |
| Primary network attacks | 3 | `aspin_dns_hijacking.pv`, `aspin_bgp_hijacking.pv`, `aspin_mitm.pv` |
| Native-TLS baselines | 3 | `tls_dns_hijacking.pv`, `tls_bgp_hijacking.pv`, `tls_mitm.pv` |
| Compatible-mode network/root binding | 1 | `aspin_compat_manifest_key.pv` |
| Primary certificate/lifecycle models | 7 | `aspin_cache.pv`, `aspin_ca_migration.pv`, `aspin_claim_key_rotation.pv`, `aspin_key_rotation.pv`, `aspin_certificate_change.pv`, `aspin_cross_sign.pv`, `aspin_cross_hostname_hc.pv` |
| Compatible certificate/lifecycle models | 7 | Corresponding `aspin_compat_*` models; `aspin_compat_root_rotation.pv` handles manifest-root replacement |
| Fail-closed and cross-app models | 4 | `aspin_availability.pv`, `aspin_compat_availability.pv`, `aspin_cross_app.pv`, `aspin_compat_cross_app.pv` |
| Shared-host signature lists | 2 | `aspin_multisig.pv`, `aspin_compat_multisig.pv` |
| Co-hosted primary-root rotation | 1 | `aspin_multisig_rotation.pv` |
| Parallel installed-app and manifest roots | 1 | `aspin_parallel_roots.pv` |
| Total | 29 | Saved outputs have matching stems under `proverif/result/` |

Only the signed SAN authorizes hostnames; Subject identifies the signed policy
and its $T_c$ anti-rollback partition. In the primary mode, $K_{apriv}$ signs
$T_k$ and the OS-selected $K_{apub}$ verifies it. In the compatibility mode,
$K_{spriv}$ signs $T_k$ and the OS resolves $K_{spub}$ from the authenticated
installed manifest. Both modes use delegated $K_{cpub}$ to verify $T_c$.

The complete signed payloads are:

$$
\begin{aligned}
T_k&=(K_{cpub},iat_k,exp_k),\\
T_c&=(Subject,SAN,IssuerSet,iat_c,exp_c).
\end{aligned}
$$

The models abstract the OS claim-host predicate rather than concrete X.509
string normalization. They separately represent header-key matching,
signatures, freshness at retrieval and at the later connection check, both
highest-seen contexts, target signing-key lookup, and cache isolation.

Separate compatibility lifecycle models cover caching, CA migration, claim-key rotation, and $K_s$ replacement,
as well as certificate change, cross-signing, and cross-hostname state transfer.
The app-signing certificate authenticates $K_{spub}$ through the signature over
the app package, including its manifest. Binding and resolution events refer to
the currently installed manifest, not a separate root store. A generator derives
six certificate/lifecycle instances with package-signature provenance checks;
the dedicated $K_s$-replacement model reads signed package abstractions from the
public channel. Native installer authorization of app identity and update
version is assumed. APK formats and downgrade protection are not modeled, and
there is no OS-maintained manifest-root history.

Each mode has a separate fail-closed and cross-app instance. Their compatible
sources use the same package-signature provenance checks as the six generated
certificate/lifecycle sources. The root-replacement model is dedicated rather
than generated in that way.

## 2. Query interpretation and adversarial inputs

| Query/output | Interpretation |
| --- | --- |
| `not event(E)` is true | Event `E` is unreachable in that model |
| `not event(E)` is false | A witness trace reaches `E` |
| `event(E1) ==> event(E2)` is true | Every reachable `E1` has a matching prior `E2` |
| True correspondence with an unreachable antecedent | Vacuous; not independent evidence of authentication |
| Cannot be proved | No correspondence established by that run |

Network tokens enter through the public channel and pass the modeled checks.
Private channels carry phase markers, protected transfer state, and internal
signature-filter requests and results. Internal requests copy public payloads
and signature lists; they do not supply a new trust root. Finite negative
controls are constructed locally. Reachability witnesses show a possible
successful schedule, not availability under suppression.

The attacker controls public delivery, including JWS objects, certificates, and
handshake messages. Perfect cryptography, trusted OS identity resolution,
native validation, synchronized rollback-resistant time, and protected atomic
state are assumptions, not implementation proofs. The network models describe
fresh TLS authentication, not resumption or established connections.

## 3. Rogue certificate attacks

The compatibility mode has its own model rather than sharing the primary-mode trust-root process.
A private OS process binds the installed target app to its authenticated
manifest key $K_{spub}$. All $T_k$, $T_c$, certificate, and handshake inputs still
travel on the public adversarial channel. The queries establish that every
resolved $K_{spub}$ has an earlier matching manifest binding and that every
compatible-mode $T_k$ verification uses such a resolved key. Separate
correspondences establish signing provenance for both JWS types.

A PKI-valid rogue endpoint with an unauthorized direct issuer cannot reach
either the app's malicious-connection event or the malicious server's
data-acceptance event. Legitimate connection and rogue-rejection branches are
reachable. Installation is assumed to have authenticated the package and
manifest. The terminating-MITM relay result is specific to the primary-mode
network model, not an additional compatible-mode result.

The Android realization obtains the ordered path returned by the native trust
manager, uses native TLS hostname verification for the certificate, applies the
OS claim-host predicate to signed SAN, and hashes the selected direct issuer
certificate's complete DER encoding with the claim-specified algorithm. Data
output follows the connection event.

Concrete certificate-path construction and extraction, DER parsing, hashing, base64url encoding, and differences between the two concrete hostname implementations are outside the symbolic model.
The three primary network models use singleton issuer sets for the real and
rogue certificates; the migration model separately represents dual-issuer
sets. The malicious-server correspondence is true but vacuous because its
antecedent is unreachable; it is not standalone evidence of authentication.

## 4. Cross-app connections

The cross-app models give A and B distinct policy roots and disclose A's
policy-root private key to the attacker. The protected resolver still selects
B's authenticated root. `CrossAppData` implies matching target resolution,
authenticated policy, native certificate validation, leaf-key possession, and
the protected connection event. Legitimate B connections, native acceptance of
the PKI-valid rogue leaf, and supplementary rejection of its unauthorized issuer
are reachable. Data output to that issuer and use of A's root for B are
unreachable.

Missing or invisible B is an explicit local resolution failure on the protected
opt-in path. The app's optional native-TLS-only fallback is outside that path
and its guarantees. The resolver abstracts the installed identity at query
time, not concurrent install/uninstall scheduling or store lookup for an
uninstalled target. Concrete package visibility and timeouts remain OS
assumptions. Cache models additionally check cross-app isolation. These
results provide certificate-policy authentication, not permission to access
B's business data.

## 5. Cache

### 5.1 Publication provenance and isolation

Every insertion and returned claim corresponds to publication authenticated
under the same target signing key, delegated claim key, Subject/SAN,
$IssuerSet$, $iat_c$, and $exp_c$. App A can name B, but the protected resolver
selects B's $K_{apub}$; neither A's key nor a caller-supplied key enters the
cache index.

The model makes cached $T_c$ readable only through a fresh local
$(K_{apub},h)$ entry yielding the owner-wide delegated key that authenticated
it. Cross-signing-key, cross-delegated-key, and cross-claim-host reads are unreachable.
Intentional A-to-B selection is isolated under B's signing identity, the
delegated key recorded for the local lookup context, and signed claim
hostname. This does not prove hostname-specific provenance of $T_k$ or
isolation between packages deliberately sharing a signing identity.

### 5.2 Rollback, expiration, and emergency removal

Separate traces accept higher-$iat$ replacements and replay still-fresh
predecessors of both JWS types. Both negated rejection queries are false:
each trace reaches the highest-seen comparison after header, signature,
structure, freshness, and hostname checks. Lifetime is derived as
$ttl=exp-iat$. Acceptance at $t_{\mathrm{now}}=exp$ is unreachable, while
exact-expiration rejection is reachable.

An emergency replacement has a higher $iat$ and removes the former issuer
without changing the modeled Subject/SAN partition. Acceptance implies
matching publication, followed by rejection of the still-fresh former policy
in that partition. This shows executable partition-preserving emergency
removal without allowing an attacker-created high timestamp to set the floor.

### 5.3 Parallel installed-app and manifest roots

A dedicated model authenticates both $K_{apub}$ and the additional manifest
$K_{spub}$ for one installed target. Claims under either root are reachable.
Accepted claims imply authorization of the selected root and matching
delegation signatures; cache returns imply insertion under that root. Neither
root reads the other's delegated-key entry. An unrelated attacker-controlled
root and an unauthorized issuer cannot authorize a claim. All ten queries
have their expected outcomes.

This checks the union of two explicit authorities and separate namespaces,
not deterministic root preference, package-update scheduling, or a joint
signature requirement. The mode-specific models retain their lifecycle scopes.

### 5.4 Shared-host multi-signature models

Both models represent $T_k$ as one common payload and an unbounded symbolic signature list.
A public list constructor lets the attacker prepend, append, remove, or reorder
entries. Recursive membership abstracts selection; verification checks the
protected key identifier and signature against the root already resolved from
the authenticated package context. This internal abstraction is not a
request-side owner selector. It establishes safety of an accepted entry, not
deterministic scan order or guaranteed completion.

A three-owner publication shares one delegated key, with the target's only
matching signature in position three. Both queried owners' delegations and the
target claim are reachable. Matching signing provenance holds for $T_k/T_c$.
Returning the target claim under the caller's root or accepting an unauthorized
issuer is unreachable.

Finite zero- or one-entry controls reach rejection for an empty array, an
absent owner signature, a forged matching `kid`, and a signature copied onto a
different payload. None reaches acceptance. They use the same header and
cryptographic checks without relying on negative-predicate trace
reconstruction; separate public-input queries cover arbitrary list lengths.
The compatible instance additionally establishes APK-signature-authenticated
manifest binding. All 14 primary and 17 compatibility queries have their
expected outcomes.

The isolation queries are retained explicitly for source/result lookup:

| Negated event query | Meaning of a true result |
| --- | --- |
| `not event(CrossSigningKeyCacheHit(...))` | No cross-signing-root cache hit |
| `not event(CrossDelegationCacheHit(...))` | No cross-delegated-key cache hit |
| `not event(CrossHostnameCacheHit(...))` | No cross-claim-host cache hit |

## 6. Fail-closed behavior

The models prime a cache by authenticating signed artifacts and evaluate use
before and at the earlier signed expiration. Separate cases let $T_k$ or $T_c$
impose that bound. An empty or expired cache followed by failed retrieval
reaches refusal; neither a protected connection nor application-data output is
reachable. Public replay cannot extend either expiration.

Witnesses reach data output in `available_cached` before expiry and in
`available_restored` after delivery of a fresh, nondecreasing-$iat$ pair. Data
events imply a connection preceded by authenticated fresh policy and native
certificate checks.

Silence does not itself generate a timeout in the asynchronous calculus:
the local timeout/failure outcome is explicit. Restoration is an existential
trace, not a fairness assumption or a guaranteed recovery protocol. These
models verify conditional fail-closed safety and expose the availability cost
of refresh suppression.
