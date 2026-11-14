# ASPin: App Self-Protecting Certificate Claim Pinning for Mobile Apps

This repository contains the prototype implementation, formal ProVerif security models, trust artifact generators, Android client source code, and benchmark scripts for **ASPin** (*App Self-Protecting Certificate Claim Pinning*).

---

## 1. Environment Setup & Prerequisites

### System Requirements & Dependencies

#### Arch Linux
```bash
sudo pacman -S certificate-ripper-bin python-pip jdk21-openjdk maven openssl nginx android-tools
pip install -r requirements.txt
npm install -g eckles
```

#### Ubuntu / Debian
```bash
sudo apt update
sudo apt install -y python3-pip openjdk-21-jdk maven openssl nginx adb python3-jwcrypto
pip install -r requirements.txt
```

#### Python Dependencies
Ensure `jwcrypto`, `cryptography`, and `requests` are installed:
```bash
pip install -r requirements.txt
```

Applying the AOSP patch bundle additionally requires the Android `repo` tool,
Git, GNU tar, and Zstandard (`zstd`). Building AOSP uses the JDK and host tools
included or required by the selected Android branch. The Android app benchmark
uses JDK 21 when `/usr/lib/jvm/java-21-openjdk` is available.

---

## 2. Trust Artifact Generation

Generate short-lived claim-signing public key tokens ($T_k$) and certificate claim tokens ($T_c$) across all 4 evaluated cryptographic algorithm suites (`es256`, `es384`, `rsa3072`, `rsa4096`), and synchronize them to Nginx web root directories:

```bash
python3 ./gen-trust-artifacts.py
```

Generation fails unless both artifacts use General JWS JSON Serialization and
exactly the TeX schema (these generated single-owner fixtures have one signature),
their `kid` values identify the configured app/claim keys, signatures verify,
the APK signing certificate matches the $T_k$ trust anchor, and the Subject,
SAN, and direct-issuer-CA IssuerId match the source server certificate chain.

This updates:
- `ClaimSigningKey.primary.jws` (primary-mode $T_k$, rooted in the app signing key)
- `ClaimSigningKey.compat.jws` (compatible-mode $T_k$, rooted in manifest key $K_{spub}$)
- `ClaimSigningKey.jws` (the active endpoint copy; primary by default)
- `ServerCertClaim.jws` ($T_c$)
- Android NSC SHA-256 SPKI pins for the SCP APKs
- Synchronizes both $T_k$ forms and $T_c$ to
  `realserver/var/www/<alg>/.well-known/`

The benchmark selects the endpoint's active $T_k$ with:

```bash
./activate-claim-signing-key.sh es256 primary
./activate-claim-signing-key.sh es256 compat
```

The `issuer` array in $T_c$ contains deterministic identifiers of the form
`hash-name:hash-value`. `hash-value` is the unpadded base64url digest of the
complete DER-encoded CA certificate that directly issued the intended leaf.
The generators read that CA certificate from the server chain, verify that it
directly issued the leaf, and publish `sha256` by default; the implementation
also accepts `sha384`. After native TLS validation, the app extracts the direct
issuer CA certificate from the received chain, recomputes the digest named by
each claim entry, and requires one exact match. An absent direct issuer,
unsupported hash name, malformed encoding, or digest mismatch fails closed.

---

## 3. Building & Signing Algorithm-Specific APKs

Build and sign the primary ASPin APKs for all four key algorithm suites:

```bash
python3 ./gen-signed-apks.py --output-dir results/apks
```

Build all four configurations with at most 24 Gradle workers:

```bash
python3 ./gen-signed-apks.py --workers 24 \
  --mode primary --mode scp --mode dcp --mode compatible \
  --output-dir results/apks
```

For each algorithm this produces `ASPin-<alg>.apk` (primary ASPin),
`ASPin-<alg>-scp.apk` (standard Android NSC `pin-set`),
`ASPin-<alg>-dcp.apk` (independent extended-NSC DCP), and
`ASPin-<alg>-compatible.apk` (ASPin compatibility mode).
The DCP APK declares `android.security.dcp.POLICY_PUBLIC_KEY`; its NSC
`dynamic-pin-set` directly verifies the hostname-bound leaf-SPKI policy at
`/.well-known/DCPServerCertPin.jws`. It never calls the ASPin service.
The Android 17 `trunk_staging` build enables Conscrypt-hosted NSC, so the active
extension is in `external/conscrypt/nsc/src/android/security/net/config`.
The corresponding framework NSC path is retained for builds with modular NSC
disabled. Check the Conscrypt NSC build output for `DcpPinningVerifier` before
flashing; changing only the inactive framework path is insufficient.
The compatible APK instead declares `android.security.aspin.POLICY_PUBLIC_KEY`
and uses the ASPin service's two-token lifecycle. This manifest key adds
$K_{spub}$ alongside the installed $K_{apub}$; it does not override it.
Each root has independent cache and protected rollback state. A freshly fetched
delegation valid under both roots selects $K_{apub}$ first. Existing cached
policies may remain usable under either authorized root; isolate RAM cache
between root-mode benchmark groups when attributing timings to $K_{spub}$.

These app sources use the Java 21 toolchain. Set `JAVA_HOME` and
`ASPIN_JAVA_HOME` to `/usr/lib/jvm/java-21-openjdk` (or an equivalent JDK 21).

The compiled and signed APKs will be saved in `results/apks/`.

### Complete fresh Internet evaluation (preferred)

For a complete reproduction session, including a measurement-time check of the
installed system image, all main/API suites, and the certificate-renewal/rekey
suite, use the top-level runner below. The phone must already have the audited
image, USB authorization, and Wi-Fi Internet access. This command does not flash
or wipe the phone. The supplied certificate directory is an input fixture only:
the runner rechecks its validity, public trust, and renewal/rekey properties,
then records new observations rather than importing earlier measurements.

```bash
BENCH_SESSION=/mnt/code/aspin/results/reproduction-$(date -u +%Y%m%dT%H%M%SZ)
systemd-run --user --unit="aspin-reproduction-$(date -u +%Y%m%dT%H%M%SZ)" \
  --remain-after-exit --property=WorkingDirectory=/mnt/code/aspin \
  --property="StandardOutput=append:$BENCH_SESSION.log" \
  --property="StandardError=append:$BENCH_SESSION.log" \
  /usr/bin/python3 -u /mnt/code/aspin/run-reproducible-evaluation.py \
  --run-dir "$BENCH_SESSION" \
  --deployment /mnt/code/aspin/remote-experiment/deployments/main.json \
  --cross-deployment /mnt/code/aspin/remote-experiment/deployments/public-cross.json \
  --certificate-fixtures /mnt/code/aspin/certificate-fixtures/renewal-rekey
```

Do not launch the component services below at the same time as this top-level
runner. Its `reproduction.json` records stage status, installed runtime hashes,
the raw system-partition prefix digest, public source snapshots, and audits.
It preserves failures and partial observations rather than marking an
incomplete session successful. APK builds use 24 workers. Device reboots and a
temporary clock rollback are part of the robustness suite; its cleanup restores
the clock and automatic-time setting. Test TLS keys remain Git-ignored; app,
delegation, and DCP authority private keys are not uploaded or source-archived.

If the Wi-Fi-provided DNS is unusable, explicitly add `--dns-server 8.8.8.8` to
the top-level command. This changes only the active experiment network's Android
resolver configuration, not its IP address, Wi-Fi credentials, TLS trust, or
private-DNS mode. Preflights reapply the requested server after test reboots and
reconnections. The override is recorded in `reproduction.json`; omitting it
keeps the normal network-provided DNS. The bounded DNS/Internet preflight fails
before measurements when name resolution is unavailable.

For individual suites instead of the complete top-level session:

This workflow creates a new result cohort, regenerates and publishes public
policies, rebuilds all four experiment configurations with 24 workers, and runs
the connection matrix, lifecycle/fail-closed/cross-app scenarios, and public-CA
issuer-set/path tests sequentially. It does not import measurements from earlier
directories. Use the ASPin-flashed Pixel 8 with working Wi-Fi Internet access;
the existing isolated `hk` deployments must already be running.

Run builds and experiments as independent background services:

```bash
BENCH_COHORT=/mnt/code/aspin/results/internet-evaluation-$(date -u +%Y%m%dT%H%M%SZ)
systemd-run --user --unit="aspin-internet-$(date -u +%Y%m%dT%H%M%SZ)" \
  --property=WorkingDirectory=/mnt/code/aspin \
  --property="StandardOutput=append:$BENCH_COHORT.log" \
  --property="StandardError=append:$BENCH_COHORT.log" \
  /usr/bin/python3 -u /mnt/code/aspin/run-internet-evaluation.py \
  --run-dir "$BENCH_COHORT" \
  --deployment /mnt/code/aspin/remote-experiment/deployments/main.json \
  --cross-deployment /mnt/code/aspin/remote-experiment/deployments/public-cross.json
```

After `cohort.json` has appeared, queue the API/robustness suite. Its
`--after-cohort` guard waits for successful completion of the first service;
the two services never operate on the phone concurrently.

```bash
systemd-run --user --unit="aspin-internet-api-$(date -u +%Y%m%dT%H%M%SZ)" \
  --property=WorkingDirectory=/mnt/code/aspin \
  --property="StandardOutput=append:$BENCH_COHORT-api.log" \
  --property="StandardError=append:$BENCH_COHORT-api.log" \
  /usr/bin/python3 -u /mnt/code/aspin/run-remote-api-robustness.py \
  --deployment /mnt/code/aspin/remote-experiment/deployments/main.json \
  --apk-dir "$BENCH_COHORT/apks" --run-dir "$BENCH_COHORT/api-robustness" \
  --after-cohort "$BENCH_COHORT/cohort.json"
```

The API suite measures 1-/8-thread cached self/cross-app calls for every target
profile after policy authentication over the Internet. It builds ES256- and
ES384-signed copies of the same caller: an ES384 target uses the ES256 caller,
and all other targets use the ES384 caller. Cache-only timings are OS-call costs, not
Internet round-trip latency. Server audits require no metadata downloads during
these measured cache runs. It also checks parallel remote refresh, ordinary
reboot persistence, separate old-token replays, and a temporary ten-minute
wall-clock rollback; it restores the clock and automatic-time setting on exit.
These are functional robustness checks, not proof of privileged rollback
resistance. Do not use a phone needed for unrelated work during this suite.

Once both services complete, independently audit the whole cohort:

```bash
python3 summarize-internet-evaluation.py "$BENCH_COHORT"
```

After updating the paper's numbers from this cohort, add `--check-paper` to
verify the connection, cold-path, artifact-size, and cached-API tables against
the actual new observations and fixtures.

The auditor requires fresh, complete manifests, rechecks raw decisions and
request identities, checks both lifecycle and public-path evidence, and writes
`checks.json`, `api-summary.csv`, and `evidence-sha256.json`. The matrix's exact
fresh public JWS fixtures are archived in `matrix-artifacts/` for byte counts.
Incomplete/failed runs are retained separately and cannot populate paper tables;
there is no fallback to local or historical measurements. Neither runner flashes
the phone, erases protected state, changes DNS, or uploads policy-signing keys.

### Complete cached API matrix without rerunning lifecycle tests

For a completed Internet cohort, this supplementary session regenerates public
policies, rebuilds the eight target APKs and two differently signed callers with
24 workers, and measures both APIs under both roots for all four target profiles.
It runs 32 timed batches (2,000 calls per batch by default), plus separate priming
and cache-hit probes. A normal reboot between root modes clears volatile caches
without deleting protected state. It does not repeat clock-rollback or lifecycle
tests, flash the device, or reuse old API timing samples.

Choose a cohort whose `api-cache-matrix/` does not already exist:

```bash
CACHED_COHORT=/mnt/code/aspin/results/reproduction-20261114T062526Z/internet
systemd-run --user --unit="aspin-cached-api-$(date -u +%Y%m%dT%H%M%SZ)" \
  --property=WorkingDirectory=/mnt/code/aspin \
  --property="StandardOutput=append:$CACHED_COHORT/api-cache-matrix.log" \
  --property="StandardError=append:$CACHED_COHORT/api-cache-matrix.log" \
  /usr/bin/python3 -u /mnt/code/aspin/run-remote-api-robustness.py \
  --cache-matrix-only --prepare \
  --deployment /mnt/code/aspin/remote-experiment/deployments/main.json \
  --apk-dir "$CACHED_COHORT/api-cache-matrix/apks" \
  --run-dir "$CACHED_COHORT/api-cache-matrix"
```

The same cohort auditor detects this directory and requires a complete session
on the same device image, all self/cross-app dimensions, matching query/hostname
fields, successful calls, fresh signed policies, and zero business or metadata
requests during the timed cache batches. It then uses this complete session for
the API table while retaining the original robustness evidence. Incomplete or
failed supplementary sessions block the audit rather than falling back to old
timings. After updating the paper, rerun the auditor with `--check-paper`.

### Certificate renewal and TLS-key replacement with unchanged policies

This supplementary Internet experiment holds Subject/SAN and the **exact direct
issuer CA certificate DER** constant across three distinct leaf certificates:
baseline, same-key renewal, and TLS-key replacement. It compares native TLS,
NSC SCP, independent NSC DCP, primary ASPin, and compatible ASPin on the
ASPin-flashed Pixel 8. It does not build or flash AOSP, change DNS A records,
reset protected state, or alter the clock.

Choose a fresh directory. The certificate helper reuses the existing Certbot
account and DNS-01 credentials; it does not register an account. It preserves
the existing endpoint credentials and writes new fixtures only beneath the
chosen directory. All private keys remain Git-ignored. Certificate acquisition,
APK builds, and device measurements run as independent background services:

```bash
CERT_CHANGE_RUN=/mnt/code/aspin/results/certificate-change-internet-$(date -u +%Y%m%dT%H%M%SZ)
systemd-run --user --unit="aspin-cert-change-issue-$(date -u +%Y%m%dT%H%M%SZ)" \
  --property=WorkingDirectory=/mnt/code/aspin --property=UMask=0077 \
  --property="StandardOutput=append:$CERT_CHANGE_RUN.issuance.log" \
  --property=StandardError=inherit \
  /usr/bin/python3 -u /mnt/code/aspin/prepare-certificate-change.py \
  --output-dir "$CERT_CHANGE_RUN/certificates" --issue
```

Wait for `certificates/fixtures.json` to report `state: complete`. A public CA
may select a different intermediate for an order. If the helper refuses the
exact-issuer invariant, retain that failed attempt. Explicit bounded retries
use the same directory with `--rekey-attempt 2`, then, only if needed,
`--rekey-attempt 3`. The last option tries another TLS key and selects eligible
certificates from the archived issuance pool **before** device testing. It
never substitutes an issuer name or CA public key for certificate-DER equality.
Stop if no eligible triplet is available; consider ACME rate limits before
requesting another certificate. Do not rerun issuance against a completed run.

After fixtures pass, build all four APKs. The generated SCP resource overlay
pins the selected baseline leaf key; ordinary APK builds are unaffected.

```bash
systemd-run --user --unit="aspin-cert-change-build-$(date -u +%Y%m%dT%H%M%SZ)" \
  --property=WorkingDirectory=/mnt/code/aspin \
  --setenv=JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
  --property="StandardOutput=append:$CERT_CHANGE_RUN.build.log" \
  --property=StandardError=inherit \
  /usr/bin/python3 -u /mnt/code/aspin/gen-signed-apks.py \
  --variant es256 --workers 24 \
  --mode primary --mode scp --mode dcp --mode compatible \
  --scp-resource-dir "$CERT_CHANGE_RUN/scp-res" \
  --output-dir "$CERT_CHANGE_RUN/apks"
```

After the build succeeds, run the experiment with the existing isolated remote
origin and an authorized, Internet-connected ASPin Pixel 8:

```bash
systemd-run --user --unit="aspin-cert-change-test-$(date -u +%Y%m%dT%H%M%SZ)" \
  --property=WorkingDirectory=/mnt/code/aspin \
  --property="StandardOutput=append:$CERT_CHANGE_RUN.benchmark.log" \
  --property=StandardError=inherit \
  /usr/bin/python3 -u /mnt/code/aspin/run-certificate-change-benchmark.py \
  --deployment /mnt/code/aspin/remote-experiment/deployments/main.json \
  --run-dir "$CERT_CHANGE_RUN" --iterations 20 --warmups 3
```

The runner holds one fresh, byte-identical ASPin token pair per root across
the stages. Renewal and rekey cells reuse the baseline OS cache without forced
preloading; audits require zero metadata downloads. SCP and DCP retain their
baseline leaf-SPKI policies. Their rekey refusals mean those policies need a
pin update, not that DCP cannot support key replacement. A normal reboot before
compatible mode clears RAM tokens but preserves highest-seen state. Only test
TLS keys and public policies are uploaded; policy-authority keys stay local.
The original isolated server manifest, state, and code are restored on exit.

Independent auditing requires no device or TLS private keys:

```bash
python3 summarize-certificate-change-results.py "$CERT_CHANGE_RUN" --check-paper
```

The completed session is
`results/reproduction-20261114T062526Z/certificate-change/`: 15 cells and 300
measured attempts, with 260 acceptances and 40 expected SCP/DCP rekey refusals.
All configurations accept renewal; both ASPin modes also accept rekeying with
unchanged tokens. Raw CSVs, public certificates/CSRs, unchanged signed policies,
request audits, APK/source hashes, and an evidence index are retained. This
fixed-order ES256 functional session supplements, rather than modifies, the
original 1,280-attempt connection matrix. It is not a latency comparison.
See [the scenario specification](spec/evaluation-scenarios.md) for selection
invariants and evidence boundaries.

### Direct remote four-scheme comparison

Use only a Pixel 8 running the newly built ASPin image (`ro.build.user=exp`),
with normal Internet access and no adb reverse mappings. The runner refuses a
device without the ASPin OS service. Keep an existing isolated remote deployment
record; do not redeploy over unrelated services or repeat an occupied origin port.

```bash
python3 update-remote-policies.py \
  --deployment remote-experiment/deployments/main.json
python3 run-remote-comparison.py \
  --device 3A201FDJH000GP \
  --deployment remote-experiment/deployments/main.json \
  --apk-dir results/reproduction-20261114T062526Z/internet/apks \
  --run-dir results/comparison-new \
  --iterations 20 --warmups 3
```

The 64-cell matrix separates four protected schemes and a native-TLS control,
four signature configurations, real/rogue certificates, and applicable cache
conditions. It records raw time-to-acceptance/rejection and response-read costs
separately. Server logs must corroborate application requests and DCP metadata
fetches; a network failure cannot count as successful policy rejection. The
compatibility group reboots the device to avoid attributing a surviving primary
root's RAM cache hit to $K_{spub}$; protected rollback state is retained. This
fixed group order is a measurement limitation. No configured added-RTT number
is assigned to this real Internet path; use the separate isolated-netem matrix
for controlled added RTT. Results are not promoted to paper tables until the
device run and all audits pass.

The runner keeps the externally powered phone awake and restores the original
setting on exit. This prevents Android from aborting a benchmark app's sockets
after it becomes a background/cached process. `--record-transport-failures`
retains transport failures explicitly as failed observations, outside the
expected-outcome latency distribution; it never reclassifies them as policy
rejections. Failed runs remain in their own directories. The origin performs
TLS handshakes in independent connection threads so DCP can download policy
while a business handshake waits for its supplementary check.

Build the differently signed cross-app callers before functional scenarios:

```bash
cd ASPin/es256
JAVA_HOME=/usr/lib/jvm/java-21-openjdk ./gradlew --no-daemon --max-workers=24 \
  :app:assembleCrossAppCaller :app:assembleCrossAppHidden
cd ../..
```

For the manifest-key rotation case, build the compatible APK with
`-PaspinPolicyPublicKeyFile=/absolute/path/to/new-public-key.txt` and save it as
`ASPin-es256-compatible-rotated-root.apk` in the chosen APK directory. Keep the
original compatible APK separately. This changes manifest public metadata,
not the APK's app-signing identity.

```bash
python3 run-remote-policy-scenarios.py \
  --device 3A201FDJH000GP \
  --deployment remote-experiment/deployments/main.json \
  --apk-dir results/reproduction-20261114T062526Z/internet/apks \
  --run-dir results/policy-scenarios-new \
  --short-seconds 60
```

This separate functional suite uses both ASPin roots, a differently signed
caller, missing/invisible targets, shared-host signature filtering, cached
availability, real signed expiry, HTTP-503/timeout suppression, expired replay,
CA migration, claim-key change, authenticated app-key lineage, and manifest-key
replacement. Each case is a single observation, not a latency distribution.
It retains protected highest-seen values and does not advance the device clock.
Migration retains the current TLS certificate during staging except for an
explicit alternate-certificate probe, waits a full configured interval, and
jointly switches the certificate and new-only policy. Only TLS server private
keys and public policies are deployed remotely; policy-signing keys stay local.
Use `--after-matrix /path/to/matrix.json` to queue the suite after a successful
comparison. Standard endpoint policies are renewed on exit so they are not
left below the test's newly accepted issuance floors.

After a complete run, independently recheck the raw decisions, request audits,
four expiration bounds, both real-time staging intervals, and manifest-root
replacement before using its results:

```bash
python3 summarize-remote-functional.py \
  results/policy-scenarios-new
```

The current suite expects 98 observations (49 per mode), including 95 audited
connection scenarios and three claim-only rollback probes. The summary refuses
partial runs. This is functional evidence, not an availability guarantee,
packet-level leakage measurement, or performance distribution.

The Android application ID is `com.cert.aspin`. The evaluated claim-retrieval
and ASPin connection paths obtain authenticated claims exclusively from the
OS-level ASPin service; the app does not use a legacy app-local claim path in
the reported measurements.

The OS exposes two query APIs:

- `getCertificateClaim(hostname)` is the self-query. Android derives the
  caller's App ID from its Binder identity and resolves the caller's verified
  signing key.
- `getCertificateClaimForApp(targetAppId, hostname)` is the cross-app query.
  App A can request the claim for an installed App B and App B's server
  hostname. Android resolves App B's verified signing key and caches the
  authenticated `(App B signing key, Subject, SAN, IssuerSet)` binding; it never
  accepts signing-key material from App A.

Each query resolves the target's current authenticated installed version and
signing certificate before cache lookup. A missing, uninstalled, or invisible B
causes an API failure, not a successful cached answer. App A may explicitly
choose native TLS alone for a lower-risk operation; financial or valuable-asset
operations should refuse the connection. That fallback is outside ASPin's
protection. Store-authenticated lookup without installing B is future work,
not an implemented Google Play identity API. Query-time resolution does not
retroactively revoke a claim already returned before a package change.

App A chooses B's package name and server hostname in advance. The OS resolves
B's signing key first, looks in that key's cache collection, and retrieves the
tokens from the supplied hostname when needed. A hostname can occur in several
independent signing-key collections; it does not select a unique policy owner.
Shared hosting needs no request-side owner selector: one General JWS `T_k` can
include an entry for each authorizing app key over the same delegation payload.
The already resolved `K_apub` filters the entries and verifies its signature;
the common delegated key verifies `T_c`. The verifier never derives a trust root
from the hostname or an untrusted `kid`. Co-signing does not merge owner caches
or imply signing lineage. The updated source accepts any non-empty `T_k`
signature array without a fixed signature-count limit; the 1 MiB token-response
bound still applies, and `T_c` retains its single-signature profile. Rotation
verification also searches the entire array for the required old-key signature.
Shared-host device tests have not yet been run, and this source update does not
change the reported device measurements. Adding signatures does not allow
different payloads inside one General JWS object.

To add authorizing owners to an existing `T_k`, use the repeatable `--signer`
option below. Each group specifies the algorithm, private-key file, and matching
SPKI public-key file. There is no limit on the number of groups. This preserves
the encoded payload and existing signatures, adds a protected `alg`/`kid` entry
for each new key, and writes only the public signed token. All owners must
authorize the same delegated key and validity interval. Supply real file paths
in place of the example paths:

```bash
python3 signing/cosign_claim_signing_key.py signing/es256/ClaimSigningKey.jws \
  --signer ES256 /secure/owner-b-key.pem /secure/owner-b-pubkey.pem \
  --signer ES384 /secure/owner-c-key.pem /secure/owner-c-pubkey.pem \
  --output /path/to/ClaimSigningKey.shared.jws
```

Host regressions for multi-signature generation, context-key selection, and
rotation signatures beyond the second entry use disposable keys. The AOSP test
extracts the actual verification methods and runs them with the AOSP JSON
library; it does not build an image or measure Android performance:

```bash
python3 -m unittest -v test_multi_signature.py
```

The prototype's `refreshCertificateClaim...` methods are forced-refresh
instrumentation for benchmark runs. The OS restricts them to debuggable apps
on debuggable builds; they are not additional production query APIs.

### Applying the OS-level AOSP patch bundle

The reproducible AOSP patch bundle is in `aosp-aspin/`:

- `base.xml` is the `android17-release` manifest. It pins the exact baseline
  revisions of the three modified projects.
- `patches.tar.zst` contains the `frameworks/base`, `external/conscrypt`, and
  `system/sepolicy` patches, a series file, source commit IDs, and internal
  SHA-256 checksums. The patches include parallel app-signing/manifest ASPin
  roots, native TLS token retrieval, and the independent NSC DCP verifier.
- `apply.sh` verifies the archive, the project revisions, the cleanliness of
  all three worktrees, and `git apply --check` before modifying any source file.

The patch set intentionally excludes unrelated local `build/soong` changes.
Use a clean checkout; `apply.sh` refuses to run if any target project is at
the wrong revision or already contains local changes.

The following example creates an AOSP checkout using the supplied baseline
manifest. `ASPIN_REPO` is this repository and `AOSP_ROOT` is the destination
for the Android source tree:

```bash
export ASPIN_REPO=/mnt/code/aspin
export AOSP_ROOT=/mnt/code/aosp-main/aosp

mkdir -p "$AOSP_ROOT"
cd "$AOSP_ROOT"
repo init \
  -u https://android.googlesource.com/platform/manifest \
  -b android17-release

# Make the supplied full manifest available to the existing manifest checkout,
# select it, and synchronize with 24-way parallelism.
cp "$ASPIN_REPO/aosp-aspin/base.xml" \
  "$AOSP_ROOT/.repo/manifests/aspin-base.xml"
repo init -m aspin-base.xml
repo sync -c -j24
```

Preflight and apply the patches:

```bash
"$ASPIN_REPO/aosp-aspin/apply.sh" --check "$AOSP_ROOT"
"$ASPIN_REPO/aosp-aspin/apply.sh" "$AOSP_ROOT"
```

The preflight mode performs all checks without changing the checkout. A
successful application leaves the ASPin changes as normal uncommitted Git
changes in `frameworks/base`, `external/conscrypt`, and `system/sepolicy`.

### Checking the patches against the paper's experimental runtime

`aosp-aspin/experiment-code.json` records a **retrospective** audit of the
preserved October 28 image and the October 29/30 paper sessions. It binds the
patch archive and three baseline/source trees, all 20 modified source files,
251 byte-identical Java classes, seven files read from the image, and the NSC
JAR inside its compressed Conscrypt APEX. Isolated recompilation used the
original compiler actions, with outputs redirected to temporary directories.
The image's build date, user, incremental version, and fingerprint match the
connection-matrix record. The audit does not rewrite experiment manifests,
evidence indexes, or paper measurements.

Check the archive, reconstructed source trees, and archived source revisions:

```bash
python3 aosp-aspin/check-experiment-code.py \
  --aosp-root /mnt/code/aosp-main/aosp
```

The general `check-implementation-consistency.py` also runs this source/patch
guard when the local AOSP checkout is available, catching later bundle drift.

With the preserved build directory, also check the actual image contents and
repeat the isolated Java recompilation as an independent background process:

```bash
systemd-run --user --unit="aspin-code-audit-$(date -u +%Y%m%dT%H%M%SZ)" \
  --remain-after-exit --property=WorkingDirectory=/mnt/code/aspin \
  /usr/bin/python3 /mnt/code/aspin/aosp-aspin/check-experiment-code.py \
  --aosp-root /mnt/code/aosp-main/aosp \
  --build-out /mnt/code/aosp-main/out/gsi-pixel8-arm64 --recompile
```

The current reproduction session retains the exact selected experiment driver
sources and public build inputs. The AOSP record binds the unchanged patch and
runtime to these snapshots and to the session's measured system-partition and
component digests. This is not a signed build attestation or a reproducible
full-image rebuild. Neither audit command flashes an image or performs device
measurements.

To require complete recorded driver-source coverage as well as the AOSP runtime,
run:

```bash
python3 aosp-aspin/check-experiment-code.py --require-complete-sources
```

This stricter check requires actual archived source bytes for the recorded
session, not substitute source versions or a hash-only declaration. After a
new complete session passes both independent evidence audits, bind the runtime
record to that session before retiring previous result directories:

```bash
python3 aosp-aspin/refresh-experiment-evidence.py \
  results/reproduction-20261114T062526Z
python3 aosp-aspin/check-experiment-code.py --require-complete-sources
```

Refreshing this metadata does not change the patch archive or any observation.
The session explicitly records the post-run reference-refresh timestamp.

Future runs of `run-internet-evaluation.py` archive the selected Java/Python
sources, build configuration, manifests, NSC XML, and public certificate/key
inputs in `source-snapshot/`, preserving relative paths and exact bytes alongside
`cohort.json`'s hashes. Private keys are outside this source allowlist.
The runner refuses source drift before the connection matrix and before
marking the cohort complete. Audit a newly generated cohort with:

```bash
python3 summarize-internet-evaluation.py /path/to/new-cohort \
  --require-source-snapshot --check-paper
```

The auditor checks the full snapshot inventory and each digest; missing,
modified, extra, or symlinked files fail. A successful snapshot check covers
only the selected sources, not a reproducible toolchain or device-image
attestation by itself. The top-level runner separately records the installed
image and component digests before measuring.

### Building the patched OS image

Build the framework, system service, and GSI system image with 24-way
parallelism:

```bash
cd "$AOSP_ROOT"
OUT_DIR=/mnt/code/aosp-main/out/gsi-pixel8-arm64 \
BUILD_USERNAME=exp \
SOONG_NINJA=ninja GOGC=20 GOMEMLIMIT=42GiB \
build/soong/soong_ui.bash --make-mode \
  TARGET_PRODUCT=gsi_arm64 \
  TARGET_RELEASE=trunk_staging \
  TARGET_BUILD_VARIANT=userdebug \
  -j24 services framework-minus-apex systemimage
```

Give the generated image the ASPin artifact name used by this project:

```bash
cp /mnt/code/aosp-main/out/gsi-pixel8-arm64/target/product/generic_arm64/system.img \
  /mnt/code/aosp-main/out/gsi-pixel8-arm64/target/product/generic_arm64/gsi-pixel8-arm64-system-aspin.img
```

For the Pixel 8 test device used in the paper, reboot to fastbootd and flash the
logical system partition. The bootloader must already be unlocked. This
operation replaces the current system image and may require a data wipe if the
device cannot boot the new GSI; back up the device first:

```bash
adb reboot fastboot
# Wait until `fastboot devices` lists the phone as `fastbootd`.
fastboot getvar is-userspace  # Expected: yes
fastboot flash system \
  /mnt/code/aosp-main/out/gsi-pixel8-arm64/target/product/generic_arm64/gsi-pixel8-arm64-system-aspin.img
fastboot reboot
```

After booting the userdebug image, verify that the service is registered before
installing the benchmark apps:

```bash
adb wait-for-device
adb shell service check aspin
# Expected: Service aspin: found
```

---

## 4. Web Server (Nginx) Deployment

### Repeatable public certificate issuance

`request-server-certificates.sh` submits the existing PKCS#10 CSRs through
Certbot and the **`certbot-dns-godaddy-v3`** DNS-01 plugin:

- `realserver/etc/cert/{dcp,es256,es384,rsa3072,rsa4096}` uses Let's Encrypt.
- `rogueserver/etc/cert/{es256,es384,rsa3072,rsa4096}` uses ZeroSSL.

Install Certbot and the v3 plugin in the **same** isolated Python environment.
For example, with a user-owned pipx installation:

```bash
pipx install certbot
pipx inject certbot certbot-dns-godaddy-v3
```

The script discovers the Python environment from `certbot` on `PATH`. For
other installations, set `--certbot-python /path/to/venv/bin/python`.
The main script needs the repository's `cryptography` dependency (version
42 or newer) and OpenSSL. It derives its repository root from its own path;
the current working directory does not matter.

Supply the PAT as `GODADDY_TOKEN` or in an owner-only `0600` environment
file. The PAT must grant `domains.domain:read` and `domains.dns:update`.
By default, the script reads
`$XDG_CONFIG_HOME/environment.d/91-aspin-godaddy-v3.conf` and, if present,
`90-aspin-zerossl.conf`; `$XDG_CONFIG_HOME` defaults to `$HOME/.config`.
Alternatively, provide `--env-file /secure/path/environment.conf` (repeatable)
or `--godaddy-credentials /secure/path/godaddy-v3.ini`, whose token field is
`dns_godaddy_v3_token`. Existing process environment variables take precedence.
Never put credential values in commands, committed files, or log messages.

ACME accounts, logs, temporary credential files, backups, and run manifests
are kept **outside this repository**, under
`$XDG_DATA_HOME/aspin-acme` (default `$HOME/.local/share/aspin-acme`).
The script reuses the existing accounts in `letsencrypt/config` and
`zerossl/config`, and **does not register accounts**. On the current host,
both accounts are already configured. A fresh host must first configure its
accounts; an EAB KID/HMAC key alone does not replace a saved ZeroSSL ACME
account and its private key. Use `--state-dir /secure/path/aspin-acme` to
select a different existing account store. If a CA has multiple accounts,
select `--letsencrypt-account ACCOUNT_ID` or `--zerossl-account ACCOUNT_ID`.

```bash
# Offline input validation and plan only: no certificate requests or DNS writes.
bash ./request-server-certificates.sh --dry-run

# Normal repeatable operation: renew only missing, invalid, or near-expiry certs.
bash ./request-server-certificates.sh

# Select one CA or one algorithm across the applicable CAs.
bash ./request-server-certificates.sh --ca letsencrypt
bash ./request-server-certificates.sh --ca zerossl --targets es256

# Preserve existing private keys and repair only mismatched CSRs before renewal.
bash ./request-server-certificates.sh --refresh-csr

# Review an unconditional reissuance plan, then explicitly force a new issuance.
bash ./request-server-certificates.sh --force --dry-run
bash ./request-server-certificates.sh --force
```

The default renewal threshold is 30 days (`--renew-before-days`), DNS
propagation wait is 120 seconds (`--propagation-seconds`), and challenge TTL
is 600 seconds (`--dns-ttl`). `--dry-run` means an **offline preflight**, not
Certbot's staging-CA test. `--force` can consume CA issuance limits; do not
use it for routine repeated checks. All selected CSRs must have valid
signatures, DNS SANs, and matching private keys before the first ACME request.
`--refresh-csr` preserves the existing subject/SAN and private key, and
backs up the original CSR. It never runs the old `gen_csr.sh` helpers, which
generate new private keys.

Each new certificate must match its CSR, existing private key, and DNS SANs;
its chain, fullchain, validity, issuer, and native OpenSSL hostname/path
verification must also pass. Only then are the three certificate files
backed up and replaced using their existing filenames. A failed validation
leaves the installed certificate unchanged. Successful earlier jobs remain
installed if a later job fails; rerunning normally skips those fresh
certificates. A state-directory lock prevents simultaneous runs. Per-run
`runs/<timestamp-random>/manifest.json` records outcomes and backup paths;
logs redact configured credentials, and temporary DNS credential files are
removed when the run exits.

The script modifies **only DNS-01 challenge records**, not A, AAAA, CNAME,
nameserver, or other DNS settings. Certbot cleans up its challenges; after an
uncatchable process termination, check for remaining challenge TXT records.
It does not reload Nginx, sync files to another host, update JWS claims/SCP
pins, build APKs, or run benchmarks. After certificate/issuer changes,
regenerate the corresponding trust artifacts with `gen-trust-artifacts.py`
before deploying the protected connection setup. CSR-mode certificates do
not configure Certbot automatic renewal; rerun this script before expiry.

Offline script tests (no CA or GoDaddy requests):

```bash
python3 -m unittest -v test_request_server_certificates
```

Deploy the Nginx server configurations for both the legitimate real server and
the controlled unauthorized-direct-issuer-CA test server.

The deployment and benchmark scripts recursively copy files from
`realserver/etc`, `realserver/var`, `rogueserver/etc`, and `rogueserver/var`
into the host's `/etc` and `/var`. Run them only on a dedicated benchmark host
or after backing up the existing Nginx configuration. The automated benchmark
scripts invoke `sudo -n`, so the required copy and `systemctl restart nginx`
operations must be permitted without an interactive password prompt:

```bash
sudo -n true
```

### Deploy Real Server Configuration
```bash
sudo cp -pr realserver/etc/* /etc/
sudo cp -pr realserver/var/* /var/
sudo systemctl restart nginx.service
```

### Deploy Rogue Server Configuration
```bash
sudo cp -pr rogueserver/etc/* /etc/
sudo cp -pr rogueserver/var/* /var/
sudo systemctl restart nginx.service
```

---

## 5. Running Benchmark Tests

For the current paper, use **Complete fresh Internet evaluation (preferred)**
above. The local diagnostic commands below are retained for development only;
their outputs, debug CAs, and ADB-forwarded paths are not current paper evidence.

Run benchmarks from the repository root. Before starting, verify all of the
following for those local diagnostics:

1. Exactly one Android device is connected through ADB. The scripts select the
   first device reported in the `device` state.
2. The device runs the patched userdebug image and reports
   `Service aspin: found`.
3. The device and local Nginx host are reachable over the same diagnostic
   network, or use the optional ADB reverse transport shown below.
4. Without ADB reverse, the five test hostnames resolve from the device to the
   Nginx benchmark host. With ADB reverse, the script temporarily maps them to
   loopback and restores the device hosts file on exit. Production ASPin calls
   reject loopback and other special-use DNS answers; the debug-build-only forced-
   refresh path explicitly permits loopback so this local benchmark can seed the
   cache. This exception is unavailable on production builds and ordinary calls.
5. Keep the device's normally assigned DNS servers; the experiment does not
   require forcing `8.8.8.8` or another public resolver.
6. `adb` is on `PATH`, and `ANDROID_HOME` points to an Android SDK with
   Build-Tools; the scripts otherwise use `/opt/android-sdk`. Set
   `ASPIN_JAVA_HOME` if JDK 21 is installed at a nonstandard path.

Useful preflight commands are:

```bash
cd /mnt/code/aspin
adb devices -l
adb shell service check aspin
adb shell 'su 0 id -u'                 # Required by the full robustness run
adb shell ping -c 1 es256.idouzi.top  # Repeat for the other test hostnames
sudo -n true
systemctl is-active nginx
python3 ./check-implementation-consistency.py
```

The consistency checker validates the current trust artifacts and statically
checks the two OS API paths, CertClaimCheck semantics, signing schemas,
public-channel ProVerif lifecycle models, 24-worker APK build setting, and
benchmark coverage. Each focused or full benchmark runs it automatically after
generating fresh artifacts.

Do not run any benchmark scripts in parallel. They install the same app ID
(`com.cert.aspin`), modify the same Nginx deployment, and may overwrite result
files. The robustness script takes a non-blocking host lock keyed by the device
serial number and refuses to start when another robustness run owns that lock.
Exit traps restore the real-server profile and uninstall the test apps, but an
interrupted process should still be checked before another run.

Only the fresh Internet cohort and its independent auditor are authoritative
for the current paper tables. The focused and local robustness commands below
are diagnostic helpers, not substitutes for the public-CA Internet suite.

### Focused Benchmark 1: Policy Refresh Latency
Measures the same OS service retrieval, verification, rollback, persistence,
and cache-commit path for primary ASPin and the Section 3.7 compatible ASPin
mode. SCP has no separately refreshable token and is therefore absent (default:
2,000 iterations):

```bash
BENCHMARK_TIMEOUT_SECONDS=7200 \
  ./run-avgveriftime-benchmark.sh 2000
```

Outputs:

- Per-algorithm and mode files:
  `results/benchmark_<alg>_<primary|compatible>_refresh.csv`
- Local diagnostic summary (not paper evidence):
  `results/table_refresh_summary.csv`

### Focused Benchmark 2: Connection Diagnostics
Measures connection setup and policy-check behavior (default: 2,000
iterations). This local diagnostic is not the source of the paper's controlled
unauthorized-issuer rows; use the fresh Internet workflow for those results:

```bash
BENCHMARK_TIMEOUT_SECONDS=7200 \
  ./run-avgvisittime-benchmark.sh 2000
```

For each algorithm the script installs four separate APKs in both the real-
server and controlled rogue-server phases. The primary APK measures native TLS
and primary ASPin. The SCP APK relies only on the standard NSC `pin-set`. The
DCP APK uses its separate manifest DCP key and NSC `dynamic-pin-set`.
The compatible ASPin APK uses manifest $K_{spub}$ through the ASPin service.
Neither the DCP baseline nor SCP is an ASPin service wrapper.
The aggregate robustness helper attributes only forced two-token refresh to
compatible ASPin; use the new comparison matrix for isolated compatible-mode
connection timings. Historical reduced-DCP refresh records retain their old
labels and are not interpreted as independent NSC DCP measurements.

Outputs:

- Per-algorithm, mode, and phase files:
  `results/benchmark_<alg>_<primary|scp|dcp>_<realserver|rogueserver>_connections.csv`
- Evaluation summary:
  `results/table_connection_summary.csv`

For a valid 2,000-iteration run, every summary row must contain `Result=PASS`.
The expected connection counts are:

- Real server: Standard TLS, ASPin, SCP, and DCP each succeed 2,000 times.
- Rogue server: Standard TLS succeeds 2,000 times; ASPin, SCP, and DCP each
  succeed zero times because all rogue-certificate attempts are rejected.

Both scripts install each algorithm-specific APK in turn, pull the generated
CSV, uninstall `com.cert.aspin`, and restore the real-server Nginx
configuration from their exit trap. They overwrite earlier CSV files with the
same names, so copy any result set that must be preserved before rerunning.

### RTT, Policy-Cache, and Connection-Outcome Matrix

The new matrix is test code; it has not yet produced device measurements or
changed the paper's Evaluation tables. It reuses the robustness harness's fresh
authorized/unexpected debug CAs and three APK configurations, but exits before
the reboot and clock-rollback experiments. It never builds AOSP or flashes a
device. It synchronizes the userdebug test clock to the host, then restores
automatic-time configuration on exit, as the existing harness does.

Run the matrix on a dedicated Linux benchmark host with `ip`, `tc`, Nginx,
Python 3, passwordless `sudo`, and an authorized rooted ASPin device:

```bash
# Small first run: 100 timed observations per cell, 10 excluded warmups.
bash ./run-rtt-cache-benchmark.sh 100

# Configurable measurement run; this is substantially longer.
ASPIN_RTT_VALUES_MS=0,20,50,100,200 ASPIN_RTT_REPEATS=3 \
ASPIN_RTT_WARMUPS=20 BENCHMARK_TIMEOUT_SECONDS=7200 \
  bash ./run-rtt-cache-benchmark.sh 2000
```

The default matrix has 320 cells: five added RTTs, four algorithm
configurations, two certificate profiles, and eight scheme/cache combinations.
The combinations are native TLS/no policy cache, SCP/static policy, and
ASPin primary, ASPin compatible, and independent NSC DCP each with hot and
cold-forced-refresh policy.
SCP and TLS do not have dynamic token caches and are not labeled hot/cold.
A same-RTT native-TLS baseline precedes each block and must accept both
certificate profiles. Protected-cell order and block order are shuffled using
`ASPIN_RTT_SEED` (default 2027), and the plan is recorded before measurement.

RTT is **added link delay**, not a claimed WAN or mobile-radio measurement.
The runner creates a unique network namespace and veth pair, applies half the
configured delay to each veth egress, and runs an isolated Nginx there. It does
not apply a qdisc to host loopback, Wi-Fi, USB, or a default-route interface.
Local TCP relays and adb reverse carry both token and TLS traffic through this
link. Every cell also measures 20 one-byte echo round trips from the device;
the observed echo P50/P95 and qdisc evidence are recorded separately from the
configured added RTT. Namespace processes, interfaces, and relays are cleaned
up on ordinary exit; an uncatchable kill requires checking for leftover
`aspin-rtt-*` namespaces. The wrapper retains the existing harness's temporary
device hosts/adb-reverse setup and cleanup.

`hot` requires zero `T_k/T_c` transfer/verification timing from the service.
`cold-forced-refresh` requires positive timings for **both** tokens on every
attempt. It uses the debug forced-refresh API and retains protected
highest-seen state; it is not first installation, an empty persistent state,
or a cold DNS/TLS/JIT experiment. In primary ASPin the timed operation includes
the claim API and TLS check. Compatible ASPin follows the same two-token path.
DCP performs one independent signed-pin lookup inside NSC; it never invokes
the ASPin API. On userdebug builds, the host sets `debug.aspin.dcp_cold=1`
for forced-cold DCP cells and restores it afterwards. DCP request-count audit
sidecars must confirm one preload fetch for hot cells or one fetch per warmup
and measured attempt for cold cells. An absent or failed audit cannot pass.
Each attempt creates a fresh SSL context and connection, with connection
reuse disabled at the private server. Before each compatible-mode RTT cell,
the runner restarts the Android framework (not the kernel) to clear volatile
ASPin token caches, retaining protected rollback state and adb forwarding.
This setup action is excluded from timing. Without it, an eligible cached
$K_{apub}$ claim could be mistaken for a $K_{spub}$ cache hit. This suite studies
fresh certificate authentication, not TLS resumption or long-lived connections.

Raw results preserve policy time, connection time, time to TLS acceptance or
policy rejection, and subsequent HTTP-read time separately. A protected rogue
attempt passes only for the exact scheme-specific certificate-policy failure;
timeouts, unrelated trust failures, lookup failures, and cache-regime mismatches
fail the cell. Rejection-path time is not a speed advantage over an accepting
TLS baseline. Summary percentiles pool raw observations across repetitions;
they are not means of per-run percentiles.

Outputs live under `results/robustness-<run>/rtt-cache/`:

- `matrix.json`: planned cells, order, warmup/sample counts, and completion state;
- `rtt-*.csv`: one row per measured attempt;
- `network/`: added-delay definition and qdisc settings; and
- `table_rtt_cache.csv`: validated means, P50/P95/P99, outcomes, and echo RTTs.

Revalidate or summarize an existing complete raw dataset with:

```bash
python3 ./summarize-rtt-cache-results.py results/robustness-<run>/rtt-cache
```

Offline checks (no device traffic or network configuration):

```bash
python3 -m unittest -v test_rtt_benchmark
cd ASPin/es256
./gradlew --offline --max-workers=24 :app:testDebugUnitTest \
  --tests com.cert.aspin.RttBenchmarkChecksTest
```

### Lifecycle Experiments: CA Migration and Key Rotation

Run the functional lifecycle suite separately from the latency distributions:

```bash
ASPIN_MIGRATION_LMAX_SECONDS=30 BENCHMARK_TIMEOUT_SECONDS=7200 \
  ./run-lifecycle-benchmark.sh 20
```

The functional lifecycle suite starts from the ES256 host/configuration; the
app-signing-key test rotates its app root to ES384. The CA-migration experiment
uses one Subject/SAN with independent current and new direct issuer CA
certificates. It evaluates the complete three-window
schedule from Table 3 of the paper:

- `w1`: current-only policy accepts `CurrCert` and rejects `NewCert`;
- `w2`: the server continues to deploy `CurrCert`, while the overlap claim
  contains `CurrCA+NewCA` and permits either controlled certificate;
- the harness keeps the overlap publication active until its signed lifetime
  reaches the experiment's full $L_{max}$; and
- `w3`: the harness jointly activates `NewCert` and the new-only claim, accepts
  `NewCert`, and rejects `CurrCert`.

The key-rotation experiment covers both delegated claim-key and app-signing-key
rotation. For the delegated key, it first accepts the old pair, rejects both
mixed old/new $T_k/T_c$ pairs, accepts the matched new pair, and rejects a
still-fresh replay of the old pair. For the app signing key, it installs an APK
under the old key, upgrades it with an Android-authenticated signing lineage,
accepts the dual-signed transitional $T_k$, accepts the new-key-only $T_k$ at
cutover, and rejects a replay of the transitional version. These are
correctness tests rather than latency samples.

The script generates fresh CAs, leaves their private keys only in a temporary
working directory, rebuilds the primary ES256 APK with both test CAs trusted by
native TLS, aligns the rooted userdebug device clock to the benchmark host, and
restores the clock, app, and Nginx state on exit. Its timestamped
`results/lifecycle-*` directory contains each raw probe and
`table_lifecycle_transitions.csv`, which must report `PASS` for every row. The
default $L_{max}$ is 30 seconds to keep this controlled test bounded; it is the
experiment profile's maximum permitted $T_c$ lifetime, not a protocol-wide
constant.

### Cross-Signed Direct-Issuer Certificates

When alternate native-valid paths use cross-signed variants of one direct issuer,
`IssuerSet` must contain the DER-based identifier of **every supported variant**,
not just one certificate or the shared public key. Ancestor roots do not enter
this set unless they directly issue the leaf. The publisher supplies the complete
variant collection; neither the signer nor the OS discovers unknown certificates.
The four claim signers accept multiple PEM chain/variant bundles and deduplicate
the matching direct issuers:

```bash
cd signing/es256
python3 gen_jws_ServerCertClaim.py LEAF.pem CHAIN_A.pem CHAIN_B.pem
```

Each supplied CA must directly verify the leaf; same-name wrong-key certificates
and unrelated ancestors are excluded. The artifact validator requires all direct
issuer variants present in the configured `real-chain.pem` bundle to be covered.

### Public-CA Same-CSR and Cross-Sign-Chain Experiment

The current device suite uses **only Android system roots**. The public endpoint
`cross.idouzi.top` points to `64.90.5.66`. One retained P-256 private key and one
PKCS#10 CSR are submitted, unchanged, to both Let's Encrypt and ZeroSSL through
Certbot DNS-01 and GoDaddy v3. Repeating the request preserves that key/CSR and
skips certificates valid beyond the renewal threshold. The script reuses existing
ACME accounts; it never registers an account or prints credential/private-key
values. To issue or renew as an independent background task:

```bash
cd /mnt/code/aspin
mkdir -p tmp
ASPIN_ISSUE_UNIT="aspin-public-cross-issue-$(date -u +%Y%m%dT%H%M%S)"
systemd-run --user --unit="$ASPIN_ISSUE_UNIT" \
  --property=WorkingDirectory=/mnt/code/aspin \
  --property="StandardOutput=append:/mnt/code/aspin/tmp/$ASPIN_ISSUE_UNIT.log" \
  --property="StandardError=append:/mnt/code/aspin/tmp/$ASPIN_ISSUE_UNIT.log" \
  /usr/bin/python3 /mnt/code/aspin/request-public-cross-certificates.py --configure-a
```

Public CSR/certificate outputs are under `public-cross/certificates/`:
`server.csr.pem`, `letsencrypt/real-{cert,chain,fullchain}.pem`,
`zerossl/rogue-cert.crt`, `zerossl/rogue-ca.crt`,
`zerossl/rogue-fullchain.pem`, and `issuance.json`. The single
`server-privkey.pem` is owner-only and explicitly Git-ignored. Credentials,
account keys and Certbot logs remain outside the repository. CSR-based Certbot
issuance does not create automatic-renewal configuration; rerun before expiry.
This does not add CSR upload to the paper synchronization script.
The legacy `rogue-` filename prefix denotes the second-CA test profile, not an
actual mis-issuance: both certificates were legitimately issued for our domain.

Two public CAs signing the same CSR produce **different leaf certificates with
the same TLS public key**, not cross-signed variants of one intermediate. The
issued LE chain contains public ancestor cross-certificates (Root YE and
ISRG Root X2); its full and shortened presentations retain the SAME direct
issuer. The experiment reports these facts separately and never relabels the
two leaves as a cross-signed intermediate.

The current run's `results/reproduction-20261114T062526Z/internet/public-cross/` contains 360
attempts: 200 accepted, 160 issuer-policy rejections, and 200 matching tagged
application requests. Native verification succeeded in every attempt. Both LE
presentations selected the same ISRG Root X2 path; the ZeroSSL path terminated
at the system Sectigo Root E46. No locally generated CA is trusted by these
APKs. `checks.json` explicitly marks direct-issuer cross-signing as untested on
device. Earlier result directories do not contribute observations and are
retired after the new complete session passes its audits.

`run-public-cross-benchmark.py` has nine cases per mode, 20 attempts per case:
LE-only policy accepts LE and rejects ZeroSSL, including a peer list padded with
the authorized LE issuer; the dual policy accepts both issuers and both LE chain
presentations; a policy listing only a non-direct ancestor is rejected; ZeroSSL-only
policy accepts ZeroSSL and rejects LE. Only the two public-root-only ES256 APKs
are built, with 24 workers. Every attempt records the actual native-selected path
as fingerprints AND DER, peer input, OS-returned issuer set, decision, and request
tag. Timeouts and unrelated native-TLS failures cannot pass negative cases.

To repeat using the saved public endpoint deployment (use the original
`remote-experiment/deployments/main.json` only for its first SNI setup):

```bash
ASPIN_CROSS_RUN="/mnt/code/aspin/results/public-cross-$(date -u +%Y%m%dT%H%M%S)"
ASPIN_CROSS_UNIT="aspin-public-cross-$(date -u +%Y%m%dT%H%M%S)"
systemd-run --user --unit="$ASPIN_CROSS_UNIT" \
  --property=WorkingDirectory=/mnt/code/aspin \
  --property="StandardOutput=append:/mnt/code/aspin/tmp/$ASPIN_CROSS_UNIT.log" \
  --property="StandardError=append:/mnt/code/aspin/tmp/$ASPIN_CROSS_UNIT.log" \
  --setenv=JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
  --setenv=ANDROID_HOME=/opt/android-sdk \
  /usr/bin/python3 /mnt/code/aspin/run-public-cross-benchmark.py \
  --deployment /mnt/code/aspin/remote-experiment/deployments/public-cross.json \
  --restore-apk /mnt/code/aspin/results/reproduction-20261114T062526Z/internet/apks/ASPin-es256.apk \
  --run-dir "$ASPIN_CROSS_RUN" --iterations 20
```

After successful completion, independently verify the raw observations, actual
JWS signatures, native DER paths against the archived Android system root store,
the one-CSR/two-leaf public-key relationship, and per-case server audits:

```bash
python3 summarize-public-cross-results.py "$ASPIN_CROSS_RUN"
```

The runner never flashes, adds a root, uninstalls the app, changes the clock or
resets protected state. It restores the original app and power setting. Initial
SNI setup adds only the requested hostname and uses HAProxy's graceful
master-worker reload; unrelated routes and the default backend are retained.
On success it leaves the new endpoint serving the LE certificate and a fresh,
higher-`iat` dual-issuer policy. On failed initial setup it restores the previous
SNI configuration. Private app/delegation keys stay local; only the endpoint's
TLS key and public policies reach the isolated server. Saved failure directories
are never overwritten or reclassified as passes. Unlabeled public requests are
archived separately, not attributed to always-tagged device probes; duplicate,
missing, or wrongly labeled probe requests still fail validation.

Local correctness tests also generate disposable certificates and signed JWS
objects, validate both chains with OpenSSL, and check the evidence validator:

```bash
python3 -m unittest -v test_public_cross.py test_cross_sign.py
```

Those disposable-certificate tests are host regressions, not the current
public-root-only Android measurements. Earlier local-root device observations
are retained only as historical results and are not the current Evaluation.
The corresponding primary and compatible ProVerif models have separate result
logs: all 15 primary and 18 compatibility queries have their expected outcomes.
Their witnesses distinguish native-valid unauthorized issuers from unrelated
TLS failures and reach issuer-policy refusal both with and without padding.

### Optional Cross-App API Smoke Test

The following test installs App B as `com.cert.aspin`, installs a separately
signed App A as `com.cert.aspin.caller`, and has App A request
`getCertificateClaimForApp(com.cert.aspin, es256.idouzi.top)`. Because App A is deliberately signed with
a different key, successful verification demonstrates that the OS used App B's
signing key rather than the caller's key:

```bash
./run-cross-app-aspin-smoke.sh
```

- Output: `results/cross_app_target_claim.csv`

### Local Robustness Diagnostics (not paper data)

Collect complete-refresh and tail-latency distributions, cached concurrent
calls, restart persistence, fail-closed clock rollback, and a named-target run
between independently signed apps:

```bash
ASPIN_ADB_REVERSE_TRANSPORT=1 ASPIN_GENERATE_ROGUE_CA=1 \
ASPIN_CONCURRENCY_THREADS=8 BENCHMARK_TIMEOUT_SECONDS=7200 \
ASPIN_AOSP_FRAMEWORKS_BASE=/mnt/code/aosp-main/aosp/frameworks/base \
ASPIN_FLASHED_IMAGE=/mnt/code/aosp-main/out/gsi-pixel8-arm64/target/product/generic_arm64/gsi-pixel8-arm64-system-aspin.img \
  ./run-robustness-benchmark.sh 2000
```

The script does not build AOSP or flash a device. It refuses to start unless
`service list` exposes the OS-level `aspin` service. It builds only the test
apps, uses 24 Gradle workers, writes CSVs to app-private storage, and pulls them
as root. By default it generates two fresh short-lived benchmark CAs and
hostname-valid leaves for each configuration. One CA signs the legitimate
profile and its certificate digest is placed in the generated ASPin policy;
the other signs the controlled unauthorized-issuer profile. Both CAs are added
only to debug APKs through an Android network-security configuration; release
builds contain neither them nor the configuration. Native TLS therefore
accepts both profiles, while ASPin, SCP, and DCP reject the profile whose direct
issuer CA certificate is absent from policy. Benchmark CA and leaf certificates
are retained with the results, but generated CA and leaf private keys are removed
by the exit trap. A timestamped
directory under `results/robustness-*` contains:

- `cold-refresh-<alg>.csv`: four-algorithm end-to-end API/IPC, both token
  downloads and verifications, persistent anti-rollback write, and cache
  commit, with ASPin and DCP mean/p50/p95/p99;
- `cached-{real,rogue}-<alg>.csv`: mean/p95/p99 and acceptance counts for TLS,
  ASPin, SCP, and DCP against both server profiles;
- `concurrent-cache-<alg>.csv`: four-algorithm 8-thread cached self-query
  latency, failures, and throughput;
- `post-restart-old-{tk,tc}-replay.csv`: after accepting higher-iat tokens and
  rebooting, independent replay of each still-fresh older token must fail with
  the anti-rollback reason. `post-restart-current-tokens.csv` then confirms the
  current pair remains usable;
- `clock-rollback.csv`: expected fail-closed result after a two-day wall-clock
  rollback with an explicit `not fresh` reason, followed by `clock-restored.csv`;
- `cross-app-target-refresh.csv` and `cross-app-concurrent-cache.csv`: forced
  refresh and cached named-target calls from an app signed independently of the
  target; and
- `parallel-cold-refresh.csv`: two different signing-key/hostname contexts
  refresh concurrently, detecting accidental global serialization around the
  network path;
- `delegation-expiry.csv`: publishes a pair whose two expirations differ by one
  hour and verifies that the OS-returned claim expiration is exactly
  `min(exp_k, exp_c)`; and
- `table_full_refresh_tail.csv`, `table_connection_tail.csv`,
  `table_concurrency.csv`, and `table_lifecycle.csv`: validated, compact tables
  produced by `summarize-robustness-results.py` for local diagnostics only.

Set `ASPIN_SKIP_APP_BUILD=1` to reuse already built app APKs. The script still
regenerates fresh signed trust artifacts, deletes every device-side CSV before
starting its benchmark, forces a fresh legitimate claim before the connection
preflights, requires exactly one result row, and aborts unless each row's
correctness field is `PASS`. It requires a rooted userdebug phone for the
clock test and passwordless `sudo` for switching the dedicated Nginx host. After
the lifecycle reboot it waits for Android boot completion, the primary user to
become unlocked, and reachability of `ASPIN_NETWORK_CHECK_HOST` (the ES256 test
host by default); adjust the bound with `ASPIN_NETWORK_WAIT_SECONDS` if network
association is slow.

Do not use these local `table_*.csv` files as inputs for current paper tables.
The fresh Internet cohort replaces that earlier workflow. Preserve the whole
directory, including `environment.txt` and `token-snapshots/`, so the device,
build fingerprint, parameters, AOSP commit/dirty state, flashed-image digest,
and lifecycle artifacts remain auditable.

If a run is interrupted only after it has accepted v2 and rebooted, preserve
the timestamped result directory and resume the lifecycle/cross-app phase:

```bash
ASPIN_RESUME_AFTER_REBOOT=1 \
ASPIN_RESUME_RUN_DIR="$PWD/results/robustness-<run-id>" \
  ./run-robustness-benchmark.sh 2000
```

If the four-algorithm distributions completed but execution stopped before v1
was accepted, resume at the lifecycle phase instead:

```bash
ASPIN_RESUME_LIFECYCLE=1 \
ASPIN_RESUME_RUN_DIR="$PWD/results/robustness-<run-id>" \
  ./run-robustness-benchmark.sh 2000
```

`ASPIN_EXPIRY_ONLY=1` is a diagnostic recovery mode for regenerating only the
non-degenerate delegation-expiration probe in an otherwise complete run. The
normal full benchmark runs this probe after the replay and clock tests because
it intentionally publishes a newer ES256 pair with unequal lifetimes.

Resume mode requires the saved v1/v2 token snapshots and revalidates every
new CSV before regenerating all four compact summary tables.

The two app identities emulate separate signing domains; the result verifies
the mechanism needed by a cross-vendor deployment but does not claim that two
external vendors participated in the experiment.

---

### Fail-Closed Availability and Cross-App Connection Scenarios

The new scenario harness is implemented and locally checked, but **has not yet
been run on the device**. Its results must not be presented as measurements.
It covers both the primary app-signing root and the manifest-authenticated
compatible root, using ES256 artifacts and a differently signed caller app.
One independent repeat plans 94 observations:

- Cross-app: B self-query primes policy; A retrieves the same policy through
  the explicit-target API and completes a protected connection. A native-only
  control accepts the unauthorized-issuer certificate, while A's B-policy check
  rejects it. A self-query cannot substitute A's identity for B. Caller-signed
  delegation substitution, an invisible target, and an uninstalled target must
  fail before protected TLS. Reinstallation restores target lookup.
- Availability: only the policy endpoints return 503 or withhold responses;
  business TLS stays reachable. Both self and cross-app queries use fresh cache
  entries without downloads. The harness then waits for real signed expiry,
  rejects expired artifacts, and restores higher-`iat` artifacts. Separate trials
  make `exp_k` and `exp_c` impose `exp_f`; protected highest-seen state is retained.
- Evidence: one complete app CSV per observation, plus tagged server HTTP logs.
  Expected failures require the specific lookup error or typed unauthorized-issuer
  rejection. Unexpected TLS/network/parser/state errors fail the run. A rejected
  observation must produce zero tagged application requests at the server.
  This is HTTP-request evidence, not packet-level leakage measurement.

The existing OS permits local/special-use retrieval only through the **debug
forced-refresh API**. Ordinary fresh-cache queries use normal APIs. At expiry,
the ordinary query must first reject at the special-use egress guard; subsequent
503/timeout/replay probes explicitly use debug forced refresh after expiration.
These are separate cases in the raw results. They do not establish production
automatic-refresh behavior over the loopback transport. No protected-state reset,
clock rollback, reboot, AOSP build, or flash occurs. The harness synchronizes the
device clock as the existing robustness setup does and restores automatic time.

When device testing is authorized, run on a dedicated test host/device:

```bash
cd /mnt/code/aspin
systemd-run --user --unit=aspin-policy-scenarios --collect \
  --working-directory=/mnt/code/aspin \
  /bin/bash /mnt/code/aspin/run-policy-scenario-benchmark.sh 1
journalctl --user -u aspin-policy-scenarios -f
```

`ASPIN_POLICY_SHORT_SECONDS=60` selects the short token lifetime (minimum 30 s).
Pass a larger repeat count for independently re-primed trials; each case is one
observation per repeat, not a latency distribution. Temporary namespace services,
the three touched reverse mappings, device hosts configuration and test apps are
cleaned up as in the isolated RTT harness. Do not run alongside another benchmark.

Raw evidence is saved under `results/robustness-<timestamp>/policy-scenarios/`.
The summary refuses missing observations, unexpected outcomes, incorrect identity
or cache evidence, and disagreement with the server request audit:

```bash
python3 run-policy-scenario-matrix.py --summary-only \
  --run-dir results/robustness-<timestamp>/policy-scenarios
python3 -m unittest -v test_policy_scenarios.py test_rtt_benchmark.py
```

## 6. ProVerif Formal Verification & Consistency Check

### Detailed Model and Evaluation Specifications

The `spec/` directory contains the model/prototype evidence crosswalk, detailed
symbolic encodings, trace-level explanations, and experimental procedures
accompanying Appendices B and C:

- [Specification index](spec/README.md): document scope, source/result locations,
  and consistency-check commands.
- [Model assumptions and Android prototype gap](spec/model-prototype-gap.md):
  the complete model/experiment consistency table, time and storage assumptions,
  operator obligations, lifecycle coverage, and availability boundaries.
- [Model setup and connection behavior](spec/proverif-models.md): the 29-model
  inventory, trust roots, query interpretation, network and cross-app models,
  cache isolation, multi-signature filtering, and fail-closed behavior.
- [Certificate and key lifecycles](spec/proverif-lifecycle.md): certificate change,
  cross-signed issuers, CA migration, claim-key and app-key rotation,
  manifest-root replacement, cross-hostname state transfer, and limitations.
- [Evaluation protocol](spec/evaluation-protocol.md): signature profiles,
  baseline fairness, connection timing, cache/API measurements, robustness,
  evidence audits, and statistical scope.
- [Evaluation scenarios](spec/evaluation-scenarios.md): cross-app and fail-closed
  procedures, public-CA chains, CA migration, claim-key rotation, app updates,
  and manifest-root replacement.

These documents explain the existing model sources and saved outputs. They do
not introduce additional proofs or Android measurements. The paper retains the
security results, essential assumptions, and a brief model/prototype boundary;
the detailed evidence crosswalk is in the linked gap specification.

### Execute All ProVerif Models
Run all twenty-nine symbolic formal security models (twenty-six ASPin instances and
three native-TLS baselines):

```bash
cd proverif
./run.sh
```

The ASPin models give the two token payloads the same fields as the paper:
$T_k=(K_{cpub},iat_k,exp_k)$ and
$T_c=(Subject,SAN,IssuerSet,iat_c,exp_c)$. Issuer identifiers are abstract atoms
in most models; the cross-sign model instead applies a symbolic hash to distinct
CA-certificate structures. DER parsing and base64url encoding are tested in the implementation rather
than modeled symbolically. There is no independent token `scope`
field. The requested hostname is constrained by the signed Subject/SAN server
identity. The $T_k$ cache is partitioned by app-signing key and hostname, the
$T_c$ cache by app-signing key and signed Subject/SAN, and a cached $T_c$ is
readable only when a fresh hostname-local $T_k$ yields the delegated key that
authenticated it. The models
also require both tokens to be fresh when a claim is accepted, bound cached
claim use by the earlier of `exp_k` and `exp_c`, derive (rather than trust) each
TTL, reject `now == exp`, and keep
highest-seen-`iat` rollback state independent of the cache. The cache model
checks cross-signing-identity/cross-delegation/cross-host isolation, migration,
and emergency replacement. The dedicated lifecycle models provide separate
result logs:

- `proverif/aspin_ca_migration.pv`: current-only, dual-issuer overlap held for a
  full symbolic $L_{max}$, and joint new-certificate/new-only-policy activation.
  Native-valid certificate decisions reach all intended phases; incompatible
  issuer sets and the expired overlap claim cannot authorize cutover. Phase
  advance does not wait for a client acknowledgement.
- `proverif/aspin_claim_key_rotation.pv`: a fresh cached old delegation, claim
  cache eviction, one authenticated delegation refresh, and one claim retry.
  The model reaches successful rotation and retry exhaustion, excludes mixed
  old/new signing-key pairs, and independently rejects still-fresh $T_k$ and
  $T_c$ rollback. It also reaches acceptance of an unexpired old pair before a
  newer pair is authenticated.
- `proverif/aspin_key_rotation.pv`: old-key-only, dual-signed transition, and
  new-key-only app-signing stages. The updated verifier checks both signatures
  over the same payload before transferring the $H_k/H_c$ lineage maxima;
  still-fresh predecessor replays are rejected after cutover.
- `proverif/aspin_certificate_change.pv`: the same fresh token pair accepts an
  original leaf, a renewed serial number with the same TLS key, and a new TLS
  key under the same authorized issuer. Wrong hostnames, invalid certificate
  signatures, unauthorized issuers, and expired-policy acceptance are excluded.
- `proverif/aspin_cross_hostname_hc.pv`: a claim observed through hostname A
  establishes a shared Subject/SAN rollback floor. After an authenticated root
  change, hostname B has no earlier `H_k` and can initialize it with a
  current-root-only token, but must retain or advance the inherited `H_c`.
  Unexpired below-floor claims are rejected.
- `proverif/aspin_cross_sign.pv`: two CA certificates share a Subject/key but
  have different trusted signing roots and complete-certificate identifiers.
  A complete signed set permits either path; a deliberately incomplete policy
  rejects the omitted variant. Same-name wrong-key CA acceptance, including a
  peer list padded with an authorized certificate, is unreachable. Token
  provenance and native-validation correspondences hold, and expiry rejection
  is reachable. This abstracts path building, hashing, and variant discovery.
- `proverif/aspin_multisig.pv` and its compatible counterpart represent one
  common `T_k` payload and an unbounded signature list. Recursive membership
  selects a candidate internally; the resolved root, matching `kid`, and
  signature authenticate it. Arbitrary public list construction is allowed,
  with no signature-count bound. A witness accepts a target signature in entry
  three. Owner substitution and payload splicing are excluded; empty,
  missing-owner, forged-`kid`, and spliced-payload controls reach rejection.
  This abstracts scan order, completion, JSON parsing, and byte limits.
- `proverif/aspin_multisig_rotation.pv`: a primary-mode co-hosted transition
  places the required new/old signatures in entries three and four. Both must
  authenticate the same payload before protected lineage and `H_k/H_c` state
  authorize a maximum-preserving transfer. Co-signing without lineage reaches
  refusal, not transfer. This supplements the complete rotation/replay model;
  it does not add cross-`K_s` state transfer or a device measurement.

Each lifecycle has a compatible counterpart. The native installer verifies the
app package's signature, which covers its manifest and authenticates `K_spub`
under the app-signing certificate. The OS reads the current installed manifest;
it does not maintain an independent manifest-root store or root history.

`aspin_compat_root_rotation.pv` separately checks replacement through a signed
app update. A dual-signed transitional token serves old and updated app versions;
each verifies its own current root's entry. A wrong package signature or an
old-root-only token cannot authorize the new root. Changing `K_s` starts a new
state namespace: old-root `H_k/H_c` values are not automatically inherited.
The model explicitly witnesses this boundary, then checks replay rejection
after higher versions have been accepted under the new root.

The compatible cross-hostname model keeps `K_s` unchanged. Hostname B can
initialize `H_k` while retaining the Subject/SAN `H_c` established through A.
This is not a claim of state transfer across different `K_s` values.

`aspin_availability.pv` and `aspin_compat_availability.pv` verify conditional
fail-closed safety with an explicit local retrieval-failure abstraction. Fresh
cached use, both token-expiration bounds, refusal after failure, expired replay
rejection, and recovery after fresh delivery all have reachability witnesses.
No protected connection/data event is reachable with an unusable cache and failed
retrieval. Silence in asynchronous ProVerif is not a timeout; the models do not
prove eventual delivery, fairness, or service availability against suppression.

`aspin_cross_app.pv` and `aspin_compat_cross_app.pv` separately model a differently
signed A requesting B's policy, even with A's policy-root private key disclosed.
Data output implies B-root resolution, authenticated policy, native certificate
checks, leaf-key possession, and the protected connection. Caller-root substitution
and unauthorized-issuer output are unreachable. Missing/invisible-target refusal
is an explicit OS resolution outcome on the opt-in protected path. A caller's
optional native-TLS-only fallback is outside the model's guarantees. Current
installed identity is abstracted at query time, not concurrent installation
scheduling. Concrete visibility remains an OS assumption, not a business-
authorization guarantee.

Nine compatible sources (six certificate/lifecycle, one fail-closed, one cross-app,
and one multi-signature) are generated from the primary models to keep
verification, freshness, and rollback logic synchronized; the `K_s`-replacement
model is maintained separately. The checker compares corresponding queries and
also checks APK-signature provenance. After editing a source lifecycle model,
regenerate the derived instances before running the suite:

```bash
python3 proverif/generate_compatible_models.py
```

`proverif/run.sh` checks that these generated files are current before parsing
and running all twenty-nine models. The models assume OS-authenticated installation
and authorized updates. APK parsing, downgrade policy, and implementation of
the installation pipeline are outside the symbolic model.

`aspin_parallel_roots.pv` additionally checks that the same installed app can
authorize claims through either $K_{apub}$ or manifest $K_{spub}$. Its ten
queries establish authorized-root/signature provenance, reachability of both
legitimate paths, and separate cache namespaces; it does not model root-priority
timing or concurrent package updates. Enabling both roots adds an authority:
publishers must coordinate their policies and cannot revoke another root's
still-fresh policy by updating only one namespace.

Lifecycle verifiers read all tokens and candidate peer certificates from the
public attacker-controlled channel. Private channels carry phase signals,
protected state, and internal signature-filter requests/results; those requests
copy the public token and use a context root already selected by the OS.
Finite negative controls are constructed locally. The dedicated lifecycle
models cover both primary and compatible ASPin. The separate compatibility
network model covers trust-root selection and rogue-endpoint rejection; its
scope does not include the primary model's terminating-MITM relay.

### Verify Consistency Across Code, Models, and LaTeX Text
Verify that the ProVerif models, output logs, Android Java code, Python scripts, and LaTeX paper tables remain 100% aligned:

```bash
python3 proverif/check_consistency.py
```

For a source/artifact/App/benchmark check that does not depend on saved
ProVerif output logs, run:

```bash
python3 ./check-implementation-consistency.py
```
