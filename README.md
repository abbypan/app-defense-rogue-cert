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
uses JDK 17 when `/usr/lib/jvm/java-17-openjdk` is available.

---

## 2. Trust Artifact Generation

Generate short-lived claim-signing public key tokens ($T_k$) and certificate claim tokens ($T_c$) across all 4 evaluated cryptographic algorithm suites (`es256`, `es384`, `rsa3072`, `rsa4096`), and synchronize them to Nginx web root directories:

```bash
python3 ./gen-trust-artifacts.py
```

Generation fails unless both compact JWS artifacts use exactly the TeX schema,
their `kid` values identify the configured app/claim keys, signatures verify,
the APK signing certificate matches the $T_k$ trust anchor, and the Subject,
SAN, and DER-derived IssuerId match the source server certificate.

This updates:
- `ClaimSigningKey.jwt` ($T_k$)
- `ServerCertClaim.jwt` ($T_c$)
- `DCPServerCertPin.json` (DCP baseline pin)
- Synchronizes tokens to `realserver/var/www/<alg>/.well-known/`

The `issuer` array in $T_c$ contains deterministic identifiers of the form
`sha256:base64url(SHA-256(DER(issuer Name)))`. Generators derive them directly
from the intended leaf certificate, and the app derives the same value from
`X500Principal.getEncoded()`. Provider-specific X.500 display strings are not
part of the comparison.

---

## 3. Building & Signing Algorithm-Specific APKs

Build and sign the Android client APKs for all four key algorithm suites (`ASPin-es256.apk`, `ASPin-es384.apk`, `ASPin-rsa3072.apk`, `ASPin-rsa4096.apk`):

```bash
python3 ./gen-signed-apks.py --output-dir results/apks
```

The Android Gradle Plugin requires JDK 11 or newer. The benchmark scripts use
`/usr/lib/jvm/java-17-openjdk` when it is available; set `ASPIN_JAVA_HOME` to a
different JDK 11+ installation when needed.

The compiled and signed APKs will be saved in `results/apks/`.

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

The prototype's `refreshCertificateClaim...` methods are forced-refresh
instrumentation for benchmark runs. The OS restricts them to debuggable apps
on debuggable builds; they are not additional production query APIs.

### Applying the OS-level AOSP patch bundle

The reproducible AOSP patch bundle is in `aosp-aspin/`:

- `base.xml` is the `android17-release` manifest. It pins the exact baseline
  revisions of the two modified projects.
- `patches.tar.zst` contains the `frameworks/base` and `system/sepolicy`
  patches, a series file, and internal SHA-256 checksums.
- `apply.sh` verifies the archive, the project revisions, the cleanliness of
  both worktrees, and `git apply --check` before modifying any source file.

The patch set intentionally excludes unrelated local `build/soong` changes.
Use a clean checkout; `apply.sh` refuses to run if either target project is at
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
changes in `frameworks/base` and `system/sepolicy`.

### Building the patched OS image

Build the framework, system service, and GSI system image with 24-way
parallelism:

```bash
cd "$AOSP_ROOT"
OUT_DIR=/mnt/code/aosp-main/out/gsi-pixel8-arm64 \
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

Flash the image using the device-specific GSI/fastboot procedure. Flashing can
erase device data, so it is intentionally not automated here. After booting
the userdebug image, verify that the service is registered before installing
the benchmark apps:

```bash
adb wait-for-device
adb shell service check aspin
# Expected: Service aspin: found
```

---

## 4. Web Server (Nginx) Deployment

Deploy the Nginx server configurations for both the legitimate real server and the malicious rogue server.

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

Run benchmarks from the repository root. Before starting, verify all of the
following:

1. Exactly one Android device is connected through ADB. The scripts select the
   first device reported in the `device` state.
2. The device runs the patched userdebug image and reports
   `Service aspin: found`.
3. The device and Nginx host are reachable over the same benchmark network.
4. `es256.idouzi.top`, `es384.idouzi.top`, `rsa3072.idouzi.top`,
   `rsa4096.idouzi.top`, and `dcp.idouzi.top` resolve from the device to the
   Nginx benchmark host.
5. Keep the device's normally assigned DNS servers; the experiment does not
   require forcing `8.8.8.8` or another public resolver.
6. `adb` is on `PATH`, and `ANDROID_HOME` points to an Android SDK with
   Build-Tools; the scripts otherwise use `/opt/android-sdk`. Set
   `ASPIN_JAVA_HOME` if JDK 17 is installed at a nonstandard path.

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
files. Exit traps restore the real-server profile and uninstall the test apps,
but an interrupted process should still be checked before another run.

For the complete Evaluation dataset, use the robustness benchmark described
below; it covers forced-refresh distributions, real/rogue cached connections,
concurrency, restart persistence, clock rollback, and cross-app target lookup
in one timestamped run. The two focused scripts are useful when only one paper
table needs to be repeated.

### Focused Benchmark 1: Verification Latency (`table:osveriftime`)
Measures the OS service's retrieval-and-verification times for $T_k$ and $T_c$,
and the DCP baseline pin retrieval-and-verification time, on the Android device (default:
2,000 iterations):

```bash
BENCHMARK_TIMEOUT_SECONDS=7200 \
  ./run-avgveriftime-benchmark.sh 2000
```

Outputs:

- Per-algorithm files:
  `results/benchmark_<alg>_avgveriftime.csv`
- Evaluation summary:
  `results/table_avgveriftime_summary.csv`

### Focused Benchmark 2: Real & Rogue Connections (`table:connectiontime`)
Measures connection setup times against the real server and real-time rejection latencies against a malicious rogue server presenting an unauthorized certificate (default: 2,000 iterations):

```bash
BENCHMARK_TIMEOUT_SECONDS=7200 \
  ./run-avgvisittime-benchmark.sh 2000
```

This is the long-running test: for each of four algorithms it executes a real
server phase and a rogue server phase, and each iteration measures Standard
TLS, ASPin, SCP, and DCP sequentially.

Outputs:

- Per-algorithm and per-phase files:
  `results/benchmark_<alg>_<realserver|rogueserver>_avgvisittime.csv`
- Evaluation summary:
  `results/table_avgvisittime_summary.csv`

For a valid 2,000-iteration run, every summary row must contain
`Matches_TeX_Design=PASS`. The expected connection counts are:

- Real server: Standard TLS, ASPin, SCP, and DCP each succeed 2,000 times.
- Rogue server: Standard TLS succeeds 2,000 times; ASPin, SCP, and DCP each
  succeed zero times because all rogue-certificate attempts are rejected.

Both scripts install each algorithm-specific APK in turn, pull the generated
CSV, uninstall `com.cert.aspin`, and restore the real-server Nginx
configuration from their exit trap. They overwrite earlier CSV files with the
same names, so copy any result set that must be preserved before rerunning.

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

### Recommended Full Evaluation Benchmark

Collect complete-refresh and tail-latency distributions, cached concurrent
calls, restart persistence, fail-closed clock rollback, and a named-target run
between independently signed apps:

```bash
ASPIN_CONCURRENCY_THREADS=8 BENCHMARK_TIMEOUT_SECONDS=7200 \
  ./run-robustness-benchmark.sh 2000
```

The script does not build AOSP or flash a device. It refuses to start unless
`service list` exposes the OS-level `aspin` service. It builds only the test
apps, uses 24 Gradle workers, and writes a timestamped directory under
`results/robustness-*` containing:

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
- `table_full_refresh_tail.csv`, `table_connection_tail.csv`,
  `table_concurrency.csv`, and `table_lifecycle.csv`: validated, compact tables
  produced by `summarize-robustness-results.py` for the Evaluation section.

Set `ASPIN_SKIP_APP_BUILD=1` to reuse already built app APKs. The script still
regenerates fresh signed trust artifacts, deletes every device-side CSV before
starting its benchmark, requires exactly one result row, and aborts unless each
row's correctness field is `PASS`. It requires a rooted userdebug phone for the
clock test and passwordless `sudo` for switching the dedicated Nginx host. After
the lifecycle reboot it waits for both Android boot completion and reachability
of `ASPIN_NETWORK_CHECK_HOST` (the ES256 test host by default); adjust the bound
with `ASPIN_NETWORK_WAIT_SECONDS` if Wi-Fi association is slow.

After a successful run, use the four `table_*.csv` files in the timestamped
directory as the compact inputs for the paper tables. Preserve the whole
directory, including `environment.txt` and `token-snapshots/`, so the device,
build fingerprint, parameters, and lifecycle artifacts remain auditable.

If a run is interrupted only after it has accepted v2 and rebooted, preserve
the timestamped result directory and resume the lifecycle/cross-app phase:

```bash
ASPIN_RESUME_AFTER_REBOOT=1 \
ASPIN_RESUME_RUN_DIR="$PWD/results/robustness-<run-id>" \
  ./run-robustness-benchmark.sh 2000
```

Resume mode requires the saved v1/v2 token snapshots and revalidates every
new CSV before regenerating all four compact summary tables.

The two app identities emulate separate signing domains; the result verifies
the mechanism needed by a cross-vendor deployment but does not claim that two
external vendors participated in the experiment.

---

## 6. ProVerif Formal Verification & Consistency Check

### Execute All ProVerif Models
Run all symbolic formal security models (covering MITM, BGP/DNS hijacking, CA migration, anti-rollback, and app-key rotation):

```bash
cd proverif
./run.sh
```

The ASPin models give the two token payloads the same fields as the paper:
$T_k=(K_{cpub},iat_k,exp_k)$ and
$T_c=(Subject,SAN,IssuerSet,iat_c,exp_c)$. Issuer identifiers are abstract atoms
in ProVerif; DER parsing and SHA-256 are tested in the implementation rather
than modeled symbolically. There is no independent token `scope`
field. The requested hostname is constrained by the signed Subject/SAN server
identity and by the verified app-signing-key/hostname cache index. The models
also derive (rather than trust) each TTL, reject `now == exp`, and keep
highest-seen-`iat` rollback state independent of the cache. The migration model
checks two-window CA overlap, cross-app/cross-host cache isolation, and emergency
replacement. The key-rotation model checks both protected old/new signatures
over one common payload, explicit transfer of protected highest-seen state, and
rejection of a still-fresh transitional-token replay after cutover. Lifecycle
verifiers read all tokens from the public attacker-controlled channel; private
channels carry only schedule signals for honest liveness traces.

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
