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

This updates:
- `ClaimSigningKey.jwt` ($T_k$)
- `ServerCertClaim.jwt` ($T_c$)
- `DCPServerCertPin.json` (DCP baseline pin)
- Synchronizes tokens to `realserver/var/www/<alg>/.well-known/`

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

The platform exposes two query APIs:

- `getCertificateClaim(hostname)` is the self-query. Android derives the
  caller's App ID from its Binder identity and resolves the caller's verified
  signing key.
- `getCertificateClaimForApp(targetAppId, hostname)` is the cross-app query.
  App A can request the claim for an installed App B and App B's server
  hostname. Android resolves App B's verified signing key and caches the
  authenticated `(App B signing key, Subject, SAN, Issuer)` binding; it never
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
export ASPIN_REPO=/mnt/code/rogue-cert
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
6. `ANDROID_HOME` points to an Android SDK containing `adb`, or the default
   `/opt/android-sdk` exists. Set `ASPIN_JAVA_HOME` if JDK 17 is installed at a
   nonstandard path.

Useful preflight commands are:

```bash
cd /mnt/code/rogue-cert
adb devices -l
adb shell service check aspin
sudo -n true
systemctl is-active nginx
```

Do not run the two benchmark scripts in parallel. Both install the same app ID
(`com.cert.aspin`), rewrite the same result files, and switch the host between
the real and rogue Nginx configurations. Each script rebuilds and signs all
four algorithm-specific APKs before collecting measurements.

### Benchmark 1: Verification Latency (`table:osveriftime`)
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

### Benchmark 2: Real & Rogue Server Connection Latencies (`table:osrealvisittime` and `table:osmaliciousvisittime`)
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

### Cross-App API Smoke Test

The following test installs App B as `com.cert.aspin`, installs a separately
signed App A as `com.cert.aspin.caller`, and has App A request
`getCertificateClaimForApp(com.cert.aspin, es256.idouzi.top)`. Because App A is deliberately signed with
a different key, successful verification demonstrates that the OS used App B's
signing key rather than the caller's key:

```bash
./run-cross-app-aspin-smoke.sh
```

- Output: `results/cross_app_target_claim.csv`

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
$T_c=(Subject,SAN,Issuer,iat_c,exp_c)$. There is no independent token `scope`
field. The requested hostname is constrained by the signed Subject/SAN server
identity and by the verified app-signing-key/hostname cache index. The models
also derive (rather than trust) each TTL, reject `now == exp`, and keep
highest-seen-`iat` rollback state independent of the cache. The migration model
checks two-window CA overlap, cross-app/cross-host cache isolation, and emergency
replacement. The key-rotation model checks the common-payload dual signature and
rejection of old-key replay after cutover.

### Verify Consistency Across Code, Models, and LaTeX Text
Verify that the ProVerif models, output logs, Android Java code, Python scripts, and LaTeX paper tables remain 100% aligned:

```bash
python3 proverif/check_consistency.py
```
