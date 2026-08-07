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

The compiled and signed APKs will be saved in `results/apks/`.

---

## 4. Web Server (Nginx) Deployment

Deploy the Nginx server configurations for both the legitimate real server and the malicious rogue server.

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

Ensure an Android device or emulator is connected via ADB (`adb devices`).

### Benchmark 1: Verification Latency (`table:avgveriftime`)
Measures the client-side signature verification times of $T_k$, $T_c$, and DCP baseline pin checks on the Android device (default: 2,000 iterations):

```bash
./run-avgveriftime-benchmark.sh 2000
```
- Output summary: `results/table_avgveriftime_summary.csv`

### Benchmark 2: Real & Rogue Server Connection Latencies (`table:realavgvisittime` & `table:maliciousavgvisittime`)
Measures connection setup times against the real server and real-time rejection latencies against a malicious rogue server presenting an unauthorized certificate (default: 2,000 iterations):

```bash
./run-avgvisittime-benchmark.sh 2000
```
- Output summary: `results/table_avgvisittime_summary.csv`

---

## 6. ProVerif Formal Verification & Consistency Check

### Execute All ProVerif Models
Run all symbolic formal security models (covering MITM, BGP/DNS hijacking, CA migration, anti-rollback, and app-key rotation):

```bash
cd proverif
./run.sh
```

### Verify Consistency Across Code, Models, and LaTeX Text
Verify that the ProVerif models, output logs, Android Java code, Python scripts, and LaTeX paper tables remain 100% aligned:

```bash
python3 proverif/check_consistency.py
```
