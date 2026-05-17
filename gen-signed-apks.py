#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


VARIANTS = ("es256", "es384", "rsa3072", "rsa4096")


def run_checked(command, description, cwd=None):
    print(f"> {description}")
    result = subprocess.run(command, cwd=cwd)
    if result.returncode != 0:
        raise SystemExit(f"{description} failed with exit code {result.returncode}")


def version_key(path):
    numbers = [int(part) for part in re.findall(r"\d+", path.name)]
    return tuple(numbers)


def tool_names(name):
    if os.name == "nt":
        return (f"{name}.bat", f"{name}.exe", name)
    return (name,)


def resolve_tool(name, explicit_path=None, sdk_root=None, search_android_sdk=True):
    if explicit_path:
        path = Path(explicit_path).expanduser().resolve()
        if path.exists():
            return path
        raise SystemExit(f"{name} was not found at: {path}")

    for candidate in tool_names(name):
        found = shutil.which(candidate)
        if found:
            return Path(found)

    if not search_android_sdk:
        raise SystemExit(
            f"Cannot find '{name}' on PATH. Pass --{name} with the full path."
        )

    sdk_roots = []
    if sdk_root:
        sdk_roots.append(Path(sdk_root).expanduser())

    for env_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(env_name)
        if value:
            sdk_roots.append(Path(value).expanduser())

    local_app_data = os.environ.get("LOCALAPPDATA")
    user_profile = os.environ.get("USERPROFILE")
    program_files = os.environ.get("ProgramFiles")

    if local_app_data:
        sdk_roots.append(Path(local_app_data) / "Android" / "Sdk")
    if user_profile:
        sdk_roots.append(Path(user_profile) / "AppData" / "Local" / "Android" / "Sdk")
    if program_files:
        sdk_roots.append(Path(program_files) / "Android" / "Sdk")
    sdk_roots.append(Path("D:/software/Android/SDK"))

    seen = set()
    unique_roots = []
    for root in sdk_roots:
        resolved = root.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique_roots.append(resolved)

    for root in unique_roots:
        build_tools = root / "build-tools"
        if not build_tools.is_dir():
            continue

        versions = sorted(
            (path for path in build_tools.iterdir() if path.is_dir()),
            key=version_key,
            reverse=True,
        )
        for version_dir in versions:
            for candidate in tool_names(name):
                path = version_dir / candidate
                if path.exists():
                    return path

    searched = ", ".join(str(root) for root in unique_roots) or "(none)"
    raise SystemExit(
        f"Cannot find Android SDK build-tool '{name}'.\n"
        f"Searched PATH and SDK roots: {searched}\n"
        f"Install Android SDK Build-Tools, set ANDROID_HOME / ANDROID_SDK_ROOT, "
        f"or pass --sdk-root / --{name}."
    )


def convert_pem_to_pk8(openssl, pem_key, pk8_key):
    run_checked(
        [
            str(openssl),
            "pkcs8",
            "-topk8",
            "-inform",
            "PEM",
            "-outform",
            "DER",
            "-nocrypt",
            "-in",
            str(pem_key),
            "-out",
            str(pk8_key),
        ],
        f"PKCS#8 DER conversion for {pem_key.parent.name}",
    )


def gradle_wrapper(project_dir):
    if os.name == "nt":
        wrapper = project_dir / "gradlew.bat"
        if wrapper.exists():
            return ["cmd", "/c", str(wrapper)]

    wrapper = project_dir / "gradlew"
    if wrapper.exists():
        return ["sh", str(wrapper)]

    wrapper = project_dir / "gradlew.bat"
    if wrapper.exists():
        return ["cmd", "/c", str(wrapper)]

    raise SystemExit(f"Cannot find Gradle wrapper in {project_dir}")


def built_apk(project_dir, build_type, explicit_apk=None):
    if explicit_apk:
        path = Path(explicit_apk).expanduser().resolve()
        if path.exists():
            return path
        raise SystemExit(f"APK was not found at: {path}")

    apk_dir = project_dir / "app" / "build" / "outputs" / "apk" / build_type
    candidates = (
        apk_dir / f"app-{build_type}-unsigned.apk",
        apk_dir / f"app-{build_type}.apk",
    )

    for path in candidates:
        if path.exists():
            return path

    raise SystemExit(f"Cannot find built APK in {apk_dir}. Run without --skip-build first.")


def main():
    repo_root = Path(__file__).resolve().parent
    default_output = repo_root / "signed-apks"

    parser = argparse.ArgumentParser(
        description="Build and sign APKs with signing/es256, es384, rsa3072, and rsa4096 app keys."
    )
    parser.add_argument("--build-type", choices=("debug", "release"), default="release")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--output-dir", default=str(default_output))
    parser.add_argument("--sdk-root", help="Android SDK root containing build-tools/")
    parser.add_argument("--zipalign", help="Path to zipalign or zipalign.exe")
    parser.add_argument("--apksigner", help="Path to apksigner or apksigner.bat")
    parser.add_argument("--openssl", help="Path to openssl or openssl.exe")
    parser.add_argument("--apk", help="Use an existing APK instead of the default Gradle output path")
    args = parser.parse_args()

    project_dir = repo_root / "ASPRoC"
    if not project_dir.is_dir():
        raise SystemExit(f"Cannot find Android project directory: {project_dir}")

    if not args.skip_build:
        task = f":app:assemble{args.build_type[:1].upper()}{args.build_type[1:]}"
        run_checked(gradle_wrapper(project_dir) + [task], f"Gradle task {task}", cwd=project_dir)

    unsigned_apk = built_apk(project_dir, args.build_type, args.apk)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    zipalign = resolve_tool("zipalign", args.zipalign, args.sdk_root)
    apksigner = resolve_tool("apksigner", args.apksigner, args.sdk_root)
    openssl = None

    for variant in VARIANTS:
        signing_dir = repo_root / "signing" / variant
        key = signing_dir / "my-app-key.pk8"
        pem_key = signing_dir / "my-app-key.pem"
        cert = signing_dir / "my-app-cert.pem"

        if not key.exists() and not pem_key.exists():
            raise SystemExit(f"Missing private key: {key} or {pem_key}")
        if not cert.exists():
            raise SystemExit(f"Missing certificate: {cert}")

        aligned_apk = output_dir / f"app-{args.build_type}-{variant}-aligned.apk"
        signed_apk = output_dir / f"app-{args.build_type}-{variant}-signed.apk"
        pk8_key = output_dir / f"{variant}-my-app-key.pk8"

        try:
            if key.exists():
                pk8_key = key
            else:
                if openssl is None:
                    openssl = resolve_tool("openssl", args.openssl, search_android_sdk=False)
                convert_pem_to_pk8(openssl, pem_key, pk8_key)
            run_checked(
                [str(zipalign), "-p", "-f", "4", str(unsigned_apk), str(aligned_apk)],
                f"zipalign for {variant}",
            )
            run_checked(
                [
                    str(apksigner),
                    "sign",
                    "--key",
                    str(pk8_key),
                    "--cert",
                    str(cert),
                    "--out",
                    str(signed_apk),
                    str(aligned_apk),
                ],
                f"APK signing for {variant}",
            )
            run_checked(
                [str(apksigner), "verify", "--verbose", "--print-certs", str(signed_apk)],
                f"APK verification for {variant}",
            )
        finally:
            aligned_apk.unlink(missing_ok=True)
            if pk8_key != key:
                pk8_key.unlink(missing_ok=True)

        print(f"Wrote {signed_apk}")


if __name__ == "__main__":
    main()
