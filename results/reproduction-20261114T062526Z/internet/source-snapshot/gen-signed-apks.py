#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


VARIANTS = ("es256", "es384", "rsa3072", "rsa4096")
MODES = {
    "primary": ("debug", ""),
    "scp": ("scpBenchmark", "-scp"),
    "dcp": ("dcpBenchmark", "-dcp"),
    "compatible": ("compatibilityBenchmark", "-compatible"),
    "public-primary": ("publicCrossPrimary", "-public-primary"),
    "public-compatible": ("publicCrossCompatible", "-public-compatible"),
}


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
    sdk_roots.append(Path("/opt/android-sdk"))
    sdk_roots.append(Path("D:/software/Android/SDK"))

    seen = set()
    unique_roots = []
    for root in sdk_roots:
        resolved = root.resolve()
        if resolved not in seen and resolved.exists():
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


def build_api_callers(repo_root, output_dir, workers, zipalign, apksigner):
    """Sign the same caller code with either test identity, never archive keys."""
    project = repo_root / "ASPin" / "es256"
    run_checked(gradle_wrapper(project) + ["--no-daemon", f"--max-workers={workers}",
                ":app:assembleCrossAppCaller"], "Build cached-API caller", cwd=project)
    with tempfile.TemporaryDirectory(prefix="aspin-api-callers-") as temporary:
        aligned = Path(temporary) / "caller-aligned.apk"
        run_checked([str(zipalign), "-p", "-f", "4",
                     str(built_apk(project, "crossAppCaller")), str(aligned)],
                    "Align cached-API caller")
        for variant in ("es256", "es384"):
            signing = repo_root / "signing" / variant
            key = signing / "my-app-key.pk8"
            if not key.exists():
                key = Path(temporary) / (variant + ".pk8")
                convert_pem_to_pk8(resolve_tool("openssl", search_android_sdk=False),
                                   signing / "my-app-key.pem", key)
            target = output_dir / ("ASPin-caller-" + variant + ".apk")
            run_checked([str(apksigner), "sign", "--key", str(key), "--cert",
                         str(signing / "my-app-cert.pem"), "--out", str(target), str(aligned)],
                        "Sign cached-API caller with " + variant)
            run_checked([str(apksigner), "verify", "--verbose", str(target)],
                        "Verify cached-API caller " + variant)


def main():
    repo_root = Path(__file__).resolve().parent
    default_output = repo_root / "results" / "apks"

    parser = argparse.ArgumentParser(
        description="Build and sign APKs for es256, es384, rsa3072, and rsa4096 using signing/<variant>/my-app-key."
    )
    parser.add_argument(
        "--mode",
        action="append",
        choices=tuple(MODES),
        help="APK experiment mode. Repeat for multiple modes; defaults to primary.",
    )
    parser.add_argument(
        "--variant",
        action="append",
        choices=VARIANTS,
        help="Algorithm variant to build. Repeat for multiple variants; defaults to all.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=24,
        help="Maximum Gradle worker count (default: 24)",
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--build-callers", action="store_true",
                        help="Also build ES256/ES384-signed callers for the full cached API matrix")
    parser.add_argument("--output-dir", default=str(default_output))
    parser.add_argument("--scp-resource-dir", type=Path,
                        help="Explicit SCP experiment resource overlay; other modes are unchanged")
    parser.add_argument("--sdk-root", help="Android SDK root containing build-tools/")
    parser.add_argument("--zipalign", help="Path to zipalign or zipalign.exe")
    parser.add_argument("--apksigner", help="Path to apksigner or apksigner.bat")
    parser.add_argument("--openssl", help="Path to openssl or openssl.exe")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    zipalign = resolve_tool("zipalign", args.zipalign, args.sdk_root)
    apksigner = resolve_tool("apksigner", args.apksigner, args.sdk_root)
    openssl = None

    modes = args.mode or ["primary"]
    variants = args.variant or VARIANTS
    if args.scp_resource_dir and tuple(variants) != ("es256",):
        parser.error("The certificate-change SCP resource overlay requires --variant es256")
    if any(mode.startswith("public-") for mode in modes) and tuple(variants) != ("es256",):
        parser.error("The public cross-CA test APKs require --variant es256")
    for variant in variants:
        variant_project_dir = repo_root / "ASPin" / variant
        if not variant_project_dir.is_dir():
            print(f"Skipping missing variant project directory: {variant_project_dir}")
            continue

        signing_dir = repo_root / "signing" / variant
        key = signing_dir / "my-app-key.pk8"
        pem_key = signing_dir / "my-app-key.pem"
        cert = signing_dir / "my-app-cert.pem"

        if not key.exists() and not pem_key.exists():
            raise SystemExit(f"Missing private key for {variant}: {key} or {pem_key}")
        if not cert.exists():
            raise SystemExit(f"Missing certificate for {variant}: {cert}")

        pk8_key = output_dir / f"{variant}-my-app-key.pk8"
        if key.exists():
            pk8_key = key
        else:
            if openssl is None:
                openssl = resolve_tool("openssl", args.openssl, search_android_sdk=False)
            convert_pem_to_pk8(openssl, pem_key, pk8_key)

        try:
            for mode in modes:
                build_type, suffix = MODES[mode]
                if not args.skip_build:
                    task = f":app:assemble{build_type[:1].upper()}{build_type[1:]}"
                    properties = []
                    if mode == "scp" and args.scp_resource_dir:
                        resource = args.scp_resource_dir.expanduser().resolve()
                        if not (resource / "xml/network_security_config.xml").is_file():
                            raise SystemExit("SCP overlay must contain xml/network_security_config.xml")
                        properties.append("-PaspinScpResourceDir=" + str(resource))
                    run_checked(
                        gradle_wrapper(variant_project_dir)
                        + [f"--max-workers={args.workers}", *properties, task],
                        f"Gradle task {task} for {variant} ({mode})",
                        cwd=variant_project_dir,
                    )

                unsigned_apk = built_apk(variant_project_dir, build_type)
                aligned_apk = output_dir / f"ASPin-{variant}{suffix}-aligned.apk"
                signed_apk = output_dir / f"ASPin-{variant}{suffix}.apk"
                try:
                    run_checked(
                        [str(zipalign), "-p", "-f", "4", str(unsigned_apk), str(aligned_apk)],
                        f"zipalign for {variant} ({mode})",
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
                        f"APK signing for {variant} ({mode})",
                    )
                    run_checked(
                        [str(apksigner), "verify", "--verbose", "--print-certs", str(signed_apk)],
                        f"APK verification for {variant} ({mode})",
                    )
                finally:
                    aligned_apk.unlink(missing_ok=True)
                print(f"--> Built and signed {variant} {mode} APK: {signed_apk}")
        finally:
            if pk8_key != key:
                pk8_key.unlink(missing_ok=True)

    if args.build_callers:
        build_api_callers(repo_root, output_dir, args.workers, zipalign, apksigner)


if __name__ == "__main__":
    main()
