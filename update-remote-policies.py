#!/usr/bin/env python3
"""Update ONLY public policies and the isolated origin scripts in an existing deployment."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("deploy_remote", ROOT / "deploy-remote-experiment.py")
DEPLOY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DEPLOY)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    args = parser.parse_args()
    record = json.loads(args.deployment.read_text())
    alias, remote = record["ssh_alias"], Path(record["remote_dir"])
    if remote.parent != Path("/opt/aspin-experiment") or record.get("prepared_only"):
        raise ValueError("Expected an existing dedicated experiment deployment")
    with tempfile.TemporaryDirectory(prefix="aspin-public-policies-") as temporary:
        directory = Path(temporary)
        for variant in DEPLOY.ALGORITHMS:
            source = ROOT / "signing" / variant
            target = directory / variant
            target.mkdir()
            for filename in ("ClaimSigningKey.primary.jws", "ClaimSigningKey.compat.jws",
                             "ServerCertClaim.jws", "DCPServerCertPin.jws"):
                shutil.copyfile(source / filename, target / filename)
            for mode, stem in (("primary", "my-app"), ("compat", "my-dcp")):
                token = (source / f"ClaimSigningKey.{mode}.jws").read_text()
                extra = [(algorithm, ROOT / "signing" / other / f"{stem}-key.pem",
                          ROOT / "signing" / other / f"{stem}-pubkey.pem")
                         for other, algorithm in DEPLOY.ALGORITHMS.items() if other != variant]
                value = json.loads(DEPLOY.cosign(token, extra))
                value["signatures"] = value["signatures"][1:] + value["signatures"][:1]
                (target / f"ClaimSigningKey.shared.{mode}.jws").write_text(json.dumps(value))
            files = [str(item) for item in target.iterdir()]
            subprocess.run(["scp", "-q", *files, f"{alias}:{remote}/tokens/{variant}/"], check=True)
        subprocess.run(["scp", "-q", str(ROOT / "remote-experiment/server.py"),
                        str(ROOT / "remote-experiment/control.py"), f"{alias}:{remote}/"], check=True)
    DEPLOY.ssh(alias, ["systemctl", "restart", record["origin_unit"]])
    print("Updated public ASPin/DCP policies; authority private keys stayed local.")


if __name__ == "__main__":
    main()
