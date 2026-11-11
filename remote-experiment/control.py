#!/usr/bin/env python3
"""Atomically change a root-controlled experiment profile through SSH only."""

import argparse
import json
import os
from pathlib import Path
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--host", default="all")
    parser.add_argument("--phase", choices=("real", "rogue", "renewal", "rekey"))
    parser.add_argument("--mode", choices=("primary", "compat"))
    parser.add_argument("--fault", choices=("none", "503", "timeout"))
    parser.add_argument("--key-file")
    parser.add_argument("--claim-file")
    parser.add_argument("--dcp-file")
    parser.add_argument("--generation", required=True)
    args = parser.parse_args()
    state = json.loads(args.state.read_text())
    profile = state.setdefault("default", {}) if args.host == "all" else state.setdefault("hosts", {}).setdefault(args.host, {})
    values = {"phase": args.phase, "mode": args.mode, "metadata_fault": args.fault,
              "key_file": args.key_file, "claim_file": args.claim_file, "dcp_file": args.dcp_file,
              "generation": args.generation}
    profile.update({key: value for key, value in values.items() if value is not None})
    if args.mode and args.key_file is None:
        profile["key_file"] = "ClaimSigningKey." + args.mode + ".jws"
    if args.host == "all":
        state["hosts"] = {}
    descriptor, pending = tempfile.mkstemp(prefix="state-pending-", dir=args.state.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(state, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, args.state)
    finally:
        Path(pending).unlink(missing_ok=True)
    print(json.dumps({"generation": args.generation, "host": args.host}))


if __name__ == "__main__":
    main()
