import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def read_evidence(root):
    directory = root / "docs/evidence"
    metadata = json.loads((directory / "handshake_v2.metadata.json").read_text())
    if metadata.get("backend") != "liboqs" or metadata.get("protocol_version") != 2:
        raise ValueError("Expected recorded real-liboqs protocol v2 results")
    source_files = sorted((root / "src").glob("*.py"))
    if not source_files:
        raise ValueError("Python source files are missing")
    digest = hashlib.sha256()
    for path in source_files:
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    if digest.hexdigest() != metadata.get("python_source_sha256"):
        raise ValueError("Source differs from the recorded benchmark; regenerate the evidence")
    trials = metadata.get("trials_per_configuration")
    if type(trials) is not int or trials < 1:
        raise ValueError("Recorded trial count must be a positive integer")
    groups = defaultdict(list)
    mechanisms = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
    with (directory / "handshake_v2.csv").open(newline="") as source:
        for row in csv.DictReader(source):
            mode = row["mode"]
            mechanism = row["mechanism"]
            latency = int(row["sim_latency_ms"])
            elapsed = float(row["handshake_time_ms"])
            size = int(row["wire_bytes"])
            valid_pair = (mode == "classical" and mechanism == "n/a") or (
                mode in {"pqc", "hybrid", "signed"} and mechanism in mechanisms
            )
            if not valid_pair or latency not in {0, 20, 75}:
                raise ValueError("Unexpected benchmark configuration")
            if not math.isfinite(elapsed) or elapsed <= 0 or size <= 0:
                raise ValueError("Invalid recorded duration or byte count")
            groups[mode, mechanism, latency].append((elapsed, size))
    if metadata.get("configurations") != 30 or len(groups) != 30:
        raise ValueError("Expected all 30 full-sweep configurations")
    if any(len(samples) != trials for samples in groups.values()):
        raise ValueError("Missing or extra trials in a configuration")
    return metadata, groups


def show_evidence(root):
    metadata, groups = read_evidence(root)
    total = sum(len(samples) for samples in groups.values())
    print("Recorded benchmark evidence; no live benchmark was run.", flush=True)
    print(f"liboqs={metadata['liboqs_version']} measured_trials={total} configurations={len(groups)}")
    print("Python source digest matches the recorded snapshot.")
    print("This checks file consistency, not independent proof of how the run was executed.")
    for mode in ("classical", "pqc", "hybrid", "signed"):
        mechanism = "n/a" if mode == "classical" else "ML-KEM-768"
        samples = groups[mode, mechanism, 0]
        times = sorted(elapsed for elapsed, _ in samples)
        p95 = times[math.ceil(0.95 * len(times)) - 1]
        mean_bytes = statistics.mean(size for _, size in samples)
        print(f"{mode}: mean_ms={statistics.mean(times):.4f} p95_ms={p95:.4f} bytes={mean_bytes:g}")
    print("These are client wall-clock timings. Signed mode provides different guarantees.")


def run_command(command, root):
    print("Running: " + " ".join(str(argument) for argument in command), flush=True)
    subprocess.run(command, cwd=root, check=True, timeout=120)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--part", choices=("evidence", "protocol", "policy"), default="evidence")
    args = parser.parse_args()
    if args.part == "evidence":
        show_evidence(ROOT)
    elif args.part == "protocol":
        run_command([
            sys.executable, "-m", "pytest", "tests/test_protocol.py",
            "tests/test_signed_security.py", "-v",
        ], ROOT)
        run_command([
            sys.executable, "-O", "-m", "pytest", "tests/test_handshakes.py",
            "-k", "key_mismatch", "-v",
        ], ROOT)
    else:
        conftest = ROOT / ".tools/conftest"
        if not conftest.is_file():
            raise RuntimeError("Install Conftest first: python scripts/install_tools.py conftest")
        run_command([str(conftest), "verify", "--policy", "security/policy"], ROOT)
        run_command([sys.executable, "scripts/test_policies.py"], ROOT)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Demo stopped: {error}", file=sys.stderr)
        raise SystemExit(1)
