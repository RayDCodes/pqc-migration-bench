import argparse
from contextlib import ExitStack
import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import socket
import subprocess
import threading
import time
from pathlib import Path

from netsim import DelayedSocket
from common import ByteCounter
from oqs_compat import KEM_MECHANISMS, SIG_MECHANISM, Signature, require_backend
import handshake_classical
import handshake_pqc
import handshake_hybrid
import handshake_signed

ROOT_DIR = Path(__file__).resolve().parent.parent
MECHANISMS = list(KEM_MECHANISMS)
LATENCIES_MS = [0, 20, 75]
TRIALS_DEFAULT = 60
SOCKET_TIMEOUT = 5.0
HANDSHAKES = {
    "classical": handshake_classical,
    "pqc": handshake_pqc,
    "hybrid": handshake_hybrid,
    "signed": handshake_signed,
}


def run_server(mode, mechanism, delay_s, ready_event, result_holder, port_holder, signer):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.settimeout(SOCKET_TIMEOUT)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port_holder.append(server.getsockname()[1])
            ready_event.set()
            conn, _ = server.accept()
            with conn:
                conn.settimeout(SOCKET_TIMEOUT)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                wrapped = DelayedSocket(conn, delay_s)
                counter = ByteCounter()
                args = () if mode == "classical" else (mechanism,)
                if mode == "signed":
                    args += (SIG_MECHANISM, signer)
                key = HANDSHAKES[mode].server_handshake(wrapped, counter, *args)
                result_holder.update(server_key=key, counter=counter)
    except Exception as error:
        result_holder["error"] = error
    finally:
        ready_event.set()


def run_one_handshake(mode: str, mechanism: str, delay_ms: int):
    if mode not in HANDSHAKES:
        raise ValueError(f"Unsupported mode: {mode}")
    if not 0 <= delay_ms <= 1000:
        raise ValueError("delay_ms must be between 0 and 1000")
    if mode != "classical":
        if mechanism not in KEM_MECHANISMS:
            raise ValueError(f"Unsupported KEM mechanism: {mechanism}")
        require_backend()

    with ExitStack() as context:
        signer = None
        trusted_key = None
        if mode == "signed":
            signer = context.enter_context(Signature(SIG_MECHANISM))
            trusted_key = signer.generate_keypair()

        ready = threading.Event()
        holder = {}
        ports = []
        thread = threading.Thread(
            target=run_server,
            args=(mode, mechanism, delay_ms / 1000, ready, holder, ports, signer),
            daemon=True,
        )
        thread.start()
        if not ready.wait(SOCKET_TIMEOUT):
            raise TimeoutError("server startup timed out")
        if "error" in holder:
            raise RuntimeError("server startup failed") from holder["error"]

        try:
            with socket.create_connection(("127.0.0.1", ports[0]), SOCKET_TIMEOUT) as conn:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                wrapped = DelayedSocket(conn, delay_ms / 1000)
                counter = ByteCounter()
                args = () if mode == "classical" else (mechanism,)
                if mode == "signed":
                    args += (SIG_MECHANISM, trusted_key)
                start = time.perf_counter()
                client_key = HANDSHAKES[mode].client_handshake(wrapped, counter, *args)
                elapsed_ms = (time.perf_counter() - start) * 1000
        finally:
            thread.join(SOCKET_TIMEOUT + 1)
        if thread.is_alive():
            raise TimeoutError("server handshake did not finish")
        if "error" in holder:
            raise RuntimeError("server handshake failed") from holder["error"]
        if client_key != holder["server_key"]:
            raise RuntimeError("handshake key mismatch")
        server_counter = holder["counter"]
        if counter.sent != server_counter.received or counter.received != server_counter.sent:
            raise RuntimeError("inconsistent handshake byte counts")
        return elapsed_ms, counter.sent + counter.received


def write_metadata(out_path, trials, jobs):
    backend = require_backend()
    source_hash = hashlib.sha256()
    for path in sorted((ROOT_DIR / "src").glob("*.py")):
        source_hash.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    revision = os.environ.get("PQC_BENCH_REVISION", "unknown")
    dirty = None
    if (ROOT_DIR / ".git").exists():
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT_DIR, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT_DIR, check=True,
            capture_output=True, text=True,
        ).stdout)
    metadata = {
        "protocol_version": 2,
        "backend": "liboqs",
        "liboqs_version": backend.oqs_version(),
        "liboqs_python_version": backend.oqs_python_version(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cryptography": importlib.metadata.version("cryptography"),
        "git_commit": revision,
        "working_tree_dirty": dirty,
        "python_source_sha256": source_hash.hexdigest(),
        "trials_per_configuration": trials,
        "configurations": len(jobs),
        "latency_model": "sleep before each sendall, not packet-level RTT",
        "timing": "client handshake only; signing identity provisioned before timer",
        "authentication": "signed v2 pins an out-of-band public key; no PKI or client identity",
    }
    out_path.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=TRIALS_DEFAULT)
    parser.add_argument("--out", default="results/handshake_results.csv")
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("--trials must be positive")
    require_backend()
    trials = 10 if args.quick else args.trials
    latencies = [0, 20] if args.quick else LATENCIES_MS
    mechanisms = ["ML-KEM-768"] if args.quick else MECHANISMS
    jobs = [("classical", "n/a", latency) for latency in latencies]
    jobs += [
        (mode, mechanism, latency)
        for mode in ("pqc", "hybrid", "signed")
        for mechanism in mechanisms for latency in latencies
    ]
    rows = []
    for mode, mechanism, latency in jobs:
        run_one_handshake(mode, mechanism, latency)
        for _ in range(trials):
            elapsed, wire_bytes = run_one_handshake(mode, mechanism, latency)
            rows.append({
                "mode": mode, "mechanism": mechanism, "sim_latency_ms": latency,
                "handshake_time_ms": round(elapsed, 4), "wire_bytes": wire_bytes,
            })
        print(f"[bench] {mode} {mechanism} delay={latency}ms trials={trials}", flush=True)

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = ROOT_DIR / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_metadata(out_path, trials, jobs)
    with out_path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"[bench] wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
