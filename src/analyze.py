"""
Reads results/handshake_results.csv and produces:
    - results/latency_overhead.png   (compute-only handshake time, 0ms sim latency)
    - results/wire_bytes.png         (bytes on the wire per mode/mechanism)
    - results/latency_vs_network.png (handshake time across simulated RTTs)
    - results/summary.csv            (aggregated mean/stdev table)
"""
import argparse
import csv
import json
import math
import statistics as stats
from collections import defaultdict
from pathlib import Path
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT_DIR / "results"
IN_CSV = RESULTS_DIR / "handshake_results.csv"

LABELS = {
    ("classical", "n/a"): "Classical\nX25519",
    ("pqc", "ML-KEM-768"): "ML-KEM-768",
    ("hybrid", "ML-KEM-768"): "Hybrid\nX25519+768",
    ("signed", "ML-KEM-768"): "Signed\nML-KEM-768",
}

ORDER = list(LABELS.keys())
COLORS = {
    "classical": "#4C72B0",
    "pqc": "#DD8452",
    "hybrid": "#55A868",
    "signed": "#C44E52",
}

KEYS_TO_PLOT = [
    ("classical", "n/a"),
    ("pqc", "ML-KEM-768"),
    ("hybrid", "ML-KEM-768"),
    ("signed", "ML-KEM-768"),
]

def load_rows():
    rows = []
    with open(IN_CSV) as f:
        for r in csv.DictReader(f):
            r["sim_latency_ms"] = int(r["sim_latency_ms"])
            r["handshake_time_ms"] = float(r["handshake_time_ms"])
            r["wire_bytes"] = int(r["wire_bytes"])
            rows.append(r)
    return rows


def aggregate(rows):
    """key = (mode, mechanism, sim_latency_ms) -> list of samples"""
    groups = defaultdict(list)
    for r in rows:
        key = (r["mode"], r["mechanism"], r["sim_latency_ms"])
        groups[key].append(r)
    return groups


def chart_compute_only(groups):
    fig, ax = plt.subplots(figsize=(9, 5.5))
    xs, means, errs, colors = [], [], [], []
    for key in ORDER:
        mode, mech = key
        rows = groups.get((mode, mech, 0), [])
        if not rows:
            continue
        times = [r["handshake_time_ms"] for r in rows]
        xs.append(LABELS[key])
        means.append(stats.mean(times))
        errs.append(stats.stdev(times) if len(times) > 1 else 0)
        colors.append(COLORS[mode])

    bars = ax.bar(xs, means, yerr=errs, capsize=4, color=colors)
    ax.set_ylabel("Client handshake time (ms), zero injected delay")
    ax.set_title("Loopback handshake latency by mode")
    for b, m in zip(bars, means):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height(), f"{m:.3f}ms", ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "latency_overhead.png", dpi=150)
    plt.close(fig)


def chart_wire_bytes(groups):
    fig, ax = plt.subplots(figsize=(9, 5.5))
    xs, vals, colors = [], [], []
    for key in ORDER:
        mode, mech = key
        rows = groups.get((mode, mech, 0), [])
        if not rows:
            continue
        xs.append(LABELS[key])
        vals.append(rows[0]["wire_bytes"])
        colors.append(COLORS[mode])

    bars = ax.bar(xs, vals, color=colors)
    ax.set_ylabel("Total handshake bytes on the wire")
    ax.set_title("Handshake size: classical vs PQC vs hybrid vs signed")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height(), f"{v}B", ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "wire_bytes.png", dpi=150)
    plt.close(fig)


def chart_vs_network(groups):
    fig, ax = plt.subplots(figsize=(9, 5.5))
    latencies = sorted(set(k[2] for k in groups.keys()))
    for key in KEYS_TO_PLOT:
        mode, mech = key
        ys = []
        for lat in latencies:
            rows = groups.get((mode, mech, lat), [])
            ys.append(stats.mean([r["handshake_time_ms"] for r in rows]) if rows else None)
        ax.plot(latencies, ys, marker="o", label=LABELS[key].replace("\n", " "), color=COLORS[mode])

    ax.set_xlabel("Injected delay before each sendall (ms)")
    ax.set_ylabel("Total handshake time (ms)")
    ax.set_title("Client handshake latency under the per-send delay model\n(ML-KEM-768 shown for PQC, hybrid, and signed)")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "latency_vs_network.png", dpi=150)
    plt.close(fig)


def write_summary(groups):
    with (RESULTS_DIR / "summary.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["mode", "mechanism", "sim_latency_ms", "mean_ms", "stdev_ms", "mean_wire_bytes", "n", "p50_ms", "p95_ms"])
        for key in sorted(groups.keys()):
            rows = groups[key]
            times = [r["handshake_time_ms"] for r in rows]
            w.writerow(
                [
                    key[0],
                    key[1],
                    key[2],
                    round(stats.mean(times), 4),
                    round(stats.stdev(times), 4) if len(times) > 1 else 0,
                    stats.mean(r["wire_bytes"] for r in rows),
                    len(rows),
                    round(stats.median(times), 4),
                    round(sorted(times)[math.ceil(0.95 * len(times)) - 1], 4),
                ]
            )


def main():
    global IN_CSV, RESULTS_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--allow-legacy", action="store_true")
    args = parser.parse_args()
    IN_CSV = args.input
    RESULTS_DIR = args.out_dir
    metadata_path = IN_CSV.with_suffix(".metadata.json")
    if not args.allow_legacy:
        if not metadata_path.exists():
            parser.error("missing backend metadata; use --allow-legacy only for historical data")
        metadata = json.loads(metadata_path.read_text())
        if metadata.get("backend") != "liboqs" or metadata.get("protocol_version") != 2:
            parser.error("expected a real liboqs protocol v2 run")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = load_rows()
    if not rows:
        parser.error("input CSV contains no samples")
    groups = aggregate(rows)
    chart_compute_only(groups)
    chart_wire_bytes(groups)
    chart_vs_network(groups)
    write_summary(groups)
    print("Wrote latency_overhead.png, wire_bytes.png, latency_vs_network.png, summary.csv")


if __name__ == "__main__":
    main()
