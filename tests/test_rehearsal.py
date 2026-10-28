import csv
import hashlib
import json

import pytest

from scripts.rehearse import read_evidence, show_evidence


@pytest.fixture
def recorded_run(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    code = b"value = 1\n"
    (source / "example.py").write_bytes(code)
    directory = tmp_path / "docs/evidence"
    directory.mkdir(parents=True)
    metadata = {
        "backend": "liboqs",
        "protocol_version": 2,
        "liboqs_version": "test-fixture",
        "python_source_sha256": hashlib.sha256(b"example.py\0" + code + b"\0").hexdigest(),
        "trials_per_configuration": 1,
        "configurations": 30,
    }
    (directory / "handshake_v2.metadata.json").write_text(json.dumps(metadata))
    rows = []
    for mode in ("classical", "pqc", "hybrid", "signed"):
        mechanisms = ["n/a"] if mode == "classical" else ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
        for mechanism in mechanisms:
            for delay in (0, 20, 75):
                rows.append({
                    "mode": mode, "mechanism": mechanism, "sim_latency_ms": delay,
                    "handshake_time_ms": 1.0, "wire_bytes": 72,
                })
    write_rows(tmp_path, rows)
    return tmp_path


def write_rows(root, rows):
    path = root / "docs/evidence/handshake_v2.csv"
    with path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=[
            "mode", "mechanism", "sim_latency_ms", "handshake_time_ms", "wire_bytes",
        ])
        writer.writeheader()
        writer.writerows(rows)


def load_rows(root):
    with (root / "docs/evidence/handshake_v2.csv").open(newline="") as source:
        return list(csv.DictReader(source))


def test_complete_snapshot_is_explicitly_recorded(recorded_run, capsys):
    metadata, groups = read_evidence(recorded_run)
    assert metadata["backend"] == "liboqs"
    assert len(groups) == 30
    show_evidence(recorded_run)
    output = capsys.readouterr().out
    assert "no live benchmark was run" in output
    assert "measured_trials=30" in output


def test_changed_source_rejects_old_evidence(recorded_run):
    (recorded_run / "src/example.py").write_text("value = 2\n")
    with pytest.raises(ValueError, match="Source differs"):
        read_evidence(recorded_run)


def test_missing_configuration_is_rejected(recorded_run):
    write_rows(recorded_run, load_rows(recorded_run)[:-1])
    with pytest.raises(ValueError, match="30 full-sweep"):
        read_evidence(recorded_run)


def test_duplicate_trial_is_rejected(recorded_run):
    rows = load_rows(recorded_run)
    write_rows(recorded_run, rows + [rows[0]])
    with pytest.raises(ValueError, match="extra trials"):
        read_evidence(recorded_run)


@pytest.mark.parametrize("duration", ["nan", "inf", "-1", "0"])
def test_invalid_duration_is_rejected(recorded_run, duration):
    rows = load_rows(recorded_run)
    rows[0]["handshake_time_ms"] = duration
    write_rows(recorded_run, rows)
    with pytest.raises(ValueError, match="duration"):
        read_evidence(recorded_run)


def test_simulated_backend_is_rejected(recorded_run):
    path = recorded_run / "docs/evidence/handshake_v2.metadata.json"
    metadata = json.loads(path.read_text())
    metadata["backend"] = "simulated"
    path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="real-liboqs"):
        read_evidence(recorded_run)


def test_unknown_configuration_is_rejected(recorded_run):
    rows = load_rows(recorded_run)
    rows[0]["mechanism"] = "unrecognized"
    write_rows(recorded_run, rows)
    with pytest.raises(ValueError, match="configuration"):
        read_evidence(recorded_run)
