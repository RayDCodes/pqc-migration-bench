from semgrep_environment import scanner_environment
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent
output = root / "artifacts/semgrep.json"
output.parent.mkdir(exist_ok=True)
result = subprocess.run([
    "pysemgrep", "scan", "--config", "security/semgrep/rules.yml", "--metrics=off",
    "--disable-version-check", "--strict", "--error", "--json", "--output", str(output),
    "src", "scripts",
], cwd=root, env=scanner_environment())
if not output.exists() or not output.read_text().strip():
    raise RuntimeError("Semgrep did not produce a report")
report = json.loads(output.read_text())
scanned = report.get("paths", {}).get("scanned", [])
if not scanned or report.get("errors"):
    raise RuntimeError("Semgrep must scan source files successfully; an empty scan cannot pass")


def escape(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(",", "%2C").replace(":", "%3A")


for finding in report.get("results", []):
    filename = escape(finding["path"])
    line = int(finding["start"]["line"])
    message = escape(finding["extra"]["message"])
    print(f"::error file={filename},line={line}::{message}")
if result.returncode or report.get("results"):
    raise SystemExit(result.returncode or 1)
print(f"Semgrep scanned {len(scanned)} files; no findings")
