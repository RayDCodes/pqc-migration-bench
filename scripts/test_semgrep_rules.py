from semgrep_environment import scanner_environment
import json
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
fixtures = {
    "no-shell-execution": "import subprocess\nsubprocess.run('echo test', shell=True)\n",
    "no-dynamic-evaluation": "value = eval(user_input)\n",
    "no-runtime-security-assert": "assert key == peer_key, 'mismatch'\nassert key == peer_key\n",
    "no-insecure-random-for-keys": "import random\nnonce = random.getrandbits(256)\n",
    "no-crypto-fallback": "class FallbackKEM:\n    pass\n",
}
with tempfile.TemporaryDirectory(dir=root) as directory:
    source = Path(directory) / "src"
    source.mkdir()
    for rule, code in fixtures.items():
        (source / f"{rule}.py").write_text(code)
    (source / "safe.py").write_text("import secrets\nnonce = secrets.token_bytes(32)\n")
    result = subprocess.run(
        ["pysemgrep", "scan", "--config", str(root / "security/semgrep/rules.yml"),
         "--metrics=off", "--disable-version-check", "--json", "--no-git-ignore", str(source)],
        check=True, capture_output=True, text=True, cwd=directory, env=scanner_environment(),
    )
    report = json.loads(result.stdout)
    if report.get("errors"):
        raise RuntimeError(report["errors"])
    found = {finding["check_id"].split(".")[-1] for finding in report["results"]}
    if found != set(fixtures):
        raise RuntimeError(f"Expected {set(fixtures)}, got {found}")
    if any(finding["path"].endswith("safe.py") for finding in report["results"]):
        raise RuntimeError("safe fixture was incorrectly rejected")
print("All five unsafe patterns rejected; safe fixture accepted")
