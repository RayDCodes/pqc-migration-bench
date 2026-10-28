import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import urllib.request

root = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tools", nargs="+", choices=["conftest", "trivy", "actionlint"])
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        parser.error("pinned scanner binaries target Linux x86_64")
    tools = json.loads((root / "security/toolchain.json").read_text())
    destination = root / ".tools"
    destination.mkdir(exist_ok=True)
    for name in args.tools:
        spec = tools[name]
        with urllib.request.urlopen(spec["url"], timeout=60) as response:
            archive = response.read(150 * 1024 * 1024 + 1)
        if hashlib.sha256(archive).hexdigest() != spec["sha256"]:
            raise RuntimeError(f"{name}: download checksum mismatch")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            member = bundle.getmember(name)
            if not member.isfile() or member.size > 300 * 1024 * 1024:
                raise RuntimeError(f"{name}: invalid archive entry")
            with bundle.extractfile(member) as binary:
                (destination / name).write_bytes(binary.read())
        (destination / name).chmod(0o755)
        print(f"Installed {name} {spec['version']} with verified SHA256")


if __name__ == "__main__":
    main()
