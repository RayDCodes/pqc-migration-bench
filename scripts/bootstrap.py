import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parent.parent


def run(*args):
    subprocess.run(args, cwd=root, check=True)


def checkout(name, commit):
    destination = root / name
    if not destination.exists():
        run("git", "init", str(destination))
        run("git", "-C", str(destination), "remote", "add", "origin", f"https://github.com/open-quantum-safe/{name}.git")
    if subprocess.run(
        ["git", "-C", str(destination), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout:
        raise RuntimeError(f"Refusing to build a modified {name} checkout")
    run("git", "-C", str(destination), "fetch", "--depth", "1", "origin", commit)
    run("git", "-C", str(destination), "checkout", "--detach", commit)
    actual = subprocess.run(
        ["git", "-C", str(destination), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if actual != commit:
        raise RuntimeError(f"{name} revision mismatch")


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError("Activate a virtual environment first; system Python is not modified")
    for tool in ("git", "cmake", "ninja"):
        if not shutil.which(tool):
            raise RuntimeError(f"Missing build tool: {tool}")
    pins = json.loads((root / "security/toolchain.json").read_text())
    for name in ("liboqs", "liboqs-python"):
        checkout(name, pins[name]["commit"])
    run(
        "cmake", "-S", str(root / "liboqs"), "-B", str(root / "liboqs/build"), "-G", "Ninja",
        f"-DCMAKE_INSTALL_PREFIX={root / 'liboqs-install'}", "-DOQS_BUILD_ONLY_LIB=ON",
        "-DBUILD_SHARED_LIBS=ON", "-DOQS_DIST_BUILD=ON",
        "-DOQS_MINIMAL_BUILD=KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_65",
    )
    run("cmake", "--build", str(root / "liboqs/build"), "--parallel", "2")
    run("cmake", "--install", str(root / "liboqs/build"))
    run(sys.executable, "-m", "pip", "install", "--no-deps", str(root / "liboqs-python"))
    os.environ["OQS_INSTALL_PATH"] = str(root / "liboqs-install")
    run(sys.executable, "-c", "import oqs; print('Real liboqs:', oqs.oqs_version()); assert 'ML-DSA-65' in oqs.get_enabled_sig_mechanisms()")


if __name__ == "__main__":
    main()
