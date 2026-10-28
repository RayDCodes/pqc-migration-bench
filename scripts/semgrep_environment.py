import os
from pathlib import Path

import semgrep


def scanner_environment():
    environment = os.environ.copy()
    libraries = Path(semgrep.__file__).resolve().parent / "bin/libs"
    existing = environment.get("LD_LIBRARY_PATH")
    environment["LD_LIBRARY_PATH"] = str(libraries) + (os.pathsep + existing if existing else "")
    return environment
