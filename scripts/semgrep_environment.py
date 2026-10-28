import os
from pathlib import Path

import semgrep


def scanner_environment():
    environment = os.environ.copy()
    libraries = Path(semgrep.__file__).resolve().parent / "bin/libs"
    destination = Path(__file__).resolve().parent.parent / ".tools/semgrep-libs"
    destination.mkdir(parents=True, exist_ok=True)
    for link in destination.iterdir():
        if not link.is_symlink():
            raise RuntimeError("Unexpected file in the managed scanner library directory")
        link.unlink()
    system_libraries = (
        "libm.", "libc.", "libpthread.", "librt.", "libdl.",
        "libresolv.", "libnss_", "libutil.", "ld-linux",
    )
    for library in libraries.iterdir():
        if library.name.startswith(system_libraries):
            continue
        if library.is_file():
            (destination / library.name).symlink_to(library)
    existing = environment.get("LD_LIBRARY_PATH")
    environment["LD_LIBRARY_PATH"] = str(destination) + (os.pathsep + existing if existing else "")
    return environment
