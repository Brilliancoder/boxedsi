#!/usr/bin/env python3
"""Freeze `boxed serve` for the desktop program: a PyInstaller folder build named the way Tauri expects a sidecar.

    python3 desktop/scripts/build-sidecar.py                     # for the architecture of this machine
    python3 desktop/scripts/build-sidecar.py --source DIR        # freeze another checkout of the repository (it needs `boxed serve`)
    python3 desktop/scripts/build-sidecar.py --target x86_64-apple-darwin    # on an Apple silicon Mac with Rosetta

Why a folder and not one file: a one-file build unpacks about 800 files on every start, 3 s per call on macOS as measured; a
folder build starts in 0.1 s. The result is put where tauri.sidecar.conf.json expects it:

    desktop/src-tauri/binaries/boxed-<target-triple>[.exe]     the program
    desktop/src-tauri/binaries/_internal/                      its libraries (a macOS app keeps them in Contents/Frameworks)

Only one architecture fits in binaries/ at a time: _internal has no triple in its name.

PyInstaller cannot cross-compile, so the build runs on the architecture it builds for: the Python that freezes is picked by uv
for the target, and an x86_64 Python runs under Rosetta on an Apple silicon Mac. The Python is the one uv manages (a standalone
build with an old macOS deployment target), never the machine's: a frozen program carries its Python's deployment target, and
the Homebrew Python of a Mac that runs the newest macOS would give a program that starts on that macOS only.

What goes in: the locked dependencies of uv.lock with their hashes plus the `formats` extra (xlsx, docx, pdf) and the `ner-ru`
extra (the Russian name model, Natasha: about 90 MB of libraries and models), PyInstaller pinned with hashes in
requirements-build.txt. Not in: `ner-en` (GLiNER and torch: about a gigabyte of libraries and another one of model, which the
program would have to download), so English names are not found by this build, and the windows of the program say so. The shell
switches the Russian model on for its sidecar through BOXED_SERVE_NER=ru; boxed.toml is not touched.
Standard library only; uv must be on the PATH. After the build the frozen program is run through sidecar_check.py.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sidecar_check  # noqa: E402

HERE = Path(__file__).resolve().parent
DESKTOP = HERE.parent
BINARIES = DESKTOP / "src-tauri" / "binaries"
WINDOWS = sys.platform == "win32"
PYTHON = "3.13"
EXTRAS = ["formats", "ner-ru"]
# The Russian name model keeps its models in the package and loads them by file name, and the libraries around it import each
# other by name: what a scan of the imports misses is collected whole.
NER_RU = ["natasha", "navec", "slovnet", "razdel", "yargy", "ipymarkup", "pymorphy2", "pymorphy2_dicts_ru", "dawg_python", "intervaltree", "sortedcontainers"]

ARCH = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}


def host_triple() -> str:
    arch = ARCH.get(platform.machine().lower())
    if arch is None:
        sys.exit(f"unsupported machine: {platform.machine()}")
    if sys.platform == "darwin":
        return f"{arch}-apple-darwin"
    if WINDOWS:
        return f"{arch}-pc-windows-msvc"
    sys.exit("only macOS and Windows programs are built")


def uv_python(triple: str) -> str:
    """The request that makes uv pick its standalone Python of the target's architecture."""
    arch, _, rest = triple.partition("-")
    system = "macos" if rest.endswith("apple-darwin") else "windows"
    return f"cpython-{PYTHON}-{system}-{arch}"


def check_buildable(target: str) -> None:
    host = host_triple()
    if target == host:
        return
    # an x86_64 program runs on an Apple silicon Mac through Rosetta, and so does the Python that freezes it
    if host == "aarch64-apple-darwin" and target == "x86_64-apple-darwin":
        if subprocess.run(["arch", "-x86_64", "/usr/bin/true"], capture_output=True).returncode != 0:
            sys.exit("x86_64 needs Rosetta: softwareupdate --install-rosetta")
        return
    sys.exit(f"cannot build {target} on {host}: PyInstaller does not cross-compile")


def run(command: list, **kwargs) -> None:
    print("+ " + " ".join(str(part) for part in command), flush=True)
    subprocess.run([str(part) for part in command], check=True, **kwargs)


def is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
    except OSError:
        return False


def macos_minimum(root: Path) -> str:
    """The highest macOS version any Mach-O file in the folder needs (LC_BUILD_VERSION minos): the oldest macOS the app runs on."""
    highest: tuple[int, ...] = (0,)
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or not is_macho(path):
            continue
        command = ""
        for line in subprocess.run(["otool", "-l", str(path)], capture_output=True, text=True).stdout.splitlines():
            words = line.split()
            if len(words) == 2 and words[0] == "cmd":
                command = words[1]
            elif len(words) == 2 and (command, words[0]) in {("LC_BUILD_VERSION", "minos"), ("LC_VERSION_MIN_MACOSX", "version")}:
                highest = max(highest, tuple(int(part) for part in words[1].split(".") if part.isdigit()))
    return ".".join(str(part) for part in highest)


def size_mb(path: Path) -> float:
    if path.is_file():
        return path.stat().st_size / 1e6
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink()) / 1e6


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--target", help="target triple; default: this machine")
    parser.add_argument("--source", type=Path, default=DESKTOP.parent, help="repository to freeze (uv.lock and src/boxed); default: this one")
    parser.add_argument("--work", type=Path, default=HERE / "work", help="scratch folder (ignored by git)")
    args = parser.parse_args()

    target = args.target or host_triple()
    check_buildable(target)
    source = args.source.resolve()
    for needed in ("uv.lock", "pyproject.toml", "src/boxed/cli.py"):
        if not (source / needed).exists():
            sys.exit(f"{source} is not a checkout of the repository: {needed} is missing")
    if shutil.which("uv") is None:
        sys.exit("uv is needed: https://docs.astral.sh/uv/")

    work = args.work.resolve() / target
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    env = {name: value for name, value in os.environ.items() if name not in {"VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME"}}
    suffix = ".exe" if WINDOWS else ""
    venv = work / "venv"
    python = venv / ("Scripts/python.exe" if WINDOWS else "bin/python")

    run(["uv", "venv", "--managed-python", "--python", uv_python(target), venv], env=env)
    requirements = work / "requirements.txt"
    extras = [part for extra in EXTRAS for part in ("--extra", extra)]
    run(["uv", "export", "--frozen", "--no-dev", "--no-emit-project", *extras, "--format", "requirements-txt", "-o", requirements], cwd=source, env=env)
    run(["uv", "pip", "install", "--python", python, "--require-hashes", "-r", requirements, "-r", HERE / "requirements-build.txt"], env=env)

    # python-docx finds its default parts as <docx>/parts/../templates/..., and the kernel cannot walk through a folder that is
    # not on disk: the modules of a frozen program live in an archive, so the real docx/parts folder is added next to the data
    docx_parts = subprocess.run(
        [str(python), "-c", "import docx, pathlib; print(pathlib.Path(docx.__file__).parent / 'parts')"], capture_output=True, text=True, check=True
    ).stdout.strip()

    dist = work / "dist"
    run(
        [
            python, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--log-level", "WARN",
            "--name", "boxed",
            "--paths", source / "src",
            # boxed.formats loads these with importlib.import_module(name), which a static scan cannot see
            "--hidden-import", "openpyxl", "--hidden-import", "docx", "--hidden-import", "pypdf",
            "--add-data", f"{docx_parts}{os.pathsep}docx/parts",
            # keyring finds its operating system backend through entry points at run time
            "--collect-submodules", "keyring.backends", "--copy-metadata", "keyring",
            *[part for package in NER_RU for part in ("--collect-all", package)],
            "--distpath", dist, "--workpath", work / "pyinstaller", "--specpath", work,
            HERE / "sidecar_entry.py",
        ],
        env=env,
    )

    frozen = dist / "boxed"
    for old in BINARIES.glob("boxed-*") if BINARIES.exists() else []:
        old.unlink()
    shutil.rmtree(BINARIES / "_internal", ignore_errors=True)
    BINARIES.mkdir(parents=True, exist_ok=True)
    program = BINARIES / f"boxed-{target}{suffix}"
    shutil.copy2(frozen / f"boxed{suffix}", program)
    shutil.copytree(frozen / "_internal", BINARIES / "_internal", symlinks=True)

    print(f"\nchecking {program.name} (no Python on its PATH, a throwaway boxed home, the file key store)")
    for line in sidecar_check.check(program):
        print("ok -", line)

    print(f"\n{program}: {size_mb(program):.1f} MB, with _internal {size_mb(BINARIES):.1f} MB in total")
    if target.endswith("apple-darwin"):
        print(f"oldest macOS it runs on: {macos_minimum(BINARIES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
