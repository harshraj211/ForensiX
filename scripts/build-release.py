"""Build an unsigned portable ForensiX bundle, SBOM, manifest, and checksums."""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from forensix_server.release import seal_portable_bundle


def main() -> int:
    arguments = _arguments()
    root = Path(__file__).resolve().parents[1]
    commit = _capture(["git", "rev-parse", "HEAD"], root)
    source_dirty = bool(_capture(["git", "status", "--porcelain"], root))
    if not arguments.allow_dirty and source_dirty:
        raise SystemExit(
            "Refusing to build a release from a dirty worktree; use --allow-dirty locally."
        )
    build_root = (root / "build" / "portable-release").resolve()
    if build_root.exists():
        _remove_build_directory(root, build_root)
    build_root.mkdir(parents=True)
    output = (arguments.output_dir or root / "release").expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    _run(_pnpm_build_command(), root)
    _run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath",
            str(build_root / "dist"),
            "--workpath",
            str(build_root / "work"),
            str(root / "packaging" / "forensix.spec"),
        ],
        root,
    )
    platform_tag = _platform_tag()
    sbom = output / f"ForensiX-{arguments.version}-{platform_tag}.cdx.json"
    _run(
        [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "environment",
            "--of",
            "JSON",
            "--output-reproducible",
            "-o",
            str(sbom),
        ],
        root,
    )
    artifact = seal_portable_bundle(
        build_root / "dist" / "ForensiX",
        output,
        version=arguments.version,
        platform_tag=platform_tag,
        source_commit=commit,
        source_dirty=source_dirty,
        sbom_path=sbom,
    )
    print(f"Portable archive: {artifact.archive_path}")
    print(f"Archive SHA-256: {artifact.archive_sha256}")
    print(f"Manifest SHA-256: {artifact.manifest_sha256}")
    print("Signature status: unsigned")
    return 0


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--allow-dirty", action="store_true")
    arguments = parser.parse_args()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?", arguments.version):
        parser.error("--version must be a semantic version")
    return arguments


def _platform_tag() -> str:
    system = {"Darwin": "macos", "Windows": "windows"}.get(platform.system(), "linux")
    machine = re.sub(r"[^a-z0-9._-]", "-", platform.machine().lower())
    return f"{system}-{machine}"


def _pnpm_build_command() -> list[str]:
    if os.name == "nt":
        command_processor = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        return [command_processor, "/d", "/s", "/c", "pnpm", "build"]
    return ["pnpm", "build"]


def _run(command: list[str], working_directory: Path) -> None:
    subprocess.run(command, cwd=working_directory, check=True)  # noqa: S603


def _capture(command: list[str], working_directory: Path) -> str:
    result = subprocess.run(  # noqa: S603
        command,
        cwd=working_directory,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _remove_build_directory(root: Path, build_root: Path) -> None:
    expected_parent = (root / "build").resolve()
    if build_root.parent != expected_parent or build_root.name != "portable-release":
        raise RuntimeError("Refusing to remove a path outside the release build directory.")
    shutil.rmtree(build_root)


if __name__ == "__main__":
    raise SystemExit(main())
