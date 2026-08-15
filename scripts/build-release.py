"""Build a portable ForensiX bundle, SBOM, manifest, and checksums."""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import uuid
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
    _materialize_regular_symlinks(build_root / "dist" / "ForensiX")
    signature_status = _sign_windows_bundle(build_root / "dist" / "ForensiX")
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
    _add_reproducible_sbom_serial(sbom, commit, arguments.version, platform_tag)
    artifact = seal_portable_bundle(
        build_root / "dist" / "ForensiX",
        output,
        version=arguments.version,
        platform_tag=platform_tag,
        source_commit=commit,
        source_dirty=source_dirty,
        sbom_path=sbom,
        signature_status=signature_status,
    )
    print(f"Portable archive: {artifact.archive_path}")
    print(f"Archive SHA-256: {artifact.archive_sha256}")
    print(f"Manifest SHA-256: {artifact.manifest_sha256}")
    print(f"Signature status: {signature_status}")
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


def _materialize_regular_symlinks(bundle: Path) -> None:
    """Copy PyInstaller's external file links into the portable bundle."""
    for path in sorted(bundle.rglob("*")):
        if not path.is_symlink():
            continue
        target = path.resolve()
        temporary = path.with_name(f".{path.name}.materializing")
        if target.is_file():
            shutil.copyfile(target, temporary)
        elif target.is_dir():
            shutil.copytree(target, temporary, symlinks=False)
        else:
            raise RuntimeError(f"Release bundle contains an invalid symbolic link: {path}")
        path.unlink()
        temporary.replace(path)


def _sign_windows_bundle(bundle: Path) -> str:
    """Sign Windows PE files when a release certificate is explicitly configured."""
    if platform.system() != "Windows":
        return "unsigned"
    certificate_b64 = os.environ.get("FORENSIX_WINDOWS_SIGN_CERT_B64", "").strip()
    password = os.environ.get("FORENSIX_WINDOWS_SIGN_CERT_PASSWORD")
    if not certificate_b64 and not password:
        return "unsigned"
    if not certificate_b64 or password is None:
        raise RuntimeError(
            "Windows signing requires both FORENSIX_WINDOWS_SIGN_CERT_B64 and "
            "FORENSIX_WINDOWS_SIGN_CERT_PASSWORD."
        )
    signtool = _find_signtool()
    if signtool is None:
        raise RuntimeError("signtool.exe was not found on the Windows runner.")
    timestamp_url = os.environ.get(
        "FORENSIX_WINDOWS_SIGN_TIMESTAMP_URL", "http://timestamp.digicert.com"
    )
    certificate = bundle.parent / "forensix-signing.pfx"
    try:
        import base64

        certificate.write_bytes(base64.b64decode(certificate_b64, validate=True))
        pe_files = sorted(
            path
            for path in bundle.rglob("*")
            if path.is_file() and path.suffix.lower() in {".dll", ".exe", ".pyd"}
        )
        if not pe_files:
            raise RuntimeError("No Windows PE files were found to sign.")
        for path in pe_files:
            _run(
                [
                    signtool,
                    "sign",
                    "/quiet",
                    "/fd",
                    "SHA256",
                    "/f",
                    str(certificate),
                    "/p",
                    password,
                    "/tr",
                    timestamp_url,
                    "/td",
                    "SHA256",
                    "/d",
                    "ForensiX",
                    str(path),
                ],
                bundle,
            )
    finally:
        certificate.unlink(missing_ok=True)
    return "authenticode"


def _find_signtool() -> str | None:
    """Find the Windows SDK signing tool on local and GitHub-hosted runners."""
    discovered = shutil.which("signtool.exe")
    if discovered:
        return discovered
    candidates = []
    for root_name in ("ProgramFiles(x86)", "ProgramFiles"):
        root = os.environ.get(root_name)
        if root:
            candidates.extend(Path(root).glob("Windows Kits/10/bin/*/x64/signtool.exe"))
    return str(sorted(candidates)[-1]) if candidates else None


def _add_reproducible_sbom_serial(
    sbom_path: Path, source_commit: str, version: str, platform_tag: str
) -> None:
    """Add the required CycloneDX serial without making release metadata random."""
    document = json.loads(sbom_path.read_text(encoding="utf-8"))
    serial_input = f"forensix:{source_commit}:{version}:{platform_tag}"
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_input)}"
    sbom_path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")


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
