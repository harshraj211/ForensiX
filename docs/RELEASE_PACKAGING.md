# Portable release packaging

ForensiX has a cross-platform **unsigned portable engineering build**. It is not yet a signed
Windows installer, notarized macOS application, or distro-native Linux package. That distinction is
intentional: signing identities, agency deployment policy, and the physical-device validation
matrix are production release gates.

## Build locally

Install the pinned release-only tools and build from a clean worktree:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-release.txt
.\.venv\Scripts\python.exe .\scripts\build-release.py --version 0.1.0
```

The build compiles the React frontend, creates a PyInstaller one-directory workstation, generates a
CycloneDX JSON SBOM, writes an internal canonical manifest with SHA-256 for every file, creates a
portable ZIP, and writes an outer SHA-256 sidecar. The executable always binds to `127.0.0.1`; there
is no command-line option that exposes it to the network.

Run `ForensiX.exe --adb-path C:\path\to\adb.exe` on Windows, or the corresponding `ForensiX`
executable on Linux/macOS. Runtime data is stored in the platform user-data directory and is not
placed inside the application bundle.

## CI provenance

The `Portable release` GitHub Actions workflow builds separately on Windows, Linux, and macOS. It
uploads the ZIP, checksum, and SBOM and requests a GitHub artifact/SBOM attestation. The portable
archives remain explicitly marked `unsigned` inside their manifests.

Before distributing a production build, run the physical-device validation matrix, sign Windows
binaries/installers, sign and notarize the macOS application, sign Linux repository metadata, scan
the SBOM, verify a clean-room installation, and document update/rollback procedures.
