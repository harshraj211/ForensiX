# Release Packaging

ForensiX ships as portable, unsigned Windows, Linux, and macOS ZIP bundles. Each bundle is designed for a controlled workstation where the analyst can verify the release before use.

## GitHub download

The tagged release workflow builds all three desktop bundles. On tagged releases it publishes one stable download per platform:

- `ForensiX-Windows-Portable.zip`
- `ForensiX-Linux-Portable.zip`
- `ForensiX-macOS-Portable.zip`

The stable URLs are:

- `https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-Windows-Portable.zip`
- `https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-Linux-Portable.zip`
- `https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-macOS-Portable.zip`

The release includes one `SHA256SUMS.txt` file. SBOMs are generated and attested by GitHub Actions but are intentionally kept out of the primary download list. Each ZIP still contains its internal source manifest and per-file hashes.

## Local build

Build from a clean checkout with Node.js 24+, pnpm 11+, Python 3.12+, and the release dependencies installed:

```powershell
pnpm install --frozen-lockfile
.venv\Scripts\python.exe -m pip install -r requirements-release.txt
.venv\Scripts\python.exe scripts\build-release.py --version 0.1.0 --output-dir release
```

The build runs the frontend production build, creates a PyInstaller onedir bundle, copies the Alembic migrations and web assets, generates a CycloneDX SBOM, writes a per-file release manifest, creates a deterministic ZIP, and writes the archive SHA-256 sidecar.

The release script intentionally refuses a dirty Git worktree unless `--allow-dirty` is supplied. Release builds should use a clean commit or tag.

## Tagged GitHub release

Push a semantic version tag after CI passes:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions builds Windows, Linux, and macOS, creates attestations, uploads workflow artifacts, and publishes a GitHub Release for the tag. The release job normalizes the platform archives into the three stable download names used by the README links.

## Current release boundaries

- The bundles are not code-signed; Windows SmartScreen and macOS Gatekeeper may warn about them.
- There is no MSI or per-user installer yet.
- Android USB drivers, ADB Platform-Tools, and scrcpy are not silently installed.
- The application remains loopback-only and must not be deployed as a public web service.
- Evidence and database data live outside the application bundle and must be backed up separately.

The next distribution milestone is a signed per-user installer that installs the application and approved tool runtimes while preserving explicit hash validation and user control over evidence storage.
