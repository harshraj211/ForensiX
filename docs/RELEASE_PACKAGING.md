# Release Packaging

ForensiX currently ships as a portable, unsigned Windows ZIP. It is designed for a controlled workstation where the analyst can verify the release before use.

## GitHub download

The tagged release workflow builds the Windows portable bundle. On tagged releases it publishes the generated files to GitHub Releases and creates the stable Windows asset:

`ForensiX-Windows-Portable.zip`

The stable download URL is:

`https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-Windows-Portable.zip`

The Windows release also includes a SHA-256 sidecar, SBOM, source manifest, and platform-specific archive. The stable ZIP is an alias of the versioned Windows archive; the internal manifest remains versioned and records the source commit.

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

GitHub Actions builds Windows, creates attestations, uploads the workflow artifacts, and publishes a GitHub Release for the tag. The release job also creates the stable Windows asset used by the README download link.

## Current release boundaries

- The Windows bundle is not code-signed, so Windows SmartScreen may warn about it.
- There is no MSI or per-user installer yet.
- Android USB drivers, ADB Platform-Tools, and scrcpy are not silently installed.
- The application remains loopback-only and must not be deployed as a public web service.
- Evidence and database data live outside the application bundle and must be backed up separately.

The next distribution milestone is a signed per-user installer that installs the application and approved tool runtimes while preserving explicit hash validation and user control over evidence storage.
