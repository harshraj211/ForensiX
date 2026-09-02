<div align="center">

# 🔎 ForensiX
### Cross-Platform Android Rapid Evidence Triage & Forensic Preview Platform

[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Python-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![ADB](https://img.shields.io/badge/Transport-ADB-3DDC84?style=for-the-badge&logo=android&logoColor=white)](#local-setup)
[![Platform](https://img.shields.io/badge/Platform-Windows_|_Linux_|_macOS-555?style=for-the-badge)](#downloads)

**A local investigator workstation for capability-gated, forensically-sound Android evidence triage.**

</div>

---

## 🧭 About

ForensiX is a cross-platform Android rapid evidence triage and forensic preview workstation. It runs locally on an investigator workstation and uses Android Debug Bridge (ADB) to perform capability-gated logical collection from connected Android devices.

> 🧾 ForensiX is a controlled logical triage workstation. The UI and reports identify what was supported, blocked, or unavailable for the connected device instead of presenting unsupported extraction as completed evidence.

The current release combines local authentication, case management, device readiness, rooted/non-rooted capability assessment, supported logical previews, selected evidence acquisition, scrcpy-based documentation, reports, downloads, and case-specific audit and custody records.

📘 See the [technical repository document](TECHNICAL_REPOSITORY.md) for the complete source map, architecture, API route families, database schema, dependencies, deployment instructions, and validation process.

---

## 📥 Downloads

<div align="center">

[![Windows](https://img.shields.io/badge/⬇_Windows-Portable_ZIP-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-Windows-Portable.zip)
[![Linux](https://img.shields.io/badge/⬇_Linux-Portable_ZIP-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-Linux-Portable.zip)
[![macOS](https://img.shields.io/badge/⬇_macOS-Portable_ZIP-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-macOS-Portable.zip)

</div>

Extract the ZIP to a trusted local folder and run the `ForensiX` executable (`ForensiX.exe` on Windows). The application starts its loopback backend and bundled web interface automatically and opens the workstation in its own desktop window. **No public hosting or internet connection is required after download.**

> The distributions are **portable, not installers**. They do not silently install Android USB drivers or ADB. The Windows bundle includes the official scrcpy runtime; scrcpy is started only when an analyst requests live mirror, interactive control, or documented screen recording. PhotoRec remains optional and external. See the [technical repository](TECHNICAL_REPOSITORY.md) for workstation setup and `SHA256SUMS.txt` in the release for checksums.

---

## ✅ Implemented Now

<details open>
<summary><strong>⚡ Hardware-Level Physical Acquisition (BootROM / EDL / Download Mode)</strong></summary>

- **Qualcomm EDL (Sahara / Firehose)**: Full protocol handler (`qualcomm_edl.py`) supporting image download and raw sector reading via programmer MBNs.
- **MediaTek (MTK) BROM Bypass**: SP Flash Tool protocol suite (`mtk_brom.py`) streaming raw eMMC/UFS partition blocks.
- **Unisoc / Spreadtrum BootROM**: 2-stage bootloader protocol (`unisoc_fdl.py`) supporting HDLC-framed FDL1/FDL2 physical extraction.
- **Samsung Download Mode (Odin/LOKE)**: Native LOKE/Odin protocol parser (`samsung_download.py`) with automatic binary PIT table decoding.
- **Huawei Kirin / HiSilicon**: HiSilicon eRecovery download protocol handler (`kirin_hisi.py`) supporting Kirin 659, 710, 810, 980, 990, 9000.
- **Rockchip DFU**: USB DFU / MaskROM protocol handler (`rockchip_rkdfu.py`) supporting RK3399, RK3568, RK3588, RK3326.
- **Auto-Routing Physical Pipeline**: `physical_acquisition.py` auto-detects USB VID/PID (`chipset_detector.py`) and routes connected devices to the matching hardware module.

</details>

<details open>
<summary><strong>☁️ Cloud Backup Downloaders & Token Recovery</strong></summary>

- **Google Takeout GMS Backup**: `google_takeout.py` downloads Android device backup archives using extracted OAuth and GSF tokens.
- **WhatsApp Cloud Backup**: `whatsapp_cloud.py` queries Google Drive AppData space and downloads `msgstore.db.crypt15` archives and metadata.
- **Cloud Backup Router**: `cloud_router.py` orchestrates parallel cloud backup downloads across extracted device token bundles.

</details>

<details open>
<summary><strong>📱 Non-Rooted Agent & APK Downgrade Extraction</strong></summary>

- **Android Agent Application**: Built-in Android app (`agent_apk/forensix_agent`) executing foreground data collection for Contacts, SMS, Call Logs, and Installed Packages via standard Android `ContentResolver` APIs.
- **Agent Orchestrator**: `agent_installer.py` handles ADB installation, permission grants (`READ_CONTACTS`, `READ_SMS`, `READ_CALL_LOG`), intent triggers, and post-collection uninstalls; `agent_collector.py` polls staging areas (`/sdcard/forensix_out/`) and deserializes JSON artifacts.
- **App Downgrade Catalog**: `apk_downgrade.py` supports automated rollback attacks for 29+ target app profiles, preserving app sandbox data while extracting backups via ADB.

</details>

<details open>
<summary><strong>🔐 Passcode Assessment, Lock Bypass & Offline Hashcat Integration</strong></summary>

- **Screen Lock Bypass Engine**: `screen_lock_bypass.py` implements forensic lock bypass via `/data/system/locksettings.db` key clearing (`lockscreen.disabled=1`), Gatekeeper key removal, RAM disk boot overlay patching (`ro.secure=0`, `ro.debuggable=1`), and automated restoration.
- **Offline Hash Extractor**: `offline_hash_extractor.py` extracts Gatekeeper enrolled hashes, synthetic password blobs (`spblob`), and legacy salt keys from rooted devices.
- **Hashcat Subprocess Launcher**: `hashcat_launcher.py` manages Hashcat execution for Android modes 10 (MD5 pattern), 13800 (FBE/Gatekeeper), and 18800 (FDE).
- **Lock Screen Assessment**: `screen_lock_assessment.py` reads `locksettings.db`, classifies credential types, calculates search space sizes, and enforces wipe-risk attempt limits.

</details>

<details open>
<summary><strong>🔓 Deep Messenger Decryption & Forensic Carving</strong></summary>

- **Signal SQLCipher 4 Decryption**: `signal_rooted.py` derives database decryption keys on rooted devices and parses message databases.
- **WhatsApp Crypt14/15 Engine**: `whatsapp_downgrade.py` decrypts modern AES-GCM WhatsApp backup databases.
- **Telegram MTProto Deserializer**: `telegram_rooted.py` parses local TL binary caches and message stores.
- **SQLite B-Tree & WAL Carving**: `sqlite_carver.py` carves unallocated B-Tree slack space and freeblocks; `SafeSQLiteReader` recovers active and deleted log frames from Write-Ahead Logs (WAL).
- **OCR Intelligence & Crypto Seed Scanner**: Heuristic regex scanner detecting BIP-39 mnemonic seed phrases, PEM keys, ETH private keys, and credit card numbers across files.

</details>

<details open>
<summary><strong>📱 Device Readiness, Rooted & Non-Rooted Workflows</strong></summary>

- Authorized Android transport detection with device identity, model, Android version/API level, ADB version, authorization state, and readiness history
- Explicit root-status probing with `ROOT UID CONFIRMED` and `ROOT UID NOT AVAILABLE` outcomes, including Android Studio/userdebug `su 0 id` behavior
- Non-rooted capability profile for device information, contacts, SMS/MMS, call logs, shared storage, media, documents, and downloads when the provider accepts the authorized ADB transport
- Rooted capability profile that re-evaluates provider access after a confirmed root probe and exposes only policy-approved root-dependent options
- Clear separation between supported, unavailable, blocked, unsupported, and research-only capabilities; private WhatsApp/Telegram data is not treated as universally available

</details>

<details open>
<summary><strong>📞 Logical Collection & Media Evidence</strong></summary>

- Preview and selective acquisition options for device information, selected contacts, selected SMS/MMS, and selected call logs
- Shared-storage inventory with image, video, audio, document, download, and all-media filters
- Select-one or select-many acquisition with durable jobs, progress, cancellation, SHA-256 hashes, manifests, and chain-of-custody registration
- Case-scoped evidence explorer with metadata, file-type icons, safe image thumbnails, bounded previews, integrity verification, and local downloads for acquired evidence
- Report views that list acquired files, evidence keys, hashes, source paths, acquisition status, and custody history

</details>

<details open>
<summary><strong>🖥️ scrcpy Mirror, Control & Documentation</strong></summary>

- Bundled and validated scrcpy integration for read-only mirror, interactive control, and documented screen sessions
- Analyst acknowledgement before control or recording because taps, typing, and device-side actions can change device state
- Sealed MP4 documentation sessions with source metadata, SHA-256 integrity, and case custody history
- Screenshot capture remains available through ADB even when scrcpy control is unavailable

</details>

<details open>
<summary><strong>📄 Reports, Downloads & Auditability</strong></summary>

- Preliminary PDF, JSON, and CSV report outputs generated per case
- Native desktop save dialogs for reports, audit logs, custody checkpoints, and acquired evidence in the packaged application
- Separate workstation-wide and case-specific audit-log downloads
- Append-only case events, custody transfers, verification records, correction-by-amendment, and hash-chain verification
- Portable Windows, Linux, and macOS releases with bundled web UI, loopback backend, SBOM, release manifest, SHA-256 checksums, and GitHub Actions attestations

</details>

<details open>
<summary><strong>🖥️ Frontend & API Foundation</strong></summary>

- React 19, TypeScript 6, Vite, Tailwind CSS, TanStack Query, and accessible route shell
- FastAPI application factory with loopback-safe CORS configuration and request IDs
- SQLite WAL/foreign-key configuration and an initial reversible Alembic migration
- Migration-aware workstation startup that safely adopts recognized legacy development schemas before upgrading

</details>

<details open>
<summary><strong>🔐 Authentication, RBAC & Case Lifecycle</strong></summary>

- One-time local administrator bootstrap, Argon2id credentials, opaque hashed sessions, lockout, session rotation/revocation, CSRF validation, and explicit RBAC permissions
- Unique case numbers, creator ownership, memberships, lifecycle transitions, optimistic versions, append-only case events, protected case APIs, and Cases UI
- Case-scoped device detection, hashed device identity, immutable readiness snapshots, closed-case blocking, device history APIs, and case registry UI

</details>

<details open>
<summary><strong>🔌 ADB Transport & Capability Gating</strong></summary>

- Explicit ADB binary discovery and version validation primitives
- Typed ADB operation catalog with fixed arguments, serial validation, operation timeouts, and no browser-supplied command or path fields
- Shell-free asynchronous ADB execution with timeouts, cancellation cleanup, and output limits
- Device-state parsing for absent, authorized, unauthorized, offline, multiple, recovery, sideload, bootloader, and unknown states
- Immutable capability snapshots from fixed property/package operations and content-free shared-storage root checks with explicit supported, blocked, unknown, and unsupported decisions

</details>

<details open>
<summary><strong>📋 Acquisition Planning & Jobs</strong></summary>

- Immutable acquisition plans bound to an exact case, device, operator, and readiness snapshot, with a 30-minute freshness gate
- Metadata-only, quick-triage, shared-storage-inventory, and custom scopes with server-enforced module capability checks
- Canonical SHA-256 plan and readiness-snapshot hashes, recorded limitation acknowledgement, protected planning APIs, and plan-history UI
- Strict portable evidence-storage keys with traversal, link, and reparse-point boundary checks
- Partial-file streaming, atomic sealing, non-overwrite behavior, and streaming SHA-256 verification
- Durable versioned job states with restrictive case/plan ownership, validated transitions, monotonic progress, bounded JSON checkpoints, append-only sequenced events, cooperative cancellation, and restart interruption recovery
- Idempotent acquisition-job preparation, status/event/cancellation APIs, and case UI that clearly labels prepared jobs as not running

</details>

<details open>
<summary><strong>📂 Shared-Storage Inventory & Acquisition</strong></summary>

- Fixed-policy shared-storage path inventory with live device/fingerprint/root revalidation, a 30-second command timeout, depth 6 and 250-path limits, durable checkpoints, cancellation preservation, and a canonical SHA-256 manifest
- Path-only inventory persistence and UI: relative path, extension, per-path SHA-256, counts, limits, and manifest hash; no Android file bytes, timestamps, sizes, or arbitrary remote paths
- Selected inventory-item acquisition through shell-free `adb pull`, with a 100 MiB ceiling, 120-second timeout, contained random partial file, streaming SHA-256, canonical JSON manifest, restart/failure state, and no caller-supplied remote path
- Durable transfer-attempt ledger with startup reconciliation, retained-partial hashes, integrity-checked cleanup, explicit retain/discard decisions, and byte-zero restart without claiming unsupported ADB byte-range resume

</details>

<details open>
<summary><strong>🗂️ Evidence Explorer & Preview</strong></summary>

- Immutable metadata-only artifact normalization for sealed files, deterministic extension classification, canonical provenance/limitations, SQLite FTS5 indexing, case-scoped search filters, and a case-scoped evidence explorer
- Folder-first evidence browsing with exhaustive paged metadata loading, integrity-verified downloads for every acquired file type, and signature-gated inline viewing for PDFs, UTF-8 text, common audio, and common video
- Process-isolated JPEG/PNG/GIF/WebP signature validation and bounded thumbnail generation that re-verifies the sealed source, re-encodes a metadata-stripped PNG derivative, records extension mismatch/limits/version/hash, and never serves original evidence content
- Bounded Android stat metadata that preserves original modification epochs, normalized UTC values, source/confidence/precision, and inventory-versus-acquired size consistency without claiming creation/access times
- Deterministic timeline materialization for explicit acquisition collection timestamps, with source-artifact links, UTC basis, confidence, stable hashes, idempotent backfill, and no invented device-side times
- Analyst bookmarks, normalized case tags, and append-only notes with correction-by-supersession, separate from immutable evidence and recorded in the tamper-evident audit chain

</details>

<details open>
<summary><strong>🔗 Chain of Custody & Audit</strong></summary>

- Append-only evidence re-verification that independently re-hashes both sealed file and manifest, records verified/mismatch/missing/error outcomes, preserves original expected hashes, and exposes verification history in the UI
- Append-only chain-of-custody history with automatic evidence registration/integrity events, manual transfers, correction-by-amendment, per-case SHA-256 chaining, and chain verification
- Global tamper-evident audit chain for custody actions with canonical serialization, genesis hash, sequence/link verification, protected audit APIs, and no claim that local SQLite is tamper-proof
- Sealed custody/audit checkpoint JSON exports that verify the current custody chain and audit chain, hash the package before download, and label the result as not externally anchored
- Append-only external-anchor receipts for checkpoint hashes, with provider/reference metadata, optional receipt SHA-256, canonical anchor hashing, protected APIs, and case UI; ForensiX records the receipt but does not perform the external anchoring
- Detached RSA/ECDSA checkpoint-signature verification against supplied X.509 certificates, including certificate validity/key-usage checks, sealed-checkpoint re-hashing, immutable verification fingerprints, audit events, and case UI; certificate-chain trust and revocation validation remain external responsibilities

</details>

<details open>
<summary><strong>🧪 Validation, Recovery & CI</strong></summary>

- Deterministic mock ADB scenarios and safe API error envelopes
- Sealed end-to-end Evidence Twin known-answer validation covering import/chunk/manifest hashes, verified working copies, SQLite detection, contacts/SMS/MMS/calls, normalized timeline, custody/audit chains, and report-output integrity without retaining fixture PII
- Device-readiness UI with forensic limitations and operator guidance
- Experimental SQLite/WAL/rollback-journal recovery readiness and bounded fragment scanning on verified Evidence Twin copies, with sealed candidate records and no claim that fragments are proven deleted records
- Optional, hash-pinned TestDisk/PhotoRec external recovery on verified raw ext4/F2FS Evidence Twin copies, with controlled output, individual hashes, and explicit candidate-only limitations
- CI for frontend lint/type/test/build and backend Ruff/mypy/Pytest

</details>

<details open>
<summary><strong>🔬 Legacy Android Research Scope</strong></summary>

- The project documents a future research track for older Android 7-10 devices and devices with older security patch levels, including pre-October-2019 device-specific limitations
- APK downgrade on older/pre-2019 devices is a research idea only and is **not implemented** in ForensiX 1.0.1
- Temporary rooting, password brute force, lock bypassing, Qualcomm/EDL extraction, exploit chains, and proprietary Oxygen-style acquisition methods are **not implemented**
- These topics must not be presented as supported product features until they have a lawful, device-specific implementation, validation evidence, and a separate safety review

</details>

---

## 🚀 Local Setup

**Requirements:**

| Requirement | Notes |
| --- | --- |
| Node.js | 24+ |
| pnpm | 11+ |
| Python | 3.12+ |
| Android Platform Tools | Only when testing a real device |

Install the frontend:

```powershell
pnpm install
```

Create the Python environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Run the local API with the safe mock device:

```powershell
$env:FORENSIX_ADB_MODE = "mock"
$env:FORENSIX_MOCK_ADB_SCENARIO = "authorized"
.\.venv\Scripts\python.exe -m uvicorn forensix_api.main:app --host 127.0.0.1 --port 8765
```

In a second terminal, run the web application:

```powershell
pnpm dev
```

Open `http://127.0.0.1:5173/devices`.

On Windows, after installing dependencies, the launcher can start both services in real-device mode, validate the configured ADB executable, and open the device-readiness screen:

```powershell
.\scripts\start-forensix.ps1 -AdbPath "C:\platform-tools\adb.exe"
```

### 💻 Portable Windows Application

For the GitHub download, extract the ZIP and launch `ForensiX.exe`. The desktop launcher starts the local API and web application as one process, binds only to `127.0.0.1`, opens a native ForensiX window, and uses `%LOCALAPPDATA%\ForensiX` for the database, evidence vault, logs, and generated exports. Close the application window or terminate `ForensiX.exe` to stop the local service.

**On first use:**

1. Install Android SDK Platform-Tools and the correct USB driver for the Android device.
2. Enable Developer options and USB debugging on the device.
3. Connect the device, unlock it, and accept the RSA authorization prompt.
4. Launch `ForensiX.exe` and complete the local administrator setup.
5. Open **Device readiness**, run detection, and confirm the device is authorized before creating a case.
6. Create or open a case, link the detected device, run capability assessment, and choose only the supported acquisition options.
7. Keep the evidence directory on an encrypted workstation volume and preserve generated hashes, reports, and audit exports with the case.

If ADB is not on `PATH`, launch the desktop executable with an explicit path:

```powershell
.\ForensiX.exe --adb-path "C:\platform-tools\adb.exe"
```

> Use `--browser` to open the workstation in the default browser instead of the native window. Use `--no-browser` for a terminal-only readiness check.

The application does not need a separate **Start services** action during normal use. Its status and integration diagnostics show whether the local API, ADB, device transport, evidence storage, and optional scrcpy integration are ready. ADB is started on demand by the Android tooling. scrcpy is started only when an analyst explicitly requests mirroring, control, or recording.

### 🖱️ Optional Live Mirror & Device Control

The Windows portable release includes and validates the official scrcpy runtime automatically. Source checkouts can install it locally with:

```powershell
.\scripts\install-scrcpy.ps1
```

The launcher validates and pins the bundled or local scrcpy executable for that server session. scrcpy does not open at application startup because no device or case has been selected yet. Inside a case-linked device assessment, use **Read-only mirror** for passive viewing or **Interactive control** only after acknowledging that taps and typing change the device. See the [technical repository](TECHNICAL_REPOSITORY.md#4-major-code-flows) guide.

### 🕳️ Optional Deleted-Data Research

For controlled raw-image research, ForensiX can also invoke a separately installed and hash-pinned CGSecurity PhotoRec executable. It is not bundled with ForensiX and is only enabled for verified raw ext4/F2FS Evidence Twin working copies:

```powershell
.\scripts\install-testdisk.ps1
```

> PhotoRec output is a carved candidate set, not proof of deletion; it is never run against a live Android device or a sealed master source. See the [technical repository](TECHNICAL_REPOSITORY.md#10-capability-and-research-boundaries).

Use `-NoBrowser` for a terminal-only readiness check. Existing listeners on the configured API or web ports are reused instead of starting duplicate services.

Run `.\scripts\Test-ForensiX.ps1 -AdbPath "C:\path\to\adb.exe"` for a non-acquisition workstation check. Linux/macOS users can start with `FORENSIX_ADB_PATH=/path/to/adb ./scripts/start-forensix.sh`. See the [technical repository](TECHNICAL_REPOSITORY.md#8-installation-and-deployment) for driver, udev, Gatekeeper, status, and log guidance.

Encrypted workstation backups can be created, independently verified, and safely restored with `scripts/forensix-backup.py`; see the [technical repository](TECHNICAL_REPOSITORY.md#8-installation-and-deployment). Live evidence storage still relies on BitLocker, FileVault, or LUKS until an OS-keychain and agency-escrow design is formally validated.

Create a privacy-preserving, integrity-sealed mock or controlled-device validation record with `scripts/run-forensic-validation.py`; see the [technical repository](TECHNICAL_REPOSITORY.md#9-validation-and-quality-checks). The physical runner supports a fixed-path, two-pass known-file acquisition and SHA-256 check without allowing caller-supplied device paths, plus an examiner-driven disconnect/reconnect check. The matrix verifier rejects mock or tampered records and requires declared host, Android, OEM, rooted, and non-rooted coverage. A passing mock run is regression evidence and does not replace the physical-device release matrix.

The requirement-by-requirement implementation evidence and remaining external proof are recorded in the [technical repository](TECHNICAL_REPOSITORY.md#9-validation-and-quality-checks).

Verified SQLite databases and safe ZIP/TAR working copies can be assessed and scanned for bounded SQLite fragments from the Evidence Twin screen. The result remains candidate material: it does not prove a fragment is a deleted row. Verified raw ext4/F2FS working copies can additionally be sent to a separately installed, hash-pinned PhotoRec executable. See the [technical repository](TECHNICAL_REPOSITORY.md#10-capability-and-research-boundaries).

Supervisors and administrators can export sealed custody/audit checkpoint packages from a case after chain verification succeeds. The package hash must be preserved, signed, or published through an agency-controlled process before it becomes externally anchored. After that external action, the case screen can record its provider, reference, time, and optional receipt SHA-256 as an append-only anchor receipt. It can also verify a detached RSA/ECDSA signature against a supplied public X.509 certificate without accepting private keys. See the [technical repository](TECHNICAL_REPOSITORY.md#5-api-documentation).

Portable workstation bundles, CycloneDX SBOMs, SHA-256 manifests, GitHub build attestations, and tagged GitHub Releases are defined in the [technical repository](TECHNICAL_REPOSITORY.md#8-installation-and-deployment). Windows releases support Authenticode signing when the maintainer configures the protected signing certificate secrets; releases without those secrets remain explicitly unsigned.

> Mock scenarios are `no_devices`, `authorized`, `unauthorized`, `offline`, `multiple`, `storage_blocked`, and `timeout`. To use a real ADB executable, set `FORENSIX_ADB_MODE=system` and optionally set `FORENSIX_ADB_PATH` to the full executable path.

---

## 🐳 Container Build and Usage

ForensiX is designed for a single investigator workstation. The included `Dockerfile` therefore runs the API and the bundled web application on the loopback interface only; it is **not** intended to be published as a LAN or internet service.

### Build

```bash
docker build -t forensix .
```

### Run

Because the application deliberately binds `127.0.0.1`, use the host network to reach the API on the host loopback interface:

```bash
mkdir -p ~/forensix-data
docker run --rm --network host \
  -v ~/forensix-data:/data \
  forensix
```

Then open `http://127.0.0.1:8765/`.

The `/data` volume persists the SQLite database, acquired evidence, reports, logs, and generated exports. The image includes the Android Debug Bridge from `android-tools-adb`.

### Physical-device note

ADB inside the container cannot reach USB devices attached to the host through the default bridge network. For real-device acquisition, run with the host network **and** mount the host ADB server socket so the container can use the host's ADB instance:

```bash
docker run --rm --network host \
  -v ~/.android:/home/forensix/.android \
  -v /tmp:/tmp \
  -v ~/forensix-data:/data \
  forensix
```

The container starts its own ADB server by default. Sharing the host's `~/.android` directory lets it reuse the host-authorized device identity, and the shared `/tmp` allows the ADB socket path to be visible to both the container and the host. Authorization state and device access still depend on the host's Android SDK Platform-Tools and USB configuration. For the most predictable device experience, run ForensiX directly on the host rather than in a container.

---

## 🧪 Validation Commands

```powershell
pnpm lint
pnpm typecheck
pnpm test
pnpm build
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\mypy.exe forensic/src server/src apps/api/src tests
.\.venv\Scripts\pytest.exe
```

---

## 🔒 Security and Evidence Handling

The local API implements authentication, case-level authorization, and session/CSRF/permission checks, but the service must remain bound to `127.0.0.1`. It exposes no arbitrary ADB shell operation and accepts no command text or remote path from the browser.

A confirmed Quick Triage job can enumerate relative paths under one approved shared-storage root. An operator can then acquire one of those persisted inventory items; the browser submits only the opaque item ID. The backend revalidates device identity and root access, reconstructs the policy-approved path, uses shell-free `adb pull`, limits the transfer to 100 MiB, seals it into contained append-oriented storage, and writes file and manifest SHA-256 values.

Interrupted bytes are reconciled and hashed but remain quarantined from evidence indexing until an operator records a retain or verified-discard decision; restart begins again at byte zero. Completed files are normalized into immutable metadata records and a case-scoped FTS5 index without opening evidence content. Artifact MIME labels remain extension-derived.

On explicit request, a separate worker checks bounded magic bytes and may decode only JPEG, PNG, GIF, or WebP under time, byte, and pixel limits; the browser receives only an independently hashed, metadata-stripped PNG derivative. SVG, PDF, archive, Office, executable, audio, video, rejected, and failed inputs are never rendered. This is process isolation and resource bounding, not a claim of an absolute Windows OS sandbox.

Later integrity checks independently re-hash both sealed objects and append a result without replacing expected hashes. Evidence registration, integrity outcomes, transfers, amendments, preview outcomes, recovery decisions, and custody checkpoint downloads are hash-chained in custody/audit history. Checkpoint packages can be exported only after chain verification and are hash-sealed before download, but they remain not externally anchored unless preserved, signed, or published outside the workstation. These chains are tamper-evident, not immutable or tamper-proof, because the database and application remain on one workstation.

---

<div align="center">

Built for controlled, auditable, and explainable Android evidence triage. 🔎

</div>
