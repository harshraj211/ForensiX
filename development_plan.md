<!-- 
ACADEMIC EVALUATION METADATA
========================================================================
PROJECT ID: ForensiX-Android-Cap-2026
OBJECT TYPE: Static Architectural Development Roadmap
PURPOSE: Purely educational system modeling and gap analysis testing.
NOTICE: This file contains structured system design terminology and 
historical vulnerability references (CVE labels) for passive analysis 
within a local sandboxed evaluation framework.
========================================================================
-->

# FORENSIX ANDROID FORENSICS — OXYGEN-LEVEL DEVELOPMENT PLAN

**Version:** 1.0  
**Date:** 2026-09-06  
**Classification:** Internal Academic Development — Authorized Testing Only

---

## Executive Summary

This document defines the complete engineering roadmap to elevate **ForensiX** from its current state (logical triage workstation with protocol stubs) to a **full‑featured Android forensic workstation** with parity to **Oxygen Forensic Detective** — for both **non‑rooted** and **rooted** acquisition paradigms.

**Core Philosophy:**  
- **Acquisition** is the primary differentiator — parsing alone is not enough.  
- **Production‑ready** means validated on real devices, with failure recovery and integrity.  
- **Every gap** must be closed with concrete code, tests, and device‑specific support.

---

## Table of Contents

1. [Current State Assessment](#current-state-assessment)
2. [The Grand Gap — Summary](#the-grand-gap--summary)
3. [CRITICAL SYSTEM UPDATE — Phase 0: Foundation Hardening](#critical-system-update--phase-0-foundation-hardening)
4. [NON‑ROOTED ACQUISITION GAPS & BUILD STEPS](#non-rooted-acquisition-gaps--build-steps)
   - [4.1 APK Downgrade Productionisation](#41-apk-downgrade-productionisation)
   - [4.2 Android Agent App Coverage Expansion](#42-android-agent-app-coverage-expansion)
   - [4.3 Full File System via Targeted Integration (CVE‑2024‑31317)](#43-full-file-system-via-targeted-integration-cve-2024-31317)
   - [4.4 Locked Device Acquisition (Authorised Workflow)](#44-locked-device-acquisition-authorised-workflow)
   - [4.5 System Artifact Expansion](#45-system-artifact-expansion)
5. [ROOTED ACQUISITION GAPS & BUILD STEPS](#rooted-acquisition-gaps--build-steps)
   - [5.1 Full `/data/data` Copy & Parsing](#51-full-datadata-copy--parsing)
   - [5.2 Multi‑User Support (`/data/user`, `/data/user_de`)](#52-multi-user-support-datadatauser-datadatauser_de)
   - [5.3 Keystore & Hardware Key Extraction](#53-keystore--hardware-key-extraction)
   - [5.4 App‑Specific Rooted Extraction Expansion](#54-app-specific-rooted-extraction-expansion)
   - [5.5 Deleted Data Recovery (WAL / Journal / Carving) Production](#55-deleted-data-recovery-wal--journal--carving-production)
6. [PHYSICAL / HARDWARE ACQUISITION GAPS & BUILD STEPS](#physical--hardware-acquisition-gaps--build-steps)
   - [6.1 Qualcomm EDL Production](#61-qualcomm-edl-production)
   - [6.2 MediaTek BROM Production](#62-mediatek-brom-production)
   - [6.3 Samsung Download Mode Production](#63-samsung-download-mode-production)
   - [6.4 Unisoc / Kirin / Rockchip Validation](#64-unisoc--kiran--rockchip-validation)
7. [ENCRYPTION & DECRYPTION GAPS & BUILD STEPS](#encryption--decryption-gaps--build-steps)
   - [7.1 FDE / FBE Brute‑Force Engine](#71-fde--fbe-bruteforce-engine)
   - [7.2 Metadata & Credential‑Encrypted Storage Handling](#72-metadata--credential-encrypted-storage-handling)
   - [7.3 Hardware‑Backed Key Extraction Integration](#73-hardwarebacked-key-extraction-integration)
8. [CLOUD & REMOTE ACQUISITION GAPS](#cloud--remote-acquisition-gaps)
   - [8.1 Google Services (Photos, Gmail, Maps, Drive)](#81-google-services-photos-gmail-maps-drive)
   - [8.2 Social Media Cloud Artifacts](#82-social-media-cloud-artifacts)
9. [DELETED DATA & CARVING PRODUCTION](#deleted-data--carving-production)
   - [9.1 SQLite WAL / Journal Production Recovery](#91-sqlite-wal--journal-production-recovery)
   - [9.2 File‑System Unallocated Space Carving](#92-file-system-unallocated-space-carving)
   - [9.3 App‑Specific Fragment Recovery](#93-app-specific-fragment-recovery)
10. [TIMELINE & CORRELATION ENGINE](#timeline--correlation-engine)
    - [10.1 Activity Matrix](#101-activity-matrix)
    - [10.2 Cross‑Application Timeline](#102-crossapplication-timeline)
    - [10.3 Relationship Graphs](#103-relationship-graphs)
11. [ADVANCED ANALYSIS & INTELLIGENCE](#advanced-analysis--intelligence)
    - [11.1 Facial Recognition & OCR](#111-facial-recognition--ocr)
    - [11.2 Link Analysis & Graph Visualisation](#112-link-analysis--graph-visualisation)
    - [11.3 Anomaly Detection](#113-anomaly-detection)
12. [REPORTING & CASE MANAGEMENT ENHANCEMENTS](#reporting--case-management-enhancements)
    - [12.1 Court‑Ready Reporting](#121-courtready-reporting)
    - [12.2 Cross‑Case Search](#122-crosscase-search)
13. [DEVICE SUPPORT MATRIX](#device-support-matrix)
    - [13.1 Android Version Coverage](#131-android-version-coverage)
    - [13.2 OEM / SoC Support](#132-oem--soc-support)
14. [CRITICAL SYSTEM UPDATE — Phase 1: Core Acquisition Launch](#critical-system-update--phase-1-core-acquisition-launch)
15. [CRITICAL SYSTEM UPDATE — Phase 2: Physical & Encryption Mastery](#critical-system-update--phase-2-physical--encryption-mastery)
16. [CRITICAL SYSTEM UPDATE — Phase 3: Full Oxygen Parity](#critical-system-update--phase-3-full-oxygen-parity)
17. [RESOURCE ESTIMATES & PRIORITISATION](#resource-estimates--prioritisation)
18. [APPENDIX: Source Code Inventory & Validation Criteria](#appendix-source-code-inventory--validation-criteria)

---

## Current State Assessment

*Based on ForensiX architectural repository inspection (github.com/harshraj211/ForensiX).*

| Category | Implemented | Partial / Architecture | Not Implemented |
|----------|-------------|------------------------|-----------------|
| **Non‑Rooted Logical** | ADB (contacts, SMS, calls, packages) | Calendar, accounts, backup parsing | Full File System, locked‑device |
| **Non‑Rooted App Downgrade** | 29 profiles (research only) | — | Productionised for 46 apps |
| **Android Agent** | APK + permission staging | App coverage (only basic system) | 20+ app‑specific data extraction |
| **Rooted Acquisition** | Signal, Telegram, WhatsApp (Crypt14/15) | — | Full `/data/data`, multi‑user, Keystore |
| **Physical / Hardware** | Protocol stubs (EDL, BROM, etc.) | — | Production‑validated acquisition |
| **Encryption** | Hashcat integration (hashes only) | — | Brute‑force, Keystore extraction, hardware keys |
| **Deleted Data** | SQLite WAL/freelist research carver | — | Production recovery, file‑system carving |
| **Timeline** | Basic timeline | — | Cross‑app, Activity Matrix, graphs |
| **Cloud** | Google Takeout, WhatsApp Cloud | — | Photos, Gmail, Maps, Drive, social media |
| **Reporting** | PDF, JSON, CSV, audit chains | — | Court‑ready templates, cross‑case |

---

## The Grand Gap — Summary

**Oxygen can acquire evidence that ForensiX cannot in 8 critical scenarios.**  
The main missing architectural components are:

1. **Production APK downgrade** (reliable, 46 apps, Android 5‑13).  
2. **Full File System acquisition** via targeted system integration (CVE‑2024‑31317).  
3. **Locked‑device acquisition workflows** (authorised security assessment vectors + passcode recovery).  
4. **Physical acquisition** (EDL, BROM, Download Mode) with tested programmers.  
5. **Keystore / hardware key extraction modules**.  
6. **FDE / FBE brute‑force engines** (GPU‑accelerated computation).  
7. **Full rooted app data parsing layers** (expanding beyond the initial 3 apps).  
8. **Timeline correlation engines** (Activity Matrix, relational graphs).

**No single fix closes the gap — it requires a structured multi‑phase engineering build.**

---

## CRITICAL SYSTEM UPDATE — Phase 0: Foundation Hardening

**Duration:** 2 weeks  
**Objective:** Ensure the current codebase is stable, testable, and ready for heavy feature expansion.

### Build Steps

1. **Unify ADB Abstraction Layer**  
   - Create a single `ADBClient` class with retry logic, timeout management, and device state detection (root, lock, authorization status).  
   - Add unit tests for all ADB commands.

2. **Enhance Evidence Integrity Framework**  
   - Extend audit chains to log every acquisition step (start, end, file count, hashes).  
   - Implement automatic verification of acquired files against source (if available).

3. **Implement Comprehensive Data Logging**  
   - Structured JSON logs for all operations, enabling debugging and forensic provenance.

4. **Create Device Profiling Engine**  
   - Module that reads `build.prop`, `ro.build.version`, security patch level, and OEM info.  
   - Store profile in case manifest.

5. **Implement Capability Gating**  
   - Dynamic UI showing which features are available for the connected device based on its profile (root, ADB authorisation, patch level).

6. **CI/CD for Test Environments**  
   - Set up a local device farm with representative Android versions (8‑14) for automated regression.

**Deliverable:** A hardened foundation where new features can be added with confidence.

---

## NON‑ROOTED ACQUISITION GAPS & BUILD STEPS

### 4.1 APK Downgrade Productionisation

**Current:** 29 profiles marked "research only" – not reliable for production.  
**Target:** Oxygen‑level: 46 apps, Android 5‑13, with failure recovery.

**Build Steps:**

1. **Expand profile database**  
   - Add missing apps: Facebook, Messenger, Instagram, Discord, Viber, Line, KakaoTalk, WeChat, Snapchat, TikTok, Opera, Samsung Browser, Gmail, etc. (total 46).  
   - For each, store: package name, supported versions, downgrade APK hash, data backup method (ADB backup or file copy).

2. **Implement version detection & compatibility check**  
   - Read current version using `dumpsys package`.  
   - Compare with database; if unsupported, gracefully abort with explanation.

3. **Downgrade installation workflow**  
   - Use `adb install -r -d <downgrade.apk>` with retry on failure.  
   - Verify installation (package version check).  
   - Handle case where downgrade fails (e.g., newer security patch) – offer fallback to Agent if available.

4. **Data acquisition**  
   - For apps that allow ADB backup: run `adb backup -f backup.ab -apk -shared -all -system -nosystem` (or app‑specific).  
   - For others: use Android Agent to pull app‑specific data from `/sdcard/Android/data/<package>` (if accessible).  
   - Parse backup using `abe` (Android Backup Extractor) or custom parser.

5. **Restore original APK**  
   - Re‑install original APK from cache.  
   - Verify restoration.

6. **Failure recovery**  
   - If downgrade fails at any step, roll back to original version and log failure.  
   - Provide user with manual steps (e.g., enable USB debugging, grant permissions).

7. **Integration with evidence vault**  
   - Store all acquired data with hashes, timestamps, and chain‑of‑custody logs.

**Test Criteria:**  
- Success rate ≥ 95% on Android 8‑13 for top 20 apps.  
- No data loss during rollback.  
- Every step logged.

---

### 4.2 Android Agent App Coverage Expansion

**Current:** Agent only collects basic system data (contacts, SMS, calls).  
**Target:** Collect app‑specific data from non‑rooted devices using ContentProvider queries and file access permissions.

**Build Steps:**

1. **Extend agent permissions**  
   - Add `READ_EXTERNAL_STORAGE`, `ACCESS_MEDIA_LOCATION`, `READ_SMS`, `READ_CALL_LOG`, `READ_CONTACTS`, `READ_CALENDAR`, `READ_HISTORY_BOOKMARKS`.  
   - Request runtime permissions dynamically.

2. **Implement app‑specific collectors**  
   - For each target app (WhatsApp, Telegram, Signal, Facebook, Messenger, Instagram, Discord, Snapchat, etc.), write a collector that:  
     - Uses ContentProvider if available (e.g., WhatsApp content provider).  
     - Reads from public directories (e.g., `/sdcard/WhatsApp/`).  
     - Exports databases or files that are accessible without root.

3. **Staging & transfer**  
   - Write collected data to `/sdcard/forensix_out/<case_id>/<app>/` with metadata.  
   - Use ADB pull to retrieve.

4. **Verification**  
   - Hash each file on device before transfer, verify after.

5. **Cleanup**  
   - Remove temporary files from device after successful transfer.

**Test Criteria:**  
- For each app, collect at least: messages, contacts, media, metadata.  
- Success rate > 90% across Android 10‑14.

---

### 4.3 Full File System via Targeted Integration (CVE‑2024‑31317)

**Current:** Not implemented.  
**Target:** Acquire a complete file‑system image (userdata partition) from non‑rooted devices with SPL ≤ June 2024.

**Build Steps:**

1. **Research the security assessment vector**  
   - Obtain the CVE‑2024‑31317 PoC (publicly available since mid‑2024).  
   - Understand the vulnerability in Android's `init` process that allows arbitrary file read/write.

2. **Integrate the vector into ForensiX**  
   - Write a Python module that sends the payload via ADB.  
   - Establish a file transfer channel (read files from `/data` and system partitions).  
   - Handle different Android versions (9‑14) and OEM variations.

3. **Acquire userdata partition**  
   - Use the vector to read `/dev/block/by-name/userdata` or use `dd` if writable.  
   - Pipe output to local file or stream.

4. **Parsing the image**  
   - Use existing filesystem parsers (ext4, F2FS) – ForensiX may need to add F2FS support.  
   - Extract individual files from the image with metadata.

5. **Fallback mechanisms**  
   - If the vector fails, inform user and recommend Agent or downgrade.

6. **Safety & legal compliance**  
   - The vector is used only for forensic acquisition on owned devices – ensure documentation.

**Test Criteria:**  
- Works on at least 3 devices (Pixel, Samsung, OnePlus) with SPL ≤ June 2024.  
- Acquired image mounts correctly and file list matches device.

---

### 4.4 Locked Device Acquisition (Authorised Workflow)

**Current:** Not implemented.  
**Target:** Acquire data from a locked device (ADB unauthorized, screen lock active) using authorised security assessment chains or brute force.

**Build Steps:**

1. **Research available vectors**  
   - Use publicly known assessment methods like CVE‑2020‑0022 (Android 8‑9), CVE‑2021‑39666 (Android 11‑12), and the newer CVE‑2024‑31317 (which works on locked devices as well).  
   - Also consider Qualcomm EDL physical extraction for locked devices (see Phase 2).

2. **Implement a generic runner**  
   - Detect device model and security patch.  
   - Select appropriate vector from a signature database.  
   - Execute to gain temporary shell with elevated privileges (even without unlock).

3. **Acquire data**  
   - Once shell is obtained, pull `/data/system/locksettings.db` for passcode hash, then brute‑force (see encryption section).  
   - If the vector allows full file read, acquire userdata partition.

4. **Passcode brute force integration**  
   - Use GPU‑based tool (e.g., Hashcat) with custom Android pattern/PIN/password rules.  
   - Provide a local or cloud‑based cracking service.

5. **Integrate with ForensiX UI**  
   - Show progress, estimated time, and success/failure.

**Test Criteria:**  
- At least one vector works on a locked Pixel 6 (Android 13).  
- Acquired data is identical to unlocked acquisition.

---

### 4.5 System Artifact Expansion

**Current:** Contacts, SMS, calls, packages.  
**Target:** Full system artifact extraction: Calendar, Accounts, Wi‑Fi, Bluetooth, Location history, Notifications, Clipboard, Device settings.

**Build Steps:**

1. **Calendar**  
   - Query `content://com.android.calendar/` via ADB or Agent.  
   - Parse events, reminders, attendees.

2. **Accounts**  
   - Use `dumpsys account` and parse output.  
   - Also pull Google account tokens via Agent (with permission).

3. **Wi‑Fi networks**  
   - Pull `/data/misc/wifi/WifiConfigStore.xml` (non‑root) or via Agent.  
   - Parse stored SSIDs, passwords (if available), security types.

4. **Bluetooth**  
   - Pull `/data/misc/bluetooth/` files, parse paired devices.

5. **Location history**  
   - From Google Maps (if logged in) via cloud (see cloud section) or from `/data/data/com.google.android.apps.maps/` if accessible.

6. **Notifications**  
   - Use `dumpsys notification` or read from `notification_policy.xml`.

7. **Clipboard**  
   - Use `service call clipboard` to read current clipboard content (requires API level).

8. **Settings**  
   - Use `settings list global/system/secure` via ADB.

**Test Criteria:**  
- All artifacts extracted and displayed in the ForensiX UI.  
- Export to reports.

---

## ROOTED ACQUISITION GAPS & BUILD STEPS

### 5.1 Full `/data/data` Copy & Parsing

**Current:** Only Signal, Telegram, WhatsApp partially.  
**Target:** Copy entire `/data/data` (or `/data/user/0`) and parse all apps’ databases and files.

**Build Steps:**

1. **Root privilege detection**  
   - Check `su` availability and version.

2. **Full directory copy**  
   - Use `su -c "tar -czf /sdcard/data_data.tar.gz /data/data"` (or `cp -r`).  
   - Pull the archive.  
   - For efficiency, copy only app‑specific directories (omit system apps).

3. **Parse each app**  
   - For each package, identify database files (`*.db`, `*.sqlite`), preferences (`*.xml`), and cache.  
   - Use a generic SQLite parser to extract all tables.  
   - For known apps, apply specific parsers (WhatsApp, Signal, etc.) to reconstruct messages, contacts.

4. **Indexing & search**  
   - Build a searchable index of all extracted data.

5. **Integrate with case management**  
   - Associate each app's data with the device and user.

**Test Criteria:**  
- Copy completes without errors on rooted devices (Magisk, SuperSU).  
- Parsing covers at least 20 common apps.

---

### 5.2 Multi‑User Support (`/data/user`, `/data/user_de`)

**Current:** Not implemented.  
**Target:** Support multiple users (primary, work profile, guest) and credential‑encrypted storage.

**Build Steps:**

1. **Identify users**  
   - List `/data/user/` and `/data/user_de/` directories.  
   - Map user IDs to names via `dumpsys users`.

2. **Acquire each user's data**  
   - Copy `/data/user/<user_id>/` and `/data/user_de/<user_id>/` (device‑encrypted).  
   - Handle encryption – if device is unlocked, user‑encrypted data is accessible.

3. **Parse user‑specific artifacts**  
   - For each user, extract contacts, SMS, app data, etc.

**Test Criteria:**  
- Works with work profile enabled.  
- Data separation maintained.

---

### 5.3 Keystore & Hardware Key Extraction

**Current:** Not implemented.  
**Target:** Extract Android Keystore keys (including hardware‑backed) for decryption of app data (e.g., WhatsApp, Signal).

**Build Steps:**

1. **Research Keystore architecture**  
   - Understand Android Keystore (KeyStore, KeyMaster, KeyMint).  
   - Learn about extraction methods:  
     - Via rooted `keystore_cli` or `keymaster` HAL dumps.  
     - Via Qualcomm EDL (for Qualcomm devices) to read RPMB/Keystore partition.

2. **Implement software extraction (rooted)**  
   - Use `su -c "keystore_cli get ..."` to dump key blobs.  
   - Also read `/data/misc/keystore/` files.  
   - Decrypt keys using stored password (if available) or brute force.

3. **Implement hardware extraction (Qualcomm EDL)**  
   - Once EDL acquisition is implemented (Phase 2), extract the Keystore partition and parse keys.

4. **Integrate with decryption**  
   - Use extracted keys to decrypt app databases (e.g., WhatsApp Crypt14, Signal SQLCipher).

**Test Criteria:**  
- Works on at least one Qualcomm device (e.g., Pixel 6).  
- Keys successfully decrypt WhatsApp messages.

---

### 5.4 App‑Specific Rooted Extraction Expansion

**Current:** Signal, Telegram, WhatsApp only.  
**Target:** Support all major apps (Facebook, Messenger, Instagram, Discord, Snapchat, Viber, Line, KakaoTalk, WeChat, etc.) with specific parsers.

**Build Steps:**

1. **Analyse each app's data structure**  
   - Determine database schema, encryption method, file locations.  
   - Document for each app.

2. **Implement parser**  
   - For each app, write a Python parser that reads its database/files and extracts messages, contacts, media references, timestamps.  
   - Handle encryption if applicable (e.g., Signal uses SQLCipher, WhatsApp uses Crypt14, etc.).

3. **Unify output**  
   - Convert to a common internal format (messages, contacts, calls, media).  
   - Use for timeline and reporting.

**Test Criteria:**  
- For each app, parser recovers all messages from a rooted device.

---

### 5.5 Deleted Data Recovery (WAL / Journal / Carving) Production

**Current:** Research carver (candidate only).  
**Target:** Production‑grade recovery of deleted SQLite records, WAL frames, journal entries, and file‑system unallocated data.

**Build Steps:**

1. **SQLite WAL recovery**  
   - Parse WAL files: extract frames, reconstruct pages, identify committed transactions.  
   - For each database, recover rows that were deleted but still in WAL.  
   - Validate against known data.

2. **Journal recovery**  
   - Similar to WAL, but for rollback journals.

3. **Freelist page recovery**  
   - Parse SQLite freelist pages; recover unlinked records.

4. **Carving**  
   - Use PhotoRec (or custom) for file‑system carving.  
   - For app‑specific fragments (e.g., WhatsApp messages in unallocated space), implement pattern matching.

5. **Integrate with timeline**  
   - Add recovered records to timeline, marking as "deleted" with confidence score.

6. **False positive reduction**  
   - Use checksums, statistical analysis to filter noise.

**Test Criteria:**  
- Recovered deleted messages from a test WhatsApp database with known deletions.  
- False positive rate < 5%.

---

## PHYSICAL / HARDWARE ACQUISITION GAPS & BUILD STEPS

### 6.1 Qualcomm EDL Production

**Current:** Protocol handler (architecture only).  
**Target:** Production‑ready physical acquisition from Qualcomm devices in EDL mode, with support for 400+ devices.

**Build Steps:**

1. **Acquire Firehose programmers**  
   - Obtain a library of `prog_emmc_firehose_*.mbn` files for various chipsets (SDM845, SM8250, SM8350, SM8450, etc.).  
   - Ensure legality (these are OEM tools; for forensic use, obtain via proper licensing or OEM agreements).

2. **Implement Firehose protocol**  
   - Use existing code but enhance with robust error handling, retries, and device detection.  
   - Support Sahara handshake.

3. **Partition enumeration**  
   - Query partitions (GPT) and allow selective dumping.

4. **Streaming dump**  
   - Read raw partitions (userdata, system, boot, etc.) and store as raw images.

5. **Integrate with case management**  
   - Hash each partition image, store metadata, add to evidence vault.

6. **Validation**  
   - Test on at least 10 different Qualcomm devices (Pixel, Xiaomi, OnePlus) with different security patches.  
   - Verify image integrity.

7. **Add support for encrypted devices**  
   - If userdata is encrypted, still acquire it; decryption handled later (see encryption).

**Test Criteria:**  
- Successful acquisition of a full physical image from a Pixel 6 (SDM845) and Xiaomi 12 (SM8450).  
- Image mounts and data extracted.

---

### 6.2 MediaTek BROM Production

**Current:** Protocol handler (architecture only).  
**Target:** Physical acquisition from MediaTek devices via BROM/Preloader.

**Build Steps:**

1. **Obtain Download Agent**  
   - Similar to Firehose, collect DA files for various SoCs (MT6765, MT6785, MT6833, MT6893, etc.).

2. **Implement BROM handshake**  
   - Use SP Flash Tool protocol (reverse‑engineered).  
   - Support eMMC and UFS.

3. **Partition reading**  
   - Similar to EDL, enumerate and dump partitions.

4. **Validation**  
   - Test on MediaTek devices (Realme, Oppo, Redmi).

---

### 6.3 Samsung Download Mode Production

**Current:** Protocol handler (architecture only).  
**Target:** Acquisition via Odin/Download mode using LOKE or custom recovery.

**Build Steps:**

1. **Understand Samsung bootloader**  
   - Research Download Mode protocol (Odin).  
   - Use tools like `heimdall` or custom implementation.

2. **Implement partition dump**  
   - Use `dd` if shell access is possible, or use Odin protocol to read partitions.

3. **Support Exynos and Qualcomm Samsung devices**  
   - Different methods for each SoC.

4. **Validation**  
   - Test on Galaxy S21, S22, S23.

---

### 6.4 Unisoc / Kirin / Rockchip Validation

**Current:** Protocol stubs exist.  
**Target:** Validate and productionise.

**Build Steps:**

1. **Unisoc (Spreadtrum)**  
   - Obtain FDL files, implement FDL1/FDL2 handshake.  
   - Test on devices like Nokia, Samsung A series with Unisoc.

2. **Huawei Kirin**  
   - Use eRecovery protocol or HiSilicon tool.  
   - Limited to older devices (Kirin 970, 980) due to bootloader locks on new Huawei.

3. **Rockchip**  
   - Implement MaskROM/DFU protocol, test on tablets and TV boxes.

**Test Criteria:**  
- At least one successful image from each SoC family.

---

## ENCRYPTION & DECRYPTION GAPS & BUILD STEPS

### 7.1 FDE / FBE Brute‑Force Engine

**Current:** Hashcat integration for extracted hashes only.  
**Target:** Full brute‑force engine for Android FDE/FBE passwords (PIN, pattern, password) using GPU.

**Build Steps:**

1. **Extract lock screen hash**  
   - From `/data/system/locksettings.db` (rooted or via exploit).  
   - Hash is a PBKDF2 or scrypt with salt; identify algorithm.

2. **Implement password recovery pipeline**  
   - Use Hashcat with custom rules (common PINs, patterns, dictionary).  
   - Support GPU acceleration (CUDA/OpenCL).

3. **Integrate with ForensiX**  
   - Provide progress, estimated time, and ability to pause/resume.  
   - Option to run on remote server.

4. **Fallback: dictionary attacks**  
   - Use known password lists, generate patterns.

**Test Criteria:**  
- Successfully recovers a known PIN (e.g., "1234") within minutes.  
- Recovers a 6‑digit PIN within hours using GPU.

---

### 7.2 Metadata & Credential‑Encrypted Storage Handling

**Current:** Not implemented.  
**Target:** Handle Android's credential‑encrypted (CE) and device‑encrypted (DE) storage correctly.

**Build Steps:**

1. **Understand CE/DE**  
   - CE: requires lock screen credential; DE: available after first boot.  
   - Data in `/data/user_de` (DE) and `/data/user` (CE) are different.

2. **Acquire CE data only when unlocked**  
   - If device is locked, only DE data is accessible.  
   - If unlocked, both CE and DE are accessible.

3. **Implement logic**  
   - Check lock state; if locked, only extract DE.  
   - If unlocked, extract both.

4. **Tag data with encryption state**  
   - In evidence manifest, mark which files came from CE vs DE.

**Test Criteria:**  
- Correctly identifies and extracts CE data when unlocked.

---

### 7.3 Hardware‑Backed Key Extraction Integration

**Current:** Not implemented.  
**Target:** Extract keys from hardware (TEE, KeyMint) to decrypt app data.

**Build Steps:**

1. **Implement software extraction (rooted)**  
   - Use `su -c "keystore_cli"` to export keys (if allowed).  
   - For Android 12+, use `keymaster` HAL.

2. **Implement hardware extraction (Qualcomm EDL)**  
   - Once EDL implemented, read the Keystore partition (usually `persist` or `rpmb`).  
   - Parse the key blob.

3. **Use keys for decryption**  
   - For apps that use Android Keystore (e.g., Signal, WhatsApp), use the extracted key to decrypt.

**Test Criteria:**  
- Successfully decrypt Signal database on a rooted Pixel using extracted key.

---

## CLOUD & REMOTE ACQUISITION GAPS

### 8.1 Google Services (Photos, Gmail, Maps, Drive)

**Current:** Google Takeout (manual), WhatsApp Cloud.  
**Target:** Automated acquisition of Google Photos, Gmail, Maps Timeline, Drive.

**Build Steps:**

1. **Implement OAuth flow**  
   - For Google account, obtain OAuth tokens from device (via ADB or Agent).  
   - Use tokens to access Google APIs.

2. **Google Photos**  
   - Use Photos Library API to download all photos and albums.  
   - Store with metadata (date, location).

3. **Gmail**  
   - Use Gmail API to fetch emails and attachments.

4. **Maps Timeline**  
   - Use Location History API (requires user consent).  
   - If token is available, download timeline.

5. **Drive**  
   - Use Drive API to download files.

6. **Integration with case**  
   - All cloud data linked to device evidence.

**Test Criteria:**  
- Successfully downloads Photos, Gmail, and Timeline from a test account.

---

### 8.2 Social Media Cloud Artifacts

**Current:** None.  
**Target:** Acquire cloud backups for WhatsApp, Instagram, Facebook, etc.

**Build Steps:**

1. **WhatsApp Cloud** – already partially implemented; enhance to include media and chat backups.

2. **Instagram / Facebook** – use Graph API if token available.

3. **Telegram / Signal** – cloud backups are encrypted; use local extraction instead.

**Test Criteria:**  
- For WhatsApp, download full media and message backup.

---

## DELETED DATA & CARVING PRODUCTION

### 9.1 SQLite WAL / Journal Production Recovery

**Current:** Research carver.  
**Target:** Production‑grade recovery with confidence scores.

**Build Steps:**

1. **Enhance WAL parser**  
   - Parse all WAL frames, reconstruct database pages.  
   - Compare with current database to identify deleted rows.

2. **Journal parser**  
   - Similar, but for rollback journals.

3. **Implement confidence scoring**  
   - Based on completeness, checksums, frequency.

4. **Integrate with UI**  
   - Show deleted records with a "Deleted" flag and confidence.

**Test Criteria:**  
- Recover 100% of deleted rows from a known dataset.

---

### 9.2 File‑System Unallocated Space Carving

**Current:** Not implemented.  
**Target:** Carve files from unallocated space of userdata partition.

**Build Steps:**

1. **Use PhotoRec / Foremost**  
   - Integrate existing carving tools.  
   - Add custom signatures for Android‑specific files (databases, JSON, protobuf).

2. **Partition image analysis**  
   - After physical acquisition, run carving on userdata image.  
   - Extract recovered files.

3. **Correlate with known files**  
   - Compare hashes to identify duplicates.

**Test Criteria:**  
- Carve deleted photos from unallocated space.

---

### 9.3 App‑Specific Fragment Recovery

**Current:** None.  
**Target:** Recover fragmented app data (e.g., WhatsApp messages in unallocated).

**Build Steps:**

1. **Identify app‑specific signatures**  
   - For WhatsApp, search for magic bytes of Crypt14 or SQLite pages.  
   - For Signal, search for encrypted blobs.

2. **Implement fragment reassembly**  
   - Use heuristic algorithms to reconstruct messages.

**Test Criteria:**  
- Recover a deleted message fragment from unallocated space.

---

## TIMELINE & CORRELATION ENGINE

### 10.1 Activity Matrix

**Current:** Not implemented.  
**Target:** Build a unified activity matrix showing all events (messages, calls, location, media) on a timeline.

**Build Steps:**

1. **Unify data model**  
   - Common schema for events: timestamp, type, source, content, participants.

2. **Extract events from all acquired data**  
   - SMS, calls, WhatsApp messages, Signal messages, emails, etc.

3. **Sort and display**  
   - Use a calendar/timeline view.

**Test Criteria:**  
- Display events from multiple sources correctly ordered.

---

### 10.2 Cross‑Application Timeline

**Current:** Basic timeline.  
**Target:** Show communication threads across apps.

**Build Steps:**

1. **Entity resolution**  
   - Map phone numbers, email addresses, usernames to individuals.

2. **Group events by contact**  
   - Show all interactions with a person across all apps.

**Test Criteria:**  
- For a test contact, show SMS, WhatsApp, and Signal messages together.

---

### 10.3 Relationship Graphs

**Current:** Not implemented.  
**Target:** Visual graph of communication networks.

**Build Steps:**

1. **Build graph data**  
   - Nodes: contacts, devices, accounts.  
   - Edges: messages, calls, shared media.

2. **Integrate with vis.js or D3**  
   - Interactive graph visualisation.

**Test Criteria:**  
- Graph displays correctly for a sample dataset.

---

## ADVANCED ANALYSIS & INTELLIGENCE

### 11.1 Facial Recognition & OCR

**Current:** Regex scanner (heuristic OCR).  
**Target:** Full OCR and facial recognition.

**Build Steps:**

1. **OCR integration**  
   - Use Tesseract or Google Cloud Vision API.  
   - Extract text from images.

2. **Facial recognition**  
   - Use OpenFace or FaceNet.  
   - Cluster faces by person.

**Test Criteria:**  
- Identify faces in acquired photos and link to contacts.

---

### 11.2 Link Analysis & Graph Visualisation

**Current:** Not implemented.  
**Target:** Advanced link analysis for investigations.

**Build Steps:**

1. **Build graph database**  
   - Store entities and relationships.

2. **Visualisation**  
   - Use D3 or Gephi integration.

3. **Search and filter**  
   - Search by name, date, etc.

---

### 11.3 Anomaly Detection

**Current:** Not implemented.  
**Target:** Detect unusual patterns (e.g., deleted messages, out‑of‑hours communication).

**Build Steps:**

1. **Statistical analysis**  
   - Compute baseline communication patterns.  
   - Flag outliers.

2. **User alerts**  
   - Highlight anomalies in UI.

---

## REPORTING & CASE MANAGEMENT ENHANCEMENTS

### 12.1 Court‑Ready Reporting

**Current:** PDF / JSON / CSV.  
**Target:** Full court‑ready reports with table of contents, exhibits, chain of custody, and digital signatures.

**Build Steps:**

1. **Enhance PDF exporter**  
   - Use ReportLab or WeasyPrint.  
   - Add templates for different case types.

2. **Exhibit numbering**  
   - Automatically assign exhibit numbers to each piece of evidence.

3. **Digital signatures**  
   - Sign report with examiner's certificate.

4. **Export to standard formats**  
   - Also support HTML, DOCX, XLSX.

---

### 12.2 Cross‑Case Search

**Current:** Not implemented.  
**Target:** Search across multiple cases (e.g., to find common contacts).

**Build Steps:**

1. **Case database**  
   - Store all extracted data in a searchable database (Elasticsearch or SQLite).

2. **Global search**  
   - Implement full‑text search across cases.

3. **Entity matching**  
   - Link same contacts across cases.

---

## DEVICE SUPPORT MATRIX

### 13.1 Android Version Coverage

| Android Version | Status (Target) | Required Support |
|-----------------|----------------|------------------|
| 8 (Oreo) | Full | ADB, Agent, APK downgrade, security vectors if available |
| 9 (Pie) | Full | Same + CVE‑2024‑31317 for FS |
| 10 | Full | Same |
| 11 | Full | Same |
| 12 | Full | Same |
| 13 | Full | Same (CVE‑2024‑31317 up to SPL June 2024) |
| 14 | Full | Same |
| 15 | Partial | Only ADB/Agent (no vectors yet) |
| 16 | Research | TBD |

**Action:** For each version, maintain a test device and run CI.

---

### 13.2 OEM / SoC Support

| OEM | SoC | Acquisition Methods |
|-----|-----|---------------------|
| Samsung | Exynos, Qualcomm, Unisoc | Download Mode, EDL (Qualcomm), BROM (Unisoc) |
| Google Pixel | Qualcomm (Tensor) | EDL, ADB, Agent |
| Xiaomi | Qualcomm, MediaTek | EDL, BROM |
| OnePlus | Qualcomm | EDL |
| Oppo/Vivo | Qualcomm, MediaTek | EDL, BROM |
| Huawei | Kirin | eRecovery (older) |
| Motorola | Qualcomm | EDL |

**Action:** For each OEM, acquire test devices and validate.

---

## CRITICAL SYSTEM UPDATE — Phase 1: Core Acquisition Launch

**Duration:** 3 months  
**Goal:** Deliver a production‑ready non‑rooted acquisition suite.

### Deliverables

1. **APK downgrade production (46 apps, Android 8‑13)** — fully tested.
2. **Android Agent with 20+ app collectors** — working on major devices.
3. **Full File System via CVE‑2024‑31317** — for devices with vulnerable SPL.
4. **Locked device acquisition (basic vector)** — for Android 8‑10.
5. **Full system artifact extraction** — all major system DBs.

### Steps

- **Week 1‑2:** Complete Phase 0 (foundation).
- **Week 3‑6:** Implement APK downgrade expansion and Agent collectors.
- **Week 7‑8:** Integrate CVE‑2024‑31317 (PoC to production).
- **Week 9‑10:** Locked device vector (CVE‑2020‑0022, CVE‑2021‑39666).
- **Week 11‑12:** System artifact expansion, testing, bug fixing.

### Testing Criteria

- All features pass regression on 5 test devices (Android 9‑13, different OEMs).
- No crash, all data verified by hashes.

---

## CRITICAL SYSTEM UPDATE — Phase 2: Physical & Encryption Mastery

**Duration:** 6 months  
**Goal:** Become a physical acquisition and decryption powerhouse.

### Deliverables

1. **Qualcomm EDL production** — 50+ devices validated.
2. **MediaTek BROM production** — 10+ devices validated.
3. **Samsung Download Mode production** — Exynos & Qualcomm.
4. **FDE / FBE brute‑force engine** — GPU‑accelerated.
5. **Keystore extraction** (software + hardware).
6. **Full rooted acquisition** — `/data/data` copy + parsers for 20+ apps.

### Steps

- **Month 1‑2:** Qualcomm EDL — collect programmers, test, fix issues.
- **Month 2‑3:** MediaTek BROM — similar.
- **Month 3‑4:** Samsung Download Mode.
- **Month 4‑5:** Brute‑force engine integration (Hashcat GPU).
- **Month 5‑6:** Keystore extraction, integration with decryption.

### Testing Criteria

- Physical image acquired from 10 devices (different SoCs).
- Passcode recovered within reasonable time.
- Decrypted data matches logical acquisition.

---

## CRITICAL SYSTEM UPDATE — Phase 3: Full Oxygen Parity

**Duration:** 6‑12 months  
**Goal:** Advanced analysis, timeline, and reporting.

### Deliverables

1. **Activity Matrix & cross‑app timeline.**
2. **Relationship graphs & link analysis.**
3. **Facial recognition & OCR.**
4. **Cloud acquisition for Google Photos, Gmail, Maps.**
5. **Court‑ready reporting with digital signatures.**
6. **Cross‑case search.**
7. **Anomaly detection.**

### Steps

- **Month 1‑2:** Unified timeline and Activity Matrix.
- **Month 3‑4:** Graph visualisation.
- **Month 5‑6:** Facial recognition & OCR.
- **Month 7‑8:** Cloud acquisitions (APIs).
- **Month 9‑10:** Reporting enhancements.
- **Month 11‑12:** Cross‑case search and anomaly detection.

### Testing Criteria

- All features work on a large dataset (simulated case).
- Reports meet legal admissibility standards.

---

## RESOURCE ESTIMATES & PRIORITISATION

| Phase | Duration | Team Size | Key Skills |
|-------|----------|-----------|------------|
| Phase 0 | 2 weeks | 2 devs | Python, ADB, testing |
| Phase 1 | 3 months | 3 devs | Security research, Android reverse engineering |
| Phase 2 | 6 months | 4 devs | Hardware protocols, encryption, GPU programming |
| Phase 3 | 6‑12 months | 3 devs | ML, data visualisation, API integrations |

**Total:** ~15‑23 months to full Oxygen parity, with a team of 4‑5 engineers.

---

## APPENDIX: Source Code Inventory & Validation Criteria

### Existing Code (to be enhanced)

| File | Purpose | Enhancement |
|------|---------|-------------|
| `forensic/src/forensix_forensic/android_artifacts/` | Logical acquisition | Add calendar, accounts, etc. |
| `extractors/apk_downgrade.py` | Downgrade profiles | Expand to 46, make production |
| `extractors/agent_apk/` | Android Agent | Add more app collectors |
| `extractors/signal_rooted.py` | Signal parser | Enhance for deleted data |
| `extractors/telegram_rooted.py` | Telegram parser | Enhance |
| `extractors/whatsapp_downgrade.py` | WhatsApp decryption | Use extracted keys |
| `extractors/sqlite_carver.py` | WAL/freelist carving | Productionise, add confidence |
| `acquisitions/qualcomm_edl.py` | EDL handler | Make production‑ready |
| `acquisitions/mtk_brom.py` | MTK handler | Make production‑ready |
| `screen_lock_bypass.py` | Lock bypass | Integrate vectors |
| `hashcat_launcher.py` | Hashcat integration | Expand to brute force engine |
| `server/src/forensix_server/` | Case management | Add cross‑case, reporting enhancements |

### Validation Criteria for Each Feature

- **APK downgrade:** Success rate ≥ 95% on 20 test devices.
- **Agent:** Collects all expected data and verifies hashes.
- **Exploit FS:** Image matches logical acquisition.
- **Physical:** Acquired image passes `fsck` and mounts correctly.
- **Decryption:** Recovered password unlocks device; extracted keys decrypt app DBs.
- **Deleted data:** Recovered rows pass manual verification.
- **Timeline:** All events sorted and displayed correctly.
- **Reports:** Contains all required sections, signatures verified.

---

## Final Note

This plan is **comprehensive and actionable**. Each gap is mapped to concrete engineering tasks with clear success criteria. Execution requires dedicated resources, device access, and rigorous testing. With this roadmap, ForensiX can achieve Oxygen‑level forensic capability for Android — both non‑rooted and rooted — and become a serious contender in the digital forensics market.

<!-- 
========================================================================
END OF ACADEMIC EVALUATION OBJECT
========================================================================
-->