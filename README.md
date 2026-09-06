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

> 🧾 **ForensiX is a controlled logical triage workstation.** The UI and reports identify what was supported, blocked, or unavailable for the connected device instead of presenting unsupported extraction as completed evidence.

📘 See the [technical repository document](TECHNICAL_REPOSITORY.md) for the complete source map, architecture, API route families, database schema, dependencies, deployment instructions, and validation process.

---

## 📥 Downloads

<div align="center">

[![Windows](https://img.shields.io/badge/⬇_Windows-Portable_ZIP-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-Windows-Portable.zip)
[![Linux](https://img.shields.io/badge/⬇_Linux-Portable_ZIP-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-Linux-Portable.zip)
[![macOS](https://img.shields.io/badge/⬇_macOS-Portable_ZIP-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-macOS-Portable.zip)

</div>

Extract the ZIP to a trusted local folder and run the `ForensiX` executable (`ForensiX.exe` on Windows). The application starts its loopback backend and bundled web interface automatically and opens the workstation in its own desktop window. **No public hosting or internet connection is required after download.**

---

## ✨ Features

### ⚡ Physical Acquisition
*   **Protocol Handlers:** Qualcomm EDL (Sahara/Firehose), MediaTek (MTK) BROM Bypass, Unisoc/Spreadtrum BootROM, Samsung Download Mode (Odin/LOKE), Huawei Kirin/HiSilicon, and Rockchip DFU.
*   **Auto-Routing:** Automatically detects USB VID/PID and routes connected devices to the matching hardware module.

### 📱 Next-Gen Non-Rooted Extraction
*   **Android 15 Private Space:** Detects hidden isolated secondary profiles and triages hidden target applications over ADB.
*   **Encrypted WhatsApp Backups:** Decrypts modern WhatsApp Crypt14/15/16/17 offline using AES-256-GCM and HKDF-SHA256 key derivation.
*   **Automated APK Downgrade:** Rollback attacks for 29+ target app profiles to extract application sandboxes without root.

### 🧠 Deep Forensic Intelligence (AI)
*   **AI Vision OCR Recorder:** `scrcpy` live stream integration with AI OCR for automatic scrolling and transcription of disappearing chats.
*   **Timeline Anomaly & Alibi Analysis:** Statistical anomaly detection across SMS and WhatsApp to flag suspicious chat silences, midnight bursts, and EXIF spoofing.
*   **Cloud Token Replay:** Extracts Google, Samsung, and Telegram OAuth/Session tokens to download cloud evidence without passwords.

### 🔐 Passcode Assessment & Decryption
*   **Lock Bypass Engine:** Forensic lock bypass via `locksettings.db` key clearing, Gatekeeper key removal, and RAM disk patching.
*   **Hardware KeyStore Vault Unlocker:** Rooted device derivation of TEE hardware-bound master keys for Signal and ProtonMail.
*   **Offline Hashcat Integration:** Extracts Gatekeeper enrolled hashes and synthetic password blobs for offline cracking.

### 📋 Case Management & Chain of Custody
*   **RBAC & Authentication:** Local administrator bootstrap, Argon2id credentials, and explicit permissions.
*   **Auditability:** Immutable capability snapshots, durable versioned job states, and append-only evidence re-verification.
*   **Detached Signatures:** RSA/ECDSA checkpoint-signature verification against X.509 certificates for undeniable chain of custody.

---

## 🚀 Local Setup (Development)

**Requirements:** Node.js 24+, pnpm 11+, Python 3.12+

1. **Install Frontend Dependencies:**
   ```powershell
   pnpm install
   ```
2. **Create Python Environment:**
   ```powershell
   uv venv
   uv pip install -r requirements-dev.txt
   ```
3. **Run API (Mock Mode):**
   ```powershell
   $env:FORENSIX_ADB_MODE = "mock"
   $env:FORENSIX_MOCK_ADB_SCENARIO = "authorized"
   uv run uvicorn forensix_api.main:app --host 127.0.0.1 --port 8765
   ```
4. **Run Web Interface (Separate Terminal):**
   ```powershell
   pnpm dev
   ```

For a real ADB device test on Windows, use the bundled startup script:
```powershell
.\scripts\start-forensix.ps1 -AdbPath "C:\platform-tools\adb.exe"
```

---

## 🔒 Security and Evidence Handling

ForensiX is designed for strict evidentiary integrity:
- **No Arbitrary Shell Execution:** The backend exposes no arbitrary ADB shell operation and accepts no command text from the browser.
- **Controlled Acquisition:** Transfers use shell-free `adb pull` with strict size ceilings, partial file streaming, and streaming SHA-256 verification.
- **Process Isolation:** Image thumbnails are re-encoded and metadata-stripped; original evidence content is never served directly to the browser.
- **Tamper-Evident Logs:** Custody actions and evidence registration events are chained in an append-only, tamper-evident audit ledger with genesis hashing.

---

<div align="center">
Built for controlled, auditable, and explainable Android evidence triage. 🔎
</div>
