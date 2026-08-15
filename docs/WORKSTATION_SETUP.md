# Windows Workstation Setup

ForensiX is a local workstation application. The browser is only the user interface; the API, SQLite database, evidence vault, ADB transport, and optional scrcpy integration run on the same Windows machine.

## Portable application

1. Download the latest [Windows portable build](https://github.com/harshraj211/ForensiX/releases/latest/download/ForensiX-Windows-Portable.zip).
2. Verify the archive checksum against `ForensiX-Windows-Portable.zip.sha256`.
3. Extract the ZIP into a trusted folder such as `C:\ForensiX`.
4. Run `ForensiX.exe`.

The application starts its local services automatically, binds to `127.0.0.1`, opens the browser, and keeps persistent application data under `%LOCALAPPDATA%\ForensiX`. Do not expose the loopback port through a reverse proxy or firewall rule.

## ADB and USB connection

Install Android SDK Platform-Tools from the official Android developer distribution and install the OEM USB driver when Windows does not recognize the device. Confirm that these commands work in PowerShell:

```powershell
adb version
adb devices -l
```

If `adb` is not on `PATH`, start the application with its full path:

```powershell
.\ForensiX.exe --adb-path "C:\platform-tools\adb.exe"
```

On the phone, enable Developer options and USB debugging. Keep the device unlocked while connecting it and accept the RSA authorization prompt. ForensiX should show an `authorized` transport before a case-linked assessment can continue.

## scrcpy mirror and control

The Windows portable release includes the official scrcpy runtime and configures its executable and SHA-256 automatically. For a source checkout, install the official Windows release and keep the complete extracted folder together:

```powershell
$env:FORENSIX_SCRCPY_PATH = "C:\tools\scrcpy\scrcpy.exe"
$env:FORENSIX_SCRCPY_EXPECTED_SHA256 = (Get-FileHash $env:FORENSIX_SCRCPY_PATH -Algorithm SHA256).Hash.ToLowerInvariant()
.\ForensiX.exe
```

scrcpy does not open at application startup because it must be attached to a selected case device and its control modes have device-side effects. Use **Read-only mirror** for passive viewing. Use **Interactive control** only after acknowledging that taps and typing modify device state. Use **Start documented session** when the displayed pixels and control actions must be sealed as an MP4 case record. A screenshot capture does not require scrcpy.

## First-run workflow

1. Launch `ForensiX.exe`.
2. Create the local administrator account when prompted.
3. Open **Device readiness** and detect the connected transport.
4. Create a case and link the authorized device.
5. Run capability assessment and root-status verification.
6. Use only the providers and acquisition modes marked supported for that device.
7. Review evidence thumbnails, hashes, and chain-of-custody events.
8. Generate reports and download the case-specific audit log from the Reports page.

## Data and backups

Application data is stored in `%LOCALAPPDATA%\ForensiX` by default. This includes the SQLite database, evidence vault, logs, generated reports, and screen recordings. Store the directory on an encrypted workstation volume and include it in the case backup process. Do not delete it while an investigation is active.

## Troubleshooting

- **ADB not found:** install Platform-Tools, add its directory to `PATH`, or use `--adb-path`.
- **Device unauthorized:** unlock the phone, reconnect USB, and accept the RSA prompt.
- **No device shown:** verify the cable, USB mode, OEM driver, and `adb devices -l` output.
- **scrcpy unavailable:** on the Windows portable build, re-extract the ZIP after unblocking it in Windows file properties; for a source checkout, configure `FORENSIX_SCRCPY_PATH` and its SHA-256, then restart ForensiX.
- **Browser does not open:** browse to `http://127.0.0.1:8765` and inspect `%LOCALAPPDATA%\ForensiX\logs`.
- **Port already in use:** stop the existing ForensiX process or start the executable with another port, for example `ForensiX.exe --port 8876`.

Forensic limitations remain explicit: ADB is not a hardware write blocker, ordinary non-rooted ADB does not provide unrestricted private application data, and device-side effects must be reviewed in the case record.
