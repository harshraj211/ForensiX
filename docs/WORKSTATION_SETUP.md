# ForensiX workstation setup

ForensiX is a loopback-only workstation application. Use controlled test devices until the
validation matrix has been signed off. ADB is not a hardware write blocker.

## Windows

1. Install Python 3.12, Node 22, pnpm 11, and Android SDK Platform-Tools.
2. Install the phone manufacturer's USB driver if Windows Device Manager does not expose an ADB
   interface. Google devices can use the Google USB driver; other OEMs commonly require their own.
3. Enable Developer options and USB debugging on the controlled phone, connect a data-capable USB
   cable, unlock the phone, and approve the workstation fingerprint.
4. Run the non-mutating workstation check:

   ```powershell
   .\scripts\Test-ForensiX.ps1 -AdbPath "C:\path\to\platform-tools\adb.exe"
   ```

5. Start both local services:

   ```powershell
   .\scripts\start-forensix.ps1 -AdbPath "C:\path\to\platform-tools\adb.exe"
   ```

### Optional live mirror and device control

ForensiX uses the official [Genymobile scrcpy release](https://github.com/Genymobile/scrcpy)
for a low-latency Android mirror or an explicitly authorized control window. Install the local
runtime once:

```powershell
.\scripts\install-scrcpy.ps1
```

The runtime is saved at `tools\scrcpy\scrcpy.exe`, which is intentionally ignored by Git. The
normal launcher discovers the executable, verifies its version, calculates a SHA-256 value, and
pins that value for the current server session. You may supply a different trusted executable:

```powershell
.\scripts\start-forensix.ps1 `
  -AdbPath "C:\path\to\platform-tools\adb.exe" `
  -ScrcpyPath "C:\trusted-tools\scrcpy\scrcpy.exe"
```

In a case-linked device assessment, tick the live-screen acknowledgement and use **Read-only
mirror** first. It starts a separate scrcpy window with input injection disabled. **Interactive
control** is a distinct, audited action: taps and keyboard input alter the device and are never
forensically read-only. Website preview frames are temporary; use **Capture evidence screenshot**
when a particular frame must be sealed as case evidence.

### Optional experimental TestDisk/PhotoRec recovery

ForensiX does not bundle TestDisk or PhotoRec. Install the official portable CGSecurity release
locally when a lawful, verified raw image needs experimental file carving:

```powershell
.\scripts\install-testdisk.ps1
```

This puts `photorec_win.exe` under `tools\testdisk`, which Git ignores. The normal launcher
computes and pins its SHA-256 for that local session. To use a separately managed installation:

```powershell
.\scripts\start-forensix.ps1 `
  -AdbPath "C:\path\to\platform-tools\adb.exe" `
  -PhotoRecPath "C:\trusted-tools\testdisk\photorec_win.exe"
```

Only the **Evidence Twin** page can invoke it, and only after the source has been sealed, a
working copy has passed hash verification, and inspection identifies a raw `ext4` or `F2FS`
image. It never receives a live Android-device path or a sealed master. Output is saved in the
case-controlled recovery workspace, hashed, audited, and displayed as **candidate material**.
PhotoRec may not retain original names or directory structure; encryption, overwrite, and flash
wear-leveling can prevent useful results.

## Linux

Install Platform-Tools and configure the distribution's Android udev rules. Confirm the current
user has USB-device access, then run:

```bash
FORENSIX_ADB_PATH=/path/to/adb ./scripts/start-forensix.sh
```

## macOS

Install Platform-Tools, remove quarantine only through your organization's approved process, and
run the same POSIX launcher. For Apple Silicon, all Python and Node native dependencies must match
the host architecture.

## Interpreting diagnostics

- `missing`: the configured executable and standard SDK path were not found.
- `execution failed`: ADB exists but its bounded version/device check failed.
- `no transports`: ADB works, but the host sees no Android transport. This does not prove USB
  debugging is disabled; check the cable, USB mode, driver/udev permission, and port.
- `authorization required`: unlock the phone and approve the displayed RSA fingerprint.
- `offline`: reconnect, then use `adb kill-server` followed by `adb start-server`.
- `healthy`: at least one authorized transport is ready for ForensiX capability assessment.

Runtime stdout/stderr is written under `data/logs`. These operational logs are not evidence or an
audit substitute and must not contain evidence content.
