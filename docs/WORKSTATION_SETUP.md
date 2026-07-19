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
