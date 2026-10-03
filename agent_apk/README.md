# ForensiX Android agent

The existing Java agent now supports a user-mediated collection path with **no ADB or USB debugging** after the APK is installed normally. Open the app on the device, tap **Start collection**, grant contacts/SMS/call-log access, wait for the foreground collection to finish, then tap **Export collection bundle** and choose a destination in Android's system file picker. Transfer the `.fxz` file by a method the user controls and import it on the desktop:

```powershell
py scripts/import-agent-bundle.py C:\path\collection.fxz --case-id CASE-001 --output-dir C:\path\imports
```

The importer validates the expected files, size bounds, ZIP integrity, and SHA-256 entries before creating a collection directory. Denied sources are marked as partial. These hashes establish **bundle consistency, not device authenticity**. The exported bundle contains unencrypted personal data. Handle and retain it under the case's evidence policy.

For a case already created in the local ForensiX backend, upload the same file to the authenticated `POST /api/v1/cases/{case_id}/evidence-sources/import/agent-bundle` endpoint as a multipart `source` file, with the normal session cookie and `X-CSRF-Token` header. The backend validates the bundle, seals the original `.fxz` bytes in the evidence vault as a **logical** source, and returns the vault SHA-256, collection ID, counts, and per-source status. The summary remains available at `GET /api/v1/cases/{case_id}/evidence-sources/{source_id}/agent-bundle-summary`. After creating a working copy, run the native parser `android.agent_bundle.v1` to index contacts, SMS, calls, installed apps, device metadata, and accessible app artifacts into searchable case artifacts, timeline events, custody history, and reports.

The existing ADB installer/collector remains available as an explicitly selected **legacy** path. It writes to `/sdcard/forensix_out` and is unsuitable for production evidence handling; newer Android storage rules can also make that path fail. The default in-app path writes to app-private storage and uses SAF export.

## Build

Open `agent_apk/forensix_agent` in Android Studio or run `gradlew.bat assembleDebug` there with a JDK and Android SDK installed. The project uses Android Gradle Plugin 8.13.2 and compile SDK 36.1. The debug build passed on this workspace and produces `app/build/outputs/apk/debug/app-debug.apk`; on-device collection/export verification is still required. Use a controlled release signing key; the debug APK is only for lab testing.

## Scope

The current agent collects contacts, SMS, call logs, visible installed-app metadata, device metadata, MediaStore image/video/audio/download entries, and an opportunistic list of accessible shared-storage artifact names. MediaStore and readable file entries include SHA-256 where Android grants a readable stream. Android permissions and storage boundaries can limit or deny any source. It does not access other apps' private databases, system-wide logs, or screen content. No Device Owner enrollment, silent permission grants, remote upload, or certificate pinning is implemented. See [the audit](../docs/security-audit-2026-09-27.md) and [the pasted-design review](../docs/no-adb-agent-review-2026-09-27.md).
