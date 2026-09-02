# ForensiX Android Agent APK

Minimal Android application for unrooted logical data collection.

## Purpose
Collects SMS, Contacts, Call Logs, and Installed Application lists via standard Android APIs (`ContentResolver`), serializes them to JSON files in `/sdcard/forensix_out/`, and signals completion.

## Build Instructions
1. Open `agent_apk/forensix_agent` in Android Studio or run `./gradlew assembleDebug`.
2. Output APK location: `app/build/outputs/apk/debug/app-debug.apk`.
3. Copy the compiled APK to `forensic/src/forensix_forensic/extractors/agent_apk/forensix_agent.apk`.

## Permissions
* `READ_CONTACTS`: Reads contact names and numbers.
* `READ_SMS`: Reads SMS messages and threads.
* `READ_CALL_LOG`: Reads call history.
* `READ_EXTERNAL_STORAGE`: Staging output directory creation.
