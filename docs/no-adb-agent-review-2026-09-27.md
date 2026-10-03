# Review of the pasted no-ADB agent design

The 33 KB attachment headed “ForensiX Agent — No-ADB Collection Agent (Complete Project)” ends midway through `InstalledAppsCollector.kt`. The remaining collectors, service, SAF export, upload, enrollment, DPC, tests, and backend are absent. It is a design sketch, not a complete buildable project. The integration in this repository therefore uses the existing Java agent and implements only the parts whose behavior can be checked locally.

## Integrated into the existing agent

- Default user-started collection stores JSON in app-private `files/collection` and writes a manifest with a UUID, sizes, and SHA-256 hashes.
- Contacts, SMS, and call logs have source-specific permission checks. Denied/unavailable sources are marked in the manifest and produce a partial import result.
- An explicit SAF `ACTION_CREATE_DOCUMENT` flow exports a ZIP `.fxz` bundle. The UI warns that it contains unencrypted personal data.
- A desktop importer validates the exact file set, bounded sizes, ZIP integrity, manifest format, UUID, and hashes before importing. The CLI does not call ADB.
- The former ADB path remains an explicit legacy mode and still uses shared staging. It should not be used as evidence of no-ADB compliance.

The bundle hash checks detect inconsistent/corrupt files, **not** an adversary who can edit both the manifest and contents. There is no device attestation, signed collection manifest, trusted enrollment key, or authenticated server upload. Raw JSON inside a user-exported ZIP is unencrypted; the user must choose a trusted destination. The importer is currently a local CLI and does not register the collection in the case database/evidence vault.

## Problems in the pasted design

| Area | Concrete problem | Required correction |
|---|---|---|
| Completeness | Attachment stops inside `InstalledAppsCollector.kt`; referenced files and tests are missing. | Supply actual source and tests before treating it as an implementation. |
| Export cryptography | AES-GCM key is generated in Android Keystore and is never exported or wrapped. The desktop/backend cannot decrypt `.json.gz.enc` files from a SAF bundle. | Define recipient key wrapping or a user-held export key, and test cross-device decryption and recovery. |
| Keystore usage | The example supplies its own IV while requesting randomized encryption from Android Keystore; provider behavior must be verified on devices. | Let the provider generate the encryption IV and record `Cipher.getIV()`, or prove the selected provider accepts the design. |
| Atomic storage | `writeAtomic` deletes the old target before rename and falls back to writing the final path. A crash can lose both versions or leave a partial file. | Write and sync a temporary file, rename within one directory, sync metadata where supported, and retain the previous complete version until commit. |
| TLS | `collect.yourlab.test` and `AAAA...` pins are placeholders; the XML pin expires and has no backup pin/rotation plan. | Configure a real endpoint and authenticated enrollment, maintain backup pins, exercise rotation and failure tests. |
| DPC authority | Common manifest includes Device Admin components and password/wipe policies for both flavors, including the sideload flavor. Those powers are not required for evidence collection. | Separate DPC manifest by flavor, request only justified policies, and enroll through supported enterprise provisioning. |
| Package visibility | The `<queries>` element exposes launcher apps, not a complete installed-package inventory. Being Device Owner alone does not make `QUERY_ALL_PACKAGES` appear. | Label the result as a visible subset unless an explicitly justified and permitted broader inventory is actually available. |
| Permission gate | One global required-permission list blocks device metadata if SMS, call log, or location is denied. Background location is requested without an implemented need. | Gate each source independently and record denied/partial results. Request background location only for a defined background feature. |
| Collector reliability | The sample uses `LIMIT 5000` in provider sort order and treats `query()==null` as a successful empty result. Provider support varies. | Page through provider results with supported APIs, cap records explicitly, and report null/error as partial or failed. |
| Audit log | `SimpleDateFormat` appends `Z` while using the device's default timezone. | Set UTC explicitly or use a UTC-aware formatter. |
| Boot behavior | A boot receiver and worker are listed without a consent and collection policy. | Restore scheduling state only; never silently start sensitive collection on boot. |

These issues are source/design observations, not device exploit claims. In particular, no DPC provisioning, certificate-pinning, or upload implementation from the attachment was copied into ForensiX.

## Remaining acceptance tests

1. Run the successfully built debug APK on API 26, 28, 30, 33, 34, and 36 devices/emulators with developer options and ADB authorization off for the actual collection/export path.
2. Deny and revoke each permission independently; confirm that the UI and bundle report the missing source rather than a complete empty result.
3. Export a bundle through local and cloud SAF providers, import it on a separate computer, and verify source counts and hashes.
4. Tamper with an entry, add a path-traversal entry, duplicate a filename, and exceed size limits; the importer must reject the bundle without creating an imported collection.
5. Add authenticated provenance (device key/enrollment or signed manifest), encrypted transport/storage, evidence-vault integration, and a real retention policy before remote or unattended use.

Android's [Storage Access Framework](https://developer.android.com/training/data-storage/shared/documents-files) supports the user-selected export route. [Android Enterprise network logging](https://developer.android.com/work/dpc/logging) documents capabilities available only to properly enrolled device/profile owners. The supported [Android 16 QPR2 build configuration](https://developer.android.com/about/versions/16/qpr2/setup-sdk) requires Android Gradle Plugin 8.13+ for compile SDK 36.1.
