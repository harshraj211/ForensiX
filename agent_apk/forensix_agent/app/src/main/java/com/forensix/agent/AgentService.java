package com.forensix.agent;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.ContentUris;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.net.Uri;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.IBinder;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.MediaStore;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import androidx.core.app.NotificationCompat;
import androidx.documentfile.provider.DocumentFile;

import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class AgentService extends Service {

    private static final String CHANNEL_ID = "forensix_channel";
    private static final int NOTIF_ID = 1001;
    private static final String STAGING_DIR = "/sdcard/forensix_out";
    static final String[] OUTPUT_FILES = {
            "contacts.json", "sms.json", "call_logs.json", "installed_apps.json",
            "device_metadata.json", "app_artifacts.json", "wifi_state.json",
            "bluetooth_devices.json", "sim_metadata.json"
    };
    private File outputDir;
    private final Map<String, String> sourceStatus = new HashMap<>();

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean collecting = new AtomicBoolean(false);

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.notif_title))
                .setContentText(getString(R.string.notif_text))
                .setSmallIcon(android.R.drawable.ic_menu_save)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();

        startForeground(NOTIF_ID, notification);

        if (collecting.compareAndSet(false, true)) {
            final boolean legacyAdb = intent != null && intent.getBooleanExtra("legacy_adb", false);
            executor.execute(() -> runExtraction(legacyAdb));
        }

        return START_NOT_STICKY;
    }

    private void runExtraction(boolean legacyAdb) {
        try {
            outputDir = legacyAdb ? new File(STAGING_DIR) : privateCollectionDir();
            sourceStatus.clear();
            if (!outputDir.exists() && !outputDir.mkdirs()) {
                throw new IllegalStateException("Cannot create collection directory");
            }
            for (String name : OUTPUT_FILES) {
                File old = new File(outputDir, name);
                if (old.exists() && !old.delete()) {
                    throw new IllegalStateException("Cannot clear previous collection file");
                }
            }
            File doneFile = new File(outputDir, "DONE");
            if (doneFile.exists() && !doneFile.delete())
                throw new IllegalStateException("Cannot clear previous collection marker");
            File manifestFile = new File(outputDir, "manifest.json");
            if (manifestFile.exists() && !manifestFile.delete())
                throw new IllegalStateException("Cannot clear previous manifest");

            extractContacts();
            extractSms();
            extractCallLog();
            extractInstalledApps();
            extractDeviceMetadata();
            extractAccessibleAppArtifacts();
            extractWifiState();
            extractBondedBluetoothDevices();
            extractSimMetadata();

            writeManifest(legacyAdb);

            // Write DONE marker
            try (FileOutputStream fos = new FileOutputStream(doneFile)) {
                String doneContent = "COMPLETED_AT=" + System.currentTimeMillis();
                fos.write(doneContent.getBytes(StandardCharsets.UTF_8));
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            collecting.set(false);
            stopSelf();
        }
    }

    private void extractWifiState() {
        JSONArray records = new JSONArray();
        try {
            WifiManager manager = (WifiManager) getApplicationContext()
                    .getSystemService(WIFI_SERVICE);
            if (manager == null) {
                sourceStatus.put("wifi_state.json", "provider_unavailable");
                writeToFile("wifi_state.json", records.toString());
                return;
            }
            JSONObject record = new JSONObject();
            record.put("wifi_enabled", manager.isWifiEnabled());
            WifiInfo info = manager.getConnectionInfo();
            if (info == null) {
                sourceStatus.put("wifi_state.json", "provider_unavailable");
            } else {
                String ssid = info.getSSID();
                String bssid = info.getBSSID();
                boolean locationLimited = WifiManager.UNKNOWN_SSID.equals(ssid)
                        || "02:00:00:00:00:00".equals(bssid);
                record.put("ssid", WifiManager.UNKNOWN_SSID.equals(ssid) ? JSONObject.NULL : ssid.replace("\"", ""));
                record.put("bssid", "02:00:00:00:00:00".equals(bssid) ? JSONObject.NULL : bssid);
                record.put("rssi_dbm", info.getRssi());
                record.put("link_speed_mbps", info.getLinkSpeed());
                record.put("frequency_mhz", Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP
                        ? info.getFrequency() : JSONObject.NULL);
                record.put("network_id", info.getNetworkId());
                record.put("connected", info.getNetworkId() != -1);
                if (locationLimited) sourceStatus.put("wifi_state.json", "visibility_limited");
            }
            records.put(record);
        } catch (SecurityException e) {
            sourceStatus.put("wifi_state.json", "permission_denied");
        } catch (Exception e) {
            sourceStatus.put("wifi_state.json", "partial_error");
        }
        writeToFile("wifi_state.json", records.toString());
    }

    private void extractBondedBluetoothDevices() {
        JSONArray records = new JSONArray();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                && checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) {
            sourceStatus.put("bluetooth_devices.json", "permission_denied");
            writeToFile("bluetooth_devices.json", records.toString());
            return;
        }
        try {
            BluetoothManager manager = getSystemService(BluetoothManager.class);
            BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
            if (adapter == null) {
                sourceStatus.put("bluetooth_devices.json", "provider_unavailable");
            } else if (!adapter.isEnabled()) {
                sourceStatus.put("bluetooth_devices.json", "visibility_limited");
            } else {
                for (BluetoothDevice device : adapter.getBondedDevices()) {
                    JSONObject record = new JSONObject();
                    record.put("name", device.getName() == null ? JSONObject.NULL : device.getName());
                    record.put("address", device.getAddress());
                    record.put("bond_state", device.getBondState());
                    record.put("device_type", device.getType());
                    record.put("bluetooth_class", device.getBluetoothClass() == null
                            ? JSONObject.NULL : device.getBluetoothClass().getDeviceClass());
                    records.put(record);
                }
            }
        } catch (SecurityException e) {
            sourceStatus.put("bluetooth_devices.json", "permission_denied");
        } catch (Exception e) {
            sourceStatus.put("bluetooth_devices.json", "partial_error");
        }
        writeToFile("bluetooth_devices.json", records.toString());
    }

    private void extractSimMetadata() {
        JSONArray records = new JSONArray();
        if (checkSelfPermission(Manifest.permission.READ_PHONE_STATE)
                != PackageManager.PERMISSION_GRANTED) {
            sourceStatus.put("sim_metadata.json", "permission_denied");
            writeToFile("sim_metadata.json", records.toString());
            return;
        }
        try {
            SubscriptionManager manager = getSystemService(SubscriptionManager.class);
            if (manager == null) {
                sourceStatus.put("sim_metadata.json", "provider_unavailable");
            } else {
                List<SubscriptionInfo> subscriptions = manager.getActiveSubscriptionInfoList();
                if (subscriptions == null) {
                    sourceStatus.put("sim_metadata.json", "visibility_limited");
                } else {
                    for (SubscriptionInfo subscription : subscriptions) {
                        JSONObject record = new JSONObject();
                        record.put("subscription_id", subscription.getSubscriptionId());
                        record.put("slot_index", subscription.getSimSlotIndex());
                        record.put("carrier_name", subscription.getCarrierName() == null
                                ? JSONObject.NULL : subscription.getCarrierName().toString());
                        record.put("display_name", subscription.getDisplayName() == null
                                ? JSONObject.NULL : subscription.getDisplayName().toString());
                        record.put("mcc", subscription.getMcc());
                        record.put("mnc", subscription.getMnc());
                        record.put("country_iso", subscription.getCountryIso());
                        record.put("iccid", subscription.getIccId() == null
                                ? JSONObject.NULL : subscription.getIccId());
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            record.put("carrier_id", subscription.getCarrierId());
                        }
                        records.put(record);
                    }
                }
            }
        } catch (SecurityException e) {
            sourceStatus.put("sim_metadata.json", "permission_denied");
        } catch (Exception e) {
            sourceStatus.put("sim_metadata.json", "partial_error");
        }
        writeToFile("sim_metadata.json", records.toString());
    }

    private void extractContacts() {
        if (checkSelfPermission(Manifest.permission.READ_CONTACTS) != PackageManager.PERMISSION_GRANTED) {
            sourceStatus.put("contacts.json", "permission_denied");
            writeToFile("contacts.json", "[]");
            return;
        }
        JSONArray arr = new JSONArray();
        ContentResolver cr = getContentResolver();
        Cursor cursor = cr.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                null, null, null, null);

        if (cursor != null) {
            try {
                int nameIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME);
                int numIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER);

                while (cursor.moveToNext()) {
                    JSONObject obj = new JSONObject();
                    String name = nameIdx != -1 ? cursor.getString(nameIdx) : "";
                    String num = numIdx != -1 ? cursor.getString(numIdx) : "";

                    obj.put("name", name);
                    JSONArray nums = new JSONArray();
                    nums.put(num);
                    obj.put("phone_numbers", nums);
                    obj.put("emails", new JSONArray());
                    obj.put("account_type", "phone");

                    arr.put(obj);
                }
            } catch (Exception e) {
                sourceStatus.put("contacts.json", "partial_error");
                e.printStackTrace();
            } finally {
                cursor.close();
            }
        } else {
            sourceStatus.put("contacts.json", "provider_unavailable");
        }
        writeToFile("contacts.json", arr.toString());
    }

    private void extractSms() {
        if (checkSelfPermission(Manifest.permission.READ_SMS) != PackageManager.PERMISSION_GRANTED) {
            sourceStatus.put("sms.json", "permission_denied");
            writeToFile("sms.json", "[]");
            return;
        }
        JSONArray arr = new JSONArray();
        ContentResolver cr = getContentResolver();
        Cursor cursor = cr.query(Uri.parse("content://sms"), null, null, null, null);

        if (cursor != null) {
            try {
                int addrIdx = cursor.getColumnIndex("address");
                int bodyIdx = cursor.getColumnIndex("body");
                int dateIdx = cursor.getColumnIndex("date");
                int typeIdx = cursor.getColumnIndex("type");
                int threadIdx = cursor.getColumnIndex("thread_id");

                while (cursor.moveToNext()) {
                    JSONObject obj = new JSONObject();
                    obj.put("address", addrIdx != -1 ? cursor.getString(addrIdx) : "");
                    obj.put("body", bodyIdx != -1 ? cursor.getString(bodyIdx) : "");
                    obj.put("date_ms", dateIdx != -1 ? cursor.getLong(dateIdx) : 0);
                    obj.put("type", typeIdx != -1 ? cursor.getInt(typeIdx) : 1);
                    obj.put("thread_id", threadIdx != -1 ? cursor.getInt(threadIdx) : 0);

                    arr.put(obj);
                }
            } catch (Exception e) {
                sourceStatus.put("sms.json", "partial_error");
                e.printStackTrace();
            } finally {
                cursor.close();
            }
        } else {
            sourceStatus.put("sms.json", "provider_unavailable");
        }
        writeToFile("sms.json", arr.toString());
    }

    private void extractCallLog() {
        if (checkSelfPermission(Manifest.permission.READ_CALL_LOG) != PackageManager.PERMISSION_GRANTED) {
            sourceStatus.put("call_logs.json", "permission_denied");
            writeToFile("call_logs.json", "[]");
            return;
        }
        JSONArray arr = new JSONArray();
        ContentResolver cr = getContentResolver();
        Cursor cursor = cr.query(CallLog.Calls.CONTENT_URI, null, null, null, null);

        if (cursor != null) {
            try {
                int numIdx = cursor.getColumnIndex(CallLog.Calls.NUMBER);
                int typeIdx = cursor.getColumnIndex(CallLog.Calls.TYPE);
                int dateIdx = cursor.getColumnIndex(CallLog.Calls.DATE);
                int durIdx = cursor.getColumnIndex(CallLog.Calls.DURATION);
                int nameIdx = cursor.getColumnIndex(CallLog.Calls.CACHED_NAME);

                while (cursor.moveToNext()) {
                    JSONObject obj = new JSONObject();
                    obj.put("number", numIdx != -1 ? cursor.getString(numIdx) : "");
                    obj.put("type", typeIdx != -1 ? cursor.getInt(typeIdx) : 1);
                    obj.put("date_ms", dateIdx != -1 ? cursor.getLong(dateIdx) : 0);
                    obj.put("duration_seconds", durIdx != -1 ? cursor.getInt(durIdx) : 0);
                    obj.put("name", nameIdx != -1 ? cursor.getString(nameIdx) : null);

                    arr.put(obj);
                }
            } catch (Exception e) {
                sourceStatus.put("call_logs.json", "partial_error");
                e.printStackTrace();
            } finally {
                cursor.close();
            }
        } else {
            sourceStatus.put("call_logs.json", "provider_unavailable");
        }
        writeToFile("call_logs.json", arr.toString());
    }

    private void extractInstalledApps() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            sourceStatus.put("installed_apps.json", "visibility_limited");
        }
        JSONArray arr = new JSONArray();
        PackageManager pm = getPackageManager();
        List<PackageInfo> packages;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packages = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(
                        PackageManager.GET_PERMISSIONS | PackageManager.GET_META_DATA));
            } else {
                packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS | PackageManager.GET_META_DATA);
            }
        } catch (Exception e) {
            packages = pm.getInstalledPackages(0);
        }

        try {
            for (PackageInfo pi : packages) {
                JSONObject obj = new JSONObject();
                obj.put("package_name", pi.packageName);
                obj.put("app_label", pi.applicationInfo != null ? pi.applicationInfo.loadLabel(pm).toString() : pi.packageName);
                obj.put("version_name", pi.versionName != null ? pi.versionName : "");

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    obj.put("version_code", pi.getLongVersionCode());
                } else {
                    obj.put("version_code", pi.versionCode);
                }

                obj.put("install_time_ms", pi.firstInstallTime);
                obj.put("last_update_time_ms", pi.lastUpdateTime);

                if (pi.applicationInfo != null) {
                    obj.put("uid", pi.applicationInfo.uid);
                    obj.put("target_sdk", pi.applicationInfo.targetSdkVersion);

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        obj.put("min_sdk", pi.applicationInfo.minSdkVersion);
                    } else {
                        obj.put("min_sdk", -1);
                    }

                    boolean isSystem = (pi.applicationInfo.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0;
                    boolean isDebuggable = (pi.applicationInfo.flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                    boolean allowBackup = (pi.applicationInfo.flags & android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;

                    obj.put("is_system", isSystem);
                    obj.put("is_enabled", pi.applicationInfo.enabled);
                    obj.put("is_debuggable", isDebuggable);
                    obj.put("allow_backup", allowBackup);
                    obj.put("source_dir", pi.applicationInfo.sourceDir != null ? pi.applicationInfo.sourceDir : "");
                } else {
                    obj.put("uid", -1);
                    obj.put("target_sdk", -1);
                    obj.put("min_sdk", -1);
                    obj.put("is_system", false);
                    obj.put("is_enabled", true);
                    obj.put("is_debuggable", false);
                    obj.put("allow_backup", false);
                    obj.put("source_dir", "");
                }

                try {
                    String installer = pm.getInstallerPackageName(pi.packageName);
                    obj.put("installer_package", installer != null ? installer : "");
                } catch (Exception e) {
                    obj.put("installer_package", "");
                }

                // Requested & Granted permissions
                JSONArray reqPermsArr = new JSONArray();
                JSONArray grantedPermsArr = new JSONArray();
                if (pi.requestedPermissions != null) {
                    for (int i = 0; i < pi.requestedPermissions.length; i++) {
                        String perm = pi.requestedPermissions[i];
                        reqPermsArr.put(perm);
                        if (pi.requestedPermissionsFlags != null && i < pi.requestedPermissionsFlags.length) {
                            if ((pi.requestedPermissionsFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                                grantedPermsArr.put(perm);
                            }
                        }
                    }
                }
                obj.put("requested_permissions", reqPermsArr);
                obj.put("granted_permissions", grantedPermsArr);

                // Capability Profile Surfaces for this App
                JSONObject surfaces = new JSONObject();
                surfaces.put("private_app_storage", "restricted");
                surfaces.put("shared_storage", "available");
                surfaces.put("media", "available");
                surfaces.put("app_export", "available");
                surfaces.put("system_api", "available");
                surfaces.put("ui_access", "not_configured");
                boolean canBackup = pi.applicationInfo != null && (pi.applicationInfo.flags & android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;
                surfaces.put("backup_surface", canBackup ? "available" : "disabled");
                surfaces.put("unknown", "none");

                obj.put("surfaces", surfaces);
                arr.put(obj);
            }
        } catch (Exception e) {
            sourceStatus.put("installed_apps.json", "partial_error");
            e.printStackTrace();
        }
        writeToFile("installed_apps.json", arr.toString());
    }

    private void extractAccessibleAppArtifacts() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            sourceStatus.put("app_artifacts.json", "storage_limited");
        }
        JSONArray arr = new JSONArray();
        Set<String> seen = new HashSet<>();
        try {
            collectMediaStoreArtifacts(arr, seen);
            collectSelectedDocumentTreeArtifacts(arr, seen);
            File sdcard = Environment.getExternalStorageDirectory();
            if (sdcard != null && sdcard.exists() && sdcard.canRead()) {
                scanDirectoryForArtifacts(sdcard, arr, seen, 0, 3);
            }
        } catch (Exception e) {
            sourceStatus.put("app_artifacts.json", "partial_error");
            e.printStackTrace();
        }
        writeToFile("app_artifacts.json", arr.toString());
    }

    private void collectMediaStoreArtifacts(JSONArray arr, Set<String> seen) {
        if (!hasSharedMediaPermission()) {
            sourceStatus.put("app_artifacts.json", "permission_denied");
            return;
        }
        queryMediaStore(arr, seen, MediaStore.Images.Media.EXTERNAL_CONTENT_URI, "media_image");
        queryMediaStore(arr, seen, MediaStore.Video.Media.EXTERNAL_CONTENT_URI, "media_video");
        queryMediaStore(arr, seen, MediaStore.Audio.Media.EXTERNAL_CONTENT_URI, "media_audio");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            queryMediaStore(arr, seen, MediaStore.Downloads.EXTERNAL_CONTENT_URI, "download");
        }
    }

    private void collectSelectedDocumentTreeArtifacts(JSONArray arr, Set<String> seen) {
        String rawTree = getSharedPreferences("forensix_agent", MODE_PRIVATE)
                .getString(MainActivity.PREF_DOCUMENT_TREE, "");
        if (rawTree == null || rawTree.isEmpty()) return;
        try {
            DocumentFile root = DocumentFile.fromTreeUri(this, Uri.parse(rawTree));
            if (root == null || !root.canRead()) {
                sourceStatus.put("app_artifacts.json", "permission_denied");
                return;
            }
            scanDocumentTree(root, "", arr, seen, 0, 4, 5000);
        } catch (Exception e) {
            sourceStatus.put("app_artifacts.json", "partial_error");
        }
    }

    private void scanDocumentTree(DocumentFile entry, String relativePath, JSONArray arr, Set<String> seen,
                                  int depth, int maxDepth, int maxRecords) {
        if (entry == null || !entry.canRead() || depth > maxDepth || arr.length() >= maxRecords) return;
        if (entry.isDirectory()) {
            for (DocumentFile child : entry.listFiles()) {
                String name = child.getName() == null ? "unnamed" : child.getName();
                scanDocumentTree(child, relativePath + "/" + name, arr, seen, depth + 1, maxDepth, maxRecords);
                if (arr.length() >= maxRecords) {
                    sourceStatus.put("app_artifacts.json", "visibility_limited");
                    return;
                }
            }
            return;
        }
        String name = entry.getName() == null ? "" : entry.getName().toLowerCase();
        if (!entry.isFile() || !isInterestingArtifactFile(name) || !seen.add(entry.getUri().toString())) return;
        try {
            JSONObject obj = new JSONObject();
            obj.put("package_name", inferPackageAssociation(relativePath));
            obj.put("artifact_category", categorizeArtifact(name, relativePath));
            obj.put("relative_path", relativePath);
            obj.put("absolute_path", entry.getUri().toString());
            obj.put("size_bytes", entry.length());
            obj.put("last_modified_ms", entry.lastModified());
            obj.put("mime_type", entry.getType() == null ? guessMimeType(name) : entry.getType());
            obj.put("sha256_hash", sha256ForUri(entry.getUri()));
            obj.put("accessibility_status", "available");
            arr.put(obj);
        } catch (Exception e) {
            sourceStatus.put("app_artifacts.json", "partial_error");
        }
    }

    private void queryMediaStore(JSONArray arr, Set<String> seen, Uri collection, String artifactCategory) {
        String[] projection = new String[]{
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.MIME_TYPE,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.DATE_MODIFIED,
                MediaStore.MediaColumns.RELATIVE_PATH
        };
        try (Cursor cursor = getContentResolver().query(
                collection,
                projection,
                null,
                null,
                MediaStore.MediaColumns.DATE_MODIFIED + " DESC"
        )) {
            if (cursor == null) return;
            int idIdx = cursor.getColumnIndex(MediaStore.MediaColumns._ID);
            int nameIdx = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME);
            int mimeIdx = cursor.getColumnIndex(MediaStore.MediaColumns.MIME_TYPE);
            int sizeIdx = cursor.getColumnIndex(MediaStore.MediaColumns.SIZE);
            int modifiedIdx = cursor.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED);
            int relativeIdx = cursor.getColumnIndex(MediaStore.MediaColumns.RELATIVE_PATH);
            while (cursor.moveToNext()) {
                long id = idIdx != -1 ? cursor.getLong(idIdx) : -1;
                if (id < 0) continue;
                Uri itemUri = ContentUris.withAppendedId(collection, id);
                String name = nameIdx != -1 ? cursor.getString(nameIdx) : "";
                String relativeDir = relativeIdx != -1 ? cursor.getString(relativeIdx) : "";
                String relativePath = ((relativeDir != null ? relativeDir : "") + (name != null ? name : "")).trim();
                String key = itemUri.toString();
                if (!seen.add(key)) continue;
                JSONObject obj = new JSONObject();
                obj.put("package_name", "media_store");
                obj.put("artifact_category", artifactCategory);
                obj.put("relative_path", relativePath);
                obj.put("absolute_path", itemUri.toString());
                obj.put("size_bytes", sizeIdx != -1 ? cursor.getLong(sizeIdx) : 0);
                long modifiedSeconds = modifiedIdx != -1 ? cursor.getLong(modifiedIdx) : 0;
                obj.put("last_modified_ms", modifiedSeconds > 0 ? modifiedSeconds * 1000 : 0);
                String mime = mimeIdx != -1 ? cursor.getString(mimeIdx) : "";
                obj.put("mime_type", mime != null && !mime.isEmpty() ? mime : guessMimeType(name != null ? name.toLowerCase() : ""));
                obj.put("sha256_hash", sha256ForUri(itemUri));
                obj.put("accessibility_status", "available");
                arr.put(obj);
            }
        } catch (Exception e) {
            sourceStatus.put("app_artifacts.json", "partial_error");
        }
    }

    private void scanDirectoryForArtifacts(File dir, JSONArray arr, Set<String> seen, int currentDepth, int maxDepth) {
        if (dir == null || !dir.exists() || !dir.isDirectory() || currentDepth > maxDepth) {
            return;
        }
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File f : files) {
            try {
                if (f.isDirectory()) {
                    String name = f.getName().toLowerCase();
                    if (!name.startsWith(".")) {
                        scanDirectoryForArtifacts(f, arr, seen, currentDepth + 1, maxDepth);
                    }
                } else if (f.isFile() && f.canRead()) {
                    String name = f.getName().toLowerCase();
                    if (isInterestingArtifactFile(name)) {
                        if (!seen.add(f.getAbsolutePath())) continue;
                        JSONObject obj = new JSONObject();
                        String pkgAssoc = inferPackageAssociation(f.getAbsolutePath());
                        obj.put("package_name", pkgAssoc);
                        obj.put("artifact_category", categorizeArtifact(name, f.getAbsolutePath()));
                        String rootPath = Environment.getExternalStorageDirectory().getAbsolutePath();
                        obj.put("relative_path", f.getAbsolutePath().replace(rootPath, ""));
                        obj.put("absolute_path", f.getAbsolutePath());
                        obj.put("size_bytes", f.length());
                        obj.put("last_modified_ms", f.lastModified());
                        obj.put("mime_type", guessMimeType(name));
                        obj.put("sha256_hash", sha256ForFile(f));
                        obj.put("accessibility_status", "available");
                        arr.put(obj);
                    }
                }
            } catch (Exception ignored) {
            }
        }
    }

    private boolean isInterestingArtifactFile(String name) {
        return name.endsWith(".db") || name.endsWith(".sqlite") || name.endsWith(".bak") ||
               name.endsWith(".ab") || name.endsWith(".xml") || name.endsWith(".json") ||
               name.endsWith(".csv") || name.endsWith(".jpg") || name.endsWith(".jpeg") ||
               name.endsWith(".png") || name.endsWith(".mp4") || name.endsWith(".pdf") ||
               name.endsWith(".txt") || name.endsWith(".crypt14") || name.endsWith(".crypt15");
    }

    private String inferPackageAssociation(String path) {
        if (path.contains("/Android/data/")) {
            int idx = path.indexOf("/Android/data/");
            String sub = path.substring(idx + "/Android/data/".length());
            int nextSlash = sub.indexOf("/");
            if (nextSlash != -1) {
                return sub.substring(0, nextSlash);
            }
            return sub;
        }
        String lower = path.toLowerCase();
        if (lower.contains("whatsapp")) return "com.whatsapp";
        if (lower.contains("telegram")) return "org.telegram.messenger";
        if (lower.contains("signal")) return "org.thoughtcrime.securesms";
        if (lower.contains("chrome")) return "com.android.chrome";
        return "unknown";
    }

    private String categorizeArtifact(String name, String path) {
        if (name.endsWith(".jpg") || name.endsWith(".jpeg") || name.endsWith(".png") ||
            name.endsWith(".mp4") || name.endsWith(".pdf")) {
            return "media";
        }
        if (name.endsWith(".bak") || name.endsWith(".ab") || name.endsWith(".crypt14") || name.endsWith(".crypt15")) {
            return "user_backup";
        }
        if (name.endsWith(".csv") || name.endsWith(".xml") || name.endsWith(".txt")) {
            return "app_export";
        }
        return "shared_storage";
    }

    private String guessMimeType(String name) {
        if (name.endsWith(".jpg") || name.endsWith(".jpeg")) return "image/jpeg";
        if (name.endsWith(".png")) return "image/png";
        if (name.endsWith(".mp4")) return "video/mp4";
        if (name.endsWith(".pdf")) return "application/pdf";
        if (name.endsWith(".db") || name.endsWith(".sqlite")) return "application/x-sqlite3";
        if (name.endsWith(".json")) return "application/json";
        if (name.endsWith(".xml")) return "application/xml";
        if (name.endsWith(".csv")) return "text/csv";
        return "application/octet-stream";
    }

    private boolean hasSharedMediaPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return checkSelfPermission(Manifest.permission.READ_MEDIA_IMAGES) == PackageManager.PERMISSION_GRANTED
                    || checkSelfPermission(Manifest.permission.READ_MEDIA_VIDEO) == PackageManager.PERMISSION_GRANTED
                    || checkSelfPermission(Manifest.permission.READ_MEDIA_AUDIO) == PackageManager.PERMISSION_GRANTED;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
        }
        return true;
    }

    private String sha256ForUri(Uri uri) {
        try (InputStream input = getContentResolver().openInputStream(uri)) {
            if (input == null) return "";
            return sha256ForStream(input);
        } catch (Exception e) {
            return "";
        }
    }

    private String sha256ForFile(File file) {
        try (InputStream input = new FileInputStream(file)) {
            return sha256ForStream(input);
        } catch (Exception e) {
            return "";
        }
    }

    private String sha256ForStream(InputStream input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) != -1) {
            digest.update(buffer, 0, count);
        }
        StringBuilder hash = new StringBuilder();
        for (byte b : digest.digest()) hash.append(String.format(Locale.US, "%02x", b & 0xff));
        return hash.toString();
    }

    private void extractDeviceMetadata() {
        JSONObject root = new JSONObject();
        JSONObject data = new JSONObject();
        JSONObject availabilityMap = new JSONObject();

        try {
            root.put("source", "android_agent");
            root.put("category", "device_metadata");
            root.put("collected_at_ms", System.currentTimeMillis());

            // 1. Device Identity
            putMetadataField(data, availabilityMap, "manufacturer", Build.MANUFACTURER);
            putMetadataField(data, availabilityMap, "model", Build.MODEL);
            putMetadataField(data, availabilityMap, "device", Build.DEVICE);
            putMetadataField(data, availabilityMap, "product", Build.PRODUCT);
            putMetadataField(data, availabilityMap, "board", Build.BOARD);
            putMetadataField(data, availabilityMap, "hardware", Build.HARDWARE);
            putMetadataField(data, availabilityMap, "android_release", Build.VERSION.RELEASE);
            putMetadataField(data, availabilityMap, "sdk_level", Build.VERSION.SDK_INT);
            putMetadataField(data, availabilityMap, "build_id", Build.ID);
            putMetadataField(data, availabilityMap, "build_fingerprint", Build.FINGERPRINT);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                putMetadataField(data, availabilityMap, "security_patch", Build.VERSION.SECURITY_PATCH);
            } else {
                putMetadataField(data, availabilityMap, "security_patch", "unsupported");
            }

            putMetadataField(data, availabilityMap, "cpu_abi", Build.CPU_ABI);
            JSONArray abisArr = new JSONArray();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                for (String abi : Build.SUPPORTED_ABIS) {
                    abisArr.put(abi);
                }
            } else {
                abisArr.put(Build.CPU_ABI);
            }
            data.put("supported_abis", abisArr);
            availabilityMap.put("supported_abis", "available");

            // 2. System & Security State
            putMetadataField(data, availabilityMap, "encryption_state", getSystemProp("ro.crypto.state", "unknown"));
            putMetadataField(data, availabilityMap, "verified_boot_state", getSystemProp("ro.boot.verifiedbootstate", "unknown"));
            putMetadataField(data, availabilityMap, "bootloader_state", getSystemProp("ro.bootloader", "unknown"));
            boolean isDebuggable = (getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            data.put("is_debuggable", isDebuggable);
            availabilityMap.put("is_debuggable", "available");
            putMetadataField(data, availabilityMap, "build_type", Build.TYPE);
            putMetadataField(data, availabilityMap, "build_tags", Build.TAGS);

            // 3. Runtime State
            data.put("uptime_ms", SystemClock.elapsedRealtime());
            availabilityMap.put("uptime_ms", "available");

            putMetadataField(data, availabilityMap, "locale", Locale.getDefault().toString());
            putMetadataField(data, availabilityMap, "timezone", TimeZone.getDefault().getID());

            // Battery
            try {
                Intent batteryIntent = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
                if (batteryIntent != null) {
                    int level = batteryIntent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                    int scale = batteryIntent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
                    if (level != -1 && scale != -1) {
                        int pct = (int) ((level / (float) scale) * 100);
                        data.put("battery_level", pct);
                        availabilityMap.put("battery_level", "available");
                    } else {
                        data.put("battery_level", -1);
                        availabilityMap.put("battery_level", "unavailable");
                    }

                    int status = batteryIntent.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
                    String statusStr;
                    switch (status) {
                        case BatteryManager.BATTERY_STATUS_CHARGING:
                            statusStr = "charging";
                            break;
                        case BatteryManager.BATTERY_STATUS_DISCHARGING:
                            statusStr = "discharging";
                            break;
                        case BatteryManager.BATTERY_STATUS_FULL:
                            statusStr = "full";
                            break;
                        case BatteryManager.BATTERY_STATUS_NOT_CHARGING:
                            statusStr = "not_charging";
                            break;
                        default:
                            statusStr = "unknown";
                            break;
                    }
                    data.put("charging_state", statusStr);
                    availabilityMap.put("charging_state", "available");

                    int plugged = batteryIntent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
                    String pluggedStr;
                    switch (plugged) {
                        case BatteryManager.BATTERY_PLUGGED_AC:
                            pluggedStr = "ac";
                            break;
                        case BatteryManager.BATTERY_PLUGGED_USB:
                            pluggedStr = "usb";
                            break;
                        case BatteryManager.BATTERY_PLUGGED_WIRELESS:
                            pluggedStr = "wireless";
                            break;
                        default:
                            pluggedStr = "none";
                            break;
                    }
                    data.put("battery_status", pluggedStr);
                    availabilityMap.put("battery_status", "available");
                } else {
                    data.put("battery_level", -1);
                    availabilityMap.put("battery_level", "unavailable");
                    data.put("charging_state", "unknown");
                    availabilityMap.put("charging_state", "unavailable");
                    data.put("battery_status", "unknown");
                    availabilityMap.put("battery_status", "unavailable");
                }
            } catch (Exception e) {
                data.put("battery_level", -1);
                availabilityMap.put("battery_level", "error");
                data.put("charging_state", "error");
                availabilityMap.put("charging_state", "error");
                data.put("battery_status", "error");
                availabilityMap.put("battery_status", "error");
            }

            // Storage
            try {
                File path = Environment.getDataDirectory();
                StatFs stat = new StatFs(path.getPath());
                long totalBytes = stat.getTotalBytes();
                long availBytes = stat.getAvailableBytes();
                data.put("storage_total_bytes", totalBytes);
                availabilityMap.put("storage_total_bytes", "available");
                data.put("storage_available_bytes", availBytes);
                availabilityMap.put("storage_available_bytes", "available");
            } catch (Exception e) {
                data.put("storage_total_bytes", -1);
                availabilityMap.put("storage_total_bytes", "error");
                data.put("storage_available_bytes", -1);
                availabilityMap.put("storage_available_bytes", "error");
            }

            root.put("data", data);
            root.put("availability_map", availabilityMap);

        } catch (Exception e) {
            sourceStatus.put("device_metadata.json", "partial_error");
            e.printStackTrace();
        }
        writeToFile("device_metadata.json", root.toString());
    }

    private void putMetadataField(JSONObject data, JSONObject availabilityMap, String key, Object value) {
        try {
            if (value != null && !value.toString().isEmpty() && !value.toString().equals("unknown")) {
                data.put(key, value);
                availabilityMap.put(key, "available");
            } else {
                data.put(key, value != null ? value : JSONObject.NULL);
                availabilityMap.put(key, "unavailable");
            }
        } catch (Exception e) {
            try {
                data.put(key, JSONObject.NULL);
                availabilityMap.put(key, "error");
            } catch (Exception ignored) {
            }
        }
    }

    private String getSystemProp(String key, String fallback) {
        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            Method get = c.getMethod("get", String.class, String.class);
            String res = (String) get.invoke(null, key, fallback);
            return (res != null && !res.trim().isEmpty()) ? res : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    private void writeToFile(String filename, String data) {
        File file = new File(outputDir, filename);
        File tmp = new File(outputDir, filename + ".tmp");
        try (FileOutputStream fos = new FileOutputStream(tmp)) {
            fos.write(data.getBytes(StandardCharsets.UTF_8));
            fos.getFD().sync();
        } catch (Exception e) {
            throw new IllegalStateException("Collection output could not be written: " + filename, e);
        }
        if (!tmp.renameTo(file))
            throw new IllegalStateException("Collection output could not be committed: " + filename);
    }

    private File privateCollectionDir() {
        return new File(getFilesDir(), "collection");
    }

    private void writeManifest(boolean legacyAdb) throws Exception {
        JSONObject manifest = new JSONObject();
        manifest.put("format", "forensix-agent-v2");
        manifest.put("collection_id", java.util.UUID.randomUUID().toString());
        manifest.put("created_at_ms", System.currentTimeMillis());
        manifest.put("mode", legacyAdb ? "legacy_adb" : "user_export");
        JSONObject files = new JSONObject();
        boolean complete = true;
        for (String name : OUTPUT_FILES) {
            File file = new File(outputDir, name);
            if (!file.isFile()) throw new IllegalStateException("Missing collection file: " + name);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (FileInputStream input = new FileInputStream(file)) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
            }
            StringBuilder hash = new StringBuilder();
            for (byte b : digest.digest()) hash.append(String.format(Locale.US, "%02x", b & 0xff));
            JSONObject entry = new JSONObject();
            entry.put("sha256", hash.toString());
            entry.put("bytes", file.length());
            String status = sourceStatus.containsKey(name) ? sourceStatus.get(name) : "ok";
            entry.put("status", status);
            if (!"ok".equals(status)) complete = false;
            files.put(name, entry);
        }
        manifest.put("files", files);
        manifest.put("complete", complete);
        writeToFile("manifest.json", manifest.toString());
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.channel_name),
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription(getString(R.string.channel_desc));
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        executor.shutdown();
        super.onDestroy();
    }
}
