package com.forensix.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.provider.CallLog;
import android.provider.ContactsContract;
import androidx.core.app.NotificationCompat;

import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AgentService extends Service {

    private static final String CHANNEL_ID = "forensix_channel";
    private static final int NOTIF_ID = 1001;
    private static final String STAGING_DIR = "/sdcard/forensix_out";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

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

        executor.execute(this::runExtraction);

        return START_NOT_STICKY;
    }

    private void runExtraction() {
        try {
            File dir = new File(STAGING_DIR);
            if (!dir.exists()) {
                dir.mkdirs();
            }

            extractContacts();
            extractSms();
            extractCallLog();
            extractInstalledApps();
            extractDeviceMetadata();
            extractAccessibleAppArtifacts();

            // Write DONE marker
            File doneFile = new File(dir, "DONE");
            FileOutputStream fos = new FileOutputStream(doneFile);
            String doneContent = "COMPLETED_AT=" + System.currentTimeMillis();
            fos.write(doneContent.getBytes(StandardCharsets.UTF_8));
            fos.close();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            stopSelf();
        }
    }

    private void extractContacts() {
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
                e.printStackTrace();
            } finally {
                cursor.close();
            }
        }
        writeToFile("contacts.json", arr.toString());
    }

    private void extractSms() {
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
                e.printStackTrace();
            } finally {
                cursor.close();
            }
        }
        writeToFile("sms.json", arr.toString());
    }

    private void extractCallLog() {
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
                e.printStackTrace();
            } finally {
                cursor.close();
            }
        }
        writeToFile("call_logs.json", arr.toString());
    }

    private void extractInstalledApps() {
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
            e.printStackTrace();
        }
        writeToFile("installed_apps.json", arr.toString());
    }

    private void extractAccessibleAppArtifacts() {
        JSONArray arr = new JSONArray();
        try {
            File sdcard = Environment.getExternalStorageDirectory();
            if (sdcard != null && sdcard.exists() && sdcard.canRead()) {
                scanDirectoryForArtifacts(sdcard, arr, 0, 3);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        writeToFile("app_artifacts.json", arr.toString());
    }

    private void scanDirectoryForArtifacts(File dir, JSONArray arr, int currentDepth, int maxDepth) {
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
                        scanDirectoryForArtifacts(f, arr, currentDepth + 1, maxDepth);
                    }
                } else if (f.isFile() && f.canRead()) {
                    String name = f.getName().toLowerCase();
                    if (isInterestingArtifactFile(name)) {
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
                        obj.put("sha256_hash", "");
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
        try {
            File file = new File(STAGING_DIR, filename);
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data.getBytes(StandardCharsets.UTF_8));
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
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
}
