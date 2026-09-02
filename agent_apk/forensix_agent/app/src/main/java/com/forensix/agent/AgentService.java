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

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
        List<PackageInfo> packages = pm.getInstalledPackages(0);

        try {
            for (PackageInfo pi : packages) {
                JSONObject obj = new JSONObject();
                obj.put("package_name", pi.packageName);
                obj.put("app_label", pi.applicationInfo.loadLabel(pm).toString());
                obj.put("version_name", pi.versionName != null ? pi.versionName : "");
                obj.put("install_time_ms", pi.firstInstallTime);
                boolean isSystem = (pi.applicationInfo.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0;
                obj.put("is_system", isSystem);

                arr.put(obj);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        writeToFile("installed_apps.json", arr.toString());
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
