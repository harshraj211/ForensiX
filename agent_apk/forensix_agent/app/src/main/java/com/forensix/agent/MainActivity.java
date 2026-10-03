package com.forensix.agent;

import android.Manifest;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

public class MainActivity extends AppCompatActivity {

    private static final int PERM_REQUEST_CODE = 2001;
    private static final int EXPORT_REQUEST_CODE = 2002;
    private static final int DOCUMENT_TREE_REQUEST_CODE = 2003;
    static final String PREF_DOCUMENT_TREE = "selected_document_tree";

    private static final String[] CORE_PERMISSIONS = new String[]{
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_SMS,
            Manifest.permission.READ_CALL_LOG
    };

    private TextView status;
    private boolean legacyAdb;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        legacyAdb = getIntent().getBooleanExtra("legacy_adb", false);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 32, 32, 32);
        status = new TextView(this);
        status.setText(legacyAdb
                ? "Legacy ADB collection writes to shared storage. Tap Start collection to continue."
                : "Tap Start collection, grant access, then export the bundle to a location you choose.");
        layout.addView(status);
        Button start = new Button(this);
        start.setText("Start collection");
        start.setOnClickListener(view -> {
            if (hasAllPermissions()) {
                startAgentService();
            } else {
                ActivityCompat.requestPermissions(this, requiredPermissions(), PERM_REQUEST_CODE);
            }
        });
        layout.addView(start);
        Button selectFolder = new Button(this);
        selectFolder.setText("Select readable shared folder");
        selectFolder.setOnClickListener(view -> requestDocumentTree());
        layout.addView(selectFolder);
        if (!legacyAdb) {
            Button export = new Button(this);
            export.setText("Export collection bundle");
            export.setOnClickListener(view -> requestExport());
            layout.addView(export);
        }
        setContentView(layout);
    }

    private boolean hasAllPermissions() {
        for (String perm : requiredPermissions()) {
            if (ContextCompat.checkSelfPermission(this, perm) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    private String[] requiredPermissions() {
        List<String> permissions = new ArrayList<>();
        for (String permission : CORE_PERMISSIONS) {
            permissions.add(permission);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.READ_MEDIA_IMAGES);
            permissions.add(Manifest.permission.READ_MEDIA_VIDEO);
            permissions.add(Manifest.permission.READ_MEDIA_AUDIO);
        } else {
            permissions.add(Manifest.permission.READ_EXTERNAL_STORAGE);
        }
        for (String permission : optionalPermissions()) {
            permissions.add(permission);
        }
        return permissions.toArray(new String[0]);
    }

    private String[] optionalPermissions() {
        List<String> permissions = new ArrayList<>();
        permissions.add(Manifest.permission.READ_PHONE_STATE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT);
        }
        return permissions.toArray(new String[0]);
    }

    private void startAgentService() {
        if (!legacyAdb) {
            File marker = new File(collectionDir(), "DONE");
            if (marker.exists() && !marker.delete()) {
                status.setText("Cannot clear the previous collection marker.");
                return;
            }
        }
        Intent intent = new Intent(this, AgentService.class);
        intent.putExtra("legacy_adb", legacyAdb);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        status.setText("Collection started. Keep the device unlocked until it completes.");
    }

    private File collectionDir() {
        return new File(getFilesDir(), "collection");
    }

    private void requestExport() {
        if (!new File(collectionDir(), "DONE").isFile()
                || !new File(collectionDir(), "manifest.json").isFile()) {
            status.setText("Collection has not completed. Try again after the notification disappears.");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Export sensitive collection")
                .setMessage("The exported bundle contains unencrypted contacts, messages, and call logs. Choose a trusted destination and protect the file.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Choose location", (dialog, which) -> {
                    Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    intent.addCategory(Intent.CATEGORY_OPENABLE);
                    intent.setType("application/zip");
                    intent.putExtra(Intent.EXTRA_TITLE, "forensix-agent-collection.fxz");
                    startActivityForResult(intent, EXPORT_REQUEST_CODE);
                })
                .show();
    }

    private void requestDocumentTree() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, DOCUMENT_TREE_REQUEST_CODE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == DOCUMENT_TREE_REQUEST_CODE) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null) {
                Uri tree = data.getData();
                int flags = data.getFlags() & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                try {
                    getContentResolver().takePersistableUriPermission(
                            tree, flags & Intent.FLAG_GRANT_READ_URI_PERMISSION
                    );
                } catch (SecurityException error) {
                    status.setText("The folder grant could not be retained. Select it again before collection.");
                    return;
                }
                getSharedPreferences("forensix_agent", MODE_PRIVATE)
                        .edit().putString(PREF_DOCUMENT_TREE, tree.toString()).apply();
                status.setText("Shared folder selected. It will be included in the next collection.");
            }
            return;
        }
        if (requestCode != EXPORT_REQUEST_CODE || resultCode != RESULT_OK
                || data == null || data.getData() == null) return;
        final Uri destination = data.getData();
        status.setText("Exporting collection...");
        new Thread(() -> {
            try {
                exportBundle(destination);
                runOnUiThread(() -> status.setText("Export complete. Keep the bundle secure."));
            } catch (Exception e) {
                runOnUiThread(() -> status.setText("Export failed. Select a destination and retry."));
            }
        }).start();
    }

    private void exportBundle(Uri destination) throws Exception {
        try (OutputStream stream = getContentResolver().openOutputStream(destination, "wt")) {
            if (stream == null) throw new IllegalStateException("No export stream");
            try (ZipOutputStream zip = new ZipOutputStream(stream)) {
                writeZipEntry(zip, new File(collectionDir(), "manifest.json"));
                for (String name : AgentService.OUTPUT_FILES) {
                    writeZipEntry(zip, new File(collectionDir(), name));
                }
            }
        }
    }

    private void writeZipEntry(ZipOutputStream zip, File file) throws Exception {
        if (!file.isFile()) throw new IllegalStateException("Missing collection file");
        zip.putNextEntry(new ZipEntry(file.getName()));
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) zip.write(buffer, 0, count);
        }
        zip.closeEntry();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERM_REQUEST_CODE) {
            if (hasAllPermissions()) {
                startAgentService();
            } else {
                startAgentService();
                status.setText("Partial collection started; denied sources will be marked in the bundle.");
            }
        }
    }
}
