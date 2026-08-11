package com.ultra.dex2cvmp.ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.*;
import com.ultra.dex2cvmp.R;
import com.ultra.dex2cvmp.engine.CompilerManager;
import com.ultra.dex2cvmp.engine.OllvmNdkManager;

public class CompilerSetupActivity extends Activity {

    private CompilerManager cm;
    private final Handler ui = new Handler(Looper.getMainLooper());

    // NDK card
    private TextView tvNdkTitle, tvNdkSub, tvNdkBadge;
    private TextView btnNdkDownload, btnNdkCancel, btnNdkDelete;
    private ProgressBar pbNdk;
    private TextView tvNdkProgress;

    private boolean isDownloading = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_compiler_setup);
        cm = new CompilerManager(this);

        findViewById(R.id.btn_back).setOnClickListener(v -> finish());

        // NDK card
        tvNdkTitle    = findViewById(R.id.tv_ndk_title);
        tvNdkSub      = findViewById(R.id.tv_ndk_sub);
        tvNdkBadge    = findViewById(R.id.tv_ndk_badge);
        btnNdkDownload = findViewById(R.id.btn_ndk_download);
        btnNdkCancel  = findViewById(R.id.btn_ndk_cancel);
        btnNdkDelete  = findViewById(R.id.btn_ndk_delete);
        pbNdk         = findViewById(R.id.pb_ndk);
        tvNdkProgress = findViewById(R.id.tv_ndk_progress);

        btnNdkDownload.setOnClickListener(v -> startNdkDownload());
        btnNdkCancel.setOnClickListener(v -> cancelNdkDownload());
        btnNdkDelete.setOnClickListener(v -> confirmDeleteNdk());

        refreshUi();
    }

    @Override protected void onResume() {
        super.onResume();
        if (!isDownloading) refreshUi();
    }

    // ── Refresh ───────────────────────────────────────────────────────────────

    private void refreshUi() {
        refreshNdkCard();
    }

    private void refreshNdkCard() {
        boolean installed = OllvmNdkManager.isInstalled();

        if (!installed) {
            tvNdkTitle.setText("Compiler NDK  ·  Not Downloaded");
            tvNdkSub.setText("731 MB  ·  Required for protection");
            tvNdkBadge.setVisibility(View.GONE);
            btnNdkDownload.setVisibility(View.VISIBLE);
            btnNdkCancel.setVisibility(View.GONE);
            btnNdkDelete.setVisibility(View.GONE);
            pbNdk.setVisibility(View.GONE);
            tvNdkProgress.setVisibility(View.GONE);
        } else {
            tvNdkTitle.setText("Compiler NDK  ·  Ready");
            tvNdkSub.setText("clang++  ·  ARM64 + ARM32  ·  Stored in app data");
            tvNdkBadge.setVisibility(View.VISIBLE);
            btnNdkDownload.setVisibility(View.GONE);
            btnNdkCancel.setVisibility(View.GONE);
            btnNdkDelete.setVisibility(View.VISIBLE);
            pbNdk.setVisibility(View.GONE);
            tvNdkProgress.setVisibility(View.GONE);
        }
    }

    // ── NDK Download ──────────────────────────────────────────────────────────

    private void startNdkDownload() {
        isDownloading = true;
        btnNdkDownload.setVisibility(View.GONE);
        btnNdkCancel.setVisibility(View.VISIBLE);
        pbNdk.setVisibility(View.VISIBLE);
        pbNdk.setProgress(0);
        pbNdk.setMax(100);
        tvNdkProgress.setVisibility(View.VISIBLE);
        tvNdkProgress.setText("Starting download…");
        tvNdkTitle.setText("Compiler NDK  ·  Downloading…");
        btnNdkDelete.setVisibility(View.GONE);

        OllvmNdkManager.downloadAndInstall(new OllvmNdkManager.DownloadCallback() {
            @Override
            public void onProgress(int pct, String message) {
                ui.post(() -> {
                    pbNdk.setProgress(pct);
                    tvNdkProgress.setText(message);
                    tvNdkTitle.setText(pct > 40
                        ? "Compiler NDK  ·  Extracting…"
                        : "Compiler NDK  ·  Downloading…");
                });
            }

            @Override
            public void onDone(boolean success, String error) {
                ui.post(() -> {
                    isDownloading = false;
                    if (success) {
                        Toast.makeText(CompilerSetupActivity.this,
                            "Compiler NDK installed", Toast.LENGTH_SHORT).show();
                        refreshUi();
                    } else if ("Cancelled".equals(error)) {
                        tvNdkTitle.setText("Compiler NDK  ·  Not Downloaded");
                        tvNdkProgress.setText("Download paused — tap Download to resume");
                        tvNdkProgress.setVisibility(View.VISIBLE);
                        pbNdk.setVisibility(View.GONE);
                        btnNdkDownload.setVisibility(View.VISIBLE);
                        btnNdkCancel.setVisibility(View.GONE);
                        btnNdkDelete.setVisibility(View.GONE);
                    } else {
                        tvNdkTitle.setText("Compiler NDK  ·  Not Downloaded");
                        pbNdk.setVisibility(View.GONE);
                        tvNdkProgress.setVisibility(View.GONE);
                        btnNdkDownload.setVisibility(View.VISIBLE);
                        btnNdkCancel.setVisibility(View.GONE);
                        new AlertDialog.Builder(CompilerSetupActivity.this)
                            .setTitle("Download Failed")
                            .setMessage("Could not install the compiler NDK.\n\n" + error
                                + "\n\nTapping Download again will resume from where it stopped.")
                            .setPositiveButton("OK", null)
                            .show();
                    }
                });
            }
        });
    }

    private void cancelNdkDownload() {
        OllvmNdkManager.cancelDownload();
        btnNdkCancel.setEnabled(false);
        tvNdkProgress.setText("Cancelling…");
    }

    // ── Delete NDK ────────────────────────────────────────────────────────────

    private void confirmDeleteNdk() {
        new AlertDialog.Builder(this)
            .setTitle("Delete Compiler NDK?")
            .setMessage(
                "Removes the compiler NDK from app storage (731 MB freed).\n\n" +
                "You can re-download it any time from this screen.\n\n" +
                "Note: the NDK is also removed automatically if you uninstall the app.")
            .setPositiveButton("Delete", (d, w) -> {
                new Thread(() -> {
                    OllvmNdkManager.uninstall();
                    ui.post(() -> {
                        Toast.makeText(this, "Compiler NDK deleted", Toast.LENGTH_SHORT).show();
                        refreshUi();
                    });
                }, "ndk-delete").start();
            })
            .setNegativeButton("Cancel", null)
            .show();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void deleteDir(java.io.File dir) {
        if (dir == null || !dir.exists()) return;
        java.io.File[] files = dir.listFiles();
        if (files != null) for (java.io.File f : files) {
            if (f.isDirectory()) deleteDir(f); else f.delete();
        }
        dir.delete();
    }
}
