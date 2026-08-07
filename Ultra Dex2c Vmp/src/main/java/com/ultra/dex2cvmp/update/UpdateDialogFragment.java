package com.ultra.dex2cvmp.update;

import android.app.DownloadManager;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;
import com.ultra.dex2cvmp.R;

public class UpdateDialogFragment extends DialogFragment {

    private static final String ARG_VER = "ver";
    private static final String ARG_LOG = "log";
    private static final String ARG_URL = "url";

    private long    downloadId       = -1;
    private Uri     pendingInstallUri = null;
    private boolean downloadReady    = false;   // set when poll detects SUCCESS
    private DownloadManager activeDm = null;

    private final Handler  pollHandler  = new Handler(Looper.getMainLooper());
    private Runnable pollRunnable;

    public static UpdateDialogFragment newInstance(String versionName, String changelog, String apkUrl) {
        Bundle args = new Bundle();
        args.putString(ARG_VER, versionName);
        args.putString(ARG_LOG, changelog);
        args.putString(ARG_URL, apkUrl);
        UpdateDialogFragment f = new UpdateDialogFragment();
        f.setArguments(args);
        return f;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setStyle(STYLE_NO_TITLE, R.style.UpdateDialogStyle);
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_update, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View root, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(root, savedInstanceState);

        Bundle args       = requireArguments();
        String versionName = args.getString(ARG_VER, "");
        String changelog   = args.getString(ARG_LOG, "");
        String apkUrl      = args.getString(ARG_URL, "");

        ((TextView) root.findViewById(R.id.tv_update_version)).setText("Version " + versionName);
        ((TextView) root.findViewById(R.id.tv_update_changelog)).setText(changelog);

        root.findViewById(R.id.btn_update_later)
                .setOnClickListener(v -> dismissAllowingStateLoss());

        View dlBtn = root.findViewById(R.id.btn_update_download);
        dlBtn.setOnClickListener(v -> startDownload(apkUrl));

        setCancelable(false);
        animateEntrance(root);
    }

    // ── Entrance animations ──────────────────────────────────────────────────

    private void animateEntrance(View root) {
        DecelerateInterpolator decel  = new DecelerateInterpolator(2f);
        OvershootInterpolator  bounce = new OvershootInterpolator(1.4f);

        // Label slides + fades
        int[] slideIds = {
            R.id.tv_update_label,
            R.id.tv_update_version,
            R.id.divider_update_1,
            R.id.tv_update_whats_new,
            R.id.tv_update_changelog,
            R.id.divider_update_2
        };
        for (int i = 0; i < slideIds.length; i++) {
            View v = root.findViewById(slideIds[i]);
            if (v == null) continue;
            v.setAlpha(0f);
            v.setTranslationY(20f);
            v.animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setStartDelay(100L + i * 65L)
                    .setDuration(360)
                    .setInterpolator(decel)
                    .start();
        }

        // Buttons row bounces in from below
        View btnsRow = root.findViewById(R.id.update_buttons_row);
        if (btnsRow != null) {
            btnsRow.setAlpha(0f);
            btnsRow.setTranslationY(30f);
            btnsRow.animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setStartDelay(520L)
                    .setDuration(420)
                    .setInterpolator(bounce)
                    .start();
        }

        // Download button pulses after entrance settles
        View dlBtn = root.findViewById(R.id.btn_update_download);
        if (dlBtn != null) {
            dlBtn.postDelayed(() -> pulseLoop(dlBtn), 1000L);
        }
    }

    private void pulseLoop(View v) {
        if (!isAdded() || v.getParent() == null) return;
        v.animate()
                .scaleX(1.04f).scaleY(1.04f)
                .setDuration(600)
                .withEndAction(() -> v.animate()
                        .scaleX(1f).scaleY(1f)
                        .setDuration(600)
                        .withEndAction(() -> v.postDelayed(() -> pulseLoop(v), 800L))
                        .start())
                .start();
    }

    // ── Download ──────────────────────────────────────────────────────────────

    private void startDownload(String apkUrl) {
        if (apkUrl == null || apkUrl.isEmpty()) return;
        Context ctx = requireContext();

        // On Android 8+ check "install unknown apps" permission
        if (Build.VERSION.SDK_INT >= 26 && !ctx.getPackageManager().canRequestPackageInstalls()) {
            Intent intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
                    .setData(Uri.parse("package:" + ctx.getPackageName()));
            startActivity(intent);
            return;
        }

        activeDm = (DownloadManager) ctx.getSystemService(Context.DOWNLOAD_SERVICE);
        DownloadManager.Request req = new DownloadManager.Request(Uri.parse(apkUrl));
        req.setTitle("Ultra Dex2C-VMP Update");
        req.setDescription("Downloading latest version…");
        req.setNotificationVisibility(
                DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
        req.setDestinationInExternalPublicDir(
                Environment.DIRECTORY_DOWNLOADS, "UltraDex2CVMP_update.apk");
        req.setMimeType("application/vnd.android.package-archive");
        downloadId = activeDm.enqueue(req);

        // Visual feedback — dim & disable button
        View dlBtn = requireView().findViewById(R.id.btn_update_download);
        TextView dlTv = requireView().findViewById(R.id.tv_btn_download_text);
        if (dlTv != null)  dlTv.setText("DOWNLOADING…");
        if (dlBtn != null) { dlBtn.setClickable(false); dlBtn.setAlpha(0.65f); }

        // Poll DownloadManager every second — more reliable than BroadcastReceiver
        startPolling();
    }

    private void startPolling() {
        stopPolling();
        pollRunnable = new Runnable() {
            @Override public void run() {
                if (downloadId == -1 || activeDm == null) return;

                DownloadManager.Query q = new DownloadManager.Query();
                q.setFilterById(downloadId);
                Cursor c = activeDm.query(q);
                if (c == null) { pollHandler.postDelayed(this, 1000); return; }

                int status = DownloadManager.STATUS_PENDING;
                if (c.moveToFirst()) {
                    int col = c.getColumnIndex(DownloadManager.COLUMN_STATUS);
                    if (col != -1) status = c.getInt(col);
                }
                c.close();

                if (status == DownloadManager.STATUS_SUCCESSFUL) {
                    stopPolling();
                    onDownloadSuccess();
                } else if (status == DownloadManager.STATUS_FAILED) {
                    stopPolling();
                    onDownloadFailed();
                } else {
                    // Still running — check again in 1 s
                    pollHandler.postDelayed(this, 1000);
                }
            }
        };
        pollHandler.postDelayed(pollRunnable, 1000);
    }

    private void stopPolling() {
        if (pollRunnable != null) {
            pollHandler.removeCallbacks(pollRunnable);
            pollRunnable = null;
        }
    }

    private void onDownloadSuccess() {
        if (activeDm == null || downloadId == -1) return;
        Uri fileUri = activeDm.getUriForDownloadedFile(downloadId);
        if (fileUri == null) return;
        pendingInstallUri = fileUri;
        downloadReady = true;

        if (!isAdded() || getView() == null) return;
        showDownloadComplete();
    }

    private void onDownloadFailed() {
        if (!isAdded() || getView() == null) return;
        // Re-enable download button so the user can retry
        View dlBtn = getView().findViewById(R.id.btn_update_download);
        TextView dlTv = getView().findViewById(R.id.tv_btn_download_text);
        if (dlTv != null) dlTv.setText("RETRY DOWNLOAD");
        if (dlBtn != null) { dlBtn.setClickable(true); dlBtn.setAlpha(1f); }
    }

    private void showDownloadComplete() {
        if (!isAdded() || getView() == null) return;
        String filePath = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS) + "/UltraDex2CVMP_update.apk";

        View root            = getView();
        View buttonsRow      = root.findViewById(R.id.update_buttons_row);
        View completeSection = root.findViewById(R.id.download_complete_section);
        TextView tvPath      = root.findViewById(R.id.tv_download_path);
        View btnInstall      = root.findViewById(R.id.btn_install_now);

        if (tvPath != null) tvPath.setText(filePath);

        // Animate buttons row out, complete section in
        if (buttonsRow != null) {
            buttonsRow.animate().alpha(0f).translationY(10f).setDuration(200)
                    .withEndAction(() -> buttonsRow.setVisibility(View.GONE))
                    .start();
        }
        if (completeSection != null) {
            completeSection.setVisibility(View.VISIBLE);
            completeSection.setAlpha(0f);
            completeSection.setTranslationY(20f);
            completeSection.animate()
                    .alpha(1f).translationY(0f)
                    .setStartDelay(220L).setDuration(380)
                    .setInterpolator(new DecelerateInterpolator(2f))
                    .start();
        }
        if (btnInstall != null) {
            btnInstall.setOnClickListener(v -> doInstall());
        }
    }

    private void doInstall() {
        if (pendingInstallUri == null || !isAdded()) return;
        Intent install = new Intent(Intent.ACTION_VIEW);
        install.setDataAndType(pendingInstallUri, "application/vnd.android.package-archive");
        install.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try { requireContext().startActivity(install); } catch (Exception ignored) {}
        dismissAllowingStateLoss();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @Override
    public void onResume() {
        super.onResume();
        // If download finished while view was unavailable, show the state now
        if (downloadReady && pendingInstallUri != null) {
            showDownloadComplete();
        }
    }

    @Override
    public void onStart() {
        super.onStart();
        if (getDialog() != null && getDialog().getWindow() != null) {
            Window w = getDialog().getWindow();
            int width = (int) (requireContext().getResources().getDisplayMetrics().widthPixels * 0.90f);
            w.setLayout(width, ViewGroup.LayoutParams.WRAP_CONTENT);
            w.setBackgroundDrawableResource(android.R.color.transparent);
        }
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        stopPolling();
    }
}
