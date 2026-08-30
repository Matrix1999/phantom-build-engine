package com.matrix.dumper;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class LogActivity extends Activity {

    // ── Static log cache — survives rotation and back/re-open ─────────────────
    private static final List<String> LOG_CACHE  = new ArrayList<>();
    private static boolean            DUMP_DONE  = false;
    private static int                FINAL_DEX  = 0;
    private static long               FINAL_SECS = 0;

    // ── Views ─────────────────────────────────────────────────────────────────
    private TextView  logView;
    private TextView  footerStatus;
    private TextView  footerDexCount;
    private TextView  logTargetInfo;
    private ScrollView scrollView;

    // ── State ─────────────────────────────────────────────────────────────────
    private String targetPkg;
    private int    dexFound  = 0;
    private long   startTime = System.currentTimeMillis();

    // ── Broadcast receiver ────────────────────────────────────────────────────
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            String action = intent.getAction();
            if (DumperService.ACTION_LOG.equals(action)) {
                String pkg  = intent.getStringExtra(DumperService.EXTRA_PACKAGE);
                String line = intent.getStringExtra(DumperService.EXTRA_LINE);
                if (targetPkg == null || targetPkg.equals(pkg)) {
                    LOG_CACHE.add(line);
                    appendLine(line);
                }
            } else if (DumperService.ACTION_DONE.equals(action)) {
                String pkg  = intent.getStringExtra(DumperService.EXTRA_PACKAGE);
                int    dex  = intent.getIntExtra(DumperService.EXTRA_DEX_COUNT, 0);
                int    code = intent.getIntExtra(DumperService.EXTRA_EXIT, -1);
                if (targetPkg == null || targetPkg.equals(pkg)) {
                    DUMP_DONE  = true;
                    FINAL_DEX  = dex;
                    FINAL_SECS = (System.currentTimeMillis() - startTime) / 1000;
                    onDumpDone(dex, code);
                }
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_log);
        overridePendingTransition(R.anim.slide_in_right, R.anim.fade_stay);

        targetPkg = getIntent().getStringExtra("packageName");
        String appName = getIntent().getStringExtra("appName");
        String prot    = getIntent().getStringExtra("protection");

        setTitle("Matrix Dumper — " + (appName != null ? appName : targetPkg));

        logView        = findViewById(R.id.log_text);
        scrollView     = findViewById(R.id.scroll_view);
        footerStatus   = findViewById(R.id.footer_status);
        footerDexCount = findViewById(R.id.footer_dex_count);
        logTargetInfo  = findViewById(R.id.log_target_info);

        logView.setTypeface(Typeface.MONOSPACE);

        // Target info header
        if (logTargetInfo != null) {
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            logTargetInfo.setText(
                (appName != null ? appName : targetPkg)
                + "  |  " + (prot != null ? prot : "Unknown")
                + "\n" + ts);
        }

        // CLEAR button
        TextView btnClear = findViewById(R.id.btn_clear);
        if (btnClear != null) {
            btnClear.setOnClickListener(v -> {
                LOG_CACHE.clear();
                logView.setText("");
                dexFound = 0;
                updateFooter("Cleared", false);
            });
        }

        // COPY button — copies full log to clipboard
        TextView btnCopy = findViewById(R.id.btn_copy);
        if (btnCopy != null) {
            btnCopy.setOnClickListener(v -> copyLogsToClipboard());
        }

        // Replay cached logs (if user left and came back, or rotated)
        if (!LOG_CACHE.isEmpty()) {
            for (String cached : LOG_CACHE) appendLine(cached);
        }

        // If dump already finished while we were away, restore footer
        if (DUMP_DONE) {
            onDumpDone(FINAL_DEX, 0);
        } else {
            updateFooter("Running...", false);
        }

        // Register broadcast receiver
        IntentFilter f = new IntentFilter();
        f.addAction(DumperService.ACTION_LOG);
        f.addAction(DumperService.ACTION_DONE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(receiver, f, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(receiver, f);
        }
    }

    /** Clear static cache when starting a fresh dump */
    public static void clearCache() {
        LOG_CACHE.clear();
        DUMP_DONE  = false;
        FINAL_DEX  = 0;
        FINAL_SECS = 0;
    }

    private void copyLogsToClipboard() {
        StringBuilder sb = new StringBuilder();
        for (String line : LOG_CACHE) sb.append(line).append('\n');
        if (sb.length() == 0) {
            Toast.makeText(this, "No logs to copy", Toast.LENGTH_SHORT).show();
            return;
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("Matrix Dumper Log", sb.toString()));
        Toast.makeText(this, "Logs copied to clipboard", Toast.LENGTH_SHORT).show();
    }

    private void appendLine(String line) {
        if (line == null) return;
        runOnUiThread(() -> {
            int color = colorForLine(line);

            // Footer live updates
            if (line.contains("] [DONE]"))          updateFooter("Dump complete", true);
            else if (line.contains("] [INJECT]"))   updateFooter("Injecting Frida...", false);
            else if (line.contains("] [SCAN]")) {
                if (line.contains("[+] DEX") || line.contains("[+] Found")) {
                    dexFound++;
                    footerDexCount.setText("DEX: " + dexFound);
                    pulseDexCount();
                }
                updateFooter("Scanning memory...", false);
            }
            else if (line.contains("] [PID]") && line.contains("PID:"))
                updateFooter("Process found, injecting...", false);
            else if (line.contains("] [LAUNCH]"))   updateFooter("Launching target app...", false);
            else if (line.contains("] [EXTRACT]"))  updateFooter("Extracting binary...", false);
            else if (line.contains("] [ERROR]"))    updateFooter("Error — see log", true);

            SpannableString ss = new SpannableString(line + "\n");
            ss.setSpan(new ForegroundColorSpan(color), 0, ss.length(), 0);
            logView.append(ss);
            scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }

    private int colorForLine(String line) {
        if (line.contains("] [DONE]") && (line.contains("[OK]") || line.contains("COMPLETE")))
            return Color.parseColor("#00E676");
        if (line.contains("] [DONE]"))    return Color.parseColor("#69F0AE");
        if (line.contains("] [ERROR]"))   return Color.parseColor("#FF4444");
        if (line.contains("] [WARN]"))    return Color.parseColor("#FF6E40");
        if (line.contains("] [BYPASS]"))  return Color.parseColor("#CE93D8");
        if (line.contains("] [INJECT]"))  return Color.parseColor("#29B6F6");
        if (line.contains("] [SCAN]"))    return Color.parseColor("#FFB74D");
        if (line.contains("] [PID]"))     return Color.parseColor("#00BCD4");
        if (line.contains("] [ROOT]"))    return Color.parseColor("#40C4FF");
        if (line.contains("] [EXTRACT]")) return Color.parseColor("#2196F3");
        if (line.contains("] [SCRIPT]"))  return Color.parseColor("#B39DDB");
        if (line.contains("] [LAUNCH]"))  return Color.parseColor("#CDDC39");
        if (line.contains("] [FRIDA]"))   return Color.parseColor("#EEEEEE");
        if (line.contains("] [INIT]"))    return Color.parseColor("#9E9E9E");
        if (line.contains("══") || line.contains("──"))
            return Color.parseColor("#000000");
        return Color.parseColor("#AAAAAA");
    }

    private void onDumpDone(int dex, int code) {
        runOnUiThread(() -> {
            long elapsed = FINAL_SECS > 0 ? FINAL_SECS
                         : (System.currentTimeMillis() - startTime) / 1000;
            footerDexCount.setText("DEX: " + dex);
            footerDexCount.setTextColor(
                dex > 0 ? Color.parseColor("#00E676") : Color.parseColor("#FF4444"));
            updateFooter(
                dex > 0 ? "Done in " + elapsed + "s — " + dex + " file(s) saved"
                        : "Finished in " + elapsed + "s — no DEX found",
                true);
            pulseDexCount();
            flashLogView();
        });
    }

    private void updateFooter(String status, boolean done) {
        runOnUiThread(() -> {
            if (footerStatus != null) {
                footerStatus.setText(status);
                footerStatus.setTextColor(done
                    ? Color.parseColor("#000000")
                    : Color.parseColor("#000000"));
            }
        });
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        overridePendingTransition(R.anim.fade_in_main, R.anim.slide_out_right);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        try { unregisterReceiver(receiver); } catch (Exception ignored) {}
    }

    private void pulseDexCount() {
        if (footerDexCount == null) return;
        ObjectAnimator scaleX = ObjectAnimator.ofFloat(footerDexCount, "scaleX", 1f, 1.6f, 1f);
        ObjectAnimator scaleY = ObjectAnimator.ofFloat(footerDexCount, "scaleY", 1f, 1.6f, 1f);
        scaleX.setDuration(380);
        scaleY.setDuration(380);
        scaleX.setInterpolator(new OvershootInterpolator(2f));
        scaleY.setInterpolator(new OvershootInterpolator(2f));
        AnimatorSet set = new AnimatorSet();
        set.playTogether(scaleX, scaleY);
        set.start();
    }

    private void flashLogView() {
        if (logView == null) return;
        ObjectAnimator flash = ObjectAnimator.ofFloat(logView, "alpha", 0.2f, 1f);
        flash.setDuration(700);
        flash.setInterpolator(new AccelerateDecelerateInterpolator());
        flash.start();
    }
}
