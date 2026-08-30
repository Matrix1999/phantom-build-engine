package com.ultra.dex2cvmp.service;

import android.app.*;
import android.content.*;
import android.net.Uri;
import android.os.*;
import androidx.core.app.NotificationCompat;
import com.ultra.dex2cvmp.R;
import com.ultra.dex2cvmp.engine.ApkProtector;

public class ProtectionService extends Service {

    public static final String ACTION_START      = "com.ultra.dex2cvmp.START";
    public static final String ACTION_CANCEL     = "com.ultra.dex2cvmp.CANCEL";
    public static final String EXTRA_URI         = "uri";
    public static final String EXTRA_FILTER      = "filter";
    public static final String EXTRA_SIGN        = "sign";
    public static final String EXTRA_VMP         = "vmp";
    public static final String EXTRA_BLOCK_ROOTED = "block_rooted";

    public static final String BROADCAST_PROGRESS = "com.ultra.dex2cvmp.PROGRESS";
    public static final String EXTRA_PERCENT   = "percent";
    public static final String EXTRA_MSG       = "msg";
    public static final String EXTRA_OUTPUT    = "output";
    public static final String EXTRA_ERROR     = "error";

    private static final String CHANNEL_ID   = "dex2c_protection";
    private static final int    NOTIF_ID     = 1001;
    private static final int    NOTIF_DONE   = 1002;

    /**
     * Static flag — survives activity restarts within the same process.
     * When the app is killed and reopened, this resets to false (service also dies),
     * so it correctly reflects "nothing running" in that case.
     */
    public static volatile boolean SERVICE_RUNNING = false;
    public static volatile String  LAST_STATUS     = "";
    public static volatile int     LAST_PROGRESS   = 0;

    /**
     * Active child OS processes (Python bridge, clang link step).
     * Set by engine classes so cancel() can forcibly kill them immediately.
     */
    public static volatile java.lang.Process ACTIVE_PROCESS = null;
    public static final java.util.concurrent.CopyOnWriteArrayList<java.lang.Process>
            ACTIVE_COMPILE_PROCS = new java.util.concurrent.CopyOnWriteArrayList<>();

    private PowerManager.WakeLock wakeLock;
    private volatile boolean running = false;
    private Thread workerThread;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Dex2c:WakeLock");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;

        if (ACTION_CANCEL.equals(intent.getAction())) {
            cancel();
            return START_NOT_STICKY;
        }

        if (ACTION_START.equals(intent.getAction())) {
            Uri     uri         = intent.getParcelableExtra(EXTRA_URI);
            String  flt         = intent.getStringExtra(EXTRA_FILTER);
            boolean sign        = intent.getBooleanExtra(EXTRA_SIGN,         false);
            boolean vmp         = intent.getBooleanExtra(EXTRA_VMP,          false);
            boolean blockRooted = intent.getBooleanExtra(EXTRA_BLOCK_ROOTED, false);
            startProtection(uri, flt, sign, vmp, blockRooted);
        }
        return START_NOT_STICKY;
    }

    private void startProtection(Uri uri, String filter, boolean sign, boolean vmp, boolean blockRooted) {
        if (running) return;
        running = true;
        SERVICE_RUNNING = true;
        LAST_STATUS     = "Starting...";
        LAST_PROGRESS   = 0;
        ACTIVE_PROCESS  = null;
        ACTIVE_COMPILE_PROCS.clear();

        startForeground(NOTIF_ID, buildRunningNotification("Starting...", 0));
        // 4-hour ceiling — covers even the longest Phantom-Level runs.
        // PARTIAL_WAKE_LOCK keeps the CPU alive with the screen off.
        if (!wakeLock.isHeld()) wakeLock.acquire(4 * 60 * 60 * 1000L);

        workerThread = new Thread(() -> {
            try {
                ApkProtector protector = new ApkProtector(getApplicationContext());
                protector.setProgressCallback((pct, msg) -> {
                    LAST_STATUS   = msg;
                    LAST_PROGRESS = pct;
                    broadcast(pct, msg, null, null);
                    updateRunningNotification(msg, pct);
                });
                String output = protector.protect(uri, filter, sign, vmp, blockRooted);
                broadcast(100, "Done!", output, null);
                finishWithSuccess("Protection complete! Output saved.");
            } catch (Exception e) {
                String err = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                broadcast(0, "Failed: " + err, null, err);
                finishWithError("Failed: " + err);
            }
        }, "Dex2c-Worker");
        workerThread.setPriority(Thread.MAX_PRIORITY);
        workerThread.start();
    }

    private void finishWithSuccess(String msg) {
        running = false;
        SERVICE_RUNNING = false;
        LAST_STATUS = msg;
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        // Remove the non-dismissible foreground notification
        stopForeground(STOP_FOREGROUND_REMOVE);
        // Post a NEW dismissible "done" notification
        postDoneNotification(msg, true);
        stopSelf();
    }

    private void finishWithError(String msg) {
        running = false;
        SERVICE_RUNNING = false;
        LAST_STATUS = msg;
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        stopForeground(STOP_FOREGROUND_REMOVE);
        postDoneNotification(msg, false);
        stopSelf();
    }

    private void cancel() {
        running = false;
        SERVICE_RUNNING = false;
        // Kill the active Python / clang-link process immediately
        java.lang.Process p = ACTIVE_PROCESS;
        if (p != null) { try { p.destroyForcibly(); } catch (Exception ignored) {} }
        ACTIVE_PROCESS = null;
        // Kill all parallel clang compile processes
        for (java.lang.Process cp : ACTIVE_COMPILE_PROCS) {
            try { cp.destroyForcibly(); } catch (Exception ignored) {}
        }
        ACTIVE_COMPILE_PROCS.clear();
        // Interrupt the Java worker thread (unblocks any remaining waitFor)
        if (workerThread != null) workerThread.interrupt();
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    // ── Notifications ─────────────────────────────────────────────────────────

    /** Ongoing, non-dismissible notification shown during processing. */
    private Notification buildRunningNotification(String msg, int pct) {
        NotificationCompat.Builder b = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Ultra Dex2C-VMP · Protecting")
                .setContentText(msg)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setPriority(NotificationCompat.PRIORITY_LOW);
        if (pct > 0 && pct < 100)
            b.setProgress(100, pct, false);
        else
            b.setProgress(100, 0, true);
        return b.build();
    }

    private void updateRunningNotification(String msg, int pct) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIF_ID, buildRunningNotification(msg, pct));
    }

    /** Dismissible notification posted after processing finishes or fails. */
    private void postDoneNotification(String msg, boolean success) {
        NotificationCompat.Builder b = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(success
                        ? android.R.drawable.ic_dialog_info
                        : android.R.drawable.ic_dialog_alert)
                .setContentTitle(success ? "Ultra Dex2C-VMP · Done ✓" : "Ultra Dex2C-VMP · Failed ✗")
                .setContentText(msg)
                .setAutoCancel(true)           // user can swipe to dismiss
                .setOngoing(false)             // NOT ongoing — fully dismissible
                .setPriority(NotificationCompat.PRIORITY_DEFAULT);
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIF_DONE, b.build());
    }

    private void createNotificationChannel() {
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "APK Protection", NotificationManager.IMPORTANCE_DEFAULT);
        ch.setDescription("Dex2c protection progress and results");
        // IMPORTANCE_DEFAULT ensures aggressive OEMs (Samsung/Xiaomi/OPPO) do not
        // suppress the notification, which would cause the foreground state to be lost.
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) nm.createNotificationChannel(ch);
    }

    private void broadcast(int pct, String msg, String output, String error) {
        Intent i = new Intent(BROADCAST_PROGRESS);
        i.putExtra(EXTRA_PERCENT, pct);
        i.putExtra(EXTRA_MSG,     msg);
        if (output != null) i.putExtra(EXTRA_OUTPUT, output);
        if (error  != null) i.putExtra(EXTRA_ERROR,  error);
        sendBroadcast(i);
    }

    /**
     * Android 15 (API 35)+ calls this when a foreground service exceeds its allowed
     * background runtime. We cancel cleanly rather than waiting for an ANR.
     * No @Override — compileSdk may be < 35; virtual dispatch still routes here at runtime.
     */
    public void onTimeout(int startId, int fgsType) {
        broadcast(0, "Cancelled: system background time limit reached.", null,
                "Foreground service timeout (Android 15+)");
        cancel();
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        super.onDestroy();
        running = false;
        SERVICE_RUNNING = false;
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
    }
}
