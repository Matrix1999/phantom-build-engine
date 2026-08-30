package com.ultra.dex2cvmp.service;

import android.app.*;
import android.content.*;
import android.os.*;
import androidx.core.app.NotificationCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import com.ultra.dex2cvmp.R;
import com.ultra.dex2cvmp.engine.CompilerManager;

import java.io.*;

/**
 * PythonDownloadService — foreground service that downloads and extracts
 * a standalone Python 3 ARM64 binary package (no Termux required).
 *
 * Mirrors NdkDownloadService exactly:
 *   • Downloads ARM64 tar.gz from GitHub
 *   • Extracts to filesDir/python3/
 *   • WakeLock keeps CPU alive so download finishes with screen off
 *   • Survives app close / swipe-away
 */
public class PythonDownloadService extends Service {

    public static final String ACTION_START  = "com.ultra.dex2cvmp.python.START";
    public static final String ACTION_CANCEL = "com.ultra.dex2cvmp.python.CANCEL";

    public static final String BROADCAST   = "com.ultra.dex2cvmp.python.PROGRESS";
    public static final String EXTRA_PCT   = "pct";
    public static final String EXTRA_MSG   = "msg";
    public static final String EXTRA_DONE  = "done";
    public static final String EXTRA_ERROR = "error";

    private static final String CHANNEL_ID = "python_download";
    private static final int    NOTIF_ID   = 2002;

    /** Global state — lets CompilerSetupActivity check status on resume. */
    public static volatile boolean RUNNING  = false;
    public static volatile int     LAST_PCT = 0;
    public static volatile String  LAST_MSG = "";

    private PowerManager.WakeLock wakeLock;
    private volatile boolean cancelled = false;
    private Thread worker;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_CANCEL.equals(intent.getAction())) {
            cancelled = true;
            if (worker != null) worker.interrupt();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (RUNNING) return START_NOT_STICKY;

        startForeground(NOTIF_ID, buildNotification("Starting download…", 0));
        acquireWakeLock();
        RUNNING   = true;
        LAST_PCT  = 0;
        LAST_MSG  = "Starting…";
        cancelled = false;

        worker = new Thread(this::doDownload, "PythonDownload");
        worker.start();
        return START_NOT_STICKY;
    }

    // ── Download + extract ────────────────────────────────────────────────────

    private void doDownload() {
        // Python 3 is now bundled in assets — no network download needed.
        // Just extract from the bundled asset if not already installed.
        CompilerManager cm = new CompilerManager(this);
        try {
            post(10, "Extracting bundled Python 3…");
            updateNotification("Extracting Python 3…", 10);

            boolean ok = cm.ensurePythonExtracted();

            if (ok) {
                post(100, "Python 3 ready! (ARM64)");
                updateNotification("Python 3 installed ✓", 100);
                broadcast(100, "Python 3 ready!", true, null);
            } else {
                broadcast(0, "Failed: extraction error", false, "Failed to extract bundled Python");
                updateNotification("Extraction failed", 0);
            }
        } catch (Exception e) {
            String err = e.getClass().getSimpleName() + ": " + e.getMessage();
            broadcast(0, "Failed: " + err, false, err);
            updateNotification("Failed", 0);
        } finally {
            RUNNING = false;
            releaseWakeLock();
            new Handler(Looper.getMainLooper()).postDelayed(this::stopSelf, 3000);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void post(int pct, String msg) {
        LAST_PCT = pct;
        LAST_MSG = msg;
        updateNotification(msg, pct);
        broadcast(pct, msg, false, null);
    }

    private void broadcast(int pct, String msg, boolean done, String error) {
        LAST_PCT = pct;
        LAST_MSG = msg;
        Intent i = new Intent(BROADCAST);
        i.putExtra(EXTRA_PCT,  pct);
        i.putExtra(EXTRA_MSG,  msg);
        i.putExtra(EXTRA_DONE, done);
        if (error != null) i.putExtra(EXTRA_ERROR, error);
        LocalBroadcastManager.getInstance(this).sendBroadcast(i);
    }

    private void updateNotification(String text, int pct) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIF_ID, buildNotification(text, pct));
    }

    private Notification buildNotification(String text, int pct) {
        Intent open = new Intent(this, com.ultra.dex2cvmp.ui.CompilerSetupActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent cancelIntent = new Intent(this, PythonDownloadService.class);
        cancelIntent.setAction(ACTION_CANCEL);
        PendingIntent cancelPi = PendingIntent.getService(this, 2, cancelIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        NotificationCompat.Builder b = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("Dex2c ─ Python Download")
                .setContentText(text)
                .setContentIntent(pi)
                .setOngoing(pct < 100)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Cancel", cancelPi);
        if (pct > 0 && pct < 100)
            b.setProgress(100, pct, false);
        else if (pct == 100)
            b.setProgress(0, 0, false).setSmallIcon(android.R.drawable.stat_sys_download_done);
        return b.build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "Python Download", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("Shows Python 3 download progress");
            ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(ch);
        }
    }

    private void acquireWakeLock() {
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm != null) {
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Dex2c::PythonDownload");
            wakeLock.acquire(30L * 60 * 1000);
        }
    }

    private void releaseWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        cancelled = true;
        RUNNING   = false;
        releaseWakeLock();
        super.onDestroy();
    }
}
