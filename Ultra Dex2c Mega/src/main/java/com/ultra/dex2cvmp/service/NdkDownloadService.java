package com.ultra.dex2cvmp.service;

import android.app.*;
import android.content.*;
import android.os.*;
import androidx.core.app.NotificationCompat;
import com.ultra.dex2cvmp.R;

import android.system.ErrnoException;
import android.system.Os;
import java.io.*;

/**
 * NdkDownloadService — foreground service that downloads and extracts the
 * ARM-native clang++ compiler package from GitHub.
 *
 * Auto-detects device ABI (arm64 or arm32) and picks the right tar.gz.
 * WakeLock keeps the CPU alive so the download finishes even with the screen off.
 * Survives app close / swipe-away.
 */
public class NdkDownloadService extends Service {

    public static final String ACTION_START  = "com.ultra.dex2cvmp.ndk.START";
    public static final String ACTION_CANCEL = "com.ultra.dex2cvmp.ndk.CANCEL";

    private static final String CHANNEL_ID = "ndk_download";
    private static final int    NOTIF_ID   = 2001;

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

        startForeground(NOTIF_ID, buildNotification("Starting extraction…", 0));
        acquireWakeLock();
        RUNNING   = true;
        LAST_PCT  = 0;
        LAST_MSG  = "Starting…";
        cancelled = false;

        worker = new Thread(this::doDownload, "NdkDownload");
        worker.start();
        return START_NOT_STICKY;
    }

    // Not used — bundled NDK removed. Service retained as host for TarInputStream/TarEntry.
    private void doDownload() {
        RUNNING = false;
        releaseWakeLock();
        stopSelf();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Notification buildNotification(String text, int pct) {
        Intent open = new Intent(this, com.ultra.dex2cvmp.ui.CompilerSetupActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent cancelIntent = new Intent(this, NdkDownloadService.class);
        cancelIntent.setAction(ACTION_CANCEL);
        PendingIntent cancelPi = PendingIntent.getService(this, 1, cancelIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        NotificationCompat.Builder b = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("Ultra Dex2C-VMP · Compiler Download")
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
                    CHANNEL_ID, "Compiler Download", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("Shows compiler download progress");
            ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(ch);
        }
    }

    private void acquireWakeLock() {
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm != null) {
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Dex2c::NdkDownload");
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

    // ── Minimal tar reader ────────────────────────────────────────────────────

    public static class TarEntry {
        public String  name;
        public int     mode;
        public long    size;
        public boolean isDirectory;
        public boolean isSymlink;   // TAR type '2'
        public String  linkTarget;  // symlink target path (bytes 157-256 in header)
    }

    public static class TarInputStream extends InputStream {
        private final InputStream in;
        private long remaining;
        private long entrySize; // original size of current entry, for padding

        public TarInputStream(InputStream in) { this.in = in; this.remaining = 0; this.entrySize = 0; }

        public TarEntry nextEntry() throws IOException {
            // GNU tar stores long paths (>100 chars) as a preceding special entry:
            //   type 'L'  (0x4C)  → data = full filename  (././@LongLink)
            //   type 'K'  (0x4B)  → data = full symlink target
            // PAX extended headers (type 'x' / 'g') are also skipped gracefully.
            String pendingLongName   = null;
            String pendingLongTarget = null;

            while (true) {
                skipRemaining();
                byte[] hdr = new byte[512];
                if (readFully(hdr) < 512) return null;
                boolean allZero = true;
                for (byte b : hdr) if (b != 0) { allZero = false; break; }
                if (allZero) return null;

                char type = (char)(hdr[156] & 0xFF);
                long size = readOct(hdr, 124, 12);
                remaining = size;
                entrySize = size;

                if (type == 'L') {
                    // Next entry's full name is in this entry's data
                    pendingLongName = readDataAsString();
                    continue;
                }
                if (type == 'K') {
                    // Next entry's full symlink target is in this entry's data
                    pendingLongTarget = readDataAsString();
                    continue;
                }
                if (type == 'x' || type == 'g') {
                    // PAX extended header — skip data, parse minimal path= key if present
                    byte[] pax = new byte[(int) Math.min(size, 65536)];
                    int paxRead = readFully(pax);
                    String paxStr = new String(pax, 0, paxRead, "UTF-8");
                    for (String line : paxStr.split("\n")) {
                        // format: "<len> <key>=<value>"
                        int eq = line.indexOf('=');
                        if (eq < 0) continue;
                        String kv = line.substring(line.indexOf(' ') + 1);
                        eq = kv.indexOf('=');
                        if (eq < 0) continue;
                        String key = kv.substring(0, eq);
                        String val = kv.substring(eq + 1);
                        if ("path".equals(key))     pendingLongName   = val;
                        if ("linkpath".equals(key)) pendingLongTarget = val;
                    }
                    remaining = 0; // already consumed above
                    entrySize = size; // still need to align padding
                    continue;
                }

                // Normal entry
                TarEntry e   = new TarEntry();
                e.name        = pendingLongName   != null ? pendingLongName   : readStr(hdr, 0, 100);
                e.mode        = (int) readOct(hdr, 100, 8);
                e.size        = size;
                e.isDirectory = type == '5' || e.name.endsWith("/");
                e.isSymlink   = type == '2';
                if (e.isSymlink) {
                    e.linkTarget = pendingLongTarget != null ? pendingLongTarget : readStr(hdr, 157, 100);
                }
                remaining = e.size;
                entrySize = e.size;
                pendingLongName   = null;
                pendingLongTarget = null;
                return e;
            }
        }

        /** Read all remaining bytes of the current entry as a null-stripped UTF-8 string. */
        private String readDataAsString() throws IOException {
            byte[] buf = new byte[(int) Math.min(remaining, 4096)];
            int n = readFully(buf);
            // trim trailing nulls / newlines
            int end = n;
            while (end > 0 && (buf[end-1] == 0 || buf[end-1] == '\n')) end--;
            remaining = 0;
            return new String(buf, 0, end, "UTF-8");
        }

        private void skipRemaining() throws IOException {
            // Skip any unread bytes from the previous entry's data
            while (remaining > 0) {
                long n = in.skip(remaining);
                if (n <= 0) { byte[] b = new byte[1]; if (in.read(b) == -1) break; remaining--; }
                else remaining -= n;
            }
            // Skip padding to next 512-byte boundary using the ORIGINAL entry size
            long pad = (512 - (entrySize % 512)) % 512;
            if (pad > 0) { byte[] p = new byte[(int)pad]; readFully(p); }
            entrySize = 0;
        }

        @Override public int read(byte[] buf, int off, int len) throws IOException {
            if (remaining <= 0) return -1;
            int n = in.read(buf, off, (int) Math.min(len, remaining));
            if (n > 0) remaining -= n;
            return n;
        }
        @Override public int read() throws IOException {
            byte[] b = {0}; int n = read(b, 0, 1); return n == -1 ? -1 : b[0] & 0xFF;
        }

        private int readFully(byte[] buf) throws IOException {
            int t = 0;
            while (t < buf.length) { int n = in.read(buf, t, buf.length - t); if (n < 0) break; t += n; }
            return t;
        }
        private String readStr(byte[] b, int off, int len) {
            int e = off; while (e < off + len && b[e] != 0) e++;
            return new String(b, off, e - off);
        }
        private long readOct(byte[] b, int off, int len) {
            long v = 0;
            for (int i = off; i < off + len; i++) {
                char c = (char)(b[i] & 0xFF);
                if (c == ' ' || c == 0) continue;
                if (c < '0' || c > '7') break;
                v = v * 8 + (c - '0');
            }
            return v;
        }
    }
}
