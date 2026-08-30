package com.ultra.dex2cvmp.update;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import com.ultra.dex2cvmp.Vault;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class UpdateChecker {

    public interface Callback {
        void onUpdateAvailable(String versionName, String changelog, String apkUrl);
        void onNoUpdate();
    }

    public static void check(Context ctx, Callback cb) {
        long installedCode;
        try {
            PackageInfo pi = ctx.getPackageManager()
                    .getPackageInfo(ctx.getPackageName(), 0);
            installedCode = Build.VERSION.SDK_INT >= 28
                    ? pi.getLongVersionCode()
                    : pi.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            post(cb::onNoUpdate);
            return;
        }

        final long currentCode = installedCode;

        new Thread(() -> {
            try {
                String url = Vault.c() + "?t=" + System.currentTimeMillis();
                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(15000);
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Cache-Control", "no-cache, no-store");
                conn.setRequestProperty("Pragma", "no-cache");

                int code = conn.getResponseCode();
                if (code != 200) {
                    conn.disconnect();
                    post(cb::onNoUpdate);
                    return;
                }

                StringBuilder sb = new StringBuilder();
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line);
                }
                conn.disconnect();

                JSONObject json    = new JSONObject(sb.toString());
                long remoteCode    = json.getLong("version_code");

                if (remoteCode > currentCode) {
                    String vName     = json.optString("version_name", "");
                    String changelog = json.optString("changelog", "Bug fixes and improvements.");
                    String apkUrl    = json.optString("apk_url", "");
                    post(() -> cb.onUpdateAvailable(vName, changelog, apkUrl));
                } else {
                    post(cb::onNoUpdate);
                }
            } catch (Exception e) {
                post(cb::onNoUpdate);
            }
        }).start();
    }

    private static void post(Runnable r) {
        new Handler(Looper.getMainLooper()).post(r);
    }
}
