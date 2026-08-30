package com.matrix.dumper;

import android.util.Log;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

public class ShellUtils {

    private static final String TAG = "ShellUtils";

    public interface OutputCallback {
        void onLine(String line);
        void onDone(int exitCode);
    }

    public static String runAsRoot(String cmd) {
        StringBuilder output = new StringBuilder();
        try {
            Process process = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(cmd + "\n");
            os.writeBytes("exit\n");
            os.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
        } catch (Exception e) {
            Log.e(TAG, "runAsRoot failed: " + cmd, e);
        }
        return output.toString().trim();
    }

    public static void runAsRootStreaming(String cmd, OutputCallback cb) {
        new Thread(() -> {
            try {
                Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});

                Thread stdoutThread = new Thread(() -> {
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(process.getInputStream()))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            cb.onLine(line);
                        }
                    } catch (IOException e) {
                        Log.e(TAG, "stdout read error", e);
                    }
                });

                Thread stderrThread = new Thread(() -> {
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(process.getErrorStream()))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            cb.onLine("[ERR] " + line);
                        }
                    } catch (IOException e) {
                        Log.e(TAG, "stderr read error", e);
                    }
                });

                stdoutThread.start();
                stderrThread.start();
                stdoutThread.join();
                stderrThread.join();

                int code = process.waitFor();
                cb.onDone(code);
            } catch (Exception e) {
                Log.e(TAG, "runAsRootStreaming failed", e);
                cb.onLine("[ERROR] " + e.getMessage());
                cb.onDone(-1);
            }
        }).start();
    }

    public static String getPid(String packageName) {
        String result = runAsRoot("pidof " + packageName);
        if (result.isEmpty()) {
            result = runAsRoot("ps -A | grep " + packageName + " | awk '{print $2}' | head -1");
        }
        return result.trim().split("\\s+")[0];
    }

    public static boolean isRootAvailable() {
        try {
            Process process = Runtime.getRuntime().exec("su -c id");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String result = reader.readLine();
            process.destroy();
            return result != null && result.contains("uid=0");
        } catch (Exception e) {
            return false;
        }
    }
}
