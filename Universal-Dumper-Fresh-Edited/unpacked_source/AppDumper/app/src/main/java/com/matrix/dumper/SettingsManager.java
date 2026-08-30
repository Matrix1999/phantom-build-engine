package com.matrix.dumper;

import android.content.Context;

public class SettingsManager {

    private static final String PREFS = "matrix_dumper_settings";

    public static int getExtraWaitSec(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                  .getInt("extra_wait_sec", 0);
    }
    public static void setExtraWaitSec(Context ctx, int sec) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
           .edit().putInt("extra_wait_sec", sec).apply();
    }

    public static boolean isMultiPass(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                  .getBoolean("multi_pass", false);
    }
    public static void setMultiPass(Context ctx, boolean v) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
           .edit().putBoolean("multi_pass", v).apply();
    }

    public static boolean isForceStop(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                  .getBoolean("force_stop", true);
    }
    public static void setForceStop(Context ctx, boolean v) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
           .edit().putBoolean("force_stop", v).apply();
    }
}
