package com.matrix.dumper;

import android.content.Context;
import android.content.SharedPreferences;

public class ThemeManager {

    private static final String PREFS = "matrix_dumper_prefs";
    private static final String KEY   = "dark_mode";

    public static boolean isDark(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                  .getBoolean(KEY, false);
    }

    public static void setDark(Context ctx, boolean dark) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
           .edit().putBoolean(KEY, dark).apply();
    }

    public static void toggle(Context ctx) {
        setDark(ctx, !isDark(ctx));
    }

    public static int bg(Context ctx)          { return isDark(ctx) ? 0xFF000000 : 0xFFFFFFFF; }
    public static int surface(Context ctx)     { return isDark(ctx) ? 0xFF0D0D0D : 0xFFF5F5F5; }
    public static int divider(Context ctx)     { return isDark(ctx) ? 0xFF1A1A1A : 0xFFE0E0E0; }
    public static int textPrimary(Context ctx) { return isDark(ctx) ? 0xFFFFFFFF : 0xFF111111; }
    public static int textSecondary(Context ctx){ return isDark(ctx) ? 0xFF000000 : 0xFF000000; }
    public static int searchBg(Context ctx)    { return isDark(ctx) ? 0xFF1A1A1A : 0xFFEEEEEE; }
    public static int searchText(Context ctx)  { return isDark(ctx) ? 0xFFFFFFFF : 0xFF111111; }
    public static int searchHint(Context ctx)  { return isDark(ctx) ? 0xFF000000 : 0xFF999999; }
    public static int headerBg(Context ctx)    { return isDark(ctx) ? 0xFF0A0A0A : 0xFFFAFAFA; }
    public static int toggleText(Context ctx)  { return isDark(ctx) ? 0xFF000000 : 0xFF000000; }
}
