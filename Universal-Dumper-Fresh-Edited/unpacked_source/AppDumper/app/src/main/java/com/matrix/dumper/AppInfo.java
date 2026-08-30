package com.matrix.dumper;

import android.graphics.drawable.Drawable;

public class AppInfo {
    public String appName;
    public String packageName;
    public String apkPath;
    public Drawable icon;
    public ProtectionType protection = ProtectionType.UNKNOWN;

    public enum ProtectionType {
        // ── Chinese packers ───────────────────────────────────────────────────
        IJIAMI          ("爱加密 ijiami",        "#E91E63"),
        JIAGU_360       ("360加固",              "#4CAF50"),
        OPPO_ZEUS       ("OPPO加固 Zeus",        "#FF5722"),
        TENCENT_LEGU    ("Tencent Legu",        "#EF5350"),
        TENCENT_TPSHELL ("Tencent TPShell",     "#FF7043"),
        BAIDU           ("百度加固 Baidu",        "#2196F3"),
        BANGCLE         ("Bangcle / SecShell",  "#009688"),
        NETEASE         ("网易易盾 NetEase",      "#00BCD4"),
        NQ_SHIELD       ("NQ Shield",           "#795548"),
        ALIBABA         ("Alibaba mPaaS",       "#FF9800"),
        SHADOW_SAFETY   ("ShadowSafety / JAQ",  "#9C27B0"),
        NAGAPT          ("Nagapt",              "#8BC34A"),
        // ── International packers ─────────────────────────────────────────────
        DEXPROTECTOR    ("DexProtector",        "#673AB7"),
        APPDOME         ("Appdome",             "#F44336"),
        DPT_SHELL       ("DPT Shell",           "#FF6F00"),
        // ── Meta ─────────────────────────────────────────────────────────────
        NONE            ("No Protection",       "#455A64"),
        UNKNOWN         ("Unknown",             "#9E9E9E");

        public final String label;
        public final String color;

        ProtectionType(String label, String color) {
            this.label = label;
            this.color = color;
        }
    }
}
