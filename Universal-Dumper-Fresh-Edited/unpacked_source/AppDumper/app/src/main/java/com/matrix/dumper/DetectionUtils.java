package com.matrix.dumper;

import android.util.Log;

import java.io.File;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class DetectionUtils {

    private static final String TAG = "DetectionUtils";

    /**
     * Scans the APK zip entries to identify which packer (if any) protects the app.
     * Detection is ordered from most-distinctive to least, so the first match wins.
     */
    public static AppInfo.ProtectionType detect(String apkPath) {
        if (apkPath == null || !new File(apkPath).exists()) {
            return AppInfo.ProtectionType.UNKNOWN;
        }
        try (ZipFile zf = new ZipFile(apkPath)) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName().toLowerCase();

                // ── ijiami 爱加密 ──────────────────────────────────────────────
                // libijcore.so / libdtcagent.so / libdtcloader.so — ijiami native loaders
                // assets/ijiami.dat                               — ijiami config blob
                // assets/ijm_*                                    — ijiami payload assets
                // classes.zip (inside APK root)                   — ijiami wraps DEX in zip
                if (name.endsWith("libijcore.so") ||
                    name.endsWith("libdtcagent.so") ||
                    name.endsWith("libdtcloader.so") ||
                    name.endsWith("libexec.so") ||
                    name.equals("assets/ijiami.dat") ||
                    (name.startsWith("assets/ijm_")) ||
                    name.equals("classes.zip")) {
                    return AppInfo.ProtectionType.IJIAMI;
                }

                // ── OPPO 加固 Zeus (omas) ─────────────────────────────────────
                // libomas.so          — OPPO Mobile Auth System, the primary loader.
                // libzeus_direct_dex.so — Zeus DEX decryptor/injector native lib.
                // assets/classes.png  — OPPO hides the encrypted real DEX as a .png.
                // Manifest Application: com.omes.omas.ProxyApplication (checked below).
                // Numeric-only asset (e.g. assets/478057776) — Zeus plugin bundle;
                // matched by a pure-digits filename pattern in assets/.
                if (name.endsWith("libomas.so") ||
                    name.endsWith("libzeus_direct_dex.so") ||
                    name.equals("assets/classes.png")) {
                    return AppInfo.ProtectionType.OPPO_ZEUS;
                }
                // Pure-digits asset filename = OPPO Zeus plugin bundle
                if (name.startsWith("assets/")) {
                    String assetFile = name.substring("assets/".length());
                    if (!assetFile.isEmpty() && assetFile.matches("[0-9]+")) {
                        return AppInfo.ProtectionType.OPPO_ZEUS;
                    }
                }

                // ── 360 Jiagu / SecNeo ────────────────────────────────────────
                // libjiagu*.so are definitively 360 — no other SDK uses this name.
                // assets/jiagu_* — 360 payload assets.
                if (name.endsWith("libjiagu.so") ||
                    name.endsWith("libjiagu_a64.so") ||
                    name.endsWith("libjiagu_x64.so") ||
                    name.endsWith("libjiagu_ls.so") ||
                    name.startsWith("assets/jiagu_") ||
                    name.contains("com.qihoo.util") ||
                    name.contains("/com.qihoo/")) {
                    return AppInfo.ProtectionType.JIAGU_360;
                }

                // ── Tencent Legu ──────────────────────────────────────────────
                // libshell-super.2019.so / libshell-super.so — current Legu shell libs.
                // libshella-* / libshellx-*                  — per-arch Legu variants.
                // libdexhelper.so                            — Legu DEX helper.
                // assets/*tosversion                         — Legu version marker.
                if (name.endsWith("libshell-super.2019.so") ||
                    name.endsWith("libshell-super.so") ||
                    name.contains("libshella-") ||
                    name.contains("libshellx-") ||
                    name.endsWith("libdexhelper.so") ||
                    (name.startsWith("assets/") && name.endsWith("tosversion"))) {
                    return AppInfo.ProtectionType.TENCENT_LEGU;
                }

                // ── Tencent TPShell ───────────────────────────────────────────
                // Separate Tencent product — distinct from Legu.
                // libtpss.so / libtprt.so / libtpmss.so — TPShell native libs.
                if (name.endsWith("libtpss.so") ||
                    name.endsWith("libtprt.so") ||
                    name.endsWith("libtpmss.so") ||
                    (name.startsWith("assets/") && name.startsWith("assets/tencent_protect"))) {
                    return AppInfo.ProtectionType.TENCENT_TPSHELL;
                }

                // ── Baidu Shield / ASM ────────────────────────────────────────
                // libbaiduprotect.so / libbaidu-protect.so — current and legacy names.
                // libsecexe.so / libsecmain.so / libsecshell.so — Baidu sub-loaders.
                // assets/baiduprotect* / assets/bd_protect* / assets/moba_* — payloads.
                if (name.endsWith("libbaiduprotect.so") ||
                    name.endsWith("libbaidu-protect.so") ||
                    name.endsWith("libsecexe.so") ||
                    name.endsWith("libsecmain.so") ||
                    name.startsWith("assets/baiduprotect") ||
                    name.startsWith("assets/bd_protect") ||
                    name.startsWith("assets/moba_")) {
                    return AppInfo.ProtectionType.BAIDU;
                }

                // ── Bangcle / SecShell ────────────────────────────────────────
                // libsecshell.so          — Bangcle native shell.
                // libbangcle*.so          — branded variant.
                // assets/bangcle_classes* — Bangcle wraps classes in a zip asset.
                if (name.endsWith("libsecshell.so") ||
                    name.contains("libbangcle") ||
                    (name.startsWith("assets/") && name.contains("bangcle_classes"))) {
                    return AppInfo.ProtectionType.BANGCLE;
                }

                // ── DexProtector (Guardsquare) ────────────────────────────────
                // libdexprotector.so / libdexprotector_*.so — the loader shared lib.
                // assets/dexprotector*                      — encrypted payload.
                if (name.endsWith("libdexprotector.so") ||
                    name.contains("libdexprotector_") ||
                    (name.startsWith("assets/") && name.contains("dexprotector"))) {
                    return AppInfo.ProtectionType.DEXPROTECTOR;
                }

                // ── NetEase YiDun (网易易盾) ──────────────────────────────────
                // libnesec.so / libneprotect.so — YiDun native libs.
                // assets/yidun*                — YiDun payload assets.
                if (name.endsWith("libnesec.so") ||
                    name.endsWith("libneprotect.so") ||
                    (name.startsWith("assets/") && name.startsWith("assets/yidun"))) {
                    return AppInfo.ProtectionType.NETEASE;
                }

                // ── NQ Shield ─────────────────────────────────────────────────
                // libnqshield.so  — NQ Mobile native shield lib.
                // assets/nqshield*
                if (name.endsWith("libnqshield.so") ||
                    (name.startsWith("assets/") && name.startsWith("assets/nqshield"))) {
                    return AppInfo.ProtectionType.NQ_SHIELD;
                }

                // ── Alibaba mPaaS / sgmain ────────────────────────────────────
                // libsgmain.so              — Alibaba mobile security main lib.
                // libandroid-aliprotect.so  — branded alias.
                // assets/aliprotect*        — encrypted payload.
                // Note: libsgcore.so alone is NOT enough — it is also used by
                // ShadowSafety/JAQ (matched below). Only match sgmain here.
                if (name.endsWith("libsgmain.so") ||
                    name.contains("libandroid-aliprotect") ||
                    (name.startsWith("assets/") && name.startsWith("assets/aliprotect"))) {
                    return AppInfo.ProtectionType.ALIBABA;
                }

                // ── ShadowSafety (Alibaba JAQ + DroidPlugin) ──────────────────
                // liblywmaliagainstid.so              — Alibaba anti-ID, unique to JAQ.
                // libjiagu_sdk_droidpluginengine*.so  — DroidPlugin with JAQ shell.
                // libsgcore.so + libpglarmor.so       — paired: sgcore alone is generic,
                //                                       but with pglarmor it is JAQ.
                if (name.endsWith("liblywmaliagainstid.so") ||
                    name.contains("libjiagu_sdk_droidplugin") ||
                    name.endsWith("libpglarmor.so") ||
                    name.endsWith("libsgcore.so")) {
                    return AppInfo.ProtectionType.SHADOW_SAFETY;
                }

                // ── Nagapt ────────────────────────────────────────────────────
                if (name.endsWith("libnaga.so") ||
                    name.endsWith("libnagapt.so") ||
                    (name.startsWith("assets/") && name.startsWith("assets/naga"))) {
                    return AppInfo.ProtectionType.NAGAPT;
                }

                // ── Appdome ───────────────────────────────────────────────────
                if (name.contains("libappdome") ||
                    (name.startsWith("assets/") && name.startsWith("assets/appdome"))) {
                    return AppInfo.ProtectionType.APPDOME;
                }

                // ── DPT Shell ─────────────────────────────────────────────────
                // d_shell_data_001 is the primary DPT Shell asset — highly distinctive.
                // libdpt.so / libdptsec.so are the native loaders.
                // loading.json is the DPT config blob (present alongside d_shell_data_001).
                // Obfuscated all-letter asset names (OooooooOooo, vwwwwwwvwww) are
                // generated by DPT's asset obfuscation pass; matched by letter-only pattern.
                if (name.equals("assets/d_shell_data_001") ||
                    name.endsWith("libdpt.so") ||
                    name.endsWith("libdptsec.so") ||
                    name.endsWith("libdptshell.so")) {
                    return AppInfo.ProtectionType.DPT_SHELL;
                }
            }

            // ── Manifest binary scan ─────────────────────────────────────────
            // Binary AXML stores strings as UTF-16LE in the string pool.
            // We scan raw ISO-8859-1 bytes so single-byte chars from UTF-16LE
            // are still visible as ASCII substrings (null bytes between chars
            // don't break contains() on the raw string).
            ZipEntry manifest = zf.getEntry("AndroidManifest.xml");
            if (manifest != null) {
                try (InputStream is = zf.getInputStream(manifest)) {
                    byte[] buf = is.readAllBytes();
                    String raw = new String(buf, java.nio.charset.StandardCharsets.ISO_8859_1);

                    // ── OPPO Zeus manifest check ──────────────────────────────
                    // Application class is com.omes.omas.ProxyApplication.
                    // "omas" alone is a strong signal; paired with "ProxyApplication"
                    // or the APP_NAME meta-data pattern it is definitive.
                    if (raw.contains("omas.ProxyApplication") ||
                            (raw.contains("libomas") && raw.contains("ProxyApplication")) ||
                            (raw.contains("omas") && raw.contains("zeus_direct_dex"))) {
                        return AppInfo.ProtectionType.OPPO_ZEUS;
                    }

                    // ── DPT Shell manifest check ──────────────────────────────
                    // BvdKJmTZwa.ProxyApplication (obfuscated pkg varies, class name fixed).
                    if (raw.contains("ProxyApplication") &&
                            (raw.contains("d_shell") || raw.contains("dptshell") ||
                             raw.contains("libdpt"))) {
                        return AppInfo.ProtectionType.DPT_SHELL;
                    }
                } catch (Exception ignored) {}
            }

        } catch (Exception e) {
            Log.e(TAG, "Failed to scan APK: " + apkPath, e);
        }
        return AppInfo.ProtectionType.NONE;
    }
}
