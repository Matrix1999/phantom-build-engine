package com.ultra.dex2cvmp.engine.packer;

import java.io.*;
import java.util.Enumeration;
import java.util.zip.*;

/**
 * APK extract + repack utility.
 *
 * Moved from timscriptov/ApkProtector-multiplatform DexGuard/Desktop;
 * surgical edits: removed LoggerUtils, desktop-only DexPatcher/smali,
 * Preferences and Constants references — all paths are now explicit params.
 */
public class FastZip {

    /** Extensions that must be stored uncompressed in the APK. */
    public static final String[] STORED_EXTENSIONS = {
            ".arsc", ".jpg", ".jpeg", ".png", ".gif",
            ".wav", ".mp2", ".mp3", ".ogg", ".aac",
            ".mpg", ".mpeg", ".mid", ".midi", ".smf", ".jet",
            ".rtttl", ".imy", ".xmf", ".mp4", ".m4a", ".m4v",
            ".3gp", ".3gpp", ".3g2", ".3gpp2", ".amr", ".awb",
            ".wma", ".wmv"
    };

    /**
     * Extract AndroidManifest.xml and all classes*.dex from the APK
     * into {@code extractDir}.
     */
    public static void extract(File zip, File extractDir) throws IOException {
        extractDir.mkdirs();
        ZipFile apk = new ZipFile(zip);
        Enumeration<? extends ZipEntry> entries = apk.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            if (entry.isDirectory()) continue;
            if (name.equals("AndroidManifest.xml")
                    || name.matches("classes\\.dex")
                    || name.matches("classes\\d+\\.dex")) {
                File out = new File(extractDir, name);
                out.getParentFile().mkdirs();
                try (InputStream is = apk.getInputStream(entry);
                     FileOutputStream fos = new FileOutputStream(out)) {
                    copyStream(is, fos);
                }
            }
        }
        apk.close();
    }

    /**
     * Repack the protected APK.
     *
     * @param inZip       Original (input) APK.
     * @param outZip      Output protected APK.
     * @param stubDex     Pre-built stub classes.dex bytes (ProxyApplication + loader).
     * @param assetsDir   Directory whose contents become assets/<assetDirName>/ entries.
     * @param assetDirName Name of the asset sub-directory in the output APK (e.g. "dp-lib").
     * @param patchedManifest Patched binary AndroidManifest.xml bytes.
     */
    public static void repack(File inZip, File outZip,
                              byte[] stubDex,
                              File assetsDir, String assetDirName,
                              byte[] patchedManifest) throws Exception {
        ZipFile zipFile = new ZipFile(inZip);
        Enumeration<? extends ZipEntry> entries = zipFile.entries();

        try (FastZipOutputStream fzos = new FastZipOutputStream(
                new BufferedOutputStream(new FileOutputStream(outZip)))) {

            // 1. Write patched stub classes.dex
            fzos.putNextEntry(new ZipEntry("classes.dex"));
            fzos.write(stubDex);
            fzos.closeEntry();

            // 2. Write patched AndroidManifest.xml
            ZipEntry mfEntry = new ZipEntry("AndroidManifest.xml");
            fzos.putNextEntry(mfEntry);
            fzos.write(patchedManifest);
            fzos.closeEntry();

            // 3. Write encrypted DEX shards into assets/<assetDirName>/
            if (assetsDir != null && assetsDir.exists()) {
                File[] shards = assetsDir.listFiles();
                if (shards != null) {
                    for (File shard : shards) {
                        if (shard.isDirectory()) continue;
                        String entryName = "assets/" + assetDirName + "/" + shard.getName();
                        fzos.putNextEntry(new ZipEntry(entryName));
                        try (FileInputStream fis = new FileInputStream(shard)) {
                            copyStream(fis, fzos);
                        }
                        fzos.closeEntry();
                    }
                }
            }

            // 4. Copy everything else from the original APK (skip what we replaced)
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.startsWith("META-INF/")) continue;
                if (name.equals("AndroidManifest.xml")) continue;
                if (name.matches("classes\\.dex") || name.matches("classes\\d+\\.dex")) continue;
                if (name.startsWith("assets/" + assetDirName + "/")) continue;

                // Preserve compression level: stored types stay stored
                boolean store = false;
                for (String ext : STORED_EXTENSIONS) {
                    if (name.endsWith(ext)) { store = true; break; }
                }
                ZipEntry newEntry = new ZipEntry(name);
                if (store) {
                    newEntry.setMethod(ZipEntry.STORED);
                    newEntry.setSize(entry.getSize());
                    newEntry.setCrc(entry.getCrc());
                }
                fzos.putNextEntry(newEntry);
                try (InputStream is = zipFile.getInputStream(entry)) {
                    copyStream(is, fzos);
                }
                fzos.closeEntry();
            }
        }
        zipFile.close();
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int len;
        while ((len = in.read(buf)) > 0) out.write(buf, 0, len);
    }
}
