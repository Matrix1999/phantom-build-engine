package com.ultra.dex2cvmp.ui;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.widget.SwitchCompat;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import com.ultra.dex2cvmp.R;
import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SettingsFragment extends Fragment {

    public static final String PREFS_NAME       = "dex2c_prefs";
    public static final String KEY_LIBRARY_NAME = "library_name";
    public static final String KEY_ABI_ARM64         = "abi_arm64_v8a";
    public static final String KEY_ABI_ARMEABI       = "abi_armeabi_v7a";
    public static final String KEY_ABI_X86_64        = "abi_x86_64";
    public static final String KEY_ABI_X86           = "abi_x86";
    /** When false, ApkProtector writes sentinel stamps (0,0) so guard.cpp skips the check. */
    public static final String KEY_MANIFEST_DEX_CHECK = "manifest_dex_check";
    /**
     * When true, ApkProtector extracts the META-INF signing certificate from the
     * input APK, SHA-256s the raw bytes, and bakes the digest into font_kern.dat.
     * guard.cpp then verifies the installed APK signature on every load — using
     * a direct syscall (bypassing libc IO hooks / SRPatch IO method) so tools
     * like SRPatch, NP Manager PMS hook, and LSPatch cannot spoof the result.
     *
     * IMPORTANT: the input APK must already be signed BEFORE protection.
     * Using Ultra Dex2C-VMP's own built-in signer is NOT compatible with this check
     * because signing happens after protection — the cert won't match.
     */
    public static final String KEY_SIG_CHECK = "sig_check";

    /**
     * When true, ApkProtector wraps the processed APK with the com.secure.dex stub loader
     * (ProxyApplication + DexProtector + MyClassLoader). The stub DEX is compiled from the
     * stub-loader module and bundled as assets/stub.dex. Original DEX files are encrypted
     * with the custom cipher and placed in assets/dp-lib/ inside the output APK.
     */
    public static final String KEY_DEX_PACKER = "dex_packer_enabled";

    /**
     * Persisted in "dex2c_mega_prefs" (same file as ProtectViewModel) so the
     * value flows directly into DexPacker at protection time without any extra reads.
     */
    public static final String KEY_BLOCK_ROOTED      = "block_rooted_enabled";
    public static final String PREFS_MEGA_NAME       = "dex2c_mega_prefs";

    public static final String DEFAULT_LIBRARY_NAME = "ultra-dex2cvmp";

    private EditText etLibraryName;
    private CheckBox cbArm64, cbArmeabi, cbX86_64, cbX86;
    private SwitchCompat swManifestDex;
    private SwitchCompat swSigCheck;
    private SwitchCompat swDexPacker;
    private SwitchCompat swBlockRooted;
    private TextView tvCacheSize;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler  = new Handler(Looper.getMainLooper());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_settings, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        etLibraryName = view.findViewById(R.id.et_library_name);
        cbArm64        = view.findViewById(R.id.cb_arm64_v8a);
        cbArmeabi      = view.findViewById(R.id.cb_armeabi_v7a);
        cbX86_64       = view.findViewById(R.id.cb_x86_64);
        cbX86          = view.findViewById(R.id.cb_x86);
        swManifestDex  = view.findViewById(R.id.sw_manifest_dex_check);
        swSigCheck     = view.findViewById(R.id.sw_sig_check);
        swDexPacker    = view.findViewById(R.id.sw_dex_packer);
        swBlockRooted  = view.findViewById(R.id.sw_block_rooted);
        tvCacheSize    = view.findViewById(R.id.tv_cache_size);

        loadSettings();
        refreshCacheSize();

        view.findViewById(R.id.btn_save_settings).setOnClickListener(v -> saveSettings());
        view.findViewById(R.id.btn_clear_cache).setOnClickListener(v -> clearCache());
    }

    // ── Cache helpers ────────────────────────────────────────────────────────

    /** Calculates cache dir size on a background thread and updates the label. */
    private void refreshCacheSize() {
        tvCacheSize.setText("Calculating…");
        File cacheDir = requireContext().getCacheDir();
        executor.execute(() -> {
            long bytes = dirSize(cacheDir);
            String label = formatSize(bytes);
            mainHandler.post(() -> {
                if (isAdded()) tvCacheSize.setText(label);
            });
        });
    }

    /** Deletes all files inside getCacheDir() and refreshes the size label. */
    private void clearCache() {
        tvCacheSize.setText("Clearing…");
        File cacheDir = requireContext().getCacheDir();
        executor.execute(() -> {
            File[] children = cacheDir.listFiles();
            if (children != null) {
                for (File f : children) deleteRecursive(f);
            }
            long remaining = dirSize(cacheDir);
            String label = formatSize(remaining);
            mainHandler.post(() -> {
                if (!isAdded()) return;
                tvCacheSize.setText(label);
                Toast.makeText(requireContext(), "Cache cleared", Toast.LENGTH_SHORT).show();
            });
        });
    }

    /** Returns the total size in bytes of a directory tree. */
    private static long dirSize(File dir) {
        if (dir == null || !dir.exists()) return 0;
        if (dir.isFile()) return dir.length();
        long total = 0;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) total += dirSize(f);
        }
        return total;
    }

    /** Deletes a file or directory tree. */
    private static void deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) for (File c : children) deleteRecursive(c);
        }
        f.delete();
    }

    /** Formats a byte count as KB / MB / GB. */
    private static String formatSize(long bytes) {
        if (bytes < 1024)             return bytes + " B";
        if (bytes < 1024 * 1024)      return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.2f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        executor.shutdown();
    }

    // ─────────────────────────────────────────────────────────────────────────

    private SharedPreferences prefs() {
        return requireContext().getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE);
    }

    /** Shared with ProtectViewModel — used only for the Block Rooted toggle. */
    private SharedPreferences megaPrefs() {
        return requireContext().getSharedPreferences(PREFS_MEGA_NAME, android.content.Context.MODE_PRIVATE);
    }

    private void loadSettings() {
        SharedPreferences p = prefs();
        etLibraryName.setText(p.getString(KEY_LIBRARY_NAME, DEFAULT_LIBRARY_NAME));
        // both default ON — user can toggle either off
        cbArm64.setChecked(p.getBoolean(KEY_ABI_ARM64, true));
        cbArmeabi.setChecked(p.getBoolean(KEY_ABI_ARMEABI, true));
        // x86_64 / x86 hidden — not shown to user, always false
        cbX86_64.setChecked(false);
        cbX86.setChecked(false);
        swManifestDex.setChecked(p.getBoolean(KEY_MANIFEST_DEX_CHECK, true));
        swSigCheck.setChecked(p.getBoolean(KEY_SIG_CHECK, true));
        swDexPacker.setChecked(p.getBoolean(KEY_DEX_PACKER, false));
        // Block Rooted lives in dex2c_mega_prefs so ProtectViewModel reads the same value.
        swBlockRooted.setChecked(megaPrefs().getBoolean(KEY_BLOCK_ROOTED, true));
        // Auto-save immediately on toggle — DexPacker reads fresh from SharedPreferences
        // at pack time so no ViewModel sync needed.
        swBlockRooted.setOnCheckedChangeListener((btn, checked) ->
                megaPrefs().edit().putBoolean(KEY_BLOCK_ROOTED, checked).apply());
    }

    private void saveSettings() {
        String name = etLibraryName.getText().toString().trim();
        if (TextUtils.isEmpty(name)) {
            Toast.makeText(requireContext(), "Library name cannot be empty", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!name.matches("[A-Za-z0-9_-]+")) {
            Toast.makeText(requireContext(),
                    "Only letters, numbers, hyphens and underscores are allowed",
                    Toast.LENGTH_SHORT).show();
            return;
        }

        prefs().edit()
                .putString(KEY_LIBRARY_NAME, name)
                .putBoolean(KEY_ABI_ARM64,   cbArm64.isChecked())
                .putBoolean(KEY_ABI_ARMEABI, cbArmeabi.isChecked())
                .putBoolean(KEY_ABI_X86_64,  false)   // not supported
                .putBoolean(KEY_ABI_X86,     false)   // not supported
                .putBoolean(KEY_MANIFEST_DEX_CHECK, swManifestDex.isChecked())
                .putBoolean(KEY_SIG_CHECK,   swSigCheck.isChecked())
                .putBoolean(KEY_DEX_PACKER,  swDexPacker.isChecked())
                .apply();

        // Block Rooted saved to dex2c_mega_prefs — DexPacker reads it fresh at pack time.
        megaPrefs().edit().putBoolean(KEY_BLOCK_ROOTED, swBlockRooted.isChecked()).apply();

        Toast.makeText(requireContext(), "Settings saved", Toast.LENGTH_SHORT).show();
    }
}
