package com.ultra.dex2cvmp.ui;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.*;
import android.widget.*;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.*;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import android.content.Intent;
import com.ultra.dex2cvmp.R;
import com.ultra.dex2cvmp.engine.CompilerManager;
import com.ultra.dex2cvmp.ui.CompilerSetupActivity;
import com.ultra.dex2cvmp.ui.tree.ApkExplorer;
import com.ultra.dex2cvmp.ui.tree.ClassTreeAdapter;
import com.ultra.dex2cvmp.ui.tree.PackageNode;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.switchmaterial.SwitchMaterial;

import android.animation.ValueAnimator;
import com.ultra.dex2cvmp.engine.OllvmNdkManager;
import java.io.*;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ProtectFragment extends Fragment {

    private ProtectViewModel viewModel;

    // State views
    private View stateEmpty, stateLoading, stateTree, stateProgress;
    private View bottomActionBar;
    private TextView tvApkName, tvApkSize;
    private View btnReset;
    private TextView tvLoadingMsg;
    private TextView tvSelectionCount;
    private RecyclerView rvTree;
    private ClassTreeAdapter treeAdapter;

    // Mode toggle
    private View tabManual, tabClassList;
    private TextView tvTabManual, tvTabClassList;
    private View panelManual, panelClassList;
    private EditText etClassList;
    private TextView tvClassListCount;
    private boolean classListMode = false;

    // Compiler banner
    private TextView tvCompilerStatus;
    private TextView tvCompilerDot;
    private View btnCompilerSetup;
    private ValueAnimator ndkPulseAnim;

    // Action bar
    private View btnProtect, btnCancel;
    private TextView btnProtectLabel;
    private SwitchMaterial switchSign;
    private SwitchMaterial switchVmp;
    private TextView tvModeTitle;
    private TextView tvModeSubtitle;

    private static final String DEX2C_TITLE    = "Dex2C Mode";
    private static final String DEX2C_SUBTITLE = "Bytecode stripped and rebuilt as hardened C++ native";
    private static final String VMP_TITLE      = "VMP Mode";
    private static final String VMP_SUBTITLE   = "Converts bytecode to encrypted custom VM opcodes";

    // Progress state
    private ProgressBar progressBar;
    private TextView tvStage, tvTimer, tvConsole;
    private ScrollView scrollConsole;

    // Elapsed timer
    private final Handler timerHandler = new Handler(Looper.getMainLooper());
    private long startTimeMs;
    private boolean timerRunning;

    // Log
    private final StringBuilder logBuilder = new StringBuilder();
    // Prevents duplicate log entries when observers re-fire after tab return
    private boolean isRestoringState = false;

    // Background parsing
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private File cachedApkFile;

    // ── Launchers ────────────────────────────────────────────────────────────
    private final ActivityResultLauncher<Intent> pickApkLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    Uri uri = result.getData().getData();
                    onApkPicked(uri);
                }
            });

    private final ActivityResultLauncher<Intent> manageStorageLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
                if (PermissionHelper.hasStorageAccess(this)) startProtection();
                else showSnackbar("Storage permission denied — cannot save output", false);
            });

    private final ActivityResultLauncher<String[]> runtimePermLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), grants -> {
                if (!grants.containsValue(Boolean.FALSE)) startProtection();
                else showSnackbar("Storage permission denied — cannot save output", false);
            });

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    @Nullable @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_protect, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        viewModel = new ViewModelProvider(requireActivity()).get(ProtectViewModel.class);

        // State containers
        stateEmpty   = view.findViewById(R.id.state_empty);
        stateLoading = view.findViewById(R.id.state_loading);
        stateTree    = view.findViewById(R.id.state_tree);
        stateProgress = view.findViewById(R.id.state_progress);
        bottomActionBar = view.findViewById(R.id.bottom_action_bar);

        // APK bar
        tvApkName = view.findViewById(R.id.tv_apk_name);
        tvApkSize = view.findViewById(R.id.tv_apk_size);
        btnReset  = view.findViewById(R.id.btn_reset);
        view.findViewById(R.id.btn_pick_apk).setOnClickListener(v -> pickApk());
        btnReset.setOnClickListener(v -> resetToEmpty());

        // Loading
        tvLoadingMsg = view.findViewById(R.id.tv_loading_msg);

        // Tree
        tvSelectionCount = view.findViewById(R.id.tv_selection_count);
        rvTree = view.findViewById(R.id.rv_tree);
        rvTree.setLayoutManager(new LinearLayoutManager(requireContext()));
        rvTree.setItemAnimator(null); // disable flicker on expand/collapse
        treeAdapter = new ClassTreeAdapter();
        treeAdapter.setOnSelectionChangedListener((sel, total) -> {
            if (tvSelectionCount != null) {
                String msg = sel == total
                    ? "All " + total + " classes selected"
                    : sel + " of " + total + " classes selected";
                tvSelectionCount.setText(msg);
            }
        });
        rvTree.setAdapter(treeAdapter);

        view.findViewById(R.id.btn_select_all).setOnClickListener(v -> treeAdapter.selectAll(true));
        view.findViewById(R.id.btn_clear_all).setOnClickListener(v  -> treeAdapter.selectAll(false));

        // Mode toggle
        tabManual      = view.findViewById(R.id.tab_manual);
        tabClassList   = view.findViewById(R.id.tab_class_list);
        tvTabManual    = view.findViewById(R.id.tv_tab_manual);
        tvTabClassList = view.findViewById(R.id.tv_tab_class_list);
        panelManual    = view.findViewById(R.id.panel_manual);
        panelClassList = view.findViewById(R.id.panel_class_list);
        etClassList    = view.findViewById(R.id.et_class_list);
        tvClassListCount = view.findViewById(R.id.tv_class_list_count);

        tabManual.setOnClickListener(v -> setClassListMode(false));
        tabClassList.setOnClickListener(v -> setClassListMode(true));

        // Paste button — reads clipboard into the edit text
        view.findViewById(R.id.btn_paste_classes).setOnClickListener(v -> {
            android.content.ClipboardManager cm = (android.content.ClipboardManager)
                    requireContext().getSystemService(android.content.Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip() != null) {
                android.content.ClipData.Item item = cm.getPrimaryClip().getItemAt(0);
                if (item != null) {
                    String text = item.getText() != null ? item.getText().toString() : "";
                    if (!text.isEmpty()) {
                        String existing = etClassList.getText().toString();
                        if (existing.isEmpty()) {
                            etClassList.setText(text);
                        } else {
                            etClassList.append("\n" + text);
                        }
                        etClassList.setSelection(etClassList.getText().length());
                    }
                }
            }
        });

        // Clear class list
        view.findViewById(R.id.btn_clear_class_list).setOnClickListener(v -> {
            etClassList.setText("");
        });

        // Count update as user types
        etClassList.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int a) {}
            @Override public void onTextChanged(CharSequence s, int st, int b, int c) {}
            @Override public void afterTextChanged(Editable s) {
                updateClassListCount();
            }
        });

        // Search bar
        EditText etSearch = view.findViewById(R.id.et_search);
        TextView btnClearSearch = view.findViewById(R.id.btn_clear_search);
        etSearch.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int a) {}
            @Override public void onTextChanged(CharSequence s, int st, int b, int c) {}
            @Override public void afterTextChanged(Editable s) {
                String q = s.toString();
                treeAdapter.setSearchQuery(q);
                btnClearSearch.setVisibility(q.isEmpty() ? View.GONE : View.VISIBLE);
            }
        });
        btnClearSearch.setOnClickListener(v -> {
            etSearch.setText("");
            treeAdapter.setSearchQuery("");
        });

        // Bottom bar
        btnProtect      = view.findViewById(R.id.btn_protect);
        btnCancel       = view.findViewById(R.id.btn_cancel);
        btnProtectLabel = view.findViewById(R.id.btn_protect_label);
        switchSign      = view.findViewById(R.id.switch_sign);
        switchSign.setChecked(viewModel.isSignEnabled());
        switchSign.setOnCheckedChangeListener((b, c) -> viewModel.setSignEnabled(c));

        tvModeTitle    = view.findViewById(R.id.tv_mode_title);
        tvModeSubtitle = view.findViewById(R.id.tv_mode_subtitle);

        switchVmp = view.findViewById(R.id.switch_vmp);
        switchVmp.setChecked(viewModel.isVmpEnabled());
        updateModeLabels(viewModel.isVmpEnabled());
        switchVmp.setOnCheckedChangeListener((b, vmpOn) -> {
            viewModel.setVmpEnabled(vmpOn);
            updateModeLabels(vmpOn);
        });

        btnProtect.setOnClickListener(v -> onRunClicked(view));
        btnCancel.setOnClickListener(v -> {
            viewModel.cancel();
            showState(STATE_TREE);
        });

        // Progress
        progressBar  = view.findViewById(R.id.progress_bar);
        tvStage      = view.findViewById(R.id.tv_stage);
        tvTimer      = view.findViewById(R.id.tv_timer);
        tvConsole    = view.findViewById(R.id.tv_console);
        scrollConsole = view.findViewById(R.id.scroll_console);

        // Copy button — copies entire console log to clipboard
        view.findViewById(R.id.btn_copy_log).setOnClickListener(v -> {
            String text = logBuilder.toString();
            if (text.isEmpty()) {
                showSnackbar("Nothing to copy yet", false);
                return;
            }
            android.content.ClipboardManager cm = (android.content.ClipboardManager)
                    requireContext().getSystemService(android.content.Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(android.content.ClipData.newPlainText("Dex2c Log", text));
            showSnackbar("Log copied to clipboard", true);
        });

        // Compiler banner
        tvCompilerStatus = view.findViewById(R.id.tv_compiler_status);
        tvCompilerDot    = view.findViewById(R.id.tv_compiler_dot);
        btnCompilerSetup = view.findViewById(R.id.btn_compiler_setup);
        btnCompilerSetup.setOnClickListener(v ->
                startActivity(new Intent(requireContext(), CompilerSetupActivity.class)));
        refreshCompilerBanner();

        // Restore if APK was previously selected
        if (viewModel.getInputUri() != null && cachedApkFile == null) {
            tvApkName.setText(viewModel.getInputName());
            tvApkSize.setText("previously selected");
            // If protection is running right now, don't re-parse — the isRunning
            // observer will immediately show STATE_PROGRESS instead.
            if (!Boolean.TRUE.equals(viewModel.isRunning().getValue())) {
                showState(STATE_LOADING);
                loadApkTree(viewModel.getInputUri());
            }
        }

        // ── ViewModel observers ───────────────────────────────────────────────
        // NOTE: isRunning is observed FIRST so isRestoringState is set before
        // status/error/output observers fire with their re-delivered values.
        viewModel.isRunning().observe(getViewLifecycleOwner(), running -> {
            if (running) {
                // Restore persisted console — suppress duplicate log entries that
                // the other observers will immediately re-deliver on fragment recreate.
                String saved = viewModel.getConsoleLog();
                if (!saved.isEmpty()) {
                    logBuilder.setLength(0);
                    logBuilder.append(saved);
                    if (tvConsole != null) tvConsole.setText(saved);
                    isRestoringState = true;
                }
                showState(STATE_PROGRESS);
                // Restore the real start time so the timer continues from where
                // it left off instead of resetting to 00:00.
                resumeElapsedTimer(viewModel.getProtectionStartMs());
            } else {
                stopElapsedTimer();
                isRestoringState = false;
                btnProtectLabel.setText("Run Protection");
                btnProtect.setEnabled(true);
            }
            btnCancel.setVisibility(running ? View.VISIBLE : View.GONE);
            switchSign.setEnabled(!running);
            if (switchVmp != null) switchVmp.setEnabled(!running);
        });

        viewModel.getStatus().observe(getViewLifecycleOwner(), s -> {
            if (s == null || s.isEmpty()) return;
            if (tvStage != null) tvStage.setText(s);
            if (isRestoringState) { isRestoringState = false; return; }
            appendLog(s);
        });

        viewModel.getProgress().observe(getViewLifecycleOwner(), pct -> {
            if (progressBar != null) {
                progressBar.setProgress(pct);
                progressBar.setIndeterminate(false);
            }
        });

        viewModel.getOutputPath().observe(getViewLifecycleOwner(), path -> {
            if (path == null || path.isEmpty()) return;
            // Only show if not already in the restored log (survives tab switches)
            String marker = "✓ Saved:";
            String currentLog = logBuilder.toString();
            if (!currentLog.isEmpty() && !currentLog.contains(marker)) {
                appendLog(marker + " " + path);
                showSnackbar("Saved to /storage/emulated/0/Dex2c/", true);
            }
            if (progressBar != null) progressBar.setProgress(100);
        });

        viewModel.getError().observe(getViewLifecycleOwner(), err -> {
            if (err == null || err.isEmpty()) return;
            String marker = "✗ Error:";
            String currentLog = logBuilder.toString();
            if (!currentLog.isEmpty() && !currentLog.contains(marker)) {
                appendLog(marker + " " + err);
                showSnackbar(err, false);
            }
        });
    }

    // ── APK picking and tree loading ──────────────────────────────────────────
    private void pickApk() {
        // Compiler auto-extracts on first protection run — no gate needed here.
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                "application/vnd.android.package-archive",
                "application/octet-stream"
        });
        pickApkLauncher.launch(intent);
    }

    private void onApkPicked(Uri uri) {
        String name = resolveFileName(uri);
        long   size = resolveFileSize(uri);
        viewModel.setInputUri(uri, name);

        tvApkName.setText(name);
        tvApkSize.setText(size > 0 ? formatSize(size) : "");

        logBuilder.setLength(0);
        showState(STATE_LOADING);
        tvLoadingMsg.setText("Parsing APK structure...");

        loadApkTree(uri);
    }

    private void loadApkTree(Uri uri) {
        executor.execute(() -> {
            try {
                // Copy APK to cache so DexIO can open it as a File
                File cacheDir = requireContext().getCacheDir();
                File tmpApk = new File(cacheDir, "explore_" + System.currentTimeMillis() + ".apk");
                copyUriToFile(uri, tmpApk);
                cachedApkFile = tmpApk;

                new Handler(Looper.getMainLooper()).post(() ->
                    tvLoadingMsg.setText("Scanning packages and classes..."));

                List<PackageNode> tree = ApkExplorer.explore(tmpApk);

                new Handler(Looper.getMainLooper()).post(() -> {
                    treeAdapter.setData(tree);
                    // Don't overwrite progress screen if protection started
                    // while the tree was still being parsed in the background.
                    if (Boolean.TRUE.equals(viewModel.isRunning().getValue())) return;
                    showState(STATE_TREE);
                    if (tree.isEmpty()) {
                        showSnackbar("No user classes found in this APK", false);
                        showState(STATE_EMPTY);
                    }
                });

            } catch (Exception e) {
                new Handler(Looper.getMainLooper()).post(() -> {
                    showSnackbar("Failed to parse APK: " + e.getMessage(), false);
                    showState(STATE_EMPTY);
                });
            }
        });
    }

    private void copyUriToFile(Uri uri, File dest) throws IOException {
        try (InputStream in = requireContext().getContentResolver().openInputStream(uri);
             FileOutputStream out = new FileOutputStream(dest)) {
            if (in == null) throw new IOException("Cannot open URI stream");
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
    }

    // ── States ────────────────────────────────────────────────────────────────
    private static final int STATE_EMPTY    = 0;
    private static final int STATE_LOADING  = 1;
    private static final int STATE_TREE     = 2;
    private static final int STATE_PROGRESS = 3;

    private void showState(int state) {
        if (stateEmpty == null) return;
        stateEmpty.setVisibility(   state == STATE_EMPTY    ? View.VISIBLE : View.GONE);
        stateLoading.setVisibility( state == STATE_LOADING  ? View.VISIBLE : View.GONE);
        stateTree.setVisibility(    state == STATE_TREE     ? View.VISIBLE : View.GONE);
        stateProgress.setVisibility(state == STATE_PROGRESS ? View.VISIBLE : View.GONE);
        bottomActionBar.setVisibility(state == STATE_TREE || state == STATE_PROGRESS
                ? View.VISIBLE : View.GONE);
        // Show reset icon whenever an APK is loaded (tree, loading, or progress)
        if (btnReset != null)
            btnReset.setVisibility(state != STATE_EMPTY ? View.VISIBLE : View.GONE);
    }

    private void resetToEmpty() {
        // Cancel any running job first
        viewModel.cancel();
        stopElapsedTimer();

        // Clear ViewModel state
        viewModel.setInputUri(null, null);
        viewModel.clearConsoleLog();

        // Clear local UI state
        logBuilder.setLength(0);
        cachedApkFile = null;
        if (treeAdapter != null) treeAdapter.setData(null);
        if (tvApkName  != null) tvApkName.setText("No APK selected");
        if (tvApkSize  != null) tvApkSize.setText("Tap Browse to open an APK");
        if (tvConsole  != null) tvConsole.setText("");
        if (progressBar != null) { progressBar.setProgress(0); progressBar.setIndeterminate(false); }
        if (btnProtectLabel != null) btnProtectLabel.setText("Run Protection");
        if (btnProtect      != null) btnProtect.setEnabled(true);
        if (etClassList     != null) etClassList.setText("");
        setClassListMode(false);

        showState(STATE_EMPTY);
    }

    // ── Running protection ─────────────────────────────────────────────────────
    private void onRunClicked(View rootView) {
        if (viewModel.getInputUri() == null) {
            showSnackbar("Select an APK file first", false);
            return;
        }
        // JIT permission check (Taurus Shield pattern)
        PermissionHelper.ensureStorage(
            this, manageStorageLauncher, runtimePermLauncher,
            new PermissionHelper.Callback() {
                @Override public void onGranted()             { startProtection(); }
                @Override public void onDenied(String reason) { showSnackbar(reason, false); }
            });
    }

    private void requestBatteryOptimizationExemption() {
        try {
            android.os.PowerManager pm = (android.os.PowerManager)
                    requireContext().getSystemService(android.content.Context.POWER_SERVICE);
            if (pm == null) return;
            String pkg = requireContext().getPackageName();
            if (pm.isIgnoringBatteryOptimizations(pkg)) return; // already exempt

            // Only ask once — never nag the user every run
            android.content.SharedPreferences prefs = requireContext()
                    .getSharedPreferences("dex2c_prefs", android.content.Context.MODE_PRIVATE);
            if (prefs.getBoolean("battery_asked", false)) return;
            prefs.edit().putBoolean("battery_asked", true).apply();

            // Show a clear snackbar BEFORE the system dialog so the user knows what to tap
            showSnackbar("Tap ALLOW on the next screen so protection keeps running when your screen is off", true);

            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                try {
                    android.content.Intent i = new android.content.Intent(
                            android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                    i.setData(android.net.Uri.parse("package:" + pkg));
                    startActivity(i);
                } catch (Exception ignored) {}
            }, 1800); // small delay so the snackbar is visible first
        } catch (Exception ignored) {}
    }

    // ── Mode toggle ───────────────────────────────────────────────────────────
    private void setClassListMode(boolean listMode) {
        classListMode = listMode;
        if (panelManual == null || panelClassList == null) return;

        panelManual.setVisibility(listMode ? View.GONE : View.VISIBLE);
        panelClassList.setVisibility(listMode ? View.VISIBLE : View.GONE);

        if (tabManual != null) {
            tabManual.setBackgroundResource(listMode
                    ? R.drawable.bg_card_border : R.drawable.bg_btn_green);
        }
        if (tvTabManual != null) {
            tvTabManual.setTextColor(listMode
                    ? getResources().getColor(R.color.text_secondary, null)
                    : getResources().getColor(R.color.black, null));
        }
        if (tabClassList != null) {
            tabClassList.setBackgroundResource(listMode
                    ? R.drawable.bg_btn_green : R.drawable.bg_card_border);
        }
        if (tvTabClassList != null) {
            tvTabClassList.setTextColor(listMode
                    ? getResources().getColor(R.color.black, null)
                    : getResources().getColor(R.color.text_secondary, null));
        }
    }

    private void updateClassListCount() {
        if (tvClassListCount == null || etClassList == null) return;
        String text = etClassList.getText().toString();
        int count = 0;
        for (String line : text.split("\n")) {
            if (!line.trim().isEmpty()) count++;
        }
        tvClassListCount.setText(count == 1 ? "1 class" : count + " classes");
    }

    private void updateModeLabels(boolean vmpOn) {
        if (tvModeTitle    == null) return;
        if (tvModeSubtitle == null) return;
        tvModeTitle.setText(vmpOn    ? VMP_TITLE    : DEX2C_TITLE);
        tvModeSubtitle.setText(vmpOn ? VMP_SUBTITLE : DEX2C_SUBTITLE);
    }

    private String buildFilterFromClassList() {
        if (etClassList == null) return "";
        String raw = etClassList.getText().toString();
        StringBuilder sb = new StringBuilder();
        for (String line : raw.split("\n")) {
            String cls = line.trim();
            if (!cls.isEmpty() && !cls.startsWith("#")) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(cls);
            }
        }
        return sb.toString();
    }

    /**
     * Merge two filter strings (class-list and manual), removing:
     *   1. Exact duplicate lines
     *   2. Redundant method-level entries whose class is already fully covered
     *      by a whole-class entry in either source (whole-class always wins)
     *
     * Whole-class entry: a line with no "->" and no "(" — just a class name,
     *   e.g. "com.example.MainActivity"
     * Method entry: contains "->" with a descriptor, e.g.
     *   "Lcom/example/MainActivity;->foo()V"
     */
    private String mergeFilters(String filterA, String filterB) {
        java.util.LinkedHashSet<String> seen   = new java.util.LinkedHashSet<>();
        java.util.Set<String>          classes = new java.util.HashSet<>();

        // Two-pass: first collect all whole-class entries from BOTH sources
        for (String src : new String[]{filterA, filterB}) {
            if (src == null) continue;
            for (String raw : src.split("\n")) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (!line.contains("->") && !line.contains("(")) {
                    // Whole-class entry — normalise to smali prefix for matching
                    // "com.example.Foo"  →  "Lcom/example/Foo;"
                    // "Lcom/example/Foo;" already fine
                    String smali;
                    if (line.startsWith("L") && line.endsWith(";")) {
                        smali = line;
                    } else {
                        smali = "L" + line.replace('.', '/') + ";";
                    }
                    classes.add(smali);
                }
            }
        }

        // Second pass: collect lines, skipping redundant method entries
        for (String src : new String[]{filterA, filterB}) {
            if (src == null) continue;
            for (String raw : src.split("\n")) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.contains("->")) {
                    // Method-level entry — check if class is already covered
                    int arrow = line.indexOf("->");
                    String classPart = line.substring(0, arrow); // "Lcom/example/Foo;"
                    if (classes.contains(classPart)) continue; // whole-class already covers it
                }

                seen.add(line); // deduplicate exact matches automatically
            }
        }

        return String.join("\n", seen);
    }

    private void startProtection() {
        // Ask OS once to stop killing our Python child process when screen turns off
        requestBatteryOptimizationExemption();

        // Always collect from BOTH sources and merge them so the user can combine
        // class-list (paste) selections with manual tree selections simultaneously.
        // mergeFilters() deduplicates exact lines and drops method-level entries
        // whose class is already fully covered by a whole-class entry.
        String classFilter  = buildFilterFromClassList();
        String manualFilter = treeAdapter != null ? treeAdapter.buildFilter() : null;

        boolean hasClass  = classFilter  != null && !classFilter.trim().isEmpty();
        boolean hasManual = manualFilter != null && !manualFilter.trim().isEmpty();

        String filter = mergeFilters(classFilter, manualFilter);

        if (filter == null || filter.trim().isEmpty()) {
            showSnackbar("Select at least one class or method first", false);
            return;
        }

        logBuilder.setLength(0);
        viewModel.clearConsoleLog();
        viewModel.setProtectionStartMs(System.currentTimeMillis());
        if (tvConsole != null) tvConsole.setText("");
        if (progressBar != null) progressBar.setProgress(0);
        btnProtectLabel.setText("Running...");
        btnProtect.setEnabled(false);

        // Log the merged filter summary so the user can verify exactly what
        // rules are active before the engine starts processing methods.
        appendLog(buildFilterSummary(filter, hasClass, hasManual));

        boolean sign        = switchSign.isChecked();
        boolean useVmp      = switchVmp         != null && switchVmp.isChecked();
        viewModel.runProtection(filter, sign, useVmp, viewModel.isBlockRootedEnabled());
    }

    // ── Filter summary ────────────────────────────────────────────────────────
    /**
     * Builds a human-readable summary of the merged filter that is logged at the
     * very start of each protection run.  The user can read this in the console to
     * verify exactly which rules are active before the engine processes methods.
     *
     * Blacklist rules (! prefix) always win over include rules regardless of the
     * order they appear in the merged string — the engine checks them first.
     */
    private String buildFilterSummary(String filter, boolean fromClassList, boolean fromManual) {
        int include = 0, exclude = 0;
        for (String line : filter.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            if (t.startsWith("!")) exclude++;
            else include++;
        }

        String source;
        if (fromClassList && fromManual) source = "class-list + manual";
        else if (fromClassList)          source = "class-list";
        else                             source = "manual";

        StringBuilder sb = new StringBuilder();
        sb.append("▶ Filter [").append(source).append("]: ");
        sb.append(include).append(" include");
        if (exclude > 0) {
            sb.append(", ").append(exclude).append(" exclude");
            if (fromClassList && fromManual) {
                sb.append(" — exclude rules always win over include rules");
            }
        }
        sb.append(include + exclude != 1 ? " rules" : " rule");
        return sb.toString();
    }

    // ── Elapsed timer ─────────────────────────────────────────────────────────
    private final Runnable timerTick = new Runnable() {
        @Override public void run() {
            if (!timerRunning) return;
            long e    = (System.currentTimeMillis() - startTimeMs);
            long secs = (e / 1000) % 60;
            long mins = e / 60000;
            if (tvTimer != null)
                tvTimer.setText(String.format(Locale.US, "%02d:%02d", mins, secs));
            timerHandler.postDelayed(this, 500);
        }
    };
    /** Fresh start — saves start time in ViewModel so it survives tab switches. */
    private void startElapsedTimer() {
        long now = System.currentTimeMillis();
        viewModel.setProtectionStartMs(now);
        resumeElapsedTimer(now);
    }

    /** Resume from a saved start time (called when fragment recreates mid-run). */
    private void resumeElapsedTimer(long savedStartMs) {
        timerRunning = true;
        startTimeMs  = (savedStartMs > 0) ? savedStartMs : System.currentTimeMillis();
        timerHandler.removeCallbacks(timerTick);
        timerHandler.post(timerTick);
    }

    private void stopElapsedTimer() {
        timerRunning = false;
        timerHandler.removeCallbacks(timerTick);
    }

    // ── Console log ───────────────────────────────────────────────────────────
    private void appendLog(String line) {
        long elapsed = timerRunning ? (System.currentTimeMillis() - startTimeMs) / 1000 : 0;
        String prefix = timerRunning
                ? String.format(Locale.US, "[%02d:%02d] ", elapsed / 60, elapsed % 60)
                : "";
        String entry = prefix + line + "\n";
        logBuilder.append(entry);
        viewModel.appendConsoleLog(entry);
        if (tvConsole != null) {
            tvConsole.setText(logBuilder.toString());
            if (scrollConsole != null)
                scrollConsole.post(() -> scrollConsole.fullScroll(View.FOCUS_DOWN));
        }
    }

    // ── Floating snackbar ─────────────────────────────────────────────────────
    private void showSnackbar(String message, boolean success) {
        View root = getView();
        if (root == null) return;
        Snackbar sb = Snackbar.make(root, message, Snackbar.LENGTH_LONG);
        sb.getView().setBackgroundResource(success
                ? R.drawable.bg_snack_success
                : R.drawable.bg_snack_error);
        sb.setTextColor(0xFFFFFFFF);
        sb.show();
    }

    // ── File info resolvers ───────────────────────────────────────────────────
    private String resolveFileName(Uri uri) {
        if (uri == null) return "Unknown";
        try (Cursor c = requireContext().getContentResolver().query(
                uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (i >= 0) return c.getString(i);
            }
        } catch (Exception ignored) {}
        String path = uri.getPath();
        if (path == null) return "Unknown";
        int s = path.lastIndexOf('/');
        return s >= 0 ? path.substring(s + 1) : path;
    }

    private long resolveFileSize(Uri uri) {
        if (uri == null) return 0;
        try (Cursor c = requireContext().getContentResolver().query(
                uri, new String[]{OpenableColumns.SIZE}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int i = c.getColumnIndex(OpenableColumns.SIZE);
                if (i >= 0) return c.getLong(i);
            }
        } catch (Exception ignored) {}
        return 0;
    }

    private String formatSize(long b) {
        if (b <= 0)           return "";
        if (b < 1024)         return b + " B";
        if (b < 1024 * 1024)  return String.format(Locale.US, "%.1f KB", b / 1024f);
        return String.format(Locale.US, "%.1f MB", b / (1024f * 1024f));
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshCompilerBanner();
    }

    private void refreshCompilerBanner() {
        if (tvCompilerStatus == null) return;
        if (!isAdded() || getContext() == null) return;

        OllvmNdkManager.init(requireContext());

        if (OllvmNdkManager.isInstalled()) {
            stopNdkPulse();
            tvCompilerStatus.setText("Compiler Ready");
            tvCompilerStatus.setTextColor(0xFF9BA8BB); // text_secondary
            tvCompilerStatus.setAlpha(1f);
            if (tvCompilerDot != null) {
                tvCompilerDot.setTextColor(0xFF00E676); // green
                tvCompilerDot.setScaleX(1f);
                tvCompilerDot.setScaleY(1f);
            }
        } else {
            tvCompilerStatus.setText("Install NDK");
            tvCompilerStatus.setTextColor(0xFFEF4444); // danger red
            if (tvCompilerDot != null) tvCompilerDot.setTextColor(0xFFEF4444);
            startNdkPulse();
        }
    }

    private void startNdkPulse() {
        if (ndkPulseAnim != null && ndkPulseAnim.isRunning()) return;
        ndkPulseAnim = ValueAnimator.ofFloat(0f, 1f);
        ndkPulseAnim.setDuration(900);
        ndkPulseAnim.setRepeatCount(ValueAnimator.INFINITE);
        ndkPulseAnim.setRepeatMode(ValueAnimator.RESTART);
        ndkPulseAnim.addUpdateListener(anim -> {
            float t = (float) anim.getAnimatedValue();
            // Heartbeat curve: lub (big beat) → dub (smaller beat) → rest
            float scale, alpha;
            if (t < 0.15f) {
                // lub — rise
                scale = 1f + (t / 0.15f) * 0.30f;
                alpha = 1f;
            } else if (t < 0.28f) {
                // lub — fall
                float p = (t - 0.15f) / 0.13f;
                scale = 1.30f - p * 0.20f;
                alpha = 1f - p * 0.45f;
            } else if (t < 0.40f) {
                // dub — rise
                float p = (t - 0.28f) / 0.12f;
                scale = 1.10f + p * 0.14f;
                alpha = 0.55f + p * 0.45f;
            } else if (t < 0.52f) {
                // dub — fall
                float p = (t - 0.40f) / 0.12f;
                scale = 1.24f - p * 0.24f;
                alpha = 1f - p * 0.65f;
            } else {
                // rest — fade back
                float p = (t - 0.52f) / 0.48f;
                scale = 1f;
                alpha = 0.35f + p * 0.65f;
            }
            if (tvCompilerDot != null) {
                tvCompilerDot.setScaleX(scale);
                tvCompilerDot.setScaleY(scale);
            }
            if (tvCompilerStatus != null) {
                tvCompilerStatus.setAlpha(alpha);
            }
        });
        ndkPulseAnim.start();
    }

    private void stopNdkPulse() {
        if (ndkPulseAnim != null) {
            ndkPulseAnim.cancel();
            ndkPulseAnim = null;
        }
        if (tvCompilerDot != null) { tvCompilerDot.setScaleX(1f); tvCompilerDot.setScaleY(1f); }
        if (tvCompilerStatus != null) tvCompilerStatus.setAlpha(1f);
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        stopElapsedTimer();
        stopNdkPulse();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }
}
