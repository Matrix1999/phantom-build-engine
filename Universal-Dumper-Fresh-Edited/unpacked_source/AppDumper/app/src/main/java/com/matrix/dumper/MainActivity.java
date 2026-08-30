package com.matrix.dumper;

import android.Manifest;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.content.res.ColorStateList;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MainActivity extends Activity {

    private ListView listView;
    private AppListAdapter adapter;
    private final List<AppInfo> allApps  = new ArrayList<>();
    private final List<AppInfo> filtered = new ArrayList<>();
    private EditText searchBox;

    private Boolean rootOk = null;
    private boolean loaded = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setTitle("Matrix Dumper");

        searchBox = findViewById(R.id.search_box);
        listView  = findViewById(R.id.list_view);

        adapter = new AppListAdapter(this, filtered);
        listView.setAdapter(adapter);

        listView.setOnItemLongClickListener((parent, view, pos, id) -> {
            startDump(filtered.get(pos));
            return true;
        });
        adapter.setDumpListener(this::startDump);

        searchBox.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int a) {}
            @Override public void afterTextChanged(Editable s) {}
            @Override public void onTextChanged(CharSequence s, int st, int bf, int cnt) {
                filterApps(s.toString());
            }
        });

        TextView toggle = findViewById(R.id.theme_toggle);
        if (toggle != null) {
            toggle.setOnClickListener(v -> {
                ThemeManager.toggle(this);
                recreate();
            });
        }

        ImageView hamburger = findViewById(R.id.hamburger_btn);
        if (hamburger != null) {
            hamburger.setOnClickListener(v -> showDumpersPopup(v));
        }

        ImageView refreshBtn = findViewById(R.id.refresh_btn);
        if (refreshBtn != null) {
            refreshBtn.setOnClickListener(v -> {
                refreshBtn.animate().rotationBy(360f).setDuration(500).start();
                allApps.clear();
                filtered.clear();
                adapter.notifyDataSetChanged();
                loaded = false;
                loadApps();
            });
        }

        startEagleAnimation();

        new Thread(() -> { rootOk = ShellUtils.isRootAvailable(); }).start();
    }

    private void startEagleAnimation() {
        ImageView eagle = findViewById(R.id.app_icon_view);
        if (eagle == null) return;

        ObjectAnimator scaleX = ObjectAnimator.ofFloat(eagle, "scaleX", 1f, 1.22f);
        scaleX.setDuration(1100);
        scaleX.setRepeatCount(ObjectAnimator.INFINITE);
        scaleX.setRepeatMode(ObjectAnimator.REVERSE);
        scaleX.setInterpolator(new AccelerateDecelerateInterpolator());

        ObjectAnimator scaleY = ObjectAnimator.ofFloat(eagle, "scaleY", 1f, 1.22f);
        scaleY.setDuration(1100);
        scaleY.setRepeatCount(ObjectAnimator.INFINITE);
        scaleY.setRepeatMode(ObjectAnimator.REVERSE);
        scaleY.setInterpolator(new AccelerateDecelerateInterpolator());

        ObjectAnimator alpha = ObjectAnimator.ofFloat(eagle, "alpha", 1f, 0.65f);
        alpha.setDuration(1100);
        alpha.setRepeatCount(ObjectAnimator.INFINITE);
        alpha.setRepeatMode(ObjectAnimator.REVERSE);
        alpha.setInterpolator(new AccelerateDecelerateInterpolator());

        AnimatorSet pulse = new AnimatorSet();
        pulse.playTogether(scaleX, scaleY, alpha);
        pulse.start();
    }

    @Override
    protected void onResume() {
        super.onResume();
        applyTheme();
        requestStoragePermission();
        if (!loaded) {
            loaded = true;
            loadApps();
        }
    }

    private void applyTheme() {
        LinearLayout root   = findViewById(R.id.root_layout);
        LinearLayout header = findViewById(R.id.header_layout);
        ListView     list   = findViewById(R.id.list_view);
        EditText     search = findViewById(R.id.search_box);
        TextView     toggle = findViewById(R.id.theme_toggle);

        if (root   != null) root.setBackgroundColor(ThemeManager.bg(this));
        if (header != null) header.setBackgroundColor(ThemeManager.headerBg(this));
        if (list   != null) {
            list.setBackgroundColor(ThemeManager.bg(this));
            list.setDivider(new ColorDrawable(ThemeManager.divider(this)));
        }
        if (search != null) {
            search.setTextColor(ThemeManager.searchText(this));
            search.setHintTextColor(ThemeManager.searchHint(this));
            search.setBackgroundColor(ThemeManager.searchBg(this));
        }
        if (toggle != null) {
            boolean dark = ThemeManager.isDark(this);
            toggle.setText(dark ? "LIGHT" : "DARK");
            toggle.setTextColor(ThemeManager.toggleText(this));
        }
    }

    // ── Hamburger popup ───────────────────────────────────────────────────────

    private void showDumpersPopup(View anchor) {
        boolean dark = ThemeManager.isDark(this);
        int popupBg   = dark ? 0xFF141414 : 0xFFF8F8F8;
        int textPrim  = ThemeManager.textPrimary(this);
        int textSec   = ThemeManager.textSecondary(this);
        int divColor  = dark ? 0xFF252525 : 0xFFEAEAEA;

        // Count apps by protection type from the full loaded list
        int[] counts = new int[AppInfo.ProtectionType.values().length];
        int total = 0;
        for (AppInfo app : allApps) {
            counts[app.protection.ordinal()]++;
            total++;
        }

        // Root container
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(0), dp(0), dp(0), dp(0));
        GradientDrawable rootBg = new GradientDrawable();
        rootBg.setColor(popupBg);
        rootBg.setCornerRadius(dp(14));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            root.setBackground(rootBg);
        }
        root.setElevation(dp(8));

        // ── Header ──────────────────────────────────────────────────────────
        LinearLayout headerRow = new LinearLayout(this);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);
        headerRow.setPadding(dp(18), dp(16), dp(18), dp(12));

        TextView headerTitle = new TextView(this);
        headerTitle.setText("SUPPORTED DUMPERS");
        headerTitle.setTextColor(0xFFFF0000);
        headerTitle.setTextSize(11);
        headerTitle.setTypeface(null, Typeface.BOLD);
        headerTitle.setLetterSpacing(0.1f);
        LinearLayout.LayoutParams htLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        headerTitle.setLayoutParams(htLp);
        headerRow.addView(headerTitle);

        // Total badge
        TextView totalBadge = makeBadge(String.valueOf(total), 0xFF000000);
        headerRow.addView(totalBadge);

        root.addView(headerRow);

        // ── Divider ─────────────────────────────────────────────────────────
        root.addView(makeDivider(divColor));

        // ── Dumper rows ─────────────────────────────────────────────────────
        // Define display order: protected first, then no-protection
        AppInfo.ProtectionType[] displayOrder = {
            AppInfo.ProtectionType.IJIAMI,
            AppInfo.ProtectionType.JIAGU_360,
            AppInfo.ProtectionType.TENCENT_LEGU,
            AppInfo.ProtectionType.TENCENT_TPSHELL,
            AppInfo.ProtectionType.BAIDU,
            AppInfo.ProtectionType.BANGCLE,
            AppInfo.ProtectionType.DEXPROTECTOR,
            AppInfo.ProtectionType.NETEASE,
            AppInfo.ProtectionType.NQ_SHIELD,
            AppInfo.ProtectionType.ALIBABA,
            AppInfo.ProtectionType.SHADOW_SAFETY,
            AppInfo.ProtectionType.NAGAPT,
            AppInfo.ProtectionType.APPDOME,
            AppInfo.ProtectionType.DPT_SHELL,
            AppInfo.ProtectionType.NONE,
        };

        for (int i = 0; i < displayOrder.length; i++) {
            AppInfo.ProtectionType type = displayOrder[i];
            int count = counts[type.ordinal()];
            int color = Color.parseColor(type.color);

            root.addView(makeDumperRow(type.label, color, count, textPrim, textSec));

            if (i < displayOrder.length - 1) {
                root.addView(makeDivider(divColor));
            }
        }

        // ── Footer ───────────────────────────────────────────────────────────
        root.addView(makeDivider(divColor));
        TextView footer = new TextView(this);
        footer.setText(total + " user apps scanned");
        footer.setTextColor(textSec);
        footer.setTextSize(10.5f);
        footer.setGravity(Gravity.CENTER);
        footer.setPadding(dp(18), dp(10), dp(18), dp(13));
        root.addView(footer);

        // ── Settings section ──────────────────────────────────────────────────
        root.addView(makeDivider(divColor));

        LinearLayout settingsHeader = new LinearLayout(this);
        settingsHeader.setOrientation(LinearLayout.HORIZONTAL);
        settingsHeader.setGravity(Gravity.CENTER_VERTICAL);
        settingsHeader.setPadding(dp(18), dp(14), dp(18), dp(6));
        TextView settingsTitle = new TextView(this);
        settingsTitle.setText("⚙   SETTINGS");
        settingsTitle.setTextColor(0xFFFF0000);
        settingsTitle.setTextSize(11);
        settingsTitle.setTypeface(null, Typeface.BOLD);
        settingsTitle.setLetterSpacing(0.1f);
        settingsHeader.addView(settingsTitle);
        root.addView(settingsHeader);

        // ── Extra wait slider ─────────────────────────────────────────────────
        LinearLayout waitRow = new LinearLayout(this);
        waitRow.setOrientation(LinearLayout.VERTICAL);
        waitRow.setPadding(dp(18), dp(4), dp(18), dp(10));

        LinearLayout waitLabelRow = new LinearLayout(this);
        waitLabelRow.setOrientation(LinearLayout.HORIZONTAL);
        waitLabelRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView waitLabel = new TextView(this);
        waitLabel.setText("Extra Wait");
        waitLabel.setTextColor(textPrim);
        waitLabel.setTextSize(13f);
        waitLabel.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        waitLabelRow.addView(waitLabel);

        int currentWait = SettingsManager.getExtraWaitSec(this);
        TextView waitValue = new TextView(this);
        waitValue.setText(currentWait == 0 ? "Default" : "+" + currentWait + "s");
        waitValue.setTextColor(0xFFFF0000);
        waitValue.setTextSize(12f);
        waitValue.setTypeface(null, Typeface.BOLD);
        waitLabelRow.addView(waitValue);
        waitRow.addView(waitLabelRow);

        SeekBar seekBar = new SeekBar(this);
        seekBar.setMax(20);
        seekBar.setProgress(currentWait);
        seekBar.setProgressTintList(ColorStateList.valueOf(0xFFFF0000));
        seekBar.setThumbTintList(ColorStateList.valueOf(0xFFFF0000));
        LinearLayout.LayoutParams sbLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sbLp.setMargins(0, dp(6), 0, 0);
        seekBar.setLayoutParams(sbLp);
        seekBar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override public void onStartTrackingTouch(SeekBar sb) {}
            @Override public void onStopTrackingTouch(SeekBar sb) {}
            @Override public void onProgressChanged(SeekBar sb, int progress, boolean fromUser) {
                if (!fromUser) return;
                SettingsManager.setExtraWaitSec(MainActivity.this, progress);
                waitValue.setText(progress == 0 ? "Default" : "+" + progress + "s");
            }
        });
        waitRow.addView(seekBar);
        root.addView(waitRow);

        root.addView(makeDivider(divColor));

        // ── Multi-pass toggle ─────────────────────────────────────────────────
        final boolean[] mpOn = { SettingsManager.isMultiPass(this) };
        final TextView[] mpBadgeRef = new TextView[1];
        LinearLayout mpRow = makeSettingsToggleRow(
                "Multi-Pass Scan", "2nd & 3rd memory sweep",
                mpOn[0], textPrim, textSec);
        mpBadgeRef[0] = (TextView) mpRow.getTag();
        mpRow.setOnClickListener(v -> {
            mpOn[0] = !mpOn[0];
            SettingsManager.setMultiPass(MainActivity.this, mpOn[0]);
            applyToggleBadge(mpBadgeRef[0], mpOn[0]);
        });
        root.addView(mpRow);

        root.addView(makeDivider(divColor));

        // ── Force-stop toggle ─────────────────────────────────────────────────
        final boolean[] fsOn = { SettingsManager.isForceStop(this) };
        final TextView[] fsBadgeRef = new TextView[1];
        LinearLayout fsRow = makeSettingsToggleRow(
                "Force-Stop First", "Kill app before cold launch",
                fsOn[0], textPrim, textSec);
        fsBadgeRef[0] = (TextView) fsRow.getTag();
        fsRow.setOnClickListener(v -> {
            fsOn[0] = !fsOn[0];
            SettingsManager.setForceStop(MainActivity.this, fsOn[0]);
            applyToggleBadge(fsBadgeRef[0], fsOn[0]);
        });
        root.addView(fsRow);

        // ── Popup (scrollable so Settings section is always reachable) ──────────
        int popupW = dp(268);

        ScrollView scrollWrapper = new ScrollView(this);
        scrollWrapper.setVerticalScrollBarEnabled(false);
        scrollWrapper.addView(root);

        // Measure full content height, cap at 78% of screen
        root.measure(View.MeasureSpec.makeMeasureSpec(popupW, View.MeasureSpec.EXACTLY),
                     View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));
        int fullH   = root.getMeasuredHeight();
        int screenH = getResources().getDisplayMetrics().heightPixels;
        int popupH  = Math.min(fullH, (int)(screenH * 0.78f));

        PopupWindow popup = new PopupWindow(scrollWrapper, popupW, popupH, true);
        popup.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        popup.setOutsideTouchable(true);
        popup.setElevation(dp(12));

        popup.showAsDropDown(anchor, -dp(8), dp(6));
    }

    private LinearLayout makeDumperRow(String name, int color, int count,
                                        int textPrim, int textSec) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(18), dp(12), dp(18), dp(12));

        // Color dot
        View dot = new View(this);
        GradientDrawable dotBg = new GradientDrawable();
        dotBg.setShape(GradientDrawable.OVAL);
        dotBg.setColor(color);
        dot.setBackground(dotBg);
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dp(10), dp(10));
        dotLp.setMarginEnd(dp(12));
        dot.setLayoutParams(dotLp);
        row.addView(dot);

        // Name
        TextView nameView = new TextView(this);
        nameView.setText(name);
        nameView.setTextColor(textPrim);
        nameView.setTextSize(13.5f);
        LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        nameView.setLayoutParams(nameLp);
        row.addView(nameView);

        // Count badge
        TextView badge = makeBadge(String.valueOf(count), color);
        row.addView(badge);

        return row;
    }

    private TextView makeBadge(String text, int color) {
        TextView badge = new TextView(this);
        badge.setText(text);
        badge.setTextColor(0xFFFFFFFF);
        badge.setTextSize(10.5f);
        badge.setTypeface(null, Typeface.BOLD);
        badge.setGravity(Gravity.CENTER);
        badge.setMinWidth(dp(28));
        badge.setPadding(dp(7), dp(3), dp(7), dp(3));
        GradientDrawable badgeBg = new GradientDrawable();
        badgeBg.setColor(color);
        badgeBg.setCornerRadius(dp(20));
        badge.setBackground(badgeBg);
        return badge;
    }

    private LinearLayout makeSettingsToggleRow(String title, String sub,
                                                boolean on, int textPrim, int textSec) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(18), dp(12), dp(18), dp(12));
        row.setClickable(true);
        row.setFocusable(true);
        row.setBackground(getResources().getDrawable(
                android.R.drawable.list_selector_background, null));

        LinearLayout textCol = new LinearLayout(this);
        textCol.setOrientation(LinearLayout.VERTICAL);
        textCol.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView titleView = new TextView(this);
        titleView.setText(title);
        titleView.setTextColor(textPrim);
        titleView.setTextSize(13f);
        textCol.addView(titleView);

        TextView subView = new TextView(this);
        subView.setText(sub);
        subView.setTextColor(textSec);
        subView.setTextSize(10.5f);
        subView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        textCol.addView(subView);

        row.addView(textCol);

        TextView badge = makeBadge(on ? "ON" : "OFF", on ? 0xFFFF0000 : 0xFF000000);
        row.setTag(badge);
        row.addView(badge);

        return row;
    }

    private void applyToggleBadge(TextView badge, boolean on) {
        badge.setText(on ? "ON" : "OFF");
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(on ? 0xFFFF0000 : 0xFF000000);
        bg.setCornerRadius(dp(20));
        badge.setBackground(bg);
    }

    private View makeDivider(int color) {
        View div = new View(this);
        div.setBackgroundColor(color);
        div.setLayoutParams(new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 1));
        return div;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    // ── Storage permission ────────────────────────────────────────────────────

    private void requestStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    startActivity(new Intent(
                            Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                            Uri.parse("package:" + getPackageName())));
                } catch (Exception e) {
                    try {
                        startActivity(new Intent(
                                Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                    } catch (Exception ignored) {}
                }
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{
                        Manifest.permission.WRITE_EXTERNAL_STORAGE,
                        Manifest.permission.READ_EXTERNAL_STORAGE}, 100);
            }
        }
    }

    // ── App loading ───────────────────────────────────────────────────────────

    private void loadApps() {
        ProgressDialog pd = new ProgressDialog(this);
        pd.setMessage("Scanning installed apps...");
        pd.setCancelable(false);
        pd.show();

        new Thread(() -> {
            PackageManager pm = getPackageManager();
            List<ApplicationInfo> packages =
                    pm.getInstalledApplications(PackageManager.GET_META_DATA);
            List<AppInfo> result = new ArrayList<>();

            for (ApplicationInfo ai : packages) {
                if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
                AppInfo info     = new AppInfo();
                info.packageName = ai.packageName;
                info.apkPath     = ai.sourceDir;
                info.appName     = pm.getApplicationLabel(ai).toString();
                info.icon        = pm.getApplicationIcon(ai);
                info.protection  = DetectionUtils.detect(ai.sourceDir);
                result.add(info);
            }

            Collections.sort(result, (a, b) -> {
                int pa = protOrder(a.protection), pb = protOrder(b.protection);
                return pa != pb ? Integer.compare(pa, pb)
                                : a.appName.compareToIgnoreCase(b.appName);
            });

            runOnUiThread(() -> {
                if (isFinishing()) return;
                pd.dismiss();
                allApps.clear();
                allApps.addAll(result);
                filterApps(searchBox.getText().toString());
            });
        }).start();
    }

    private int protOrder(AppInfo.ProtectionType t) {
        switch (t) {
            case IJIAMI:          return 0;
            case JIAGU_360:       return 1;
            case TENCENT_LEGU:    return 2;
            case TENCENT_TPSHELL: return 3;
            case BAIDU:           return 4;
            case BANGCLE:         return 5;
            case DEXPROTECTOR:    return 6;
            case NETEASE:         return 7;
            case NQ_SHIELD:       return 8;
            case ALIBABA:         return 9;
            case SHADOW_SAFETY:   return 10;
            case NAGAPT:          return 11;
            case APPDOME:         return 12;
            case DPT_SHELL:       return 13;
            case NONE:            return 14;
            default:              return 15;
        }
    }

    private void filterApps(String query) {
        filtered.clear();
        String q = query.toLowerCase().trim();
        for (AppInfo app : allApps) {
            if (q.isEmpty()
                    || app.appName.toLowerCase().contains(q)
                    || app.packageName.toLowerCase().contains(q))
                filtered.add(app);
        }
        adapter.notifyDataSetChanged();
    }

    // ── Dump launch ───────────────────────────────────────────────────────────

    void startDump(AppInfo app) {
        new Thread(() -> {
            boolean ok = (rootOk != null) ? rootOk : ShellUtils.isRootAvailable();
            if (rootOk == null) rootOk = ok;

            runOnUiThread(() -> {
                if (!ok) {
                    Toast.makeText(this,
                            "Root not available — grant root access to Matrix Dumper.",
                            Toast.LENGTH_LONG).show();
                    return;
                }
                LogActivity.clearCache();
                Intent logIntent = new Intent(this, LogActivity.class);
                logIntent.putExtra("packageName", app.packageName);
                logIntent.putExtra("appName",     app.appName);
                logIntent.putExtra("protection",  app.protection.label);
                startActivity(logIntent);

                Intent svc = new Intent(this, DumperService.class);
                svc.putExtra("packageName", app.packageName);
                svc.putExtra("apkPath",     app.apkPath);
                svc.putExtra("protection",  app.protection.name());
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                    startForegroundService(svc);
                else
                    startService(svc);
            });
        }).start();
    }
}
