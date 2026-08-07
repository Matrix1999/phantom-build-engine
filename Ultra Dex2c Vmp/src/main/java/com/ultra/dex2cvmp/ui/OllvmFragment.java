package com.ultra.dex2cvmp.ui;

import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.SwitchCompat;
import androidx.fragment.app.Fragment;

import com.ultra.dex2cvmp.R;

import java.util.ArrayList;
import java.util.List;

public class OllvmFragment extends Fragment {

    private static final String PREFS_NAME   = "dex2c_prefs";
    private static final String KEY_ENABLED  = "use_ollvm_ndk";
    private static final String KEY_LEVEL    = "ollvm_level";

    // Custom-pass individual keys (stored as booleans, default true)
    static final String KEY_PASS_FLA   = "ollvm_pass_fla";
    static final String KEY_PASS_BCF   = "ollvm_pass_bcf";
    static final String KEY_PASS_SUB   = "ollvm_pass_sub";
    static final String KEY_PASS_SOBF  = "ollvm_pass_sobf";
    static final String KEY_PASS_SPLIT = "ollvm_pass_split";
    static final String KEY_PASS_IBR   = "ollvm_pass_ibr";
    static final String KEY_PASS_ICALL = "ollvm_pass_icall";
    static final String KEY_PASS_IGV   = "ollvm_pass_igv";

    /** Sentinel level value that means "custom passes". */
    static final int LEVEL_CUSTOM = 9;
    private static final int LEVEL_COUNT = 9; // preset levels 0-8

    // ── Preset level cards ───────────────────────────────────────────────────
    private final View[]      levelCards    = new View[LEVEL_COUNT];
    private final TextView[]  tvLevelActive = new TextView[LEVEL_COUNT];
    private final ImageView[] ivLevelIcons  = new ImageView[LEVEL_COUNT];

    // ── Custom card ──────────────────────────────────────────────────────────
    private View      cardCustom;
    private TextView  tvCustomActive;
    private ImageView ivCustomIcon;
    private LinearLayout llCustomPasses;

    // ── Pass-row switches ────────────────────────────────────────────────────
    private SwitchCompat swFla, swBcf, swSub, swSobf, swSplit, swIbr, swIcall, swIgv;

    // ── Misc ─────────────────────────────────────────────────────────────────
    private SwitchCompat swEngine;
    private LinearLayout llLevels;
    private final List<ObjectAnimator> animators = new ArrayList<>();

    // ── Pass metadata ────────────────────────────────────────────────────────
    private static final class PassInfo {
        final String flag, name, tag, description, protects, badgeColor, prefKey;
        PassInfo(String flag, String name, String tag, String description,
                 String protects, String badgeColor, String prefKey) {
            this.flag = flag; this.name = name; this.tag = tag;
            this.description = description; this.protects = protects;
            this.badgeColor = badgeColor; this.prefKey = prefKey;
        }
    }

    private static final PassInfo[] PASSES = {
        new PassInfo(
            "-fla", "Control-Flow Flattening", "Scrambles code flow paths",
            "Your app's logic normally flows like a story — step A leads to B, then C. "
            + "This pass collapses every function into one giant loop with a central dispatcher. "
            + "Instead of seeing a clear path, anyone trying to reverse the code sees hundreds of cases "
            + "spinning in a roundabout. The real order of execution becomes completely invisible.",
            "Defeats static control-flow analysis tools like IDA Pro and Ghidra. "
            + "Makes it impossible to trace how the app reaches any given decision.",
            "#00E5FF", KEY_PASS_FLA
        ),
        new PassInfo(
            "-bcf", "Bogus Control Flow", "Inserts fake dead-code branches",
            "Injects fake branches filled with junk code that never actually executes. "
            + "The conditions guarding them are mathematically always true or always false — "
            + "but a decompiler cannot tell that. Tools like IDA and Ghidra see dozens of dead paths "
            + "and get completely confused about what code is real and what is noise.",
            "Confuses decompilers and disassemblers. Doubles or triples the apparent complexity of every function. "
            + "Makes automated analysis produce incorrect or incomplete results.",
            "#FF1744", KEY_PASS_BCF
        ),
        new PassInfo(
            "-sub", "Instruction Substitution", "Replaces math ops with complex equivalents",
            "Simple operations like a + b get swapped for complex bitwise equivalents that produce "
            + "the exact same result. For example a + b becomes a - (-b) or a long chain of bit shifts "
            + "and XORs. The app runs identically, but the assembly looks completely alien to anyone reading it.",
            "Makes arithmetic and logic in native methods unreadable at the assembly level. "
            + "Breaks automated pattern-matching tools that recognize standard instruction sequences.",
            "#FF6D00", KEY_PASS_SUB
        ),
        new PassInfo(
            "-sobf", "String Encryption", "XOR-encrypts all string literals in the binary",
            "Every string inside the native code — URLs, class names, error messages, keys, identifiers — "
            + "gets XOR-encrypted and stored scrambled in the binary. They only decrypt back to readable "
            + "text at runtime, in memory. Anyone opening the APK in a hex editor or strings tool sees "
            + "gibberish instead of anything meaningful.",
            "Hides all hardcoded strings from static inspection. URLs, API endpoints, class names, "
            + "and any text your app references are completely invisible until runtime.",
            "#FFAB00", KEY_PASS_SOBF
        ),
        new PassInfo(
            "-split", "Basic-Block Splitting", "Bloats the function graph with chopped blocks",
            "Takes each chunk of straight-line code and chops it into tiny pieces, then reconnects "
            + "them with explicit jumps. This massively inflates the function count and the size of the "
            + "control-flow graph. Reverse engineering tools struggle to reconstruct the original function "
            + "boundaries when everything is fragmented.",
            "Breaks automated function boundary detection. Makes decompiled output enormous and hard "
            + "to follow. Inflates the size of the control-flow graph seen by analysis tools.",
            "#C6FF00", KEY_PASS_SPLIT
        ),
        new PassInfo(
            "-ibr", "Indirect Branch", "Hides jump destinations from disassemblers",
            "Instead of 'jump to address X' — which any disassembler can follow instantly — "
            + "the destination address is computed at runtime from a register or lookup table. "
            + "Disassemblers cannot statically trace where execution goes next, so the control-flow "
            + "graph they produce becomes a map full of unknowns and dead ends.",
            "Defeats static disassembly. Breaks cross-reference navigation in IDA Pro, Ghidra, "
            + "and Binary Ninja. Makes jump-table recovery fail.",
            "#00E676", KEY_PASS_IBR
        ),
        new PassInfo(
            "-icall", "Indirect Call", "Hides which function is being called",
            "Function calls are made through a register pointer instead of a direct call instruction. "
            + "Rather than 'call myFunction()', the app stores the function address in a register "
            + "and jumps through it. Static analysis tools lose track of what function is being called, "
            + "completely breaking cross-reference analysis that attackers rely on to navigate the code.",
            "Breaks call-graph analysis. Makes it impossible to statically determine what function "
            + "a call site targets. Defeats automated API-usage auditing.",
            "#D500F9", KEY_PASS_ICALL
        ),
        new PassInfo(
            "-igv", "Indirect Global Variable", "Hides global data access through indirection",
            "Global variables and constants are accessed through pointer indirection rather than "
            + "directly. Every global read or write goes through a computed pointer layer. An attacker "
            + "cannot simply look up where a global is referenced — the data flow is obscured behind "
            + "indirection that tools cannot resolve statically.",
            "Hides which global variables a function accesses. Breaks data-flow analysis. "
            + "Makes tracing constants and configuration values through the binary extremely difficult.",
            "#2979FF", KEY_PASS_IGV
        )
    };

    // ── Pass-row view IDs (in same order as PASSES array) ───────────────────
    private static final int[] ROW_IDS = {
        R.id.row_pass_fla, R.id.row_pass_bcf, R.id.row_pass_sub, R.id.row_pass_sobf,
        R.id.row_pass_split, R.id.row_pass_ibr, R.id.row_pass_icall, R.id.row_pass_igv
    };
    private static final int[] SW_IDS = {
        R.id.sw_pass_fla, R.id.sw_pass_bcf, R.id.sw_pass_sub, R.id.sw_pass_sobf,
        R.id.sw_pass_split, R.id.sw_pass_ibr, R.id.sw_pass_icall, R.id.sw_pass_igv
    };

    // ── Inflation ────────────────────────────────────────────────────────────

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_ollvm, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        swEngine = view.findViewById(R.id.sw_ollvm_engine);
        llLevels = view.findViewById(R.id.ll_ollvm_levels);

        // ── Wire up preset level cards ───────────────────────────────────
        int[] cardIds = {
            R.id.card_level_0, R.id.card_level_1, R.id.card_level_2,
            R.id.card_level_3, R.id.card_level_4, R.id.card_level_5,
            R.id.card_level_6, R.id.card_level_7, R.id.card_level_8
        };
        int[] activeIds = {
            R.id.tv_level_0_active, R.id.tv_level_1_active, R.id.tv_level_2_active,
            R.id.tv_level_3_active, R.id.tv_level_4_active, R.id.tv_level_5_active,
            R.id.tv_level_6_active, R.id.tv_level_7_active, R.id.tv_level_8_active
        };
        int[] iconIds = {
            R.id.iv_level_0_icon, R.id.iv_level_1_icon, R.id.iv_level_2_icon,
            R.id.iv_level_3_icon, R.id.iv_level_4_icon, R.id.iv_level_5_icon,
            R.id.iv_level_6_icon, R.id.iv_level_7_icon, R.id.iv_level_8_icon
        };
        for (int i = 0; i < LEVEL_COUNT; i++) {
            levelCards[i]    = view.findViewById(cardIds[i]);
            tvLevelActive[i] = view.findViewById(activeIds[i]);
            ivLevelIcons[i]  = view.findViewById(iconIds[i]);
        }

        // ── Wire up custom card ──────────────────────────────────────────
        cardCustom     = view.findViewById(R.id.card_level_custom);
        tvCustomActive = view.findViewById(R.id.tv_custom_active);
        ivCustomIcon   = view.findViewById(R.id.iv_custom_icon);
        llCustomPasses = view.findViewById(R.id.ll_custom_passes);

        // ── About card ───────────────────────────────────────────────────
        view.findViewById(R.id.card_ollvm_about).setOnClickListener(v -> showAboutModal());

        // ── Restore saved state ──────────────────────────────────────────
        SharedPreferences p = prefs();
        boolean enabled = p.getBoolean(KEY_ENABLED, false);
        int     level   = p.getInt(KEY_LEVEL, 0);

        swEngine.setChecked(enabled);
        llLevels.setVisibility(enabled ? View.VISIBLE : View.GONE);
        selectLevel(level, false);

        // ── Engine master toggle ─────────────────────────────────────────
        swEngine.setOnCheckedChangeListener((btn, checked) -> {
            prefs().edit().putBoolean(KEY_ENABLED, checked).apply();
            llLevels.setVisibility(checked ? View.VISIBLE : View.GONE);
            if (checked) {
                int savedLevel = prefs().getInt(KEY_LEVEL, 0);
                selectLevel(savedLevel, true);
            }
        });

        // ── Preset level card clicks ─────────────────────────────────────
        for (int i = 0; i < LEVEL_COUNT; i++) {
            final int idx = i;
            levelCards[i].setOnClickListener(v -> {
                prefs().edit().putInt(KEY_LEVEL, idx).apply();
                selectLevel(idx, true);
            });
        }

        // ── Custom card click ────────────────────────────────────────────
        cardCustom.setOnClickListener(v -> {
            prefs().edit().putInt(KEY_LEVEL, LEVEL_CUSTOM).apply();
            selectLevel(LEVEL_CUSTOM, true);
        });

        // ── Pass-row toggle + info modal wiring ──────────────────────────
        setupPassRows(view);

        startAnimations();
    }

    // ── Pass rows ────────────────────────────────────────────────────────────

    private void setupPassRows(View root) {
        for (int i = 0; i < PASSES.length; i++) {
            final int idx = i;
            final PassInfo pass = PASSES[i];

            View     row = root.findViewById(ROW_IDS[i]);
            SwitchCompat sw  = root.findViewById(SW_IDS[i]);

            // Load saved state (all passes default ON)
            sw.setChecked(prefs().getBoolean(pass.prefKey, false));

            // Toggle auto-saves
            sw.setOnCheckedChangeListener((btn, checked) ->
                prefs().edit().putBoolean(pass.prefKey, checked).apply());

            // Tap row body (not the switch) → detail modal
            row.setOnClickListener(v -> showPassDetailModal(idx));
        }
    }

    // ── Level selection ───────────────────────────────────────────────────────

    private void selectLevel(int level, boolean animate) {
        // Preset cards 0-8
        for (int i = 0; i < LEVEL_COUNT; i++) {
            boolean active = (i == level);
            levelCards[i].setBackgroundResource(
                    active ? R.drawable.bg_level_active : R.drawable.bg_level_inactive);
            tvLevelActive[i].setVisibility(active ? View.VISIBLE : View.GONE);

            if (active && animate) {
                bounce(ivLevelIcons[i]);
            }
        }

        // Custom card
        boolean customActive = (level == LEVEL_CUSTOM);
        cardCustom.setBackgroundResource(
                customActive ? R.drawable.bg_level_active : R.drawable.bg_level_inactive);
        tvCustomActive.setVisibility(customActive ? View.VISIBLE : View.GONE);
        llCustomPasses.setVisibility(customActive ? View.VISIBLE : View.GONE);

        if (customActive && animate) {
            bounce(ivCustomIcon);
        }
    }

    private void bounce(ImageView iv) {
        if (iv == null) return;
        ObjectAnimator sx = ObjectAnimator.ofFloat(iv, "scaleX", 1f, 1.3f, 1f);
        ObjectAnimator sy = ObjectAnimator.ofFloat(iv, "scaleY", 1f, 1.3f, 1f);
        sx.setDuration(300); sx.setInterpolator(new DecelerateInterpolator()); sx.start();
        sy.setDuration(300); sy.setInterpolator(new DecelerateInterpolator()); sy.start();
    }

    // ── Pass detail modal ─────────────────────────────────────────────────────

    private void showPassDetailModal(int passIdx) {
        PassInfo pass = PASSES[passIdx];

        View dv = LayoutInflater.from(requireContext())
                .inflate(R.layout.dialog_pass_detail, null);

        // Badge
        TextView badge = dv.findViewById(R.id.tv_pass_badge);
        badge.setText(pass.flag);
        badge.setTextColor(android.graphics.Color.parseColor(pass.badgeColor));

        // Name
        ((TextView) dv.findViewById(R.id.tv_pass_name)).setText(pass.name);

        // Tag
        TextView tagView = dv.findViewById(R.id.tv_pass_tag);
        tagView.setText(pass.tag);
        tagView.setTextColor(android.graphics.Color.parseColor(pass.badgeColor));

        // Description + protects
        ((TextView) dv.findViewById(R.id.tv_pass_description)).setText(pass.description);
        ((TextView) dv.findViewById(R.id.tv_pass_protects)).setText(pass.protects);

        // Modal toggle mirrors the main toggle — they stay in sync
        SwitchCompat modalSw = dv.findViewById(R.id.sw_pass_modal_toggle);
        modalSw.setChecked(prefs().getBoolean(pass.prefKey, false));
        modalSw.setOnCheckedChangeListener((btn, checked) -> {
            prefs().edit().putBoolean(pass.prefKey, checked).apply();
            // Sync the row toggle in the main list
            View passRootView = getView();
            if (passRootView != null) {
                SwitchCompat rowSw = passRootView.findViewById(SW_IDS[passIdx]);
                if (rowSw != null) rowSw.setChecked(checked);
            }
        });

        AlertDialog dialog = new AlertDialog.Builder(requireContext())
                .setView(dv).create();
        if (dialog.getWindow() != null)
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);

        dv.findViewById(R.id.btn_pass_close).setOnClickListener(v -> dialog.dismiss());
        dialog.show();
    }

    // ── Icon animations ───────────────────────────────────────────────────────
    //
    //  0 Phantom Level  — blazing fast spin  (2800 ms)
    //  1 Ultimate Level — fast spin          (4500 ms)
    //  2 Supreme Level  — fast reverse spin  (6000 ms)
    //  3 Advanced Level — medium reverse     (9000 ms)
    //  4 Turbo          — energetic pulse    (750 ms)
    //  5 Ultra Level    — slow forward spin  (13000 ms)
    //  6 Prime Level    — slow reverse spin  (17000 ms)
    //  7 Nova Level     — alpha breathe      (2500 ms)
    //  8 Lite Level     — slow alpha breathe (4500 ms)
    //  Custom           — gentle pulse       (1800 ms)

    private void startAnimations() {
        addSpin(ivLevelIcons[0], 2800,  true);
        addSpin(ivLevelIcons[1], 4500,  true);
        addSpin(ivLevelIcons[2], 6000,  false);
        addSpin(ivLevelIcons[3], 9000,  false);
        addPulse(ivLevelIcons[4], 750);
        addSpin(ivLevelIcons[5], 13000, true);
        addSpin(ivLevelIcons[6], 17000, false);
        addBreathe(ivLevelIcons[7], 2500);
        addBreathe(ivLevelIcons[8], 4500);
        addPulse(ivCustomIcon, 1800);          // custom card — gentle pulse
    }

    private void addSpin(ImageView iv, long durationMs, boolean forward) {
        if (iv == null) return;
        ObjectAnimator anim = ObjectAnimator.ofFloat(iv, "rotation",
                forward ? 0f : 360f, forward ? 360f : 0f);
        anim.setDuration(durationMs);
        anim.setInterpolator(new LinearInterpolator());
        anim.setRepeatCount(ValueAnimator.INFINITE);
        anim.setRepeatMode(ValueAnimator.RESTART);
        anim.start();
        animators.add(anim);
    }

    private void addPulse(ImageView iv, long halfCycleMs) {
        if (iv == null) return;
        for (String prop : new String[]{"scaleX", "scaleY"}) {
            ObjectAnimator a = ObjectAnimator.ofFloat(iv, prop, 1f, 1.28f, 1f);
            a.setDuration(halfCycleMs);
            a.setRepeatCount(ValueAnimator.INFINITE);
            a.setRepeatMode(ValueAnimator.RESTART);
            a.start();
            animators.add(a);
        }
    }

    private void addBreathe(ImageView iv, long durationMs) {
        if (iv == null) return;
        ObjectAnimator anim = ObjectAnimator.ofFloat(iv, "alpha", 1f, 0.25f, 1f);
        anim.setDuration(durationMs);
        anim.setRepeatCount(ValueAnimator.INFINITE);
        anim.setRepeatMode(ValueAnimator.RESTART);
        anim.start();
        animators.add(anim);
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        for (ObjectAnimator a : animators) a.cancel();
        animators.clear();
    }

    // ── About modal ───────────────────────────────────────────────────────────

    private void showAboutModal() {
        View dv = LayoutInflater.from(requireContext())
                .inflate(R.layout.dialog_ollvm_about, null);
        AlertDialog dialog = new AlertDialog.Builder(requireContext())
                .setView(dv).create();
        if (dialog.getWindow() != null)
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        dv.findViewById(R.id.btn_close_dialog).setOnClickListener(v -> dialog.dismiss());
        dialog.show();
    }

    // ── SharedPreferences helper ──────────────────────────────────────────────

    private SharedPreferences prefs() {
        return requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }
}
