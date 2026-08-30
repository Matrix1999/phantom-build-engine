package com.ultra.dex2cvmp.ui.tree;

import android.content.res.ColorStateList;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import com.ultra.dex2cvmp.R;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Flat-list RecyclerView adapter that renders a 3-level Package → Class → Method tree.
 * Packages and classes are collapsible. Each level has checkboxes.
 * Supports live search filtering by package name, class name, or full class path.
 */
public class ClassTreeAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    public interface OnSelectionChangedListener {
        void onSelectionChanged(int selectedClasses, int totalClasses);
    }

    private static final int TYPE_PACKAGE = 0;
    private static final int TYPE_CLASS   = 1;
    private static final int TYPE_METHOD  = 2;

    private final List<Object> items = new ArrayList<>();
    private List<PackageNode> packages;
    private String searchQuery = "";
    private OnSelectionChangedListener selectionListener;

    public void setData(List<PackageNode> packages) {
        this.packages = packages;
        rebuildItems();
        notifyDataSetChanged();
        notifySelectionChanged();
    }

    public void setOnSelectionChangedListener(OnSelectionChangedListener l) {
        this.selectionListener = l;
    }

    /** Filter visible tree by package name, class simple name, or full class name. */
    public void setSearchQuery(String query) {
        this.searchQuery = query == null ? "" : query.trim().toLowerCase(Locale.US);
        rebuildItems();
        notifyDataSetChanged();
    }

    private boolean matchesQuery(PackageNode pkg, ClassNode cls) {
        if (searchQuery.isEmpty()) return true;
        return pkg.name.toLowerCase(Locale.US).contains(searchQuery)
            || cls.simpleName.toLowerCase(Locale.US).contains(searchQuery)
            || cls.fullName.toLowerCase(Locale.US).contains(searchQuery);
    }

    private void rebuildItems() {
        items.clear();
        if (packages == null) return;
        for (PackageNode pkg : packages) {
            boolean pkgMatches = !searchQuery.isEmpty()
                    && pkg.name.toLowerCase(Locale.US).contains(searchQuery);

            // Collect visible classes for this package
            List<ClassNode> visibleClasses = new ArrayList<>();
            for (ClassNode cls : pkg.classes) {
                if (matchesQuery(pkg, cls)) visibleClasses.add(cls);
            }

            if (visibleClasses.isEmpty() && !searchQuery.isEmpty()) continue;

            items.add(pkg);
            boolean forceExpand = !searchQuery.isEmpty();
            if (pkg.expanded || forceExpand) {
                for (ClassNode cls : pkg.classes) {
                    if (!matchesQuery(pkg, cls)) continue;
                    items.add(cls);
                    if (cls.expanded) {
                        for (MethodNode m : cls.methods) items.add(m);
                    }
                }
            }
        }
    }

    /** Collect selected filter text from the tree. */
    public String buildFilter() {
        if (packages == null) return "";
        StringBuilder sb = new StringBuilder();
        for (PackageNode pkg : packages) {
            for (ClassNode cls : pkg.classes) {
                String part = cls.buildFilter();
                if (part != null && !part.isEmpty()) {
                    if (sb.length() > 0) sb.append('\n');
                    sb.append(part);
                }
            }
        }
        return sb.toString();
    }

    private void notifySelectionChanged() {
        if (selectionListener == null || packages == null) return;
        int sel = 0, total = 0;
        for (PackageNode pkg : packages) {
            for (ClassNode cls : pkg.classes) {
                total++;
                Boolean s = cls.getSelectionState();
                if (s != Boolean.FALSE) sel++;
            }
        }
        selectionListener.onSelectionChanged(sel, total);
    }

    public void selectAll(boolean val) {
        if (packages == null) return;
        for (PackageNode pkg : packages) pkg.setAll(val);
        notifyDataSetChanged();
        notifySelectionChanged();
    }

    @Override public int getItemCount() { return items.size(); }

    @Override public int getItemViewType(int pos) {
        Object item = items.get(pos);
        if (item instanceof PackageNode) return TYPE_PACKAGE;
        if (item instanceof ClassNode)   return TYPE_CLASS;
        return TYPE_METHOD;
    }

    @NonNull @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inf = LayoutInflater.from(parent.getContext());
        switch (viewType) {
            case TYPE_PACKAGE:
                return new PackageVH(inf.inflate(R.layout.item_tree_package, parent, false));
            case TYPE_CLASS:
                return new ClassVH(inf.inflate(R.layout.item_tree_class, parent, false));
            default:
                return new MethodVH(inf.inflate(R.layout.item_tree_method, parent, false));
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int pos) {
        Object item = items.get(pos);
        if (holder instanceof PackageVH) bindPackage((PackageVH) holder, (PackageNode) item);
        else if (holder instanceof ClassVH) bindClass((ClassVH) holder, (ClassNode) item);
        else bindMethod((MethodVH) holder, (MethodNode) item);
    }

    // ── Package ───────────────────────────────────────────────────────────────
    private void bindPackage(PackageVH h, PackageNode pkg) {
        h.tvName.setText(pkg.name);
        h.tvMeta.setText(pkg.classes.size() + " class" + (pkg.classes.size() != 1 ? "es" : ""));
        boolean forceExpand = !searchQuery.isEmpty();
        h.ivArrow.setRotation((pkg.expanded || forceExpand) ? 90f : 0f);

        Boolean state = pkg.getSelectionState();
        h.checkBox.setButtonTintList(greenTint(h.checkBox));
        h.checkBox.setOnCheckedChangeListener(null);
        if (state == null) {
            h.checkBox.setChecked(true);
            h.checkBox.setAlpha(0.5f);
        } else {
            h.checkBox.setChecked(state);
            h.checkBox.setAlpha(1f);
        }

        h.checkBox.setOnCheckedChangeListener((btn, checked) -> {
            pkg.setAll(checked);
            rebuildItems();
            notifyDataSetChanged();
            notifySelectionChanged();
        });

        h.itemView.setOnClickListener(v -> {
            pkg.expanded = !pkg.expanded;
            rebuildItems();
            notifyDataSetChanged();
        });
    }

    // ── Class ─────────────────────────────────────────────────────────────────
    private void bindClass(ClassVH h, ClassNode cls) {
        h.tvName.setText(cls.simpleName);
        h.tvFull.setText(cls.fullName);
        int mCount = cls.methods.size();
        h.tvMeta.setText(mCount > 0 ? mCount + " method" + (mCount != 1 ? "s" : "") : "no methods");
        h.ivArrow.setVisibility(mCount > 0 ? View.VISIBLE : View.INVISIBLE);
        h.ivArrow.setRotation(cls.expanded ? 90f : 0f);

        Boolean state = cls.getSelectionState();
        h.checkBox.setButtonTintList(greenTint(h.checkBox));
        h.checkBox.setOnCheckedChangeListener(null);
        if (state == null) {
            h.checkBox.setChecked(true);
            h.checkBox.setAlpha(0.5f);
        } else {
            h.checkBox.setChecked(state == Boolean.TRUE);
            h.checkBox.setAlpha(1f);
        }

        h.checkBox.setOnCheckedChangeListener((btn, checked) -> {
            cls.setAllMethods(checked);
            notifyDataSetChanged();
            notifySelectionChanged();
        });

        h.itemView.setOnClickListener(v -> {
            if (mCount == 0) return;
            cls.expanded = !cls.expanded;
            rebuildItems();
            notifyDataSetChanged();
        });
    }

    // ── Method ────────────────────────────────────────────────────────────────
    private void bindMethod(MethodVH h, MethodNode m) {
        h.tvSig.setText(m.displaySig);
        h.checkBox.setButtonTintList(greenTint(h.checkBox));
        h.checkBox.setOnCheckedChangeListener(null);
        h.checkBox.setChecked(m.selected);
        h.checkBox.setOnCheckedChangeListener((btn, checked) -> {
            m.selected = checked;
            notifyDataSetChanged();
            notifySelectionChanged();
        });
        h.itemView.setOnClickListener(v -> {
            m.selected = !m.selected;
            notifyDataSetChanged();
            notifySelectionChanged();
        });
    }

    private ColorStateList greenTint(View v) {
        return v.getResources().getColorStateList(R.color.checkbox_tint, null);
    }

    // ── ViewHolders ───────────────────────────────────────────────────────────
    static class PackageVH extends RecyclerView.ViewHolder {
        TextView tvName, tvMeta; ImageView ivArrow; CheckBox checkBox;
        PackageVH(View v) {
            super(v);
            tvName   = v.findViewById(R.id.tv_pkg_name);
            tvMeta   = v.findViewById(R.id.tv_pkg_meta);
            ivArrow  = v.findViewById(R.id.iv_arrow);
            checkBox = v.findViewById(R.id.checkbox);
        }
    }

    static class ClassVH extends RecyclerView.ViewHolder {
        TextView tvName, tvFull, tvMeta; ImageView ivArrow; CheckBox checkBox;
        ClassVH(View v) {
            super(v);
            tvName   = v.findViewById(R.id.tv_class_name);
            tvFull   = v.findViewById(R.id.tv_class_full);
            tvMeta   = v.findViewById(R.id.tv_class_meta);
            ivArrow  = v.findViewById(R.id.iv_arrow);
            checkBox = v.findViewById(R.id.checkbox);
        }
    }

    static class MethodVH extends RecyclerView.ViewHolder {
        TextView tvSig; CheckBox checkBox;
        MethodVH(View v) {
            super(v);
            tvSig    = v.findViewById(R.id.tv_method_sig);
            checkBox = v.findViewById(R.id.checkbox);
        }
    }
}
