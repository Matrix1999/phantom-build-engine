package com.matrix.dumper;

import android.content.Context;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.List;

public class AppListAdapter extends BaseAdapter {

    public interface DumpListener { void onDump(AppInfo app); }

    private final Context ctx;
    private final List<AppInfo> apps;
    private DumpListener dumpListener;

    public AppListAdapter(Context ctx, List<AppInfo> apps) {
        this.ctx  = ctx;
        this.apps = apps;
    }

    public void setDumpListener(DumpListener l) { this.dumpListener = l; }

    @Override public int getCount()          { return apps.size(); }
    @Override public Object getItem(int pos) { return apps.get(pos); }
    @Override public long getItemId(int pos) { return pos; }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder holder;
        if (convertView == null) {
            convertView = LayoutInflater.from(ctx).inflate(R.layout.item_app, parent, false);
            holder = new ViewHolder(convertView);
            convertView.setTag(holder);
        } else {
            holder = (ViewHolder) convertView.getTag();
        }

        AppInfo app  = apps.get(position);
        boolean dark = ThemeManager.isDark(ctx);

        holder.row.setBackgroundColor(ThemeManager.bg(ctx));
        holder.icon.setImageDrawable(app.icon);
        holder.name.setText(app.appName);
        holder.name.setTextColor(ThemeManager.textPrimary(ctx));
        holder.pkg.setText(app.packageName);
        holder.pkg.setTextColor(ThemeManager.textSecondary(ctx));
        holder.badge.setText(app.protection.label);
        holder.badge.setTextColor(Color.parseColor(app.protection.color));
        holder.dumpBtn.setTextColor(Color.parseColor("#FF0000"));

        holder.dumpBtn.setOnClickListener(v -> {
            if (dumpListener != null) dumpListener.onDump(app);
        });

        return convertView;
    }

    static class ViewHolder {
        LinearLayout row;
        ImageView icon;
        TextView name, pkg, badge, dumpBtn;
        ViewHolder(View v) {
            row     = (LinearLayout) v;
            icon    = v.findViewById(R.id.app_icon);
            name    = v.findViewById(R.id.app_name);
            pkg     = v.findViewById(R.id.app_pkg);
            badge   = v.findViewById(R.id.protection_badge);
            dumpBtn = v.findViewById(R.id.btn_dump);
        }
    }
}
