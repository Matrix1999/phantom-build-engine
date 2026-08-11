package com.ultra.dex2cvmp.ui;

import android.Manifest;
import android.app.Dialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.view.*;
import androidx.activity.result.ActivityResultLauncher;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import com.ultra.dex2cvmp.R;

public class PermissionHelper {

    public interface Callback {
        void onGranted();
        void onDenied(String reason);
    }

    public static void ensureStorage(Fragment fragment,
                                     ActivityResultLauncher<Intent> manageStorageLauncher,
                                     ActivityResultLauncher<String[]> runtimePermLauncher,
                                     Callback callback) {
        if (hasStorageAccess(fragment)) {
            callback.onGranted();
            return;
        }

        if (Build.VERSION.SDK_INT >= 30) {
            showFancyDialog(fragment, manageStorageLauncher, callback);
        } else if (Build.VERSION.SDK_INT >= 23) {
            runtimePermLauncher.launch(new String[]{
                    Manifest.permission.READ_EXTERNAL_STORAGE,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE
            });
        } else {
            callback.onGranted();
        }
    }

    private static void showFancyDialog(Fragment fragment,
                                        ActivityResultLauncher<Intent> manageStorageLauncher,
                                        Callback callback) {
        Dialog dialog = new Dialog(fragment.requireContext());
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(false);

        View v = LayoutInflater.from(fragment.requireContext())
                .inflate(R.layout.dialog_permission, null);
        dialog.setContentView(v);

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            dialog.getWindow().setLayout(
                    (int)(fragment.requireContext().getResources().getDisplayMetrics().widthPixels * 0.90f),
                    WindowManager.LayoutParams.WRAP_CONTENT);
            dialog.getWindow().setGravity(Gravity.CENTER);
            // dim behind
            dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            dialog.getWindow().setDimAmount(0.75f);
        }

        v.findViewById(R.id.btn_dialog_allow).setOnClickListener(btn -> {
            dialog.dismiss();
            Intent intent = new Intent(
                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:" + fragment.requireContext().getPackageName()));
            manageStorageLauncher.launch(intent);
        });

        v.findViewById(R.id.btn_dialog_skip).setOnClickListener(btn -> {
            dialog.dismiss();
            callback.onDenied("Storage permission was skipped");
        });

        dialog.show();
    }

    public static boolean hasStorageAccess(Fragment fragment) {
        if (Build.VERSION.SDK_INT >= 30) {
            return Environment.isExternalStorageManager();
        } else if (Build.VERSION.SDK_INT >= 23) {
            return ContextCompat.checkSelfPermission(fragment.requireContext(),
                    Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
                && ContextCompat.checkSelfPermission(fragment.requireContext(),
                    Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
        }
        return true;
    }
}
