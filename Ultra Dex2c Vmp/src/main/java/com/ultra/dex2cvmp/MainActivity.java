package com.ultra.dex2cvmp;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.navigation.NavController;
import androidx.navigation.fragment.NavHostFragment;
import androidx.navigation.ui.NavigationUI;
import com.ultra.dex2cvmp.update.UpdateChecker;
import com.ultra.dex2cvmp.update.UpdateDialogFragment;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private final ActivityResultLauncher<String[]> permissionLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(),
                    results -> {});

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        NavHostFragment navHostFragment = (NavHostFragment) getSupportFragmentManager()
                .findFragmentById(R.id.nav_host_fragment);
        NavController navController = navHostFragment.getNavController();

        BottomNavigationView bottomNav = findViewById(R.id.bottom_nav);
        NavigationUI.setupWithNavController(bottomNav, navController);

        // Request only notification permission at startup — storage is requested
        // just-in-time before processing (Taurus Shield pattern).
        requestNotificationPermission();

        // Check for updates silently after UI is ready
        new Handler(Looper.getMainLooper()).postDelayed(() ->
            UpdateChecker.check(this, new UpdateChecker.Callback() {
                @Override
                public void onUpdateAvailable(String versionName, String changelog, String apkUrl) {
                    if (isFinishing() || isDestroyed()) return;
                    UpdateDialogFragment.newInstance(versionName, changelog, apkUrl)
                            .show(getSupportFragmentManager(), "update_dialog");
                }
                @Override
                public void onNoUpdate() {}
            }), 1800L);
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33) {
            List<String> needed = new ArrayList<>();
            if (ContextCompat.checkSelfPermission(this,
                    Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                needed.add(Manifest.permission.POST_NOTIFICATIONS);
            }
            if (!needed.isEmpty()) {
                permissionLauncher.launch(needed.toArray(new String[0]));
            }
        }
    }
}
