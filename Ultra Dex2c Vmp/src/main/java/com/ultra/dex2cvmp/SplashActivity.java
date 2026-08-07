package com.ultra.dex2cvmp;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class SplashActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_splash);

        ImageView logo    = findViewById(R.id.splash_logo);
        TextView  title   = findViewById(R.id.splash_title);
        TextView  subtitle = findViewById(R.id.splash_subtitle);
        View      scanLine = findViewById(R.id.scan_line);

        logo.setAlpha(0f);
        title.setAlpha(0f);
        subtitle.setAlpha(0f);

        ObjectAnimator logoFade   = ObjectAnimator.ofFloat(logo,    "alpha",  0f, 1f);
        ObjectAnimator logoScaleX = ObjectAnimator.ofFloat(logo,    "scaleX", 0.6f, 1f);
        ObjectAnimator logoScaleY = ObjectAnimator.ofFloat(logo,    "scaleY", 0.6f, 1f);
        ObjectAnimator titleFade  = ObjectAnimator.ofFloat(title,   "alpha",  0f, 1f);
        ObjectAnimator subFade    = ObjectAnimator.ofFloat(subtitle, "alpha",  0f, 0.9f);
        ObjectAnimator scanAnim   = ObjectAnimator.ofFloat(scanLine, "translationY", -400f, 400f);

        logoFade.setDuration(600);
        logoScaleX.setDuration(600);
        logoScaleY.setDuration(600);

        titleFade.setDuration(400);
        titleFade.setStartDelay(380);

        subFade.setDuration(350);
        subFade.setStartDelay(550);

        scanAnim.setDuration(1400);
        scanAnim.setStartDelay(150);
        scanAnim.setRepeatCount(1);

        AnimatorSet set = new AnimatorSet();
        set.playTogether(logoFade, logoScaleX, logoScaleY, titleFade, subFade, scanAnim);
        set.setInterpolator(new AccelerateDecelerateInterpolator());
        set.start();

        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            startActivity(new Intent(this, MainActivity.class));
            finish();
            overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out);
        }, 2200);
    }
}
