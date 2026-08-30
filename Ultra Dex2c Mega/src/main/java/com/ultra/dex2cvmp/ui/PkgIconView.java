package com.ultra.dex2cvmp.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.*;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.LinearInterpolator;

/**
 * Tiny self-animating package/namespace icon.
 * Draws a slowly rotating hexagon outline with three counter-orbiting dots —
 * visually represents a code namespace / package node.
 * Auto-starts on attach, auto-stops on detach. No adapter changes needed.
 */
public class PkgIconView extends View {

    private static final int GREEN = 0xFF10B981;

    private final Paint strokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint dotPaint    = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path  hexPath     = new Path();

    private float angle = 0f;
    private ValueAnimator animator;

    public PkgIconView(Context ctx)                           { super(ctx); init(); }
    public PkgIconView(Context ctx, AttributeSet a)          { super(ctx, a); init(); }
    public PkgIconView(Context ctx, AttributeSet a, int def) { super(ctx, a, def); init(); }

    private void init() {
        strokePaint.setStyle(Paint.Style.STROKE);
        strokePaint.setColor(GREEN);
        strokePaint.setStrokeCap(Paint.Cap.ROUND);
        strokePaint.setStrokeJoin(Paint.Join.ROUND);

        dotPaint.setStyle(Paint.Style.FILL);
        dotPaint.setColor(GREEN);

        animator = ValueAnimator.ofFloat(0f, 360f);
        animator.setDuration(5000);
        animator.setRepeatCount(ValueAnimator.INFINITE);
        animator.setInterpolator(new LinearInterpolator());
        animator.addUpdateListener(a -> { angle = (float) a.getAnimatedValue(); invalidate(); });
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float W  = getWidth();
        float H  = getHeight();
        float cx = W / 2f;
        float cy = H / 2f;
        float r  = Math.min(cx, cy) * 0.82f;

        strokePaint.setStrokeWidth(Math.min(W, H) * 0.09f);

        // Outer rotating hexagon
        canvas.save();
        canvas.rotate(angle, cx, cy);
        hexPath.rewind();
        for (int i = 0; i < 6; i++) {
            double a = Math.toRadians(60 * i - 90);
            float x = cx + r * (float) Math.cos(a);
            float y = cy + r * (float) Math.sin(a);
            if (i == 0) hexPath.moveTo(x, y); else hexPath.lineTo(x, y);
        }
        hexPath.close();
        strokePaint.setAlpha(220);
        canvas.drawPath(hexPath, strokePaint);
        canvas.restore();

        // Inner counter-rotating triangle of dots
        canvas.save();
        canvas.rotate(-angle * 0.6f, cx, cy);
        float innerR = r * 0.40f;
        float dotR   = Math.min(W, H) * 0.09f;
        dotPaint.setAlpha(210);
        for (int i = 0; i < 3; i++) {
            double a = Math.toRadians(120 * i - 90);
            float dx = cx + innerR * (float) Math.cos(a);
            float dy = cy + innerR * (float) Math.sin(a);
            canvas.drawCircle(dx, dy, dotR, dotPaint);
        }
        canvas.restore();

        // Centre dot
        dotPaint.setAlpha(160);
        canvas.drawCircle(cx, cy, Math.min(W, H) * 0.06f, dotPaint);
    }

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (animator != null && !animator.isRunning()) animator.start();
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (animator != null) animator.cancel();
    }
}
