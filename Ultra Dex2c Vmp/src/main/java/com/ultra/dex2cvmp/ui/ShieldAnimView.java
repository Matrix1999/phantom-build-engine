package com.ultra.dex2cvmp.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.*;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.LinearInterpolator;

import java.util.Random;

/**
 * Advanced protection animation — multi-ring radar, orbiting data nodes,
 * circuit-trace streams, hex grid, matrix rain columns, and deep green glow.
 */
public class ShieldAnimView extends View {

    // Deep matrix green palette
    private static final int GREEN_BRIGHT = 0xFF00E676;
    private static final int GREEN_MID    = 0xFF00C853;
    private static final int GREEN_DIM    = 0xFF005C28;
    private static final int GREEN_GLOW   = 0xFF00FF6A;

    // Animators
    private ValueAnimator pulseAnim;
    private ValueAnimator orbitAnim;
    private ValueAnimator scanAnim;
    private ValueAnimator radarAnim;
    private ValueAnimator glitchAnim;

    private float pulse     = 0f;  // 0..1
    private float orbit     = 0f;  // 0..360
    private float scan      = 0f;  // 0..1
    private float radar     = 0f;  // 0..360 sweep angle
    private float glitch    = 0f;  // 0..1 flicker

    // Matrix rain columns
    private static final int RAIN_COLS = 12;
    private final float[] rainY    = new float[RAIN_COLS];
    private final int[]   rainChar = new int[RAIN_COLS];
    private final float[] rainX    = new float[RAIN_COLS];
    private final float[] rainAlpha= new float[RAIN_COLS];
    private final Random  rng      = new Random(42);

    // Circuit nodes (fixed positions relative to center, as angles+radii)
    private static final int NODE_COUNT = 6;
    private final float[] nodeAngle = {0f, 60f, 120f, 180f, 240f, 300f};
    private final float[] nodeR     = {0.55f, 0.70f, 0.58f, 0.72f, 0.60f, 0.68f};

    // Paints
    private final Paint bgPaint      = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ringPaint    = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint dashRingPaint= new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glowPaint    = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint radarPaint   = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint nodePaint    = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint linePaint    = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint rainPaint    = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint shieldPath   = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint lockPaint    = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint hexPaint     = new Paint(Paint.ANTI_ALIAS_FLAG);

    private final RectF  arcBounds   = new RectF();
    private final Path   shieldShape = new Path();

    public ShieldAnimView(Context ctx)                              { super(ctx); init(); }
    public ShieldAnimView(Context ctx, AttributeSet a)             { super(ctx, a); init(); }
    public ShieldAnimView(Context ctx, AttributeSet a, int def)    { super(ctx, a, def); init(); }

    private void init() {
        setLayerType(LAYER_TYPE_SOFTWARE, null); // needed for blur/shadow

        bgPaint.setStyle(Paint.Style.FILL);
        bgPaint.setColor(Color.argb(50, 0, 230, 118));

        ringPaint.setStyle(Paint.Style.STROKE);
        ringPaint.setStrokeWidth(1.8f);
        ringPaint.setColor(GREEN_MID);

        dashRingPaint.setStyle(Paint.Style.STROKE);
        dashRingPaint.setStrokeWidth(1.2f);
        dashRingPaint.setColor(Color.argb(120, 0, 200, 83));
        dashRingPaint.setPathEffect(new DashPathEffect(new float[]{8, 5}, 0));

        glowPaint.setStyle(Paint.Style.STROKE);
        glowPaint.setStrokeWidth(3f);
        glowPaint.setColor(GREEN_GLOW);

        radarPaint.setStyle(Paint.Style.FILL);

        nodePaint.setStyle(Paint.Style.FILL);
        nodePaint.setColor(GREEN_BRIGHT);

        linePaint.setStyle(Paint.Style.STROKE);
        linePaint.setStrokeWidth(1f);
        linePaint.setColor(Color.argb(90, 0, 230, 118));

        rainPaint.setTextSize(11f * getResources().getDisplayMetrics().density);
        rainPaint.setTypeface(Typeface.MONOSPACE);
        rainPaint.setTextAlign(Paint.Align.CENTER);

        shieldPath.setStyle(Paint.Style.STROKE);
        shieldPath.setStrokeWidth(2.5f);
        shieldPath.setColor(GREEN_BRIGHT);
        shieldPath.setStrokeCap(Paint.Cap.ROUND);
        shieldPath.setStrokeJoin(Paint.Join.ROUND);

        lockPaint.setStyle(Paint.Style.STROKE);
        lockPaint.setStrokeWidth(3.5f);
        lockPaint.setColor(GREEN_BRIGHT);
        lockPaint.setStrokeCap(Paint.Cap.ROUND);
        lockPaint.setStrokeJoin(Paint.Join.ROUND);

        hexPaint.setStyle(Paint.Style.STROKE);
        hexPaint.setStrokeWidth(0.8f);
        hexPaint.setColor(Color.argb(25, 0, 230, 118));

        for (int i = 0; i < RAIN_COLS; i++) resetRain(i, true);

        startAnimators();
    }

    private void resetRain(int i, boolean randomStart) {
        rainX[i]    = 0.05f + rng.nextFloat() * 0.9f; // 5%–95% width
        rainY[i]    = randomStart ? rng.nextFloat() : 0f;
        rainChar[i] = rng.nextInt(2);
        rainAlpha[i]= 0.15f + rng.nextFloat() * 0.35f;
    }

    private void startAnimators() {
        pulseAnim = ValueAnimator.ofFloat(0f, 1f);
        pulseAnim.setDuration(2400);
        pulseAnim.setRepeatCount(ValueAnimator.INFINITE);
        pulseAnim.setRepeatMode(ValueAnimator.REVERSE);
        pulseAnim.addUpdateListener(a -> { pulse = (float) a.getAnimatedValue(); invalidate(); });
        pulseAnim.start();

        orbitAnim = ValueAnimator.ofFloat(0f, 360f);
        orbitAnim.setDuration(7000);
        orbitAnim.setRepeatCount(ValueAnimator.INFINITE);
        orbitAnim.setInterpolator(new LinearInterpolator());
        orbitAnim.addUpdateListener(a -> orbit = (float) a.getAnimatedValue());
        orbitAnim.start();

        scanAnim = ValueAnimator.ofFloat(0f, 1f);
        scanAnim.setDuration(1800);
        scanAnim.setRepeatCount(ValueAnimator.INFINITE);
        scanAnim.setRepeatMode(ValueAnimator.REVERSE);
        scanAnim.addUpdateListener(a -> scan = (float) a.getAnimatedValue());
        scanAnim.start();

        radarAnim = ValueAnimator.ofFloat(0f, 360f);
        radarAnim.setDuration(3500);
        radarAnim.setRepeatCount(ValueAnimator.INFINITE);
        radarAnim.setInterpolator(new LinearInterpolator());
        radarAnim.addUpdateListener(a -> radar = (float) a.getAnimatedValue());
        radarAnim.start();

        glitchAnim = ValueAnimator.ofFloat(0f, 1f);
        glitchAnim.setDuration(120);
        glitchAnim.setRepeatCount(ValueAnimator.INFINITE);
        glitchAnim.setRepeatMode(ValueAnimator.REVERSE);
        glitchAnim.addUpdateListener(a -> glitch = (float) a.getAnimatedValue());
        glitchAnim.start();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float W  = getWidth();
        float H  = getHeight();
        float cx = W / 2f;
        float cy = H / 2f;
        float r  = Math.min(cx, cy) * 0.88f;

        drawHexGrid(canvas, cx, cy, r);
        drawMatrixRain(canvas, W, H);
        drawRadar(canvas, cx, cy, r);
        drawRings(canvas, cx, cy, r);
        drawCircuitLines(canvas, cx, cy, r);
        drawNodes(canvas, cx, cy, r);
        drawOrbitDots(canvas, cx, cy, r);
        drawScanLine(canvas, cx, cy, r);
        drawShieldCenter(canvas, cx, cy, r);
    }

    private void drawHexGrid(Canvas canvas, float cx, float cy, float r) {
        float hexR = r * 0.12f;
        float hexW = hexR * 1.73f;
        float hexH = hexR * 2f;
        int cols = (int)(r * 2 / hexW) + 2;
        int rows = (int)(r * 2 / (hexH * 0.75f)) + 2;
        float startX = cx - r - hexW;
        float startY = cy - r - hexH;
        for (int row = 0; row < rows; row++) {
            for (int col = 0; col < cols; col++) {
                float hx = startX + col * hexW + (row % 2 == 0 ? 0 : hexW * 0.5f);
                float hy = startY + row * hexH * 0.75f;
                float dist = (float) Math.sqrt((hx - cx) * (hx - cx) + (hy - cy) * (hy - cy));
                if (dist > r * 1.05f) continue;
                drawHex(canvas, hx, hy, hexR * 0.88f);
            }
        }
    }

    private void drawHex(Canvas canvas, float cx, float cy, float r) {
        Path p = new Path();
        for (int i = 0; i < 6; i++) {
            double a = Math.toRadians(60 * i - 30);
            float x = cx + r * (float) Math.cos(a);
            float y = cy + r * (float) Math.sin(a);
            if (i == 0) p.moveTo(x, y); else p.lineTo(x, y);
        }
        p.close();
        canvas.drawPath(p, hexPaint);
    }

    private void drawMatrixRain(Canvas canvas, float W, float H) {
        for (int i = 0; i < RAIN_COLS; i++) {
            float x = rainX[i] * W;
            float y = rainY[i] * H;
            int alpha = (int)(rainAlpha[i] * 255);
            rainPaint.setColor(Color.argb(alpha, 0, 230, 118));
            canvas.drawText(rainChar[i] == 0 ? "0" : "1", x, y, rainPaint);
            rainY[i] += 0.008f;
            if (rainY[i] > 1.05f) resetRain(i, false);
        }
    }

    private void drawRadar(Canvas canvas, float cx, float cy, float r) {
        float sweepR = r * 0.82f;
        arcBounds.set(cx - sweepR, cy - sweepR, cx + sweepR, cy + sweepR);

        SweepGradient sg = new SweepGradient(cx, cy,
            new int[]{
                Color.TRANSPARENT,
                Color.argb(10,  0, 255, 106),
                Color.argb(60,  0, 255, 106),
                Color.argb(130, 0, 230, 118),
                Color.TRANSPARENT
            },
            new float[]{0f, 0.6f, 0.85f, 1f, 1f});

        radarPaint.setShader(sg);
        canvas.save();
        canvas.rotate(radar, cx, cy);
        canvas.drawCircle(cx, cy, sweepR, radarPaint);
        canvas.restore();

        Paint sweepLine = new Paint(Paint.ANTI_ALIAS_FLAG);
        sweepLine.setStyle(Paint.Style.STROKE);
        sweepLine.setStrokeWidth(2f);
        sweepLine.setColor(Color.argb(200, 0, 255, 106));
        sweepLine.setMaskFilter(new BlurMaskFilter(8, BlurMaskFilter.Blur.NORMAL));
        double sweepRad = Math.toRadians(radar);
        canvas.drawLine(cx, cy,
            cx + sweepR * (float) Math.cos(sweepRad),
            cy + sweepR * (float) Math.sin(sweepRad),
            sweepLine);
    }

    private void drawRings(Canvas canvas, float cx, float cy, float r) {
        // Outer dashed ring
        dashRingPaint.setAlpha((int)((0.4f + 0.3f * pulse) * 255));
        canvas.drawCircle(cx, cy, r * 0.95f, dashRingPaint);

        // Middle dashed ring (counter)
        canvas.save();
        canvas.rotate(-orbit * 0.4f, cx, cy);
        dashRingPaint.setAlpha((int)((0.3f + 0.2f * pulse) * 255));
        canvas.drawCircle(cx, cy, r * 0.82f, dashRingPaint);
        canvas.restore();

        // Solid inner ring with glow
        float glowAlpha = 0.35f + 0.55f * pulse;
        glowPaint.setAlpha((int)(glowAlpha * 255));
        glowPaint.setMaskFilter(new BlurMaskFilter(18 + 12 * pulse, BlurMaskFilter.Blur.NORMAL));
        canvas.drawCircle(cx, cy, r * 0.68f, glowPaint);
        glowPaint.setMaskFilter(null);

        ringPaint.setAlpha((int)((0.5f + 0.4f * pulse) * 255));
        canvas.drawCircle(cx, cy, r * 0.68f, ringPaint);

        // Innermost pulse ring
        float innerR = r * 0.45f + r * 0.06f * pulse;
        ringPaint.setAlpha((int)((0.2f + 0.4f * pulse) * 255));
        canvas.drawCircle(cx, cy, innerR, ringPaint);
    }

    private void drawCircuitLines(Canvas canvas, float cx, float cy, float r) {
        for (int i = 0; i < NODE_COUNT; i++) {
            double a1 = Math.toRadians(nodeAngle[i] + orbit * 0.15f);
            float nx = cx + r * nodeR[i] * (float) Math.cos(a1);
            float ny = cy + r * nodeR[i] * (float) Math.sin(a1);

            int next = (i + 1) % NODE_COUNT;
            double a2 = Math.toRadians(nodeAngle[next] + orbit * 0.15f);
            float nx2 = cx + r * nodeR[next] * (float) Math.cos(a2);
            float ny2 = cy + r * nodeR[next] * (float) Math.sin(a2);

            linePaint.setAlpha((int)((0.3f + 0.2f * pulse) * 255));
            canvas.drawLine(nx, ny, nx2, ny2, linePaint);

            // Center spoke
            linePaint.setAlpha((int)(0.18f * 255));
            canvas.drawLine(cx, cy, nx, ny, linePaint);
        }
    }

    private void drawNodes(Canvas canvas, float cx, float cy, float r) {
        for (int i = 0; i < NODE_COUNT; i++) {
            double a = Math.toRadians(nodeAngle[i] + orbit * 0.15f);
            float nx = cx + r * nodeR[i] * (float) Math.cos(a);
            float ny = cy + r * nodeR[i] * (float) Math.sin(a);

            float nodeAlpha = 0.5f + 0.5f * (float) Math.abs(Math.sin(
                    Math.toRadians(nodeAngle[i] + radar)));

            nodePaint.setMaskFilter(new BlurMaskFilter(10, BlurMaskFilter.Blur.NORMAL));
            nodePaint.setAlpha((int)(nodeAlpha * 180));
            canvas.drawCircle(nx, ny, 4.5f, nodePaint);
            nodePaint.setMaskFilter(null);
            nodePaint.setAlpha((int)(nodeAlpha * 255));
            canvas.drawCircle(nx, ny, 2.5f, nodePaint);
        }
    }

    private void drawOrbitDots(Canvas canvas, float cx, float cy, float r) {
        Paint dotP = new Paint(Paint.ANTI_ALIAS_FLAG);
        dotP.setStyle(Paint.Style.FILL);
        float[] angles = {orbit, orbit + 90f, orbit + 180f, orbit + 270f};
        float[] radii  = {0.95f, 0.95f, 0.95f, 0.95f};

        for (int i = 0; i < angles.length; i++) {
            double a = Math.toRadians(angles[i]);
            float dx = cx + r * radii[i] * (float) Math.cos(a);
            float dy = cy + r * radii[i] * (float) Math.sin(a);

            float alpha = (i == 0) ? 1f : 0.5f - i * 0.1f;
            float dotR  = (i == 0) ? 5.5f : 3.5f - i * 0.5f;

            dotP.setColor(GREEN_GLOW);
            dotP.setMaskFilter(new BlurMaskFilter(12, BlurMaskFilter.Blur.NORMAL));
            dotP.setAlpha((int)(alpha * 200));
            canvas.drawCircle(dx, dy, dotR + 2, dotP);
            dotP.setMaskFilter(null);
            dotP.setAlpha((int)(alpha * 255));
            canvas.drawCircle(dx, dy, dotR, dotP);
        }
    }

    private void drawScanLine(Canvas canvas, float cx, float cy, float r) {
        float clampR = r * 0.65f;
        float scanY  = cy - clampR + scan * clampR * 2f;

        Paint linePaint2 = new Paint(Paint.ANTI_ALIAS_FLAG);
        linePaint2.setStyle(Paint.Style.FILL);
        int fadeAlpha = (int)(35 * (1f - Math.abs(scan - 0.5f) * 2f));
        linePaint2.setColor(Color.argb(fadeAlpha, 0, 255, 106));
        canvas.drawRect(cx - clampR, scanY - 16f, cx + clampR, scanY + 16f, linePaint2);

        Paint line2 = new Paint(Paint.ANTI_ALIAS_FLAG);
        line2.setStyle(Paint.Style.STROKE);
        line2.setStrokeWidth(1.2f);
        line2.setColor(Color.argb((int)(160 * pulse), 0, 255, 106));
        line2.setMaskFilter(new BlurMaskFilter(4, BlurMaskFilter.Blur.NORMAL));
        canvas.drawLine(cx - clampR, scanY, cx + clampR, scanY, line2);
    }

    private void drawShieldCenter(Canvas canvas, float cx, float cy, float r) {
        float s = r * 0.32f;

        // Shield outline path
        Path shield = new Path();
        shield.moveTo(cx, cy - s);
        shield.cubicTo(cx + s * 1.0f, cy - s * 0.9f, cx + s * 1.0f, cy + s * 0.2f, cx, cy + s * 1.1f);
        shield.cubicTo(cx - s * 1.0f, cy + s * 0.2f, cx - s * 1.0f, cy - s * 0.9f, cx, cy - s);
        shield.close();

        shieldPath.setMaskFilter(new BlurMaskFilter(10 + 6 * pulse, BlurMaskFilter.Blur.NORMAL));
        shieldPath.setAlpha((int)((0.4f + 0.5f * pulse) * 255));
        canvas.drawPath(shield, shieldPath);
        shieldPath.setMaskFilter(null);
        shieldPath.setAlpha(255);
        canvas.drawPath(shield, shieldPath);

        // Keyhole / lock body
        float lx = cx;
        float ly = cy + s * 0.15f;
        float lr = s * 0.22f;
        float lh = s * 0.30f;

        // Lock arch (open padlock shackle)
        lockPaint.setAlpha((int)((0.7f + 0.3f * pulse) * 255));
        arcBounds.set(lx - lr, ly - lr * 2.0f, lx + lr, ly);
        canvas.drawArc(arcBounds, 200f, 140f, false, lockPaint);

        // Lock body rectangle
        Paint bodyFill = new Paint(Paint.ANTI_ALIAS_FLAG);
        bodyFill.setStyle(Paint.Style.FILL);
        bodyFill.setColor(Color.argb((int)((0.5f + 0.3f * pulse) * 255), 0, 230, 118));
        RectF body = new RectF(lx - lr * 1.2f, ly - lr * 0.2f, lx + lr * 1.2f, ly + lh);
        canvas.drawRoundRect(body, lr * 0.3f, lr * 0.3f, bodyFill);
        lockPaint.setAlpha((int)((0.8f + 0.2f * pulse) * 255));
        canvas.drawRoundRect(body, lr * 0.3f, lr * 0.3f, lockPaint);

        // Keyhole dot
        Paint dotFill = new Paint(Paint.ANTI_ALIAS_FLAG);
        dotFill.setStyle(Paint.Style.FILL);
        dotFill.setColor(Color.argb(200, 0, 255, 106));
        canvas.drawCircle(lx, ly + lh * 0.35f, lr * 0.25f, dotFill);
    }

    @Override protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (pulseAnim != null) pulseAnim.cancel();
        if (orbitAnim != null) orbitAnim.cancel();
        if (scanAnim  != null) scanAnim.cancel();
        if (radarAnim != null) radarAnim.cancel();
        if (glitchAnim!= null) glitchAnim.cancel();
    }

    @Override protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (pulseAnim != null && !pulseAnim.isRunning()) pulseAnim.start();
        if (orbitAnim != null && !orbitAnim.isRunning()) orbitAnim.start();
        if (scanAnim  != null && !scanAnim.isRunning())  scanAnim.start();
        if (radarAnim != null && !radarAnim.isRunning()) radarAnim.start();
        if (glitchAnim!= null && !glitchAnim.isRunning())glitchAnim.start();
    }
}
