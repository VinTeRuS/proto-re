package com.protore.game;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.system.ErrnoException;
import android.system.Os;
import android.util.TypedValue;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Launcher: finds the game files and starts ProtoActivity, or explains where to put them. The game can live in the
 * app's own folder (Android/data/com.protore.game/files/game, which file managers often cannot open on Android 11+)
 * or in /sdcard/Prototype, which needs "all files access" (storage permission before Android 11).
 */
public class SetupActivity extends Activity {
    /** Shown on the setup screen and in the in-game settings panel. */
    static final String CREDIT = "Android port by VinTeRuS";
    static final String CREDIT_URL = "github.com/VinTeRuS/proto-re";
    static final String SUPPORT_URL = "https://www.patreon.com/cw/VinTeRuS/membership";

    /** Opens the author's Patreon page in the browser. */
    static void openSupport(android.content.Context context) {
        try {
            context.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(SUPPORT_URL))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        } catch (Exception ignored) {
            // no browser
        }
    }

    private static final String DLL = "prototypeenginef.dll";
    private static final int REQUEST_STORAGE = 1;

    private File appGame() {
        File base = getExternalFilesDir(null);  // also creates Android/data/<package>/files
        return base == null ? null : new File(base, "game");
    }

    /** The app's folder on a memory card (Android/data/com.protore.game/files/game there; no permission needed). */
    private File sdCardGame() {
        File[] dirs = getExternalFilesDirs(null);
        for (int i = 1; i < dirs.length; ++i) {
            File game = dirs[i] == null ? null : new File(dirs[i], "game");
            if (game != null && new File(game, DLL).canRead()) return game;
        }
        return null;
    }

    private static File sharedGame() {
        return new File(Environment.getExternalStorageDirectory(), "Prototype");
    }

    private boolean hasSharedAccess() {
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager();
        return checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    @Override
    protected void onResume() {
        super.onResume();
        check();  // also after coming back from the permission screen
    }

    /**
     * Files the game reads at start (from the PC game folder). Without proto_uv.dat, for one, it closes a second
     * after starting with no message.
     */
    private static final String[] REQUIRED = {
        DLL, "proto_uv.dat", "cementfiles.p3d", "skuinfo.p3d", "art.rcf", "cells.rcf", "scripts.rcf",
        "shaders.rcf", "00woi.rcf",
    };

    /** The required files missing from `dir` (names compared ignoring case, like the game does). */
    private static java.util.List<String> missing(File dir) {
        java.util.Set<String> have = new java.util.HashSet<>();
        String[] names = dir == null ? null : dir.list();
        if (names != null) for (String n : names) have.add(n.toLowerCase(java.util.Locale.ROOT));
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String r : REQUIRED) if (!have.contains(r)) out.add(r);
        return out;
    }

    private void check() {
        File app = appGame();
        if (app != null) app.mkdirs();
        File shared = sharedGame();
        if (hasSharedAccess()) shared.mkdirs();
        File found = null;
        if (app != null && new File(app, DLL).canRead()) found = app;
        else if (hasSharedAccess() && new File(shared, DLL).canRead()) found = shared;
        else found = sdCardGame();
        if (found == null) {
            showHelp(app, shared, null);
            return;
        }
        java.util.List<String> lack = missing(found);
        if (!lack.isEmpty()) {
            showHelp(app, shared, found.getAbsolutePath() + " is missing: " + String.join(", ", lack));
            return;
        }
        launch(found == app ? null : found);
    }

    private void launch(File gameDir) {
        try {
            if (gameDir == null) Os.unsetenv("PROTORE_GAME");
            else Os.setenv("PROTORE_GAME", gameDir.getAbsolutePath(), true);
        } catch (ErrnoException ignored) {
            // the native side falls back to the app folder
        }
        File driver = installCustomDriver();
        try {
            if (driver == null) Os.unsetenv("PROTORE_CUSTOM_DRIVER");
            else Os.setenv("PROTORE_CUSTOM_DRIVER", driver.getAbsolutePath(), true);
        } catch (ErrnoException ignored) {
            // the bundled drivers are used
        }
        startActivity(new Intent(this, ProtoActivity.class));
        finish();
    }

    /**
     * A user-supplied Vulkan driver (an Adreno driver .so, e.g. a Turnip build made for emulators) in
     * Android/data/com.protore.game/files/driver/: copied into the app's private storage, where the linker may load
     * it from (not from shared storage). Returns the private copy, or null when there is none (the copy is removed
     * when the user removes the driver).
     */
    private File installCustomDriver() {
        File base = getExternalFilesDir(null);
        File[] found = base == null ? null : new File(base, "driver").listFiles((d, name) -> name.endsWith(".so"));
        File dest = new File(new File(getFilesDir(), "driver"), "libvulkan_custom.so");
        if (found == null || found.length == 0) {
            dest.delete();
            return null;
        }
        File src = found[0];
        if (dest.exists() && dest.length() == src.length() && dest.lastModified() >= src.lastModified()) return dest;
        dest.getParentFile().mkdirs();
        try (InputStream in = new FileInputStream(src); OutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[1 << 16];
            for (int n; (n = in.read(buf)) > 0;) out.write(buf, 0, n);
        } catch (IOException e) {
            dest.delete();
            return null;
        }
        return dest;
    }

    private void requestAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName())));
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            }
        } else {
            requestPermissions(new String[] {Manifest.permission.READ_EXTERNAL_STORAGE}, REQUEST_STORAGE);
        }
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
        check();
    }

    private int dp(float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics());
    }

    private TextView text(String s, float sp, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextColor(Color.rgb(230, 230, 230));
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setPadding(0, 0, 0, dp(12));
        return t;
    }

    private Button button(String label, Runnable action) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setOnClickListener(v -> action.run());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, dp(12), 0);
        b.setLayoutParams(lp);
        return b;
    }

    private void showHelp(File app, File shared, String problem) {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(32), dp(24), dp(32), dp(24));
        col.addView(text(problem == null ? "Game files not found" : "Some game files are missing", 22, true));
        if (problem != null) {
            TextView p = text(problem, 15, true);
            p.setTextColor(Color.rgb(255, 120, 100));
            col.addView(p);
        }
        col.addView(text("Copy the contents of your Prototype folder (PC version, Steam): prototypeenginef.dll, "
                + "proto_uv.dat, all .rcf and .p3d files and the art, audio and scripts folders, to one of these "
                + "places:", 15, false));
        col.addView(text("1. " + (app != null ? app.getAbsolutePath() : "Android/data/" + getPackageName()
                + "/files/game") + "\n   The folder exists now. On Android 11+ most file managers cannot open "
                + "Android/data; copy from a PC over USB, or use option 2. The same folder on a memory card "
                + "works too.", 14, false));
        String access = hasSharedAccess() ? "access granted" : "needs file access: tap the button below";
        col.addView(text("2. " + shared.getAbsolutePath() + "\n   Any file manager can open it (" + access + ").",
                14, false));
        col.addView(text("Then tap Check again.", 15, false));

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.START);
        row.addView(button("Check again", this::check));
        if (!hasSharedAccess()) row.addView(button("Allow file access", this::requestAccess));
        row.addView(button("Exit", this::finish));
        row.addView(button("Support on Patreon", () -> openSupport(this)));
        col.addView(row);
        TextView credit = text(CREDIT + " \u00b7 " + CREDIT_URL, 12, false);
        credit.setTextColor(Color.rgb(150, 150, 150));
        credit.setPadding(0, dp(24), 0, 0);
        col.addView(credit);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.rgb(18, 18, 18));
        scroll.addView(col);
        setContentView(scroll);
    }
}
