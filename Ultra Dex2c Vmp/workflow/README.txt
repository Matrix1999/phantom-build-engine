================================================================================
  DEX2C MEGA — WORKFLOWS REFERENCE
  GitHub: https://github.com/Matrixzat/Dex2c-Mega
================================================================================

This folder stores the GitHub Actions workflow files used in the private repo
at https://github.com/Matrixzat/Dex2c-Mega. They are saved here for reference
so future agents and developers have full context without needing repo access.

================================================================================
  1. build-libcipher.yml — Build guard.cpp into prebuilt .so assets
================================================================================

PURPOSE:
  Compiles guard.cpp (the native anti-tamper / guard code) into two prebuilt
  shared libraries that are embedded inside the Dex2c Mega APK:

    libcipher_arm64.so   → jniLibs/arm64-v8a/libcipher.so
    libcipher_armeabi.so → jniLibs/armeabi-v7a/libcipher.so

  These are NOT shipped as separate .so files in the protected APK. At
  protection time, NdkBuilder absorbs them into the target .so via
  --whole-archive, so the end-user APK has zero extra runtime dependencies.
  libc++ is statically linked in — no libc++_shared.so needed.

HOW IT WORKS — TWO JOBS:

  ┌─ Job 1: build-ollvm ─────────────────────────────────────────────────────┐
  │  Checks if OLLVM clang-19 release asset already exists in the repo.      │
  │  → Asset EXISTS:  skips all build steps (~10 seconds total).             │
  │  → Asset MISSING: clones TIMER-err/ollvm-19 from GitHub, builds clang   │
  │    from source with AArch64 + ARM targets (40–90 min on ubuntu-latest),  │
  │    packages as ollvm-clang-linux-x86_64.tar.xz, and uploads it as a      │
  │    GitHub release asset under the tag "ollvm-clang-linux".               │
  │  Cache key includes "AArch64-ARM" so old AArch64-only builds are never   │
  │  reused if targets change.                                                │
  └──────────────────────────────────────────────────────────────────────────┘

  ┌─ Job 2: build-guard ─────────────────────────────────────────────────────┐
  │  Downloads OLLVM clang-19 from the release asset, then compiles          │
  │  guard.cpp for BOTH ABIs with ALL 8 OLLVM obfuscation passes:            │
  │                                                                           │
  │    1. fla   — control flow flattening                                    │
  │    2. bcf   — bogus control flow  (80% probability, 3 loops)             │
  │    3. sub   — instruction substitution  (3 loops)                        │
  │    4. sobf  — string obfuscation  (encrypts all string literals)         │
  │    5. split — basic block splitting  (5 sub-blocks per block)            │
  │    6. ibr   — indirect branch  (all jumps through registers)             │
  │    7. icall — indirect call  (all calls through registers)               │
  │    8. igv   — indirect global variable  (184k+ relocations per binary)   │
  │                                                                           │
  │  Compile step: OLLVM clang-19  (applies obfuscation passes)              │
  │  Link step:    NDK r25c clang wrappers (supplies sysroot + runtime libs) │
  │  C++ runtime:  libc++_static.a baked in statically — no shared dep.      │
  │                                                                           │
  │  Outputs uploaded as artifact "cipher-binaries" (kept 90 days):          │
  │    libcipher_arm64.so                                                     │
  │    libcipher_armeabi.so                                                   │
  └──────────────────────────────────────────────────────────────────────────┘

TRIGGERS:
  - Auto-triggers on push to:  cpp/guard.cpp  |  cpp/guard_pstrings.inc
  - Auto-triggers on push to:  .github/workflows/build-libcipher.yml
  - Manual trigger via GitHub Actions → Run workflow

AFTER IT FINISHES:
  Download the "cipher-binaries" artifact zip and copy:
    libcipher_arm64.so   → Dex2c Mega/src/main/jniLibs/arm64-v8a/libcipher.so
    libcipher_armeabi.so → Dex2c Mega/src/main/jniLibs/armeabi-v7a/libcipher.so
  Then commit, push, and rebuild the APK.

TO FORCE OLLVM REBUILD FROM SOURCE:
  Delete the "ollvm-clang-linux" release asset from the GitHub repo, then
  trigger the workflow manually. Job 1 will detect no asset and rebuild.

SOURCE FILES (in the private GitHub repo):
  cpp/guard.cpp           — main native guard implementation
  cpp/guard_pstrings.inc  — protected string definitions

================================================================================
  2. build.yml — Cloud Build Engine: Universal APK Builder
================================================================================

FULL NAME:  "Cloud Build Engine — Universal APK Builder"

PURPOSE:
  Builds the full Dex2c Mega Android source code (or any submitted Android,
  Flutter, or React Native project) into a signed, release-ready APK.
  This is the workflow that produces the actual APK that gets distributed.

  It is triggered by the Dex2c Mega app itself — when a user submits their
  source code for compilation, the app dispatches this workflow via the GitHub
  API, passing the source as a release asset or branch. The workflow builds it,
  signs it, and uploads the APK as an artifact for the app to retrieve.

INPUTS (all passed by the app at dispatch time):
  app_name        — Display name of the app being built
  package_name    — Android package name (e.g. com.example.app)
  job_id          — Unique ID used to name the output artifact (apk-<job_id>)
  flutter_version — Flutter version to use (default: 3.29.1)
  build_mode      — release | debug | profile  (default: release)
  asset_id        — GitHub Release asset ID of the uploaded source zip
                    (deleted immediately after download for security)
  source_branch   — Alternative: a git branch in the repo holding the source

BUILD STEPS (13 steps):
  1.  Install system deps  (unzip, wget, curl, jq, apksigner, zipalign)
  2.  Set up Java 17
  3.  Download source code from release asset or branch
  4.  Clean up staging branch/asset immediately after download (security)
  5.  Extract source zip, auto-relocate project root if nested
  6.  Patch gradle.properties for CI compatibility
  7.  Detect project type automatically:
        → Flutter        (pubspec.yaml present)
        → React Native   (package.json + android/ folder)
        → Expo           (package.json + expo markers)
        → Unity Android  (unityLibrary detected)
        → Native Android (build.gradle / settings.gradle)
  8.  Set up Flutter / Node.js / Android SDK as needed for the project type
  9.  Install project-specific NDK version and SDK platform from build.gradle
  10. Set up signing keystore (CBE default key or user-supplied key)
  11. Auto-fix common Gradle issues
  12. Build APK:
        Flutter        → flutter build apk
        React Native   → npm install + gradlew assembleRelease
        Expo           → expo prebuild + gradlew assembleRelease
        Native Android → gradlew assembleRelease / assembleBeta / etc.
  13. Sign APK with apksigner + zipalign, verify signature
  14. Upload signed APK as artifact "apk-<job_id>"  (kept 1 day)
  15. Write build summary to GitHub step summary

TRIGGERS:
  - Manual dispatch only (workflow_dispatch) — triggered by the Dex2c Mega
    app via GitHub Actions API, never run manually.

OUTPUT:
  Artifact named "apk-<job_id>" containing the final signed APK.
  The Dex2c Mega app polls for this artifact and delivers it to the user.

PERMISSIONS:
  contents: write — required to delete the staging release asset after
  source download (keeps the repo clean, source never stays in the repo).

================================================================================
  REPO: https://github.com/Matrixzat/Dex2c-Mega
================================================================================
