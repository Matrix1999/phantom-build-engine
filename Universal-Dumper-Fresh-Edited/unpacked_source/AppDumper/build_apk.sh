#!/bin/bash
set -e

ANDROID_HOME=/home/runner/workspace/android-sdk
BUILD_TOOLS=$ANDROID_HOME/build-tools/35.0.0
PLATFORM=$ANDROID_HOME/platforms/android-35/android.jar
APP_DIR=/home/runner/workspace/apk-work/AppDumper/app/src/main
BUILD=/home/runner/workspace/apk-work/AppDumper/build_out
KEYSTORE=/home/runner/workspace/apk-work/debug.keystore
OUT=/home/runner/workspace/apk-work/AppDumper.apk

echo "[1] Clean build dir"
rm -rf $BUILD && mkdir -p $BUILD/{res_compiled,gen,classes,dex}

echo "[2] Compile resources with aapt2"
$BUILD_TOOLS/aapt2 compile \
  --dir $APP_DIR/res \
  -o $BUILD/res_compiled/

echo "    Compiled resources:"
ls $BUILD/res_compiled/

echo "[3] Link resources + generate R.java"
$BUILD_TOOLS/aapt2 link \
  -o $BUILD/app-res.apk \
  -I $PLATFORM \
  --manifest $APP_DIR/AndroidManifest.xml \
  --java $BUILD/gen \
  --min-sdk-version 26 \
  --target-sdk-version 35 \
  --version-code 1 \
  --version-name "1.0" \
  $BUILD/res_compiled/*.flat

echo "    Generated R.java files:"
find $BUILD/gen -name "*.java"

echo "[4] Compile Java sources"
SRCS="$(find $APP_DIR/java -name '*.java') $(find $BUILD/gen -name '*.java')"
javac \
  --release 11 \
  -encoding UTF-8 \
  -classpath $PLATFORM \
  -d $BUILD/classes \
  $SRCS

echo "    Class files:"
find $BUILD/classes -name "*.class" | wc -l

echo "[5] Convert .class to DEX"
$BUILD_TOOLS/d8 \
  --output $BUILD/dex \
  --min-api 26 \
  --lib $PLATFORM \
  $(find $BUILD/classes -name "*.class")

ls -lh $BUILD/dex/

echo "[6] Package APK (resources + dex + assets)"
cp $BUILD/app-res.apk $BUILD/app-unsigned.apk

# Add assets/
cd $APP_DIR && zip -q -r $BUILD/app-unsigned.apk assets/

# Add DEX
cd $BUILD/dex && zip -q -j $BUILD/app-unsigned.apk classes.dex

echo "[7] Align APK"
$BUILD_TOOLS/zipalign -f 4 $BUILD/app-unsigned.apk $BUILD/app-aligned.apk

echo "[8] Sign APK with jarsigner"
JAVA_BIN=$(readlink -f $(which java))
JAVA_HOME_BIN=$(dirname $JAVA_BIN)
$JAVA_HOME_BIN/jarsigner \
  -keystore $KEYSTORE \
  -storepass android -keypass android \
  -signedjar $OUT \
  $BUILD/app-aligned.apk debug

echo ""
echo "✅ APK built successfully!"
ls -lh $OUT
