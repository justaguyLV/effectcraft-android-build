#!/usr/bin/env bash
# Runs inside the emulator job: installs the APK, starts it, and records what happens
# (screenshots, logcat, whether the process stays alive). Output goes to $OUT.
set -u
APK="$1"
OUT="${OUT:-emulator-out}"
PKG=ai.storyteller.effectcraft
mkdir -p "$OUT"

adb wait-for-device
{
  echo "android: $(adb shell getprop ro.build.version.release | tr -d '\r') (sdk $(adb shell getprop ro.build.version.sdk | tr -d '\r'))"
  echo "abis: $(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
  echo "vulkan: $(adb shell getprop ro.hardware.vulkan | tr -d '\r')"
} | tee "$OUT/device.txt"

adb install -r "$APK" 2>&1 | tee "$OUT/install.txt"
adb logcat -c
adb shell am start -W -n "$PKG/android.app.NativeActivity" 2>&1 | tee "$OUT/start.txt"

shot() { adb exec-out screencap -p > "$OUT/$1.png" 2>/dev/null; echo "shot $1: $(stat -c %s "$OUT/$1.png" 2>/dev/null) bytes"; }
sleep 15; shot shot-15s; echo "pid after 15s: $(adb shell pidof $PKG | tr -d '\r')" | tee -a "$OUT/alive.txt"
sleep 30; shot shot-45s; echo "pid after 45s: $(adb shell pidof $PKG | tr -d '\r')" | tee -a "$OUT/alive.txt"
# A tap, to see whether the UI reacts at all.
adb shell input tap 200 200; sleep 5; shot shot-after-tap
echo "pid at end: $(adb shell pidof $PKG | tr -d '\r')" | tee -a "$OUT/alive.txt"

adb logcat -d -v threadtime > "$OUT/logcat-full.txt"
grep -E "EffectCraft|AndroidRuntime|FATAL|panicked|wgpu|vulkan|Vulkan|egui|libc  *: Fatal|DEBUG|backtrace" "$OUT/logcat-full.txt" | tail -n 200 > "$OUT/logcat-filtered.txt"
echo "---- filtered logcat (tail) ----"; tail -n 60 "$OUT/logcat-filtered.txt"
exit 0
