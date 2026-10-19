# Android APK Security Audit

A cross-platform tool for auditing Android APKs installed on a connected device via ADB. It pulls APKs (including split APKs), verifies signatures, extracts manifest metadata, computes hashes, and flags common security risks.

Originally written as a Windows-only PowerShell script, this repository provides **two portable implementations**:

- **Bash** — native for Linux/macOS/WSL/Git Bash (recommended for CI)
- **PowerShell 7** (`pwsh`) — cross-platform (Windows/Linux/macOS)

---

## Features

For every installed package the tool will:

- **Pull all APKs** belonging to the package (supports split APKs) to `apk_audit/apks/<package>/`
- **Verify the signature** with `apksigner verify --print-certs` → `apk_audit/certs/<package>.txt`
- **Compute SHA-256** of the base APK → `apk_audit/hashes/<package>.sha256`
- **Dump manifest metadata** with `aapt2 dump badging` → `apk_audit/manifests/<package>.txt`
- **Extract metadata**: `versionName`, `versionCode`, `targetSdkVersion`, `debuggable`
- **Detect cleartext traffic** via `adb shell dumpsys package`
- **Detect installer** via `adb shell pm list packages -i`
- **Detect system apps** based on APK path (`/system`, `/product`, `/vendor`)
- **Detect test/debug signing keys** (`CN=Android Debug`, `testkey`)
- **Produce reports**: `apk_audit/report.csv` and `apk_audit/report.json`

### Risk flags

| Flag | Meaning |
|---|---|
| `DEBUGGABLE` | APK declares `android:debuggable="true"` |
| `CLEARTEXT` | Package has `usesCleartextTraffic=true` |
| `TESTKEY` | Signed with an Android debug or AOSP test key |
| `UNKNOWN_INSTALLER` | No installer recorded (`pm list packages -i`) |
| `SYSTEM_OUTSIDE_SYSTEM` | Marked as system app but located outside `/system` (e.g. `/product`, `/vendor`) |

> **Note:** `SYSTEM_OUTSIDE_SYSTEM` is preserved from the original logic for report compatibility. On modern Android, apps in `/product` and `/vendor` are legitimately system apps — you may want to drop this flag.

---

## Requirements

### Common

- **ADB** with a connected device (`adb devices` must list it)
- **Android build-tools** in `PATH`:
  - `apksigner`
  - `aapt2`

Install via Android SDK Manager or your package manager:

```bash
# Debian/Ubuntu
sudo apt install android-sdk-platform-tools android-sdk-build-tools

# macOS (Homebrew)
brew install --cask android-platform-tools
brew install android-sdk