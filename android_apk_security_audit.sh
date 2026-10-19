#!/usr/bin/env bash
# android_apk_security_audit.sh
# Требования: adb, apksigner, aapt2, sha256sum (или shasum на macOS), jq (опционально)
# Использование: ./android_apk_security_audit.sh [base_dir]
set -uo pipefail

BASE_DIR="${1:-apk_audit}"
APK_DIR="$BASE_DIR/apks"
CERT_DIR="$BASE_DIR/certs"
HASH_DIR="$BASE_DIR/hashes"
MAN_DIR="$BASE_DIR/manifests"
CSV="$BASE_DIR/report.csv"
JSON="$BASE_DIR/report.json"

mkdir -p "$APK_DIR" "$CERT_DIR" "$HASH_DIR" "$MAN_DIR"

# --- Кроссплатформенный sha256 ---
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# --- CSV-эскейпинг ---
csv_escape() {
    local s="${1//\"/\"\"}"
    printf '"%s"' "$s"
}

# --- Проверка зависимостей ---
for bin in adb apksigner aapt2; do
    command -v "$bin" >/dev/null 2>&1 || { echo "[!] Не найден: $bin"; exit 1; }
done

echo "[*] Получаем список пакетов..."
PKG_LIST="$(adb shell pm list packages -f 2>/dev/null | tr -d '\r')"

# Заголовок CSV
{
    echo "Package,Version,VersionCode,TargetSdk,SHA256,Installer,SystemApp,Debuggable,Cleartext,TestKey,RiskFlags,ApkPath"
} > "$CSV"

: > "$JSON.tmp"   # будем собирать JSON-массив вручную

first_json=1

while IFS= read -r line; do
    [[ "$line" =~ ^package: ]] || continue
    clean="${line#package:}"
    apk_path="${clean%%=*}"
    pkg="${clean#*=}"
    [[ -z "$pkg" || "$apk_path" == "$clean" ]] && continue

    echo
    echo "[+] $pkg"

    pkg_dir="$APK_DIR/$pkg"
    mkdir -p "$pkg_dir"

    # --- Скачиваем APK (включая split APKs) ---
    mapfile -t apk_paths < <(adb shell pm path "$pkg" 2>/dev/null | tr -d '\r')
    for p in "${apk_paths[@]}"; do
        remote="${p#package:}"
        fname="$(basename "$remote")"
        adb pull "$remote" "$pkg_dir/$fname" >/dev/null 2>&1 || true
    done

    # --- Ищем base.apk ---
    base_apk="$pkg_dir/base.apk"
    if [[ ! -f "$base_apk" ]]; then
        base_apk="$(find "$pkg_dir" -maxdepth 1 -name '*.apk' | head -n1)"
    fi
    [[ -z "$base_apk" || ! -f "$base_apk" ]] && { echo "  [~] APK не получен, пропускаем"; continue; }

    # --- apksigner ---
    cert_out="$(apksigner verify --print-certs "$base_apk" 2>&1 || true)"
    echo "$cert_out" > "$CERT_DIR/$pkg.txt"

    # --- SHA256 ---
    sha256="$(sha256_of "$base_apk")"
    echo "$sha256" > "$HASH_DIR/$pkg.sha256"

    # --- aapt2 ---
    aapt_out="$(aapt2 dump badging "$base_apk" 2>/dev/null || true)"
    echo "$aapt_out" > "$MAN_DIR/$pkg.txt"

    # --- Метаданные ---
    version_name="$(echo "$aapt_out" | grep -m1 -oP "versionName='\K[^']*" || true)"
    version_code="$(echo "$aapt_out" | grep -m1 -oP "versionCode='\K[^']*" || true)"
    target_sdk="$(echo "$aapt_out"   | grep -m1 -oP "targetSdkVersion:'\K[^']*" || true)"
    debuggable=0
    grep -q "application-debuggable" <<<"$aapt_out" && debuggable=1

    # --- Cleartext (из dumpsys, как в оригинале) ---
    dumpsys_out="$(adb shell dumpsys package "$pkg" 2>/dev/null | tr -d '\r' || true)"
    cleartext=0
    grep -q "usesCleartextTraffic=true" <<<"$dumpsys_out" && cleartext=1

    # --- Installer ---
    installer="$(adb shell pm list packages -i "$pkg" 2>/dev/null | tr -d '\r' | sed -n 's/.*installer=\([^ ]*\).*/\1/p' | head -n1)"
    [[ -z "$installer" ]] && installer=""

    # --- System app ---
    is_system=0
    [[ "$apk_path" =~ ^/(system|product|vendor) ]] && is_system=1

    # --- Test key ---
    test_key=0
    grep -qE "CN=Android Debug|testkey" <<<"$cert_out" && test_key=1

    # --- Risk flags ---
    risks=()
    (( debuggable )) && risks+=("DEBUGGABLE")
    (( cleartext ))  && risks+=("CLEARTEXT")
    (( test_key ))   && risks+=("TESTKEY")
    [[ -z "$installer" ]] && risks+=("UNKNOWN_INSTALLER")
    if (( is_system )) && [[ ! "$apk_path" =~ ^/system ]]; then
        risks+=("SYSTEM_OUTSIDE_SYSTEM")
    fi
    risk_flags="$(IFS=,; echo "${risks[*]}")"

    # --- CSV ---
    {
        csv_escape "$pkg"; printf ','
        csv_escape "$version_name"; printf ','
        csv_escape "$version_code"; printf ','
        csv_escape "$target_sdk"; printf ','
        csv_escape "$sha256"; printf ','
        csv_escape "$installer"; printf ','
        echo "$is_system,$debuggable,$cleartext,$test_key,"
        csv_escape "$risk_flags"; printf ','
        csv_escape "$apk_path"
        echo
    } >> "$CSV"

    # --- JSON (ручная сборка, без jq) ---
    json_str() { # экранирование для JSON
        local s="$1"
        s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
        s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"
        s="${s//$'\t'/\\t}"
        printf '%s' "$s"
    }
    (( first_json )) || echo "," >> "$JSON.tmp"
    first_json=0
    cat >> "$JSON.tmp" <<EOF
{
  "Package": "$(json_str "$pkg")",
  "Version": "$(json_str "$version_name")",
  "VersionCode": "$(json_str "$version_code")",
  "TargetSdk": "$(json_str "$target_sdk")",
  "SHA256": "$(json_str "$sha256")",
  "Installer": "$(json_str "$installer")",
  "SystemApp": $([[ $is_system -eq 1 ]] && echo true || echo false),
  "Debuggable": $([[ $debuggable -eq 1 ]] && echo true || echo false),
  "Cleartext": $([[ $cleartext -eq 1 ]] && echo true || echo false),
  "TestKey": $([[ $test_key -eq 1 ]] && echo true || echo false),
  "RiskFlags": "$(json_str "$risk_flags")",
  "ApkPath": "$(json_str "$apk_path")"
}
EOF
done <<< "$PKG_LIST"

# Собираем JSON
{
    echo "["
    cat "$JSON.tmp"
    echo
    echo "]"
} > "$JSON"
rm -f "$JSON.tmp"

echo
echo " Аудит завершён. Отчёты: $CSV / $JSON"