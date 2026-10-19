# =========================
# Android APK Security Audit v2.2 - Fixed
# =========================

$ErrorActionPreference = "Stop"

# --- Device fingerprint
$Serial = (adb get-serialno).Trim()
$Brand  = (adb shell getprop ro.product.brand).Trim()
$Model  = (adb shell getprop ro.product.model).Trim()
$OS     = (adb shell getprop ro.build.version.release).Trim()
$Time   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$RootDir = "AndroidAudit_${Brand}_${Model}_${Serial}"
$ApkDir  = Join-Path $RootDir "apks"
$CertDir = Join-Path $RootDir "certs"
$HashDir = Join-Path $RootDir "hashes"
$ManDir  = Join-Path $RootDir "manifests"
$DexDir  = Join-Path $RootDir "dex"
$YaraDir = Join-Path $RootDir "yara"
$ForDir  = Join-Path $RootDir "forensics"
$ReportDir = Join-Path $RootDir "reports"
$BaselineFile = "baseline\allowlist_signers.json"

New-Item -ItemType Directory -Force -Path `
    $RootDir,$ApkDir,$CertDir,$HashDir,$ManDir,$DexDir,$YaraDir,$ForDir,$ReportDir | Out-Null

# --- Forensics: device info
@{
    Serial = $Serial
    Brand  = $Brand
    Model  = $Model
    OS     = $OS
    ScanTimeUTC = $Time
} | ConvertTo-Json -Depth 4 | Out-File (Join-Path $ForDir "device_info.json")

# --- Entropy function
function Get-Entropy($Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $freq = @{}
    foreach ($b in $bytes) { $freq[$b] = ($freq[$b] + 1) }
    $entropy = 0
    foreach ($f in $freq.Values) {
        $p = $f / $bytes.Length
        $entropy -= $p * [Math]::Log($p,2)
    }
    [Math]::Round($entropy,2)
}

# --- Load baseline allowlist
$Baseline = @{}
if (Test-Path $BaselineFile) {
    $Baseline = Get-Content $BaselineFile | ConvertFrom-Json
}

$Report = @()

Write-Host "[*] Scanning device: $Brand $Model ($Serial)"

$pkgLines = adb shell pm list packages -f

foreach ($line in $pkgLines) {

    if ($line -notmatch "^package:") { continue }

    $clean = $line -replace "^package:", ""
    $idx = $clean.LastIndexOf("=")
    if ($idx -lt 0) { continue }
    $apkPath = $clean.Substring(0,$idx).Trim()
    $pkg     = $clean.Substring($idx+1).Trim()

    Write-Host "`n[+] $pkg"

    $pkgDir = Join-Path $ApkDir $pkg
    New-Item -ItemType Directory -Force -Path $pkgDir | Out-Null

    # --- Pull APKs (skip if уже загружены)
    $apkPaths = adb shell pm path $pkg
    $apkExists = $true

    foreach ($p in $apkPaths) {
        if ($p -notmatch "^package:") { continue }
        $remote = ($p -replace "^package:", "").Trim()
        $name = Split-Path $remote -Leaf
        $localPath = Join-Path $pkgDir $name
        if (-not (Test-Path $localPath)) {
            $apkExists = $false
            break
        }
    }

    if ($apkExists) {
        Write-Host "    [*] Skipping pull for $pkg — APK already exists"
    }
    else {
        Write-Host "    [*] Pulling APKs for $pkg..."
        foreach ($p in $apkPaths) {
            if ($p -notmatch "^package:") { continue }
            $remote = ($p -replace "^package:", "").Trim()
            $name = Split-Path $remote -Leaf
            adb pull $remote (Join-Path $pkgDir $name) | Out-Null
        } # <- закрыт внутренний foreach
    } # <- закрыт if-else

} # <- закрыт внешний foreach

    # --- base.apk detection
    $baseApk = Get-ChildItem -LiteralPath $pkgDir -Filter "base.apk" -File -ErrorAction SilentlyContinue |
               Select-Object -First 1
    if (-not $baseApk) {
        $baseApk = Get-ChildItem -LiteralPath $pkgDir -Filter "*.apk" -File -ErrorAction SilentlyContinue |
                   Select-Object -First 1
    }
    if (-not $baseApk) { continue }

    # --- Hash
    $sha256 = (Get-FileHash $baseApk.FullName -Algorithm SHA256).Hash
    $sha256 | Out-File (Join-Path $HashDir "$pkg.sha256")

    # --- apksigner
    $certOut = apksigner verify --print-certs $baseApk.FullName
    $certOut | Out-File (Join-Path $CertDir "$pkg.txt")
    $CertSHA = ($certOut | Select-String "SHA-256").ToString()

    # --- APKMirror fingerprint check
    $FingerprintOK = $false
    foreach ($b in $Baseline.GetEnumerator()) {
        if ($CertSHA -match $b.Value) { $FingerprintOK = $true }
    }

    # --- aapt2 manifest / permissions
    $aapt = aapt2 dump badging $baseApk.FullName 2>$null
    $aapt | Out-File (Join-Path $ManDir "$pkg.txt")

    $debuggable = ($aapt | Select-String "debuggable").Length -gt 0
    $targetSdk  = ($aapt | Select-String "targetSdkVersion").ToString()
    $version    = ($aapt | Select-String "versionName").ToString()
    $permissions = ($aapt | Select-String "uses-permission").ToString()

    # --- DEX extraction
    $dexOut = Join-Path $DexDir "$pkg-classes.dex"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($baseApk.FullName, $pkgDir)
        Copy-Item (Join-Path $pkgDir "classes.dex") $dexOut -Force
    } catch {
        Write-Warning "DEX extraction failed for $pkg"
    }

    # --- Runtime checks
    $cleartext = adb shell dumpsys package $pkg | Select-String "usesCleartextTraffic=true"
    $installer = adb shell pm list packages -i | Select-String $pkg
    $isSystem  = $apkPath -match "^/system|^/product|^/vendor"
    $testKey   = $certOut -match "testkey|Android Debug"
    $entropy   = Get-Entropy $baseApk.FullName

    # --- YARA scan
    $yaraMatch = $false
    if (Get-Command yara64.exe -ErrorAction SilentlyContinue) {
        $y = yara64.exe "yara\android_malware.yar" $baseApk.FullName
        if ($y) {
            $y | Out-File (Join-Path $YaraDir "$pkg.txt")
            $yaraMatch = $true
        }
    }

    # --- Risk scoring
    $Score = 0
    if (-not $FingerprintOK) { $Score += 30 }
    if ($testKey)           { $Score += 30 }
    if ($debuggable)        { $Score += 20 }
    if ($cleartext)         { $Score += 15 }
    if ($yaraMatch)         { $Score += 40 }
    if ($entropy -gt 7.5)   { $Score += 25 }

    switch ($Score) {
        {$_ -ge 80} {$Severity="CRITICAL"; break}
        {$_ -ge 50} {$Severity="HIGH"; break}
        {$_ -ge 25} {$Severity="MED"; break}
        default      {$Severity="LOW"}
    }

    # --- MDM exit codes / remediation hints
    if ($Severity -in @("CRITICAL","HIGH")) {
        $MDMCode = 1
        $Remediation = "Uninstall / Verify source / Check signatures"
    } else {
        $MDMCode = 0
        $Remediation = "Compliant"
    }

    $Report += [PSCustomObject]@{
        Package     = $pkg
        Version     = $version
        TargetSdk   = $targetSdk
        SHA256      = $sha256
        CertSHA256  = $CertSHA
        FingerprintOK = $FingerprintOK
        Installer   = $installer
        SystemApp   = $isSystem
        Debuggable  = $debuggable
        Cleartext   = [bool]$cleartext
        TestKey     = $testKey
        Entropy     = $entropy
        YaraMatch   = $yaraMatch
        Permissions = $permissions
        RiskScore   = $Score
        Severity    = $Severity
        MDMCode     = $MDMCode
        Remediation = $Remediation
        ApkPath     = $apkPath
    }
} # <- Закрыли foreach

# --- HTML / CSV / JSON output
function Get-UniqueFileName($path) {
    if (-not (Test-Path $path)) { return $path }
    $dir = Split-Path $path -Parent
    $name = [System.IO.Path]::GetFileNameWithoutExtension($path)
    $ext  = [System.IO.Path]::GetExtension($path)
    $ts   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    return Join-Path $dir ("$name" + "_" + $ts + $ext)
}

$csvFile  = Get-UniqueFileName (Join-Path $ReportDir "report.csv")
$jsonFile = Get-UniqueFileName (Join-Path $ReportDir "report.json")
$htmlFile = Get-UniqueFileName (Join-Path $ReportDir "report.html")

$Report | Export-Csv $csvFile -NoTypeInformation -Encoding UTF8
$Report | ConvertTo-Json -Depth 5 | Out-File $jsonFile

# --- HTML with safe string
$htmlPreContent = '<h1>' + $Brand + ' ' + $Model + ' (' + $Serial + ')</h1><p>Scan: ' + $Time + '</p>'

$Report | ConvertTo-Html `
    -Title 'Android APK Security Audit v2.2' `
    -PreContent $htmlPreContent |
    Out-File $htmlFile -Encoding UTF8

Write-Host "`n[✓] Audit completed: $RootDir"
Write-Host "[✓] Reports generated:"
Write-Host "    CSV : $csvFile"
Write-Host "    JSON: $jsonFile"
Write-Host "    HTML: $htmlFile"
Write-Host "[✓] APK pull skip, baseline diff, APKMirror fingerprints, DEX scan, severity, MDM exit codes included"
