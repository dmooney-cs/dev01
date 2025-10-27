# CS-Toolbox-Launcher-FromZip.ps1
# Bootstrapper for ConnectSecure Technician Toolbox (prod-01-01)
# - Downloads prod-01-01.zip (with retry logic)
# - Extracts to C:\CS-Toolbox-TEMP\prod-01-01
# - Launches CS-Toolbox-Launcher.ps1 in the SAME PowerShell window (dot-sourced)
# - Handles nested folders in the ZIP and unblocks files

# --------------------------
# Config
# --------------------------
$ZipUrl      = 'https://github.com/dmooney-cs/dev01/raw/refs/heads/main/prod-01-01.zip'  # RAW file url
$ZipPath     = Join-Path $env:TEMP 'prod-01-01.zip'
$ExtractPath = 'C:\CS-Toolbox-TEMP'
$DestRoot    = Join-Path $ExtractPath 'prod-01-01'
$Launcher    = Join-Path $DestRoot 'CS-Toolbox-Launcher.ps1'

# --------------------------
# Prompt user
# --------------------------
$response = Read-Host 'Download and install the ConnectSecure Technician Toolbox (prod-01-01)? (Y/N)'
if ($response -notin @('Y','y')) {
    Write-Host 'Aborted by user.' -ForegroundColor Yellow
    return
}

# --------------------------
# Prep environment
# --------------------------
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# Ensure base folder exists
if (-not (Test-Path -LiteralPath $ExtractPath)) {
    try {
        New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    } catch {
        Write-Host ('❌ ERROR: Failed to create {0}: {1}' -f $ExtractPath, $_.Exception.Message) -ForegroundColor Red
        return
    }
}

# Clean existing destination (avoid stale files)  <-- fixed: removed extra ')'
if (Test-Path -LiteralPath $DestRoot) {
    try {
        Remove-Item -LiteralPath $DestRoot -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Host ('⚠️ WARN: Could not remove existing folder {0}: {1}' -f $DestRoot, $_.Exception.Message) -ForegroundColor Yellow
    }
}

# --------------------------
# Helper: Download with retries
# --------------------------
function Invoke-DownloadWithRetry {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$OutFile,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2
    )

    # Ensure no stale file before we start
    if (Test-Path -LiteralPath $OutFile) {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Host ("Downloading toolbox... Attempt {0}/{1}" -f $attempt, $MaxAttempts) -ForegroundColor Cyan
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -ErrorAction Stop

            # Basic integrity check: ensure file exists and is > 0 bytes
            if ((Test-Path -LiteralPath $OutFile) -and ((Get-Item -LiteralPath $OutFile).Length -gt 0)) {
                Write-Host "✅ Download successful." -ForegroundColor Green
                return $true
            } else {
                throw "Downloaded file is missing or empty."
            }
        } catch {
            # Clean up any partial file then decide to retry or fail
            if (Test-Path -LiteralPath $OutFile) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }
            $isLast = ($attempt -eq $MaxAttempts)
            if ($isLast) {
                Write-Host ("❌ ERROR: Download failed on attempt {0}/{1}: {2}" -f $attempt, $MaxAttempts, $_.Exception.Message) -ForegroundColor Red
                return $false
            } else {
                Write-Host ("⚠️ Attempt {0}/{1} failed: {2}" -f $attempt, $MaxAttempts, $_.Exception.Message) -ForegroundColor Yellow
                Write-Host ("   Retrying in {0} seconds..." -f $DelaySeconds) -ForegroundColor Yellow
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    return $false
}

# --------------------------
# Download ZIP (with retry status 1/3, 2/3, 3/3)
# --------------------------
$downloadOk = Invoke-DownloadWithRetry -Uri $ZipUrl -OutFile $ZipPath -MaxAttempts 3 -DelaySeconds 2
if (-not $downloadOk) {
    Write-Host 'Download did not succeed after 3 attempts. Please check your connection or try again later.' -ForegroundColor Red
    return
}

# --------------------------
# Extract ZIP
# --------------------------
Write-Host 'Extracting toolbox...' -ForegroundColor Cyan
try {
    # Extract into ExtractPath; we will normalize into $DestRoot next
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
} catch {
    Write-Host ('❌ ERROR: Extract failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    return
}

# Ensure destination exists for normalization
if (-not (Test-Path -LiteralPath $DestRoot)) {
    New-Item -Path $DestRoot -ItemType Directory -Force | Out-Null
}

# --------------------------
# Normalize folder structure
# Handle cases:
#  - ZIP root already contains prod-01-01/
#  - ZIP contains a single nested folder with contents
#  - ZIP dumps files directly in ExtractPath
# --------------------------
function Move-Contents([string]$Source, [string]$Target) {
    if (-not (Test-Path -LiteralPath $Source)) { return }
    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        try {
            Move-Item -LiteralPath $_.FullName -Destination $Target -Force
        } catch {
            Write-Host ('⚠️ WARN: Failed to move {0} -> {1}: {2}' -f $_.FullName, $Target, $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

# If files already ended up in prod-01-01, we’re good; otherwise normalize.
$alreadyGood = Test-Path -LiteralPath (Join-Path $DestRoot 'CS-Toolbox-Launcher.ps1')

if (-not $alreadyGood) {
    # Try to detect a single top-level directory that isn't prod-01-01
    $topDirs = Get-ChildItem -LiteralPath $ExtractPath -Directory -Force | Where-Object { $_.FullName -ne $DestRoot }
    $topFiles = Get-ChildItem -LiteralPath $ExtractPath -File -Force | Where-Object { $_.FullName -ne $ZipPath }

    if ($topDirs.Count -eq 1 -and $topFiles.Count -eq 0) {
        # Single nested folder — move its contents into DestRoot
        Move-Contents -Source $topDirs[0].FullName -Target $DestRoot
        # Attempt to remove the empty nested folder
        try { Remove-Item -LiteralPath $topDirs[0].FullName -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    } else {
        # Mixed or files at root — move everything except the zip and DestRoot into DestRoot
        foreach ($d in $topDirs) { Move-Contents -Source $d.FullName -Target $DestRoot }
        foreach ($f in $topFiles) {
            try { Move-Item -LiteralPath $f.FullName -Destination $DestRoot -Force } catch { }
        }
        # Clean up any now-empty top-level folders we moved from
        foreach ($d in $topDirs) {
            try { Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
}

# --------------------------
# Unblock all extracted files (avoid execution warnings)
# --------------------------
try {
    Get-ChildItem -LiteralPath $DestRoot -Recurse -Force -File | ForEach-Object {
        try { Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue } catch { }
    }
} catch { }

# --------------------------
# Verify launcher exists
# --------------------------
if (-not (Test-Path -LiteralPath $Launcher)) {
    Write-Host ('❌ ERROR: Launcher not found: {0}' -f $Launcher) -ForegroundColor Red
    Write-Host 'Please verify the ZIP contents or try again.' -ForegroundColor Yellow
    return
}

# --------------------------
# Ready to launch in SAME window
# --------------------------
Write-Host '✅ Download & extraction complete.' -ForegroundColor Green
$null = Read-Host 'Press ENTER to launch the ConnectSecure Technician Toolbox'

# Dot-source so it runs IN THIS WINDOW (no new PowerShell process)
try {
    . $Launcher
} catch {
    Write-Host ('❌ ERROR launching Toolbox: {0}' -f $_.Exception.Message) -ForegroundColor Red
    $null = Read-Host 'Press ENTER to exit'
}
