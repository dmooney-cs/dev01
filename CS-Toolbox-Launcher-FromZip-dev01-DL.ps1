# CS-Toolbox-Launcher-FromZip-dev01-NOHASH.ps1
# Bootstrapper for ConnectSecure Technician Toolbox (dev01)
#
# NOTE:
#   This version intentionally performs NO file hash or integrity verification.
#
# - Downloads prod-01-01.zip (with retry logic)
# - Extracts to C:\CS-Toolbox-TEMP\prod-01-01
# - Launches CS-Toolbox-Launcher.ps1 in the SAME PowerShell window (dot-sourced)

# --------------------------
# Config
# --------------------------
$ZipUrl      = 'https://github.com/dmooney-cs/dev01/raw/refs/heads/main/prod-01-01.zip'
$ZipPath     = Join-Path $env:TEMP 'prod-01-01.zip'
$ExtractPath = 'C:\CS-Toolbox-TEMP'
$DestRoot    = Join-Path $ExtractPath 'prod-01-01'
$Launcher    = Join-Path $DestRoot 'CS-Toolbox-Launcher.ps1'

# --------------------------
# Prompt user
# --------------------------
$response = Read-Host 'Download and install the ConnectSecure Technician Toolbox (dev01)? (Y/N)'
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

# Clean existing destination
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
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2
    )

    if (Test-Path -LiteralPath $OutFile) {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Host ("Downloading toolbox... Attempt {0}/{1}" -f $attempt, $MaxAttempts) -ForegroundColor Cyan
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
            if ((Test-Path -LiteralPath $OutFile) -and ((Get-Item -LiteralPath $OutFile).Length -gt 0)) {
                Write-Host "✅ Download successful." -ForegroundColor Green
                return $true
            } else {
                throw "Downloaded file is missing or empty."
            }
        } catch {
            if (Test-Path -LiteralPath $OutFile) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }
            if ($attempt -eq $MaxAttempts) {
                Write-Host ("❌ ERROR: Download failed on attempt {0}/{1}: {2}" -f $attempt, $MaxAttempts, $_.Exception.Message) -ForegroundColor Red
                return $false
            } else {
                Write-Host ("⚠️ Attempt {0}/{1} failed: {2}" -f $attempt, $MaxAttempts, $_.Exception.Message) -ForegroundColor Yellow
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }
    return $false
}

# --------------------------
# Download ZIP
# --------------------------
if (-not (Invoke-DownloadWithRetry -Uri $ZipUrl -OutFile $ZipPath)) {
    Write-Host 'Download did not succeed after multiple attempts.' -ForegroundColor Red
    return
}

# --------------------------
# Extract ZIP
# --------------------------
Write-Host 'Extracting toolbox...' -ForegroundColor Cyan
try {
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
} catch {
    Write-Host ('❌ ERROR: Extract failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    return
}

# --------------------------
# Normalize folder structure
# --------------------------
function Move-Contents([string]$Source, [string]$Target) {
    if (-not (Test-Path -LiteralPath $Source)) { return }
    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        try { Move-Item -LiteralPath $_.FullName -Destination $Target -Force } catch { }
    }
}

if (-not (Test-Path -LiteralPath $Launcher)) {
    $dirs = Get-ChildItem -LiteralPath $ExtractPath -Directory -Force | Where-Object { $_.FullName -ne $DestRoot }
    if ($dirs.Count -eq 1) {
        Move-Contents -Source $dirs[0].FullName -Target $DestRoot
        Remove-Item -LiteralPath $dirs[0].FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --------------------------
# Unblock files
# --------------------------
Get-ChildItem -LiteralPath $DestRoot -Recurse -File -Force |
    ForEach-Object { Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue }

# --------------------------
# Verify launcher exists
# --------------------------
if (-not (Test-Path -LiteralPath $Launcher)) {
    Write-Host ('❌ ERROR: Launcher not found: {0}' -f $Launcher) -ForegroundColor Red
    return
}

# --------------------------
# Launch in SAME window
# --------------------------
Write-Host '✅ Download & extraction complete.' -ForegroundColor Green
Read-Host 'Press ENTER to launch the ConnectSecure Technician Toolbox' | Out-Null

. $Launcher
