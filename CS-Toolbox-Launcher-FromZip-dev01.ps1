# CS-Toolbox-Launcher-FromZip.ps1
# Downloads, verifies SHA-256 (BEFORE extract), extracts, launches

# --------------------------
# Config
# --------------------------
$ZipUrl         = 'https://github.com/dmooney-cs/dev01/raw/refs/heads/main/prod-01-01.zip'
$ExpectedSHA256 = 'd8b3055ae1a1bb8ce2c0604ae8962dd108164ac5f9b9b24db1cfc0d795046db9'  # <-- 64 hex chars
$ExtractPath    = 'C:\CS-Toolbox-TEMP'
$DestRoot       = Join-Path $ExtractPath 'prod-01-01'
$ZipPath        = Join-Path $ExtractPath  'prod-01-01.zip'  # <-- put the ZIP next to the folder we control
$Launcher       = Join-Path $DestRoot 'CS-Toolbox-Launcher.ps1'
$ProgressPreference = 'SilentlyContinue'

Write-Host ("Using ExtractPath: {0}" -f $ExtractPath) -ForegroundColor DarkGray
Write-Host ("Using ZipPath    : {0}" -f $ZipPath)     -ForegroundColor DarkGray

# Prompt
$response = Read-Host 'Download and install the ConnectSecure Technician Toolbox (prod-01-01)? (Y/N)'
if ($response -notin @('Y','y')) { Write-Host 'Aborted by user.' -ForegroundColor Yellow; return }

# TLS
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# Ensure base folder
if (-not (Test-Path -LiteralPath $ExtractPath)) {
  try { New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null }
  catch { Write-Host ("❌ ERROR: Failed to create {0}: {1}" -f $ExtractPath, $_.Exception.Message) -ForegroundColor Red; return }
}

# Clean dest folder
if (Test-Path -LiteralPath $DestRoot) {
  try { Remove-Item -LiteralPath $DestRoot -Recurse -Force -ErrorAction Stop }
  catch { Write-Host ("⚠️ WARN: Could not remove {0}: {1}" -f $DestRoot, $_.Exception.Message) -ForegroundColor Yellow }
}

# Download
Write-Host 'Downloading toolbox...' -ForegroundColor Cyan
try {
  if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue }
  Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath -UseBasicParsing -ErrorAction Stop
} catch {
  Write-Host ("❌ ERROR: Download failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
  return
}

# Validate expected hash string
$ExpectedSHA256 = $ExpectedSHA256.Trim().ToLower()
Write-Host ("Expected SHA-256: {0} (len={1})" -f $ExpectedSHA256, $ExpectedSHA256.Length) -ForegroundColor DarkGray
if ($ExpectedSHA256 -notmatch '^[0-9a-f]{64}$') {
  Write-Host '❌ ERROR: Invalid expected SHA-256 format. Please contact ConnectSecure support.' -ForegroundColor Red
  try { Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue } catch { }
  return
}

# Compute actual SHA-256 (BEFORE extract)
function Get-ZipSHA256([string]$Path) {
  try { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToLower() }
  catch {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs  = [System.IO.File]::OpenRead($Path)
    try { -join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) }
    finally { $fs.Dispose(); $sha.Dispose() }
  }
}

try {
  if (-not (Test-Path -LiteralPath $ZipPath)) { throw "Downloaded file not found at $ZipPath" }
  $actual = Get-ZipSHA256 -Path $ZipPath
  Write-Host ("Computed SHA-256: {0}" -f $actual) -ForegroundColor DarkGray

  if (-not [string]::Equals($actual, $ExpectedSHA256, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Host '❌ ERROR: Download integrity check failed.' -ForegroundColor Red
    Write-Host ("Expected SHA-256: {0}" -f $ExpectedSHA256) -ForegroundColor Yellow
    Write-Host ("Actual   SHA-256: {0}" -f $actual)         -ForegroundColor Yellow
    try { Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue } catch { }
    Write-Host 'Please contact ConnectSecure support.' -ForegroundColor Red
    return
  }
  Write-Host '✅ SHA-256 verified.' -ForegroundColor Green
} catch {
  Write-Host ("❌ ERROR: Could not verify download integrity: {0}" -f $_.Exception.Message) -ForegroundColor Red
  try { Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue } catch { }
  Write-Host 'Please contact ConnectSecure support.' -ForegroundColor Red
  return
}

# Extract after pass
Write-Host 'Extracting toolbox...' -ForegroundColor Cyan
try { Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force }
catch { Write-Host ("❌ ERROR: Extract failed: {0}" -f $_.Exception.Message) -ForegroundColor Red; return }
finally { try { Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue } catch { } }

# Ensure destination
if (-not (Test-Path -LiteralPath $DestRoot)) { New-Item -Path $DestRoot -ItemType Directory -Force | Out-Null }

# Normalize folder structure (unchanged from before) ...
# [snip for brevity — keep your existing Move-Contents and normalization blocks]
