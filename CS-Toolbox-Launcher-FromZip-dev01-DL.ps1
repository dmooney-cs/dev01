param(
    [switch]$Prompt,
    [switch]$Launch   # ONLY launch when explicitly set
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ZipUrl      = 'https://github.com/dmooney-cs/dev01/raw/refs/heads/main/prod-01-01.zip'
$ZipPath     = Join-Path $env:TEMP 'prod-01-01.zip'
$ExtractPath = 'C:\CS-Toolbox-TEMP'
$DestRoot    = Join-Path $ExtractPath 'prod-01-01'
$Launcher    = Join-Path $DestRoot 'CS-Toolbox-Launcher.ps1'

function Wait-Path {
    param([Parameter(Mandatory)][string]$Path,[int]$TimeoutSec=180,[int]$PollMs=250)
    $sw=[Diagnostics.Stopwatch]::StartNew()
    while(-not(Test-Path -LiteralPath $Path)){
        if($sw.Elapsed.TotalSeconds -ge $TimeoutSec){ throw "Timed out waiting for: $Path" }
        Start-Sleep -Milliseconds $PollMs
    }
}
function Wait-Files {
    param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)][string[]]$Files,[int]$TimeoutSec=180)
    foreach($f in $Files){ Wait-Path -Path (Join-Path $Root $f) -TimeoutSec $TimeoutSec }
}

if ($Prompt) {
    $response = Read-Host 'Download and install the ConnectSecure Technician Toolbox (dev01)? (Y/N)'
    if ($response -notin @('Y','y')) { Write-Warning 'Aborted by user.'; return }
}

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

if (-not (Test-Path -LiteralPath $ExtractPath)) {
    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
}

if (Test-Path -LiteralPath $DestRoot) {
    Remove-Item -LiteralPath $DestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-DownloadWithRetry {
    param([string]$Uri,[string]$OutFile,[int]$MaxAttempts=3)
    Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
    for ($i=1; $i -le $MaxAttempts; $i++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
            if ((Get-Item -LiteralPath $OutFile).Length -gt 0) { return }
        } catch {
            if ($i -eq $MaxAttempts) { throw }
            Start-Sleep -Seconds 2
        }
    }
}

Invoke-DownloadWithRetry -Uri $ZipUrl -OutFile $ZipPath

Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

# Normalize folder
if (-not (Test-Path -LiteralPath $Launcher)) {
    $dirs = Get-ChildItem -LiteralPath $ExtractPath -Directory -Force | Where-Object { $_.FullName -ne $DestRoot }
    if ($dirs.Count -eq 1) {
        Get-ChildItem -LiteralPath $dirs[0].FullName -Force | Move-Item -Destination $DestRoot -Force
        Remove-Item -LiteralPath $dirs[0].FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Wait for required files to exist (adjust list as needed)
$Root = $DestRoot
Wait-Path  -Path $Root -TimeoutSec 300
Wait-Files -Root $Root -Files @('Registry-Search.ps1','CS-Toolbox-Launcher.ps1') -TimeoutSec 300

Get-ChildItem -LiteralPath $DestRoot -Recurse -File -Force | Unblock-File -ErrorAction SilentlyContinue

# If we're not launching, we're done.
if (-not $Launch) { return }

if ($Prompt) { Read-Host 'Press ENTER to launch the ConnectSecure Technician Toolbox' | Out-Null }

. $Launcher
