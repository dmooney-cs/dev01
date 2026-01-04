<# =================================================================================================
 CS-Toolbox-DecryptorDesktopIcon.ps1  (v1.3)

 Landing rules (FINAL):
  - .ps1 + .ico  -> C:\CS-Toolbox-TEMP\Launchers
  - .lnk         -> ACTIVE interactive user's Desktop
  - Logs + JSON  -> C:\CS-Toolbox-TEMP\Collected-Info
  - Work staging -> C:\CS-Toolbox-TEMP\Decrypt\_work

 Supports:
  - Elevated execution
  - Interactive user resolution via Win32_ComputerSystem + HKU:\SID
  - -ExportOnly (JSON export + exit)
================================================================================================= #>

#requires -version 5.1
[CmdletBinding()]
param(
    [string]$ZipUrl = "https://github.com/dmooney-cs/dev01/raw/refs/heads/main/decryptor-zip.zip",
    [switch]$Silent,
    [switch]$ExportOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ------------------------- Paths -------------------------
$DecryptRoot     = "C:\CS-Toolbox-TEMP\Decrypt"
$LauncherRoot    = "C:\CS-Toolbox-TEMP\Launchers"
$CollectedInfo   = "C:\CS-Toolbox-TEMP\Collected-Info"
$WorkRoot        = Join-Path $DecryptRoot "_work"

$LogFile    = Join-Path $CollectedInfo "CS-Toolbox-DecryptorDesktopIcon.log"
$ExportJson = Join-Path $CollectedInfo "CS-Toolbox-DecryptorDesktopIcon.json"

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

Ensure-Dir $DecryptRoot
Ensure-Dir $LauncherRoot
Ensure-Dir $CollectedInfo
Ensure-Dir $WorkRoot

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')]$Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    if (-not $Silent) {
        switch ($Level) {
            'ERROR' { Write-Host $line -ForegroundColor Red }
            'WARN'  { Write-Host $line -ForegroundColor Yellow }
            'OK'    { Write-Host $line -ForegroundColor Green }
            default { Write-Host $line }
        }
    }
}

function Get-LoggedOnUserSid {
    $cs = Get-CimInstance Win32_ComputerSystem
    if (-not $cs.UserName) { throw "No interactive user detected." }
    $nt  = New-Object System.Security.Principal.NTAccount($cs.UserName)
    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    [pscustomobject]@{ User=$cs.UserName; Sid=$sid }
}

function Get-DesktopPath {
    param([string]$Sid)
    $key = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    (Get-ItemProperty $key -Name Desktop).Desktop
}

function Invoke-Download {
    param($Uri,$OutFile)
    Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
    for ($i=1;$i -le 3;$i++) {
        try {
            Write-Log "Downloading ($i/3): $Uri"
            Invoke-WebRequest $Uri -OutFile $OutFile -UseBasicParsing
            if ((Get-Item $OutFile).Length -gt 0) { return $true }
        } catch {
            Write-Log "Download attempt $i failed: $($_.Exception.Message)" "WARN"
            Start-Sleep 2
        }
    }
    return $false
}

function Normalize-Extract {
    param([string]$Root)

    # Force arrays so .Count is always valid under StrictMode
    $dirs  = @(Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue)
    $files = @(Get-ChildItem -LiteralPath $Root -File      -Force -ErrorAction SilentlyContinue)

    if ($dirs.Count -eq 1 -and $files.Count -eq 0) {
        $top = $dirs[0].FullName
        Get-ChildItem -LiteralPath $top -Force | Move-Item -Destination $Root -Force
        Remove-Item -LiteralPath $top -Recurse -Force
    }
}

function Copy-All {
    param($Files,$Dest)
    Ensure-Dir $Dest
    $out=@()
    foreach ($f in $Files) {
        $d = Join-Path $Dest $f.Name
        Copy-Item $f.FullName $d -Force
        Write-Log "Copied: $($f.Name) -> $Dest" "OK"
        $out += $d
    }
    $out
}

# ------------------------- Summary -------------------------
$summary = [ordered]@{
    startedAt     = (Get-Date).ToString('o')
    zipUrl        = $ZipUrl
    launcherRoot  = $LauncherRoot
    collectedInfo = $CollectedInfo
    workRoot      = $WorkRoot
    result        = "UNKNOWN"
}

Write-Log "Starting Decryptor Desktop Icon deploy"

try {
    $user = Get-LoggedOnUserSid
    $desktop = Get-DesktopPath $user.Sid
    Write-Log "Interactive user: $($user.User)"

    $zip = Join-Path $WorkRoot ("launchers_{0}.zip" -f (Get-Date -Format yyyyMMddHHmmss))
    if (-not (Invoke-Download $ZipUrl $zip)) {
        throw "Download failed after retries."
    }

    $extract = Join-Path $WorkRoot ([guid]::NewGuid().ToString())
    Expand-Archive $zip $extract -Force
    Normalize-Extract $extract

    # Force arrays so .Count is always valid under StrictMode
    $ps1 = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter *.ps1 -Force -ErrorAction SilentlyContinue)
    $ico = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter *.ico -Force -ErrorAction SilentlyContinue)
    $lnk = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter *.lnk -Force -ErrorAction SilentlyContinue)

    $summary.ps1Count = $ps1.Count
    $summary.icoCount = $ico.Count
    $summary.lnkCount = $lnk.Count

    if ($ExportOnly) {
        $summary.result = "EXPORTONLY"
    } else {
        if ($ps1.Count -gt 0) { $summary.ps1Copied = Copy-All $ps1 $LauncherRoot }
        if ($ico.Count -gt 0) { $summary.icoCopied = Copy-All $ico $LauncherRoot }
        if ($lnk.Count -gt 0) { $summary.lnkCopied = Copy-All $lnk $desktop }
        $summary.result = "SUCCESS"
    }
}
catch {
    $summary.result = "FAILED"
    $summary.error = $_.Exception.Message
    Write-Log "FAILED: $($summary.error)" "ERROR"
    if (-not $Silent) { throw }
}
finally {
    $summary.finishedAt = (Get-Date).ToString('o')
    $summary | ConvertTo-Json -Depth 12 | Set-Content $ExportJson -Encoding UTF8
    Write-Log "Summary written to $ExportJson"
}

exit 0
