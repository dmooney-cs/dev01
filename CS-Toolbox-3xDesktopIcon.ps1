<# =================================================================================================
 CS-Toolbox-3xDesktopIcon.ps1  (v1.0)

 Downloads a ZIP from GitHub (with up to 3 attempts), extracts to SYSTEM temp (C:\Windows\Temp),
 then copies the correct items:
   - Launcher .lnk -> interactive user's Desktop and/or Taskbar pinned folder
   - CS-Toolbox-Launcher-DevTools-ZeroTouch.ps1 -> C:\Temp

 Default behavior:
   - If neither -Desktop nor -Taskbar is specified, Desktop is assumed.
   - Runs verbose by default (shows actions + hashes + prompts).
   - -Silent makes it deployment-friendly (no prompts, minimal console output; still logs + exports summary).

 Switches:
   -ZipUrl     : Direct GitHub zip URL (required)
   -Desktop    : Copy LNK to user's Desktop
   -Taskbar    : Copy LNK to user's Taskbar pinned folder
   -Silent     : No prompts; minimal output; still logs
   -ExportOnly : Export JSON summary to C:\Temp\collected-info and exit (toolbox convention)

 Your GitHub ZIP URL example:
   https://github.com/dmooney-cs/dev01/raw/refs/heads/main/Toolbox-Launchers.zip

================================================================================================= #>

#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ZipUrl,

    [switch]$Desktop,
    [switch]$Taskbar,

    [switch]$Silent,

    # Required by your toolbox conventions
    [switch]$ExportOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------- Defaults -------------------------
if (-not $Desktop -and -not $Taskbar) { $Desktop = $true }

# ------------------------- Paths / logging -------------------------
$DeployRoot = "C:\Temp"
$CollectedInfoDir = Join-Path $DeployRoot "collected-info"
$LogFile = Join-Path $DeployRoot "CS-Toolbox-GitHubZip-Deploy.log"
$ExportJson = Join-Path $CollectedInfoDir "CS-Toolbox-GitHubZip-Deploy.json"

function Ensure-Dir {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

Ensure-Dir $DeployRoot
Ensure-Dir $CollectedInfoDir

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')] [string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
    if (-not $Silent) {
        switch ($Level) {
            'ERROR' { Write-Host $line -ForegroundColor Red }
            'WARN'  { Write-Host $line -ForegroundColor Yellow }
            'OK'    { Write-Host $line -ForegroundColor Green }
            default { Write-Host $line }
        }
    }
}

$script:LogFile = $LogFile
Write-Log "Starting. ZipUrl='$ZipUrl' Desktop=$Desktop Taskbar=$Taskbar Silent=$Silent ExportOnly=$ExportOnly" "INFO"

# ------------------------- Helpers -------------------------
function Get-LoggedOnUserSid {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if (-not $cs.UserName) { throw "No interactive user detected (Win32_ComputerSystem.UserName is empty)." }

    $nt = New-Object System.Security.Principal.NTAccount($cs.UserName)
    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    return [pscustomobject]@{ UserName = $cs.UserName; Sid = $sid }
}

function Get-UserShellFolderPath {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][ValidateSet('Desktop','AppData')] [string]$Folder
    )
    $base = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    $name = if ($Folder -eq 'Desktop') { 'Desktop' } else { 'AppData' }
    $val = (Get-ItemProperty -Path $base -Name $name -ErrorAction Stop).$name
    if (-not $val) { throw "Unable to resolve $Folder path from HKU:\$Sid Shell Folders." }
    return $val
}

function Find-FirstMatch {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$Patterns
    )
    foreach ($p in $Patterns) {
        $hit = Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -like $p } |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

function Get-FileHashSafe {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Download-GitHubZipWithRetry {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$OutFile,

        [int]$MaxAttempts = 3
    )

    # TLS hardening for PS 5.1
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12 -bor
            [Net.SecurityProtocolType]::Tls11 -bor
            [Net.SecurityProtocolType]::Tls
    } catch {}

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-Log "Download attempt $attempt of $MaxAttempts" "INFO"
            Write-Log "URL: $Url" "INFO"
            Write-Log "Out: $OutFile" "INFO"

            if (Test-Path -LiteralPath $OutFile) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }

            $usedBits = $false
            try {
                if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
                    Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
                    $usedBits = $true
                }
            } catch {
                Write-Log "BITS failed: $($_.Exception.Message)" "WARN"
            }

            if (-not $usedBits) {
                Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
            }

            if (-not (Test-Path -LiteralPath $OutFile -PathType Leaf)) {
                throw "File not present after download"
            }

            Write-Log "Download successful on attempt $attempt" "OK"
            return
        }
        catch {
            Write-Log "Attempt $attempt failed: $($_.Exception.Message)" "WARN"

            if ($attempt -lt $MaxAttempts) {
                $delay = 3 * $attempt
                Write-Log "Retrying in $delay seconds..." "INFO"
                Start-Sleep -Seconds $delay
            } else {
                throw "Download failed after $MaxAttempts attempts"
            }
        }
    }
}

# ------------------------- Summary object (ExportOnly/collected-info) -------------------------
$summary = [ordered]@{
    startedAt           = (Get-Date).ToString('o')
    zipUrl              = $ZipUrl
    downloadedZip       = $null
    downloadSha256      = $null
    extractTo           = $null
    interactiveUser     = $null
    userSid             = $null
    userDesktop         = $null
    userAppData         = $null
    taskbarPinnedFolder = $null
    foundLink           = $null
    foundPs1            = $null
    copiedToDesktop     = $null
    copiedToTaskbar     = $null
    copiedToCTemp       = $null
    hashes              = [ordered]@{
        linkSourceSha256  = $null
        linkDesktopSha256 = $null
        linkTaskbarSha256 = $null
        ps1SourceSha256   = $null
        ps1CTempSha256    = $null
    }
    result              = "UNKNOWN"
}

try {
    # Determine interactive user + target folders
    $user = Get-LoggedOnUserSid
    $summary.interactiveUser = $user.UserName
    $summary.userSid = $user.Sid
    Write-Log "Interactive user: $($user.UserName)  SID=$($user.Sid)" "INFO"

    $desktopPath = Get-UserShellFolderPath -Sid $user.Sid -Folder Desktop
    $appDataPath = Get-UserShellFolderPath -Sid $user.Sid -Folder AppData
    $summary.userDesktop = $desktopPath
    $summary.userAppData = $appDataPath

    $taskbarDir = Join-Path $appDataPath "Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    $summary.taskbarPinnedFolder = $taskbarDir

    # Download ZIP into SYSTEM temp
    $sysTemp = Join-Path $env:windir "Temp"
    Ensure-Dir $sysTemp

    $zipFile = Join-Path $sysTemp ("Toolbox-Launchers_" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_" + ([guid]::NewGuid().ToString("N").Substring(0,8)) + ".zip")

    Download-GitHubZipWithRetry -Url $ZipUrl -OutFile $zipFile -MaxAttempts 3

    $summary.downloadedZip = $zipFile
    $summary.downloadSha256 = Get-FileHashSafe -Path $zipFile
    Write-Log "Downloaded ZIP SHA256: $($summary.downloadSha256)" "OK"

    # Extract into SYSTEM temp unique folder
    $extractDir = Join-Path $sysTemp ("CS-Toolbox-Extract_" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_" + ([guid]::NewGuid().ToString("N").Substring(0,8)))
    Ensure-Dir $extractDir
    $summary.extractTo = $extractDir

    Write-Log "Extracting to: $extractDir" "INFO"
    Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDir -Force
    Write-Log "Extract complete." "OK"

    # Find the correct files in extracted tree
    $lnk = Find-FirstMatch -Root $extractDir -Patterns @(
        "*ConnectSeure*Toolbox*Launcher*.lnk",
        "*ConnectSecure*Toolbox*Launcher*.lnk",
        "*CS-Toolbox*Launcher*.lnk",
        "*Toolbox*Launcher*.lnk",
        "*.lnk"
    )

    $ps1 = Find-FirstMatch -Root $extractDir -Patterns @(
        "*CS-Toolbox-Launcher-DevTools-ZeroTouch.ps1",
        "*ZeroTouch*.ps1"
    )

    if (-not $lnk) { throw "Could not find a .lnk inside extracted contents." }
    if (-not $ps1) { throw "Could not find the ZeroTouch .ps1 inside extracted contents." }

    $summary.foundLink = $lnk
    $summary.foundPs1  = $ps1
    Write-Log "Found LNK: $lnk" "OK"
    Write-Log "Found PS1: $ps1" "OK"

    $summary.hashes.linkSourceSha256 = Get-FileHashSafe -Path $lnk
    $summary.hashes.ps1SourceSha256  = Get-FileHashSafe -Path $ps1

    if (-not $Silent) {
        Write-Host ""
        Write-Host "Hashes:" -ForegroundColor Cyan
        Write-Host "  ZIP SHA256 : $($summary.downloadSha256)"
        Write-Host "  LNK SHA256 : $($summary.hashes.linkSourceSha256)"
        Write-Host "  PS1 SHA256 : $($summary.hashes.ps1SourceSha256)"
        Write-Host ""
    }

    if (-not $Silent -and -not $ExportOnly) {
        Write-Host "Planned actions:" -ForegroundColor Cyan
        if ($Desktop) { Write-Host " - Copy LNK to Desktop: $desktopPath" }
        if ($Taskbar) { Write-Host " - Copy LNK to Taskbar pinned folder: $taskbarDir" }
        Write-Host " - Copy PS1 to C:\Temp"
        Write-Host ""
        $ans = Read-Host "Proceed? (Y/N)"
        if ($ans -notin @('Y','y')) { throw "User cancelled." }
    }

    if ($ExportOnly) {
        $summary.result = "EXPORTONLY"
        $summary.finishedAt = (Get-Date).ToString('o')
        ($summary | ConvertTo-Json -Depth 10) | Set-Content -Path $ExportJson -Encoding UTF8
        if (-not $Silent) { Write-Host "Exported: $ExportJson" }
        exit 0
    }

    # Copy PS1 to C:\Temp
    Ensure-Dir $DeployRoot
    $ps1Dest = Join-Path $DeployRoot (Split-Path -Leaf $ps1)
    Copy-Item -LiteralPath $ps1 -Destination $ps1Dest -Force
    $summary.copiedToCTemp = $ps1Dest
    $summary.hashes.ps1CTempSha256 = Get-FileHashSafe -Path $ps1Dest
    Write-Log "Copied PS1 to: $ps1Dest" "OK"

    # Copy LNK to Desktop
    if ($Desktop) {
        Ensure-Dir $desktopPath
        $lnkDest = Join-Path $desktopPath (Split-Path -Leaf $lnk)
        Copy-Item -LiteralPath $lnk -Destination $lnkDest -Force
        $summary.copiedToDesktop = $lnkDest
        $summary.hashes.linkDesktopSha256 = Get-FileHashSafe -Path $lnkDest
        Write-Log "Copied LNK to Desktop: $lnkDest" "OK"
    }

    # Copy LNK to Taskbar pinned folder
    if ($Taskbar) {
        Ensure-Dir $taskbarDir
        $tbDest = Join-Path $taskbarDir (Split-Path -Leaf $lnk)
        Copy-Item -LiteralPath $lnk -Destination $tbDest -Force
        $summary.copiedToTaskbar = $tbDest
        $summary.hashes.linkTaskbarSha256 = Get-FileHashSafe -Path $tbDest
        Write-Log "Copied LNK to Taskbar pinned folder: $tbDest" "OK"
    }

    $summary.result = "SUCCESS"
}
catch {
    $summary.result = "FAILED"
    $summary.error  = $_.Exception.Message
    Write-Log "FAILED: $($summary.error)" "ERROR"
    if (-not $Silent) { throw }
}
finally {
    $summary.finishedAt = (Get-Date).ToString('o')
    ($summary | ConvertTo-Json -Depth 10) | Set-Content -Path $ExportJson -Encoding UTF8
    Write-Log "Summary exported to: $ExportJson" "INFO"
    Write-Log "Done. Result=$($summary.result)" "INFO"
}

exit 0
