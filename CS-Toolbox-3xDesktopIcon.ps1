<# =================================================================================================
 CS-Toolbox-3xDesktopIcon.ps1  (v1.3 - copy ALL by extension)

 One-liner friendly:
   irm https://raw.githubusercontent.com/dmooney-cs/dev01/main/CS-Toolbox-3xDesktopIcon.ps1 | iex

 - Downloads ZIP (3 attempts) with strong validation (rejects HTML, verifies ZIP structure)
 - Extracts to SYSTEM temp (C:\Windows\Temp)
 - Copies:
     • ALL .lnk files -> interactive user's Desktop and/or Taskbar pinned folder
     • ALL .ps1 files -> C:\Temp

 Switches:
   -ZipUrl     : override ZIP URL
   -Desktop    : copy .lnk files to Desktop
   -Taskbar    : copy .lnk files to Taskbar pinned folder
   -Silent     : no prompts; minimal console output (still logs + exports summary)
   -ExportOnly : export JSON summary to C:\Temp\collected-info and exit
================================================================================================= #>

#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$ZipUrl = "https://raw.githubusercontent.com/dmooney-cs/dev01/main/Toolbox-Launchers.zip",

    [switch]$Desktop,
    [switch]$Taskbar,
    [switch]$Silent,

    # toolbox convention
    [switch]$ExportOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Desktop -and -not $Taskbar) { $Desktop = $true }

# ------------------------- Paths -------------------------
$DeployRoot = "C:\Temp"
$CollectedInfoDir = Join-Path $DeployRoot "collected-info"
$LogFile = Join-Path $DeployRoot "CS-Toolbox-3xDesktopIcon.log"
$ExportJson = Join-Path $CollectedInfoDir "CS-Toolbox-3xDesktopIcon.json"

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

function Get-LoggedOnUserSid {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if (-not $cs.UserName) { throw "No interactive user detected (Win32_ComputerSystem.UserName is empty)." }
    $nt = New-Object System.Security.Principal.NTAccount($cs.UserName)
    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    [pscustomobject]@{ UserName = $cs.UserName; Sid = $sid }
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
    $val
}

function Get-FileHashSafe {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Resolve-GitHubDownloadUrl {
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Url)

    if ($Url -match '^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$') {
        return "https://raw.githubusercontent.com/$($Matches[1])/$($Matches[2])/$($Matches[3])/$($Matches[4])"
    }
    if ($Url -match '^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.+)$') {
        return "https://raw.githubusercontent.com/$($Matches[1])/$($Matches[2])/$($Matches[3])/$($Matches[4])"
    }
    return $Url
}

function Test-DownloadedIsHtml {
    param([Parameter(Mandatory)][string]$Path)
    $len = (Get-Item -LiteralPath $Path).Length
    if ($len -le 0) { return $true }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $take = [Math]::Min($bytes.Length, 4096)
    $head = [System.Text.Encoding]::UTF8.GetString($bytes, 0, $take)

    return (
        $head -match '<!DOCTYPE\s+html' -or
        $head -match '<html' -or
        ($head -match '<title>' -and $head -match 'GitHub') -or
        ($head -match 'github\.com' -and $head -match '<body')
    )
}

function Test-ZipOpens {
    param([Parameter(Mandatory)][string]$Path)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read, $false)
            try {
                $null = $zip.Entries.Count
                return $true
            } finally { $zip.Dispose() }
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Download-FileValidatedWithRetry {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [string]$Url,

        [Parameter(Mandatory)][string]$OutFile,

        [int]$MaxAttempts = 3
    )

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
                Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers @{ "Accept"="application/octet-stream" } -ErrorAction Stop
            }

            if (-not (Test-Path -LiteralPath $OutFile -PathType Leaf)) {
                throw "File not present after download"
            }

            if (Test-DownloadedIsHtml -Path $OutFile) {
                throw "Downloaded content appears to be HTML (not a ZIP)."
            }
            if (-not (Test-ZipOpens -Path $OutFile)) {
                throw "Downloaded file is not a valid ZIP (cannot open ZipArchive / central directory missing)."
            }

            Write-Log "Download validated as a real ZIP on attempt $attempt" "OK"
            return
        }
        catch {
            Write-Log "Attempt $attempt failed: $($_.Exception.Message)" "WARN"
            if (Test-Path -LiteralPath $OutFile) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }
            if ($attempt -lt $MaxAttempts) {
                $delay = 3 * $attempt
                Write-Log "Retrying in $delay seconds..." "INFO"
                Start-Sleep -Seconds $delay
            } else {
                throw "Download failed after $MaxAttempts attempts: $($_.Exception.Message)"
            }
        }
    }
}

function Get-AllFilesByExtension {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Extension  # like ".lnk" or ".ps1"
    )
    Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction Stop |
        Where-Object { $_.Extension -ieq $Extension }
}

function Copy-AllFiles {
    param(
        [Parameter(Mandatory)][System.IO.FileInfo[]]$Files,
        [Parameter(Mandatory)][string]$Destination
    )
    Ensure-Dir $Destination

    $copied = @()
    foreach ($f in $Files) {
        $dest = Join-Path $Destination $f.Name
        Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
        $copied += $dest
        Write-Log "Copied: $($f.FullName) -> $dest" "OK"
    }
    return $copied
}

# ------------------------- Summary -------------------------
$summary = [ordered]@{
    startedAt           = (Get-Date).ToString('o')
    zipUrlInput         = $ZipUrl
    zipUrlResolved      = $null
    downloadedZip       = $null
    downloadSha256      = $null
    extractTo           = $null
    interactiveUser     = $null
    userSid             = $null
    userDesktop         = $null
    userAppData         = $null
    taskbarPinnedFolder = $null
    lnkCountFound        = 0
    ps1CountFound        = 0
    copiedLnkToDesktop   = @()
    copiedLnkToTaskbar   = @()
    copiedPs1ToCTemp     = @()
    hashes              = [ordered]@{
        zipSha256         = $null
    }
    result              = "UNKNOWN"
}

Write-Log "Starting. ZipUrlInput='$ZipUrl' Desktop=$Desktop Taskbar=$Taskbar Silent=$Silent ExportOnly=$ExportOnly" "INFO"

try {
    $zipResolved = Resolve-GitHubDownloadUrl -Url $ZipUrl
    $summary.zipUrlResolved = $zipResolved
    if ($zipResolved -ne $ZipUrl) { Write-Log "Resolved GitHub URL -> $zipResolved" "OK" }

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

    $sysTemp = Join-Path $env:windir "Temp"
    Ensure-Dir $sysTemp

    $zipFile = Join-Path $sysTemp ("ToolboxPayload_" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_" + ([guid]::NewGuid().ToString("N").Substring(0,8)) + ".zip")

    Download-FileValidatedWithRetry -Url $zipResolved -OutFile $zipFile -MaxAttempts 3

    $summary.downloadedZip  = $zipFile
    $summary.downloadSha256 = Get-FileHashSafe -Path $zipFile
    $summary.hashes.zipSha256 = $summary.downloadSha256
    Write-Log "Downloaded ZIP SHA256: $($summary.downloadSha256)" "OK"

    $extractDir = Join-Path $sysTemp ("CS-Toolbox-Extract_" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_" + ([guid]::NewGuid().ToString("N").Substring(0,8)))
    Ensure-Dir $extractDir
    $summary.extractTo = $extractDir

    Write-Log "Extracting to: $extractDir" "INFO"
    Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDir -Force
    Write-Log "Extract complete." "OK"

    # Find ALL files by extension
    $lnkFiles = @(Get-AllFilesByExtension -Root $extractDir -Extension ".lnk")
    $ps1Files = @(Get-AllFilesByExtension -Root $extractDir -Extension ".ps1")

    $summary.lnkCountFound = $lnkFiles.Count
    $summary.ps1CountFound = $ps1Files.Count

    if ($lnkFiles.Count -eq 0) { throw "No .lnk files found in extracted zip." }
    if ($ps1Files.Count -eq 0) { throw "No .ps1 files found in extracted zip." }

    Write-Log "Found .lnk files: $($lnkFiles.Count)" "OK"
    Write-Log "Found .ps1 files: $($ps1Files.Count)" "OK"

    if (-not $Silent -and -not $ExportOnly) {
        Write-Host ""
        Write-Host "Planned actions:" -ForegroundColor Cyan
        if ($Desktop) { Write-Host " - Copy ALL .lnk to Desktop: $desktopPath" }
        if ($Taskbar) { Write-Host " - Copy ALL .lnk to Taskbar pinned folder: $taskbarDir" }
        Write-Host " - Copy ALL .ps1 to C:\Temp"
        Write-Host ""
        $ans = Read-Host "Proceed? (Y/N)"
        if ($ans -notin @('Y','y')) { throw "User cancelled." }
    }

    if ($ExportOnly) {
        $summary.result = "EXPORTONLY"
        $summary.finishedAt = (Get-Date).ToString('o')
        ($summary | ConvertTo-Json -Depth 12) | Set-Content -Path $ExportJson -Encoding UTF8
        if (-not $Silent) { Write-Host "Exported: $ExportJson" }
        exit 0
    }

    # Copy ALL PS1 -> C:\Temp
    $summary.copiedPs1ToCTemp = Copy-AllFiles -Files $ps1Files -Destination $DeployRoot

    # Copy ALL LNK -> Desktop and/or Taskbar
    if ($Desktop) {
        $summary.copiedLnkToDesktop = Copy-AllFiles -Files $lnkFiles -Destination $desktopPath
    }
    if ($Taskbar) {
        $summary.copiedLnkToTaskbar = Copy-AllFiles -Files $lnkFiles -Destination $taskbarDir
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
    ($summary | ConvertTo-Json -Depth 14) | Set-Content -Path $ExportJson -Encoding UTF8
    Write-Log "Summary exported to: $ExportJson" "INFO"
    Write-Log "Done. Result=$($summary.result)" "INFO"
}

exit 0
