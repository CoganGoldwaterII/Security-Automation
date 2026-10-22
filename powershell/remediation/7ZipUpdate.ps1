# ============================================================================
# NAME: 7-Zip Update + Legacy Version Cleanup - Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   LogDir        = C:\MME\AutoLogs
#   DownloadPage  = https://www.7-zip.org/download.html
#   DownloadDir   = C:\MME\AutoLogs
#   LedgerLineCap = 60
# OUTPUT TOKENS:
#   RESULT    | UPDATED 7-Zip
#   RESULT    | ERROR (update or remediation failure)
#   NO_ACTION | 7-Zip absent or already current
# CUSTOM FIELDS:
#   Reads: remediationSummary (Multi-line)
#   Writes:
#     lastRemediationDate (Text)
#     remediationSummary (Multi-line)
# FILE TRANSFERS:
#   Required: No
#   Files: None
#   MSI downloaded directly from 7-Zip.
# LOGGING PATH:
#   C:\MME\AutoLogs\7Zip_Remediation.log
# DESCRIPTION:
#   Retrieves the latest 7-Zip x64 MSI from the official download page.
#   Detects installed versions through Windows uninstall registry entries.
#   Attempts removal of outdated versions before installing the latest MSI.
#   Verifies the installed version after remediation.
#   Updates NinjaOne remediation fields with a line-capped ledger.
#   Compatible with Windows PowerShell 5.1. Always exits 0.
# ============================================================================

$ErrorActionPreference = "Stop"

$LogDir  = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogDir "7Zip_Remediation.log"
$DownloadPage = "https://www.7-zip.org/download.html"
$DownloadDir  = "C:\MME\AutoLogs"

# Line cap only (new global standard)
$LedgerLineCap = 60

# ---------------- Helpers ----------------

function Ensure-Dir([string]$p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Log([string]$m) {
    Ensure-Dir $LogDir
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [7Zip] $m"
}

function Resolve-NinjaCli {
    $candidates = @(
        "C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe",
        "$env:ProgramFiles\NinjaRMMAgent\ninjarmm-cli.exe",
        "$env:ProgramFiles(x86)\NinjaRMMAgent\ninjarmm-cli.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Set-NinjaField($name, $value) {
    try {
        if (Get-Command ninja-property-set -ErrorAction SilentlyContinue) {
            ninja-property-set $name "$value" | Out-Null
            Log "Ninja field set via ninja-property-set: $name"
            return $true
        }

        $cli = Resolve-NinjaCli
        if ($cli) {
            & $cli set $name "$value" | Out-Null
            Log "Ninja field set via ninjarmm-cli: $name"
            return $true
        }

        Log "WARN: No Ninja setter available."
    } catch {
        Log "WARN: Field set failed: $($_.Exception.Message)"
    }
    return $false
}

function Get-NinjaField($name) {
    try {
        if (Get-Command ninja-property-get -ErrorAction SilentlyContinue) {
            return (ninja-property-get $name 2>$null | Out-String).Trim()
        }

        $cli = Resolve-NinjaCli
        if ($cli) {
            return ((& $cli get $name 2>$null) | Out-String).Trim()
        }
    } catch {}
    return $null
}

function Append-RemediationSummary([string]$entry) {
    try {
        $existing = Get-NinjaField "remediationSummary"
        if ($null -eq $existing) { $existing = "" }

        $existing = ($existing -replace "`r`n", "`n") -replace "`r", "`n"
        $entry = $entry.Trim()

        $lines = @()
        if (-not [string]::IsNullOrWhiteSpace($existing)) {
            $lines = $existing -split "`n" |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -ne "" }
        }

        if ($lines.Count -gt 0 -and $lines[-1] -eq $entry) {
            Log "Ledger de-dupe: identical last entry skipped."
            return
        }

        $lines += $entry

        if ($lines.Count -gt $LedgerLineCap) {
            $lines = $lines[-$LedgerLineCap..-1]
        }

        $combined = ($lines -join "`r`n").Trim()
        Set-NinjaField "remediationSummary" $combined | Out-Null
        Log "remediationSummary updated."
    } catch {
        Log "WARN: remediationSummary append failed."
    }
}

function Finish([string]$out, [string]$ledgerLine = $null) {
    try {
        $iso = (Get-Date).ToString("yyyy-MM-dd")
        Set-NinjaField "lastRemediationDate" $iso | Out-Null

        if ($ledgerLine) {
            Append-RemediationSummary $ledgerLine
        }
    } catch {
        Log "WARN: Ledger update failed."
    }

    Log "FINAL: $out"
    Write-Output $out
    exit 0
}

# ---------------- Version helpers ----------------

function Normalize-Version([string]$raw) {
    if (-not $raw) { return $null }
    $m = [regex]::Match($raw.Trim(), '(\d+)\.(\d+)')
    if (!$m.Success) { return $null }
    return ("{0}.{1:D2}" -f [int]$m.Groups[1].Value, [int]$m.Groups[2].Value)
}

function Get-Latest7Zip {
    Log "Fetching latest 7-Zip"
    $html = Invoke-WebRequest -Uri $DownloadPage -UseBasicParsing -TimeoutSec 30
    $c = $html.Content

    $m = [regex]::Match($c, 'href="(?<href>[^"]*7z(?<ver>\d{4})-x64\.msi)"', 'IgnoreCase')
    if (!$m.Success) { throw "Latest MSI not found." }

    $href = $m.Groups['href'].Value
    $digits = $m.Groups['ver'].Value

    $maj = [int]$digits.Substring(0,2)
    $min = [int]$digits.Substring(2,2)
    $ver = ("{0}.{1:D2}" -f $maj, $min)

    $url = if ($href -match '^https?://') { $href }
           else { "https://www.7-zip.org/" + ($href.TrimStart('/')) }

    return [pscustomobject]@{ Version = $ver; Url = $url }
}

function Get-7ZipEntries {
    $out = @()
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match '^7-Zip\b' } |
            ForEach-Object {
                $out += [pscustomobject]@{
                    DisplayName = $_.DisplayName
                    DisplayVersionRaw = $_.DisplayVersion
                    DisplayVersion = Normalize-Version $_.DisplayVersion
                    QuietUninstallString = $_.QuietUninstallString
                    UninstallString = $_.UninstallString
                }
            }
    }
    return $out
}

function Run-UninstallCmd([string]$cmd) {
    if (-not $cmd) { return }
    Log "Uninstall: $cmd"
    Start-Process cmd.exe "/c $cmd" -Wait
}

# ---------------- Main ----------------

try {
    Log "========== START =========="

    $latestInfo = Get-Latest7Zip
    $latest = $latestInfo.Version

    $entries = Get-7ZipEntries
    if (-not $entries) {
        Finish "NO_ACTION | 7-Zip not installed"
    }

    $highest = ($entries | Where DisplayVersion |
        ForEach DisplayVersion |
        Sort-Object { [version]$_ } -Descending |
        Select-Object -First 1)

    Log "Installed=$highest Latest=$latest"

    if ([version]$highest -ge [version]$latest) {
        Finish "NO_ACTION | 7-Zip already current ($highest)"
    }

    foreach ($e in $entries) {
        if ([version]$e.DisplayVersion -lt [version]$latest) {
            $cmd = $e.QuietUninstallString
            if (-not $cmd) { $cmd = $e.UninstallString }
            Run-UninstallCmd $cmd
        }
    }

    Ensure-Dir $DownloadDir
    $msiPath = Join-Path $DownloadDir (Split-Path $latestInfo.Url -Leaf)

    Invoke-WebRequest $latestInfo.Url -OutFile $msiPath -UseBasicParsing

    Start-Process msiexec.exe "/i `"$msiPath`" /qn /norestart" -Wait

    $entries2 = Get-7ZipEntries
    $highest2 = ($entries2 | Where DisplayVersion |
        ForEach DisplayVersion |
        Sort-Object { [version]$_ } -Descending |
        Select -First 1)

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if ($highest2 -and ([version]$highest2 -ge [version]$latest)) {
        Finish "RESULT | UPDATED 7-Zip ($highest -> $latest)" `
               "$ts - 7-Zip UPDATED ($highest -> $latest)"
    }

    Finish "RESULT | ERROR (Update did not confirm)" `
           "$ts - 7-Zip ERROR (Update did not confirm)"

}
catch {
    Log "ERROR: $($_.Exception.Message)"
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Finish "RESULT | ERROR ($($_.Exception.Message))" `
           "$ts - 7-Zip ERROR ($($_.Exception.Message))"
}