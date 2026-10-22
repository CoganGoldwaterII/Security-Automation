# ============================================================================
# NAME: Browser and Native Password Manager Rollback
# AUTHORED BY: Cogan Goldwater
# TYPE: Rollback
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   RESULT    | One or more browser policy settings were removed
#   NO_ACTION | Targeted browser policy settings were already absent
#   ERROR     | One or more browser rollback operations failed
#
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\MME\AutoLogs\Browser_Password_Rollback.log
#
# DESCRIPTION:
#   Rolls back password-related browser policies applied by the
#   Browser and Native Password Manager remediation scripts.
#
#   Chrome / Edge / Brave:
#     - Removes "passwords" entries from SyncTypesListDisabled.
#     - Removes PasswordManagerEnabled.
#     - Preserves other SyncTypesListDisabled entries.
#
#   Firefox:
#     - Removes Sync\Passwords.
#     - Removes Sync\Locked.
#     - Removes PasswordManagerEnabled.
#
#   Verifies removal of each targeted registry value.
#   Processes each browser independently.
#
#   Removing these settings returns them to Not Configured,
#   allowing browser defaults or other management policies
#   to determine their effective behavior.
#
#   Does not force-enable browser password saving or sync.
#   Does not restore deleted browser passwords.
#   Does not restart browsers.
#
#   WARNING:
#   Removes matching registry policy values regardless of
#   whether they were originally created by our remediation.
#
#   Existing output uses bare RESULT / NO_ACTION / ERROR tokens
#   followed by per-browser details.
#   Script exits 0 upon normal completion.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "Browser_Password_Rollback.log"

# ============================================================
# Basic helpers
# ============================================================

function New-Dir {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

New-Dir $LogRoot

"Browser Password Rollback - $(Get-Date -Format s)" |
    Set-Content -Path $LogPath -Encoding UTF8

function Write-Log {
    param([string]$Message)

    "$(Get-Date -Format s) | $Message" |
        Add-Content -Path $LogPath -Encoding UTF8
}

# ============================================================
# Registry helpers
# ============================================================

function Test-RegistryValue {
    param(
        [string]$RegistryPath,
        [string]$ValueName
    )

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        return $false
    }

    try {
        $null = Get-ItemPropertyValue `
            -LiteralPath $RegistryPath `
            -Name $ValueName `
            -ErrorAction Stop

        return $true
    }
    catch {
        return $false
    }
}

function Remove-PolicyValueVerified {
    param(
        [string]$RegistryPath,
        [string]$ValueName
    )

    if (-not (Test-RegistryValue `
        -RegistryPath $RegistryPath `
        -ValueName $ValueName)) {

        return $false
    }

    Remove-ItemProperty `
        -LiteralPath $RegistryPath `
        -Name $ValueName `
        -Force `
        -ErrorAction Stop

    if (Test-RegistryValue `
        -RegistryPath $RegistryPath `
        -ValueName $ValueName) {

        throw "Rollback verification failed: $RegistryPath\$ValueName still exists"
    }

    return $true
}

function Get-RegistryListValueNamesForString {
    param(
        [string]$RegistryPath,
        [string]$DesiredValue
    )

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        return @()
    }

    $Properties = Get-ItemProperty `
        -LiteralPath $RegistryPath `
        -ErrorAction SilentlyContinue

    if (-not $Properties) {
        return @()
    }

    $MatchedValueNames = New-Object System.Collections.Generic.List[string]

    foreach ($Property in $Properties.PSObject.Properties) {
        if ($Property.Name -like "PS*") {
            continue
        }

        if (
            $Property.Name -match "^\d+$" -and
            [string]$Property.Value -ceq $DesiredValue
        ) {
            $MatchedValueNames.Add([string]$Property.Name)
        }
    }

    return @($MatchedValueNames)
}

function Remove-RegistryListStringVerified {
    param(
        [string]$RegistryPath,
        [string]$DesiredValue
    )

    $ValueNames = @(
        Get-RegistryListValueNamesForString `
            -RegistryPath $RegistryPath `
            -DesiredValue $DesiredValue
    )

    if ($ValueNames.Count -eq 0) {
        return @()
    }

    foreach ($ValueName in $ValueNames) {
        Remove-ItemProperty `
            -LiteralPath $RegistryPath `
            -Name $ValueName `
            -Force `
            -ErrorAction Stop
    }

    $Remaining = @(
        Get-RegistryListValueNamesForString `
            -RegistryPath $RegistryPath `
            -DesiredValue $DesiredValue
    )

    if ($Remaining.Count -gt 0) {
        throw "Rollback verification failed: $RegistryPath still contains '$DesiredValue'"
    }

    return @($ValueNames)
}

# ============================================================
# Result helpers
# ============================================================

function New-RollbackResult {
    param(
        [string]$Browser,
        [bool]$Changed,
        [string[]]$Removed
    )

    [PSCustomObject]@{
        Browser      = $Browser
        Status       = "OK"
        Changed      = $Changed
        Removed      = @($Removed)
        ErrorMessage = $null
    }
}

function New-RollbackErrorResult {
    param(
        [string]$Browser,
        [string]$Message
    )

    [PSCustomObject]@{
        Browser      = $Browser
        Status       = "ERROR"
        Changed      = $false
        Removed      = @()
        ErrorMessage = $Message
    }
}

function Format-RollbackResult {
    param([object]$Result)

    if ($Result.Status -eq "ERROR") {
        return "$($Result.Browser): ERROR | $($Result.ErrorMessage)"
    }

    if ($Result.Changed) {
        return "$($Result.Browser): Rolled Back | Removed=$($Result.Removed -join ', ')"
    }

    return "$($Result.Browser): No Change | Password-related rollback policies already absent"
}

# ============================================================
# Chromium rollback
# ============================================================

function Invoke-ChromiumRollback {
    param(
        [string]$Browser,
        [string]$PolicyPath
    )

    $Removed = New-Object System.Collections.Generic.List[string]

    $PasswordSyncListPath = Join-Path $PolicyPath "SyncTypesListDisabled"

    $RemovedSyncValueNames = @(
        Remove-RegistryListStringVerified `
            -RegistryPath $PasswordSyncListPath `
            -DesiredValue "passwords"
    )

    foreach ($ValueName in $RemovedSyncValueNames) {
        $Removed.Add("SyncTypesListDisabled\$ValueName=passwords")
        Write-Log "$Browser | Removed password sync list entry | $PasswordSyncListPath\$ValueName=passwords"
    }

    if ($RemovedSyncValueNames.Count -eq 0) {
        Write-Log "$Browser | Password sync list entry already absent | $PasswordSyncListPath | passwords"
    }

    if (Remove-PolicyValueVerified `
        -RegistryPath $PolicyPath `
        -ValueName "PasswordManagerEnabled") {

        $Removed.Add("PasswordManagerEnabled")
        Write-Log "$Browser | Removed policy value | $PolicyPath\PasswordManagerEnabled"
    }
    else {
        Write-Log "$Browser | Policy value already absent | $PolicyPath\PasswordManagerEnabled"
    }

    return New-RollbackResult `
        -Browser $Browser `
        -Changed ($Removed.Count -gt 0) `
        -Removed @($Removed)
}

# ============================================================
# Firefox rollback
# ============================================================

function Invoke-FirefoxRollback {
    $Browser = "Firefox"
    $PolicyPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox"
    $SyncPolicyPath = Join-Path $PolicyPath "Sync"

    $Removed = New-Object System.Collections.Generic.List[string]

    foreach ($SyncValueName in @("Passwords", "Locked")) {
        if (Remove-PolicyValueVerified `
            -RegistryPath $SyncPolicyPath `
            -ValueName $SyncValueName) {

            $Removed.Add("Sync\$SyncValueName")
            Write-Log "$Browser | Removed policy value | $SyncPolicyPath\$SyncValueName"
        }
        else {
            Write-Log "$Browser | Policy value already absent | $SyncPolicyPath\$SyncValueName"
        }
    }

    if (Remove-PolicyValueVerified `
        -RegistryPath $PolicyPath `
        -ValueName "PasswordManagerEnabled") {

        $Removed.Add("PasswordManagerEnabled")
        Write-Log "$Browser | Removed policy value | $PolicyPath\PasswordManagerEnabled"
    }
    else {
        Write-Log "$Browser | Policy value already absent | $PolicyPath\PasswordManagerEnabled"
    }

    return New-RollbackResult `
        -Browser $Browser `
        -Changed ($Removed.Count -gt 0) `
        -Removed @($Removed)
}

# ============================================================
# Main
# ============================================================

$Results = New-Object System.Collections.Generic.List[object]

try {
    $Results.Add(
        (Invoke-ChromiumRollback `
            -Browser "Chrome" `
            -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome")
    )
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Chrome | ERROR | $Message"
    $Results.Add((New-RollbackErrorResult -Browser "Chrome" -Message $Message))
}

try {
    $Results.Add(
        (Invoke-ChromiumRollback `
            -Browser "Edge" `
            -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge")
    )
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Edge | ERROR | $Message"
    $Results.Add((New-RollbackErrorResult -Browser "Edge" -Message $Message))
}

try {
    $Results.Add(
        (Invoke-ChromiumRollback `
            -Browser "Brave" `
            -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave")
    )
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Brave | ERROR | $Message"
    $Results.Add((New-RollbackErrorResult -Browser "Brave" -Message $Message))
}

try {
    $Results.Add((Invoke-FirefoxRollback))
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Firefox | ERROR | $Message"
    $Results.Add((New-RollbackErrorResult -Browser "Firefox" -Message $Message))
}

# ============================================================
# Final output token
# ============================================================

$AnyErrors = @(
    $Results |
        Where-Object { $_.Status -eq "ERROR" }
).Count -gt 0

$AnyChanges = @(
    $Results |
        Where-Object {
            $_.Status -eq "OK" -and
            $_.Changed -eq $true
        }
).Count -gt 0

if ($AnyErrors) {
    $Token = "ERROR"
}
elseif ($AnyChanges) {
    $Token = "RESULT"
}
else {
    $Token = "NO_ACTION"
}

$OutputLines = New-Object System.Collections.Generic.List[string]
$OutputLines.Add($Token)

foreach ($Result in $Results) {
    $OutputLines.Add((Format-RollbackResult -Result $Result))
}

$OutputLines.Add("NOTE: Browser password/sync policies were returned to Not Configured. Deleted browser passwords cannot be restored by rollback.")

Write-Output ($OutputLines -join "`r`n")

exit 0