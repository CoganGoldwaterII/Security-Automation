# ============================================================================
# NAME: Local User Account Cleanup
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne remediation automation
# VARIABLES:
#   RemoveProfiles = $true
#     Deletes associated profile directories after successful account removal.
#   DryRun = $false
#     When enabled, reports planned changes without performing them.
#   ProtectedRIDs = @(500, 501, 503, 504)
#     Built-in Administrator, Guest, DefaultAccount, WDAGUtilityAccount.
# OUTPUT TOKENS:
#   None; outputs diagnostic messages and remediation summaries.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None; console output only
# DESCRIPTION:
#   Identifies local Windows user accounts and disables the built-in Guest
#   account using RID 501, including when the account has been renamed.
#
#   Deletes local user accounts whose RIDs are not in the protected list.
#   Accounts without identifiable RIDs are excluded from deletion.
#
#   Optionally removes associated user profile directories after account
#   deletion. Supports a DryRun mode for reviewing planned operations.
#
#   Displays local accounts before and after remediation and reports
#   deleted accounts, failed deletions, and execution settings.
#
# WARNING:
#   Destructive remediation. All local accounts outside the protected RID
#   list are deletion candidates, including custom administrative accounts.
#   Profile directory deletion may permanently remove user data.
#   Review account inventory and test with DryRun enabled before deployment.
# ============================================================================

$ErrorActionPreference = "Stop"

$RemoveProfiles = $true
$DryRun         = $false

$ProtectedRIDs = @(500, 501, 503, 504)  # Built-in Admin, Guest, DefaultAccount, WDAGUtilityAccount

function Write-Section([string]$title) {
    Write-Host ""
    Write-Host "==== $title ===="
}

function Get-LocalRidFromSid([string]$sid) {
    if ([string]::IsNullOrWhiteSpace($sid)) { return $null }
    if ($sid -match '-(\d+)$') { return [int]$Matches[1] }
    return $null
}

function Get-LocalUsersSafe {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        return Get-LocalUser | Select-Object Name, Enabled, LastLogon, @{Name="SID";Expression={$_.SID.Value}}
    } else {
        $computer = $env:COMPUTERNAME
        $adsi = [ADSI]"WinNT://$computer"
        return $adsi.Children |
            Where-Object { $_.SchemaClassName -eq "User" } |
            ForEach-Object {
                [pscustomobject]@{ Name=$_.Name[0]; Enabled=$null; LastLogon=$null; SID=$null }
            } | Sort-Object Name
    }
}

function Remove-LocalUserSafe([string]$userName) {
    if (Get-Command Remove-LocalUser -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $userName
    } else {
        $computer = $env:COMPUTERNAME
        $user = [ADSI]"WinNT://$computer/$userName,user"
        $user.Parent.Delete("user", $userName)
    }
}

function Disable-LocalUserSafe([string]$userName) {
    if (Get-Command Disable-LocalUser -ErrorAction SilentlyContinue) {
        Disable-LocalUser -Name $userName
    } else {
        & net user $userName /active:no | Out-Null
    }
}

function Get-ProfilePathForUser([string]$userName) {
    try {
        $nt  = New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME", $userName)
        $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        if (Test-Path $key) {
            $p = (Get-ItemProperty $key -ErrorAction Stop).ProfileImagePath
            if ($p) { return $p }
        }
    } catch {}
    return $null
}

function Get-BuiltInGuestAccount {
    try {
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $u = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
            if ($u) { return [pscustomobject]@{ Name=$u.Name; SID=$u.SID.Value } }
        }

        $u2 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
              Where-Object { $_.SID -match '-501$' } |
              Select-Object -First 1
        if ($u2) { return [pscustomobject]@{ Name=$u2.Name; SID=$u2.SID } }
    } catch {}

    return $null
}

function Format-UserLine($u) {
    $enabled   = if ($null -ne $u.Enabled) { $u.Enabled } else { "?" }
    $lastLogon = if ($u.LastLogon) { $u.LastLogon } else { "" }
    $rid       = Get-LocalRidFromSid $u.SID
    $ridText   = if ($null -ne $rid) { "RID:$rid" } else { "RID:?" }
    "{0,-30} Enabled:{1,-6} {2,-10} {3}" -f $u.Name, $enabled, $ridText, $lastLogon
}

Write-Section "Local Users (BEFORE)"
$before = Get-LocalUsersSafe | Sort-Object Name
$before | ForEach-Object { Format-UserLine $_ }

Write-Section "Disable Built-in Guest (RID 501, renamed-safe)"
$guest = Get-BuiltInGuestAccount
if (-not $guest) {
    Write-Host "Built-in Guest not detected; nothing to disable."
} else {
    Write-Host "Built-in Guest detected as: '$($guest.Name)' (SID: $($guest.SID))"
    if ($DryRun) {
        Write-Host "DRY RUN: Would disable '$($guest.Name)'"
    } else {
        try {
            Disable-LocalUserSafe -userName $guest.Name
            Write-Host "Built-in Guest disabled (or already disabled)."
        } catch {
            Write-Host "WARNING: Failed to disable built-in Guest '$($guest.Name)': $($_.Exception.Message)"
        }
    }
}

# Delete all non-default locals (by RID). If SID/RID can't be determined, we skip deletion for safety.
$candidates = $before | Where-Object {
    $rid = Get-LocalRidFromSid $_.SID
    ($null -ne $rid) -and (-not ($ProtectedRIDs -contains $rid))
}

Write-Section "Deletion Plan"
Write-Host "Protected RIDs (kept): $($ProtectedRIDs -join ', ')"
if (-not $candidates -or $candidates.Count -eq 0) {
    Write-Host "No non-default local users detected to delete."
} else {
    Write-Host "Users to delete: $($candidates.Name -join ', ')"
}

$deleted = @()
$failed  = @()

foreach ($u in ($candidates | Sort-Object Name)) {
    $userName = $u.Name
    Write-Host ""
    Write-Host "Deleting local user: $userName"

    $profilePath = if ($RemoveProfiles) { Get-ProfilePathForUser $userName } else { $null }

    if ($DryRun) {
        Write-Host "DRY RUN: Would delete account '$userName'"
        if ($RemoveProfiles) { Write-Host "DRY RUN: Would delete profile folder '$profilePath'" }
        continue
    }

    try {
        Remove-LocalUserSafe -userName $userName
        $deleted += $userName
        Write-Host "Account deleted: $userName"
    } catch {
        $failed += $userName
        Write-Host "FAILED to delete account '$userName' : $($_.Exception.Message)"
        continue
    }

    if ($RemoveProfiles -and $profilePath -and (Test-Path $profilePath)) {
        try {
            Remove-Item -Path $profilePath -Recurse -Force -ErrorAction Stop
            Write-Host "Profile folder deleted: $profilePath"
        } catch {
            Write-Host "WARNING: Account deleted but failed to remove profile folder '$profilePath' : $($_.Exception.Message)"
        }
    }
}

Write-Section "Local Users (AFTER)"
$after = Get-LocalUsersSafe | Sort-Object Name
$after | ForEach-Object { Format-UserLine $_ }

Write-Section "Summary"
Write-Host "Deleted users: " + ($(if ($deleted.Count) { $deleted -join ", " } else { "None" }))
Write-Host "Failed deletions: " + ($(if ($failed.Count)  { $failed  -join ", " } else { "None" }))
Write-Host "DryRun: $DryRun"
Write-Host "RemoveProfiles: $RemoveProfiles"