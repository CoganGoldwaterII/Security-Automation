# ============================================================================
# NAME: Local User Account Cleanup - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   ProtectedRIDs = @(500, 501, 503, 504)
#     Built-in Administrator, Guest, DefaultAccount, WDAGUtilityAccount
# OUTPUT TOKENS:
#   TRIGGER   | Non-default local users detected, built-in Guest enabled,
#             | Guest state unknown/not detectable, or evaluation error
#   NO_ACTION | No non-default users detected and built-in Guest disabled
#   ERROR     | Not emitted; evaluation exceptions produce TRIGGER
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None; console output only
# DESCRIPTION:
#   Evaluates local Windows user accounts using their relative identifiers
#   (RIDs), protecting built-in accounts 500, 501, 503, and 504.
#
#   Detects non-default local users and checks whether the built-in Guest
#   account (RID 501) is disabled, including when Guest has been renamed.
#
#   Triggers remediation if non-default users are detected, Guest is enabled,
#   Guest status cannot be determined, or an evaluation exception occurs.
#
#   Accounts without readable SIDs are not classified as non-default.
#   Always exits with code 0 for NinjaOne automation compatibility.
# ============================================================================

$ErrorActionPreference = "Stop"

$ProtectedRIDs = @(500, 501, 503, 504)  # Built-in Admin, Guest, DefaultAccount, WDAGUtilityAccount

function Get-LocalRidFromSid([string]$sid) {
    if ([string]::IsNullOrWhiteSpace($sid)) { return $null }
    if ($sid -match '-(\d+)$') { return [int]$Matches[1] }
    return $null
}

function Get-LocalUsersSafe {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        return Get-LocalUser | Select-Object Name, Enabled, @{Name="SID";Expression={$_.SID.Value}}
    } else {
        $computer = $env:COMPUTERNAME
        $adsi = [ADSI]"WinNT://$computer"
        return $adsi.Children |
            Where-Object { $_.SchemaClassName -eq "User" } |
            ForEach-Object {
                [pscustomobject]@{ Name = $_.Name[0]; Enabled = $null; SID = $null }
            } | Sort-Object Name
    }
}

function Get-BuiltInGuestAccount {
    # Detect built-in Guest via RID 501 (SID ends with -501), even if renamed
    try {
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $u = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
            if ($u) {
                return [pscustomobject]@{ Name = $u.Name; Enabled = $u.Enabled; SID = $u.SID.Value; RID = 501 }
            }
        }

        $u2 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
              Where-Object { $_.SID -match '-501$' } |
              Select-Object -First 1

        if ($u2) {
            # Win32_UserAccount often exposes Disabled; derive Enabled if present
            $enabled = $null
            if ($u2.PSObject.Properties.Name -contains "Disabled") { $enabled = -not [bool]$u2.Disabled }
            return [pscustomobject]@{ Name = $u2.Name; Enabled = $enabled; SID = $u2.SID; RID = 501 }
        }
    } catch {}

    return $null
}

try {
    $reasons = @()

    $users = Get-LocalUsersSafe

    # Non-default local users = any user with RID not in protected list (when we can compute RID)
    $nonDefaultUsers = $users | Where-Object {
        $rid = Get-LocalRidFromSid $_.SID
        ($null -ne $rid) -and (-not ($ProtectedRIDs -contains $rid))
    }

    if ($nonDefaultUsers.Count -gt 0) {
        $reasons += "Non-default local users present: $($nonDefaultUsers.Name -join ', ')"
    }

    # Built-in Guest status (RID 501) — if enabled OR unknown OR not detectable => trigger (fail safe)
    $guest = Get-BuiltInGuestAccount
    if (-not $guest) {
        $reasons += "Built-in Guest (RID 501) not detectable"
    } else {
        if ($guest.Enabled -eq $true) {
            $reasons += "Built-in Guest (RID 501) is enabled (name: $($guest.Name))"
        } elseif ($null -eq $guest.Enabled) {
            $reasons += "Built-in Guest (RID 501) enabled state unknown (name: $($guest.Name))"
        }
    }

    if ($reasons.Count -gt 0) {
        Write-Output ("TRIGGER | " + ($reasons -join " | "))
        exit 0
    }

    Write-Output "NO_ACTION | Healthy"
    exit 0
}
catch {
    # Fail-safe: if detection script errors, request remediation rather than reporting healthy
    Write-Output ("TRIGGER | Detection script error: " + $_.Exception.Message)
    exit 0
}