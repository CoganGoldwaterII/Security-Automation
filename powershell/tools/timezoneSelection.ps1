# ============================================================================
# NAME: Set Windows Time Zone
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows endpoints / NinjaOne / Manually targeted devices
# VARIABLES:
#   timeZone (Dropdown, required): Exact Windows time zone ID selected in
#       NinjaOne, e.g., Pacific Standard Time or Alberta Standard Time.
#       NinjaOne calculated variable name MUST be: timeZone
# OUTPUT TOKENS:
#   RESULT    | Requested time zone applied and verified
#   NO_ACTION | Requested time zone already configured
#   ERROR     | Input missing/unsupported, query/apply/verification failure,
#             | or logging failure; output explains what failed
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   None
# LOGGING PATH:
#   C:\MME\AutoLogs\TimeZone_Remediation.log
# DESCRIPTION:
#   Accepts the exact Windows time zone ID supplied by the NinjaOne dropdown.
#   Checks that the selected ID is installed on this endpoint before making
#   any change. Applies only when necessary, then reads the setting back to
#   verify success. Does not substitute time zones or modify DST/automatic
#   time zone settings. Run as LOCAL SYSTEM or elevated administrator.
# ============================================================================

$ErrorActionPreference = 'Stop'
$LogDirectory = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDirectory 'TimeZone_Remediation.log'
$OutputToken = 'ERROR'
$OutputDetails = 'NotCompleted'
$Stage = 'Initialize'
$RequestedId = ''
$PreviousId = '<unknown>'

try {
    $Stage = 'PrepareLogging'
    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $Stage = 'ValidateInput'
    $RequestedId = ([string]$env:timeZone).Trim()
    if ([string]::IsNullOrWhiteSpace($RequestedId)) {
        throw "Missing or blank NinjaOne dropdown input. Expected calculated variable 'timeZone' with a Windows time zone ID, e.g. 'Pacific Standard Time'. No changes made."
    }

    $Stage = 'ReadCurrentTimeZone'
    $PreviousId = (Get-TimeZone -ErrorAction Stop).Id

    $Stage = 'ValidateInstalledTimeZone'
    $InstalledZones = @(Get-TimeZone -ListAvailable -ErrorAction Stop)
    $SelectedZone = $InstalledZones |
        Where-Object { $_.Id -ieq $RequestedId } |
        Select-Object -First 1

    if ($null -eq $SelectedZone) {
        throw "Selected ID '$RequestedId' is not available on this device (installed time zone IDs: $($InstalledZones.Count)). Current ID='$PreviousId'. No changes made. Check dropdown value against 'Get-TimeZone -ListAvailable | Select-Object -ExpandProperty Id' on this endpoint. New Canadian time zones may require current Windows updates; no automatic fallback is permitted."
    }

    if ($PreviousId -ieq $SelectedZone.Id) {
        $OutputToken = 'NO_ACTION'
        $OutputDetails = "AlreadyConfigured Requested='$RequestedId' Current='$PreviousId' Verified=True"
    }
    else {
        $Stage = 'ApplyTimeZone'
        Set-TimeZone -Id $SelectedZone.Id -ErrorAction Stop

        $Stage = 'VerifyTimeZone'
        [System.TimeZoneInfo]::ClearCachedData()
        $AppliedId = (Get-TimeZone -ErrorAction Stop).Id

        if ($AppliedId -ine $SelectedZone.Id) {
            throw "Read-back mismatch after Set-TimeZone. Requested='$($SelectedZone.Id)' Previous='$PreviousId' Actual='$AppliedId'. Check system policy or automatic time zone settings."
        }

        $OutputToken = 'RESULT'
        $OutputDetails = "Updated Requested='$RequestedId' Previous='$PreviousId' Current='$AppliedId' Verified=True"
    }
}
catch {
    $OutputToken = 'ERROR'
    $Reason = $_.Exception.Message -replace '[\r\n]+', ' '
    $OutputDetails = "Stage=$Stage Requested='$RequestedId' Previous='$PreviousId' Reason=$Reason"

    # A set operation can potentially take effect even if a later step fails.
    # Report the presently observable state rather than claiming no change.
    if ($Stage -eq 'ApplyTimeZone' -or $Stage -eq 'VerifyTimeZone') {
        try {
            [System.TimeZoneInfo]::ClearCachedData()
            $ObservedId = (Get-TimeZone -ErrorAction Stop).Id
            $OutputDetails += " ObservedNow='$ObservedId'"
        }
        catch {
            $OutputDetails += ' ObservedNow=<unavailable>'
        }
    }
}

try {
    $Timestamp = (Get-Date -Format 'ddMMMyyyy HH:mm:ss').ToUpperInvariant()
    Add-Content -LiteralPath $LogPath -Value "$Timestamp | $OutputToken | $OutputDetails" -Encoding UTF8 -ErrorAction Stop
}
catch {
    $PriorResult = "$OutputToken | $OutputDetails"
    $OutputToken = 'ERROR'
    $LogReason = $_.Exception.Message -replace '[\r\n]+', ' '
    $OutputDetails = "Stage=WriteLog Log='$LogPath' Reason=$LogReason PriorResult=[$PriorResult]"
}

Write-Output "$OutputToken | $OutputDetails"
exit 0
