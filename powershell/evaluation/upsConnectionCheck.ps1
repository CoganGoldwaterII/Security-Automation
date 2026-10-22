# ============================================================================
# NAME: APC UPS Connectivity Check - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   GraceMinutes  = 10
#   LookbackHours = 24
#   EventSource   = APCPBEAgent
#   LogNames      = Application, System
#   BadEventIds   = 3004, 3005, 3006, 3000
#   RecoveryEventIds = 1020, 1002
# OUTPUT TOKENS:
#   TRIGGER   | UPS communication loss exceeds grace period
#   NO_ACTION | No unresolved loss, within grace period, or evaluation error
#   ERROR     | Not emitted by the current implementation
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\APC_UPS_Comm_State_Eval.log
# DESCRIPTION:
#   Evaluates APC UPS communication status using Windows Event Logs.
#   Searches Application and System logs for APC PowerChute Business
#   Edition Agent communication loss and recovery events.
#
#   Identifies communication loss events occurring after the most
#   recent recovery event within the configured lookback window.
#   Applies a 10-minute grace period before triggering remediation.
#
#   Returns NO_ACTION when no communication loss is detected,
#   communication has recovered, or the loss remains within grace.
#
#   Evaluation errors are logged and reported as NO_ACTION.
#   Produces one final NinjaOne output token and always exits 0.
# ============================================================================

# -------------------------------------
# Variables
# -------------------------------------
$GraceMinutes  = 10
$LookbackHours = 24
$EventSource   = "APCPBEAgent"
$LogNames      = @("Application", "System")

$BadEventIds = @(
    3004, # Comm Lost While On Battery
    3005, # Communication Not Established
    3006, # Battery Communication Lost
    3000  # Lost Communication With UPS
)

$RecoveryEventIds = @(
    1020, # Battery Communication Established
    1002  # Communications Established
)

$AllEventIds = $BadEventIds + $RecoveryEventIds

# -------------------------------------
# Logging
# -------------------------------------
$LogPath = "C:\MME\AutoLogs"
$LogFile = Join-Path $LogPath "APC_UPS_Comm_State_Eval.log"

if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$Timestamp | $Message"
}

function Finish-Check {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("TRIGGER", "NO_ACTION")]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Log "$Token | $Message"
    Write-Output "$Token | $Message"
    exit 0
}

# -------------------------------------
# Main
# -------------------------------------
try {
    Write-Log "Starting APC UPS communication state evaluation."
    Write-Log "Source: $EventSource | LookbackHours: $LookbackHours | GraceMinutes: $GraceMinutes"

    $Now = Get-Date
    $StartTime = $Now.AddHours(-$LookbackHours)
    $Events = @()

    foreach ($LogName in $LogNames) {
        try {
            $LogEvents = Get-WinEvent -FilterHashtable @{
                LogName      = $LogName
                ProviderName = $EventSource
                Id           = $AllEventIds
                StartTime    = $StartTime
            } -ErrorAction Stop

            if ($LogEvents) {
                $Events += $LogEvents
                Write-Log "Found $($LogEvents.Count) matching event(s) in '$LogName'."
            }
        }
        catch {
            Write-Log "No matching events found or unable to query log '$LogName'. Detail: $($_.Exception.Message)"
        }
    }

    if (-not $Events) {
        Finish-Check -Token "NO_ACTION" -Message "No APC UPS communication state events found within the last $LookbackHours hours."
    }

    $Events = $Events | Sort-Object TimeCreated

    $BadEvents = $Events | Where-Object {
        $BadEventIds -contains $_.Id
    }

    $RecoveryEvents = $Events | Where-Object {
        $RecoveryEventIds -contains $_.Id
    }

    if (-not $BadEvents) {
        Finish-Check -Token "NO_ACTION" -Message "No APC UPS communication loss events found within the last $LookbackHours hours."
    }

    $LatestRecoveryEvent = $RecoveryEvents |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 1

    if ($LatestRecoveryEvent) {
        Write-Log "Latest recovery event: ID $($LatestRecoveryEvent.Id) at $($LatestRecoveryEvent.TimeCreated)."

        $UnresolvedBadEvents = $BadEvents | Where-Object {
            $_.TimeCreated -gt $LatestRecoveryEvent.TimeCreated
        }
    }
    else {
        Write-Log "No recovery event found within lookback window. Treating all bad events in lookback as unresolved."
        $UnresolvedBadEvents = $BadEvents
    }

    if (-not $UnresolvedBadEvents) {
        Finish-Check -Token "NO_ACTION" -Message "APC UPS communication is currently recovered. No bad event exists after the latest recovery event."
    }

    $OldestUnresolvedBadEvent = $UnresolvedBadEvents |
        Sort-Object TimeCreated |
        Select-Object -First 1

    $NewestUnresolvedBadEvent = $UnresolvedBadEvents |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 1

    $BadDurationMinutes = [math]::Round(($Now - $OldestUnresolvedBadEvent.TimeCreated).TotalMinutes, 2)

    Write-Log "Oldest unresolved bad event: ID $($OldestUnresolvedBadEvent.Id) at $($OldestUnresolvedBadEvent.TimeCreated)."
    Write-Log "Newest unresolved bad event: ID $($NewestUnresolvedBadEvent.Id) at $($NewestUnresolvedBadEvent.TimeCreated)."
    Write-Log "Unresolved bad duration: $BadDurationMinutes minute(s)."

    if ($BadDurationMinutes -lt $GraceMinutes) {
        Finish-Check -Token "NO_ACTION" -Message "APC UPS communication loss is still within grace period. Oldest unresolved bad event ID $($OldestUnresolvedBadEvent.Id) occurred at $($OldestUnresolvedBadEvent.TimeCreated). Duration: $BadDurationMinutes minutes. Grace period: $GraceMinutes minutes."
    }

    Finish-Check -Token "TRIGGER" -Message "APC UPS communication appears unresolved. Oldest unresolved bad event ID $($OldestUnresolvedBadEvent.Id) occurred at $($OldestUnresolvedBadEvent.TimeCreated). Newest unresolved bad event ID $($NewestUnresolvedBadEvent.Id) occurred at $($NewestUnresolvedBadEvent.TimeCreated). No newer recovery event found."
}
catch {
    Write-Log "Unhandled script error: $($_.Exception.Message)"
    Finish-Check -Token "NO_ACTION" -Message "Evaluation error occurred. See log: $LogFile"
}