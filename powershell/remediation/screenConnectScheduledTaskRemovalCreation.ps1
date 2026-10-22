# ============================================================================
# NAME: Schedule ScreenConnect Removal
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / NinjaOne Remediation Automation
#
# VARIABLES:
#   Required: None
#
#   Optional:
#     screenConnectRemovalTaskName
#       Overrides the scheduled task name.
#
#     screenConnectRemovalPayloadPath
#       Overrides the transferred remediation payload path.
#
#   These values must match the paired ScreenConnect Presence Evaluation.
#
# OUTPUT TOKENS:
#   RESULT    | ScreenConnect removal task scheduled
#   NO_ACTION | Matching ScreenConnect removal task already scheduled
#   ERROR     | Scheduling failed or remediation payload is missing
#
#   Exit Code: Always 0
#
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
#
# FILE TRANSFERS:
#   Required: Yes
#   Payload: screenConnectRemoval.ps1
#
#   Default destination:
#     %ProgramData%\AutomationPlaybook\Payloads\screenConnectRemoval.ps1
#
# LOGGING PATH:
#   %ProgramData%\AutomationPlaybook\Logs\
#   ScreenConnect_Schedule_Remediation.log
#
# DESCRIPTION:
#   Schedules a transferred ScreenConnect removal payload to execute once
#   at the next 00:00 (midnight) in the endpoint's local time zone.
#
#   The scheduled task:
#     - Uses Windows PowerShell 5.1
#     - Executes as LOCAL SYSTEM
#     - Runs with highest privileges
#     - Uses a one-time trigger
#     - Can start when available
#     - Can run while on battery power
#
#   If an equivalent future task already exists for the intended midnight
#   execution, the script returns NO_ACTION.
#
#   If an existing task with the same name is stale or does not match the
#   required configuration, the script unregisters and replaces it.
#
#   Task registration is verified after creation.
#
#   The paired ScreenConnect Presence Evaluation recognizes a valid future
#   removal task and returns NO_ACTION to prevent repeated scheduling.
#
#   The scheduled task intentionally references ScreenConnect. The paired
#   removal payload is responsible for detecting and removing associated
#   scheduled tasks during its own cleanup.
#
#   This scheduler does not modify the transferred remediation payload.
#   It does not immediately uninstall ScreenConnect.
#
# REQUIREMENTS:
#   Windows endpoint with Task Scheduler PowerShell cmdlets.
#   Administrative privileges or LOCAL SYSTEM.
#   Transferred remediation payload must already exist.
#
# WARNING:
#   This script replaces an existing task with the configured task name
#   when that task does not match the expected configuration.
#   Confirm the task name does not conflict with unrelated scheduled tasks.
# ============================================================================


# =========================
# CONFIG
# =========================

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$PayloadPath = if (
    -not [string]::IsNullOrWhiteSpace(
        $env:screenConnectRemovalPayloadPath
    )
) {
    $env:screenConnectRemovalPayloadPath
}
else {
    Join-Path `
        $env:ProgramData `
        'AutomationPlaybook\Payloads\screenConnectRemoval.ps1'
}

$TaskName = if (
    -not [string]::IsNullOrWhiteSpace(
        $env:screenConnectRemovalTaskName
    )
) {
    $env:screenConnectRemovalTaskName
}
else {
    'AutomationPlaybook - ScreenConnect Removal'
}

$TaskPath = "\"

$TaskDescription = (
    "Runs the ScreenConnect removal remediation once at " +
    "00:00 local endpoint time."
)

$PowerShellPath = (
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
)

$LogRoot = Join-Path $env:ProgramData 'AutomationPlaybook\Logs'

$LogPath = Join-Path `
    $LogRoot `
    'ScreenConnect_Schedule_Remediation.log'


# =========================
# FUNCTIONS
# =========================

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $Line = "{0} [{1}] {2}" -f `
        (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),
        $Level,
        $Message

    try {
        if (-not (Test-Path -LiteralPath $LogRoot)) {
            New-Item `
                -Path $LogRoot `
                -ItemType Directory `
                -Force `
                -ErrorAction Stop | Out-Null
        }

        Add-Content `
            -LiteralPath $LogPath `
            -Value $Line `
            -Encoding UTF8 `
            -ErrorAction Stop
    }
    catch {
        Write-Host (
            "WARN | Failed writing to log file: " +
            $_.Exception.Message
        )
    }

    Write-Host $Line
}


function Get-Next0000 {
    $Now = Get-Date

    $RunAt = Get-Date `
        -Hour 0 `
        -Minute 0 `
        -Second 0

    if ($RunAt -le $Now) {
        $RunAt = $RunAt.AddDays(1)
    }

    return $RunAt
}


function Test-MatchingScheduledTask {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Task,

        [Parameter(Mandatory = $true)]
        [datetime]$ExpectedRunAt
    )

    try {
        $TaskInfo = Get-ScheduledTaskInfo `
            -TaskName $TaskName `
            -TaskPath $TaskPath `
            -ErrorAction Stop

        $NextRunMatches =
            ($TaskInfo.NextRunTime -gt (Get-Date)) -and
            (
                $TaskInfo.NextRunTime.ToString("yyyyMMddHHmm") -eq
                $ExpectedRunAt.ToString("yyyyMMddHHmm")
            )

        $ActionMatches = $false

        foreach ($Action in @($Task.Actions)) {
            if (
                ($Action.Execute -ieq $PowerShellPath) -and
                ($Action.Arguments -like "*$PayloadPath*")
            ) {
                $ActionMatches = $true
                break
            }
        }

        $PrincipalMatches =
            (
                ($Task.Principal.UserId -ieq "SYSTEM") -or
                (
                    $Task.Principal.UserId -ieq
                    "NT AUTHORITY\SYSTEM"
                )
            ) -and
            ($Task.Principal.RunLevel -eq "Highest")

        return (
            $NextRunMatches -and
            $ActionMatches -and
            $PrincipalMatches
        )
    }
    catch {
        Write-Log `
            -Level "WARN" `
            -Message (
                "Could not validate existing scheduled task: " +
                $_.Exception.Message
            )

        return $false
    }
}


# =========================
# MAIN
# =========================

$FinalToken = "ERROR"
$FinalMessage = "Unexpected scheduling termination before completion."

try {
    Write-Log "Starting ScreenConnect scheduled-remediation setup."

    # ---------------------------------------------------------
    # VERIFY TRANSFERRED REMEDIATION PAYLOAD
    # ---------------------------------------------------------

    if (-not (Test-Path -LiteralPath $PayloadPath -PathType Leaf)) {
        throw "Transferred remediation file not found: $PayloadPath"
    }

    # ---------------------------------------------------------
    # VERIFY WINDOWS POWERSHELL
    # ---------------------------------------------------------

    if (-not (Test-Path -LiteralPath $PowerShellPath -PathType Leaf)) {
        throw "Windows PowerShell executable not found: $PowerShellPath"
    }

    # ---------------------------------------------------------
    # VERIFY SCHEDULED TASK COMMANDS
    # ---------------------------------------------------------

    $RequiredCommands = @(
        "Get-ScheduledTask",
        "Get-ScheduledTaskInfo",
        "New-ScheduledTaskAction",
        "New-ScheduledTaskTrigger",
        "New-ScheduledTaskPrincipal",
        "New-ScheduledTaskSettingsSet",
        "Register-ScheduledTask",
        "Unregister-ScheduledTask"
    )

    foreach ($Command in $RequiredCommands) {
        if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
            throw "Required scheduled-task command is unavailable: $Command"
        }
    }

    # ---------------------------------------------------------
    # CALCULATE NEXT MIDNIGHT
    # ---------------------------------------------------------

    $RunAt = Get-Next0000

    Write-Log "Transferred payload verified: $PayloadPath"

    Write-Log (
        "Intended run time: " +
        $RunAt.ToString('yyyy-MM-dd HH:mm:ss') +
        " local endpoint time."
    )

    # ---------------------------------------------------------
    # CHECK FOR AN EXISTING SCHEDULED TASK
    # ---------------------------------------------------------

    $ExistingTask = Get-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -ErrorAction SilentlyContinue

    if ($null -ne $ExistingTask) {
        if (
            Test-MatchingScheduledTask `
                -Task $ExistingTask `
                -ExpectedRunAt $RunAt
        ) {
            $ExistingInfo = Get-ScheduledTaskInfo `
                -TaskName $TaskName `
                -TaskPath $TaskPath `
                -ErrorAction Stop

            $FinalToken = "NO_ACTION"

            $FinalMessage = (
                "Matching ScreenConnect removal task already scheduled" +
                " | Task=$TaskName" +
                " NextRun=$(" +
                    $ExistingInfo.NextRunTime.ToString(
                        'yyyy-MM-dd HH:mm:ss'
                    ) +
                ")"
            )
        }
        else {
            Write-Log (
                "Existing task is stale or does not match the " +
                "required configuration. Replacing task: $TaskName"
            )

            Unregister-ScheduledTask `
                -TaskName $TaskName `
                -TaskPath $TaskPath `
                -Confirm:$false `
                -ErrorAction Stop

            $ExistingTask = $null
        }
    }

    # ---------------------------------------------------------
    # REGISTER SCHEDULED REMEDIATION
    # ---------------------------------------------------------

    if ($FinalToken -ne "NO_ACTION") {
        $Arguments = (
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass " +
            "-File `"$PayloadPath`""
        )

        $Action = New-ScheduledTaskAction `
            -Execute $PowerShellPath `
            -Argument $Arguments

        $Trigger = New-ScheduledTaskTrigger `
            -Once `
            -At $RunAt

        $Principal = New-ScheduledTaskPrincipal `
            -UserId "SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest

        $Settings = New-ScheduledTaskSettingsSet `
            -StartWhenAvailable `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries

        Register-ScheduledTask `
            -TaskName $TaskName `
            -TaskPath $TaskPath `
            -Action $Action `
            -Trigger $Trigger `
            -Principal $Principal `
            -Settings $Settings `
            -Description $TaskDescription `
            -Force `
            -ErrorAction Stop | Out-Null

        # -----------------------------------------------------
        # VERIFY REGISTERED TASK
        # -----------------------------------------------------

        $VerifiedTask = Get-ScheduledTask `
            -TaskName $TaskName `
            -TaskPath $TaskPath `
            -ErrorAction Stop

        if (
            -not (
                Test-MatchingScheduledTask `
                    -Task $VerifiedTask `
                    -ExpectedRunAt $RunAt
            )
        ) {
            throw (
                "Scheduled task was registered but failed " +
                "post-registration validation."
            )
        }

        $VerifiedInfo = Get-ScheduledTaskInfo `
            -TaskName $TaskName `
            -TaskPath $TaskPath `
            -ErrorAction Stop

        $FinalToken = "RESULT"

        $FinalMessage = (
            "ScreenConnect removal task scheduled" +
            " | Task=$TaskName" +
            " NextRun=$(" +
                $VerifiedInfo.NextRunTime.ToString(
                    'yyyy-MM-dd HH:mm:ss'
                ) +
            ")" +
            " Payload=$PayloadPath"
        )
    }

    Write-Log "$FinalToken | $FinalMessage"
}
catch {
    $FinalToken = "ERROR"

    $FinalMessage = (
        "Failed to schedule ScreenConnect removal: " +
        $_.Exception.Message
    )

    Write-Log `
        -Level "ERROR" `
        -Message "$FinalToken | $FinalMessage"
}
finally {
    Write-Host "$FinalToken | $FinalMessage"
    exit 0
}
