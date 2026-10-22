# ============================================================================
# NAME: NTLMv1 Usage Detection - Eval
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   LookbackDays = 30
#   TopN         = 10
#   LogPath      = C:\MME\AutoLogs\NTLMv1_Usage_Detect.log
#   NtlmLogName  = Microsoft-Windows-NTLM/Operational
# OUTPUT TOKENS:
#   TRIGGER   | NTLMv1 evidence detected
#   TRIGGER   | NTLM Operational log unavailable or disabled
#   NO_ACTION | No NTLMv1 evidence detected in lookback period
#   ERROR     | Not emitted by this script
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\MME\AutoLogs\NTLMv1_Usage_Detect.log
# DESCRIPTION:
#   Evaluates Windows NTLM Operational event logs for evidence of NTLMv1
#   authentication activity within a configurable lookback period.
#
#   Searches event messages for NTLMv1/LM indicators and extracts
#   available process, client, IP address, user, and authentication
#   version information.
#
#   Groups detected activity by client, IP, process, user, event ID,
#   and NTLM version to identify the most frequent offenders.
#
#   Logs the top offender groups and up to five recent event samples.
#
#   Reports TRIGGER when NTLMv1 evidence is detected or when the NTLM
#   Operational log is unavailable or disabled.
#
#   Reports NO_ACTION when no matching evidence is found.
#   Always exits with code 0 for NinjaOne automation compatibility.
#
# SECURITY NOTES:
#   Runtime logs may contain usernames, hostnames, IP addresses,
#   process paths, and other environment-specific information.
#   Review generated logs before external distribution.
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

# ---------- CONFIG ----------
$LookbackDays = 30
$TopN = 10
$LogPath = "C:\MME\AutoLogs\NTLMv1_Usage_Detect.log"
$NtlmLogName = "Microsoft-Windows-NTLM/Operational"

# ---------- HELPERS ----------
function Ensure-Dir($path) {
    $dir = Split-Path -Path $path -Parent
    if (!(Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}
function Write-Log($msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $LogPath -Value "$ts | $msg" -Encoding UTF8
}

function Get-XmlDataMap($event) {
    # Converts Event XML <EventData><Data Name="...">value</Data> into a hashtable
    $map = @{}
    try {
        $xml = [xml]$event.ToXml()
        $nodes = $xml.Event.EventData.Data
        if ($nodes) {
            foreach ($n in $nodes) {
                $name = $n.Name
                $val  = ($n.'#text')
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                if ($null -eq $val) { $val = "" }
                $map[$name] = $val
            }
        }
    } catch {
        # ignore
    }
    return $map
}

function Pick-FirstPresent($map, $keys) {
    foreach ($k in $keys) {
        if ($map.ContainsKey($k) -and -not [string]::IsNullOrWhiteSpace($map[$k])) {
            return $map[$k].Trim()
        }
    }
    return ""
}

function BestEffortExtract($event) {
    # Tries XML fields first; falls back to message regex if needed.
    $m = Get-XmlDataMap $event

    $procName = Pick-FirstPresent $m @("ProcessName","Image","Application","CallerProcessName","ClientProcessName")
    $procId   = Pick-FirstPresent $m @("ProcessId","PID","ClientProcessId","CallerProcessId")
    $client   = Pick-FirstPresent $m @("ClientName","ClientMachineName","ClientComputerName","Workstation","WorkstationName","SourceWorkstation")
    $clientIP = Pick-FirstPresent $m @("ClientAddress","IpAddress","SourceAddress","ClientIP","RemoteAddress")
    $user     = Pick-FirstPresent $m @("UserName","AccountName","TargetUserName","SubjectUserName","User","Account")
    $domain   = Pick-FirstPresent $m @("DomainName","TargetDomainName","SubjectDomainName","Domain")
    $ntlmVer  = Pick-FirstPresent $m @("NtlmVersion","NTLMVersion","LmPackageName","AuthenticationPackageName")

    # Fallback to message parsing if key fields are blank
    $msg = $event.Message
    if ([string]::IsNullOrWhiteSpace($procName) -and $msg) {
        $rx = [regex]::Match($msg, '(?im)^\s*(Process\s*Name|Image)\s*:\s*(.+)$')
        if ($rx.Success) { $procName = $rx.Groups[2].Value.Trim() }
    }
    if ([string]::IsNullOrWhiteSpace($client) -and $msg) {
        $rx = [regex]::Match($msg, '(?im)^\s*(Client\s*Name|Workstation)\s*:\s*(.+)$')
        if ($rx.Success) { $client = $rx.Groups[2].Value.Trim() }
    }
    if ([string]::IsNullOrWhiteSpace($clientIP) -and $msg) {
        $rx = [regex]::Match($msg, '(?im)^\s*(Client\s*Address|IP\s*Address)\s*:\s*(.+)$')
        if ($rx.Success) { $clientIP = $rx.Groups[2].Value.Trim() }
    }
    if ([string]::IsNullOrWhiteSpace($user) -and $msg) {
        $rx = [regex]::Match($msg, '(?im)^\s*(User\s*Name|Account\s*Name|Target\s*User\s*Name)\s*:\s*(.+)$')
        if ($rx.Success) { $user = $rx.Groups[2].Value.Trim() }
    }

    if (-not [string]::IsNullOrWhiteSpace($domain) -and -not [string]::IsNullOrWhiteSpace($user)) {
        $user = "$domain\$user"
    }

    # Normalize empties
    if ([string]::IsNullOrWhiteSpace($procName)) { $procName = "(unknown_proc)" }
    if ([string]::IsNullOrWhiteSpace($procId))   { $procId   = "(unknown_pid)" }
    if ([string]::IsNullOrWhiteSpace($client))   { $client   = "(unknown_client)" }
    if ([string]::IsNullOrWhiteSpace($clientIP)) { $clientIP = "(unknown_ip)" }
    if ([string]::IsNullOrWhiteSpace($user))     { $user     = "(unknown_user)" }
    if ([string]::IsNullOrWhiteSpace($ntlmVer))  { $ntlmVer  = "(unknown_ver)" }

    return [pscustomobject]@{
        EventId     = $event.Id
        TimeCreated = $event.TimeCreated
        ProcName    = $procName
        ProcId      = $procId
        Client      = $client
        ClientIP    = $clientIP
        User        = $user
        NtlmVer     = $ntlmVer
    }
}

# ---------- MAIN ----------
Ensure-Dir $LogPath
"==== START NTLMv1 Usage Detection (Expanded) ====" | Out-File -FilePath $LogPath -Encoding UTF8
Write-Log "LookbackDays=$LookbackDays TopN=$TopN"
Write-Log "Checking log: $NtlmLogName"

$logInfo = Get-WinEvent -ListLog $NtlmLogName 2>$null
if (-not $logInfo) {
    Write-Log "ERROR: NTLM Operational log not found or not accessible."
    Write-Output "TRIGGER | UNKNOWN: NTLM Operational log not available"
    exit 0
}
if ($logInfo.IsEnabled -ne $true) {
    Write-Log "WARNING: NTLM Operational log is present but NOT enabled."
    Write-Output "TRIGGER | UNKNOWN: NTLM Operational log is disabled"
    exit 0
}

$startTime = (Get-Date).AddDays(-1 * $LookbackDays)

$events = Get-WinEvent -FilterHashtable @{ LogName = $NtlmLogName; StartTime = $startTime } -ErrorAction SilentlyContinue
if (-not $events) {
    Write-Log "No events returned in lookback window."
    Write-Output "NO_ACTION | No NTLM events in last $LookbackDays days"
    exit 0
}

# Identify likely NTLMv1 evidence (best-effort; message format varies)
$ntlmv1Events = $events | Where-Object { $_.Message -match '(?i)\bNTLM\s*V1\b|\bNTLMv1\b|\bLM\b' }
$cnt = ($ntlmv1Events | Measure-Object).Count
Write-Log "TotalEvents=$($events.Count); NTLMv1EvidenceEvents=$cnt"

if ($cnt -le 0) {
    Write-Output "NO_ACTION | No NTLMv1 evidence in last $LookbackDays days"
    exit 0
}

# Expand and summarize offenders
$expanded = foreach ($e in $ntlmv1Events) { BestEffortExtract $e }

# Group key: Client + IP + Proc + User + EventId (+ ver if present)
$top = $expanded |
    Group-Object -Property @{Expression={
        "$($_.Client)|$($_.ClientIP)|$($_.ProcName)|$($_.ProcId)|$($_.User)|EID=$($_.EventId)|$($_.NtlmVer)"
    }} |
    Sort-Object Count -Descending |
    Select-Object -First $TopN

Write-Log "---- TOP $TopN NTLMv1 offender groups (count | client | ip | proc | pid | user | eventid | ver) ----"
foreach ($g in $top) {
    $parts = $g.Name.Split('|')
    $client = $parts[0]; $ip=$parts[1]; $pname=$parts[2]; $pid=$parts[3]; $user=$parts[4]; $eid=$parts[5]; $ver=$parts[6]
    Write-Log ("{0} | {1} | {2} | {3} | {4} | {5} | {6} | {7}" -f $g.Count, $client, $ip, $pname, $pid, $user, $eid, $ver)
}

# Also log a few recent raw samples for quick eyeballing
Write-Log "---- Sample recent NTLMv1 events (up to 5) ----"
$expanded | Sort-Object TimeCreated -Descending | Select-Object -First 5 | ForEach-Object {
    Write-Log ("Sample | {0} | EID={1} | Client={2}({3}) | Proc={4}({5}) | User={6} | Ver={7}" -f `
        $_.TimeCreated, $_.EventId, $_.Client, $_.ClientIP, $_.ProcName, $_.ProcId, $_.User, $_.NtlmVer)
}

Write-Output "TRIGGER | NTLMv1 evidence seen (events=$cnt)"
exit 0