# ============================================================================
# NAME: AUTOMATION - Video Port Inventory
# AUTHORED BY:
# TYPE: Standalone inventory / custom-field reporting
# SCOPE: Windows / NinjaOne SYSTEM / Local endpoint
# VARIABLES: None
# OUTPUT TOKENS: RESULT | ERROR
# CUSTOM FIELDS: videoPorts (Text; read/write)
# LOGGING PATH: C:\MME\AutoLogs\Video_Port_Inventory.log
# DESCRIPTION: Count active Windows display connections by reported output
#              technology. Overwrite and read back videoPorts. No physical
#              connector inventory, monitor details, vendor lookups, downloads,
#              external API calls, endpoint configuration or ledger changes.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ScriptBuild = '2026.11.25-v4'
$LogFile = 'C:\MME\AutoLogs\Video_Port_Inventory.log'
$Field = 'videoPorts'
$Final = 'ERROR | Inventory did not complete'
$script:LogFailed = $false

function Safe-Text {
    param([AllowNull()][object]$Value)
    return (([string]$Value -replace '[\r\n|]+', ' ') -replace '\s{2,}', ' ').Trim()
}

function Write-Log {
    param([string]$Level, [string]$Message)
    try {
        Add-Content -LiteralPath $LogFile -Encoding UTF8 -Value (
            '{0} | {1} | {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, (Safe-Text $Message)
        ) -ErrorAction Stop
    } catch {
        $script:LogFailed = $true
    }
}

function Get-DisplayType {
    param([uint32]$Code)
    switch ($Code) {
        0 { 'VGA' }
        1 { 'S-Video' }
        2 { 'Composite' }
        3 { 'Component' }
        4 { 'DVI' }
        5 { 'HDMI' }
        6 { 'Internal' }
        8 { 'D-JPN' }
        9 { 'SDI' }
        10 { 'DP' }
        11 { 'Internal' }
        12 { 'UDI' }
        13 { 'Internal' }
        14 { 'TV dongle' }
        15 { 'Wireless' }
        16 { 'Indirect wired' }
        17 { 'Virtual' }
        18 { 'DP USB tunnel' }
        2147483648 { 'Internal' }
        default { 'Other video' }
    }
}

try {
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $LogFile) -Force
    Write-Log INFO "Start Build=$ScriptBuild Device=$env:COMPUTERNAME"
    if ($script:LogFailed) { throw 'Required log is not writable.' }

    $active = @{}
    $issues = @()
    $monitors = @()
    $displayReadOk = $false

    try {
        $monitors = @(Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorConnectionParams)
        foreach ($monitor in $monitors) {
            if ($null -eq $monitor.Active -or $null -eq $monitor.VideoOutputTechnology) { throw 'Monitor state or connection type missing.' }
            $code = [uint32]$monitor.VideoOutputTechnology
            $type = Get-DisplayType -Code $code
            Write-Log INFO "Display Active=$($monitor.Active); Technology=$code; Classified=$type"
            if ($monitor.Active) {
                if (-not $active.ContainsKey($type)) { $active[$type] = 0 }
                $active[$type]++
            }
        }
        $displayReadOk = $true
        if ($active.ContainsKey('Other video')) { $issues += 'Unclassified active display connection' }
    } catch {
        $active.Clear()
        $issues += 'Active display query failed'
        Write-Log ERROR "Display query: $($_.Exception.Message)"
    }

    $activeSummary = 'Unknown'
    if ($displayReadOk) {
        $activeSummary = 'None detected'
        if ($active.Count -gt 0) {
            $activeSummary = (@(foreach ($type in ($active.Keys | Sort-Object)) {
                '{0} x{1}' -f $type, $active[$type]
            }) -join ', ')
        }
    }
    $value = "Active: $activeSummary"
    Write-Log INFO "Inventory: $value"
    foreach ($issue in ($issues | Sort-Object -Unique)) { Write-Log WARN $issue }
    if ($script:LogFailed) { throw 'Required logging failed before field update.' }
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -ge 200) {
        throw 'Inventory is empty or exceeds Text field limit; full inventory in log. Field not updated.'
    }

    $null = Get-Command -Name Ninja-Property-Set -ErrorAction Stop
    $null = Get-Command -Name Ninja-Property-Get -ErrorAction Stop
    Write-Log INFO "Updating custom field $Field"
    $null = Ninja-Property-Set -Name $Field -Value $value
    $readBack = Ninja-Property-Get -Name $Field
    if ([string]$readBack -cne $value) { throw 'Custom field read-back mismatch.' }
    Write-Log INFO 'Local custom field read-back verified.'
    if ($issues.Count -gt 0) {
        $Final = "ERROR | PartialInventory; $value"
    } else {
        $Final = "RESULT | $value"
    }
} catch {
    Write-Log ERROR $_.Exception.Message
    $Final = 'ERROR | ' + (Safe-Text $_.Exception.Message)
} finally {
    Write-Log INFO "Final: $Final"
    if ($script:LogFailed) { $Final = 'ERROR | Required logging failed; see available log and verify field state.' }
    Write-Output $Final
}
exit 0
