# ============================================================================
# NAME: Endpoint IR Evidence Collector
# AUTHORED BY: Cogan Goldwater
# TYPE: Evidence Collection
# SCOPE: Windows endpoints / Incident Response
# VARIABLES:
#   EvidenceRoot        (Optional string; default C:\MME\IR\IR-<COMPUTERNAME>-<yyyy-MM-dd>)
#   CollectionStartDate (Optional datetime; default last 30 days)
# OUTPUT TOKENS:
#   STARTED   | Collector started
#   COMPLETED | Collector completed
#   FAILED    | Collector failed; see Endpoint_IR_Collection_Status.txt
#   DONE      | Endpoint IR collection complete
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   Evidence-local status files under C:\MME\IR\IR-<COMPUTERNAME>-<yyyy-MM-dd>
#   Main status: Endpoint_IR_Collection_Status.txt
# DESCRIPTION:
#   Collects endpoint-side incident-response evidence for device security review.
#   Includes Windows event logs, system/persistence state, WMI persistence, driver
#   inventory and driver-file hashes/signatures, execution/access artifacts, browser
#   and SaaS artifacts, remote-access-tool evidence, and an evidence hash manifest.
#   Native acquisition fallbacks are used for locked Amcache/SRUM artifacts when
#   ordinary file copying cannot read the live source. Locked Amcache files may be
#   acquired from a temporary VSS snapshot, which is deleted after collection.
#   Collection is read-only where practical and does not clear logs, uninstall
#   software, delete source artifacts, or execute suspicious files. Missing artifacts
#   are recorded as SKIPPED/NO_MATCHES where supported. Browser artifacts may contain
#   sensitive cookie/session/login material and must be handled as IR evidence.
# ============================================================================
[CmdletBinding()]
param(
    [string]$EvidenceRoot = "",
    [datetime]$CollectionStartDate = (Get-Date).AddDays(-30)
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $SafeComputerName = ($env:COMPUTERNAME -replace '[\\/:*?"<>|]', "_")
    $EvidenceRoot = "C:\MME\IR\IR-$SafeComputerName-$(Get-Date -Format 'yyyy-MM-dd')"
}

function New-Dir {
    param([string]$Path)
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Safe-Name {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return "_" }
    return ($Name -replace '[\\/:*?"<>|]', "_")
}

function Write-Log {
    param([string]$Path, [string]$Message)
    if ($Path) { $Message | Add-Content -Path $Path }
    Write-Host $Message
}

function Export-List {
    param(
        [System.Collections.IEnumerable]$Data,
        [string]$Path,
        [string]$NoMatchLabel
    )
    $Array = @($Data)
    if ($Array.Count -gt 0) {
        $Array | Export-Csv -Path $Path -NoTypeInformation
    }
    else {
        [PSCustomObject]@{ Status = "NO_MATCHES"; Detail = $NoMatchLabel } |
            Export-Csv -Path $Path -NoTypeInformation
    }
}

function Get-Users {
    Get-ChildItem -Path "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public","Default","Default User","All Users","defaultuser0") }
}

function Hash-File {
    param([string]$Path, [string]$HashFile)
    if (-not (Test-Path -Path $Path)) { return $null }
    try {
        $Hash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($HashFile) { "$Hash  $Path" | Add-Content -Path $HashFile }
        return $Hash
    }
    catch { return "Hash failed: $($_.Exception.Message)" }
}

function Copy-Artifact {
    param([string]$Source, [string]$Destination, [string]$HashFile)

    $Status = "Copied"
    $Hash = $null

    try {
        New-Dir -Path (Split-Path -Path $Destination -Parent)
        Copy-Item -Path $Source -Destination $Destination -Force -ErrorAction Stop
    }
    catch { $Status = "Copy failed: $($_.Exception.Message)" }

    if (Test-Path -Path $Destination) {
        $Hash = Hash-File -Path $Destination -HashFile $HashFile
    }

    [PSCustomObject]@{ CopyStatus = $Status; SHA256 = $Hash }
}

New-Dir -Path $EvidenceRoot
$MainStatus = Join-Path $EvidenceRoot "Endpoint_IR_Collection_Status.txt"
"Endpoint IR Collection - $(Get-Date -Format s)" | Set-Content -Path $MainStatus
"EvidenceRoot: $EvidenceRoot" | Add-Content -Path $MainStatus
"CollectionStartDate: $CollectionStartDate" | Add-Content -Path $MainStatus

# ============================================================
# 03_Windows_Event_Logs
# ============================================================

function Collect-WindowsEventLogs {
    $Root = Join-Path $EvidenceRoot "03_Windows_Event_Logs"
    $Evtx = Join-Path $Root "EVTX"
    $LogsOut = Join-Path $Root "Export_Logs"
    New-Dir $Evtx
    New-Dir $LogsOut

    $Status = Join-Path $LogsOut "Windows_Event_Log_Export_Status.txt"
    "Windows Event Log Export - $(Get-Date -Format s)" | Set-Content -Path $Status

    $Logs = @(
        @{Name="Security"; File="Security.evtx"},
        @{Name="System"; File="System.evtx"},
        @{Name="Application"; File="Application.evtx"},
        @{Name="Microsoft-Windows-PowerShell/Operational"; File="Microsoft-Windows-PowerShell_Operational.evtx"},
        @{Name="Microsoft-Windows-TaskScheduler/Operational"; File="Microsoft-Windows-TaskScheduler_Operational.evtx"},
        @{Name="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; File="Microsoft-Windows-TerminalServices-LocalSessionManager_Operational.evtx"},
        @{Name="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; File="Microsoft-Windows-TerminalServices-RemoteConnectionManager_Operational.evtx"},
        @{Name="Microsoft-Windows-WinRM/Operational"; File="Microsoft-Windows-WinRM_Operational.evtx"},
        @{Name="Microsoft-Windows-WMI-Activity/Operational"; File="Microsoft-Windows-WMI-Activity_Operational.evtx"},
        @{Name="Microsoft-Windows-Bits-Client/Operational"; File="Microsoft-Windows-Bits-Client_Operational.evtx"},
        @{Name="Microsoft-Windows-SMBClient/Connectivity"; File="Microsoft-Windows-SMBClient_Connectivity.evtx"},
        @{Name="Microsoft-Windows-SMBClient/Security"; File="Microsoft-Windows-SMBClient_Security.evtx"},
        @{Name="Microsoft-Windows-Windows Defender/Operational"; File="Microsoft-Windows-Windows Defender_Operational.evtx"},
        @{Name="Microsoft-Windows-Sysmon/Operational"; File="Microsoft-Windows-Sysmon_Operational.evtx"}
    )

    foreach ($Log in $Logs) {
        $OutFile = Join-Path $Evtx $Log.File
        try {
            $null = Get-WinEvent -ListLog $Log.Name -ErrorAction Stop
            $Output = & wevtutil.exe epl $Log.Name $OutFile /ow:true 2>&1
            if (Test-Path $OutFile) {
                Write-Log $Status "EXPORTED | $($Log.Name) | $OutFile"
            }
            else {
                Write-Log $Status "SKIPPED | $($Log.Name) | Export did not create file | $(($Output | Out-String).Trim())"
            }
        }
        catch { Write-Log $Status "SKIPPED | $($Log.Name) | $($_.Exception.Message)" }
    }
}

# ============================================================
# 04_System_Persistence
# ============================================================

function Collect-RunningProcesses {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Running_Processes"
    New-Dir $Out
    $Csv = Join-Path $Out "Running_Processes.csv"
    $Txt = Join-Path $Out "Running_Processes_CommandLines.txt"

    $Data = Get-CimInstance Win32_Process |
        Select-Object Name, ProcessId, ParentProcessId, CreationDate, ExecutablePath, CommandLine, SessionId

    Export-List $Data $Csv "No running processes returned"
    $Data | Sort-Object ProcessId | Format-List * | Out-File $Txt -Encoding UTF8

    Write-Host "EXPORTED | Running processes | $Csv"
}

function Collect-Services {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Services"
    New-Dir $Out
    $Csv = Join-Path $Out "Services.csv"
    $Txt = Join-Path $Out "Services_Details.txt"

    $Data = Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId, Description

    Export-List $Data $Csv "No services returned"
    $Data | Sort-Object Name | Format-List * | Out-File $Txt -Encoding UTF8

    Write-Host "EXPORTED | Services | $Csv"
}

function Collect-ScheduledTasks {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Scheduled_Tasks"
    New-Dir $Out
    $Csv = Join-Path $Out "Scheduled_Tasks.csv"
    $Txt = Join-Path $Out "Scheduled_Tasks_Details.txt"

    $Data = Get-ScheduledTask | ForEach-Object {
        $Task = $_
        $Info = $null
        try { $Info = Get-ScheduledTaskInfo -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction Stop } catch {}

        $Actions = @()
        if ($Task.Actions) {
            $Actions = $Task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }
        }

        $Triggers = @()
        if ($Task.Triggers) {
            $Triggers = $Task.Triggers | ForEach-Object { if ($null -ne $_) { ($_ | Out-String) } }
        }

        [PSCustomObject]@{
            TaskName       = $Task.TaskName
            TaskPath       = $Task.TaskPath
            State          = $Task.State
            Author         = $Task.Author
            Description    = $Task.Description
            UserId         = $Task.Principal.UserId
            RunLevel       = $Task.Principal.RunLevel
            Actions        = ($Actions -join " | ")
            Triggers       = (($Triggers -join " | ") -replace "`r|`n"," ").Trim()
            LastRunTime    = if ($Info) { $Info.LastRunTime } else { $null }
            LastTaskResult = if ($Info) { $Info.LastTaskResult } else { $null }
            NextRunTime    = if ($Info) { $Info.NextRunTime } else { $null }
        }
    }

    Export-List $Data $Csv "No scheduled tasks returned"
    $Data | Sort-Object TaskPath, TaskName | Format-List * | Out-File $Txt -Encoding UTF8

    Write-Host "EXPORTED | Scheduled tasks | $Csv"
}

function Collect-StartupItems {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Startup_Items"
    New-Dir $Out
    $WmiCsv = Join-Path $Out "Startup_Commands_WMI.csv"
    $RegCsv = Join-Path $Out "Startup_Registry_Run_Keys.csv"
    $FolderCsv = Join-Path $Out "Startup_Folder_Items.csv"
    $Summary = Join-Path $Out "Startup_Items_Summary.txt"

    Get-CimInstance Win32_StartupCommand |
        Select-Object Name, Command, Location, User, UserSID |
        Export-Csv -Path $WmiCsv -NoTypeInformation

    $RegPaths = @(
        "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
        $RegPaths += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $RegPaths += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }

    $RegData = foreach ($Path in $RegPaths) {
        if (Test-Path $Path) {
            $Props = Get-ItemProperty -Path $Path
            foreach ($Prop in $Props.PSObject.Properties) {
                if ($Prop.Name -notmatch "^PS") {
                    [PSCustomObject]@{ Path=$Path; Name=$Prop.Name; Value=$Prop.Value }
                }
            }
        }
    }
    Export-List $RegData $RegCsv "No startup registry values found"

    $Folders = @("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    Get-Users | ForEach-Object {
        $Folders += Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    }

    $FolderData = foreach ($Folder in $Folders) {
        if (Test-Path $Folder) {
            Get-ChildItem -Path $Folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{
                    Folder        = $Folder
                    Name          = $_.Name
                    FullName      = $_.FullName
                    ItemType      = if ($_.PSIsContainer) { "Directory" } else { "File" }
                    Extension     = if (-not $_.PSIsContainer) { $_.Extension } else { $null }
                    Length        = if (-not $_.PSIsContainer) { $_.Length } else { $null }
                    CreationTime  = $_.CreationTime
                    LastWriteTime = $_.LastWriteTime
                }
            }
        }
    }
    Export-List $FolderData $FolderCsv "No startup folder items found"

    "Startup Items Export - $(Get-Date -Format s)" | Set-Content $Summary
    "EXPORTED | WMI startup commands | $WmiCsv" | Add-Content $Summary
    "EXPORTED | Registry startup keys | $RegCsv" | Add-Content $Summary
    "EXPORTED | Startup folder items | $FolderCsv" | Add-Content $Summary

    Write-Host "EXPORTED | Startup items | $Out"
}

function Collect-InstalledSoftware {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Installed_Software"
    New-Dir $Out
    $Csv = Join-Path $Out "Installed_Software.csv"
    $Txt = Join-Path $Out "Installed_Software_Details.txt"

    $Paths = @(
        "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
        $Paths += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }

    $Data = foreach ($Path in $Paths) {
        Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.DisplayName) {
                [PSCustomObject]@{
                    DisplayName     = $_.DisplayName
                    DisplayVersion  = $_.DisplayVersion
                    Publisher       = $_.Publisher
                    InstallDate     = $_.InstallDate
                    InstallLocation = $_.InstallLocation
                    UninstallString = $_.UninstallString
                    QuietUninstall  = $_.QuietUninstallString
                    RegistryPath    = $_.PSPath
                }
            }
        }
    }

    $Data = @($Data | Sort-Object DisplayName, DisplayVersion)
    Export-List $Data $Csv "No installed software entries found"
    $Data | Format-List * | Out-File $Txt -Encoding UTF8

    Write-Host "EXPORTED | Installed software | $Csv"
}

function Collect-LocalUsers {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Local_Users"
    New-Dir $Out
    $Csv = Join-Path $Out "Local_Users.csv"
    $Txt = Join-Path $Out "Local_Users_Details.txt"

    $Data = Get-LocalUser |
        Select-Object Name, Enabled, SID, Description, FullName, LastLogon, PasswordRequired, PasswordLastSet, UserMayChangePassword, PasswordExpires

    Export-List $Data $Csv "No local users returned"
    $Data | Sort-Object Name | Format-List * | Out-File $Txt -Encoding UTF8

    Write-Host "EXPORTED | Local users | $Csv"
}

function Collect-LocalAdmins {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Local_Admins"
    New-Dir $Out
    $Csv = Join-Path $Out "Local_Administrators.csv"
    $Txt = Join-Path $Out "Local_Administrators_Details.txt"
    $NetRaw = Join-Path $Out "Local_Administrators_NetLocalGroup.txt"
    $Status = Join-Path $Out "Local_Administrators_Collection_Status.txt"

    "Local Administrators Collection - $(Get-Date -Format s)" | Set-Content $Status

    try {
        $Data = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name            = $_.Name
                ObjectClass     = $_.ObjectClass
                PrincipalSource = $_.PrincipalSource
                SID             = $_.SID.Value
            }
        })

        if ($Data.Count -gt 0) {
            $Data | Export-Csv -Path $Csv -NoTypeInformation
            $Data | Sort-Object Name | Format-List * | Out-File $Txt -Encoding UTF8
            Write-Log $Status "EXPORTED | Local administrators | Method=Get-LocalGroupMember | Rows=$($Data.Count) | $Csv"
            return
        }

        [PSCustomObject]@{ Status = "NO_MATCHES"; Detail = "No local administrators returned" } |
            Export-Csv -Path $Csv -NoTypeInformation
        "NO_MATCHES | No local administrators returned" | Set-Content $Txt
        Write-Log $Status "NO_MATCHES | Local administrators | Method=Get-LocalGroupMember"
        return
    }
    catch {
        $PrimaryError = $_.Exception.Message
        Write-Log $Status "FALLBACK | Get-LocalGroupMember failed | $PrimaryError"
    }

    # Some domain/trust conditions cause Get-LocalGroupMember to fail while the
    # built-in NET command can still enumerate the local Administrators group.
    # Preserve the raw NET output and also parse member names into the normal CSV.
    $NetOutput = @(& net.exe localgroup Administrators 2>&1 | ForEach-Object { [string]$_ })
    $NetExit = $LASTEXITCODE
    $NetOutput | Set-Content -Path $NetRaw -Encoding UTF8

    if ($NetExit -eq 0) {
        $SeparatorIndex = -1
        for ($i = 0; $i -lt $NetOutput.Count; $i++) {
            if ($NetOutput[$i] -match '^\s*-{3,}\s*$') {
                $SeparatorIndex = $i
                break
            }
        }

        $Members = @()
        if ($SeparatorIndex -ge 0) {
            for ($i = $SeparatorIndex + 1; $i -lt $NetOutput.Count; $i++) {
                $Line = $NetOutput[$i].Trim()
                if ([string]::IsNullOrWhiteSpace($Line)) { continue }
                if ($Line -match '^The command completed successfully\.?$') { break }
                $Members += $Line
            }
        }

        if ($Members.Count -gt 0) {
            $Data = @($Members | ForEach-Object {
                [PSCustomObject]@{
                    Name            = $_
                    ObjectClass     = $null
                    PrincipalSource = $null
                    SID             = $null
                }
            })

            $Data | Export-Csv -Path $Csv -NoTypeInformation
            @(
                "CollectionMethod: net localgroup Administrators"
                "PrimaryMethodError: $PrimaryError"
                ""
                ($Data | Sort-Object Name | Format-List * | Out-String).TrimEnd()
            ) | Set-Content -Path $Txt -Encoding UTF8

            Write-Log $Status "EXPORTED | Local administrators | Method=net localgroup Administrators | Rows=$($Data.Count) | $Csv"
            return
        }

        [PSCustomObject]@{ Status = "NO_MATCHES"; Detail = "net localgroup Administrators returned no parsed members" } |
            Export-Csv -Path $Csv -NoTypeInformation
        @(
            "NO_MATCHES | net localgroup Administrators returned no parsed members"
            "PrimaryMethodError: $PrimaryError"
            "RawOutput: $NetRaw"
        ) | Set-Content -Path $Txt -Encoding UTF8
        Write-Log $Status "NO_MATCHES | Local administrators | Method=net localgroup Administrators"
        return
    }

    $NetError = ($NetOutput -join ' | ').Trim()
    [PSCustomObject]@{
        Status = "QUERY_FAILED"
        Detail = "Get-LocalGroupMember and net localgroup Administrators both failed"
        Error  = "Primary=$PrimaryError || FallbackExit=$NetExit || Fallback=$NetError"
    } | Export-Csv -Path $Csv -NoTypeInformation

    @(
        "QUERY_FAILED | Local Administrators enumeration failed"
        "Get-LocalGroupMember: $PrimaryError"
        "net localgroup exit code: $NetExit"
        "RawOutput: $NetRaw"
    ) | Set-Content -Path $Txt -Encoding UTF8

    Write-Log $Status "FAILED | Local administrators | Primary=$PrimaryError | FallbackExit=$NetExit"
    throw "Local administrators enumeration failed with Get-LocalGroupMember and net localgroup Administrators"
}

function Collect-FirewallRules {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Firewall_Rules"
    New-Dir $Out
    $Csv = Join-Path $Out "Firewall_Rules.csv"
    $Txt = Join-Path $Out "Firewall_Rules_Netsh.txt"

    # Firewall filters are one-to-one with firewall rules and share the rule's
    # InstanceID. Retrieve each filter family once, correlate in memory, and
    # fall back to the original associated-rule lookup only if a bulk result
    # does not contain the expected filter. This preserves evidence coverage
    # while avoiding four CIM/provider round trips for every firewall rule.
    $Rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue)

    $AppMap = @{}
    Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ForEach-Object {
        if ($null -ne $_.InstanceID) { $AppMap[[string]$_.InstanceID] = $_ }
    }

    $PortMap = @{}
    Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object {
        if ($null -ne $_.InstanceID) { $PortMap[[string]$_.InstanceID] = $_ }
    }

    $AddressMap = @{}
    Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | ForEach-Object {
        if ($null -ne $_.InstanceID) { $AddressMap[[string]$_.InstanceID] = $_ }
    }

    $ServiceMap = @{}
    Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue | ForEach-Object {
        if ($null -ne $_.InstanceID) { $ServiceMap[[string]$_.InstanceID] = $_ }
    }

    $Data = foreach ($Rule in $Rules) {
        $InstanceId = [string]$Rule.InstanceID

        $App = $null
        if ($AppMap.ContainsKey($InstanceId)) {
            $App = $AppMap[$InstanceId]
        }
        else {
            $App = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
        }

        $Port = $null
        if ($PortMap.ContainsKey($InstanceId)) {
            $Port = $PortMap[$InstanceId]
        }
        else {
            $Port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
        }

        $Address = $null
        if ($AddressMap.ContainsKey($InstanceId)) {
            $Address = $AddressMap[$InstanceId]
        }
        else {
            $Address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
        }

        $Service = $null
        if ($ServiceMap.ContainsKey($InstanceId)) {
            $Service = $ServiceMap[$InstanceId]
        }
        else {
            $Service = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
        }

        [PSCustomObject]@{
            DisplayName   = $Rule.DisplayName
            Name          = $Rule.Name
            Enabled       = $Rule.Enabled
            Direction     = $Rule.Direction
            Action        = $Rule.Action
            Profile       = $Rule.Profile
            Program       = $App.Program
            Service       = $Service.Service
            Protocol      = $Port.Protocol
            LocalPort     = $Port.LocalPort
            RemotePort    = $Port.RemotePort
            LocalAddress  = $Address.LocalAddress
            RemoteAddress = $Address.RemoteAddress
            Description   = $Rule.Description
            PolicyStore   = $Rule.PolicyStoreSource
        }
    }

    Export-List $Data $Csv "No firewall rules returned"
    cmd.exe /c "netsh advfirewall firewall show rule name=all > `"$Txt`" 2>&1" | Out-Null

    Write-Host "EXPORTED | Firewall rules | $Csv"
}

function Collect-NetworkState {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Network_State"
    New-Dir $Out

    $TcpCsv = Join-Path $Out "TCP_Connections.csv"
    $UdpCsv = Join-Path $Out "UDP_Endpoints.csv"
    $DnsCsv = Join-Path $Out "DNS_Cache.csv"
    $AdaptersCsv = Join-Path $Out "Network_Adapters.csv"
    $RoutesCsv = Join-Path $Out "Routes.csv"
    $IpTxt = Join-Path $Out "IPConfig_All.txt"
    $RouteTxt = Join-Path $Out "Route_Print.txt"
    $ArpTxt = Join-Path $Out "ARP_Table.txt"
    $NetstatTxt = Join-Path $Out "Netstat_ANOB.txt"

    # Capture the network endpoint sets first, then resolve each unique owning
    # PID once. This preserves every TCP/UDP row and the same process fields
    # while eliminating repeated Get-Process calls for processes owning many
    # sockets.
    $TcpRaw = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $UdpRaw = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)

    $ProcessMap = @{}
    $OwningPids = @(
        $TcpRaw | Select-Object -ExpandProperty OwningProcess -ErrorAction SilentlyContinue
        $UdpRaw | Select-Object -ExpandProperty OwningProcess -ErrorAction SilentlyContinue
    ) | Where-Object { $null -ne $_ } | Sort-Object -Unique

    foreach ($OwningPid in $OwningPids) {
        $Proc = $null
        try { $Proc = Get-Process -Id $OwningPid -ErrorAction Stop } catch {}
        if ($Proc) { $ProcessMap[[int]$OwningPid] = $Proc }
    }

    $Tcp = $TcpRaw | ForEach-Object {
        $Proc = $null
        if ($ProcessMap.ContainsKey([int]$_.OwningProcess)) {
            $Proc = $ProcessMap[[int]$_.OwningProcess]
        }
        [PSCustomObject]@{
            LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort
            RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort
            State=$_.State; OwningProcess=$_.OwningProcess
            ProcessName=if ($Proc) { $Proc.ProcessName } else { $null }
            ProcessPath=if ($Proc) { $Proc.Path } else { $null }
        }
    }
    Export-List $Tcp $TcpCsv "No TCP connections returned"

    $Udp = $UdpRaw | ForEach-Object {
        $Proc = $null
        if ($ProcessMap.ContainsKey([int]$_.OwningProcess)) {
            $Proc = $ProcessMap[[int]$_.OwningProcess]
        }
        [PSCustomObject]@{
            LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort
            OwningProcess=$_.OwningProcess
            ProcessName=if ($Proc) { $Proc.ProcessName } else { $null }
            ProcessPath=if ($Proc) { $Proc.Path } else { $null }
        }
    }
    Export-List $Udp $UdpCsv "No UDP endpoints returned"

    Get-DnsClientCache -ErrorAction SilentlyContinue | Export-Csv -Path $DnsCsv -NoTypeInformation
    Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, DriverInformation | Export-Csv -Path $AdaptersCsv -NoTypeInformation
    Get-NetRoute -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias, InterfaceIndex, PolicyStore | Export-Csv -Path $RoutesCsv -NoTypeInformation

    cmd.exe /c "ipconfig /all > `"$IpTxt`" 2>&1" | Out-Null
    cmd.exe /c "route print > `"$RouteTxt`" 2>&1" | Out-Null
    cmd.exe /c "arp -a > `"$ArpTxt`" 2>&1" | Out-Null
    cmd.exe /c "netstat -anob > `"$NetstatTxt`" 2>&1" | Out-Null

    Write-Host "EXPORTED | Network state | $Out"
}


# ============================================================
# 04_System_Persistence - WMI Persistence
# ============================================================

function Collect-WMIPersistence {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\WMI_Persistence"
    New-Dir $Out

    $FiltersCsv   = Join-Path $Out "WMI_Event_Filters.csv"
    $ConsumersCsv = Join-Path $Out "WMI_Event_Consumers.csv"
    $BindingsCsv  = Join-Path $Out "WMI_Filter_To_Consumer_Bindings.csv"
    $Status       = Join-Path $Out "WMI_Persistence_Collection_Status.txt"

    "WMI Persistence Collection - $(Get-Date -Format s)" | Set-Content $Status

    function Invoke-WmiQuery {
        param(
            [string]$ClassName,
            [string]$Namespace,
            [string]$OutputPath,
            [string]$NoMatchLabel,
            [scriptblock]$Transform
        )

        try {
            $Raw = @(Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop)

            if ($Raw.Count -eq 0) {
                [PSCustomObject]@{ Status = "NO_MATCHES"; Detail = $NoMatchLabel } |
                    Export-Csv -Path $OutputPath -NoTypeInformation
                Write-Log $Status "NO_MATCHES | $ClassName | Namespace=$Namespace"
                return
            }

            $Data = @(if ($Transform) { $Raw | ForEach-Object $Transform } else { $Raw })
            $Data | Export-Csv -Path $OutputPath -NoTypeInformation
            Write-Log $Status "EXPORTED | $ClassName | Rows=$($Data.Count) | $OutputPath"
        }
        catch {
            [PSCustomObject]@{
                Status = "QUERY_FAILED"
                Class = $ClassName
                Namespace = $Namespace
                Error = $_.Exception.Message
            } | Export-Csv -Path $OutputPath -NoTypeInformation

            Write-Log $Status "FAILED | $ClassName | Namespace=$Namespace | $($_.Exception.Message)"
        }
    }

    Invoke-WmiQuery -ClassName "__EventFilter" -Namespace "root\subscription" -OutputPath $FiltersCsv `
        -NoMatchLabel "No permanent WMI event filters found" -Transform {
            [PSCustomObject]@{
                Name           = $_.Name
                Query          = $_.Query
                QueryLanguage  = $_.QueryLanguage
                EventNamespace = $_.EventNamespace
                CreatorSID     = if ($_.CreatorSID) { [System.BitConverter]::ToString($_.CreatorSID) } else { $null }
                Path           = $_.CimSystemProperties.Path
            }
        }

    $ConsumerClasses = @(
        "CommandLineEventConsumer",
        "ActiveScriptEventConsumer",
        "LogFileEventConsumer",
        "NTEventLogEventConsumer",
        "SMTPEventConsumer"
    )

    $Consumers = New-Object System.Collections.Generic.List[object]
    $ConsumerQueryFailures = New-Object System.Collections.Generic.List[string]

    foreach ($ClassName in $ConsumerClasses) {
        try {
            $Rows = @(Get-CimInstance -Namespace "root\subscription" -ClassName $ClassName -ErrorAction Stop)
            foreach ($Row in $Rows) {
                $Consumers.Add([PSCustomObject]@{
                    ConsumerClass   = $ClassName
                    Name            = $Row.Name
                    CommandLine     = $Row.CommandLineTemplate
                    ExecutablePath  = $Row.ExecutablePath
                    ScriptText      = $Row.ScriptText
                    ScriptingEngine = $Row.ScriptingEngine
                    FileName        = $Row.FileName
                    Text            = $Row.Text
                    UNCServerName   = $Row.UNCServerName
                    SMTPServer      = $Row.SMTPServer
                    Subject         = $Row.Subject
                    Path            = $Row.CimSystemProperties.Path
                })
            }
            Write-Log $Status "QUERY_OK | $ClassName | Rows=$($Rows.Count)"
        }
        catch {
            $ConsumerQueryFailures.Add("$ClassName | $($_.Exception.Message)")
            Write-Log $Status "FAILED | $ClassName | Namespace=root\\subscription | $($_.Exception.Message)"
        }
    }

    if ($Consumers.Count -gt 0) {
        $Consumers | Export-Csv -Path $ConsumersCsv -NoTypeInformation
        Write-Log $Status "EXPORTED | WMI event consumers | Rows=$($Consumers.Count) | $ConsumersCsv"
    }
    elseif ($ConsumerQueryFailures.Count -gt 0) {
        [PSCustomObject]@{
            Status = "QUERY_FAILED"
            Detail = ($ConsumerQueryFailures -join " || ")
        } | Export-Csv -Path $ConsumersCsv -NoTypeInformation
    }
    else {
        [PSCustomObject]@{ Status = "NO_MATCHES"; Detail = "No permanent WMI event consumers found" } |
            Export-Csv -Path $ConsumersCsv -NoTypeInformation
        Write-Log $Status "NO_MATCHES | WMI event consumers"
    }

    Invoke-WmiQuery -ClassName "__FilterToConsumerBinding" -Namespace "root\subscription" -OutputPath $BindingsCsv `
        -NoMatchLabel "No permanent WMI filter-to-consumer bindings found" -Transform {
            [PSCustomObject]@{
                Filter   = [string]$_.Filter
                Consumer = [string]$_.Consumer
                Path     = $_.CimSystemProperties.Path
            }
        }

    Write-Host "EXPORTED | WMI persistence | $Out"
}

# ============================================================
# 04_System_Persistence - Drivers
# ============================================================

function Collect-Drivers {
    $Out = Join-Path $EvidenceRoot "04_System_Persistence\Drivers"
    New-Dir $Out

    $SystemDriversCsv = Join-Path $Out "System_Drivers.csv"
    $PnpDriversCsv    = Join-Path $Out "PnP_Signed_Drivers.csv"
    $DriverFilesCsv   = Join-Path $Out "Driver_File_Hashes_Signatures.csv"
    $Status           = Join-Path $Out "Drivers_Collection_Status.txt"

    "Driver Collection - $(Get-Date -Format s)" | Set-Content $Status

    $SystemDrivers = @()
    try {
        $SystemDrivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                State       = $_.State
                Status      = $_.Status
                StartMode   = $_.StartMode
                StartName   = $_.StartName
                PathName    = $_.PathName
                ServiceType = $_.ServiceType
                Started     = $_.Started
                AcceptPause = $_.AcceptPause
                AcceptStop  = $_.AcceptStop
            }
        })
        Export-List $SystemDrivers $SystemDriversCsv "No system drivers returned"
        Write-Log $Status "EXPORTED | Win32_SystemDriver | Rows=$($SystemDrivers.Count) | $SystemDriversCsv"
    }
    catch {
        [PSCustomObject]@{ Status="QUERY_FAILED"; Class="Win32_SystemDriver"; Error=$_.Exception.Message } |
            Export-Csv -Path $SystemDriversCsv -NoTypeInformation
        Write-Log $Status "FAILED | Win32_SystemDriver | $($_.Exception.Message)"
    }

    $PnpDrivers = @()
    try {
        $PnpDrivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                DeviceName        = $_.DeviceName
                DeviceID          = $_.DeviceID
                DriverVersion     = $_.DriverVersion
                DriverDate        = $_.DriverDate
                DriverProviderName= $_.DriverProviderName
                Manufacturer      = $_.Manufacturer
                InfName           = $_.InfName
                IsSigned          = $_.IsSigned
                Signer            = $_.Signer
                DriverName        = $_.DriverName
                FriendlyName      = $_.FriendlyName
                Description       = $_.Description
            }
        })
        Export-List $PnpDrivers $PnpDriversCsv "No PnP signed drivers returned"
        Write-Log $Status "EXPORTED | Win32_PnPSignedDriver | Rows=$($PnpDrivers.Count) | $PnpDriversCsv"
    }
    catch {
        [PSCustomObject]@{ Status="QUERY_FAILED"; Class="Win32_PnPSignedDriver"; Error=$_.Exception.Message } |
            Export-Csv -Path $PnpDriversCsv -NoTypeInformation
        Write-Log $Status "FAILED | Win32_PnPSignedDriver | $($_.Exception.Message)"
    }

    $DriverPaths = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($Driver in $SystemDrivers) {
        if ([string]::IsNullOrWhiteSpace($Driver.PathName)) { continue }

        $Path = [Environment]::ExpandEnvironmentVariables([string]$Driver.PathName).Trim().Trim('"')
        if ($Path -match '^\\SystemRoot\\') {
            $Path = Join-Path $env:SystemRoot ($Path -replace '^\\SystemRoot\\','')
        }
        elseif ($Path -match '^System32\\') {
            $Path = Join-Path $env:SystemRoot $Path
        }

        if ($Path -match '^(.*?\.sys)(\s+.*)?$') {
            $Path = $Matches[1]
        }

        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $null = $DriverPaths.Add((Get-Item -LiteralPath $Path -Force).FullName)
        }
    }

    $DriverFiles = New-Object System.Collections.Generic.List[object]

    foreach ($Path in $DriverPaths) {
        $Item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if (-not $Item) { continue }

        $Hash = $null
        try { $Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}

        $Signature = $null
        try { $Signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop } catch {}

        $DriverFiles.Add([PSCustomObject]@{
            FullName          = $Item.FullName
            Name              = $Item.Name
            Length            = $Item.Length
            CreationTime      = $Item.CreationTime
            LastWriteTime     = $Item.LastWriteTime
            SHA256            = $Hash
            SignatureStatus   = if ($Signature) { $Signature.Status } else { $null }
            SignerCertificate = if ($Signature -and $Signature.SignerCertificate) { $Signature.SignerCertificate.Subject } else { $null }
            Issuer            = if ($Signature -and $Signature.SignerCertificate) { $Signature.SignerCertificate.Issuer } else { $null }
            SerialNumber      = if ($Signature -and $Signature.SignerCertificate) { $Signature.SignerCertificate.SerialNumber } else { $null }
            NotBefore         = if ($Signature -and $Signature.SignerCertificate) { $Signature.SignerCertificate.NotBefore } else { $null }
            NotAfter          = if ($Signature -and $Signature.SignerCertificate) { $Signature.SignerCertificate.NotAfter } else { $null }
        })
    }

    Export-List $DriverFiles $DriverFilesCsv "No driver binaries were resolved from Win32_SystemDriver paths"
    Write-Log $Status "EXPORTED | Driver file hashes/signatures | Rows=$($DriverFiles.Count) | $DriverFilesCsv"
    Write-Host "EXPORTED | Drivers | $Out"
}

# ============================================================
# 05_Execution_Access_Artifacts
# ============================================================

function Collect-PowerShellArtifacts {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\Powershell"
    $CopyRoot = Join-Path $Out "Collected_Files"
    New-Dir $Out
    New-Dir $CopyRoot

    $Csv = Join-Path $Out "PowerShell_Artifact_Inventory.csv"
    $HashTxt = Join-Path $Out "PowerShell_Artifacts_SHA256.txt"
    "" | Set-Content $HashTxt

    $Data = New-Object System.Collections.Generic.List[object]

    foreach ($UserDir in Get-Users) {
        $User = $UserDir.Name
        $Files = @(
            (Join-Path $UserDir.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
            (Join-Path $UserDir.FullName "Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"),
            (Join-Path $UserDir.FullName "Documents\PowerShell\Microsoft.PowerShell_profile.ps1")
        )

        foreach ($File in $Files) {
            if (Test-Path $File) {
                $Dest = Join-Path $CopyRoot "$(Safe-Name $User)_$((Split-Path $File -Leaf))"
                $Copy = Copy-Artifact $File $Dest $HashTxt
                $Item = Get-Item $File

                $Data.Add([PSCustomObject]@{
                    UserName=$User; SourcePath=$File; CopiedTo=$Dest; CopyStatus=$Copy.CopyStatus
                    Length=$Item.Length; CreationTime=$Item.CreationTime; LastWriteTime=$Item.LastWriteTime
                    SHA256=$Copy.SHA256
                })
            }
        }
    }

    Export-List $Data $Csv "No PowerShell profile/history artifacts found"
    Write-Host "EXPORTED | PowerShell artifacts | $Csv"
}

function Collect-TempPaths {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\Temp_Paths"
    New-Dir $Out
    $Csv = Join-Path $Out "Temp_Paths_File_Metadata.csv"
    $Hits = Join-Path $Out "Temp_Paths_Suspicious_Name_Hits.csv"

    $Roots = @("C:\Temp","C:\Windows\Temp","C:\Windows\SystemTemp")
    Get-Users | ForEach-Object { $Roots += Join-Path $_.FullName "AppData\Local\Temp" }

    $Data = foreach ($Root in $Roots) {
        if (Test-Path $Root) {
            Get-ChildItem -Path $Root -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $CollectionStartDate } |
                ForEach-Object {
                    $Hash = $null
                    if ($_.Length -le 100MB) {
                        try { $Hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
                    }
                    [PSCustomObject]@{
                        Root=$Root; FullName=$_.FullName; Name=$_.Name; Extension=$_.Extension; Length=$_.Length
                        CreationTime=$_.CreationTime; LastWriteTime=$_.LastWriteTime; LastAccessTime=$_.LastAccessTime; SHA256=$Hash
                    }
                }
        }
    }

    Export-List $Data $Csv "No temp path files found for collection window"
    $Terms = "SC_AutoFix|ScreenConnect|ConnectWise|ClientSetup|\.ps1$|powershell|rundll32|msiexec|\.dll$|\.exe$|\.bat$|\.cmd$|\.vbs$|\.js$"
    @($Data) | Where-Object { $_.FullName -match $Terms } | Export-Csv -Path $Hits -NoTypeInformation

    Write-Host "EXPORTED | Temp paths | $Csv"
}

function Collect-Prefetch {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\Prefetch"
    $CopyRoot = Join-Path $Out "Collected_Prefetch_Files"
    New-Dir $Out
    New-Dir $CopyRoot

    $Csv = Join-Path $Out "Prefetch_File_Metadata.csv"
    $Hits = Join-Path $Out "Prefetch_Suspicious_Name_Hits.csv"
    $HashTxt = Join-Path $Out "Prefetch_SHA256.txt"
    $Status = Join-Path $Out "Prefetch_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "Prefetch Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]
    $Root = "C:\Windows\Prefetch"

    if (Test-Path $Root) {
        Get-ChildItem -Path $Root -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -eq ".pf" -or $_.Extension -eq ".ini" } |
            ForEach-Object {
                $Dest = Join-Path $CopyRoot $_.Name
                $Copy = Copy-Artifact $_.FullName $Dest $HashTxt
                $Data.Add([PSCustomObject]@{
                    SourcePath=$_.FullName; CopiedTo=$Dest; CopyStatus=$Copy.CopyStatus; Name=$_.Name; Length=$_.Length
                    CreationTime=$_.CreationTime; LastWriteTime=$_.LastWriteTime; LastAccessTime=$_.LastAccessTime; SHA256=$Copy.SHA256
                })
            }
        Export-List $Data $Csv "No prefetch files found"
        $Terms = "SC_AUTOFIX|SCREENCONNECT|CONNECTWISE|CLIENTSETUP|POWERSHELL|RUNDLL32|MSIEXEC|CMD|WSCRIPT|CSCRIPT|CONHOST"
        $Data | Where-Object { $_.Name -match $Terms } | Export-Csv -Path $Hits -NoTypeInformation
        Write-Log $Status "EXPORTED | Prefetch metadata | $Csv"
    }
    else { Write-Log $Status "SKIPPED | Prefetch folder not found | $Root" }
}

function Copy-ArtifactSetByPattern {
    param(
        [string]$Out,
        [string]$SourceRoot,
        [string]$Pattern,
        [string]$NamePrefix
    )

    New-Dir $Out
    $Csv = Join-Path $Out "$($NamePrefix)_File_Inventory.csv"
    $HashTxt = Join-Path $Out "$($NamePrefix)_SHA256.txt"
    $Status = Join-Path $Out "$($NamePrefix)_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "$NamePrefix Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]

    if (Test-Path $SourceRoot) {
        Get-ChildItem -Path $SourceRoot -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like $Pattern } |
            ForEach-Object {
                $Dest = Join-Path $Out $_.Name
                $Copy = Copy-Artifact $_.FullName $Dest $HashTxt
                $Data.Add([PSCustomObject]@{
                    SourcePath=$_.FullName; CopiedTo=$Dest; CopyStatus=$Copy.CopyStatus; Name=$_.Name; Length=$_.Length
                    CreationTime=$_.CreationTime; LastWriteTime=$_.LastWriteTime; LastAccessTime=$_.LastAccessTime; SHA256=$Copy.SHA256
                })
            }
        Export-List $Data $Csv "No files matched $Pattern under $SourceRoot"
        Write-Log $Status "EXPORTED | $NamePrefix inventory | $Csv"
    }
    else { Write-Log $Status "SKIPPED | Source folder not found | $SourceRoot" }
}

function Collect-Amcache {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\Amcache"
    $SourceRoot = "C:\Windows\AppCompat\Programs"
    New-Dir $Out

    $Csv = Join-Path $Out "Amcache_File_Inventory.csv"
    $HashTxt = Join-Path $Out "Amcache_SHA256.txt"
    $Status = Join-Path $Out "Amcache_Collection_Status.txt"
    $RegSaveOutput = Join-Path $Out "Amcache_RegSave_Output.txt"
    $VssOutput = Join-Path $Out "Amcache_VSS_Output.txt"
    "" | Set-Content $HashTxt
    "Amcache Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]
    $VssState = [PSCustomObject]@{
        ShadowId = $null
        ShadowDevice = $null
        ShadowCreated = $false
    }

    function Ensure-AmcacheShadowCopy {
        if ($VssState.ShadowDevice) { return $true }

        try {
            Write-Log $Status "VSS_START | Creating temporary ClientAccessible shadow copy for C:\"
            $ShadowClass = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
            $CreateResult = $ShadowClass.Create("C:\", "ClientAccessible")

            if ($null -eq $CreateResult) {
                Write-Log $Status "VSS_FAILED | Create returned no result"
                return $false
            }

            if ([int]$CreateResult.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace([string]$CreateResult.ShadowID)) {
                Write-Log $Status "VSS_FAILED | ReturnValue=$($CreateResult.ReturnValue) | ShadowID=$($CreateResult.ShadowID)"
                return $false
            }

            $VssState.ShadowId = [string]$CreateResult.ShadowID
            $VssState.ShadowCreated = $true
            $Shadow = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop |
                Where-Object { $_.ID -eq $VssState.ShadowId } |
                Select-Object -First 1

            if (-not $Shadow -or [string]::IsNullOrWhiteSpace([string]$Shadow.DeviceObject)) {
                Write-Log $Status "VSS_FAILED | Shadow created but DeviceObject could not be resolved | ShadowID=$($VssState.ShadowId)"
                return $false
            }

            $VssState.ShadowDevice = ([string]$Shadow.DeviceObject).TrimEnd('\')
            "ShadowID=$($VssState.ShadowId)`r`nDeviceObject=$($VssState.ShadowDevice)" | Set-Content -Path $VssOutput -Encoding UTF8
            Write-Log $Status "VSS_READY | ShadowID=$($VssState.ShadowId) | DeviceObject=$($VssState.ShadowDevice)"
            return $true
        }
        catch {
            Write-Log $Status "VSS_FAILED | $($_.Exception.Message)"
            return $false
        }
    }

    function Copy-AmcacheFromShadow {
        param(
            [string]$FileName,
            [string]$Destination
        )

        if (-not (Ensure-AmcacheShadowCopy)) {
            return [PSCustomObject]@{ Success=$false; Detail="VSS unavailable" }
        }

        try {
            $ShadowSource = "$($VssState.ShadowDevice)\Windows\AppCompat\Programs\$FileName"
            $CopyOutputFile = Join-Path $Out "Amcache_VSS_Copy_$((Safe-Name $FileName)).txt"
            $CopyOutput = @(& cmd.exe /c copy /y "`"$ShadowSource`"" "`"$Destination`"" 2>&1 | ForEach-Object { [string]$_ })
            $CopyExit = $LASTEXITCODE
            $CopyOutput | Set-Content -Path $CopyOutputFile -Encoding UTF8

            if ($CopyExit -eq 0 -and (Test-Path -LiteralPath $Destination)) {
                return [PSCustomObject]@{ Success=$true; Detail="Collected via VSS snapshot" }
            }

            return [PSCustomObject]@{ Success=$false; Detail="VSS copy failed with exit code $CopyExit" }
        }
        catch {
            return [PSCustomObject]@{ Success=$false; Detail="VSS copy failed: $($_.Exception.Message)" }
        }
    }

    try {
        if (-not (Test-Path $SourceRoot)) {
            Write-Log $Status "SKIPPED | Source folder not found | $SourceRoot"
            Export-List $Data $Csv "No Amcache source folder found"
            return
        }

        $Files = @(Get-ChildItem -Path $SourceRoot -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "Amcache.hve*" })

        foreach ($File in $Files) {
            $Dest = Join-Path $Out $File.Name
            $Method = "Copy-Item"
            $CopyStatus = $null
            $Hash = $null

            try {
                Copy-Item -LiteralPath $File.FullName -Destination $Dest -Force -ErrorAction Stop
                $CopyStatus = "Copied"
                $Hash = Hash-File -Path $Dest -HashFile $HashTxt
            }
            catch {
                $CopyStatus = "Copy failed: $($_.Exception.Message)"
                Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
            }

            if ($CopyStatus -like "Copy failed:*") {
                if ($File.Name -eq "Amcache.hve") {
                    $Method = "reg save HKLM\Amcache"
                    $RegOutput = @(& reg.exe save "HKLM\Amcache" $Dest /y 2>&1 | ForEach-Object { [string]$_ })
                    $RegExit = $LASTEXITCODE
                    $RegOutput | Set-Content -Path $RegSaveOutput -Encoding UTF8

                    if ($RegExit -eq 0 -and (Test-Path -LiteralPath $Dest)) {
                        $CopyStatus = "Collected via reg save"
                        $Hash = Hash-File -Path $Dest -HashFile $HashTxt
                        Write-Log $Status "FALLBACK_OK | Amcache.hve | Method=reg save HKLM\Amcache | $Dest"
                    }
                    else {
                        Write-Log $Status "FALLBACK_FAILED | Amcache.hve | Method=reg save HKLM\Amcache | ExitCode=$RegExit"
                        Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
                    }
                }

                if (-not (Test-Path -LiteralPath $Dest)) {
                    $VssCopy = Copy-AmcacheFromShadow -FileName $File.Name -Destination $Dest
                    $Method = if ($Method -eq "Copy-Item") { "VSS snapshot" } else { "$Method -> VSS snapshot" }

                    if ($VssCopy.Success) {
                        $CopyStatus = $VssCopy.Detail
                        $Hash = Hash-File -Path $Dest -HashFile $HashTxt
                        Write-Log $Status "FALLBACK_OK | $($File.Name) | Method=VSS snapshot | $Dest"
                    }
                    else {
                        Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
                        $Hash = $null
                        $CopyStatus = "$CopyStatus | $($VssCopy.Detail)"
                        Write-Log $Status "FALLBACK_FAILED | $($File.Name) | Method=VSS snapshot | $($VssCopy.Detail)"
                    }
                }
            }

            $Data.Add([PSCustomObject]@{
                SourcePath=$File.FullName; CopiedTo=$Dest; CopyStatus=$CopyStatus; CollectionMethod=$Method
                Name=$File.Name; Length=$File.Length; CreationTime=$File.CreationTime; LastWriteTime=$File.LastWriteTime
                LastAccessTime=$File.LastAccessTime; SHA256=$Hash
            })
        }

        Export-List $Data $Csv "No files matched Amcache.hve* under $SourceRoot"
        Write-Log $Status "EXPORTED | Amcache inventory | Rows=$($Data.Count) | $Csv"

        $Primary = @($Data | Where-Object { $_.Name -eq "Amcache.hve" } | Select-Object -First 1)
        if ($Primary.Count -gt 0 -and -not (Test-Path -LiteralPath $Primary[0].CopiedTo)) {
            throw "Primary Amcache.hve acquisition failed after direct copy, registry-save, and VSS fallback attempts"
        }
    }
    finally {
        if ($VssState.ShadowCreated -and $VssState.ShadowId) {
            $DeleteOutput = @(& vssadmin.exe delete shadows "/Shadow=$($VssState.ShadowId)" /Quiet 2>&1 | ForEach-Object { [string]$_ })
            $DeleteExit = $LASTEXITCODE
            $DeleteOutput | Add-Content -Path $VssOutput -Encoding UTF8

            if ($DeleteExit -eq 0) {
                Write-Log $Status "VSS_CLEANUP_OK | ShadowID=$($VssState.ShadowId)"
            }
            else {
                Write-Log $Status "VSS_CLEANUP_FAILED | ShadowID=$($VssState.ShadowId) | ExitCode=$DeleteExit"
                throw "Temporary VSS shadow copy cleanup failed | ShadowID=$($VssState.ShadowId) | ExitCode=$DeleteExit"
            }
        }
    }
}

function Collect-SRUM {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\SRUM"
    $SourceRoot = "C:\Windows\System32\sru"
    New-Dir $Out

    $Csv = Join-Path $Out "SRUM_File_Inventory.csv"
    $HashTxt = Join-Path $Out "SRUM_SHA256.txt"
    $Status = Join-Path $Out "SRUM_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "SRUM Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path $SourceRoot)) {
        Write-Log $Status "SKIPPED | Source folder not found | $SourceRoot"
        Export-List $Data $Csv "No SRUM source folder found"
        return
    }

    $Files = @(Get-ChildItem -Path $SourceRoot -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "SRUDB.dat*" })

    foreach ($File in $Files) {
        $Dest = Join-Path $Out $File.Name
        $Copy = Copy-Artifact $File.FullName $Dest $HashTxt
        $Method = "Copy-Item"
        $CopyStatus = $Copy.CopyStatus
        $Hash = $Copy.SHA256

        if ($CopyStatus -like "Copy failed:*") {
            $Method = "esentutl /y"
            $EsentOutputFile = Join-Path $Out "SRUM_Esentutl_$((Safe-Name $File.Name)).txt"
            $EsentOutput = @(& esentutl.exe /y $File.FullName "/d$Dest" /o 2>&1 | ForEach-Object { [string]$_ })
            $EsentExit = $LASTEXITCODE
            $EsentOutput | Set-Content -Path $EsentOutputFile -Encoding UTF8

            if ($EsentExit -eq 0 -and (Test-Path -LiteralPath $Dest)) {
                $CopyStatus = "Collected via esentutl /y"
                $Hash = Hash-File -Path $Dest -HashFile $HashTxt
                Write-Log $Status "FALLBACK_OK | $($File.Name) | Method=esentutl /y | $Dest"
            }
            else {
                $CopyStatus = "$CopyStatus | esentutl /y failed with exit code $EsentExit"
                Write-Log $Status "FALLBACK_FAILED | $($File.Name) | Method=esentutl /y | ExitCode=$EsentExit"
            }
        }

        $Data.Add([PSCustomObject]@{
            SourcePath=$File.FullName; CopiedTo=$Dest; CopyStatus=$CopyStatus; CollectionMethod=$Method
            Name=$File.Name; Length=$File.Length; CreationTime=$File.CreationTime; LastWriteTime=$File.LastWriteTime
            LastAccessTime=$File.LastAccessTime; SHA256=$Hash
        })
    }

    Export-List $Data $Csv "No files matched SRUDB.dat* under $SourceRoot"
    Write-Log $Status "EXPORTED | SRUM inventory | Rows=$($Data.Count) | $Csv"
}

function Collect-UserHives {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\User_Hives"
    New-Dir $Out
    $Csv = Join-Path $Out "User_Hives_Inventory.csv"
    $HashTxt = Join-Path $Out "User_Hives_SHA256.txt"
    $Status = Join-Path $Out "User_Hives_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "User Hive Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]

    $Profiles = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $Props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($Props.ProfileImagePath -and $Props.ProfileImagePath -like "C:\Users\*") {
                [PSCustomObject]@{
                    SID=$_.PSChildName; ProfilePath=$Props.ProfileImagePath; UserName=(Split-Path $Props.ProfileImagePath -Leaf)
                }
            }
        } | Where-Object { $_.UserName -notin @("Public","Default","Default User","All Users","defaultuser0") }

    foreach ($Profile in $Profiles) {
        $UserOut = Join-Path $Out (Safe-Name $Profile.UserName)
        New-Dir $UserOut

        $Items = @(
            [PSCustomObject]@{
                Label="NTUSER"; Source=(Join-Path $Profile.ProfilePath "NTUSER.DAT")
                Hive="HKU\$($Profile.SID)"; RegPath="Registry::HKEY_USERS\$($Profile.SID)"
                Dest=(Join-Path $UserOut "NTUSER.DAT")
            },
            [PSCustomObject]@{
                Label="UsrClass"; Source=(Join-Path $Profile.ProfilePath "AppData\Local\Microsoft\Windows\UsrClass.dat")
                Hive="HKU\$($Profile.SID)_Classes"; RegPath="Registry::HKEY_USERS\$($Profile.SID)_Classes"
                Dest=(Join-Path $UserOut "UsrClass.dat")
            }
        )

        foreach ($Item in $Items) {
            $Method = $null; $CollectStatus = $null; $Hash = $null

            if (Test-Path $Item.RegPath) {
                $Method = "reg save"
                $StdOut = Join-Path $UserOut "$($Item.Label)_reg_save_stdout.txt"
                $StdErr = Join-Path $UserOut "$($Item.Label)_reg_save_stderr.txt"

                $Proc = Start-Process -FilePath "reg.exe" `
                    -ArgumentList @("save", $Item.Hive, $Item.Dest, "/y") `
                    -Wait -PassThru -WindowStyle Hidden `
                    -RedirectStandardOutput $StdOut `
                    -RedirectStandardError $StdErr

                if ($Proc.ExitCode -eq 0 -and (Test-Path $Item.Dest)) { $CollectStatus = "Collected" }
                else { $CollectStatus = "reg save failed with exit code $($Proc.ExitCode)" }
            }
            elseif (Test-Path $Item.Source) {
                $Method = "Copy-Item"
                $Copy = Copy-Artifact $Item.Source $Item.Dest $HashTxt
                $CollectStatus = $Copy.CopyStatus
                $Hash = $Copy.SHA256
            }
            else {
                $Method = "Not found"
                $CollectStatus = "Source not found"
            }

            if ((Test-Path $Item.Dest) -and -not $Hash) {
                $Hash = Hash-File $Item.Dest $HashTxt
            }

            $Data.Add([PSCustomObject]@{
                UserName=$Profile.UserName; SID=$Profile.SID; Artifact=$Item.Label; SourceFile=$Item.Source
                DestinationFile=$Item.Dest; CollectionMethod=$Method; CollectionStatus=$CollectStatus; SHA256=$Hash
            })
        }
    }

    Export-List $Data $Csv "No user hives found"
    Write-Log $Status "EXPORTED | User hive inventory | $Csv"
}

function Collect-RecentFiles {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\Recent_Files"
    $CopyRoot = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\Collected_Recent_Files"
    New-Dir $Out
    New-Dir $CopyRoot

    $Csv = Join-Path $Out "Recent_Files_Inventory.csv"
    $HashTxt = Join-Path $Out "Recent_Files_SHA256.txt"
    $Status = Join-Path $Out "Recent_Files_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "Recent Files Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]

    foreach ($UserDir in Get-Users) {
        $User = $UserDir.Name
        $Recent = Join-Path $UserDir.FullName "AppData\Roaming\Microsoft\Windows\Recent"
        if (Test-Path $Recent) {
            $UserCopy = Join-Path $CopyRoot (Safe-Name $User)
            New-Dir $UserCopy
            Get-ChildItem -Path $Recent -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
                $Dest = Join-Path $UserCopy $_.Name
                $Copy = Copy-Artifact $_.FullName $Dest $HashTxt
                $Data.Add([PSCustomObject]@{
                    UserName=$User; SourcePath=$_.FullName; CopiedTo=$Dest; CopyStatus=$Copy.CopyStatus; Name=$_.Name
                    Extension=$_.Extension; Length=$_.Length; CreationTime=$_.CreationTime; LastWriteTime=$_.LastWriteTime
                    LastAccessTime=$_.LastAccessTime; Attributes=$_.Attributes; SHA256=$Copy.SHA256
                })
            }
        }
        else {
            $Data.Add([PSCustomObject]@{
                UserName=$User; SourcePath=$Recent; CopiedTo=$null; CopyStatus="Recent folder not found"; Name=$null
                Extension=$null; Length=$null; CreationTime=$null; LastWriteTime=$null; LastAccessTime=$null; Attributes=$null; SHA256=$null
            })
        }
    }

    Export-List $Data $Csv "No recent files found"
    Write-Log $Status "EXPORTED | Recent files inventory | $Csv"
}

function Collect-JumpLists {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\Jump_Lists"
    $AutoRoot = Join-Path $Out "AutomaticDestinations"
    $CustomRoot = Join-Path $Out "CustomDestinations"
    New-Dir $Out
    New-Dir $AutoRoot
    New-Dir $CustomRoot

    $Csv = Join-Path $Out "Jump_Lists_Inventory.csv"
    $HashTxt = Join-Path $Out "Jump_Lists_SHA256.txt"
    $Status = Join-Path $Out "Jump_Lists_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "Jump Lists Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]

    foreach ($UserDir in Get-Users) {
        $User = $UserDir.Name
        $SafeUser = Safe-Name $User
        $Locations = @(
            [PSCustomObject]@{Type="AutomaticDestinations"; Source=(Join-Path $UserDir.FullName "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"); DestRoot=(Join-Path $AutoRoot $SafeUser)},
            [PSCustomObject]@{Type="CustomDestinations"; Source=(Join-Path $UserDir.FullName "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"); DestRoot=(Join-Path $CustomRoot $SafeUser)}
        )
        foreach ($Loc in $Locations) {
            New-Dir $Loc.DestRoot
            if (Test-Path $Loc.Source) {
                Get-ChildItem -Path $Loc.Source -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $Dest = Join-Path $Loc.DestRoot $_.Name
                    $Copy = Copy-Artifact $_.FullName $Dest $HashTxt
                    $Data.Add([PSCustomObject]@{
                        UserName=$User; ArtifactType=$Loc.Type; SourcePath=$_.FullName; CopiedTo=$Dest; CopyStatus=$Copy.CopyStatus
                        Name=$_.Name; Extension=$_.Extension; Length=$_.Length; CreationTime=$_.CreationTime; LastWriteTime=$_.LastWriteTime
                        LastAccessTime=$_.LastAccessTime; Attributes=$_.Attributes; SHA256=$Copy.SHA256
                    })
                }
            }
            else {
                $Data.Add([PSCustomObject]@{
                    UserName=$User; ArtifactType=$Loc.Type; SourcePath=$Loc.Source; CopiedTo=$null; CopyStatus="Source folder not found"
                    Name=$null; Extension=$null; Length=$null; CreationTime=$null; LastWriteTime=$null; LastAccessTime=$null; Attributes=$null; SHA256=$null
                })
            }
        }
    }

    Export-List $Data $Csv "No jump list artifacts found"
    Write-Log $Status "EXPORTED | Jump lists inventory | $Csv"
}

function Collect-UserFileMetadata {
    $Out = Join-Path $EvidenceRoot "05_Execution_Access_Artifacts\User_File_Metadata"
    New-Dir $Out
    $Csv = Join-Path $Out "User_File_Metadata.csv"
    $Hits = Join-Path $Out "User_File_Metadata_Suspicious_Name_Hits.csv"
    $Status = Join-Path $Out "User_File_Metadata_Collection_Status.txt"
    "User File Metadata Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]
    $Relative = @("Desktop","Downloads","Documents","Pictures")

    foreach ($UserDir in Get-Users) {
        foreach ($Rel in $Relative) {
            $Target = Join-Path $UserDir.FullName $Rel
            if (Test-Path $Target) {
                Get-ChildItem -Path $Target -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $Data.Add([PSCustomObject]@{
                        UserName=$UserDir.Name; Category=$Rel; FullName=$_.FullName; DirectoryName=$_.DirectoryName; Name=$_.Name
                        Extension=$_.Extension; Length=$_.Length; CreationTime=$_.CreationTime; LastWriteTime=$_.LastWriteTime
                        LastAccessTime=$_.LastAccessTime; Attributes=$_.Attributes
                    })
                }
            }
            else {
                $Data.Add([PSCustomObject]@{
                    UserName=$UserDir.Name; Category=$Rel; FullName=$Target; DirectoryName=$null; Name=$null
                    Extension=$null; Length=$null; CreationTime=$null; LastWriteTime=$null; LastAccessTime=$null; Attributes="Path not found"
                })
            }
        }
    }

    Export-List $Data $Csv "No user file metadata found"
    $Terms = "SC_AutoFix|ScreenConnect|ConnectWise|ClientSetup|AnyDesk|TeamViewer|Splashtop|RustDesk|GoTo|LogMeIn|Atera|Syncro|\.ps1$|\.bat$|\.cmd$|\.vbs$|\.js$|\.jse$|\.wsf$|\.hta$|\.exe$|\.dll$|\.msi$|\.zip$|\.7z$|\.rar$"
    $Data | Where-Object { $_.FullName -match $Terms -or $_.Name -match $Terms } | Export-Csv -Path $Hits -NoTypeInformation

    Write-Log $Status "EXPORTED | User file metadata | $Csv"
}

# ============================================================
# 06_Browser_SaaS_Artifacts
# ============================================================

function Copy-BrowserArtifact {
    param(
        [string]$Browser,
        [string]$UserName,
        [string]$ProfileName,
        [string]$ArtifactName,
        [string]$SourcePath,
        [string]$DestinationRoot,
        [System.Collections.Generic.List[object]]$Inventory,
        [string]$HashFile
    )

    $DestDir = Join-Path $DestinationRoot "$(Safe-Name $UserName)\$(Safe-Name $ProfileName)"
    New-Dir $DestDir
    $Dest = Join-Path $DestDir (Safe-Name $ArtifactName)

    if (-not (Test-Path $SourcePath)) {
        $Inventory.Add([PSCustomObject]@{
            Browser=$Browser; UserName=$UserName; Profile=$ProfileName; Artifact=$ArtifactName; SourcePath=$SourcePath
            CopiedTo=$Dest; CopyStatus="SKIPPED | Source not found"; Length=$null; CreationTime=$null; LastWriteTime=$null
            LastAccessTime=$null; SHA256=$null
        })
        return
    }

    $Item = Get-Item $SourcePath -Force
    $Copy = Copy-Artifact $SourcePath $Dest $HashFile
    $Inventory.Add([PSCustomObject]@{
        Browser=$Browser; UserName=$UserName; Profile=$ProfileName; Artifact=$ArtifactName; SourcePath=$SourcePath
        CopiedTo=$Dest; CopyStatus=$Copy.CopyStatus; Length=$Item.Length; CreationTime=$Item.CreationTime
        LastWriteTime=$Item.LastWriteTime; LastAccessTime=$Item.LastAccessTime; SHA256=$Copy.SHA256
    })
}

function Collect-ChromiumBrowser {
    param([string]$Browser, [string]$RelativeUserDataPath)

    $Out = Join-Path $EvidenceRoot "06_Browser_SaaS_Artifacts\$Browser"
    $CopyRoot = Join-Path $Out "Collected_Files"
    New-Dir $Out
    New-Dir $CopyRoot

    $Csv = Join-Path $Out "$($Browser)_Artifact_Inventory.csv"
    $HashTxt = Join-Path $Out "$($Browser)_Artifacts_SHA256.txt"
    $Status = Join-Path $Out "$($Browser)_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "$Browser Artifact Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Inventory = New-Object System.Collections.Generic.List[object]

    foreach ($UserDir in Get-Users) {
        $User = $UserDir.Name
        $Root = Join-Path $UserDir.FullName $RelativeUserDataPath

        if (-not (Test-Path $Root)) {
            $Inventory.Add([PSCustomObject]@{
                Browser=$Browser; UserName=$User; Profile=$null; Artifact="User Data root"; SourcePath=$Root; CopiedTo=$null
                CopyStatus="SKIPPED | Browser user data root not found"; Length=$null; CreationTime=$null; LastWriteTime=$null
                LastAccessTime=$null; SHA256=$null
            })
            continue
        }

        Copy-BrowserArtifact $Browser $User "Root" "Local State" (Join-Path $Root "Local State") $CopyRoot $Inventory $HashTxt

        $Profiles = Get-ChildItem -Path $Root -Directory | Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" }
        foreach ($Profile in $Profiles) {
            $Artifacts = @(
                "History","Cookies","Network\Cookies","Login Data","Web Data","Preferences","Secure Preferences","Bookmarks",
                "Current Session","Current Tabs","Last Session","Last Tabs"
            )
            foreach ($Artifact in $Artifacts) {
                Copy-BrowserArtifact $Browser $User $Profile.Name $Artifact (Join-Path $Profile.FullName $Artifact) $CopyRoot $Inventory $HashTxt
            }

            $Sessions = Join-Path $Profile.FullName "Sessions"
            if (Test-Path $Sessions) {
                Get-ChildItem -Path $Sessions -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Copy-BrowserArtifact $Browser $User $Profile.Name "Sessions\$($_.Name)" $_.FullName $CopyRoot $Inventory $HashTxt
                }
            }
        }
    }

    Export-List $Inventory $Csv "No $Browser artifacts found"
    Write-Log $Status "EXPORTED | $Browser artifact inventory | $Csv"
}

function Collect-FirefoxBrowser {
    $Browser = "Firefox"
    $Out = Join-Path $EvidenceRoot "06_Browser_SaaS_Artifacts\Firefox"
    $CopyRoot = Join-Path $Out "Collected_Files"
    New-Dir $Out
    New-Dir $CopyRoot

    $Csv = Join-Path $Out "Firefox_Artifact_Inventory.csv"
    $HashTxt = Join-Path $Out "Firefox_Artifacts_SHA256.txt"
    $Status = Join-Path $Out "Firefox_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "Firefox Artifact Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Inventory = New-Object System.Collections.Generic.List[object]
    $Artifacts = @(
        "places.sqlite","cookies.sqlite","logins.json","key4.db","cert9.db","permissions.sqlite","formhistory.sqlite",
        "webappsstore.sqlite","prefs.js","handlers.json","extensions.json","addons.json","sessionstore.jsonlz4"
    )

    foreach ($UserDir in Get-Users) {
        $User = $UserDir.Name
        $ProfilesRoot = Join-Path $UserDir.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"

        if (-not (Test-Path $ProfilesRoot)) {
            $Inventory.Add([PSCustomObject]@{
                Browser="Firefox"; UserName=$User; Profile=$null; Artifact="Firefox Profiles root"; SourcePath=$ProfilesRoot
                CopiedTo=$null; CopyStatus="SKIPPED | Firefox profiles root not found"; Length=$null; CreationTime=$null
                LastWriteTime=$null; LastAccessTime=$null; SHA256=$null
            })
            continue
        }

        Get-ChildItem -Path $ProfilesRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $Profile = $_
            foreach ($Artifact in $Artifacts) {
                Copy-BrowserArtifact "Firefox" $User $Profile.Name $Artifact (Join-Path $Profile.FullName $Artifact) $CopyRoot $Inventory $HashTxt
            }

            $Backups = Join-Path $Profile.FullName "sessionstore-backups"
            if (Test-Path $Backups) {
                Get-ChildItem -Path $Backups -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Copy-BrowserArtifact "Firefox" $User $Profile.Name "sessionstore-backups\$($_.Name)" $_.FullName $CopyRoot $Inventory $HashTxt
                }
            }
        }
    }

    Export-List $Inventory $Csv "No Firefox artifacts found"
    Write-Log $Status "EXPORTED | Firefox artifact inventory | $Csv"
}

function Collect-BrowserExtensionInventory {
    $Out = Join-Path $EvidenceRoot "06_Browser_SaaS_Artifacts\Extension_Inventory"
    $ManifestRoot = Join-Path $Out "Collected_Manifests"
    New-Dir $Out
    New-Dir $ManifestRoot

    $Csv = Join-Path $Out "Browser_Extension_Inventory.csv"
    $HashTxt = Join-Path $Out "Browser_Extension_Manifest_SHA256.txt"
    $Status = Join-Path $Out "Browser_Extension_Inventory_Status.txt"
    "" | Set-Content $HashTxt
    "Browser Extension Inventory - $(Get-Date -Format s)" | Set-Content $Status

    $Results = New-Object System.Collections.Generic.List[object]

    function Add-ChromiumExt {
        param([string]$Browser, [string]$RelativeUserDataPath)

        foreach ($UserDir in Get-Users) {
            $User = $UserDir.Name
            $Root = Join-Path $UserDir.FullName $RelativeUserDataPath
            if (-not (Test-Path $Root)) {
                $Results.Add([PSCustomObject]@{
                    Browser=$Browser; UserName=$User; Profile=$null; ExtensionId=$null; ExtensionFolderVer=$null
                    ManifestName=$null; ManifestVersion=$null; ManifestDescription=$null; SourcePath=$Root; CopiedTo=$null
                    Status="SKIPPED | Browser user data root not found"; SHA256=$null
                })
                continue
            }

            Get-ChildItem -Path $Root -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" } |
                ForEach-Object {
                    $Profile = $_
                    $ExtRoot = Join-Path $Profile.FullName "Extensions"
                    if (-not (Test-Path $ExtRoot)) {
                        $Results.Add([PSCustomObject]@{
                            Browser=$Browser; UserName=$User; Profile=$Profile.Name; ExtensionId=$null; ExtensionFolderVer=$null
                            ManifestName=$null; ManifestVersion=$null; ManifestDescription=$null; SourcePath=$ExtRoot; CopiedTo=$null
                            Status="SKIPPED | Extensions folder not found"; SHA256=$null
                        })
                        return
                    }

                    Get-ChildItem -Path $ExtRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $ExtId = $_.Name
                        Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                            $Ver = $_.Name
                            $Manifest = Join-Path $_.FullName "manifest.json"
                            if (Test-Path $Manifest) {
                                $DestDir = Join-Path $ManifestRoot "$Browser\$(Safe-Name $User)\$(Safe-Name $Profile.Name)\$ExtId\$Ver"
                                $Dest = Join-Path $DestDir "manifest.json"
                                $Copy = Copy-Artifact $Manifest $Dest $HashTxt

                                $MName = $null; $MVer = $null; $MDesc = $null
                                try {
                                    $Json = Get-Content -Path $Dest -Raw -ErrorAction Stop | ConvertFrom-Json
                                    $MName = $Json.name
                                    $MVer = $Json.version
                                    $MDesc = $Json.description
                                } catch {}

                                $Results.Add([PSCustomObject]@{
                                    Browser=$Browser; UserName=$User; Profile=$Profile.Name; ExtensionId=$ExtId; ExtensionFolderVer=$Ver
                                    ManifestName=$MName; ManifestVersion=$MVer; ManifestDescription=$MDesc; SourcePath=$Manifest; CopiedTo=$Dest
                                    Status=$Copy.CopyStatus; SHA256=$Copy.SHA256
                                })
                            }
                        }
                    }
                }
        }
    }

    function Add-FirefoxExt {
        foreach ($UserDir in Get-Users) {
            $User = $UserDir.Name
            $ProfilesRoot = Join-Path $UserDir.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
            if (-not (Test-Path $ProfilesRoot)) {
                $Results.Add([PSCustomObject]@{
                    Browser="Firefox"; UserName=$User; Profile=$null; ExtensionId=$null; ExtensionFolderVer=$null
                    ManifestName=$null; ManifestVersion=$null; ManifestDescription=$null; SourcePath=$ProfilesRoot; CopiedTo=$null
                    Status="SKIPPED | Firefox profiles root not found"; SHA256=$null
                })
                continue
            }

            Get-ChildItem -Path $ProfilesRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $Profile = $_
                $ExtJson = Join-Path $Profile.FullName "extensions.json"

                if (Test-Path $ExtJson) {
                    $Hash = Hash-File $ExtJson $HashTxt
                    try {
                        $Json = Get-Content -Path $ExtJson -Raw -ErrorAction Stop | ConvertFrom-Json
                        foreach ($Addon in $Json.addons) {
                            $Results.Add([PSCustomObject]@{
                                Browser="Firefox"; UserName=$User; Profile=$Profile.Name; ExtensionId=$Addon.id; ExtensionFolderVer=$null
                                ManifestName=$Addon.defaultLocale.name; ManifestVersion=$Addon.version; ManifestDescription=$Addon.defaultLocale.description
                                SourcePath=$ExtJson; CopiedTo=$null; Status="Parsed from extensions.json"; SHA256=$Hash
                            })
                        }
                    }
                    catch {
                        $Results.Add([PSCustomObject]@{
                            Browser="Firefox"; UserName=$User; Profile=$Profile.Name; ExtensionId=$null; ExtensionFolderVer=$null
                            ManifestName=$null; ManifestVersion=$null; ManifestDescription=$null; SourcePath=$ExtJson; CopiedTo=$null
                            Status="extensions.json parse failed: $($_.Exception.Message)"; SHA256=$Hash
                        })
                    }
                }
                else {
                    $Results.Add([PSCustomObject]@{
                        Browser="Firefox"; UserName=$User; Profile=$Profile.Name; ExtensionId=$null; ExtensionFolderVer=$null
                        ManifestName=$null; ManifestVersion=$null; ManifestDescription=$null; SourcePath=$ExtJson; CopiedTo=$null
                        Status="SKIPPED | extensions.json not found"; SHA256=$null
                    })
                }
            }
        }
    }

    Add-ChromiumExt "Chrome" "AppData\Local\Google\Chrome\User Data"
    Add-ChromiumExt "Edge" "AppData\Local\Microsoft\Edge\User Data"
    Add-FirefoxExt

    Export-List $Results $Csv "No browser extension inventory rows returned"
    Write-Log $Status "EXPORTED | Browser extension inventory | $Csv"
}

# ============================================================
# 07_Remote_Access_Tools
# ============================================================

function Collect-RemoteAccessTools {
    $Out = Join-Path $EvidenceRoot "07_Remote_Access_Tools"
    $Collected = Join-Path $Out "Collected_Logs_Config"
    New-Dir $Out
    New-Dir $Collected

    $SoftwareCsv = Join-Path $Out "Remote_Access_Installed_Software.csv"
    $ServicesCsv = Join-Path $Out "Remote_Access_Services.csv"
    $ProcessesCsv = Join-Path $Out "Remote_Access_Processes.csv"
    $NetworkCsv = Join-Path $Out "Remote_Access_Network_Connections.csv"
    $FilesCsv = Join-Path $Out "Remote_Access_File_Metadata.csv"
    $CollectedCsv = Join-Path $Out "Remote_Access_Collected_Log_Config_Inventory.csv"
    $HashTxt = Join-Path $Out "Remote_Access_Collected_Log_Config_SHA256.txt"
    $Status = Join-Path $Out "Remote_Access_Collection_Status.txt"
    "" | Set-Content $HashTxt
    "Remote Access Tool Collection - $(Get-Date -Format s)" | Set-Content $Status

    $Pattern = "ScreenConnect|ConnectWise|Control\.Client|ClientSetup|Datto|CentraStage|CagService|AEMAgent|GoTo|GoToMyPC|LogMeIn|LMI|GoToAssist|AnyDesk|TeamViewer|Splashtop|SRManager|SplashtopRemote|RustDesk|Chrome Remote Desktop|remoting_host|chromoting|Atera|Syncro|SyncroLive|NinjaOne|NinjaRMM|NinjaRMMAgent|NinjaRemote"

    $Software = New-Object System.Collections.Generic.List[object]
    $Services = New-Object System.Collections.Generic.List[object]
    $Processes = New-Object System.Collections.Generic.List[object]
    $Network = New-Object System.Collections.Generic.List[object]
    $Files = New-Object System.Collections.Generic.List[object]
    $CopiedLogs = New-Object System.Collections.Generic.List[object]

    $UninstallPaths = @(
        "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
        $UninstallPaths += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }

    foreach ($Path in $UninstallPaths) {
        Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
            $Combined = "$($_.DisplayName) $($_.Publisher) $($_.InstallLocation) $($_.UninstallString) $($_.QuietUninstallString)"
            if ($Combined -match $Pattern) {
                $Software.Add([PSCustomObject]@{
                    DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion; Publisher=$_.Publisher; InstallDate=$_.InstallDate
                    InstallLocation=$_.InstallLocation; UninstallString=$_.UninstallString; QuietUninstall=$_.QuietUninstallString; RegistryPath=$_.PSPath
                })
            }
        }
    }

    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $Combined = "$($_.Name) $($_.DisplayName) $($_.PathName) $($_.StartName) $($_.Description)"
        if ($Combined -match $Pattern) {
            $Services.Add([PSCustomObject]@{
                Name=$_.Name; DisplayName=$_.DisplayName; State=$_.State; StartMode=$_.StartMode; StartName=$_.StartName
                PathName=$_.PathName; ProcessId=$_.ProcessId; Description=$_.Description
            })
        }
    }

    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $Combined = "$($_.Name) $($_.ExecutablePath) $($_.CommandLine)"
        if ($Combined -match $Pattern) {
            $Processes.Add([PSCustomObject]@{
                Name=$_.Name; ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; CreationDate=$_.CreationDate
                ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine; SessionId=$_.SessionId
            })
        }
    }

    $MatchedPids = @($Processes | Select-Object -ExpandProperty ProcessId -Unique)

    Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $MatchedPids -contains $_.OwningProcess } | ForEach-Object {
        $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $Network.Add([PSCustomObject]@{
            Protocol="TCP"; LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort
            State=$_.State; OwningProcess=$_.OwningProcess; ProcessName=$Proc.ProcessName; ProcessPath=$Proc.Path
        })
    }

    Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $MatchedPids -contains $_.OwningProcess } | ForEach-Object {
        $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $Network.Add([PSCustomObject]@{
            Protocol="UDP"; LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; RemoteAddress=$null; RemotePort=$null
            State=$null; OwningProcess=$_.OwningProcess; ProcessName=$Proc.ProcessName; ProcessPath=$Proc.Path
        })
    }

    $SearchRoots = New-Object System.Collections.Generic.List[string]
    @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, "C:\Windows\Temp", "C:\Temp") |
        Where-Object { $_ -and (Test-Path $_) } | ForEach-Object { $SearchRoots.Add($_) }

    Get-Users | ForEach-Object {
        @(
            (Join-Path $_.FullName "AppData\Local\Temp"),
            (Join-Path $_.FullName "Downloads"),
            (Join-Path $_.FullName "Desktop")
        ) | Where-Object { Test-Path $_ } | ForEach-Object { $SearchRoots.Add($_) }
    }

    $SearchRoots = @($SearchRoots | Select-Object -Unique)

    foreach ($Root in $SearchRoots) {
        Get-ChildItem -Path $Root -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $Combined = "$($_.Name) $($_.FullName)"
            if ($Combined -match $Pattern) {
                $IsFile = -not $_.PSIsContainer
                $Hash = $null
                if ($IsFile -and $_.Length -le 100MB) {
                    try { $Hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $Hash = "Hash failed" }
                }

                $Files.Add([PSCustomObject]@{
                    Root=$Root; FullName=$_.FullName; Name=$_.Name; ItemType=if ($_.PSIsContainer) {"Directory"} else {"File"}
                    Extension=if ($IsFile) {$_.Extension} else {$null}; Length=if ($IsFile) {$_.Length} else {$null}
                    CreationTime=$_.CreationTime; LastWriteTime=$_.LastWriteTime; LastAccessTime=$_.LastAccessTime
                    Attributes=$_.Attributes; SHA256=$Hash
                })

                if ($IsFile -and $_.Length -le 25MB -and $_.Extension -match "\.log|\.txt|\.config|\.json|\.xml|\.ini|\.csv") {
                    $SafeRel = Safe-Name ($_.FullName -replace "^[A-Za-z]:\\","")
                    $Dest = Join-Path $Collected $SafeRel
                    $Copy = Copy-Artifact $_.FullName $Dest $HashTxt
                    $CopiedLogs.Add([PSCustomObject]@{
                        SourcePath=$_.FullName; CopiedTo=$Dest; CopyStatus=$Copy.CopyStatus; Name=$_.Name; Extension=$_.Extension
                        Length=$_.Length; CreationTime=$_.CreationTime; LastWriteTime=$_.LastWriteTime; LastAccessTime=$_.LastAccessTime; SHA256=$Copy.SHA256
                    })
                }
            }
        }
    }

    Export-List $Software $SoftwareCsv "No remote access installed software matches found"
    Export-List $Services $ServicesCsv "No remote access service matches found"
    Export-List $Processes $ProcessesCsv "No remote access running process matches found"
    Export-List $Network $NetworkCsv "No remote access network connections found for matched processes"
    Export-List $Files $FilesCsv "No remote access file/path metadata matches found"
    Export-List $CopiedLogs $CollectedCsv "No remote access log/config files copied"

    Write-Log $Status "EXPORTED | Remote access installed software | $SoftwareCsv"
    Write-Log $Status "EXPORTED | Remote access services | $ServicesCsv"
    Write-Log $Status "EXPORTED | Remote access processes | $ProcessesCsv"
    Write-Log $Status "EXPORTED | Remote access network connections | $NetworkCsv"
    Write-Log $Status "EXPORTED | Remote access file metadata | $FilesCsv"
    Write-Log $Status "EXPORTED | Remote access collected log/config inventory | $CollectedCsv"
}

# ============================================================
# 08_Manifest_Hashes
# ============================================================

function Collect-ManifestHashes {
    $Out = Join-Path $EvidenceRoot "08_Manifest_Hashes"
    New-Dir $Out
    $Csv = Join-Path $Out "Evidence_File_Manifest.csv"
    $HashTxt = Join-Path $Out "Evidence_File_Manifest_SHA256.txt"
    $Status = Join-Path $Out "Evidence_Manifest_Status.txt"
    "" | Set-Content $HashTxt
    "Evidence Manifest - $(Get-Date -Format s)" | Set-Content $Status

    $Data = New-Object System.Collections.Generic.List[object]
    $Files = Get-ChildItem -Path $EvidenceRoot -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike "*\08_Manifest_Hashes\*" }

    foreach ($File in $Files) {
        $Hash = $null
        $HashStatus = "Hashed"
        try {
            $Hash = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            "$Hash  $($File.FullName)" | Add-Content $HashTxt
        }
        catch { $HashStatus = "Hash failed: $($_.Exception.Message)" }

        $Data.Add([PSCustomObject]@{
            FullName=$File.FullName; DirectoryName=$File.DirectoryName; Name=$File.Name; Extension=$File.Extension
            Length=$File.Length; CreationTime=$File.CreationTime; LastWriteTime=$File.LastWriteTime
            LastAccessTime=$File.LastAccessTime; Attributes=$File.Attributes; SHA256=$Hash; HashStatus=$HashStatus
        })
    }

    Export-List $Data $Csv "No evidence files found"
    Write-Log $Status "EXPORTED | Evidence file manifest | $Csv"
    Write-Log $Status "EXPORTED | Evidence file hashes | $HashTxt"
}

# ============================================================
# Main
# ============================================================

$Collectors = @(
    @{Name="03_Windows_Event_Logs"; Block={ Collect-WindowsEventLogs }},

    @{Name="04_System_Persistence\Running_Processes"; Block={ Collect-RunningProcesses }},
    @{Name="04_System_Persistence\Services"; Block={ Collect-Services }},
    @{Name="04_System_Persistence\Scheduled_Tasks"; Block={ Collect-ScheduledTasks }},
    @{Name="04_System_Persistence\Startup_Items"; Block={ Collect-StartupItems }},
    @{Name="04_System_Persistence\Installed_Software"; Block={ Collect-InstalledSoftware }},
    @{Name="04_System_Persistence\Local_Users"; Block={ Collect-LocalUsers }},
    @{Name="04_System_Persistence\Local_Admins"; Block={ Collect-LocalAdmins }},
    @{Name="04_System_Persistence\Firewall_Rules"; Block={ Collect-FirewallRules }},
    @{Name="04_System_Persistence\Network_State"; Block={ Collect-NetworkState }},
    @{Name="04_System_Persistence\WMI_Persistence"; Block={ Collect-WMIPersistence }},
    @{Name="04_System_Persistence\Drivers"; Block={ Collect-Drivers }},

    @{Name="05_Execution_Access_Artifacts\Powershell"; Block={ Collect-PowerShellArtifacts }},
    @{Name="05_Execution_Access_Artifacts\Temp_Paths"; Block={ Collect-TempPaths }},
    @{Name="05_Execution_Access_Artifacts\Prefetch"; Block={ Collect-Prefetch }},
    @{Name="05_Execution_Access_Artifacts\Amcache"; Block={ Collect-Amcache }},
    @{Name="05_Execution_Access_Artifacts\SRUM"; Block={ Collect-SRUM }},
    @{Name="05_Execution_Access_Artifacts\User_Hives"; Block={ Collect-UserHives }},
    @{Name="05_Execution_Access_Artifacts\Recent_Files"; Block={ Collect-RecentFiles }},
    @{Name="05_Execution_Access_Artifacts\Jump_Lists"; Block={ Collect-JumpLists }},
    @{Name="05_Execution_Access_Artifacts\User_File_Metadata"; Block={ Collect-UserFileMetadata }},

    @{Name="06_Browser_SaaS_Artifacts\Chrome"; Block={ Collect-ChromiumBrowser -Browser "Chrome" -RelativeUserDataPath "AppData\Local\Google\Chrome\User Data" }},
    @{Name="06_Browser_SaaS_Artifacts\Edge"; Block={ Collect-ChromiumBrowser -Browser "Edge" -RelativeUserDataPath "AppData\Local\Microsoft\Edge\User Data" }},
    @{Name="06_Browser_SaaS_Artifacts\Firefox"; Block={ Collect-FirefoxBrowser }},
    @{Name="06_Browser_SaaS_Artifacts\Extension_Inventory"; Block={ Collect-BrowserExtensionInventory }},

    @{Name="07_Remote_Access_Tools"; Block={ Collect-RemoteAccessTools }}
)

foreach ($Collector in $Collectors) {
    $Name = $Collector.Name
    Write-Host "STARTED | $Name"
    "STARTED | $Name | $(Get-Date -Format s)" | Add-Content $MainStatus

    try {
        & $Collector.Block
        "COMPLETED | $Name | $(Get-Date -Format s)" | Add-Content $MainStatus
        Write-Host "COMPLETED | $Name"
    }
    catch {
        "FAILED | $Name | $($_.Exception.Message)" | Add-Content $MainStatus
        Write-Host "FAILED | $Name | See Endpoint_IR_Collection_Status.txt"
    }
}

# Finalize the main collection status before hashing evidence. The manifest runs
# after this file is complete so no hash-tracked evidence file is modified after
# its SHA256 is recorded.
"DONE | Endpoint IR collection complete | $(Get-Date -Format s)" | Add-Content $MainStatus

Write-Host "STARTED | 08_Manifest_Hashes"
try {
    Collect-ManifestHashes
    Write-Host "COMPLETED | 08_Manifest_Hashes"
}
catch {
    Write-Host "FAILED | 08_Manifest_Hashes | $($_.Exception.Message)"
}

Write-Host "DONE | Endpoint IR collection complete | $EvidenceRoot"