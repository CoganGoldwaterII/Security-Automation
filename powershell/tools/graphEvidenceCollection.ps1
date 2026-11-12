# ============================================================================
# NAME: graphEvidenceCollection_v4.ps1
# AUTHORED BY: Cogan Goldwater
# TYPE: Manual IR Utility / Read-Only Evidence Collection
# SCOPE: Microsoft Graph email-compromise evidence collection, independent of
#        Exchange Online. NinjaOne runs the launcher as SYSTEM, then opens one
#        interactive Graph Email IR - Admin PowerShell console for the technician.
#        -Mode UnitTest performs offline checks without Microsoft authentication.
# VARIABLES: None (NinjaOne). Interactive console prompts for affected mailbox,
#            reference category, incident timestamp (yyyy-MM-dd HHmm, local),
#            and lookback days (default 7).
# OUTPUT TOKENS: RESULT | NO_ACTION | ERROR
# CUSTOM FIELDS: Reads: None; Writes: None
# LOGGING PATH: C:\MME\AutoLogs\MME_Email_IR_Graph_Collection.log
# DESCRIPTION:
#   Standalone Microsoft Graph evidence collector for email incident response.
#   Runs through NinjaOne as SYSTEM with one separate technician Graph console.
#   Uses administrator interactive authentication, not the affected user, and
#   collects Graph identity, authentication methods, OAuth grants, sign-ins,
#   risk detections, directory audit, Conditional Access, and role evidence.
#   Preserves original query scope, HTTP diagnostics, pagination, completeness
#   reporting, SHA-256 evidence manifest, and Graph connection cleanup.
#   No Defender broad hunting, endpoint telemetry, Purview cases/searches/
#   exports, or tenant permission changes. Graph collection remains read-only.
#   Evidence staged under C:\MME\CS; limitations surface as ERROR.
# ============================================================================
param(
    [ValidateSet('Launcher','Bootstrap','GraphAdmin','UnitTest')]
    [string]$Mode='Launcher',
    [string]$CaseRoot
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$Workspace='C:\MME\CS'
$LogRoot='C:\MME\AutoLogs'
$MainLog=Join-Path $LogRoot 'MME_Email_IR_Graph_Collection.log'
$ScriptVersion='2026.11.12-graph-standalone-v4'
$CurrentStage='Initialize'
$FinalOutput=$null
$ScheduledName=$null
$StagedScript=$null
$BootstrapLaunchedWorkers=$false
$WorkerStatusesPresent=$false

function Safe-Text([object]$Value) {
    if ($null -eq $Value) { return '' }
    $S=([string]$Value) -replace '[\r\n|]+',' ' -replace '\s{2,}',' '
    if ($S.Length -gt 850) { $S=$S.Substring(0,850) }
    return $S.Trim()
}
function Ensure-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}
function Write-OperationalLog([string]$Value) {
    try {
        Ensure-Directory $LogRoot
        ('{0} | {1}' -f (Get-Date).ToUniversalTime().ToString('o'),(Safe-Text $Value)) |
            Add-Content -LiteralPath $MainLog -Encoding UTF8
    } catch { }
}
function Write-JsonFile([string]$Path,[object]$Value) {
    $Temp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    $Json=ConvertTo-Json -InputObject $Value -Depth 35 -Compress
    [IO.File]::WriteAllText($Temp,$Json,[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($Temp,$Path)
}
function Make-RestrictedCaseDirectory([string]$Path,[Security.Principal.SecurityIdentifier]$UserSid) {
    Ensure-Directory $Path
    $Acl=New-Object Security.AccessControl.DirectorySecurity
    $Acl.SetAccessRuleProtection($true,$false)
    foreach ($SidString in @('S-1-5-18','S-1-5-32-544',$UserSid.Value)) {
        $Sid=[Security.Principal.SecurityIdentifier]::new($SidString)
        $Rule=[Security.AccessControl.FileSystemAccessRule]::new(
            $Sid,[Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $Acl.AddAccessRule($Rule)
    }
    [IO.Directory]::SetAccessControl($Path,$Acl)
}



# ---------------------- Ninja SYSTEM launcher (Graph ONLY) ------------------
if ($Mode -eq 'Launcher') {
    try {
        $CurrentStage='ValidateSystem'
        if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
            throw 'Ninja must run this automation as SYSTEM.'
        }
        if (-not $PSCommandPath -or -not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
            throw 'Ninja must execute this script from an on-disk PS1 file.'
        }
        $CurrentStage='FindLoggedOnTechnician'
        $DesktopUser=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if (-not $DesktopUser) {
            $FinalOutput='NO_ACTION | No logged-on technician desktop for Microsoft MFA.'
        } else {
            $UserSid=([Security.Principal.NTAccount]$DesktopUser).Translate(
                [Security.Principal.SecurityIdentifier])
            $CurrentStage='CreateCase'
            Ensure-Directory $Workspace
            Ensure-Directory $LogRoot
            $Id=(Get-Date -Format 'ddMMMyyyy_HHmmss')+'_'+[guid]::NewGuid().ToString('N').Substring(0,8)
            $CaseRoot=Join-Path $Workspace ('GraphEmailIR_'+$Id)
            Make-RestrictedCaseDirectory $CaseRoot $UserSid
            $StagedScript=Join-Path $CaseRoot 'graphEvidenceCollection.worker.ps1'
            Copy-Item -LiteralPath $PSCommandPath -Destination $StagedScript -Force
            $CurrentStage='ScheduleInteractiveBootstrap'
            $ScheduledName='MME_GraphEmailIR_'+[guid]::NewGuid().ToString('N')
            $Exe=if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
                Join-Path $env:windir 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
            } else { Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe' }
            $Arguments='-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Mode Bootstrap -CaseRoot "{1}"' -f $StagedScript,$CaseRoot
            $Action=New-ScheduledTaskAction -Execute $Exe -Argument $Arguments
            $Principal=New-ScheduledTaskPrincipal -UserId $DesktopUser -LogonType Interactive
            $Settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
            Register-ScheduledTask -TaskName $ScheduledName -Action $Action -Principal $Principal -Settings $Settings -Force | Out-Null
            Start-ScheduledTask -TaskName $ScheduledName
            Write-OperationalLog "START | GraphStandalone Build=$ScriptVersion Case=$CaseRoot Desktop=$DesktopUser"
            $BootstrapStatus=Join-Path $CaseRoot 'Bootstrap.status.json'
            $CurrentStage='AwaitBootstrap'
            while (-not (Test-Path -LiteralPath $BootstrapStatus -PathType Leaf)) {
                Start-Sleep -Seconds 2
                if (Test-Path -LiteralPath $BootstrapStatus -PathType Leaf) { break }
                $State=Get-ScheduledTask -TaskName $ScheduledName -ErrorAction SilentlyContinue
                $Info=Get-ScheduledTaskInfo -TaskName $ScheduledName -ErrorAction SilentlyContinue
                if ($State -and $State.State -ne 'Running' -and $Info -and
                    $Info.LastRunTime.Year -gt 2000) {
                    Start-Sleep -Seconds 2
                    if (Test-Path -LiteralPath $BootstrapStatus -PathType Leaf) { break }
                    $State=Get-ScheduledTask -TaskName $ScheduledName -ErrorAction SilentlyContinue
                    if ($State -and $State.State -ne 'Running' -and
                        -not (Test-Path -LiteralPath $BootstrapStatus -PathType Leaf)) {
                        throw 'Interactive Graph bootstrap exited before writing its status.'
                    }
                }
            }
            $Boot=Get-Content -LiteralPath $BootstrapStatus -Raw | ConvertFrom-Json
            if ($Boot.Result -ne 'RESULT') { throw ('Graph bootstrap failed: '+(Safe-Text $Boot.Error)) }
            $BootstrapLaunchedWorkers=$true
            if (-not $Boot.Pids.GraphAdmin) { throw 'Bootstrap did not launch GraphAdmin.' }
            $CurrentStage='AwaitGraphCollector'
            $StatusPath=Join-Path $CaseRoot 'GraphAdmin.status.json'
            while (-not (Test-Path -LiteralPath $StatusPath -PathType Leaf)) {
                if (-not (Get-Process -Id ([int]$Boot.Pids.GraphAdmin) -ErrorAction SilentlyContinue)) {
                    if (-not (Test-Path -LiteralPath $StatusPath -PathType Leaf)) {
                        Write-JsonFile $StatusPath ([ordered]@{ Role='GraphAdmin'; Result='ERROR'
                            FatalError='Graph worker exited without saving status.'; Sources=@(); Limitations=@() })
                    }
                }
                Start-Sleep -Seconds 2
            }
            $WorkerStatusesPresent=$true
            $Status=Get-Content -LiteralPath $StatusPath -Raw | ConvertFrom-Json
            $CurrentStage='FingerprintCollectedEvidence'
            $Files=@(Get-ChildItem -LiteralPath $CaseRoot -Recurse -File |
                Where-Object { $_.FullName -ne $StagedScript -and $_.Name -ne 'Evidence_SHA256.json' })
            $Hashes=@(foreach ($F in $Files) {
                [ordered]@{ RelativePath=$F.FullName.Substring($CaseRoot.Length+1)
                    Length=$F.Length; SHA256=(Get-FileHash -LiteralPath $F.FullName -Algorithm SHA256).Hash }
            })
            $Manifest=Join-Path $CaseRoot 'Evidence_SHA256.json'
            Write-JsonFile $Manifest ([ordered]@{
                GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o'); Algorithm='SHA256'; Files=$Hashes
            })
            $Count=@($Status.Limitations).Count
            if ($Status.Result -eq 'RESULT' -and $Count -eq 0) {
                $FinalOutput='RESULT | GRAPH_IR_COLLECTION | GraphAdmin=RESULT Case={0} Manifest={1}' -f $CaseRoot,$Manifest
            } else {
                $FinalOutput='ERROR | Stage=GraphCollection GraphAdmin={0} Limitations={1} PartialEvidence={2} Manifest={3}' -f
                    $Status.Result,$Count,$CaseRoot,$Manifest
            }
        }
    } catch {
        $FinalOutput='ERROR | Stage={0} Error={1} Case={2}' -f $CurrentStage,(Safe-Text $_.Exception.Message),$CaseRoot
    } finally {
        if ($ScheduledName) {
            try { Unregister-ScheduledTask -TaskName $ScheduledName -Confirm:$false -ErrorAction Stop }
            catch { Write-OperationalLog ('TASK_CLEANUP_ERROR | '+(Safe-Text $_.Exception.Message)) }
        }
        if ($StagedScript -and (Test-Path -LiteralPath $StagedScript)) {
            if ((-not $BootstrapLaunchedWorkers) -or $WorkerStatusesPresent) {
                try { Remove-Item -LiteralPath $StagedScript -Force -ErrorAction Stop }
                catch { Write-OperationalLog ('STAGED_SCRIPT_CLEANUP_ERROR | '+(Safe-Text $_.Exception.Message)) }
            } else { Write-OperationalLog 'STAGED_SCRIPT_RETAINED | Graph worker status incomplete.' }
        }
        if (-not $FinalOutput) { $FinalOutput='ERROR | Stage=Finalize Error=No launcher result.' }
        Write-OperationalLog $FinalOutput
        Write-Output $FinalOutput
        exit 0
    }
}

# ----------------- Hidden bootstrap, starts ONE Graph shell -----------------
if ($Mode -eq 'Bootstrap') {
    $BootstrapStatus=Join-Path $CaseRoot 'Bootstrap.status.json'
    try {
        $CurrentStage='VerifyTechnicianCaseFolderAccess'
        $AccessProbe=Join-Path $CaseRoot ('access_probe_'+[guid]::NewGuid().ToString('N')+'.tmp')
        try {
            [IO.File]::WriteAllText($AccessProbe,'Email IR case access check',[Text.UTF8Encoding]::new($false))
            if ([IO.File]::ReadAllText($AccessProbe) -ne 'Email IR case access check') {
                throw 'Technician session cannot read/write the case directory.'
            }
        } finally {
            if (Test-Path -LiteralPath $AccessProbe -PathType Leaf) {
                Remove-Item -LiteralPath $AccessProbe -Force -ErrorAction SilentlyContinue
            }
        }
        Write-JsonFile (Join-Path $CaseRoot 'CaseDirectoryAccess.json') ([ordered]@{
            InteractiveWindowsIdentity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
            AccessibleAsInteractiveUser=$true; CasePath=$CaseRoot
            VerifiedUtc=(Get-Date).ToUniversalTime().ToString('o')
        })
        $CurrentStage='LaunchGraphWindow'
        $Exe=Join-Path $PSHOME 'powershell.exe'
        $Args='-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode GraphAdmin -CaseRoot "{1}"' -f $PSCommandPath,$CaseRoot
        $Child=Start-Process -FilePath $Exe -ArgumentList $Args -WindowStyle Normal -PassThru -ErrorAction Stop
        Write-JsonFile $BootstrapStatus ([ordered]@{
            Result='RESULT'; Pids=[ordered]@{ GraphAdmin=$Child.Id }
            LaunchedUtc=(Get-Date).ToUniversalTime().ToString('o')
        })
    } catch {
        $Err=Safe-Text $_.Exception.Message
        Write-OperationalLog "BOOTSTRAP_ERROR | Stage=$CurrentStage Error=$Err Case=$CaseRoot"
        try { Write-JsonFile $BootstrapStatus ([ordered]@{ Result='ERROR'; Error=$Err; Stage=$CurrentStage }) } catch { }
    }
    return
}

# --------------------- Independent worker context --------------------------
if ($Mode -eq 'UnitTest') { $CaseRoot=$Workspace }
$WorkerRole=$Mode
$WorkerLog=Join-Path $CaseRoot ($WorkerRole+'.collection.log')
$WorkerStatus=Join-Path $CaseRoot ($WorkerRole+'.status.json')
$EvidenceRoot=Join-Path $CaseRoot $WorkerRole
$Collected=New-Object 'System.Collections.Generic.List[object]'
$Limitations=New-Object 'System.Collections.Generic.List[object]'
$SessionConnected=$false
$WorkerFatal=$null
$WorkerResult='ERROR'

function Write-WorkerLog([string]$Text) {
    $Safe=Safe-Text $Text
    try {
        ('{0} | {1}' -f (Get-Date).ToUniversalTime().ToString('o'),$Safe) |
            Add-Content -LiteralPath $WorkerLog -Encoding UTF8
    } catch { }
    Write-Host $Safe
}
function Add-Limitation([string]$Source,[string]$Issue) {
    $Msg=Safe-Text $Issue
    $Limitations.Add([ordered]@{ Source=$Source; Reason=$Msg; Utc=(Get-Date).ToUniversalTime().ToString('o') })
    Write-WorkerLog "LIMITATION | $Source | $Msg"
}
function Add-Source([string]$Name,[string]$Path,[int]$Count,[bool]$Complete) {
    $Collected.Add([ordered]@{ Name=$Name; RelativePath=$Path.Substring($CaseRoot.Length+1)
        Count=$Count; Complete=$Complete; CollectedUtc=(Get-Date).ToUniversalTime().ToString('o') })
    Write-WorkerLog "SAVED | $Name | Records=$Count Complete=$Complete"
}
function Open-Writer([string]$Path) {
    return [IO.StreamWriter]::new($Path,$false,[Text.UTF8Encoding]::new($false))
}
function Append-Record([IO.StreamWriter]$Writer,[object]$Record) {
    $Writer.WriteLine((ConvertTo-Json -InputObject $Record -Depth 35 -Compress))
}
function Ensure-RequiredModules([string[]]$Modules) {
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    foreach ($Name in $Modules) {
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Write-WorkerLog "INSTALL | Module=$Name Scope=CurrentUser"
            Install-Module -Name $Name -Scope CurrentUser -Repository PSGallery -AllowClobber -Force -ErrorAction Stop
        } else { Write-WorkerLog "MODULE_PRESENT | $Name" }
        # Only CHECK / INSTALL here. Authentication runs in the Graph worker.
    }
}
function Get-InvestigationWindow {
    # This worker's own nonsecret case inputs; never another shell's auth context.
    $Path=Join-Path $CaseRoot ($WorkerRole+'.InvestigationWindow.json')
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Incident date/time metadata was not created before collection.'
    }
    $W=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    if ([string]::IsNullOrEmpty($W.StartUtc) -or [string]::IsNullOrEmpty($W.EndUtc)) {
        throw 'Incident date/time metadata is incomplete.'
    }
    return $W
}
function Get-UtcWindowStart {
    $W=Get-InvestigationWindow
    return [datetime]::Parse($W.StartUtc,[Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
}
function Get-UtcWindowEnd {
    $W=Get-InvestigationWindow
    return [datetime]::Parse($W.EndUtc,[Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
}
function Escape-OData([string]$Text) { return $Text.Replace("'","''") }
function Get-ObjectProperty([object]$Object,[string]$Key) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Key] }
    $Property=$Object.PSObject.Properties[$Key]
    if ($Property) { return $Property.Value }
    return $null
}
function String-Hash([string]$Text) {
    $SHA=[Security.Cryptography.SHA256]::Create()
    try {
        $B=$SHA.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        return ([BitConverter]::ToString($B) -replace '-','').ToLowerInvariant()
    } finally { $SHA.Dispose() }
}
# ------------------------ Microsoft Graph helpers --------------------------
function Graph-Uri([string]$Path,[string]$Query,[string]$Version='v1.0') {
    $Base='https://graph.microsoft.com/'+$Version+$Path
    if ($Query) { return ($Base+'?'+$Query) }
    return $Base
}
function Encode-Filter([string]$Condition) { return [uri]::EscapeDataString($Condition) }
function Get-GraphHeader([object]$Headers,[string]$Name) {
    if ($null -eq $Headers) { return $null }
    try {
        if ($Headers -is [System.Collections.IDictionary]) {
            foreach ($Key in $Headers.Keys) {
                if ([string]$Key -ieq $Name) { return (Safe-Text (@($Headers[$Key]) -join ',')) }
            }
        } else {
            foreach ($Header in $Headers) {
                if ([string](Get-ObjectProperty $Header 'Key') -ieq $Name) {
                    return (Safe-Text (@(Get-ObjectProperty $Header 'Value') -join ','))
                }
            }
        }
    } catch { }
    return $null
}
function Get-GraphFailureDetails([object]$Record,[string]$Source,
    [object]$ResponseStatus,[object]$ResponseHeaders) {
    # Read diagnostic metadata only. Never collect authorization headers,
    # access tokens, raw HTTP requests, or Graph debug transcripts.
    $Details=[ordered]@{
        Source=$Source
        CollectedUtc=(Get-Date).ToUniversalTime().ToString('o')
        StatusCode='UNAVAILABLE'
        ErrorCode=$null
        ResponseMessage=$null
        RetryAfter=$null
        RequestId=$null
        ClientRequestId=$null
        FullyQualifiedErrorId=(Safe-Text (Get-ObjectProperty $Record 'FullyQualifiedErrorId'))
        ExceptionChain=@()
    }
    if ($null -ne $ResponseStatus) { $Details.StatusCode=Safe-Text $ResponseStatus }
    $Headers=$ResponseHeaders
    $Exception=Get-ObjectProperty $Record 'Exception'
    $Chain=New-Object 'System.Collections.Generic.List[object]'
    $Depth=0
    while ($null -ne $Exception -and $Depth -lt 8) {
        $Depth++
        $Chain.Add([ordered]@{
            Type=$Exception.GetType().FullName
            Message=(Safe-Text (Get-ObjectProperty $Exception 'Message'))
        })
        if ($Details.StatusCode -eq 'UNAVAILABLE') {
            $Code=Get-ObjectProperty $Exception 'StatusCode'
            if ($null -eq $Code) { $Code=Get-ObjectProperty $Exception 'HttpStatusCode' }
            if ($null -ne $Code) { $Details.StatusCode=Safe-Text $Code }
        }
        if (-not $Details.ErrorCode) {
            $Code=Get-ObjectProperty $Exception 'ErrorCode'
            if ($null -ne $Code) { $Details.ErrorCode=Safe-Text $Code }
        }
        $Response=Get-ObjectProperty $Exception 'Response'
        if ($null -ne $Response) {
            if ($Details.StatusCode -eq 'UNAVAILABLE') {
                $Code=Get-ObjectProperty $Response 'StatusCode'
                if ($null -ne $Code) { $Details.StatusCode=Safe-Text $Code }
            }
            if ($null -eq $Headers) { $Headers=Get-ObjectProperty $Response 'Headers' }
        }
        if ($null -eq $Headers) { $Headers=Get-ObjectProperty $Exception 'ResponseHeaders' }
        $Exception=Get-ObjectProperty $Exception 'InnerException'
    }
    $Details.ExceptionChain=$Chain.ToArray()
    $Body=[string](Get-ObjectProperty (Get-ObjectProperty $Record 'ErrorDetails') 'Message')
    if (-not [string]::IsNullOrWhiteSpace($Body)) {
        try {
            $Parsed=ConvertFrom-Json -InputObject $Body -ErrorAction Stop
            $ErrorBody=Get-ObjectProperty $Parsed 'error'
            if ($null -ne $ErrorBody) {
                $Code=Get-ObjectProperty $ErrorBody 'code'
                $Message=Get-ObjectProperty $ErrorBody 'message'
                if ($null -ne $Code) { $Details.ErrorCode=Safe-Text $Code }
                if ($null -ne $Message) { $Details.ResponseMessage=Safe-Text $Message }
                $Inner=Get-ObjectProperty $ErrorBody 'innerError'
                if ($null -ne $Inner) {
                    $Id=Get-ObjectProperty $Inner 'request-id'
                    if ($null -ne $Id) { $Details.RequestId=Safe-Text $Id }
                    $Id=Get-ObjectProperty $Inner 'client-request-id'
                    if ($null -ne $Id) { $Details.ClientRequestId=Safe-Text $Id }
                }
            }
        } catch {
            # Non-JSON ErrorDetails can still describe a retry failure.
            $Details.ResponseMessage=Safe-Text $Body
        }
    }
    $Id=Get-GraphHeader $Headers 'request-id'
    if ($Id) { $Details.RequestId=$Id }
    $Id=Get-GraphHeader $Headers 'client-request-id'
    if ($Id) { $Details.ClientRequestId=$Id }
    $Delay=Get-GraphHeader $Headers 'Retry-After'
    if ($Delay) { $Details.RetryAfter=$Delay }
    return [pscustomobject]$Details
}

function Export-GraphCollection([string]$Name,[string]$Uri) {
    $Path=Join-Path $EvidenceRoot ($Name+'.jsonl')
    $Writer=Open-Writer $Path
    $Next=$Uri
    $Count=0
    $Complete=$true
    try {
        while ($Next) {
            $GraphDiagnosticStatus=$null
            $GraphDiagnosticHeaders=$null
            $Request=@{ Uri=$Next; Method='GET'; ErrorAction='Stop' }
            # Supported SDK versions can expose response status and headers.
            # These switches only capture metadata; the GET request is unchanged.
            $Command=Get-Command Invoke-MgGraphRequest -ErrorAction Stop
            if ($Command.Parameters.ContainsKey('StatusCodeVariable')) {
                $Request.StatusCodeVariable='GraphDiagnosticStatus'
            }
            if ($Command.Parameters.ContainsKey('ResponseHeadersVariable')) {
                $Request.ResponseHeadersVariable='GraphDiagnosticHeaders'
            }
            try {
                $Page=Invoke-MgGraphRequest @Request
            } catch {
                $Diagnosis=Get-GraphFailureDetails $_ $Name $GraphDiagnosticStatus $GraphDiagnosticHeaders
                $DiagPath=Join-Path $EvidenceRoot ($Name+'.http-error.json')
                Write-JsonFile $DiagPath $Diagnosis
                Write-WorkerLog ("HTTP_DIAGNOSTIC | Source=$Name Status=$($Diagnosis.StatusCode) Code=$($Diagnosis.ErrorCode) RequestId=$($Diagnosis.RequestId) RetryAfter=$($Diagnosis.RetryAfter) File=$DiagPath")
                throw
            }
            foreach ($Item in @(Get-ObjectProperty $Page 'value')) {
                if ($null -ne $Item) { Append-Record $Writer $Item; $Count++ }
            }
            $Next=[string](Get-ObjectProperty $Page '@odata.nextLink')
        }
    } catch {
        $Complete=$false
        Add-Limitation $Name ("Graph query failed after $Count records: $($_.Exception.Message)")
    } finally { $Writer.Close() }
    Add-Source $Name $Path $Count $Complete
}
function Export-GraphObject([string]$Name,[string]$Uri) {
    $Path=Join-Path $EvidenceRoot ($Name+'.json')
    try {
        $Object=Invoke-MgGraphRequest -Uri $Uri -Method GET -ErrorAction Stop
        Write-JsonFile $Path ([ordered]@{ CollectedUtc=(Get-Date).ToUniversalTime().ToString('o'); Record=$Object })
        Add-Source $Name $Path 1 $true
        return $Object
    } catch { Add-Limitation $Name $_.Exception.Message; return $null }
}

function Get-GraphSignInEventUri([string]$Filter,[string]$EventType) {
    if ($EventType -notin @('interactiveUser','nonInteractiveUser')) {
        throw "Unsupported sign-in event type $EventType."
    }
    $Selection="$Filter and signInEventTypes/any(t: t eq '$EventType')"
    # Event-type filtering is documented for Graph beta, not v1.0.
    return (Graph-Uri '/auditLogs/signIns' ('$top=100&$filter='+(Encode-Filter $Selection)) 'beta')
}

if ($Mode -eq 'UnitTest') {
    $Failures=New-Object 'System.Collections.Generic.List[string]'
    $Tests=0
    function Assert-UnitTest([bool]$Passed,[string]$Name) {
        $script:Tests++
        if ($Passed) { Write-Output ('PASS | '+$Name) }
        else { $script:Failures.Add($Name); Write-Output ('FAIL | '+$Name) }
    }
    try {
        $Filter="userId eq '00000000-0000-0000-0000-000000000001' and createdDateTime ge 2026-11-01T12:00:00Z and createdDateTime lt 2026-11-02T12:00:00Z"
        $I=Get-GraphSignInEventUri $Filter 'interactiveUser'
        $N=Get-GraphSignInEventUri $Filter 'nonInteractiveUser'
        Assert-UnitTest ($I.StartsWith('https://graph.microsoft.com/beta/auditLogs/signIns?')) 'Interactive sign-in URI uses documented beta endpoint'
        Assert-UnitTest ($N.StartsWith('https://graph.microsoft.com/beta/auditLogs/signIns?')) 'Noninteractive sign-in URI uses documented beta endpoint'
        $DecodedI=[uri]::UnescapeDataString($I)
        $DecodedN=[uri]::UnescapeDataString($N)
        Assert-UnitTest ($DecodedI.Contains("signInEventTypes/any(t: t eq 'interactiveUser')")) 'Interactive filter is encoded correctly'
        Assert-UnitTest ($DecodedN.Contains("signInEventTypes/any(t: t eq 'nonInteractiveUser')")) 'Noninteractive filter is encoded correctly'
        Assert-UnitTest ($DecodedN.Contains('createdDateTime ge') -and $DecodedN.Contains("userId eq '00000000-0000-0000-0000-000000000001'")) 'User and time constraints retained'
        Assert-UnitTest ((Graph-Uri '/users' '$top=1').StartsWith('https://graph.microsoft.com/v1.0/users?')) 'Other Graph queries retain v1.0'
        $Thrown=$false
        try { $null=Get-GraphSignInEventUri $Filter 'servicePrincipal' } catch { $Thrown=$true }
        Assert-UnitTest $Thrown 'Unsupported event type rejected'
        $Fake=[pscustomobject]@{
            Exception=[pscustomobject]@{
                Message='Synthetic HTTP failure'; StatusCode=429; ErrorCode='TooManyRequests'
                Response=[pscustomobject]@{ StatusCode=429; Headers=@{'Retry-After'='25';'request-id'='test-request-id'} }
                InnerException=$null
            }
            FullyQualifiedErrorId='Synthetic.GraphFailure'
            ErrorDetails=$null
        }
        $TestError=Get-GraphFailureDetails $Fake 'SyntheticTest' $null $null
        Assert-UnitTest ($TestError.StatusCode -eq '429' -and $TestError.ErrorCode -eq 'TooManyRequests') 'HTTP status and Graph error code captured'
        Assert-UnitTest ($TestError.RetryAfter -eq '25' -and $TestError.RequestId -eq 'test-request-id') 'Retry-After and request ID captured'
        $EmptyError=Get-GraphFailureDetails ([pscustomobject]@{Exception=[Exception]::new('no HTTP response');FullyQualifiedErrorId='Synthetic.NoResponse';ErrorDetails=$null}) 'SyntheticTest' $null $null
        Assert-UnitTest ($EmptyError.StatusCode -eq 'UNAVAILABLE') 'Missing HTTP response is marked unavailable, not guessed'

        $Raw=Get-Content -LiteralPath $PSCommandPath -Raw
        # Match executable statements only, never matching a quoted test string.
        Assert-UnitTest ($Raw -notmatch '(?im)^\s*(?:Export-DefenderHunting|Export-GraphCollection\s+''Defender|Invoke-MgGraphRequest[^\r\n]+-Method\s+POST)\b') 'No broad Defender or endpoint evidence collection'
        Assert-UnitTest (($Raw -match '(?m)^\s*Connect-MgGraph -Scopes \$Scopes -TenantId ''organizations'' -ContextScope Process') -and
            ($Raw -notmatch '(?m)^\s*Connect-MgGraph[^\r\n]*-(?:UseDeviceCode|UseDeviceAuthentication)\b')) 'Normal Microsoft interactive Graph authentication'
        Assert-UnitTest ($Raw -notmatch '(?im)^\s*(?:New-ComplianceSearch|Start-ComplianceSearch|New-Mg\w+|Update-Mg\w+|Remove-Mg\w+|Set-Mg\w+|New-ManagementRoleAssignment)\b') 'No tenant mutation cmdlets'
        Assert-UnitTest ($Raw.Contains("$"+'SessionConnected=$true') -and $Raw.Contains('Disconnect-MgGraph')) 'Session disconnect remains implemented'
    } catch { $Failures.Add('Unit test harness error: '+(Safe-Text $_.Exception.Message)) }
    if ($Failures.Count -eq 0) { Write-Output "RESULT | GRAPH_IR_UNIT_TESTS Tests=$Tests Failed=0" }
    else {
        foreach ($F in $Failures) { Write-Output ('ERROR | UnitTest='+$F) }
        Write-Output "ERROR | Stage=UnitTests Tests=$Tests Failed=$($Failures.Count)"
    }
    return
}
# --------------------- Local case inputs in EACH worker ---------------------
function Read-CollectorCase {
    Write-Host ''
    Write-Host 'Investigation details (not Microsoft credentials)' -ForegroundColor Cyan
    do {
        $Mailbox=(Read-Host 'Affected mailbox email address').Trim()
        if ($Mailbox -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') {
            Write-Host 'Enter a valid mailbox email address.' -ForegroundColor Yellow
        }
    } while ($Mailbox -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$')
    do {
        $Reference=(Read-Host 'Reference: C=Suspected compromise, N=Notification received').Trim().ToUpperInvariant()
        if ($Reference -notin @('C','N')) { Write-Host 'Enter C or N.' -ForegroundColor Yellow }
    } while ($Reference -notin @('C','N'))
    $Category=if ($Reference -eq 'C') { 'SUSPECTED_COMPROMISE' } else { 'NOTIFICATION' }
    $Zone=[TimeZoneInfo]::Local
    Write-Host ('Time zone: '+$Zone.DisplayName)
    do {
        $TimeText=(Read-Host 'Incident/notification date and military time (yyyy-MM-dd HHmm, local)').Trim()
        $Local=[datetime]::MinValue
        $Valid=[datetime]::TryParseExact($TimeText,'yyyy-MM-dd HHmm',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,[ref]$Local)
        if ($Valid) {
            $Local=[datetime]::SpecifyKind($Local,[DateTimeKind]::Unspecified)
            if ($Zone.IsInvalidTime($Local) -or $Zone.IsAmbiguousTime($Local) -or $Local -gt (Get-Date)) {
                $Valid=$false
            }
        }
        if (-not $Valid) { Write-Host 'Invalid, future, or ambiguous local date/time. Use yyyy-MM-dd HHmm (for example, 2026-11-10 0900).' -ForegroundColor Yellow }
    } while (-not $Valid)
    do {
        $DaysText=(Read-Host 'Days before incident [7]').Trim()
        $Days=7
        $Valid=([string]::IsNullOrWhiteSpace($DaysText) -or
            ([int]::TryParse($DaysText,[ref]$Days) -and $Days -ge 0))
        if (-not $Valid) { Write-Host 'Enter a non-negative whole number, or press Enter for 7.' -ForegroundColor Yellow }
    } while (-not $Valid)
    $AnchorUtc=([datetimeoffset]::new($Local,$Zone.GetUtcOffset($Local))).UtcDateTime
    $StartUtc=$AnchorUtc.AddDays(-$Days)
    $EndUtc=(Get-Date).ToUniversalTime()
    $Data=[ordered]@{
        Role=$WorkerRole; Mailbox=$Mailbox; RelatedAccounts=@()
        ReferenceCategory=$Category
        AnchorLocal=$Local.ToString('yyyy-MM-dd HH:mm',[Globalization.CultureInfo]::InvariantCulture)
        TimeZoneId=$Zone.Id; AnchorUtc=$AnchorUtc.ToString('o')
        LookbackDays=$Days; StartUtc=$StartUtc.ToString('o'); EndUtc=$EndUtc.ToString('o')
        CreatedUtc=(Get-Date).ToUniversalTime().ToString('o')
    }
    Write-JsonFile (Join-Path $CaseRoot ($WorkerRole+'.Case.json')) $Data
    Write-JsonFile (Join-Path $CaseRoot ($WorkerRole+'.InvestigationWindow.json')) $Data
    Write-Host ("Evidence window (UTC): {0} through {1}" -f $StartUtc.ToString('yyyy-MM-dd HH:mm'),$EndUtc.ToString('yyyy-MM-dd HH:mm'))
    Write-Host 'Expand the lookback and rerun if earlier activity is indicated.'
    return [pscustomobject]$Data
}
# ---------------------- Standalone Graph worker ----------------------------
try {
    Ensure-Directory $EvidenceRoot
    $Host.UI.RawUI.WindowTitle='Graph Email IR - Admin'
    Write-WorkerLog "START | Graph Email IR - Admin | Build=$ScriptVersion"
    $CurrentStage='CollectorCaseInput'
    $Setup=Read-CollectorCase
    # No passwords, MFA values, tenant secrets, or token caches in case files.
    if ($Mode -eq 'GraphAdmin') {
        $CurrentStage='GraphModule'
        Ensure-RequiredModules @('Microsoft.Graph.Authentication')
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        $CurrentStage='GraphAuthentication'
        [string[]]$Scopes=@('User.Read.All','Directory.Read.All','AuditLog.Read.All',
            'UserAuthenticationMethod.Read.All','Policy.Read.All','RoleManagement.Read.Directory',
            'IdentityRiskEvent.Read.All')
        Write-WorkerLog 'AUTH | Sign in using the Microsoft administrator sign-in window and complete Microsoft MFA.'
        Write-WorkerLog 'AUTH | If Microsoft requests new tenant-wide consent or app permissions, do not approve during this read-only investigation.'
        # Keep Graph authentication isolated to this process; use the native
        # Microsoft interactive sign-in window, with no device-code workflow.
        Connect-MgGraph -Scopes $Scopes -TenantId 'organizations' -ContextScope Process -NoWelcome -ErrorAction Stop
        $SessionConnected=$true
        $Context=Get-MgContext -ErrorAction Stop
        $CurrentStage='VerifyGraphIdentity'
        if (-not $Context -or -not $Context.Account -or -not $Context.TenantId) {
            throw 'Could not verify the Graph administrator identity and tenant.'
        }
        if ([string]$Context.Account -ieq [string]$Setup.Mailbox) {
            throw 'Graph Admin worker authenticated as the affected account; refusing collection.'
        }
            $TargetLiteral=Escape-OData ([string]$Setup.Mailbox)
            $Condition="mail eq '$TargetLiteral' or userPrincipalName eq '$TargetLiteral'"
            $Find=Invoke-MgGraphRequest -Uri (Graph-Uri '/users' ('$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime&$top=5&$filter='+(Encode-Filter $Condition))) -Method GET -ErrorAction Stop
            $Matches=@(Get-ObjectProperty $Find 'value')
            if ($Matches.Count -ne 1) { throw 'Target mailbox identity was not uniquely resolved in Graph tenant.' }
            $Target=$Matches[0]
            $UserId=[string](Get-ObjectProperty $Target 'id')
            Write-JsonFile (Join-Path $EvidenceRoot 'AffectedUserIdentity.json') $Target
            Add-Source 'AffectedUserIdentity' (Join-Path $EvidenceRoot 'AffectedUserIdentity.json') 1 $true
            Write-JsonFile (Join-Path $EvidenceRoot 'ConnectionIdentity.json') ([ordered]@{
                SignedInAs=[string]$Context.Account; TenantId=[string]$Context.TenantId
                TargetMailbox=[string]$Setup.Mailbox; VerifiedUtc=(Get-Date).ToUniversalTime().ToString('o') })
            Add-Source 'ConnectionIdentity' (Join-Path $EvidenceRoot 'ConnectionIdentity.json') 1 $true
            $CurrentStage='ReadAnalystIncidentWindow'
            $null=Get-InvestigationWindow
            $CurrentStage='GraphAdministrativeCollection'
            $UserPath='/users/'+[uri]::EscapeDataString($UserId)
            Export-GraphCollection 'AffectedUserAuthenticationMethods' (Graph-Uri ($UserPath+'/authentication/methods') '$top=100')
            Export-GraphCollection 'AffectedUserOAuthGrants' (Graph-Uri ($UserPath+'/oauth2PermissionGrants') '$top=100')
            Export-GraphCollection 'AffectedUserAppRoleAssignments' (Graph-Uri ($UserPath+'/appRoleAssignments') '$top=100')
            Export-GraphCollection 'AffectedUserMembership' (Graph-Uri ($UserPath+'/transitiveMemberOf') '$top=100')
            $S=(Get-UtcWindowStart).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $E=(Get-UtcWindowEnd).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $UserFilter="userId eq '$UserId' and createdDateTime ge $S and createdDateTime lt $E"
            Export-GraphCollection 'AffectedUserSignIns' (Graph-Uri '/auditLogs/signIns' ('$top=100&$filter='+(Encode-Filter $UserFilter)))
            foreach ($Kind in @('interactiveUser','nonInteractiveUser')) {
                Export-GraphCollection ('SignIns_'+$Kind) (Get-GraphSignInEventUri $UserFilter $Kind)
            }
            Export-GraphCollection 'AffectedRiskDetections' (Graph-Uri '/identityProtection/riskDetections' ('$top=100&$filter='+(Encode-Filter "userId eq '$UserId'")))
            # TenantDirectoryAudit preserves affected-user events for offline correlation.
            Export-GraphCollection 'TenantDirectoryAudit' (Graph-Uri '/auditLogs/directoryAudits' ('$top=100&$filter='+(Encode-Filter "activityDateTime ge $S and activityDateTime lt $E")))
            Export-GraphCollection 'TenantOAuthConsents' (Graph-Uri '/oauth2PermissionGrants' ('$top=100&$filter='+(Encode-Filter "consentType eq 'AllPrincipals'")))
            Export-GraphCollection 'TenantConditionalAccessPolicies' (Graph-Uri '/identity/conditionalAccess/policies' '$top=100')
            Export-GraphCollection 'TenantDirectoryRoles' (Graph-Uri '/roleManagement/directory/roleAssignments' '$top=100')
            foreach ($RelatedUpn in $Setup.RelatedAccounts) {
                $RelatedCopy=[string]$RelatedUpn
                $Hash=(String-Hash $RelatedCopy).Substring(0,12)
                $RelatedUser=Export-GraphObject ('RelatedUser_'+$Hash) (Graph-Uri ('/users/'+[uri]::EscapeDataString($RelatedCopy)) '$select=id,displayName,userPrincipalName,accountEnabled,userType')
                if ($RelatedUser) {
                    $RelatedId=[string](Get-ObjectProperty $RelatedUser 'id')
                    Export-GraphCollection ('RelatedSignIns_'+$Hash) (Graph-Uri '/auditLogs/signIns' ('$top=100&$filter='+(Encode-Filter "userId eq '$RelatedId' and createdDateTime ge $S and createdDateTime lt $E")))
                    Export-GraphCollection ('RelatedOAuthGrants_'+$Hash) (Graph-Uri ('/users/'+[uri]::EscapeDataString($RelatedId)+'/oauth2PermissionGrants') '$top=100')
                    Export-GraphCollection ('RelatedAuthMethods_'+$Hash) (Graph-Uri ('/users/'+[uri]::EscapeDataString($RelatedId)+'/authentication/methods') '$top=100')
                }
            }
    }
    $WorkerResult=if ($Limitations.Count -eq 0) { 'RESULT' } else { 'ERROR' }
} catch {
    $WorkerFatal=Safe-Text $_.Exception.Message
    Write-WorkerLog "ERROR | Stage=$CurrentStage Error=$WorkerFatal"
    $WorkerResult='ERROR'
} finally {
    $CurrentStage='Disconnect'
    if ($SessionConnected) {
        try {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
            if ($null -ne (Get-MgContext -ErrorAction Stop)) { throw 'Graph context remains after disconnect.' }
            Write-WorkerLog "DISCONNECTED | $WorkerRole"
        } catch { Add-Limitation 'AuthenticationCleanup' $_.Exception.Message; $WorkerResult='ERROR' }
    }
    if ($Collected.Count -eq 0) {
        $WorkerResult='ERROR'
        if (-not $WorkerFatal) { $WorkerFatal='No evidence collected.' }
    }
    if ($Limitations.Count -gt 0) { $WorkerResult='ERROR' }
    try {
        Write-JsonFile $WorkerStatus ([ordered]@{
            Role=$WorkerRole; Build=$ScriptVersion; Result=$WorkerResult
            FatalError=$WorkerFatal; CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')
            Sources=$Collected.ToArray(); Limitations=$Limitations.ToArray()
        })
    } catch { Write-WorkerLog ('STATUS_WRITE_ERROR | '+(Safe-Text $_.Exception.Message)) }
    Write-Host ''
    Write-Host "EMAIL IR | Graph Email IR - Admin | $WorkerResult | Evidence: $EvidenceRoot"
    if ($WorkerFatal) { Write-Host "Reason: $WorkerFatal" }
    try { [void](Read-Host 'Review the outcome, then press Enter to close this window') } catch { }
    # Only Ninja SYSTEM launcher emits final exit 0.
}
