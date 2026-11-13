# ============================================================================
# NAME: exchangeEvidenceCollection_v3.ps1
# AUTHORED BY: Cogan Goldwater
# TYPE: Tool
# SCOPE: NinjaOne SYSTEM launcher on technician workstation; one interactive
#   Exchange Email IR - Admin console; target mailbox is NOT sign-in identity.
# VARIABLES: Required: None; Optional: None. Console prompts for affected mailbox, C/N reference,
#   incident timestamp (yyyy-MM-dd HHmm, local), and lookback days [7].
# OUTPUT TOKENS: RESULT | NO_ACTION | ERROR
# CUSTOM FIELDS: Reads: None; Writes: None
# FILE TRANSFERS: None; Ninja self-stages under C:\MME\CS
# LOGGING PATH: C:\MME\AutoLogs\MME_Email_IR_Exchange_Collection.log
# DESCRIPTION:
#   Standalone read-only Exchange Online collector for the Email/Microsoft 365
#   Compromise Response Guide. Captures affected mailbox identity/settings,
#   hidden inbox rules, forwarding, permissions/delegation, folder statistics,
#   inbound/outbound message traces with per-recipient delivery events, and
#   relevant Unified Audit records, including the original tenant-wide
#   Exchange configuration and administrative audit collection.
#   Mailbox folder statistics are NOT message content or suspicious-message
#   preservation. Those targeted guide activities remain analyst review.
#   Does not create Purview cases/searches/exports, modify tenant settings,
#   unblock the user, or authenticate as the affected user. Uses normal admin
#   interactive sign-in, module verification, independent session cleanup,
#   SHA-256 manifest, and explicit partial-coverage limitations.
#   One final exit 0 is emitted from Ninja launcher after its result token.
# ============================================================================
param(
    [ValidateSet('Launcher','Bootstrap','ExchangeAdmin')]
    [string]$Mode='Launcher',
    [string]$CaseRoot
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$Workspace='C:\MME\CS'
$LogRoot='C:\MME\AutoLogs'
$MainLog=Join-Path $LogRoot 'MME_Email_IR_Exchange_Collection.log'
$ScriptVersion='2026.11.13-exchange-standalone-v3'
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


# --------------------- SYSTEM launcher --------------------------------------
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
            $CaseRoot=Join-Path $Workspace ('ExchangeEmailIR_'+$Id)
            Make-RestrictedCaseDirectory $CaseRoot $UserSid
            $StagedScript=Join-Path $CaseRoot 'exchangeEvidenceCollection.worker.ps1'
            Copy-Item -LiteralPath $PSCommandPath -Destination $StagedScript -Force
            $CurrentStage='ScheduleInteractiveBootstrap'
            $ScheduledName='MME_ExchangeEmailIR_'+[guid]::NewGuid().ToString('N')
            $Exe=if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
                Join-Path $env:windir 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
            } else { Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe' }
            $Arguments='-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Mode Bootstrap -CaseRoot "{1}"' -f $StagedScript,$CaseRoot
            $Action=New-ScheduledTaskAction -Execute $Exe -Argument $Arguments
            $Principal=New-ScheduledTaskPrincipal -UserId $DesktopUser -LogonType Interactive
            $Settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
            Register-ScheduledTask -TaskName $ScheduledName -Action $Action -Principal $Principal -Settings $Settings -Force | Out-Null
            Start-ScheduledTask -TaskName $ScheduledName
            Write-OperationalLog "START | ExchangeStandalone Build=$ScriptVersion Case=$CaseRoot Desktop=$DesktopUser"
            $BootstrapStatus=Join-Path $CaseRoot 'Bootstrap.status.json'
            $CurrentStage='AwaitBootstrap'
            # A newly started task can briefly be Ready before it begins, and
            # Bootstrap.status.json can appear while the launcher checks state.
            # Treat it as failed only after observing an actual completed run
            # twice, with a final check for the atomically written status file.
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
                        throw 'Interactive bootstrap ended without writing its status. Check case logs.'
                    }
                }
            }
            $Boot=Get-Content -LiteralPath $BootstrapStatus -Raw | ConvertFrom-Json
            if ($Boot.Result -ne 'RESULT') {
                if ($Boot.Result -eq 'NO_ACTION') {
                    $FinalOutput='NO_ACTION | Case setup cancelled. Case={0}' -f $CaseRoot
                } else { throw ('Interactive bootstrap failed at '+(Safe-Text $Boot.Stage)+': '+(Safe-Text $Boot.Error)) }
            } else {
                $BootstrapLaunchedWorkers=$true
                if (-not $Boot.Pids.ExchangeAdmin) { throw 'Bootstrap did not launch ExchangeAdmin.' }
                $CurrentStage='AwaitExchangeCollector'
                $StatusPath=Join-Path $CaseRoot 'ExchangeAdmin.status.json'
                while (-not (Test-Path -LiteralPath $StatusPath -PathType Leaf)) {
                    if (-not (Get-Process -Id ([int]$Boot.Pids.ExchangeAdmin) -ErrorAction SilentlyContinue)) {
                        if (-not (Test-Path -LiteralPath $StatusPath -PathType Leaf)) {
                            Write-JsonFile $StatusPath ([ordered]@{ Role='ExchangeAdmin'; Result='ERROR'
                                FatalError='Exchange worker exited without saving status.'; Sources=@(); Limitations=@() })
                        }
                    }
                    Start-Sleep -Seconds 2
                }
                $WorkerStatusesPresent=$true
                $Status=Get-Content -LiteralPath $StatusPath -Raw | ConvertFrom-Json
                # This is evidence collection, not the complete analyst response.
                # Targeted message-content review/preservation and broader scope
                # are conditional workflow steps per the response guide.
                Write-JsonFile (Join-Path $CaseRoot 'CollectionCoverage.json') ([ordered]@{
                    Guide='Email/Microsoft 365 Compromise Response Guide'
                    Collector='Exchange Online only'
                    ExchangeCollection='See ExchangeAdmin.status.json'
                    PurviewOperation='NONE_CREATED_OR_STARTED'
                    GuideStepsWithExchangeEvidence=@(
                        'Step 2 affected mailbox identity and configuration',
                        'Step 5 Unified Audit user activity and mailbox references',
                        'Step 6 hidden inbox rules, forwarding, delegates and mailbox permissions',
                        'Step 7 inbound/outbound message trace, delivery events and folder statistics')
                    Step8TenantReview='Tenant Exchange settings and administrative audit requested as in Exchange v13; completion recorded in ExchangeAdmin.status.json'
                    AnalystReviewNotAutomated=@(
                        'Step 1 ticket creation and initial documentation',
                        'Step 3 containment and account recovery changes',
                        'Step 4 original message, headers, screenshots and user interaction',
                        'Step 5 Entra sign-ins, MFA and identity context (separate identity collection)',
                        'Step 6 Entra authentication methods, app passwords and OAuth grants (separate identity review)',
                        'Step 7 suspicious message content review/search, preservation, Defender assessment and remediation',
                        'Step 8 related-account and endpoint pivots when indicated by case evidence',
                        'Step 9 business and connected-application dependencies',
                        'Step 10 exposure, financial and notification decisions',
                        'Steps 11-14 scope assessment, restoration, handoff and closure')
                    MailboxMessageBodiesExported=$false
                    MailboxMessageBodiesExportRequiredForCollectorSuccess=$false
                    UserAccountSignInRequired=$false
                    AccountUnblockedByCollector=$false
                    GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
                })
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
                $TotalLimitations=@($Status.Limitations).Count
                if ($Status.Result -eq 'RESULT' -and $TotalLimitations -eq 0) {
                    $FinalOutput='RESULT | EXCHANGE_IR_COLLECTION | ExchangeAdmin=RESULT Case={0} Manifest={1}' -f $CaseRoot,$Manifest
                } else {
                    $FinalOutput='ERROR | Stage=ExchangeCollection ExchangeAdmin={0} Limitations={1} PartialEvidence={2} Manifest={3}' -f
                        $Status.Result,$TotalLimitations,$CaseRoot,$Manifest
                }
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
            } else {
                Write-OperationalLog 'STAGED_SCRIPT_RETAINED | Worker status is incomplete; preserving the worker PS1 for troubleshooting.'
            }
        }
        if (-not $FinalOutput) { $FinalOutput='ERROR | Stage=Finalize Error=No launcher result.' }
        Write-OperationalLog $FinalOutput
        Write-Output $FinalOutput
        exit 0
    }
}



# --------------------- Hidden interactive bootstrap -------------------------
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
        $CurrentStage='LaunchExchangeWindow'
        $Exe=Join-Path $PSHOME 'powershell.exe'
        $Args='-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode ExchangeAdmin -CaseRoot "{1}"' -f $PSCommandPath,$CaseRoot
        $Child=Start-Process -FilePath $Exe -ArgumentList $Args -WindowStyle Normal -PassThru -ErrorAction Stop
        Write-JsonFile $BootstrapStatus ([ordered]@{
            Result='RESULT'; Pids=[ordered]@{ ExchangeAdmin=$Child.Id }
            LaunchedUtc=(Get-Date).ToUniversalTime().ToString('o')
        })
    } catch {
        $Err=Safe-Text $_.Exception.Message
        Write-OperationalLog "BOOTSTRAP_ERROR | Stage=$CurrentStage Error=$Err Case=$CaseRoot"
        try { Write-JsonFile $BootstrapStatus ([ordered]@{ Result='ERROR'; Error=$Err; Stage=$CurrentStage }) } catch { }
    }
    return
}


# --------------------- Exchange worker context -----------------------------
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
function Collect-Command([string]$Name,[scriptblock]$Command) {
    $File=Join-Path $EvidenceRoot ($Name+'.json')
    Write-WorkerLog "COLLECT | $Name"
    try {
        $Data=@(& $Command)
        Write-JsonFile $File ([ordered]@{ Source=$WorkerRole; Command=$Name
            CollectedUtc=(Get-Date).ToUniversalTime().ToString('o'); Count=$Data.Count; Records=$Data })
        Add-Source $Name $File $Data.Count $true
        return $Data
    } catch {
        Add-Limitation $Name $_.Exception.Message
        return @()
    }
}
function Ensure-RequiredModules([string[]]$Modules) {
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    foreach ($Name in $Modules) {
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Write-WorkerLog "INSTALL | Module=$Name Scope=CurrentUser"
            Install-Module -Name $Name -Scope CurrentUser -Repository PSGallery -AllowClobber -Force -ErrorAction Stop
        } else { Write-WorkerLog "MODULE_PRESENT | $Name" }
        # Only CHECK / INSTALL here. Only check or install the Exchange module here.
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
# Exchange Online message trace AND delivery-detail requests are separately
# limited per tenant to 100 requests per rolling five-minute window.
# Target 90/305 sec locally, leaving a safety margin. Other callers may use
# the tenant quota, so an actual throttle response is still handled.
$Script:TraceQueryClock=@{
    Summary=(New-Object 'System.Collections.Generic.Queue[datetime]')
    Detail=(New-Object 'System.Collections.Generic.Queue[datetime]')
}
function Wait-ExchangeTraceSlot([string]$Kind) {
    $History=$Script:TraceQueryClock[$Kind]
    while ($true) {
        $Now=[datetime]::UtcNow
        while ($History.Count -gt 0 -and ($Now-$History.Peek()).TotalSeconds -ge 305) {
            [void]$History.Dequeue()
        }
        if ($History.Count -lt 90) {
            $History.Enqueue($Now)
            return
        }
        $Wait=[int][Math]::Ceiling(305-($Now-$History.Peek()).TotalSeconds)
        if ($Wait -lt 1) { $Wait=1 }
        Write-WorkerLog ("RATE_LIMIT | $Kind has $($History.Count) local requests in its rolling window; waiting $Wait seconds for Exchange quota.")
        Start-Sleep -Seconds $Wait
    }
}
function Invoke-ExchangeTraceRequest([string]$Kind,[scriptblock]$Request) {
    for ($Attempt=1; $Attempt -le 3; $Attempt++) {
        Wait-ExchangeTraceSlot $Kind
        try { return @(& $Request) }
        catch {
            $Message=[string]$_.Exception.Message
            $Throttled=($Message -match '(?i)surpassed the permitted limit|throttl|too.?many.?requests|rate.?limit|\b429\b')
            if (-not $Throttled -or $Attempt -eq 3) { throw }
            # Use the server's Retry-After if available. Otherwise respect the
            # published five-minute window, including usage by other clients.
            $Wait=305
            try {
                $Response=$_.Exception.Response
                $Headers=$Response.Headers
                if ($Headers) {
                    $Raw=$Headers['Retry-After']
                    if ($null -ne $Raw) {
                        $Number=0
                        if ([int]::TryParse([string]$Raw,[ref]$Number) -and $Number -gt 0) {
                            $Wait=$Number
                        }
                    }
                }
            } catch { }
            Write-WorkerLog ("THROTTLED | $Kind request attempt $Attempt; waiting $Wait seconds before retry.")
            Start-Sleep -Seconds $Wait
        }
    }
}

# --------------------- Exchange audit/trace helpers ------------------------
function Export-AuditWindow([string]$Name,[datetime]$Begin,[datetime]$Finish,[hashtable]$Filters) {
    if ($Begin -ge $Finish) { return }
    $Stem='{0}_{1}_{2}_{3}' -f $Name,$Begin.ToString('yyyyMMddTHHmmss'),$Finish.ToString('yyyyMMddTHHmmss'),[guid]::NewGuid().ToString('N').Substring(0,6)
    $File=Join-Path $EvidenceRoot ($Stem+'.jsonl')
    $Writer=Open-Writer $File
    $Count=0
    $Completed=$false
    $ErrorMsg=$null
    try {
        $Session=[guid]::NewGuid().ToString('N')
        do {
            $Params=@{ StartDate=$Begin; EndDate=$Finish; SessionId=$Session
                SessionCommand='ReturnLargeSet'; ResultSize=5000; ErrorAction='Stop' }
            foreach ($Key in $Filters.Keys) { $Params[$Key]=$Filters[$Key] }
            $Page=@(Search-UnifiedAuditLog @Params)
            foreach ($Entry in $Page) {
                # Unified Audit timestamps are UTC. A DateTime with Kind=Unspecified
                # must not be serialized as workstation-local time.
                $CreationDate=[datetime]$Entry.CreationDate
                if ($CreationDate.Kind -eq [DateTimeKind]::Unspecified) {
                    $CreationDate=[datetime]::SpecifyKind($CreationDate,[DateTimeKind]::Utc)
                } else {
                    $CreationDate=$CreationDate.ToUniversalTime()
                }
                # Copy the record so the original Exchange object and its raw
                # AuditData payload remain unchanged.
                $AuditRecord=$Entry | Select-Object -Property *
                $AuditRecord.CreationDate=$CreationDate.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
                Append-Record $Writer $AuditRecord
                $Count++
            }
        } while ($Page.Count -gt 0 -and $Count -lt 50000)
        $Completed=$true
    } catch { $ErrorMsg=$_.Exception.Message }
    finally { $Writer.Close() }
    if ($ErrorMsg) {
        Add-Limitation $Name ("Audit query $Begin to $Finish failed after $Count records: $ErrorMsg")
        Add-Source $Name $File $Count $false
        return
    }
    if ($Count -ge 50000) {
        # A full 50k session cannot prove completeness. Discard that bounded
        # parent export before subdividing to avoid double-counting it.
        if (($Finish-$Begin).TotalSeconds -gt 1) {
            Remove-Item -LiteralPath $File -Force
            $Middle=$Begin.AddTicks([long](($Finish.Ticks-$Begin.Ticks)/2))
            if ($Middle -gt $Begin -and $Middle -lt $Finish) {
                Export-AuditWindow $Name $Begin $Middle $Filters
                Export-AuditWindow $Name $Middle $Finish $Filters
                return
            }
        }
        Add-Limitation $Name ("Audit session hit 50,000-record ceiling for $Begin to $Finish; evidence may be incomplete")
        $Completed=$false
    }
    Add-Source $Name $File $Count $Completed
}
function Export-AuditRange([string]$Name,[hashtable]$Filters) {
    $S=Get-UtcWindowStart; $E=Get-UtcWindowEnd
    $Day=$S
    while ($Day -lt $E) {
        $Stop=$Day.AddDays(1); if ($Stop -gt $E) { $Stop=$E }
        Export-AuditWindow $Name $Day $Stop $Filters
        $Day=$Stop
    }
}
function Export-TraceWindow([string]$Name,[string]$Direction,[datetime]$Begin,[datetime]$Finish) {
    if ($Begin -ge $Finish) { return }
    $Params=@{ StartDate=$Begin; EndDate=$Finish; ResultSize=5000; ErrorAction='Stop' }
    if ($Direction -eq 'Outbound') { $Params.SenderAddress=$Setup.Mailbox }
    else { $Params.RecipientAddress=$Setup.Mailbox }
    try { $Rows=@(Invoke-ExchangeTraceRequest Summary { Get-MessageTraceV2 @Params }) }
    catch { Add-Limitation $Name ("Trace query $Begin to ${Finish}: $($_.Exception.Message)"); return }
    if ($Rows.Count -ge 5000 -and ($Finish-$Begin).TotalSeconds -gt 1) {
        $Middle=$Begin.AddTicks([long](($Finish.Ticks-$Begin.Ticks)/2))
        if ($Middle -gt $Begin -and $Middle -lt $Finish) {
            Export-TraceWindow $Name $Direction $Begin $Middle
            Export-TraceWindow $Name $Direction $Middle $Finish
            return
        }
    }
    if ($Rows.Count -ge 5000) {
        Add-Limitation $Name ("5,000 message trace result cap at $Begin to $Finish; may be incomplete")
    }
    $Stem='{0}_{1}_{2}_{3}' -f $Name,$Begin.ToString('yyyyMMddTHHmmss'),$Finish.ToString('yyyyMMddTHHmmss'),[guid]::NewGuid().ToString('N').Substring(0,6)
    $OutPath=Join-Path $EvidenceRoot ($Stem+'.jsonl')
    $DetailsPath=Join-Path $EvidenceRoot ($Stem+'_DeliveryEvents.jsonl')
    $PendingPath=Join-Path $EvidenceRoot ($Stem+'_PendingDeliveryEventRequests.jsonl')
    $TraceWriter=Open-Writer $OutPath
    $DetailWriter=Open-Writer $DetailsPath
    $PendingWriter=Open-Writer $PendingPath
    $DetailCount=0
    $TraceCount=0
    $PendingCount=0
    $DetailComplete=$true
    $DetailSuspended=$false
    try {
        $Seen=New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($Trace in $Rows) {
            $Key='{0}|{1}|{2}' -f $Trace.MessageTraceId,$Trace.RecipientAddress,$Trace.Received
            if (-not $Seen.Add($Key)) { continue }
            Append-Record $TraceWriter $Trace; $TraceCount++
            $Issue=$null
            if (-not $Trace.MessageTraceId -or -not $Trace.RecipientAddress) {
                $Issue='MessageTraceId or RecipientAddress is missing.'
            } elseif ($DetailSuspended) {
                $Issue='Delivery-event detail queries suspended after repeated tenant throttling.'
            } else {
                try {
                    $TraceId=$Trace.MessageTraceId
                    $Recipient=$Trace.RecipientAddress
                    $Events=@(Invoke-ExchangeTraceRequest Detail {
                        Get-MessageTraceDetailV2 -MessageTraceId $TraceId -RecipientAddress $Recipient -ErrorAction Stop
                    })
                    foreach ($Event in $Events) {
                        Append-Record $DetailWriter ([ordered]@{
                            MessageTraceId=[string]$TraceId; RecipientAddress=[string]$Recipient
                            Event=$Event
                        }); $DetailCount++
                    }
                } catch {
                    $Issue=Safe-Text $_.Exception.Message
                    if ($Issue -match '(?i)surpassed the permitted limit|throttl|too.?many.?requests|rate.?limit|\b429\b') {
                        $DetailSuspended=$true
                        Add-Limitation ($Name+'DeliveryEvents') 'Repeated Exchange throttling after retries. Remaining delivery-event requests are recorded in the pending manifest; do not treat the source as complete.'
                    } else {
                        Add-Limitation ($Name+'DeliveryEvents') ("TraceId=$($Trace.MessageTraceId) recipient=$($Trace.RecipientAddress): $Issue")
                    }
                }
            }
            if ($Issue) {
                $DetailComplete=$false
                Append-Record $PendingWriter ([ordered]@{
                    MessageTraceId=[string]$Trace.MessageTraceId
                    RecipientAddress=[string]$Trace.RecipientAddress
                    Received=$Trace.Received
                    Reason=$Issue
                })
                $PendingCount++
            }
        }
    } finally {
        $TraceWriter.Close()
        $DetailWriter.Close()
        $PendingWriter.Close()
    }
    if ($PendingCount -eq 0) { Remove-Item -LiteralPath $PendingPath -Force }
    else {
        Add-Source ($Name+'PendingDeliveryEventRequests') $PendingPath $PendingCount $false
        Add-Limitation ($Name+'DeliveryEvents') ("$PendingCount delivery-event requests remain incomplete; see $PendingPath")
    }
    Add-Source $Name $OutPath $TraceCount ($Rows.Count -lt 5000)
    Add-Source ($Name+'DeliveryEvents') $DetailsPath $DetailCount $DetailComplete
}
function Export-Traces([string]$Name,[string]$Direction) {
    $S=Get-UtcWindowStart; $E=Get-UtcWindowEnd
    $Oldest=(Get-Date).ToUniversalTime().AddDays(-90)
    if ($S -lt $Oldest) {
        Add-Limitation $Name ("Message trace service retains 90 days. Unavailable: $S through $Oldest")
        $S=$Oldest
    }
    if ($S -ge $E) { Add-Limitation $Name 'No requested timeframe remains within trace retention.'; return }
    while ($S -lt $E) {
        $Stop=$S.AddDays(9); if ($Stop -gt $E) { $Stop=$E }
        Export-TraceWindow $Name $Direction $S $Stop
        $S=$Stop
    }
}

# --------------------- Local case inputs in Exchange worker ---------------------
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
        Role=$WorkerRole; Mailbox=$Mailbox
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


# --------------------- Exchange admin worker execution ----------------------
try {
    Ensure-Directory $EvidenceRoot
    $Host.UI.RawUI.WindowTitle='Exchange Email IR - Admin'
    Write-WorkerLog "START | Exchange Email IR - Admin | Build=$ScriptVersion"
    $CurrentStage='CollectorCaseInput'
    $Setup=Read-CollectorCase
    # No passwords, MFA values, tenant secrets, or token caches in case files.
    if ($Mode -eq 'ExchangeAdmin') {
        $CurrentStage='ExchangeModule'
        Ensure-RequiredModules @('ExchangeOnlineManagement')
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $CurrentStage='ExchangeAuthentication'
        Write-WorkerLog 'AUTH | Sign in with your Microsoft 365 administrator and complete Microsoft MFA.'
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        $SessionConnected=$true
        $CurrentStage='VerifyExchangeIdentity'
        $Connections=@(Get-ConnectionInformation -ErrorAction Stop |
            Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession })
        if ($Connections.Count -ne 1) { throw 'Could not verify exactly one Exchange Online connection.' }
        $Actor=[string]$Connections[0].UserPrincipalName
        if ($Actor -ieq [string]$Setup.Mailbox) {
            throw 'Exchange Admin worker authenticated as the affected account; refusing collection.'
        }
        Write-JsonFile (Join-Path $EvidenceRoot 'ConnectionIdentity.json') ([ordered]@{
            SignedInAs=$Actor; TenantId=[string]$Connections[0].TenantID
            TargetMailbox=[string]$Setup.Mailbox; VerifiedUtc=(Get-Date).ToUniversalTime().ToString('o')
        })
        Add-Source 'ConnectionIdentity' (Join-Path $EvidenceRoot 'ConnectionIdentity.json') 1 $true
            $CurrentStage='ExchangeAdministrativeCollection'
            $MailboxCheck=Get-EXOMailbox -Identity $Setup.Mailbox -PropertySets All -ErrorAction Stop
            if (-not $MailboxCheck) { throw 'Target mailbox not found in authenticated Exchange tenant.' }
            Collect-Command 'MailboxConfiguration' { $MailboxCheck } | Out-Null
            Collect-Command 'MailboxConfigurationExtended' { Get-Mailbox -Identity $Setup.Mailbox -ErrorAction Stop } | Out-Null
            Collect-Command 'MailboxClientAccessAndLegacyAuth' { Get-CASMailbox -Identity $Setup.Mailbox -ErrorAction Stop } | Out-Null
            Collect-Command 'MailboxStatistics' { Get-EXOMailboxStatistics -Identity $Setup.Mailbox -ErrorAction Stop } | Out-Null
            Collect-Command 'MailboxFolderStatistics' { Get-EXOMailboxFolderStatistics -Identity $Setup.Mailbox -IncludeOldestAndNewestItems -ErrorAction Stop } | Out-Null
            if ([string]$MailboxCheck.ArchiveStatus -eq 'Active') {
                Collect-Command 'MailboxArchiveFolderStatistics' { Get-EXOMailboxFolderStatistics -Identity $Setup.Mailbox -Archive -ErrorAction Stop } | Out-Null
            }
            Collect-Command 'MailboxRecoverableItemsStatistics' { Get-EXOMailboxFolderStatistics -Identity $Setup.Mailbox -FolderScope RecoverableItems -ErrorAction Stop } | Out-Null
            $InboxRules=@(Collect-Command 'InboxRulesIncludingHidden' {
                Get-InboxRule -Mailbox $Setup.Mailbox -IncludeHidden -ErrorAction Stop
            })
            # Without -ResultSize, Exchange returns 1,000 rules by default.
            # A capped response cannot be certified complete.
            if ($InboxRules.Count -ge 1000) {
                Add-Limitation 'InboxRulesIncludingHidden' 'Default 1,000 rule limit reached; result may be incomplete.'
                foreach ($Item in $Collected) {
                    if ($Item.Name -eq 'InboxRulesIncludingHidden') { $Item.Complete=$false }
                }
            }
            Collect-Command 'MailboxFullAccessPermissions' { Get-EXOMailboxPermission -Identity $Setup.Mailbox -ErrorAction Stop } | Out-Null
            Collect-Command 'MailboxSendAsPermissions' { Get-RecipientPermission -Identity $Setup.Mailbox -ErrorAction Stop } | Out-Null
            Collect-Command 'MailboxSendOnBehalfAndForwarding' {
                Get-Mailbox -Identity $Setup.Mailbox -ErrorAction Stop |
                    Select-Object Identity,GrantSendOnBehalfTo,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
            } | Out-Null
            Collect-Command 'AcceptedDomains' { Get-AcceptedDomain -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantTransportRules' { Get-TransportRule -ResultSize Unlimited -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantInboundConnectors' { Get-InboundConnector -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantOutboundConnectors' { Get-OutboundConnector -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantRemoteDomains' { Get-RemoteDomain -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantTransportConfiguration' { Get-TransportConfig -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantOrganizationConfiguration' { Get-OrganizationConfig -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantAuthenticationPolicies' { Get-AuthenticationPolicy -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantOutboundSpamPolicies' { Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop } | Out-Null
            Collect-Command 'TenantAntiPhishPolicies' { Get-AntiPhishPolicy -ErrorAction Stop } | Out-Null
            if ((Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue) -and
                (Get-Command Get-MessageTraceDetailV2 -ErrorAction SilentlyContinue)) {
                Export-Traces 'OutboundMessageTrace' 'Outbound'
                Export-Traces 'InboundMessageTrace' 'Inbound'
            } else { Add-Limitation 'MessageTrace' 'Message trace and/or detail cmdlets not available in this Exchange session.' }
            if (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue) {
                Export-AuditRange 'UnifiedAuditUserActivity' @{ UserIds=@($Setup.Mailbox) }
                Export-AuditRange 'UnifiedAuditMailboxReferences' @{ FreeText=$Setup.Mailbox }
                Export-AuditRange 'UnifiedAuditExchangeAdministrativeActivity' @{ RecordType='ExchangeAdmin' }
            } else { Add-Limitation 'UnifiedAudit' 'Search-UnifiedAuditLog not available in this Exchange session.' }

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
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop | Out-Null
            $Still=@(Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' })
            if ($Still.Count -gt 0) { throw 'Exchange still has a connected session after disconnect.' }
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
    Write-Host "EMAIL IR | Exchange Email IR - Admin | $WorkerResult | Evidence: $EvidenceRoot"
    if ($WorkerFatal) { Write-Host "Reason: $WorkerFatal" }
    try { [void](Read-Host 'Review the outcome, then press Enter to close this window') } catch { }
    # Only Ninja SYSTEM launcher emits final exit 0.
}
