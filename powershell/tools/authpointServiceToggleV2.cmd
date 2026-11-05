@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem AuthPoint Gateway - single-file local recovery launcher + embedded PowerShell.
rem Double-click to elevate, enter a hidden password, and review the results.
rem No sidecar .ps1 file is required or created.
set "MME_RECOVERY_FILE=%~f0"
if /I "%~1"=="--elevated" goto RUN_ELEVATED

rem Request an elevated command window. No credentials are passed on the command line.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$f=$env:MME_RECOVERY_FILE; $q=[char]34; $args='/d /c '+$q+$q+$f+$q+' --elevated'+$q; try { Start-Process -FilePath $env:ComSpec -Verb RunAs -ArgumentList $args -ErrorAction Stop | Out-Null } catch { Write-Host ('ERROR | Stage=Elevation | Reason='+$_.Exception.Message); exit 1 }"
if errorlevel 1 (
    echo.
    echo ERROR: Administrator elevation failed or was canceled.
    pause
    exit /b 1
)
exit /b 0

:RUN_ELEVATED
cls
echo ==================================================
echo    AuthPoint Gateway - Local Service Recovery
echo ==================================================
echo.
rem Read the embedded PowerShell directly from this file; do not write a temp script.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText($env:MME_RECOVERY_FILE); $tag=':__MME_POWERSHELL_PAYLOAD__'; $i=$s.LastIndexOf($tag,[StringComparison]::Ordinal); if($i -lt 0) { Write-Host 'ERROR | Stage=Launcher | Reason=Embedded PowerShell payload not found'; exit 2 }; $code=$s.Substring($i+$tag.Length).TrimStart([char]13,[char]10); try { & ([ScriptBlock]::Create($code)) } catch { Write-Host ('ERROR | Stage=Launcher | Reason='+$_.Exception.Message); exit 2 }"
set "RECOVERY_CODE=%ERRORLEVEL%"
echo.
if "%RECOVERY_CODE%"=="0" (
    echo Recovery process finished. Review RESULT / NO_ACTION above.
) else (
    echo Recovery reported an error, exit code %RECOVERY_CODE%.
    echo Log: C:\MME\AutoLogs\AuthPointGateway_ServiceAccountRecovery.log
)
echo.
echo Press any key to close this window.
pause >nul
exit /b %RECOVERY_CODE%

:__MME_POWERSHELL_PAYLOAD__
# ============================================================================
# NAME: AuthPoint Gateway - Temporary Domain Admin Service Start
# AUTHORED BY: Cogan Goldwater
# TYPE: Manual / On-demand local recovery (NOT a Ninja automation)
# SCOPE: Windows endpoint hosting WatchGuard AuthPoint Gateway
# VARIABLES:
#   Auto-resolved joined AD NetBIOS domain + \Administrator; hidden password only
# OUTPUT TOKENS:
#   RESULT | ...
#   NO_ACTION | ...
#   ERROR | ...
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# LOGGING PATH:
#   C:\MME\AutoLogs\AuthPointGateway_ServiceAccountRecovery.log
# DESCRIPTION:
#   Detects the computer's joined AD domain and resolves its NetBIOS name.
#   Prompts ONLY for the password for DOMAIN\Administrator (hidden).
#   Temporarily configures all four AuthPoint services to use that account.
#   Starts any stopped services, then restores the CONFIGURED Log On account
#   for all four to LocalSystem, without stopping or restarting
#   any running service. A process started under the temporary account retains
#   that security identity until its next process start (including reboot).
#   Always attempts to restore all affected configurations, even on failure.
#   This is an interactive, local, single-device procedure only.
# ============================================================================

$ErrorActionPreference = 'Stop'

$ServiceNames = @(
    'AuthPointGateway',
    'AuthPointLDAP',
    'AuthPointRADIUS',
    'AuthPointADFS'
)

$LogDir  = 'C:\MME\AutoLogs'
$LogFile = Join-Path $LogDir 'AuthPointGateway_ServiceAccountRecovery.log'

function Write-Status {
    param([string]$Message)
    $line = '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    Add-Content -LiteralPath $LogFile -Value $line -ErrorAction Stop
}

function Get-TargetService {
    param([string]$Name)
    Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
}

function Set-TargetServiceAccount {
    param(
        [string]$Name,
        [string]$Account,
        [string]$Password
    )

    $svc = Get-TargetService -Name $Name
    if ($null -eq $svc) { throw "Missing service: $Name" }

    # Uses Windows service management directly; the password is NOT passed
    # through sc.exe, msiexec, or a process command line.
    $result = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{
        StartName     = $Account
        StartPassword = $Password
    } -ErrorAction Stop

    if ($result.ReturnValue -ne 0) {
        $reason = switch ([int]$result.ReturnValue) {
             2 { 'Access denied: elevate PowerShell and verify service permissions' }
            15 { 'Service logon failed: check credentials and Log on as a service rights' }
            21 { 'Invalid service configuration parameters' }
            22 { 'Invalid service account or insufficient service-logon rights' }
            default { 'Windows Service Control Manager rejected the account change' }
        }
        throw "Service=$Name ChangeAccountCode=$($result.ReturnValue) Reason=$reason"
    }
}

# Resolve the actual joined domain's NetBIOS name, not a guessed DNS prefix.
# DsGetDcNameW is a built-in Windows API; no AD PowerShell module is needed.
function Get-JoinedDomainNetbiosName {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if (-not $computer.PartOfDomain) {
        throw 'This device is not joined to an Active Directory domain; no service changes made.'
    }

    $joinedDomain = ([string]$computer.Domain).Trim()
    if ([string]::IsNullOrWhiteSpace($joinedDomain)) {
        throw 'Windows did not report a joined AD domain; no service changes made.'
    }

    # Legacy AD joins may report the flat domain name directly.
    if ($joinedDomain -notmatch '\.') {
        if ($joinedDomain -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,14}$') {
            throw "Joined domain '$joinedDomain' is not a valid NetBIOS name; no changes made."
        }
        return $joinedDomain
    }

    if (-not ('MMEAuthPoint.DomainLocator' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace MMEAuthPoint {
    public static class DomainLocator {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DOMAIN_CONTROLLER_INFO {
            [MarshalAs(UnmanagedType.LPWStr)] public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPWStr)] public string DomainControllerAddress;
            public UInt32 DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPWStr)] public string DomainName;
            [MarshalAs(UnmanagedType.LPWStr)] public string DnsForestName;
            public UInt32 Flags;
            [MarshalAs(UnmanagedType.LPWStr)] public string DcSiteName;
            [MarshalAs(UnmanagedType.LPWStr)] public string ClientSiteName;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "DsGetDcNameW")]
        private static extern int DsGetDcName(string computerName, string domainName,
            IntPtr domainGuid, string siteName, UInt32 flags, out IntPtr information);

        [DllImport("Netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        public static string ResolveNetbiosName(string dnsDomain) {
            // DS_IS_DNS_NAME | DS_RETURN_FLAT_NAME | DS_DIRECTORY_SERVICE_REQUIRED.
            UInt32 flags = 0x00020000u | 0x80000000u | 0x00000010u;
            IntPtr p = IntPtr.Zero;
            int status = DsGetDcName(null, dnsDomain, IntPtr.Zero, null, flags, out p);
            if (status != 0)
                throw new InvalidOperationException("Domain locator failed with Windows status " +
                    status + " for joined domain " + dnsDomain + ". Check DC reachability/DNS.");
            try {
                if (p == IntPtr.Zero) throw new InvalidOperationException("Domain locator returned no data.");
                DOMAIN_CONTROLLER_INFO info = (DOMAIN_CONTROLLER_INFO)
                    Marshal.PtrToStructure(p, typeof(DOMAIN_CONTROLLER_INFO));
                return info.DomainName;
            }
            finally {
                if (p != IntPtr.Zero) NetApiBufferFree(p);
            }
        }
    }
}
'@ -ErrorAction Stop
    }

    $flat = ([MMEAuthPoint.DomainLocator]::ResolveNetbiosName($joinedDomain)).Trim()
    if ($flat -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,14}$') {
        throw "Domain locator returned an unexpected NetBIOS domain '$flat'; no changes made."
    }
    return $flat
}

$changedNames   = [System.Collections.Generic.List[string]]::new()
$restoreErrors  = [System.Collections.Generic.List[string]]::new()
$startErrors    = [System.Collections.Generic.List[string]]::new()
$primaryError   = $null
$securePassword = $null
$password       = $null
$bstr           = [IntPtr]::Zero
$started        = [System.Collections.Generic.List[string]]::new()

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run Windows PowerShell as Administrator on the affected endpoint.'
    }

    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    Write-Status 'START | Temporary domain-account service startup; no running service will be restarted'

    $initiallyStopped = @()
    foreach ($name in $ServiceNames) {
        $svc = Get-TargetService -Name $name
        if ($null -eq $svc) { throw "Missing AuthPoint service $name; no changes made" }
        if ($svc.StartName -notin @('LocalSystem', 'Local System')) {
            throw "Service=$name ConfiguredAccount=$($svc.StartName) Reason=Not LocalSystem; no changes made"
        }
        if ($svc.State -notin @('Running', 'Stopped')) {
            throw "Service=$name State=$($svc.State) Reason=Service is transitioning; no changes made"
        }
        if ($svc.State -eq 'Stopped') { $initiallyStopped += $name }
        Write-Status "PREFLIGHT | Service=$name State=$($svc.State) ConfiguredAccount=LocalSystem"
    }

    if ($initiallyStopped.Count -eq 0) {
        Write-Status 'NO_ACTION | All four services are already running with LocalSystem configured'
        exit 0
    }

    $netbiosDomain = Get-JoinedDomainNetbiosName
    $account = "$netbiosDomain\Administrator"
    Write-Status "DOMAIN_RESOLVED | JoinedDomain=$netbiosDomain TargetAccount=$account"
    Write-Host "Enter password for $account (input hidden):"
    $securePassword = Read-Host -AsSecureString
    if ($null -eq $securePassword -or $securePassword.Length -eq 0) {
        throw 'Password not entered; no service changes made.'
    }

    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

        # Phase 1: configure ALL four for the temporary account.
        # Mark each attempted change for recovery even if Windows throws.
        foreach ($name in $ServiceNames) {
            $changedNames.Add($name)
            Set-TargetServiceAccount -Name $name -Account $account -Password $password
            Write-Status "TEMP_ACCOUNT_SET | Service=$name"
        }
    }
    finally {
        $password = $null
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $bstr = [IntPtr]::Zero
        }
        if ($null -ne $securePassword) { $securePassword.Dispose() }
        $securePassword = $null
    }

    # Phase 2: start only those services that were stopped. Do not restart
    # any running services. Continue through all targets to collect failures.
    foreach ($name in $ServiceNames) {
        if ($name -notin $initiallyStopped) {
            Write-Status "ALREADY_RUNNING | Service=$name | Not restarted"
            continue
        }
        try {
            Write-Status "STARTING | Service=$name"
            Start-Service -Name $name -ErrorAction Stop
            (Get-Service -Name $name -ErrorAction Stop).WaitForStatus('Running', (New-TimeSpan -Seconds 45))
            Start-Sleep -Seconds 2
            if ((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running') {
                throw 'Service did not stay Running after startup'
            }
            $started.Add($name)
            Write-Status "STARTED | Service=$name | Process retains temporary account until next start"
        }
        catch {
            $startErrors.Add("$name`: $($_.Exception.Message)")
            Write-Status "START_FAILED | Service=$name | Reason=$($_.Exception.Message)"
        }
    }
}
catch {
    $primaryError = $_.Exception.Message
    # Logs may not be available if preflight fails early.
    Write-Host "ERROR | Stage=Recovery | Reason=$primaryError"
}
finally {
    # Phase 3: restore the CONFIGURED account, without stopping/restarting.
    # Attempt every account restoration even if another one fails.
    foreach ($name in $changedNames) {
        try {
            Set-TargetServiceAccount -Name $name -Account 'LocalSystem' -Password ''
            $verified = Get-TargetService -Name $name
            if ($verified.StartName -notin @('LocalSystem', 'Local System')) {
                throw "Still configured as $($verified.StartName)"
            }
            Write-Status "RESTORED | Service=$name NextStartAccount=LocalSystem NoRestart=True"
        }
        catch {
            $msg = "$name`: $($_.Exception.Message)"
            $restoreErrors.Add($msg)
            Write-Warning "CRITICAL: Failed to restore LocalSystem for $msg"
        }
    }
}

if ($restoreErrors.Count -gt 0) {
    Write-Host "ERROR | Stage=RestoreLocalSystem | Count=$($restoreErrors.Count) | Action=Immediately inspect service Log On accounts: $($restoreErrors -join '; ')"
    exit 1
}

if ($primaryError) {
    Write-Host "ERROR | Stage=Recovery | Reason=$primaryError | Restored=$($changedNames.Count)"
    exit 1
}

if ($startErrors.Count -gt 0) {
    Write-Status "ERROR | Stage=StartServices | Failures=$($startErrors -join '; ') | ConfiguredAccounts=LocalSystem"
    exit 1
}

Write-Status "RESULT | Started=$($started -join ',') | ConfiguredAccounts=LocalSystem | RunningServicesNotRestarted=True"
exit 0
