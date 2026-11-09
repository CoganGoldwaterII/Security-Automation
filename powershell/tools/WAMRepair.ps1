# NAME: Repair Workplace Registration - Local User
# TYPE: Interactive, native Windows 11 repair / verification
# SCOPE: Current Windows user, Microsoft work registration only
# DESCRIPTION: Walks through Microsoft's supported selective disconnect/reconnect,
#              verifying Windows registration before and after. Does NOT delete
#              device keys, revoke TPM material, touch local AD, or run dsregcmd /leave.
# Run under the affected Windows user (not as SYSTEM or a different administrator).

$ErrorActionPreference = 'Stop'
$TargetAccount = 'info@stclairorthodontics.com'

function Read-DeviceState {
    $raw = & "$env:windir\System32\dsregcmd.exe" /status 2>&1
    if ($LASTEXITCODE -ne 0) { throw "dsregcmd /status failed: $raw" }
    $state = @{}
    foreach ($name in @('DomainJoined','AzureAdJoined','WorkplaceJoined')) {
        $line = $raw | Where-Object { $_ -match "^\s*$name\s*:\s*(YES|NO)\s*$" } | Select-Object -First 1
        if ($line -match ":\s*(YES|NO)\s*$") { $state[$name] = $Matches[1] }
        else { throw "Unable to read '$name' from dsregcmd /status. No changes made." }
    }
    return $state
}

try {
    Write-Host ''
    Write-Host 'WORKPLACE REGISTRATION REPAIR | RECEPT2PC' -ForegroundColor Cyan
    Write-Host "Windows user : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Host "Work account : $TargetAccount"
    Write-Host 'Local AD account and domain membership will NOT be changed.'
    Write-Host ''

    $before = Read-DeviceState
    Write-Host ("BEFORE | DomainJoined={0} AzureAdJoined={1} WorkplaceJoined={2}" -f $before.DomainJoined, $before.AzureAdJoined, $before.WorkplaceJoined)

    if ($before.DomainJoined -ne 'YES' -or $before.AzureAdJoined -ne 'NO') {
        throw 'Unexpected join state. This procedure is only for the documented AD-only, workplace-registered PC. No changes made.'
    }

    if ($before.WorkplaceJoined -eq 'YES') {
        Write-Host ''
        Write-Host 'STEP 1 | Disconnect only the listed Microsoft WORK account in Windows Settings.' -ForegroundColor Yellow
        Write-Host "  Target: $TargetAccount"
        Write-Host '  Do NOT disconnect the STCLAIRORTHO domain account.'
        Write-Host '  If the target account is NOT in Access work or school, STOP. Do not remove another account.'
        Start-Process 'ms-settings:workplace'
        [void](Read-Host 'After selecting the TARGET account and Disconnect (or if no such account exists), press Enter')
        $after = Read-DeviceState
        Write-Host ("CHECK | DomainJoined={0} AzureAdJoined={1} WorkplaceJoined={2}" -f $after.DomainJoined, $after.AzureAdJoined, $after.WorkplaceJoined)
        if ($after.DomainJoined -ne 'YES') {
            throw 'Unexpected domain join state after interaction. Stop and investigate.'
        }
        if ($after.WorkplaceJoined -eq 'YES') {
            Write-Host 'ERROR | Workplace registration is still present. Nothing else will be changed.' -ForegroundColor Red
            Write-Host 'If Windows needs to complete the disconnect after restarting, restart and run this file again.'
            exit 0
        }
        Write-Host 'RESULT | WorkplaceJoined=NO. Registration is no longer reported for this Windows user.' -ForegroundColor Green
        Write-Host 'RESTART WINDOWS, then run this SAME script again to reconnect the work account.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    Write-Host 'STEP 2 | WorkplaceJoined=NO. Reconnect the SAME Microsoft work account.' -ForegroundColor Yellow
    Write-Host "  Target: $TargetAccount"
    Write-Host '  In Access work or school, select Connect and sign in with the target account.'
    Write-Host '  Complete the normal work-account registration prompts.'
    Write-Host '  Do NOT join the PC to a new domain or replace the Windows sign-in account.'
    Start-Process 'ms-settings:workplace'
    [void](Read-Host 'After reconnecting the target work account, press Enter')
    $after = Read-DeviceState
    Write-Host ("AFTER | DomainJoined={0} AzureAdJoined={1} WorkplaceJoined={2}" -f $after.DomainJoined, $after.AzureAdJoined, $after.WorkplaceJoined)
    if ($after.DomainJoined -ne 'YES') { throw 'Unexpected domain join state. Stop and investigate.' }
    if ($after.WorkplaceJoined -eq 'YES') {
        Write-Host 'RESULT | Workplace registration present. Confirm the account displayed in Settings is the intended one.' -ForegroundColor Green
        Write-Host 'Now open Outlook with the WAM bypass reverted and test the Microsoft 365 mailbox.'
    } else {
        Write-Host 'ERROR | WorkplaceJoined remains NO. Reconnect was not confirmed.' -ForegroundColor Red
    }
}
catch {
    Write-Host ('ERROR | ' + $_.Exception.Message) -ForegroundColor Red
}
finally {
    Write-Host ''
    [void](Read-Host 'Press Enter to close')
}
exit 0
