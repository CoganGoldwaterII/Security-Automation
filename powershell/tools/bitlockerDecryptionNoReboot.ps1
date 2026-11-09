# NAME: BitLocker OS Drive Decryption and Protector Cleanup
# AUTHORED BY: Automation Playbook
# TYPE: Remediation (manual/on-demand)
# SCOPE: Local Windows operating system volume only
# VARIABLES: None
# OUTPUT TOKENS: RESULT | NO_ACTION | ERROR
# CUSTOM FIELDS (Reads/Writes): None / None
# LOGGING PATH: C:\MME\AutoLogs\BitLocker_OSDrive_Decryption.log
# DESCRIPTION: Starts or resumes OS-drive decryption and confirms the process is
#              underway without waiting for completion. BitLocker permanently
#              removes its key protectors when decryption completes. Does not
#              clear the TPM, delete user files, change policies, or restart.

$ErrorActionPreference = 'Stop'

$logDirectory = 'C:\MME\AutoLogs'
$logPath = Join-Path -Path $logDirectory -ChildPath 'BitLocker_OSDrive_Decryption.log'
$stage = 'Initialize'
$token = 'ERROR'
$detail = 'NotStarted'

function Write-AuditLog {
    param([string]$Message)

    $timestamp = (Get-Date).ToString(
        'ddMMMyyyy HH:mm:ss',
        [System.Globalization.CultureInfo]::InvariantCulture
    ).ToUpperInvariant()

    Add-Content -LiteralPath $logPath -Encoding UTF8 -Value "[$timestamp] $Message" -ErrorAction Stop
}

try {
    $stage = 'Preflight'
    New-Item -ItemType Directory -Path $logDirectory -Force -ErrorAction Stop | Out-Null

    $principal = [System.Security.Principal.WindowsPrincipal]::new(
        [System.Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges are required.'
    }

    $osDrive = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).SystemDrive
    if ([string]::IsNullOrWhiteSpace($osDrive)) {
        throw 'Unable to determine the operating system drive.'
    }

    $stage = 'ReadBitLockerState'
    $volume = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction Stop
    $initialStatus = [string]$volume.VolumeStatus
    $action = 'None'

    if ($initialStatus -eq 'FullyDecrypted') {
        $action = 'AlreadyDecrypted'
    }
    elseif ($initialStatus -eq 'DecryptionInProgress') {
        $action = 'AlreadyDecrypting'
    }
    elseif ($initialStatus -eq 'DecryptionPaused') {
        $stage = 'ResumeDecryption'
        & manage-bde.exe -resume $osDrive | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "manage-bde -resume failed (exit code $LASTEXITCODE)."
        }
        $action = 'ResumedDecryption'
    }
    elseif ($initialStatus -in @('FullyEncrypted', 'EncryptionInProgress', 'EncryptionPaused')) {
        # The OS volume can store auto-unlock secrets for other encrypted drives.
        # Do not erase those secrets or alter other volumes to force this operation.
        if ($volume.AutoUnlockKeyStored -eq $true) {
            throw 'OS drive stores auto-unlock keys for other volumes. No keys were cleared. Review dependent data drives before decryption.'
        }

        $stage = 'StartDecryption'
        Disable-BitLocker -MountPoint $osDrive -Confirm:$false -ErrorAction Stop | Out-Null
        $action = 'StartedDecryption'
    }
    else {
        throw "Unsupported BitLocker volume status: $initialStatus"
    }

    $stage = 'VerifyDecryptionStarted'
    $volume = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction Stop
    $currentStatus = [string]$volume.VolumeStatus
    $encryptedPercent = $volume.EncryptionPercentage
    $protectorCount = @($volume.KeyProtector | Where-Object { $null -ne $_ }).Count

    if ($currentStatus -eq 'FullyDecrypted') {
        if ($protectorCount -ne 0) {
            throw "Drive is fully decrypted but $protectorCount BitLocker protectors remain. No manual protector deletion was attempted."
        }

        if ($action -eq 'AlreadyDecrypted') {
            $token = 'NO_ACTION'
        }
        else {
            $token = 'RESULT'
        }
        $detail = "Drive=$osDrive Action=$action Status=FullyDecrypted Protectors=0 ProtectorCleanup=Complete"
    }
    elseif ($currentStatus -eq 'DecryptionInProgress') {
        if ($action -eq 'AlreadyDecrypting') {
            $token = 'NO_ACTION'
        }
        else {
            $token = 'RESULT'
        }
        $detail = "Drive=$osDrive Action=$action Status=DecryptionInProgress Encrypted=$encryptedPercent% Protectors=$protectorCount ProtectorCleanup=PendingUntilFullyDecrypted"
    }
    else {
        throw "Expected DecryptionInProgress or FullyDecrypted; current status is $currentStatus."
    }
}
catch {
    $token = 'ERROR'
    $detail = "Stage=$stage Reason=$($_.Exception.Message)"
}

try {
    if (-not (Test-Path -LiteralPath $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory -Force -ErrorAction Stop | Out-Null
    }
    Write-AuditLog -Message "$token | $detail"
}
catch {
    $token = 'ERROR'
    $detail = "Stage=WriteLog Reason=$($_.Exception.Message) Previous=$detail"
}

Write-Output "$token | $detail"
exit 0
