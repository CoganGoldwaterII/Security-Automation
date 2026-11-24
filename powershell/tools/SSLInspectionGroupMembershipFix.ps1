# ============================================================================
# NAME: AUTOMATION - AD SSL Inspection Group Membership
# AUTHORED BY: Cogan Goldwater
# TYPE: AUTOMATION
# SCOPE: Active Directory - Writable Domain Controller
# VARIABLES: None
# OUTPUT TOKENS: RESULT, NO_ACTION, ERROR
# CUSTOM FIELDS: remediationSummary (Read/Write), lastRemediationDate (Write)
# LOGGING PATH: C:\MME\AutoLogs\AD_SSL_Inspection.log
# DESCRIPTION: Discovers the local AD domain and creates the SSL Inspection
#              global security group in the default Users container if absent.
#              Adds missing Domain Users individually, including primary group
#              members, and verifies resulting membership. Runs as a standalone
#              one-time remediation under SYSTEM on a writable domain controller.
#              No existing memberships are removed.
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$ScriptBuild = '2026.11.24-v3'
$LogDirectory = 'C:\MME\AutoLogs'
$LogPath = Join-Path $LogDirectory 'AD_SSL_Inspection.log'
$GroupName = 'SSL Inspection'

$DomainName = 'Unknown'
$GroupCreated = $false
$UsersTotal = 0
$AlreadyMembers = 0
$Added = 0
$Failed = 0
$Missing = 0

$ResultToken = 'ERROR'
$ResultMessage = 'Automation did not complete.'
$LedgerMessage = ''

# ============================================================================
# LOGGING
# ============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Message = ($Message -replace '[\r\n]+', ' ').Trim()

    Add-Content -LiteralPath $LogPath `
        -Value "$Timestamp | $Level | $Message" `
        -Encoding UTF8
}

# ============================================================================
# REMEDIATION LEDGER
# ============================================================================

function Update-RemediationLedger {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    $Now = Get-Date
    $Date = $Now.ToString('yyyy-MM-dd')
    $IsoTimestamp = $Now.ToUniversalTime().ToString('o')
    $Message = ($Message -replace '[\r\n|]+', ' ').Trim()
    $Entry = "$Date | $Message"

    $MaxLines = 60
    $MaxCharacters = 4000

    if ($Entry.Length -gt $MaxCharacters) {
        throw 'Remediation ledger entry exceeds character limit.'
    }

    $Existing = Ninja-Property-Get remediationSummary

    $Lines = @(
        [string]$Existing -split '\r\n|\n|\r' |
            ForEach-Object { $_.Trim() } |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }
    )

    # Preserve existing entries and append only when not already present.
    if ($Lines -notcontains $Entry) {
        $Lines += $Entry
    }

    # Enforce line limit.
    $Lines = @(
        $Lines | Select-Object -Last $MaxLines
    )

    # Enforce character limit without splitting entries.
    while (($Lines -join "`r`n").Length -gt $MaxCharacters) {
        $Lines = @(
            $Lines | Select-Object -Skip 1
        )
    }

    $UpdatedSummary = $Lines -join "`r`n"

    Ninja-Property-Set remediationSummary $UpdatedSummary |
        Out-Null

    Ninja-Property-Set lastRemediationDate $IsoTimestamp |
        Out-Null
}

# ============================================================================
# FINALIZATION HELPER
# ============================================================================

function Finish {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('RESULT', 'NO_ACTION', 'ERROR')]
        [string]$Token,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$LedgerMessage = ''
    )

    $Message = ($Message -replace '[\r\n|]+', ' ').Trim()

    # Only verified, actual remediation can update the ledger.
    if ($Token -eq 'RESULT') {
        try {
            Update-RemediationLedger -Message $LedgerMessage
            Write-Log 'Remediation ledger updated.'
        }
        catch {
            $Token = 'ERROR'
            $Message = "$Message LedgerUpdate=Failed"
            try {
                Write-Log "Remediation ledger update or logging failed: $($_.Exception.Message)" 'ERROR'
            }
            catch {}
        }
    }

    try {
        Write-Log "$Token | $Message"
    }
    catch {
        $Token = 'ERROR'
        $Message = "$Message LoggingFailure=True"
    }

    Write-Output "$Token | $Message"
}

# ============================================================================
# MAIN
# ============================================================================

try {

    New-Item -Path $LogDirectory `
        -ItemType Directory `
        -Force |
        Out-Null

    Write-Log "Automation started. Build=$ScriptBuild"
    Write-Log "Execution identity: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

    # ========================================================================
    # DISCOVER ACTIVE DIRECTORY
    # ========================================================================

    Import-Module ActiveDirectory -ErrorAction Stop

    $Domain = Get-ADDomain -Current LocalComputer
    $DomainName = $Domain.DNSRoot

    $DC = Get-ADDomainController `
        -Discover `
        -DomainName $DomainName `
        -Writable

    $Server = [string]$DC.HostName

    $Domain = Get-ADDomain `
        -Identity $DomainName `
        -Server $Server

    Write-Log "Domain discovered: $DomainName"
    Write-Log "Writable domain controller: $Server"
    Write-Log "Default Users container: $($Domain.UsersContainer)"

    # ========================================================================
    # IDENTIFY DOMAIN USERS
    # ========================================================================

    $DomainUsersSID = "$($Domain.DomainSID.Value)-513"

    $DomainUsersGroup = Get-ADGroup `
        -Identity $DomainUsersSID `
        -Server $Server

    Write-Log "Source group: $($DomainUsersGroup.DistinguishedName)"

    # ========================================================================
    # ENUMERATE DOMAIN USERS
    # ========================================================================

    $SourceMembers = @{}

    $PrimaryMembers = @(
        Get-ADUser `
            -LDAPFilter '(primaryGroupID=513)' `
            -SearchBase $Domain.DistinguishedName `
            -Server $Server
    )

    foreach ($User in $PrimaryMembers) {
        $SourceMembers[$User.SID.Value] = $User
    }

    Write-Log "Primary group members: $($PrimaryMembers.Count)"

    $ExplicitMembers = @(
        Get-ADGroupMember `
            -Identity $DomainUsersGroup.DistinguishedName `
            -Recursive `
            -Server $Server |
            Where-Object { $_.ObjectClass -eq 'user' }
    )

    foreach ($User in $ExplicitMembers) {
        $SourceMembers[$User.SID.Value] = $User
    }

    Write-Log "Explicit and nested members: $($ExplicitMembers.Count)"

    $UsersTotal = $SourceMembers.Count

    Write-Log "Unique Domain Users: $UsersTotal"

    # ========================================================================
    # DISCOVER SSL INSPECTION GROUP
    # ========================================================================

    $Groups = @(
        Get-ADGroup `
            -Filter { Name -eq $GroupName } `
            -SearchBase $Domain.DistinguishedName `
            -Server $Server
    )

    if ($Groups.Count -gt 1) {
        throw "Multiple groups named '$GroupName' exist. Destination is ambiguous."
    }

    # ========================================================================
    # CREATE SSL INSPECTION GROUP IF ABSENT
    # ========================================================================

    if ($Groups.Count -eq 0) {

        Write-Log "Group '$GroupName' does not exist. Creating."

        try {

            $SSLGroup = New-ADGroup `
                -Name $GroupName `
                -SamAccountName $GroupName `
                -GroupScope Global `
                -GroupCategory Security `
                -Path $Domain.UsersContainer `
                -Server $Server `
                -PassThru

            $GroupCreated = $true

            Write-Log "Created group: $($SSLGroup.DistinguishedName)"

        }
        catch {
            throw "Failed to create required AD group '$GroupName': $($_.Exception.Message)"
        }

        # Verify group creation.

        $SSLGroup = Get-ADGroup `
            -Identity $SSLGroup.ObjectGUID `
            -Server $Server

        if (
            $SSLGroup.Name -ne $GroupName -or
            $SSLGroup.GroupCategory -ne 'Security' -or
            $SSLGroup.GroupScope -ne 'Global'
        ) {
            throw "Verification of newly created '$GroupName' group failed."
        }

        Write-Log 'Group creation verified.'

    }
    else {

        $SSLGroup = $Groups[0]

        Write-Log "Existing group found: $($SSLGroup.DistinguishedName)"
    }

    # ========================================================================
    # ENUMERATE EXISTING MEMBERSHIP
    # ========================================================================

    $ExistingMembers = @{}

    Get-ADGroupMember `
        -Identity $SSLGroup.DistinguishedName `
        -Server $Server |
        ForEach-Object {
            $ExistingMembers[$_.SID.Value] = $true
        }

    Write-Log "Existing destination members: $($ExistingMembers.Count)"

    # ========================================================================
    # ADD MISSING DOMAIN USERS
    # ========================================================================

    foreach ($User in $SourceMembers.Values) {

        $UserSID = $User.SID.Value

        if ($ExistingMembers.ContainsKey($UserSID)) {

            $AlreadyMembers++
            continue
        }

        try {

            Add-ADGroupMember `
                -Identity $SSLGroup.DistinguishedName `
                -Members $User.DistinguishedName `
                -Server $Server `
                -Confirm:$false

            $Added++

            Write-Log "Added user: $($User.SamAccountName)"

        }
        catch {

            $Failed++

            Write-Log `
                "Failed to add user $($User.SamAccountName): $($_.Exception.Message)" `
                'ERROR'
        }
    }

    Write-Log "Membership additions completed. Added=$Added Failed=$Failed"

    # ========================================================================
    # VERIFY RESULTING MEMBERSHIP
    # ========================================================================

    $VerifiedMembers = @{}

    Get-ADGroupMember `
        -Identity $SSLGroup.DistinguishedName `
        -Server $Server |
        ForEach-Object {
            $VerifiedMembers[$_.SID.Value] = $true
        }

    foreach ($User in $SourceMembers.Values) {

        if (-not $VerifiedMembers.ContainsKey($User.SID.Value)) {

            $Missing++

            Write-Log `
                "Membership verification failed: $($User.SamAccountName)" `
                'ERROR'
        }
    }

    Write-Log "Membership verification completed. Missing=$Missing"

    # ========================================================================
    # DETERMINE RESULT
    # ========================================================================

    $ResultMessage = (
        "Domain=$DomainName " +
        "GroupCreated=$GroupCreated " +
        "DomainUsers=$UsersTotal " +
        "AlreadyMembers=$AlreadyMembers " +
        "Added=$Added " +
        "Failed=$Failed " +
        "Missing=$Missing"
    )

    if ($Failed -gt 0 -or $Missing -gt 0) {

        $ResultToken = 'ERROR'

        Write-Log 'Remediation failed or could not be fully verified.' 'ERROR'

    }
    elseif ($GroupCreated -or $Added -gt 0) {

        Write-Log 'Remediation successfully verified.'

        $LedgerMessage = "SSL Inspection: Domain=$DomainName GroupCreated=$GroupCreated UsersAdded=$Added"

        $ResultToken = 'RESULT'

    }
    else {

        $ResultToken = 'NO_ACTION'

        Write-Log 'All required users are already members.'
    }

}
catch {

    $ResultToken = 'ERROR'

    $ErrorMessage = (
        $_.Exception.Message -replace '[\r\n|]+', ' '
    ).Trim()

    $ResultMessage = (
        "Domain=$DomainName " +
        "GroupCreated=$GroupCreated " +
        "DomainUsers=$UsersTotal " +
        "AlreadyMembers=$AlreadyMembers " +
        "Added=$Added " +
        "Failed=$Failed " +
        "Missing=$Missing " +
        "Error=$ErrorMessage"
    )

    try {
        Write-Log $ResultMessage 'ERROR'
    }
    catch {}
}

# ============================================================================
# FINALIZATION
# ============================================================================

finally {
    Finish -Token $ResultToken -Message $ResultMessage -LedgerMessage $LedgerMessage
}

exit 0
