# ============================================================================
# NAME: Network Security Audit Document Sync
# AUTHORED BY: Cogan Goldwater
# TYPE: Automation
# SCOPE: Windows Audit Runner / NinjaOne Organization Documents
#
# VARIABLES:
#   Required: None
#   Optional: None
#
#   Configuration values are defined within the script.
#   Test target: set $TargetDeviceId before use (placeholder 0).
#
# OUTPUT TOKENS:
#   RESULT | Status=Success when document synchronization verifies successfully
#   RESULT | Status=Failed when an error occurs
#
#   NO_ACTION | Not emitted
#   ERROR     | Not emitted
#
#   Script always exits 0 upon normal completion.
#
# CUSTOM FIELDS:
#   Reads: opServiceAccountToken (secure)
#   Writes: None
#
#   External writes:
#     NETWORK SECURITY AUDITS organization documents
#     Basic-<LOCATION> and Advanced-<LOCATION>, when present
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\Automation\Logs\Network_Security_Audit_Document_Sync.log
#
# DESCRIPTION:
#   Reads Local Windows Security Audit results from NinjaOne device
#   Activities and synchronizes workstation results into matching
#   NETWORK SECURITY AUDITS organization documents.
#
#   TEST PHASE:
#     Limited to the configured $TargetDeviceId (placeholder 0).
#
#   AUTHENTICATION:
#     Reads the Ninja secure custom field opServiceAccountToken.
#     Uses 1Password CLI with a configured vault and NinjaOne item.
#     Requires consoleUrl, clientId, clientSecret, and scope.
#     Requests a NinjaOne OAuth client_credentials access token.
#
#   DISCOVERY:
#     Resolves organization, location, template, document IDs, and
#     document field names dynamically through the NinjaOne API.
#
#   DOCUMENT SYNCHRONIZATION:
#     Updates both Basic-<LOCATION> and Advanced-<LOCATION> when present.
#     Requires API READ_WRITE permission on managed document fields.
#     Preserves other endpoint entries in multiline document fields.
#     Replaces existing entries matching the target Ninja device ID.
#
#   VERIFICATION:
#     Re-reads organization documents and checks that the target
#     Ninja device ID appears in each managed field.
#
#   SECURITY:
#     Does not intentionally output credentials or access tokens.
#     Clears the 1Password service account environment variable and
#     selected credential variables during cleanup.
#
#   WARNING:
#     Contains a configurable vault name and a placeholder test
#     device ID. Configure values before executing this example.
#
#     Failure output uses RESULT with Status=Failed rather than ERROR.
#     API response bodies may be included in diagnostic errors.
# ============================================================================


# ============================================================
# CONFIGURATION
# ============================================================

$TargetDeviceId = 0  # CONFIGURE: replace with an authorized NinjaOne test device ID

$VaultName    = "YOUR_1PASSWORD_VAULT"  # CONFIGURE BEFORE USE
$NinjaItem    = "NinjaOne"
$TemplateName = "NETWORK SECURITY AUDITS"

$DocumentPrefixes = @(
    "Basic-",
    "Advanced-"
)

$LogDirectory = "C:\Automation\Logs"
$LogPath      = Join-Path `
    $LogDirectory `
    "Network_Security_Audit_Document_Sync.log"


# Document field labels owned by this audit.

$ManagedFieldLabels = @(
    "Workstations - OS Version",
    "Workstations - Windows Updates",
    "Workstations - Firewall Enabled",
    "Workstations - Bitlocker Encryption",
    "Workstations - UAC",
    "Workstations - Local Admins",
    "Workstations - Local Accounts",
    "Workstations - Antivirus Enabled"
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Log {
    param(
        [string]$Message
    )

    try {

        if (-not (Test-Path -LiteralPath $LogDirectory)) {

            New-Item `
                -Path $LogDirectory `
                -ItemType Directory `
                -Force `
                -ErrorAction Stop | Out-Null
        }

        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        Add-Content `
            -LiteralPath $LogPath `
            -Value "$Timestamp | $Message" `
            -ErrorAction Stop
    }
    catch {
        # Logging failures do not terminate automation.
    }
}


function Clean-Text {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return (
        [string]$Value
    ).Replace(
        "`r", " "
    ).Replace(
        "`n", " "
    ).Replace(
        "|", "/"
    ).Trim()
}


function Get-OpExecutable {

    $Candidates = @(
        "$env:ProgramFiles\1Password CLI\op.exe",
        "$env:ProgramFiles\1Password\op.exe"
    )

    foreach ($Candidate in $Candidates) {

        if (
            $Candidate -and
            (Test-Path -LiteralPath $Candidate)
        ) {

            return $Candidate
        }
    }

    $Command = Get-Command `
        op.exe `
        -ErrorAction SilentlyContinue

    if ($Command) {
        return $Command.Source
    }

    throw "1Password CLI op.exe was not found."
}


function Get-OpItemField {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [string]$FieldName
    )

    $Field = $Item.fields |
        Where-Object {

            $_.label -eq $FieldName -or
            $_.id    -eq $FieldName
        } |
        Select-Object -First 1

    if (
        -not $Field -or
        [string]::IsNullOrWhiteSpace(
            [string]$Field.value
        )
    ) {
        throw "Required 1Password field '$FieldName' was not found."
    }

    return ([string]$Field.value).Trim()
}


function Invoke-NinjaApi {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            "GET",
            "POST",
            "PATCH"
        )]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Path,

        [AllowNull()]
        [object]$Body
    )

    $Uri = (
        $script:NinjaBaseUrl.TrimEnd("/") +
        $Path
    )

    $Parameters = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $script:NinjaHeaders
        ErrorAction = "Stop"
    }

    if ($null -ne $Body) {

        $Parameters.ContentType = "application/json"

        $Parameters.Body = (
            $Body |
                ConvertTo-Json `
                    -Depth 10 `
                    -Compress
        )
    }

    try {

        return Invoke-RestMethod @Parameters
    }
    catch {

        $ErrorText = $_.Exception.Message

        try {

            if ($_.Exception.Response) {

                $Stream = (
                    $_.Exception.Response.GetResponseStream()
                )

                if ($Stream) {

                    $Reader = New-Object `
                        System.IO.StreamReader($Stream)

                    $ResponseBody = $Reader.ReadToEnd()

                    $Reader.Dispose()

                    if ($ResponseBody) {

                        $ErrorText += (
                            " Response=" +
                            (Clean-Text $ResponseBody)
                        )
                    }
                }
            }
        }
        catch {
        }

        throw (
            "Ninja API request failed. " +
            "Method=$Method Path=$Path Error=$ErrorText"
        )
    }
}


function Get-StringLeaves {
    param(
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return
    }

    if ($InputObject -is [string]) {

        Write-Output $InputObject
        return
    }

    if ($InputObject -is [ValueType]) {
        return
    }

    if (
        $InputObject -is
        [System.Collections.IDictionary]
    ) {

        foreach ($Value in $InputObject.Values) {

            Get-StringLeaves `
                -InputObject $Value
        }

        return
    }

    if (
        $InputObject -is
        [System.Collections.IEnumerable]
    ) {

        foreach ($Item in $InputObject) {

            Get-StringLeaves `
                -InputObject $Item
        }

        return
    }

    foreach (
        $Property in
        $InputObject.PSObject.Properties
    ) {

        Get-StringLeaves `
            -InputObject $Property.Value
    }
}


function Get-AuditPayloadFromActivity {
    param(
        [Parameter(Mandatory)]
        [object]$Activity
    )

    $Strings = @(
        Get-StringLeaves `
            -InputObject $Activity
    )

    foreach ($Text in $Strings) {

        if (
            $Text -match
            'AUDIT_DATA\s*\|\s*(\{[^\r\n]+\})'
        ) {

            $Json = $Matches[1]

            try {

                return (
                    $Json |
                        ConvertFrom-Json `
                            -ErrorAction Stop
                )
            }
            catch {
                continue
            }
        }
    }

    return $null
}


function Get-PayloadValue {
    param(
        [Parameter(Mandatory)]
        [object]$Payload,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {

        $Property = (
            $Payload.PSObject.Properties |
                Where-Object {
                    $_.Name -eq $Name
                } |
                Select-Object -First 1
        )

        if (
            $Property -and
            $null -ne $Property.Value
        ) {
            return [string]$Property.Value
        }
    }

    return ""
}


function Get-DocumentFieldValue {
    param(
        [Parameter(Mandatory)]
        [object]$Document,

        [Parameter(Mandatory)]
        [string]$FieldName,

        [Parameter(Mandatory)]
        [string]$FieldLabel
    )

    $Field = $Document.fields |
        Where-Object {

            $_.name -ieq $FieldName -or
            $_.name -ieq $FieldLabel
        } |
        Select-Object -First 1

    if (
        -not $Field -or
        $null -eq $Field.value
    ) {
        return ""
    }

    if ($Field.value -is [string]) {
        return [string]$Field.value
    }

    if (
        $Field.value.PSObject.Properties.Name `
            -contains "text"
    ) {

        return [string]$Field.value.text
    }

    return [string]$Field.value
}


function Merge-DeviceLine {
    param(
        [AllowNull()]
        [string]$ExistingValue,

        [Parameter(Mandatory)]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [string]$NewLine
    )

    $Pattern = (
        "\[NinjaID:\s*" +
        [regex]::Escape($DeviceId) +
        "\]"
    )

    $ExistingLines = @()

    if (
        -not [string]::IsNullOrWhiteSpace(
            $ExistingValue
        )
    ) {

        $ExistingLines = @(
            [regex]::Split(
                $ExistingValue,
                "\r?\n"
            )
        )
    }

    $OutputLines = New-Object `
        System.Collections.Generic.List[string]

    $Replaced = $false

    foreach ($Line in $ExistingLines) {

        if ($Line -match $Pattern) {

            if (-not $Replaced) {

                $OutputLines.Add($NewLine)
                $Replaced = $true
            }

            # Any duplicate line for the same Ninja ID
            # is intentionally discarded.

            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($Line)) {

            $OutputLines.Add(
                $Line.TrimEnd()
            )
        }
    }

    if (-not $Replaced) {

        $OutputLines.Add($NewLine)
    }

    return (
        $OutputLines -join "`r`n"
    )
}


# ============================================================
# MAIN
# ============================================================

$Stage = "Initialize"

try {

    Write-Log "============================================================"
    Write-Log "START | Network Security Audit Document Sync"
    Write-Log "CONFIG | TargetDeviceId=$TargetDeviceId Template=$TemplateName"


    # ========================================================
    # 1. RETRIEVE 1PASSWORD BOOTSTRAP TOKEN
    # ========================================================

    $Stage = "NinjaBootstrap"

    Write-Log "STEP | Retrieve opServiceAccountToken"

    $BootstrapToken = Ninja-Property-Get `
        opServiceAccountToken

    if (
        [string]::IsNullOrWhiteSpace(
            [string]$BootstrapToken
        )
    ) {
        throw "opServiceAccountToken was empty."
    }

    $env:OP_SERVICE_ACCOUNT_TOKEN = (
        [string]$BootstrapToken
    ).Trim()

    $BootstrapToken = $null

    Write-Log "PASS | opServiceAccountToken retrieved"


    # ========================================================
    # 2. LOCATE / AUTHENTICATE 1PASSWORD
    # ========================================================

    $Stage = "1PasswordAuth"

    Write-Log "STEP | Locate 1Password CLI"

    $OpExe = Get-OpExecutable

    Write-Log "PASS | 1Password CLI located"

    $WhoAmI = @(
        & $OpExe whoami --format json 2>$null
    )

    if ($LASTEXITCODE -ne 0) {
        throw "1Password service account authentication failed."
    }

    Write-Log "PASS | 1Password service account authenticated"


    # ========================================================
    # 3. RETRIEVE NINJAONE CONFIGURATION
    # ========================================================

    $Stage = "NinjaConfiguration"

    Write-Log "STEP | Retrieve NinjaOne item from 1Password"

    $NinjaItemJson = @(
        & $OpExe `
            item get $NinjaItem `
            --vault $VaultName `
            --format json `
            2>$null
    ) -join "`n"

    if (
        $LASTEXITCODE -ne 0 -or
        [string]::IsNullOrWhiteSpace(
            $NinjaItemJson
        )
    ) {
        throw "Unable to retrieve NinjaOne item from 1Password."
    }

    $NinjaConfig = (
        $NinjaItemJson |
            ConvertFrom-Json `
                -ErrorAction Stop
    )

    $ConsoleUrl = Get-OpItemField `
        -Item $NinjaConfig `
        -FieldName "consoleUrl"

    $ClientId = Get-OpItemField `
        -Item $NinjaConfig `
        -FieldName "clientId"

    $ClientSecret = Get-OpItemField `
        -Item $NinjaConfig `
        -FieldName "clientSecret"

    $Scope = Get-OpItemField `
        -Item $NinjaConfig `
        -FieldName "scope"

    $NinjaItemJson = $null
    $NinjaConfig   = $null

    $script:NinjaBaseUrl = (
        $ConsoleUrl.TrimEnd("/")
    )

    Write-Log "PASS | NinjaOne configuration retrieved"


    # ========================================================
    # 4. AUTHENTICATE NINJAONE
    # ========================================================

    $Stage = "NinjaAuthentication"

    Write-Log "STEP | Request NinjaOne OAuth token"

    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12

    $TokenBody = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $Scope
    }

    $TokenResponse = Invoke-RestMethod `
        -Uri (
            $script:NinjaBaseUrl +
            "/ws/oauth/token"
        ) `
        -Method Post `
        -ContentType "application/x-www-form-urlencoded" `
        -Body $TokenBody `
        -ErrorAction Stop

    if (
        [string]::IsNullOrWhiteSpace(
            [string]$TokenResponse.access_token
        )
    ) {
        throw "NinjaOne OAuth token response contained no access token."
    }

    $script:NinjaHeaders = @{
        Authorization = (
            "Bearer " +
            $TokenResponse.access_token
        )

        Accept = "application/json"
    }

    # Secrets no longer needed after token acquisition.

    $ClientSecret = $null
    $TokenBody    = $null

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null

    Write-Log "PASS | NinjaOne authentication succeeded"


    # ========================================================
    # 5. GET TARGET DEVICE
    # ========================================================

    $Stage = "DeviceLookup"

    Write-Log "STEP | Resolve target device"

    $Device = Invoke-NinjaApi `
        -Method GET `
        -Path "/v2/device/$TargetDeviceId"

    if (-not $Device) {
        throw "Device $TargetDeviceId was not returned by NinjaOne."
    }

    $OrganizationId = [int]$Device.organizationId
    $LocationId     = [int]$Device.locationId

    $DeviceName = $null

    foreach (
        $Candidate in @(
            $Device.systemName,
            $Device.netbiosName,
            $Device.displayName,
            $Device.dnsName
        )
    ) {

        if (
            -not [string]::IsNullOrWhiteSpace(
                [string]$Candidate
            )
        ) {

            $DeviceName = (
                [string]$Candidate
            ).Trim()

            break
        }
    }

    if (-not $DeviceName) {
        $DeviceName = "UnknownDevice"
    }

    Write-Log (
        "PASS | Device resolved " +
        "DeviceId=$TargetDeviceId " +
        "Name=$DeviceName " +
        "OrganizationId=$OrganizationId " +
        "LocationId=$LocationId"
    )


    # ========================================================
    # 6. FIND LATEST AUDIT_DATA ACTIVITY
    # ========================================================

    $Stage = "ActivityLookup"

    Write-Log "STEP | Retrieve device activities"

    $ActivityResponse = Invoke-NinjaApi `
        -Method GET `
        -Path (
            "/v2/device/$TargetDeviceId/activities" +
            "?pageSize=1000"
        )

    $Activities = @(
        $ActivityResponse.activities |
            Sort-Object `
                activityTime `
                -Descending
    )

    if ($Activities.Count -eq 0) {
        throw "No Ninja activities were returned for device $TargetDeviceId."
    }

    $AuditPayload  = $null
    $AuditActivity = $null

    foreach ($Activity in $Activities) {

        $Payload = Get-AuditPayloadFromActivity `
            -Activity $Activity

        if ($Payload) {

            $PayloadAuditType = Get-PayloadValue `
                -Payload $Payload `
                -Names @(
                    "auditType"
                )

            if (
                $PayloadAuditType -and
                $PayloadAuditType -ne
                    "LocalWindowsSecurityAudit"
            ) {
                continue
            }

            $PayloadNodeId = Get-PayloadValue `
                -Payload $Payload `
                -Names @(
                    "nodeId"
                )

            if (
                $PayloadNodeId -and
                $PayloadNodeId -ne
                    [string]$TargetDeviceId
            ) {
                continue
            }

            $AuditPayload  = $Payload
            $AuditActivity = $Activity

            break
        }
    }

    if (-not $AuditPayload) {

        throw (
            "No AUDIT_DATA payload was found in the most recent " +
            "$($Activities.Count) activities for device $TargetDeviceId."
        )
    }

    Write-Log (
        "PASS | Audit payload found " +
        "ActivityId=$($AuditActivity.id)"
    )


    # ========================================================
    # 7. NORMALIZE CURRENT / FUTURE PAYLOAD FORMATS
    # ========================================================

    $Stage = "PayloadParse"

    $Uac = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "u",
            "uac"
        )

    $Firewall = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "fw",
            "firewall"
        )

    $BitLocker = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "bl",
            "bitLocker"
        )

    $Admins = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "ad",
            "admins"
        )

    $InactiveAccounts = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "ia",
            "inactiveAccounts"
        )

    $Windows = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "os",
            "windows"
        )

    $WindowsSupport = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "su",
            "windowsSupport"
        )

    $WindowsUpdate = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "wu",
            "qualityUpdate"
        )

    $Antivirus = Get-PayloadValue `
        -Payload $AuditPayload `
        -Names @(
            "av",
            "sentinelOne"
        )


    foreach (
        $RequiredValue in @(
            $Uac,
            $Firewall,
            $BitLocker,
            $Admins,
            $InactiveAccounts,
            $Windows,
            $WindowsUpdate,
            $Antivirus
        )
    ) {

        if (
            [string]::IsNullOrWhiteSpace(
                [string]$RequiredValue
            )
        ) {
            throw "Audit payload is missing one or more required values."
        }
    }

    Write-Log "PASS | Audit payload parsed"


    # ========================================================
    # 8. RESOLVE ORGANIZATION / LOCATION
    # ========================================================

    $Stage = "OrganizationLookup"

    Write-Log "STEP | Resolve organization and location"

    $Organization = Invoke-NinjaApi `
        -Method GET `
        -Path "/v2/organization/$OrganizationId"

    if (-not $Organization) {
        throw "Organization $OrganizationId could not be resolved."
    }

    $Location = $Organization.locations |
        Where-Object {
            [int]$_.id -eq $LocationId
        } |
        Select-Object -First 1

    if (-not $Location) {

        throw (
            "Location $LocationId was not found in " +
            "organization $OrganizationId."
        )
    }

    $LocationName = (
        [string]$Location.name
    ).Trim()

    if (
        [string]::IsNullOrWhiteSpace(
            $LocationName
        )
    ) {
        throw "Resolved Ninja location has no name."
    }

    Write-Log (
        "PASS | Location resolved " +
        "Organization=$($Organization.name) " +
        "Location=$LocationName"
    )


    # ========================================================
    # 9. RESOLVE DOCUMENT TEMPLATE / FIELD NAMES
    # ========================================================

    $Stage = "TemplateLookup"

    Write-Log "STEP | Resolve document template"

    $EncodedTemplateName = (
        [uri]::EscapeDataString(
            $TemplateName
        )
    )

    $Templates = @(
        Invoke-NinjaApi `
            -Method GET `
            -Path (
                "/v2/document-templates" +
                "?templateName=$EncodedTemplateName"
            )
    )

    $Template = $Templates |
        Where-Object {

            $_.name -eq $TemplateName -and
            -not $_.archived
        } |
        Select-Object -First 1

    if (-not $Template) {

        throw (
            "Document template '$TemplateName' " +
            "was not found."
        )
    }

    $TemplateId = [int]$Template.id

    $FieldMap = [ordered]@{}

    foreach ($Label in $ManagedFieldLabels) {

        $TemplateField = $Template.fields |
            Where-Object {
                $_.fieldLabel -eq $Label
            } |
            Select-Object -First 1

        if (-not $TemplateField) {

            throw (
                "Required document field was not found: " +
                "'$Label'."
            )
        }

        if (
            $TemplateField.fieldType -ne
            "TEXT_MULTILINE"
        ) {

            throw (
                "Field '$Label' is not TEXT_MULTILINE. " +
                "Type=$($TemplateField.fieldType)"
            )
        }

        if (
            $TemplateField.fieldApiPermission -ne
            "READ_WRITE"
        ) {

            throw (
                "Field '$Label' does not have API READ_WRITE permission. " +
                "Current=$($TemplateField.fieldApiPermission)"
            )
        }

        $FieldMap[$Label] = (
            [string]$TemplateField.fieldName
        )
    }

    Write-Log (
        "PASS | Template resolved " +
        "TemplateId=$TemplateId " +
        "MappedFields=$($FieldMap.Count)"
    )


    # ========================================================
    # 10. FIND BASIC / ADVANCED DOCUMENTS FOR LOCATION
    # ========================================================

    $Stage = "DocumentLookup"

    Write-Log "STEP | Resolve target documents"

    $Documents = @(
        Invoke-NinjaApi `
            -Method GET `
            -Path (
                "/v2/organization/" +
                "$OrganizationId/documents"
            )
    )

    $TargetDocumentNames = @(
        foreach ($Prefix in $DocumentPrefixes) {
            "$Prefix$LocationName"
        }
    )

    $TargetDocuments = @(
        $Documents |
            Where-Object {

                [int]$_.documentTemplateId -eq
                    $TemplateId -and

                $TargetDocumentNames -contains
                    $_.documentName
            }
    )

    if ($TargetDocuments.Count -eq 0) {

        throw (
            "No matching document found. Expected one or more of: " +
            ($TargetDocumentNames -join ", ")
        )
    }

    Write-Log (
        "PASS | Target documents found " +
        "Count=$($TargetDocuments.Count) " +
        "Names=$($TargetDocuments.documentName -join '; ')"
    )


    # ========================================================
    # 11. BUILD DEVICE-SPECIFIC FIELD VALUES
    # ========================================================

    $Stage = "BuildFieldValues"

    $DevicePrefix = (
        "$DeviceName " +
        "[NinjaID: $TargetDeviceId] | "
    )

    $OsResult = $Windows

    if (
        -not [string]::IsNullOrWhiteSpace(
            $WindowsSupport
        )
    ) {

        $OsResult += (
            " | " +
            $WindowsSupport
        )
    }

    $AuditValues = [ordered]@{

        "Workstations - OS Version" =
            $OsResult

        "Workstations - Windows Updates" =
            $WindowsUpdate

        "Workstations - Firewall Enabled" =
            $Firewall

        "Workstations - Bitlocker Encryption" =
            $BitLocker

        "Workstations - UAC" =
            $Uac

        "Workstations - Local Admins" =
            $Admins

        "Workstations - Local Accounts" =
            $InactiveAccounts

        "Workstations - Antivirus Enabled" =
            $Antivirus
    }


    # ========================================================
    # 12. BUILD PATCH REQUESTS
    # ========================================================

    $Stage = "BuildPatch"

    $PatchRequests = @()

    foreach ($Document in $TargetDocuments) {

        $FieldsToUpdate = [ordered]@{}

        foreach (
            $Label in
            $ManagedFieldLabels
        ) {

            $FieldName = $FieldMap[$Label]

            $ExistingValue = Get-DocumentFieldValue `
                -Document $Document `
                -FieldName $FieldName `
                -FieldLabel $Label

            $NewDeviceLine = (
                $DevicePrefix +
                (Clean-Text $AuditValues[$Label])
            )

            $MergedValue = Merge-DeviceLine `
                -ExistingValue $ExistingValue `
                -DeviceId ([string]$TargetDeviceId) `
                -NewLine $NewDeviceLine

            $FieldsToUpdate[$FieldName] = $MergedValue
        }

        $PatchRequests += [ordered]@{
            documentId = [int]$Document.documentId
            fields     = $FieldsToUpdate
        }
    }

    Write-Log (
        "PASS | Patch requests built " +
        "Documents=$($PatchRequests.Count)"
    )


    # ========================================================
    # 13. UPDATE DOCUMENTS
    # ========================================================

    $Stage = "DocumentUpdate"

    Write-Log "STEP | PATCH organization documents"

    $UpdateResult = @(
        Invoke-NinjaApi `
            -Method PATCH `
            -Path "/v2/organization/documents" `
            -Body $PatchRequests
    )

    Write-Log (
        "PASS | Document PATCH completed " +
        "Updated=$($UpdateResult.Count)"
    )


    # ========================================================
    # 14. VERIFY DOCUMENT WRITE
    # ========================================================

    $Stage = "Verification"

    Write-Log "STEP | Verify document update"

    $VerificationDocuments = @(
        Invoke-NinjaApi `
            -Method GET `
            -Path (
                "/v2/organization/" +
                "$OrganizationId/documents"
            )
    )

    $VerifiedDocuments = 0
    $VerifiedFields    = 0

    foreach ($OriginalDocument in $TargetDocuments) {

        $VerifiedDocument = (
            $VerificationDocuments |
                Where-Object {

                    [int]$_.documentId -eq
                    [int]$OriginalDocument.documentId
                } |
                Select-Object -First 1
        )

        if (-not $VerifiedDocument) {

            throw (
                "Updated document could not be re-read. " +
                "DocumentId=$($OriginalDocument.documentId)"
            )
        }

        foreach ($Label in $ManagedFieldLabels) {

            $FieldName = $FieldMap[$Label]

            $VerifiedValue = Get-DocumentFieldValue `
                -Document $VerifiedDocument `
                -FieldName $FieldName `
                -FieldLabel $Label

            $DevicePattern = (
                "\[NinjaID:\s*" +
                [regex]::Escape(
                    [string]$TargetDeviceId
                ) +
                "\]"
            )

            if (
                $VerifiedValue -notmatch
                $DevicePattern
            ) {

                throw (
                    "Verification failed. " +
                    "Document=$($VerifiedDocument.documentName) " +
                    "Field='$Label'"
                )
            }

            $VerifiedFields++
        }

        $VerifiedDocuments++
    }

    Write-Log (
        "PASS | Verification succeeded " +
        "Documents=$VerifiedDocuments " +
        "Fields=$VerifiedFields"
    )

    Write-Log "END | Success"

    Write-Output (
        "RESULT | Network Security Audit Document Sync | " +
        "Status=Success " +
        "Device=$DeviceName " +
        "NinjaID=$TargetDeviceId " +
        "Organization=$($Organization.name) " +
        "Location=$LocationName " +
        "Documents=$VerifiedDocuments " +
        "Fields=$VerifiedFields"
    )
}
catch {

    $Message = Clean-Text $_.Exception.Message

    Write-Log (
        "FAIL | Stage=$Stage " +
        "Error=$Message"
    )

    Write-Log "END | Failed"

    Write-Output (
        "RESULT | Network Security Audit Document Sync | " +
        "Status=Failed " +
        "Stage=$Stage " +
        "DeviceId=$TargetDeviceId " +
        "Error=$Message"
    )
}
finally {

    $env:OP_SERVICE_ACCOUNT_TOKEN = $null

    $ClientSecret = $null
    $TokenResponse = $null
    $script:NinjaHeaders = $null
}


exit 0