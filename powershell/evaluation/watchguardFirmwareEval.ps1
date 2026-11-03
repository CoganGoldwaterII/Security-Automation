# ============================================================================
# NAME: WatchGuard Global Firmware Published Inventory First Evaluation v7.2
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Credential Broker only / WatchGuard global hierarchy
# VARIABLES:
#   None
# OUTPUT TOKENS:
#   TRIGGER   | Fully evaluated global inventory contains outdated firmware
#   NO_ACTION | Fully evaluated global inventory has no outdated firmware
#   ERROR     | Incomplete discovery, reference failure, or unresolved device
# CUSTOM FIELDS:
#   Reads: Configured NinjaOne secure field containing the 1Password token
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   C:\Automation\Logs\WatchGuard_Firmware_Global_Evaluation.log
# DESCRIPTION:
#   Read-only global inventory using proven WatchGuard account/device discovery.
#   FIRST: Inventory published Firebox hardware/release pairs from
#   the live Downloads homepage, corroborated by the WatchGuard release
#   bulletin, with documented fail-closed bulletin fallback if HTML is sparse.
#   No hardcoded fleet model whitelist.
#   SECOND: Verify available model-family download pages once, before accounts.
#   THEN: Discover the global estate and resolve each model against that live
#   inventory; compare its installed firmware against the verified target.
#   Known family URLs are optional navigation hints, NOT model/version allowlists.
#   Unknown or ambiguous variants and unreviewed exact build numbers fail closed.
#   Published SHA1 is recorded only; no installer binary or PDF is downloaded.
#   Startup failures report exact exception reason, stage and script line.
#   Current build numbers are independently approved release-note references;
#   new releases require build review to prevent automatic false approval.
#   Excludes protected hosted/virtual accounts, local devices, and FireClusters.
#   Never-connected registrations and explicitly verified EOL hardware are
#   NO_ACTION / review-required exclusions, never current or upgrade-eligible.
#   Inactive devices without clear lifecycle state remain ERROR.
#   Unknown unverified models, catalog failures, and API failures remain ERROR.
#   Excluded/review-required records are retained in the JSON report.
#   No firmware changes, scheduling, deployment, Ninja field writes, or ledger.
#   All actual faults produce ERROR; exactly one final exit 0.
# ============================================================================
# PUBLIC GITHUB TEMPLATE: configure the values in the publication settings
# below before deployment. Placeholder validation fails closed before API use.
# Never publish generated device/account JSON reports or execution logs.

# No top-level parameters. NinjaOne runs this script as a plain script.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# PUBLICATION CONFIGURATION: replace these IDs with YOUR verified protected
# hosted/virtual accounts. Keep ALL production exclusions in the private copy.
# Exact IDs protect accounts against display-name changes. The public copy
# refuses to evaluate when the placeholder list is not configured.
$ProtectedAccountIds = @(
    'SET_PROTECTED_ACCOUNT_ID_1'
    'SET_PROTECTED_ACCOUNT_ID_2'
    'SET_PROTECTED_ACCOUNT_ID_3'
    'SET_PROTECTED_ACCOUNT_ID_4'
)

# Fail-closed hosted-name indicators. Protected ancestry propagates to children.
$ProtectedNamePattern = '(?i)(\bdatacentre\b|\bdata[\s-]?center\b|\bazure\b|\bhosted\b|\bhosting\b|\bco[\s-]?location\b|\bcolo\b|\bvps\b|\bvirtual[\s-]*appliance\b)'
$VirtualModelPattern = '(?i)^(?:FIREBOX\s*CLOUD|FIREBOXV|FIREBOX\s*V|NV5|VIRTUAL|CLOUD)$'

# Explicit negative-only EOL evidence. NOT a supported-model inventory or a
# firmware target table. Only a model with an independently verified vendor
# end-of-life date is excluded as retired; every other unknown model fails closed.
# WatchGuard EOL Policy: T35-W EOL was 31DEC2025 (checked 03NOV2026).
$ReviewedRetiredModels = @{
    'T35-W' = [pscustomobject]@{
        EndOfLife='2025-12-31'
        Source='https://www.watchguard.com/wgrd-trust-center/end-of-life-policy'
        Replacement='T125-W or T145-W'
    }
}

# Optional navigation hints for direct model-family download pages.
# These URLs do NOT define model eligibility or current releases.
# Live model inventory is built from software.watchguard.com at run startup.
# Pages not linked here may still be compared from the live homepage inventory;
# missing package-level proof is explicitly reported, not silently claimed.
$FirmwareFamilies = @{
    'T20_T40' = [pscustomobject]@{
        Family='T20/T40'; Heading='Software for Firebox T20 and T40'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2R0H000003CvTpUAK'
    }
    'T80' = [pscustomobject]@{
        Family='T80'; Heading='Software for Firebox T80'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2R0H000003CvTqUAK'
    }
    'T115_T125_T145' = [pscustomobject]@{
        Family='T115/T125/T145'; Heading='Software for Firebox T115, T125, T145'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2RVr000001HpWzMAK'
    }
    'T25_T45' = [pscustomobject]@{
        Family='T25/T45'; Heading='Software for Firebox T25 and T45'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2R6S00000537cVUAQ'
    }
    'T85' = [pscustomobject]@{
        Family='T85'; Heading='Software for Firebox T85'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2R6S00000537cQUAQ'
    }
    'M270_M370_M470' = [pscustomobject]@{
        Family='M270/M370/M470/M570/M670'; Heading='Software for Firebox M270, M370, M470, M570 and M670'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2R2A000002aHhRUAU'
    }
    'M290' = [pscustomobject]@{
        Family='M290'; Heading='Software for Firebox M290'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2R6S000000NkiTUAS'
    }
    'M390' = [pscustomobject]@{
        Family='M390'; Heading='Software for Firebox M390'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2R6S000000NkiOUAS'
    }
    'T35' = [pscustomobject]@{
        Family='T35'; Heading='Software for Firebox T35'
        Catalog='https://software.watchguard.com/SoftwareDownloads?current=true&familyId=a2R2A000002amFiUAI'
    }
}

# Independent official RELEASE NOTE build references, checked 03NOV2026.
# Runtime compares the actual current catalog release to these references.
# If WatchGuard publishes a NEW GA version, evaluation fails closed until its
# new build and release notes have been reviewed. Not a per-model whitelist.
$ReviewedReleaseBuilds = @{
    '2026.4' = [pscustomobject]@{
        Build=750021L
        Notes='https://www.watchguard.com/support/release-notes/fireware/2026/en_US/2026_4/Fireware_Release-Notes_v2026_4.pdf'
    }
    '12.12.4' = [pscustomobject]@{
        Build=749975L
        Notes='https://www.watchguard.com/support/release-notes/fireware/12/en-US/EN_ReleaseNotes_Fireware_12_12_4/Fireware_Release-Notes_v12_12_4.pdf'
    }
    '12.5.22' = [pscustomobject]@{
        Build=749806L
        Notes='https://www.watchguard.com/support/release-notes/fireware/12/en-US/EN_ReleaseNotes_Fireware_12_5_22/Fireware_Release-Notes_v12_5_22.pdf'
    }
}

$OnePasswordVault = 'SET_1PASSWORD_VAULT_NAME'
$WatchGuardItemName = 'SET_1PASSWORD_ITEM_NAME'
$BootstrapTokenField = 'SET_NINJA_SECURE_FIELD_NAME'
$LogPath = 'C:\Automation\Logs\WatchGuard_Firmware_Global_Evaluation.log'
$ReportPath = 'C:\Automation\Staging\WatchGuard_Firmware_Global_Evaluation.json'
$CurrentStage = 'Initialize'
$FinalOutput = $null
$ServiceAccountToken = $null
$WatchGuardItem = $null
$ApiKey = $null
$ReadOnlyAccessId = $null
$ReadOnlyPassword = $null
$AuthenticationUrl = $null
$BaseApiUrl = $null
$RootAccountId = $null
$ProviderToken = $null
$ProviderTokenAcquiredAt = $null
$OpExe = $null
$DeviceResults = [System.Collections.Generic.List[object]]::new()
$AccountResults = [System.Collections.Generic.List[object]]::new()
$DiagnosticErrors = [System.Collections.Generic.List[object]]::new()
$CatalogCache = @{}
$PublishedModels = @{}
$FamilyByBaseModel = @{}
$CatalogBootstrapErrors = [System.Collections.Generic.List[object]]::new()
$InventoryHomepageUrl = 'https://software.watchguard.com/'
$PublishedInventorySource = $null
$PublishedInventoryVersions = @()
$SeenDevices = @{}
$UnknownModels = @{}
$ErrorCount = 0
$TriggerCount = 0
$CurrentCount = 0
$ExcludedCount = 0
$DiscoveredCount = 0
$AccountsCompleted = 0
$AccountsFailed = 0
$AccountsSkipped = 0
$AccountsDiscovered = 0
$AccountsAttempted = 0
$GlobalStarted = Get-Date
$AccountRecords = @()

function SafeText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $Result = (([string]$Value -replace '[\r\n|]+',' ' -replace '\s{2,}',' ')).Trim()
    if ($Result.Length -gt 160) { return $Result.Substring(0,160) }
    return $Result
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    try {
        ('{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message) |
            Add-Content -LiteralPath $LogPath -Encoding UTF8
    } catch { }
}

function Get-HttpStatusCode {
    param([AllowNull()][object]$Exception)
    try {
        if ($null -ne $Exception -and $null -ne $Exception.Response -and
            $null -ne $Exception.Response.StatusCode) {
            return [int]$Exception.Response.StatusCode
        }
    } catch { }
    return $null
}

function Invoke-WatchGuardGetWithRetry {
    param([Parameter(Mandatory)][string]$Uri,
          [Parameter(Mandatory)][hashtable]$Headers,
          [int]$TimeoutSec = 60,
          [int]$MaxAttempts = 4)
    $Delays = @(2,5,10)
    for ($Attempt=1; $Attempt -le $MaxAttempts; $Attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec
        } catch {
            $Status = Get-HttpStatusCode -Exception $_.Exception
            $Allowed = $MaxAttempts
            if ($Status -eq 403) { $Allowed = [Math]::Min($MaxAttempts,2) }
            $Transient400 = $false
            if ($Status -eq 400) {
                $Allowed = [Math]::Min($MaxAttempts,2)
                $Transient400 = $_.Exception.Message -match '(?i)temporar|timed?\s*out|try\s+again|server\s+busy'
            }
            $CanRetry = ($null -eq $Status -or $Status -in @(403,408,429,500,502,503,504) -or $Transient400)
            if (-not $CanRetry -or $Attempt -ge $Allowed) { throw }
            $Delay = $Delays[[Math]::Min($Attempt-1,$Delays.Count-1)]
            Write-Log ('WARN | GET_RETRY Attempt={0}/{1} HTTP={2} DelaySeconds={3}' -f $Attempt,$Allowed,$Status,$Delay)
            Start-Sleep -Seconds $Delay
        }
    }
}

function Get-CatalogVerification {
    param([Parameter(Mandatory)][object]$FamilyReference)
    $Page = $null
    $Delays = @(2,5,10)
    for ($Attempt=1; $Attempt -le 4; $Attempt++) {
        try {
            $Page = Invoke-WebRequest -Method Get -Uri $FamilyReference.Catalog `
                -UseBasicParsing -TimeoutSec 45 -MaximumRedirection 3
            break
        } catch {
            $Status = Get-HttpStatusCode -Exception $_.Exception
            if ($Attempt -eq 4 -or ($null -ne $Status -and $Status -notin @(408,429,500,502,503,504))) { throw }
            Write-Log ('WARN | CatalogRetry Family={0} Attempt={1} HTTP={2}' -f $FamilyReference.Family,$Attempt,$Status)
            Start-Sleep -Seconds $Delays[$Attempt-1]
        }
    }
    if ($null -eq $Page -or [string]::IsNullOrWhiteSpace([string]$Page.Content)) {
        throw 'EmptyCatalogResponse'
    }
    $FinalUri = $null
    try { $FinalUri = $Page.BaseResponse.ResponseUri } catch { }
    if ($null -eq $FinalUri) {
        try { $FinalUri = $Page.BaseResponse.RequestMessage.RequestUri } catch { }
    }
    if ($null -eq $FinalUri -or $FinalUri.Scheme -ne 'https' -or
        $FinalUri.Host -ne 'software.watchguard.com') {
        throw 'UnexpectedCatalogRedirect'
    }
    $Html = ([string]$Page.Content) -replace '(?is)<script\b[^>]*>.*?</script>',' '
    $Html = $Html -replace '(?is)<style\b[^>]*>.*?</style>',' '
    $Text = [System.Net.WebUtility]::HtmlDecode(($Html -replace '(?s)<[^>]+>',' ')) -replace '\s+',' '
    $Heading = [regex]::Match($Text,[regex]::Escape([string]$FamilyReference.Heading),'IgnoreCase')
    if (-not $Heading.Success) { throw 'ExpectedModelFamilyHeadingMissing' }
    $Tail = $Text.Substring($Heading.Index + $Heading.Length)
    $Tail = $Tail.Substring(0,[Math]::Min(2500,$Tail.Length))
    # Some official family pages use "Fireware 12.12.4" rather than "Fireware v12.12.4".
    $Latest = [regex]::Match($Tail,'(?i)\bFireware\s+v?(?<release>\d+\.\d+(?:\.\d+)?)\b')
    if (-not $Latest.Success) { throw 'CurrentFirewareReleaseHeadingMissing' }
    $PostRelease = $Tail.Substring($Latest.Index + $Latest.Length)
    if ($PostRelease -match '^\s*(?i:beta|preview|rc\b|release\s+candidate)') {
        throw 'PrereleaseCatalogReleaseNotAllowed'
    }
    $LiveRelease = [string]$Latest.Groups['release'].Value
    $OsPackage = [regex]::Match($Tail,
        '(?i)Operating\s+System\s+Files\s+Fireware\s+(?<release>\d+\.\d+(?:\.\d+)?)\s+Released\s+.{0,90}?\bSHA1\s+(?<sha>[0-9a-f]{40})')
    if (-not $OsPackage.Success) { throw 'OSInstallerChecksumNotFoundOrCatalogChanged' }
    if ($OsPackage.Groups['release'].Value -cne $LiveRelease) {
        throw 'CatalogHeaderAndInstallerReleaseDisagree'
    }
    if (-not $ReviewedReleaseBuilds.ContainsKey($LiveRelease)) {
        throw ('UnreviewedNewRelease:{0}' -f $LiveRelease)
    }
    $Notes = $ReviewedReleaseBuilds[$LiveRelease]
    return [pscustomobject]@{
        Latest=$LiveRelease
        Version=('{0}.B{1}' -f $LiveRelease,[long]$Notes.Build)
        Build=[long]$Notes.Build
        Notes=[string]$Notes.Notes
        Sha1=$OsPackage.Groups['sha'].Value.ToLowerInvariant()
    }
}

function Get-OfficialPageText {
    param([Parameter(Mandatory)][string]$Uri)
    $Page = $null
    $Delays = @(2,5,10)
    for ($Attempt=1; $Attempt -le 4; $Attempt++) {
        try {
            $Page = Invoke-WebRequest -Method Get -Uri $Uri -UseBasicParsing `
                -TimeoutSec 45 -MaximumRedirection 3
            break
        } catch {
            $Status = Get-HttpStatusCode -Exception $_.Exception
            if ($Attempt -eq 4 -or ($null -ne $Status -and
                $Status -notin @(408,429,500,502,503,504))) { throw }
            Start-Sleep -Seconds $Delays[$Attempt-1]
        }
    }
    if ($null -eq $Page -or [string]::IsNullOrWhiteSpace([string]$Page.Content)) {
        throw 'EmptyOfficialPageResponse'
    }
    $UriObject = $null
    try { $UriObject = $Page.BaseResponse.ResponseUri } catch { }
    if ($null -eq $UriObject) {
        try { $UriObject = $Page.BaseResponse.RequestMessage.RequestUri } catch { }
    }
    if ($null -eq $UriObject -or $UriObject.Scheme -ne 'https' -or
        $UriObject.Host -notin @('software.watchguard.com','www.watchguard.com','watchguard.com')) {
        throw 'UnexpectedOfficialPageRedirect'
    }
    $Html = [string]$Page.Content
    $Clean = $Html -replace '(?is)<script\b[^>]*>.*?</script>',' '
    $Clean = $Clean -replace '(?is)<style\b[^>]*>.*?</style>',' '
    $Clean = $Clean -replace '(?is)<[^>]+>',' '
    $Text = [System.Net.WebUtility]::HtmlDecode($Clean) -replace '\s+',' '
    return [pscustomobject]@{ Html=$Html; Text=$Text; Uri=$Uri }
}

function Convert-PublishedModelListToIndex {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][ValidateSet('Homepage','Bulletin')][string]$Format
    )
    $Index = @{}
    if ($Format -eq 'Homepage') {
        $Start = [regex]::Match($Text,'(?i)Latest\s+Software\s+Releases\s*:')
        if (-not $Start.Success) { throw 'HomepageReleaseHeadingNotPresentInHttpResponse' }
        $Scope = $Text.Substring($Start.Index + $Start.Length)
        $Stop = [regex]::Match($Scope,'(?i)(WatchGuard\s+Dimension\s+v\d|\bQuick\s+Links\b)')
        if ($Stop.Success) { $Scope = $Scope.Substring(0,$Stop.Index) }
        $Rows = [regex]::Matches($Scope,
            '(?i)\bFireware\s+v?(?<release>(?:20\d{2}|\d{1,2})\.\d+(?:\.\d+)?)\s+for\s+Firebox\s+(?<models>.*?)(?=\s*[-\u2022]?\s*Fireware\s+v?(?:20\d{2}|\d{1,2})\.\d+|$)',
            [System.Text.RegularExpressions.RegexOptions]::Singleline)
    } else {
        # WatchGuard's release bulletin has an explicit 'Which release is right'
        # model matrix. Unlike its Javascript-driven Software Downloads home,
        # this article is available as ordinary server-delivered HTML.
        $Start = [regex]::Match($Text,'(?i)Which\s+release\s+is\s+right\s+for\s+your\s+Firebox')
        if (-not $Start.Success) { throw 'ReleaseBulletinCompatibilityTableMissing' }
        $Scope = $Text.Substring($Start.Index + $Start.Length)
        $Stop = [regex]::Match($Scope,'(?i)Check\s+each\s+release.{0,60}notes|\bHow\s+to\s+upgrade\b')
        if ($Stop.Success) { $Scope = $Scope.Substring(0,$Stop.Index) }
        $Rows = [regex]::Matches($Scope,
            '(?i)\bFireware\s+(?<release>(?:20\d{2}|\d{1,2})\.\d+(?:\.\d+)?)\s+(?<models>.*?)(?=\s+Fireware\s+(?:20\d{2}|\d{1,2})\.\d+|$)',
            [System.Text.RegularExpressions.RegexOptions]::Singleline)
    }
    if ($Rows.Count -lt 2) { throw ('PublishedFirewareTableUnparseable:{0}:Rows={1}' -f $Format,$Rows.Count) }

    foreach ($Row in $Rows) {
        $Release = [string]$Row.Groups['release'].Value
        $Models = [string]$Row.Groups['models'].Value
        if ($Format -eq 'Bulletin') {
            # Strip '12.12.4 notes' text that follows each model-list cell.
            $Models = [regex]::Replace($Models,'(?i)\b\d+\.\d+(?:\.\d+)?\s+notes\b',' ')
            # Expand abbreviations used by WatchGuard, not a local model list.
            # Example: T125/-W => T125, T125-W.
            $Models = [regex]::Replace($Models,
                '(?i)\b(?<base>[TM]\d{2,4})\s*/\s*(?<suffix>-[A-Z]{1,5})\b',
                '${base}, ${base}${suffix}')
            # Example: T20/40/80 => T20, T40, T80.
            $Groups = [regex]::Matches($Models,
                '(?i)\b(?<prefix>[TM])(?<first>\d{2,4})(?<rest>(?:/\d{2,4})+)\b')
            foreach ($Group in $Groups) {
                $Prefix = $Group.Groups['prefix'].Value.ToUpperInvariant()
                $Expanded = @($Prefix + $Group.Groups['first'].Value)
                foreach ($Number in $Group.Groups['rest'].Value.TrimStart('/').Split('/')) {
                    $Expanded += ($Prefix + $Number)
                }
                $Models = $Models.Replace($Group.Value,($Expanded -join ', '))
                if ($Row.Groups['models'].Value -match '(?i)all\s+variants') {
                    foreach ($Base in $Expanded) { $script:VariantEvidence[$Base] = $true }
                }
            }
        }
        $Tokens = [regex]::Matches($Models,
            '(?i)\b[TM]\d{2,4}(?:-(?:W|DW|R))?\b')
        foreach ($Token in $Tokens) {
            $Model = $Token.Value.ToUpperInvariant()
            if ($Index.ContainsKey($Model) -and $Index[$Model] -cne $Release) {
                throw ('ConflictingOfficialModelRelease:{0}' -f $Model)
            }
            $Index[$Model] = $Release
            if ($Format -eq 'Bulletin' -and $Model -match '^T\d{2,4}-(?:W|DW|R)$') {
                $script:VariantEvidence[$Model] = $true
            }
        }
    }
    if ($Index.Count -lt 10) {
        throw ('OfficialModelInventoryUnexpectedlySmall:{0}:Models={1}' -f $Format,$Index.Count)
    }
    return $Index
}

function Initialize-LivePublishedInventory {
    $script:VariantEvidence = @{}
    $script:PublishedModels = @{}
    $script:PublishedInventorySource = $null
    $BulletinUri = 'https://www.watchguard.com/it/wgrd-blog/update-your-firebox-fireware-20264-12124-and-12522'
    $HomepageUris = @(
        'https://software.watchguard.com/',
        'https://software.watchguard.com/SoftwareHome'
    )
    $HomepageIssues = [System.Collections.Generic.List[string]]::new()

    foreach ($HomepageUri in $HomepageUris) {
        try {
            $HomepageDocument = Get-OfficialPageText -Uri $HomepageUri
            $HomeIndex = Convert-PublishedModelListToIndex -Text ([string]$HomepageDocument.Text) -Format 'Homepage'
            $script:PublishedModels = $HomeIndex
            $script:PublishedInventorySource = $HomepageUri
            Write-Log ('PASS | LiveHomeInventory Models={0} Source={1}' -f $HomeIndex.Count,$HomepageUri)
            break
        } catch {
            $Issue = ('{0}={1}' -f $HomepageUri,(SafeText $_.Exception.Message))
            $HomepageIssues.Add($Issue)
            Write-Log ('WARN | LiveHomeInventoryUnavailable Source={0} Reason={1}' -f `
                $HomepageUri,(SafeText $_.Exception.Message))
        }
    }

    $Bulletin = $null
    $BulletinIndex = $null
    try {
        $Bulletin = Get-OfficialPageText -Uri $BulletinUri
        $BulletinIndex = Convert-PublishedModelListToIndex -Text ([string]$Bulletin.Text) -Format 'Bulletin'
        Write-Log ('PASS | OfficialReleaseBulletin Models={0} VariantGroups={1}' -f `
            $BulletinIndex.Count,$script:VariantEvidence.Count)
    } catch {
        # Discard evidence from any partially parsed or invalid bulletin.
        $script:VariantEvidence = @{}
        Write-Log ('WARN | OfficialReleaseBulletinUnavailable Reason={0}' -f (SafeText $_.Exception.Message))
        if ($script:PublishedModels.Count -eq 0) {
            throw ('NoParseableOfficialModelInventory:Home={0}:Bulletin={1}' -f `
                ($HomepageIssues -join ';'),(SafeText $_.Exception.Message))
        }
    }

    if ($script:PublishedModels.Count -eq 0) {
        # The download homepage may require browser Javascript. Use the model
        # matrix in WatchGuard's official release bulletin, never a hardcoded
        # fleet model table. Subsequent family-page checks fail closed on a
        # stale release, so this fallback cannot silently approve an update.
        $script:PublishedModels = $BulletinIndex
        $script:PublishedInventorySource = $BulletinUri
        Write-Log ('WARN | OfficialPublishedInventoryFallback Source={0} Models={1}' -f `
            $BulletinUri,$script:PublishedModels.Count)
    } elseif ($null -ne $BulletinIndex) {
        # Where both sources give explicit model releases, disagreement is
        # review-required: never silently prefer one source over the other.
        $Disagreement = $null
        foreach ($Model in @($BulletinIndex.Keys)) {
            if ($script:PublishedModels.ContainsKey($Model) -and
                $script:PublishedModels[$Model] -cne $BulletinIndex[$Model]) {
                $Disagreement = ('Model={0} Home={1} Bulletin={2}' -f `
                    $Model,$script:PublishedModels[$Model],$BulletinIndex[$Model])
                break
            }
        }
        if ($null -ne $Disagreement) {
            if ($script:PublishedInventorySource -eq 'https://software.watchguard.com/SoftwareHome') {
                # This secondary URL can expose an older snapshot. Prefer
                # the current dated official bulletin, then verify every known
                # family against its current Download page. No blind approval.
                Write-Log ('WARN | SecondaryHomeStale UsingBulletin Reason={0}' -f $Disagreement)
                $script:PublishedModels = $BulletinIndex
                $script:PublishedInventorySource = $BulletinUri
            } else {
                throw ('OfficialSourcesDisagreeForModel:{0}' -f $Disagreement)
            }
        }
    }
    $script:PublishedInventoryVersions = @($script:PublishedModels.Values | Select-Object -Unique | Sort-Object)
    Write-Log ('PASS | OfficialModelInventory Models={0} Releases={1} Source={2}' -f `
        $script:PublishedModels.Count,($script:PublishedInventoryVersions -join ','),$script:PublishedInventorySource)
}

function Initialize-LiveFamilyCatalogs {
    # Discover available model-family catalog pages once, at the beginning.
    # Known URLs are navigation hints only; model associations are derived from
    # the family headings, and versions must match the independent home index.
    foreach ($Key in @($FirmwareFamilies.Keys | Sort-Object)) {
        $Ref = $FirmwareFamilies[$Key]
        # Associate the page heading with its model bases BEFORE fetching.
        # If page verification fails, every affected model fails closed rather
        # than silently falling back to an unchecked homepage-only match.
        $ModelTokens = [regex]::Matches([string]$Ref.Heading,'(?i)\b[TM]\d{2,4}\b')
        foreach ($Token in $ModelTokens) {
            $BaseModel = $Token.Value.ToUpperInvariant()
            if ($script:FamilyByBaseModel.ContainsKey($BaseModel) -and
                $script:FamilyByBaseModel[$BaseModel] -cne $Key) {
                throw ('AmbiguousModelCatalogFamily:{0}' -f $BaseModel)
            }
            $script:FamilyByBaseModel[$BaseModel] = $Key
        }
        try {
            $Verified = Get-CatalogVerification -FamilyReference $Ref
            $script:CatalogCache[$Key] = [pscustomobject]@{
                valid=$true; latest=$Verified.Latest;version=$Verified.Version
                build=$Verified.Build;notes=$Verified.Notes;sha1=$Verified.Sha1
                catalog=$Ref.Catalog;family=$Ref.Family;error=$null
            }
            Write-Log ('PASS | CatalogPreflight Family={0} Latest={1} Models={2}' -f `
                $Key,$Verified.Latest,$ModelTokens.Count)
        } catch {
            $Reason = SafeText $_.Exception.Message
            $script:CatalogCache[$Key] = [pscustomobject]@{
                valid=$false;latest=$null;version=$null;build=$null;notes=$null
                sha1=$null;catalog=$Ref.Catalog;family=$Ref.Family;error=$Reason
            }
            $script:CatalogBootstrapErrors.Add([pscustomobject]@{
                family=$Key; reason=$Reason; url=$Ref.Catalog
            })
            Write-Log ('WARN | CatalogPreflightFailed Family={0} Reason={1}' -f $Key,$Reason)
        }
    }
}

function Resolve-LiveModelTarget {
    param([Parameter(Mandatory)][string]$Model)
    $Model = $Model.Trim().ToUpperInvariant()
    $Evidence = 'HomeExactModel'
    $BaseModel = $Model
    if ($Model -match '^(?<base>T\d{2,4})-(?:W|DW|R|POE|W-POE|POE-W|CW)$') {
        $BaseModel = [string]$Matches['base']
    }
    $Release = $null
    if ($PublishedModels.ContainsKey($Model)) {
        $Release = [string]$PublishedModels[$Model]
    } else {
        # Only explicitly corroborated variant groups may inherit a published
        # base-model release. Retired T35-W is NOT equivalent to T35-DW/R.
        if ($Model -match '^(T\d{2,3})-(?:W|POE|W-POE|POE-W|CW)$') {
            $BaseModel = $Matches[1]
            if (-not $script:VariantEvidence.ContainsKey($BaseModel)) {
                throw 'VariantSupportNotVerifiedByWatchGuard'
            }
            if (-not $PublishedModels.ContainsKey($BaseModel)) {
                throw 'ModelAbsentFromLiveWatchGuardInventory'
            }
            $Release = [string]$PublishedModels[$BaseModel]
            $Evidence = 'HomeBaseAndOfficialVariantBulletin'
        } elseif ($Model -in @('T35-DW','T35-R','T15-W') -and
                  $script:VariantEvidence.ContainsKey($Model)) {
            $BaseModel = ($Model -split '-')[0]
            if (-not $PublishedModels.ContainsKey($BaseModel)) {
                throw 'ModelAbsentFromLiveWatchGuardInventory'
            }
            $Release = [string]$PublishedModels[$BaseModel]
            $Evidence = 'OfficialVariantBulletin'
        } else {
            throw 'ModelAbsentOrUnverifiedInLiveWatchGuardInventory'
        }
    }
    if (-not $ReviewedReleaseBuilds.ContainsKey($Release)) {
        throw ('CurrentLiveReleaseBuildRequiresReview:{0}' -f $Release)
    }
    $Reviewed = $ReviewedReleaseBuilds[$Release]
    $FamilyKey = $null
    $CatalogResult = $null
    if ($script:FamilyByBaseModel.ContainsKey($BaseModel)) {
        $FamilyKey = $script:FamilyByBaseModel[$BaseModel]
        $CatalogResult = $script:CatalogCache[$FamilyKey]
        if ($null -eq $CatalogResult -or -not $CatalogResult.valid) {
            throw ('ModelCatalogPageVerificationFailed:{0}' -f $FamilyKey)
        }
        if ($CatalogResult.latest -cne $Release) {
            throw ('OfficialHomeAndModelCatalogDisagree:{0}:{1}' -f $Release,$CatalogResult.latest)
        }
    }
    return [pscustomobject]@{
        release=$Release; build=[long]$Reviewed.Build
        version=('{0}.B{1}' -f $Release,[long]$Reviewed.Build)
        notes=[string]$Reviewed.Notes; family=$FamilyKey
        catalog=$(if ($null -ne $CatalogResult) {$CatalogResult.catalog} else {$InventoryHomepageUrl})
        sha1=$(if ($null -ne $CatalogResult) {$CatalogResult.sha1} else {$null})
        proof=$Evidence
        package_verified=[bool]($null -ne $CatalogResult)
    }
}

function Parse-FirmwareVersion {
    param([Parameter(Mandatory)][string]$Value)
    $Match = [regex]::Match($Value.Trim(),
        '(?i)^v?(?<release>(?:20\d{2}|\d{1,2})\.\d+(?:\.\d+)?)(?:\.B(?<build>\d+))?$')
    if (-not $Match.Success) { throw 'Installed firmware version has an unrecognized format.' }
    $Parts = @($Match.Groups['release'].Value.Split('.') | ForEach-Object { [int]$_ })
    while ($Parts.Count -lt 3) { $Parts += 0 }
    $Build = $null
    if ($Match.Groups['build'].Success) { $Build = [long]$Match.Groups['build'].Value }
    return [pscustomobject]@{
        Release=[version]::new($Parts[0],$Parts[1],$Parts[2]); Build=$Build
    }
}

function Get-OnePasswordField {
    param([Parameter(Mandatory)][object]$Item,
          [Parameter(Mandatory)][string]$Label)
    $Field = @($Item.fields | Where-Object { $_.label -eq $Label }) | Select-Object -First 1
    if ($null -eq $Field -or [string]::IsNullOrWhiteSpace([string]$Field.value)) {
        throw ('Required 1Password field absent: {0}' -f $Label)
    }
    return ([string]$Field.value).Trim()
}

function Invoke-WatchGuardAuthPostWithRetry {
    param([Parameter(Mandatory)][string]$Uri,
          [Parameter(Mandatory)][hashtable]$Headers,
          [Parameter(Mandatory)][object]$Body,
          [switch]$Form)
    $Delays = @(2,5,10)
    for ($Attempt=1; $Attempt -le 4; $Attempt++) {
        try {
            if ($Form) {
                return Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers `
                    -ContentType 'application/x-www-form-urlencoded' -Body $Body -TimeoutSec 60
            }
            return Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec 60
        } catch {
            $Status = Get-HttpStatusCode -Exception $_.Exception
            $Transient400 = ($Status -eq 400 -and
                $_.Exception.Message -match '(?i)temporar|timed?\s*out|try\s+again|server\s+busy')
            $Retryable = ($null -eq $Status -or
                $Status -in @(408,429,500,502,503,504) -or $Transient400)
            $Allowed = $(if ($Status -eq 400) { 2 } else { 4 })
            # Outer audience-auth logic handles 401/403 with token refresh.
            if (-not $Retryable -or $Attempt -ge $Allowed) { throw }
            $Delay = $Delays[$Attempt-1]
            Write-Log ('WARN | AUTH_POST_RETRY Attempt={0}/{1} HTTP={2} DelaySeconds={3}' -f `
                $Attempt,$Allowed,$Status,$Delay)
            Start-Sleep -Seconds $Delay
        }
    }
}

function Get-WatchGuardAccessToken {
    param([Parameter(Mandatory)][string]$AuthenticationUrl,
          [Parameter(Mandatory)][string]$AccessId,
          [Parameter(Mandatory)][string]$Password,
          [string]$Audience)
    $Bytes = [System.Text.Encoding]::ASCII.GetBytes(('{0}:{1}' -f $AccessId,$Password))
    $Headers = @{
        Accept='application/json'
        Authorization=('Basic {0}' -f [Convert]::ToBase64String($Bytes))
    }
    $Body = @{grant_type='client_credentials';scope='api-access'}
    if (-not [string]::IsNullOrWhiteSpace($Audience)) { $Body['audience']=$Audience }
    $Response = Invoke-WatchGuardAuthPostWithRetry -Uri $AuthenticationUrl `
        -Headers $Headers -Body $Body -Form
    if ([string]::IsNullOrWhiteSpace([string]$Response.access_token)) {
        throw 'WatchGuard authentication returned no token.'
    }
    return [string]$Response.access_token
}

function Get-AccountHeaders {
    param([Parameter(Mandatory)][string]$AccountId)
    if (((Get-Date)-$script:ProviderTokenAcquiredAt).TotalMinutes -ge 50) {
        $script:ProviderToken = Get-WatchGuardAccessToken -AuthenticationUrl $script:AuthenticationUrl `
            -AccessId $script:ReadOnlyAccessId -Password $script:ReadOnlyPassword
        $script:ProviderTokenAcquiredAt = Get-Date
        Write-Log 'PASS | ProviderTokenRefreshed'
    }
    $Headers = @{
        Accept='application/json'; 'Content-Type'='application/json'
        Authorization="Bearer $($script:ProviderToken)"
        'WatchGuard-API-Key'=$script:ApiKey
    }
    if ($AccountId -ceq $script:RootAccountId) { return $Headers }
    $AudienceBody = @{ accountId=$AccountId } | ConvertTo-Json -Compress
    try {
        $AudienceResponse = Invoke-WatchGuardAuthPostWithRetry `
            -Uri "$($script:BaseApiUrl)/platform/authorization/v1/audiences" `
            -Headers $Headers -Body $AudienceBody
    } catch {
        $Status = Get-HttpStatusCode -Exception $_.Exception
        if ($Status -notin @(401,403)) { throw }
        Write-Log ('WARN | AccountAudienceAuthRetry Account={0} HTTP={1}' -f $AccountId,$Status)
        $script:ProviderToken = Get-WatchGuardAccessToken -AuthenticationUrl $script:AuthenticationUrl `
            -AccessId $script:ReadOnlyAccessId -Password $script:ReadOnlyPassword
        $script:ProviderTokenAcquiredAt = Get-Date
        $Headers.Authorization = "Bearer $($script:ProviderToken)"
        $AudienceResponse = Invoke-WatchGuardAuthPostWithRetry `
            -Uri "$($script:BaseApiUrl)/platform/authorization/v1/audiences" `
            -Headers $Headers -Body $AudienceBody
    }
    $Audience = [string]$AudienceResponse.audience
    if ([string]::IsNullOrWhiteSpace($Audience)) { throw 'Empty account-specific audience.' }
    $AccountToken = Get-WatchGuardAccessToken -AuthenticationUrl $script:AuthenticationUrl `
        -AccessId $script:ReadOnlyAccessId -Password $script:ReadOnlyPassword -Audience $Audience
    $Headers.Authorization = "Bearer $AccountToken"
    return $Headers
}

# Flatten subscriber hierarchy, carrying hosted-ancestor exclusions forward.
# The Accounts v2 API is asked to exclude delegated accounts, then we retain
# any remaining delegated indicators as separate skip candidates.
function Get-FlattenedManagedAccounts {
    param(
        [AllowNull()][object[]]$Items,
        [bool]$InheritedProtected = $false,
        [bool]$InheritedDelegated = $false
    )
    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($Item in @($Items)) {
        if ($null -eq $Item) { continue }
        $Id = ([string]$Item.accountId).Trim()
        $Name = ([string]$Item.name).Trim()
        if ([string]::IsNullOrWhiteSpace($Id)) {
            throw 'AccountHierarchyContainsEntryWithoutId'
        }
        $Protected = $InheritedProtected -or (Test-ProtectedName -Name $Name) -or
                     ($ProtectedAccountIds -ccontains $Id)
        $Delegated = $InheritedDelegated -or
                     ([string]$Item.relationType -match '(?i)delegat') -or
                     ([string]$Item.relationName -match '(?i)delegat')
        if (-not [string]::IsNullOrWhiteSpace($Id)) {
            $Rows.Add([pscustomobject]@{
                AccountId=$Id
                Name=$Name
                Type=[string]$Item.type
                ParentAccess=[string]$Item.parentAccess
                RelationName=[string]$Item.relationName
                RelationType=[string]$Item.relationType
                Protected=[bool]$Protected
                Delegated=[bool]$Delegated
            })
        }
        if ($Item.PSObject.Properties.Name -contains 'childrenList' -and
            $null -ne $Item.childrenList) {
            $Children = @(Get-FlattenedManagedAccounts -Items @($Item.childrenList) `
                -InheritedProtected $Protected -InheritedDelegated $Delegated)
            foreach ($Child in $Children) { if ($null -ne $Child) { $Rows.Add($Child) } }
        }
    }
    return $Rows.ToArray()
}

function Test-ProtectedName {
    param([AllowNull()][string]$Name)
    return (-not [string]::IsNullOrWhiteSpace($Name) -and
            $Name -match $ProtectedNamePattern)
}

function Test-DelegatedAccount {
    param([Parameter(Mandatory)][object]$Account)
    # The API exclusion flag is primary; this is a secondary explicit check.
    return ([bool]$Account.Delegated -or
            ([string]$Account.RelationType -match '(?i)delegat') -or
            ([string]$Account.RelationName -match '(?i)delegat'))
}

function Register-Problem {
    param([Parameter(Mandatory)][string]$AccountId,
          [string]$DeviceId,
          [Parameter(Mandatory)][string]$Stage,
          [Parameter(Mandatory)][string]$Reason,
          [AllowNull()][object]$HttpStatus)
    $script:DiagnosticErrors.Add([pscustomobject]@{
        account_id=$AccountId
        device_id=$DeviceId
        stage=$Stage
        http_status=$HttpStatus
        reason=$Reason
    })
}

function Ensure-ProviderToken {
    if ($null -eq $script:ProviderTokenAcquiredAt -or
        ((Get-Date)-$script:ProviderTokenAcquiredAt).TotalMinutes -ge 50) {
        $script:ProviderToken = Get-WatchGuardAccessToken `
            -AuthenticationUrl $script:AuthenticationUrl `
            -AccessId $script:ReadOnlyAccessId -Password $script:ReadOnlyPassword
        $script:ProviderTokenAcquiredAt = Get-Date
        Write-Log 'PASS | ProviderTokenRefreshed'
    }
}

function Add-DeviceResult {
    param([Parameter(Mandatory)][object]$Row)
    $script:DeviceResults.Add($Row)
    switch ($Row.decision) {
        'ERROR' { $script:ErrorCount++ }
        'TRIGGER' { $script:TriggerCount++ }
        'NO_ACTION' {
            if ($Row.reason -match 'Excluded$') { $script:ExcludedCount++ }
            else { $script:CurrentCount++ }
        }
    }
    # Full details live in JSON. Log errors/outdated devices for fast triage.
    if ($Row.decision -in @('ERROR','TRIGGER') -or [bool]$Row.review_required) {
        Write-Log ('DEVICE | Account={0} Id={1} Model={2} Installed={3} Target={4} State={5} Decision={6} Reason={7}' -f `
            (SafeText $Row.account_id),(SafeText $Row.device_id),(SafeText $Row.model), `
            (SafeText $Row.installed_firmware),(SafeText $Row.approved_ga_firmware), `
            (SafeText $Row.connectivity),(SafeText $Row.decision),(SafeText $Row.reason))
    }
}

try {
    $CurrentStage = 'Directories'
    foreach ($Directory in @('C:\Automation\Logs','C:\Automation\Staging')) {
        if (-not (Test-Path -LiteralPath $Directory)) {
            New-Item -ItemType Directory -Path $Directory -Force | Out-Null
        }
    }
    Set-Content -LiteralPath $LogPath -Value ('Firmware GLOBAL Evaluation {0}' -f (Get-Date -Format s)) -Encoding UTF8
    Write-Log 'START | GlobalHierarchy ReadOnly=True Broker=ConfiguredCredentialBroker'

    # Publication safety check: never silently omit account-ID protections.
    # This is a GitHub template, not a replacement for the verified production copy.
    $CurrentStage = 'PublicationConfiguration'
    foreach ($ConfiguredValue in @($OnePasswordVault,$WatchGuardItemName,$BootstrapTokenField)) {
        if ([string]::IsNullOrWhiteSpace([string]$ConfiguredValue) -or
            [string]$ConfiguredValue -like 'SET_*') {
            throw 'GitHubTemplateUnconfigured: Configure 1Password vault/item and NinjaOne secure field.'
        }
    }
    if (@($ProtectedAccountIds).Count -eq 0 -or
        @($ProtectedAccountIds | Where-Object {
            [string]::IsNullOrWhiteSpace([string]$_) -or
            [string]$_ -notmatch '^(WGC|ACC)-'
        }).Count -gt 0) {
        throw 'GitHubTemplateUnconfigured: Populate verified protected account IDs before evaluation.'
    }
    if (Test-Path -LiteralPath $ReportPath) { Remove-Item -LiteralPath $ReportPath -Force }

    $CurrentStage = 'OfficialLiveCatalogInventory'
    Initialize-LivePublishedInventory
    $CurrentStage = 'OfficialFamilyCatalogPreflight'
    Initialize-LiveFamilyCatalogs

    $CurrentStage = 'NinjaField'
    $ServiceAccountToken = [string](Ninja-Property-Get -Name $BootstrapTokenField)
    if ([string]::IsNullOrWhiteSpace($ServiceAccountToken)) { throw 'Ninja bootstrap token field is empty.' }
    $CurrentStage = 'OnePasswordCLI'
    $OpCommand = Get-Command 'op.exe' -ErrorAction SilentlyContinue
    if ($null -ne $OpCommand) { $OpExe = $OpCommand.Source }
    else {
        $OpExe = @('C:\Program Files\1Password CLI\op.exe',
                   'C:\Program Files\1Password\op.exe','C:\Windows\System32\op.exe') |
            Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if ([string]::IsNullOrWhiteSpace([string]$OpExe)) { throw '1Password CLI not found on broker.' }

    $CurrentStage = 'OnePasswordAuth'
    $env:OP_SERVICE_ACCOUNT_TOKEN = $ServiceAccountToken
    $WhoAmI = & $OpExe user get --me --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw '1Password service account authentication failed.' }
    $CurrentStage = 'WatchGuardItem'
    $ItemJson = & $OpExe item get $WatchGuardItemName --vault $OnePasswordVault --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw '1Password WatchGuard item retrieval failed.' }
    $WatchGuardItem = $ItemJson | ConvertFrom-Json
    $CurrentStage = 'WatchGuardConfig'
    $ApiKey = Get-OnePasswordField -Item $WatchGuardItem -Label 'credential'
    $ReadOnlyAccessId = Get-OnePasswordField -Item $WatchGuardItem -Label 'readOnlyAccessId'
    $ReadOnlyPassword = Get-OnePasswordField -Item $WatchGuardItem -Label 'readOnlyPassword'
    $RootAccountId = Get-OnePasswordField -Item $WatchGuardItem -Label 'accountID'
    $AuthenticationUrl = (Get-OnePasswordField -Item $WatchGuardItem -Label 'authenticationUrl').TrimEnd('/')
    $BaseApiUrl = (Get-OnePasswordField -Item $WatchGuardItem -Label 'baseApiUrl').TrimEnd('/')
    if ($RootAccountId -notmatch '^(WGC|ACC)-' -or
        $AuthenticationUrl -notmatch '^https://' -or $BaseApiUrl -notmatch '^https://') {
        throw 'Unexpected WatchGuard account or API URL format.'
    }
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    $ServiceAccountToken = $null
    $WatchGuardItem = $null

    $CurrentStage = 'ProviderAuth'
    Ensure-ProviderToken
    $ProviderHeaders = @{
        Accept='application/json';'Content-Type'='application/json'
        Authorization="Bearer $ProviderToken";'WatchGuard-API-Key'=$ApiKey
    }

    $CurrentStage = 'GlobalAccountDiscovery'
    $AccountsUri = "$BaseApiUrl/platform/accounts/v2/accounts/$RootAccountId/children?limit=-1&includeDelegatedAccounts=false"
    try {
        $ResponseAccounts = Invoke-WatchGuardGetWithRetry -Uri $AccountsUri -Headers $ProviderHeaders
    } catch {
        $Status = Get-HttpStatusCode -Exception $_.Exception
        if ($Status -notin @(401,403)) { throw }
        $ProviderTokenAcquiredAt = $null
        Ensure-ProviderToken
        $ProviderHeaders.Authorization = "Bearer $ProviderToken"
        $ResponseAccounts = Invoke-WatchGuardGetWithRetry -Uri $AccountsUri -Headers $ProviderHeaders
    }
    if ($null -eq $ResponseAccounts -or
        -not ($ResponseAccounts.PSObject.Properties.Name -contains 'items') -or
        $null -eq $ResponseAccounts.items) {
        throw 'Account hierarchy lacks an items collection.'
    }
    $RootRecord = [pscustomobject]@{
        AccountId=$RootAccountId;Name='ROOT';Type='ROOT';ParentAccess='True'
        RelationName='';RelationType='Root'
        Protected=($ProtectedAccountIds -ccontains $RootAccountId)
        Delegated=$false
    }
    $RawAccounts = @($RootRecord) + @(Get-FlattenedManagedAccounts -Items @($ResponseAccounts.items))
    if ($RawAccounts.Count -lt 2) { throw 'Unexpectedly empty managed-account hierarchy.' }
    # Deduplicate account IDs without discarding protected status. Distinct
    # duplicate names are diagnostic as they can obscure hosted designation.
    $AccountDedup = @{}
    foreach ($Account in $RawAccounts) {
        if ([string]::IsNullOrWhiteSpace([string]$Account.AccountId)) { continue }
        $Id = [string]$Account.AccountId
        if (-not $AccountDedup.ContainsKey($Id)) {
            $AccountDedup[$Id] = $Account
        } else {
            if ($Account.Protected) { $AccountDedup[$Id].Protected = $true }
            if ($Account.Delegated) { $AccountDedup[$Id].Delegated = $true }
            if ($Account.Name -cne $AccountDedup[$Id].Name) {
                Write-Log ('WARN | DuplicateAccountDifferentName Account={0}' -f $Id)
            }
        }
    }
    $AccountRecords = @($AccountDedup.Values | Sort-Object Name, AccountId)
    $AccountsDiscovered = $AccountRecords.Count
    Write-Log ('PASS | GlobalAccountDiscovery Accounts={0} Root={1}' -f $AccountsDiscovered,$RootAccountId)

    foreach ($Account in $AccountRecords) {
        $AccountId = [string]$Account.AccountId
        $AccountName = [string]$Account.Name
        $CurrentStage = "Account:$AccountId"
        if ([bool]$Account.Protected -or (Test-ProtectedName -Name $AccountName) -or
            ($ProtectedAccountIds -ccontains $AccountId)) {
            $AccountsSkipped++
            $AccountResults.Add([pscustomobject]@{
                account_id=$AccountId;account_name=$AccountName
                status='EXCLUDED';reason='ProtectedHostedAccountOrAncestry';firebox_objects=$null
            })
            Write-Log ('SKIP | ProtectedAccount Account={0} Name={1}' -f $AccountId,(SafeText $AccountName))
            continue
        }
        if (Test-DelegatedAccount -Account $Account) {
            $AccountsSkipped++
            $AccountResults.Add([pscustomobject]@{
                account_id=$AccountId;account_name=$AccountName
                status='EXCLUDED';reason='DelegatedAccountExcluded';firebox_objects=$null
            })
            continue
        }
        $AccountsAttempted++
        try {
            $CurrentStage = "AccountAuth:$AccountId"
            $Headers = Get-AccountHeaders -AccountId $AccountId
            $CurrentStage = "DeviceDiscovery:$AccountId"
            $Uri = "$BaseApiUrl/firebox/management/v1/info/$AccountId/devices?device_type=FB"
            try {
                $Response = Invoke-WatchGuardGetWithRetry -Uri $Uri -Headers $Headers
            } catch {
                $GetStatus = Get-HttpStatusCode -Exception $_.Exception
                if ($GetStatus -notin @(401,403)) { throw }
                # Recreate account audience/token once for an expired/unstable
                # bearer; only safe GETs are retried after reauthentication.
                Write-Log ('WARN | DeviceGetReauthentication Account={0} HTTP={1}' -f $AccountId,$GetStatus)
                $script:ProviderTokenAcquiredAt = $null
                Ensure-ProviderToken
                $Headers = Get-AccountHeaders -AccountId $AccountId
                $Response = Invoke-WatchGuardGetWithRetry -Uri $Uri -Headers $Headers
            }
            if ($null -eq $Response -or
                -not ($Response.PSObject.Properties.Name -contains 'count') -or
                -not ($Response.PSObject.Properties.Name -contains 'data')) {
                throw 'Device discovery response missing count or data.'
            }
            $Devices = @($Response.data | Where-Object { $null -ne $_ })
            if ([int]$Response.count -ne $Devices.Count -or [int]$Response.count -lt 0) {
                throw 'Device discovery returned an inconsistent inventory count.'
            }
            # Zero Fireboxes is a valid account result in a global inventory.
            $AccountsCompleted++
            $AccountResults.Add([pscustomobject]@{
                account_id=$AccountId;account_name=$AccountName
                status='DISCOVERED';reason=$null;firebox_objects=$Devices.Count
            })
            $DiscoveredCount += $Devices.Count
            Write-Log ('PASS | Discovery Account={0} Devices={1}' -f $AccountId,$Devices.Count)

            foreach ($Device in $Devices) {
                $DeviceId = ([string]$Device.id).Trim()
                $Model = ([string]$Device.short_model_name).Trim().ToUpperInvariant()
                $InstalledVersion = ([string]$Device.version).Trim()
                $State = ([string]$Device.state).Trim().ToLowerInvariant()
                $Management = ([string]$Device.cloud_managed).Trim().ToLowerInvariant()
                $Row = [ordered]@{
                    account_id=$AccountId
                    account_name=$AccountName
                    device_id=$DeviceId
                    device_name=[string]$Device.name
                    serial_number=[string]$Device.serial_number
                    model=$Model
                    installed_firmware=$InstalledVersion
                    connectivity=$State
                    cloud_managed=$Management
                    family=$null
                    latest_public_ga_release=$null
                    approved_ga_firmware=$null
                    catalog_url=$null
                    release_notes_url=$null
                    published_os_installer_sha1=$null
                    catalog_verified=$false
                    catalog_match_basis=$null
                    package_catalog_verified=$false
                    cluster_membership_verified=$false
                    offline_scheduling_candidate=$false
                    review_required=$false
                    review_category=$null
                    end_of_life_date=$null
                    exclusion_source_url=$null
                    decision='ERROR'
                    reason='NotEvaluated'
                }
                try {
                    $CurrentStage = "Inspect:$AccountId/$DeviceId"
                    if ($DeviceId -match '^FBCL-') {
                        $Row.decision='NO_ACTION';$Row.reason='FireClusterExcluded'
                    } elseif ($DeviceId -notmatch '^FB-\d+$') {
                        throw 'UnexpectedDeviceIdentifier'
                    } elseif ($SeenDevices.ContainsKey($DeviceId)) {
                        throw 'DuplicateDeviceAcrossAccounts'
                    } else {
                        $SeenDevices[$DeviceId] = $true
                        if ([string]::IsNullOrWhiteSpace($Model) -or
                            [string]::IsNullOrWhiteSpace([string]$Device.serial_number)) {
                            throw 'MissingModelOrSerial'
                        }
                        if ($Management -notin @('yes','no')) { throw 'UnknownManagementMode' }
                        if ($State -notin @('online','offline','never connected','inactive')) {
                            throw 'UnknownConnectionState'
                        }
                        if ($Model -match $VirtualModelPattern -or
                            (Test-ProtectedName -Name ([string]$Device.name))) {
                            $Row.decision='NO_ACTION';$Row.reason='ProtectedHostedDeviceExcluded'
                        } elseif ($Management -eq 'no') {
                            $Row.decision='NO_ACTION';$Row.reason='LocallyManagedExcluded'
                        } elseif ($State -eq 'never connected') {
                            # A registration that has never connected is NOT an
                            # actionable firmware candidate. Retain its details
                            # and flag manual review, but do not fail the audit.
                            $Row.decision='NO_ACTION';$Row.reason='NeverConnectedExcluded'
                            $Row.review_required=$true
                            $Row.review_category='NeverConnectedRegistration'
                        } elseif ($State -eq 'inactive') {
                            # Unlike 'never connected', this may represent a
                            # formerly managed device with stale status.
                            throw 'InactiveDeviceRequiresReview'
                        } elseif ($ReviewedRetiredModels.ContainsKey($Model)) {
                            # Exact, independently reviewed EOL model only.
                            # NEVER infer EOL status for unknown variants.
                            $Retired = $ReviewedRetiredModels[$Model]
                            $EolDate = [datetime]::ParseExact([string]$Retired.EndOfLife,
                                'yyyy-MM-dd',[System.Globalization.CultureInfo]::InvariantCulture)
                            if ((Get-Date).Date -le $EolDate.Date) {
                                throw 'ReviewedEndOfLifeDateHasNotPassed'
                            }
                            $Row.decision='NO_ACTION';$Row.reason='VerifiedEndOfLifeExcluded'
                            $Row.review_required=$true
                            $Row.review_category='HardwareReplacementRequired'
                            $Row.end_of_life_date=[string]$Retired.EndOfLife
                            $Row.exclusion_source_url=[string]$Retired.Source
                        } else {
                            $CurrentStage = "ResolveLiveCatalog:$AccountId/$DeviceId"
                            try {
                                $Resolved = Resolve-LiveModelTarget -Model $Model
                            } catch {
                                if (-not $UnknownModels.ContainsKey($Model)) { $UnknownModels[$Model] = 0 }
                                $UnknownModels[$Model]++
                                throw
                            }
                            $Row.family = $(if ($Resolved.family) { [string]$Resolved.family } else { 'LiveHomepage' })
                            $Row.catalog_url = [string]$Resolved.catalog
                            $Row.catalog_verified = $true
                            $Row.latest_public_ga_release = [string]$Resolved.release
                            $Row.approved_ga_firmware = [string]$Resolved.version
                            $Row.release_notes_url = [string]$Resolved.notes
                            $Row.published_os_installer_sha1 = [string]$Resolved.sha1
                            $Row.catalog_match_basis = [string]$Resolved.proof
                            $Row.package_catalog_verified = [bool]$Resolved.package_verified
                            $CurrentStage = "Compare:$AccountId/$DeviceId"
                            $Installed = Parse-FirmwareVersion -Value $InstalledVersion
                            $Approved = Parse-FirmwareVersion -Value $Resolved.version
                            if ($Installed.Release -gt $Approved.Release) {
                                throw 'InstalledFirmwareNewerThanApprovedRelease'
                            } elseif ($Installed.Release -lt $Approved.Release) {
                                $Row.decision='TRIGGER';$Row.reason='OlderRelease'
                            } elseif ($null -eq $Installed.Build) {
                                throw 'InstalledBuildNotProvidedForEqualRelease'
                            } elseif ($Installed.Build -gt $Approved.Build) {
                                throw 'InstalledBuildNewerThanApprovedBuild'
                            } elseif ($Installed.Build -lt $Approved.Build) {
                                $Row.decision='TRIGGER';$Row.reason='OlderBuild'
                            } else {
                                $Row.decision='NO_ACTION';$Row.reason='ExactApprovedBuildInstalled'
                            }
                            $Row.offline_scheduling_candidate = [bool]($State -eq 'offline' -and $Row.decision -eq 'TRIGGER')
                        }
                    }
                } catch {
                    $Row.decision='ERROR'
                    $Row.reason=(SafeText $_.Exception.Message)
                    Register-Problem -AccountId $AccountId -DeviceId $DeviceId `
                        -Stage (SafeText $CurrentStage) -Reason $Row.reason -HttpStatus $null
                }
                Add-DeviceResult -Row ([pscustomobject]$Row)
            }
        } catch {
            $AccountsFailed++
            $ErrorCount++
            $Status = Get-HttpStatusCode -Exception $_.Exception
            $Reason = 'AccountDiscoveryOrAuthFailed'
            $AccountResults.Add([pscustomobject]@{
                account_id=$AccountId;account_name=$AccountName
                status='ERROR';reason=$Reason;firebox_objects=$null
            })
            Register-Problem -AccountId $AccountId -Stage $CurrentStage `
                -Reason $Reason -HttpStatus $Status
            Write-Log ('ACCOUNT_ERROR | Account={0} Stage={1} HTTP={2} ExceptionType={3}' -f `
                $AccountId,(SafeText $CurrentStage),$Status,$_.Exception.GetType().Name)
        } finally {
            $Headers = $null
        }
        if ($AccountsAttempted % 25 -eq 0) {
            Write-Log ('PROGRESS | Visited={0}/{1} Completed={2} Failed={3} Devices={4} Outdated={5} Errors={6}' -f `
                ($AccountsAttempted+$AccountsSkipped),$AccountsDiscovered,$AccountsCompleted, `
                $AccountsFailed,$DiscoveredCount,$TriggerCount,$ErrorCount)
        }
    }

    $CurrentStage='WriteReport'
    if (($AccountsCompleted + $AccountsFailed + $AccountsSkipped) -ne $AccountsDiscovered) {
        $ErrorCount++
        Register-Problem -AccountId $RootAccountId -Stage 'AccountCompletionCheck' `
            -Reason 'AccountCountMismatch' -HttpStatus $null
    }
    $UnknownModelSummary = @($UnknownModels.Keys | Sort-Object | ForEach-Object {
        [pscustomobject]@{model=$_;count=[int]$UnknownModels[$_]}
    })
    # Keep unresolved failures separate from intentionally excluded hardware.
    # This queue is intentionally visible even on a clean TRIGGER result.
    $ReviewExcludedDevices = @($DeviceResults.ToArray() | Where-Object {
        [bool]$_.review_required
    } | Select-Object account_id,account_name,device_id,device_name,model, `
        installed_firmware,connectivity,reason,review_category, `
        end_of_life_date,exclusion_source_url)
    $NeverConnectedExcludedCount = @($DeviceResults.ToArray() | Where-Object {
        $_.reason -eq 'NeverConnectedExcluded'
    }).Count
    $EndOfLifeExcludedCount = @($DeviceResults.ToArray() | Where-Object {
        $_.reason -eq 'VerifiedEndOfLifeExcluded'
    }).Count
    $DeviceErrorCount = @($DeviceResults.ToArray() | Where-Object {
        $_.decision -eq 'ERROR'
    }).Count
    if ($DeviceResults.Count -ne $DiscoveredCount -or
        ($TriggerCount + $CurrentCount + $ExcludedCount + $DeviceErrorCount) -ne $DiscoveredCount) {
        $ErrorCount++
        Register-Problem -AccountId $RootAccountId -Stage 'DeviceCompletionCheck' `
            -Reason 'DeviceClassificationCountMismatch' -HttpStatus $null
    }
    $ElapsedSeconds = [math]::Round(((Get-Date)-$GlobalStarted).TotalSeconds,1)
    $Report = [ordered]@{
        generated_at_utc=(Get-Date).ToUniversalTime().ToString('o')
        root_account_id=$RootAccountId
        scope='Global account hierarchy; delegated and protected hosted accounts excluded'
        accounts_discovered=$AccountsDiscovered
        accounts_attempted=$AccountsAttempted
        accounts_completed=$AccountsCompleted
        accounts_failed=$AccountsFailed
        accounts_excluded=$AccountsSkipped
        firebox_objects_discovered=$DiscoveredCount
        trigger_count=$TriggerCount
        current_count=$CurrentCount
        excluded_device_count=$ExcludedCount
        never_connected_excluded_count=$NeverConnectedExcludedCount
        end_of_life_excluded_count=$EndOfLifeExcludedCount
        review_excluded_count=$ReviewExcludedDevices.Count
        review_exclusions=$ReviewExcludedDevices
        errors=$ErrorCount
        elapsed_seconds=$ElapsedSeconds
        unknown_model_summary=$UnknownModelSummary
        published_live_models=@($PublishedModels.Keys | Sort-Object)
        published_live_model_count=$PublishedModels.Count
        published_live_versions=@($PublishedInventoryVersions)
        published_live_inventory_source=$PublishedInventorySource
        published_live_homepage_used=($PublishedInventorySource -in @(
            'https://software.watchguard.com/',
            'https://software.watchguard.com/SoftwareHome'
        ))
        catalog_preflight_issues=@($CatalogBootstrapErrors.ToArray())
        model_family_index_derived_from_page_headings=@($FamilyByBaseModel.Keys | Sort-Object)
        published_catalog_families=@($FirmwareFamilies.Keys | Sort-Object)
        reviewed_release_note_versions=@($ReviewedReleaseBuilds.Keys | Sort-Object)
        release_note_builds_reviewed_on='2026-11-03'
        current_release_resolved_from_live_catalog=$true
        catalog_bootstrapped_before_account_discovery=$true
        static_fleet_model_whitelist_used=$false
        release_notes_checked_manually=$true
        release_notes_downloaded_by_script=$false
        evaluation_only=$true
        firmware_change_performed=$false
        upgrade_authorized=$false
        firmware_upgrade_scheduling_api_verified=$false
        hosted_environments_auto_identification_complete=$false
        cluster_membership_independently_verified=$false
        accounts=@($AccountResults.ToArray())
        devices=@($DeviceResults.ToArray())
        diagnostic_errors=@($DiagnosticErrors.ToArray())
        note='TRIGGER means outdated only, NOT upgrade authorization. Firmware inventory is built from the official live homepage, or an explicit official-bulletin fallback. Package checks use model family pages. Exact builds use reviewed release-note references. Never-connected registrations and vendor-reviewed retired T35-W hardware are explicitly excluded and remain in review_exclusions; other unknown models and verification failures remain ERROR. Hosted classification, active support entitlement, and FB cluster membership still require independent verification before remediation.'
    }
    $Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

    if ($ErrorCount -gt 0) {
        $FinalOutput=('ERROR | GlobalFirmwareAuditIncomplete Accounts={0}/{1} Failed={2} AccountSkipped={3} Devices={4} Outdated={5} Current={6} DeviceExcluded={7} ReviewExcluded={8} UnknownModels={9} Errors={10} Seconds={11} File={12}' -f `
            $AccountsCompleted,$AccountsDiscovered,$AccountsFailed,$AccountsSkipped, `
            $DiscoveredCount,$TriggerCount,$CurrentCount,$ExcludedCount,$ReviewExcludedDevices.Count, `
            $UnknownModels.Keys.Count,$ErrorCount,$ElapsedSeconds,$ReportPath)
    } elseif ($TriggerCount -gt 0) {
        $FinalOutput=('TRIGGER | GlobalOlderFirmwareDetected Accounts={0}/{1} AccountSkipped={2} Devices={3} Outdated={4} Current={5} DeviceExcluded={6} ReviewExcluded={7} Errors=0 Seconds={8} File={9}' -f `
            $AccountsCompleted,$AccountsDiscovered,$AccountsSkipped,$DiscoveredCount, `
            $TriggerCount,$CurrentCount,$ExcludedCount,$ReviewExcludedDevices.Count,$ElapsedSeconds,$ReportPath)
    } else {
        $FinalOutput=('NO_ACTION | GlobalFirmwareCurrentOrExcluded Accounts={0}/{1} AccountSkipped={2} Devices={3} Current={4} DeviceExcluded={5} ReviewExcluded={6} Errors=0 Seconds={7} File={8}' -f `
            $AccountsCompleted,$AccountsDiscovered,$AccountsSkipped,$DiscoveredCount, `
            $CurrentCount,$ExcludedCount,$ReviewExcludedDevices.Count,$ElapsedSeconds,$ReportPath)
    }
    Write-Log $FinalOutput
} catch {
    $Status = Get-HttpStatusCode -Exception $_.Exception
    if ($null -eq $Status) { $Status='N/A' }
    $FailureReason = SafeText $_.Exception.Message
    $FailureLine = $_.InvocationInfo.ScriptLineNumber
    $FinalOutput=('ERROR | Stage={0} HTTP={1} Reason={2} ExceptionType={3} Line={4} Log={5}' -f `
        (SafeText $CurrentStage),$Status,$FailureReason,$_.Exception.GetType().Name,$FailureLine,$LogPath)
    Write-Log $FinalOutput
    Write-Log ('ERROR_DETAIL | Stage={0} Line={1} Reason={2}' -f `
        (SafeText $CurrentStage),$FailureLine,$FailureReason)
} finally {
    try { $env:OP_SERVICE_ACCOUNT_TOKEN = $null } catch { }
    $ServiceAccountToken=$null
    $WatchGuardItem=$null
    $ApiKey=$null
    $ReadOnlyAccessId=$null
    $ReadOnlyPassword=$null
    $AuthenticationUrl=$null
    $BaseApiUrl=$null
    $ProviderToken=$null
    $Headers=$null
}

if ([string]::IsNullOrWhiteSpace($FinalOutput)) {
    $FinalOutput='ERROR | Stage=Finalize Reason=NoFinalOutput'
}
Write-Output $FinalOutput
exit 0
