<#
NAME: Invoke-CVEKeywordCollector.ps1
TYPE: Tool
SCOPE: Windows

PURPOSE:
  Simple CVE and security-keyword collector for manual intel review.

  This script checks configured CVE, vendor, advisory, Reddit, and security-news
  URLs, builds a source-level digest of relevant material, and writes the results
  to a single CSV.

  This is intended as a lightweight personal threat-intel / CVE awareness tool.
  It is not an endpoint audit, vulnerability scanner, alerting system, or
  remediation workflow.

  This script does not:
    - Check endpoints
    - Determine client exposure
    - Remediate systems
    - Patch software
    - Send Teams messages when TeamsWebhookUrl is not configured
    - Send alerts
    - Create tickets
    - Maintain a separate posted-state file
    - Create Markdown output
    - Create one CSV row per CVE/feed item

  This script does:
    - Check configured URLs
    - Convert returned HTML/XML/JSON/RSS content into plain searchable text
    - Search for watched vendor/product terms and security urgency keywords
    - Apply LookbackHours to dated feed/API items where a date is available
    - Extract relevant candidate items internally where possible
    - Build one digest row per checked source URL
    - Cap displayed digest items per source and note additional relevant items
    - Write full relevant-item details in the same CSV using the FullDetails column
    - Extract CVE IDs from relevant candidate items only
    - Suppress full-page CVE dumps for page-scrape sources
    - Append one CSV row per source that has new, non-duplicate relevant items
    - Optionally send one Teams digest post per new source row when TeamsWebhookUrl is configured
    - Log source successes and failures

VARIABLES:
  Required:
    None

  Optional:
    LookbackHours - Number of hours used for dated sources such as NVD recent CVEs, CISA KEV dateAdded, and RSS/Atom item dates. Default: 30
    IntelRoot - Root folder for CSV output
    LogRoot - Root folder for log file
    OutputCsv - Full path to CSV output file
    NvdApiKey - Optional NVD API key
    MaxItemsPerSource - Maximum relevant items included in each source digest row
    MaxSnippetLength - Maximum characters per digest item snippet
    TeamsWebhookUrl - Optional Teams Workflow/incoming webhook URL. When configured, one Teams post is sent for each new source digest row.

SOURCES CHECKED:
  Authoritative / higher-confidence sources:
    - CISA KEV
      URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

    - CISA Advisories
      URL: https://www.cisa.gov/cybersecurity-advisories/all.xml

    - NVD Recent CVEs
      URL: https://services.nvd.nist.gov/rest/json/cves/2.0
      Note: Queried with pubStartDate/pubEndDate based on LookbackHours.

    - Microsoft MSRC
      URL: https://api.msrc.microsoft.com/update-guide/rss

    - Chrome Releases
      URL: https://chromereleases.googleblog.com/feeds/posts/default

    - WatchGuard Security Advisories
      URL: https://www.watchguard.com/wgrd-psirt/advisories

    - ConnectWise Security Bulletins
      URL: https://www.connectwise.com/company/trust/security-bulletins

  Early-signal / security-news / chatter sources:
    - Reddit r/netsec
      URL: https://www.reddit.com/r/netsec/.rss

    - Reddit r/cybersecurity
      URL: https://www.reddit.com/r/cybersecurity/.rss

    - BleepingComputer
      URL: https://www.bleepingcomputer.com/feed/

    - The Hacker News
      URL: https://feeds.feedburner.com/TheHackersNews

    - KrebsOnSecurity
      URL: https://krebsonsecurity.com/feed/

    - Tom's Hardware
      URL: https://www.tomshardware.com/feeds/all

WATCHED VENDORS / PRODUCTS / TERMS:
  Primary vendor/product focus:
    - Microsoft
    - Windows
    - Windows Server
    - Active Directory
    - Netlogon
    - Exchange
    - SharePoint
    - Office
    - Outlook
    - Word
    - Excel
    - PowerPoint
    - Microsoft Edge
    - Chrome
    - Chromium
    - Google Chrome
    - WatchGuard
    - Fireware
    - AuthPoint
    - ConnectWise
    - ScreenConnect
    - ConnectWise Control
    - ConnectWise Automate

  Additional high-interest security terms/products:
    - Fortinet
    - FortiOS
    - FortiGate
    - Cisco
    - Meraki
    - VPN
    - RMM
    - EDR
    - MFA / 2FA / multi-factor

SECURITY KEYWORDS:
  The script searches for urgency/security keyword patterns including:
    - zero-day / 0-day
    - actively exploited
    - active exploitation
    - exploited in the wild
    - known exploited
    - proof-of-concept / PoC
    - RCE / remote code execution
    - auth bypass / authentication bypass
    - privilege escalation / elevation of privilege
    - critical vulnerability / critical security flaw
    - emergency patch
    - out-of-band patch

IMPORTANT RELEVANCE LOGIC:
  CVE- is not treated as a relevance keyword by itself.

  Generic "Microsoft" is recorded as a matched keyword when present, but it is
  not enough by itself to make an MSRC item relevant. The item must match a
  concrete watched product/technology, or must contain a standalone urgent term.

  Standalone urgent terms:
    - known exploited
    - actively exploited
    - active exploitation
    - exploited in the wild
    - zero-day / 0-day
    - emergency patch
    - out-of-band patch

  Otherwise, relevance requires:
    - watched product/vendor/technology term
    AND
    - security context such as CVE, vulnerability, security update, exploit,
      RCE, auth bypass, privilege escalation, critical vulnerability, etc.

  Page-scrape sources such as WatchGuard and ConnectWise can contain many older
  CVEs on a single page. For those page sources, the script suppresses full-page
  CVE extraction and reports "See source page" instead of dumping every CVE.

  Digest is intentionally capped for future Teams posting. FullDetails is not
  capped and contains all new relevant items found for that source in the same CSV.

  De-duplication is handled using the same CSV file. At the start of each run,
  the script imports existing ItemKeys from the CSV into memory, suppresses
  candidate items already seen, then appends only new source-digest rows. No
  separate posted-state file is created.

OUTPUT:
  CSV:
    C:\MME\ThreatIntel\CVE_Keyword_Hits.csv

    One row per checked source.
    Includes:
      - RunTime
      - Source
      - SourceType
      - Url
      - Status
      - HttpStatus
      - FoundRelevantItems
      - RelevantItems
      - DuplicateItems
      - IncludedItems
      - AdditionalItems
      - HighestPriority
      - MatchedKeywords
      - CVEs
      - TitleOrPage
      - Digest
      - FullDetails
      - ItemKeys
      - TeamsPostStatus
      - Error

    Digest is Teams-safe and capped by MaxItemsPerSource.
    FullDetails contains all new relevant items for local CSV review.
    ItemKeys stores de-duplication keys used by future runs.

  Log:
    C:\MME\AutoLogs\CVE_Keyword_Collector.log

OUTPUT TOKENS:
  RESULT | Checked=<count>; NewRelevantSources=<count>; NewRelevantItems=<count>; DuplicateItems=<count>; Errors=<count>; TeamsPosts=<count>; TeamsErrors=<count>; Csv=<path>
  ERROR  | Unexpected script error occurred. <message>
#>

[CmdletBinding()]
param(
    [int]$LookbackHours = 30,
    [string]$IntelRoot = 'C:\MME\ThreatIntel',
    [string]$LogRoot = 'C:\MME\AutoLogs',
    [string]$OutputCsv = 'C:\MME\ThreatIntel\CVE_Keyword_Hits.csv',
    [string]$NvdApiKey = '',
    [int]$MaxItemsPerSource = 5,
    [int]$MaxSnippetLength = 450,
    [string]$TeamsWebhookUrl = 'https://default1683370679a14e0d845ddd12938914.63.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/153ab743ad3a4e31b8873d0c4c92ec38/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=OJ0N_9_q-3x-f6mzSako0eMOrrFikSRjR1eqFg6emvI'
)

$ErrorActionPreference = 'Stop'

$LogPath = Join-Path $LogRoot 'CVE_Keyword_Collector.log'

if ([string]::IsNullOrWhiteSpace($TeamsWebhookUrl)) {
    if (-not [string]::IsNullOrWhiteSpace($env:TeamsWebhookUrl)) {
        $TeamsWebhookUrl = [string]$env:TeamsWebhookUrl
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:teamswebhookurl)) {
        $TeamsWebhookUrl = [string]$env:teamswebhookurl
    }
}

# Display/matched keywords. These are reported in CSV.
$DisplayWatchedPatterns = @(
    [pscustomobject]@{ Name = 'Microsoft'; Pattern = '\bMicrosoft\b' },
    [pscustomobject]@{ Name = 'Windows'; Pattern = '\bWindows\b' },
    [pscustomobject]@{ Name = 'Windows Server'; Pattern = 'Windows Server' },
    [pscustomobject]@{ Name = 'Active Directory'; Pattern = 'Active Directory' },
    [pscustomobject]@{ Name = 'Netlogon'; Pattern = 'Netlogon' },
    [pscustomobject]@{ Name = 'Exchange'; Pattern = '\bExchange\b' },
    [pscustomobject]@{ Name = 'SharePoint'; Pattern = 'SharePoint' },
    [pscustomobject]@{ Name = 'Office'; Pattern = '\bOffice\b' },
    [pscustomobject]@{ Name = 'Outlook'; Pattern = '\bOutlook\b' },
    [pscustomobject]@{ Name = 'Word'; Pattern = '\bMicrosoft Word\b|\bMS Word\b|\bWord\b' },
    [pscustomobject]@{ Name = 'Excel'; Pattern = '\bExcel\b' },
    [pscustomobject]@{ Name = 'PowerPoint'; Pattern = '\bPowerPoint\b' },
    [pscustomobject]@{ Name = 'Microsoft Edge'; Pattern = 'Microsoft Edge|Edge \(Chromium-based\)' },
    [pscustomobject]@{ Name = 'Chrome'; Pattern = '\bChrome\b' },
    [pscustomobject]@{ Name = 'Chromium'; Pattern = '\bChromium\b' },
    [pscustomobject]@{ Name = 'Google Chrome'; Pattern = 'Google Chrome' },
    [pscustomobject]@{ Name = 'WatchGuard'; Pattern = 'WatchGuard' },
    [pscustomobject]@{ Name = 'Fireware'; Pattern = 'Fireware' },
    [pscustomobject]@{ Name = 'AuthPoint'; Pattern = 'AuthPoint' },
    [pscustomobject]@{ Name = 'ConnectWise'; Pattern = 'ConnectWise' },
    [pscustomobject]@{ Name = 'ScreenConnect'; Pattern = 'ScreenConnect' },
    [pscustomobject]@{ Name = 'ConnectWise Control'; Pattern = 'ConnectWise Control' },
    [pscustomobject]@{ Name = 'ConnectWise Automate'; Pattern = 'ConnectWise Automate' },
    [pscustomobject]@{ Name = 'Fortinet'; Pattern = 'Fortinet' },
    [pscustomobject]@{ Name = 'FortiOS'; Pattern = 'FortiOS' },
    [pscustomobject]@{ Name = 'FortiGate'; Pattern = 'FortiGate' },
    [pscustomobject]@{ Name = 'Cisco'; Pattern = '\bCisco\b' },
    [pscustomobject]@{ Name = 'Meraki'; Pattern = 'Meraki' },
    [pscustomobject]@{ Name = 'VPN'; Pattern = '\bVPN\b' },
    [pscustomobject]@{ Name = 'RMM'; Pattern = '\bRMM\b' },
    [pscustomobject]@{ Name = 'EDR'; Pattern = '\bEDR\b' },
    [pscustomobject]@{ Name = 'MFA'; Pattern = '\bMFA\b|2FA|multi-factor|multifactor' }
)

# Concrete relevance watched terms. Generic "Microsoft" is intentionally excluded.
$RelevanceWatchedPatterns = @(
    [pscustomobject]@{ Name = 'Windows'; Pattern = '\bWindows\b' },
    [pscustomobject]@{ Name = 'Windows Server'; Pattern = 'Windows Server' },
    [pscustomobject]@{ Name = 'Active Directory'; Pattern = 'Active Directory' },
    [pscustomobject]@{ Name = 'Netlogon'; Pattern = 'Netlogon' },
    [pscustomobject]@{ Name = 'Exchange'; Pattern = '\bExchange\b' },
    [pscustomobject]@{ Name = 'SharePoint'; Pattern = 'SharePoint' },
    [pscustomobject]@{ Name = 'Office'; Pattern = '\bOffice\b' },
    [pscustomobject]@{ Name = 'Outlook'; Pattern = '\bOutlook\b' },
    [pscustomobject]@{ Name = 'Word'; Pattern = '\bMicrosoft Word\b|\bMS Word\b|\bWord\b' },
    [pscustomobject]@{ Name = 'Excel'; Pattern = '\bExcel\b' },
    [pscustomobject]@{ Name = 'PowerPoint'; Pattern = '\bPowerPoint\b' },
    [pscustomobject]@{ Name = 'Microsoft Edge'; Pattern = 'Microsoft Edge|Edge \(Chromium-based\)' },
    [pscustomobject]@{ Name = 'Chrome'; Pattern = '\bChrome\b' },
    [pscustomobject]@{ Name = 'Chromium'; Pattern = '\bChromium\b' },
    [pscustomobject]@{ Name = 'Google Chrome'; Pattern = 'Google Chrome' },
    [pscustomobject]@{ Name = 'WatchGuard'; Pattern = 'WatchGuard' },
    [pscustomobject]@{ Name = 'Fireware'; Pattern = 'Fireware' },
    [pscustomobject]@{ Name = 'AuthPoint'; Pattern = 'AuthPoint' },
    [pscustomobject]@{ Name = 'ConnectWise'; Pattern = 'ConnectWise' },
    [pscustomobject]@{ Name = 'ScreenConnect'; Pattern = 'ScreenConnect' },
    [pscustomobject]@{ Name = 'ConnectWise Control'; Pattern = 'ConnectWise Control' },
    [pscustomobject]@{ Name = 'ConnectWise Automate'; Pattern = 'ConnectWise Automate' },
    [pscustomobject]@{ Name = 'Fortinet'; Pattern = 'Fortinet' },
    [pscustomobject]@{ Name = 'FortiOS'; Pattern = 'FortiOS' },
    [pscustomobject]@{ Name = 'FortiGate'; Pattern = 'FortiGate' },
    [pscustomobject]@{ Name = 'Cisco'; Pattern = '\bCisco\b' },
    [pscustomobject]@{ Name = 'Meraki'; Pattern = 'Meraki' },
    [pscustomobject]@{ Name = 'VPN'; Pattern = '\bVPN\b' },
    [pscustomobject]@{ Name = 'RMM'; Pattern = '\bRMM\b' },
    [pscustomobject]@{ Name = 'EDR'; Pattern = '\bEDR\b' },
    [pscustomobject]@{ Name = 'MFA'; Pattern = '\bMFA\b|2FA|multi-factor|multifactor' }
)

$SecurityPatterns = @(
    [pscustomobject]@{ Name = 'zero-day'; Pattern = 'zero[- ]day|0-day' },
    [pscustomobject]@{ Name = 'actively exploited'; Pattern = 'actively exploited|active exploitation|exploited in the wild|known exploited' },
    [pscustomobject]@{ Name = 'PoC'; Pattern = 'proof[- ]of[- ]concept|PoC' },
    [pscustomobject]@{ Name = 'RCE'; Pattern = '\bRCE\b|remote code execution' },
    [pscustomobject]@{ Name = 'auth bypass'; Pattern = 'auth bypass|authentication bypass' },
    [pscustomobject]@{ Name = 'privilege escalation'; Pattern = 'privilege escalation|elevation of privilege' },
    [pscustomobject]@{ Name = 'critical vulnerability'; Pattern = 'critical vulnerability|critical security flaw' },
    [pscustomobject]@{ Name = 'emergency patch'; Pattern = 'emergency patch|out-of-band patch' }
)

$StandaloneUrgentPattern = '(?i)known exploited|actively exploited|active exploitation|exploited in the wild|zero[- ]day|0-day|emergency patch|out-of-band patch'
$SecurityContextPattern = '(?i)CVE-\d{4}-\d{4,7}|vulnerability|vulnerabilities|security update|security flaw|exploit|exploitation|proof[- ]of[- ]concept|PoC|\bRCE\b|remote code execution|auth bypass|authentication bypass|privilege escalation|elevation of privilege|critical vulnerability|critical security flaw|patch|patched|mitigation|mitigate'

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Level = 'INFO'
    )

    Ensure-Directory -Path $LogRoot
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function ConvertTo-UtcDate {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    try {
        return ([datetime]$text).ToUniversalTime()
    }
    catch {
        try {
            return [datetime]::Parse($text).ToUniversalTime()
        }
        catch {
            return $null
        }
    }
}

function Format-NvdDate {
    param([datetime]$Date)

    return $Date.ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fff',
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function New-QueryUrl {
    param(
        [Parameter(Mandatory)][string]$BaseUrl,
        [Parameter(Mandatory)][hashtable]$Query
    )

    $pairs = @()

    foreach ($key in $Query.Keys) {
        $pairs += ('{0}={1}' -f [uri]::EscapeDataString([string]$key), [uri]::EscapeDataString([string]$Query[$key]))
    }

    return "$BaseUrl`?$($pairs -join '&')"
}

function New-StringFromCodePoints {
    param([Parameter(Mandatory)][int[]]$CodePoints)

    $chars = foreach ($codePoint in $CodePoints) {
        [string][char]$codePoint
    }

    return ($chars -join '')
}

function Repair-TextEncodingArtifacts {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $clean = [string]$Text

    # These mojibake sequences are built from character codes so the script
    # does not contain parser-hostile control characters or broken quote bytes.
    $replacementPairs = @(
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x20AC, 0x2122)); Good = "'" },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x20AC, 0x02DC)); Good = "'" },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x20AC, 0x0153)); Good = '"' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x20AC, 0x009D)); Good = '"' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x0080, 0x009C)); Good = '"' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x0080, 0x009D)); Good = '"' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x20AC, 0x201C)); Good = '-' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x0080, 0x0093)); Good = '-' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x20AC, 0x201D)); Good = '-' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x0080, 0x0094)); Good = '-' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00E2, 0x20AC, 0x00A6)); Good = '...' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00C2, 0x0020)); Good = ' ' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00C2, 0x00AE)); Good = '(R)' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00C2, 0x00A9)); Good = '(C)' },
        [pscustomobject]@{ Bad = (New-StringFromCodePoints @(0x00C2, 0x00B7)); Good = '-' }
    )

    foreach ($pair in $replacementPairs) {
        $clean = $clean.Replace($pair.Bad, $pair.Good)
    }

    return $clean
}

function ConvertFrom-SourceText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $clean = [string]$Text

    $clean = $clean -replace "`0", ''
    $clean = $clean -replace '^\s*ï»¿', ''
    $clean = $clean.TrimStart([char]0xFEFF)

    $clean = [regex]::Replace($clean, '<script[\s\S]*?</script>', ' ')
    $clean = [regex]::Replace($clean, '<style[\s\S]*?</style>', ' ')

    $clean = [regex]::Replace($clean, '<title[^>]*>', ' Title: ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $clean = [regex]::Replace($clean, '</title>', '. ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    $clean = [regex]::Replace($clean, '<description[^>]*>', ' Description: ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $clean = [regex]::Replace($clean, '</description>', '. ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    $clean = [regex]::Replace($clean, '<summary[^>]*>', ' Summary: ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $clean = [regex]::Replace($clean, '</summary>', '. ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    $clean = [regex]::Replace($clean, '<content[^>]*>', ' Content: ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $clean = [regex]::Replace($clean, '</content>', '. ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    $clean = [regex]::Replace($clean, '<[^>]+>', ' ')
    $clean = [System.Net.WebUtility]::HtmlDecode($clean)
    $clean = Repair-TextEncodingArtifacts -Text $clean
    $clean = [regex]::Replace($clean, '\s+', ' ').Trim()

    return $clean
}

function ConvertTo-CleanXmlContent {
    param([string]$Content)

    if ([string]::IsNullOrWhiteSpace($Content)) {
        return ''
    }

    $clean = [string]$Content
    $clean = $clean -replace "`0", ''
    $clean = $clean.TrimStart([char]0xFEFF)
    $clean = $clean -replace '^\s*ï»¿', ''
    $clean = $clean.TrimStart()

    return $clean
}

function Get-PageTitle {
    param(
        [string]$RawContent,
        [string]$Fallback
    )

    if ([string]::IsNullOrWhiteSpace($RawContent)) {
        return $Fallback
    }

    $titleMatch = [regex]::Match(
        $RawContent,
        '<title[^>]*>([\s\S]*?)</title>',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($titleMatch.Success) {
        $title = ConvertFrom-SourceText -Text $titleMatch.Groups[1].Value

        if (-not [string]::IsNullOrWhiteSpace($title)) {
            return $title
        }
    }

    return $Fallback
}

function Get-CveIds {
    param(
        [string]$Text,
        [int]$MaxCount = 25
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $matches = [regex]::Matches(
        $Text,
        'CVE-\d{4}-\d{4,7}',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    $ids = @($matches | ForEach-Object { $_.Value.ToUpperInvariant() } | Sort-Object -Unique)

    if ($ids.Count -le $MaxCount) {
        return ($ids -join '; ')
    }

    $shown = @($ids | Select-Object -First $MaxCount)
    return (($shown -join '; ') + "; +$($ids.Count - $MaxCount) more")
}


function Get-StableHash {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        $Text = ''
    }

    $normalized = [regex]::Replace(([string]$Text).Trim().ToLowerInvariant(), '\s+', ' ')
    $sha = [System.Security.Cryptography.SHA256]::Create()

    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
        $hashBytes = $sha.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').Substring(0, 32)
    }
    finally {
        if ($sha) {
            $sha.Dispose()
        }
    }
}

function Get-MatchedKeywords {
    param([string]$Text)

    $matched = @()

    foreach ($keyword in @($DisplayWatchedPatterns + $SecurityPatterns)) {
        if ($Text -match $keyword.Pattern) {
            $matched += $keyword.Name
        }
    }

    $matched = @($matched | Sort-Object -Unique)
    return ($matched -join '; ')
}

function Test-ConcreteWatchedMatch {
    param([string]$Text)

    foreach ($keyword in $RelevanceWatchedPatterns) {
        if ($Text -match $keyword.Pattern) {
            return $true
        }
    }

    return $false
}

function Test-RelevantText {
    param(
        [string]$Text,
        [switch]$ForceRelevant
    )

    if ($ForceRelevant) {
        return $true
    }

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    if ($Text -match $StandaloneUrgentPattern) {
        return $true
    }

    $hasConcreteWatched = Test-ConcreteWatchedMatch -Text $Text
    $hasSecurityContext = $Text -match $SecurityContextPattern

    if ($hasConcreteWatched -and $hasSecurityContext) {
        return $true
    }

    return $false
}

function Get-Priority {
    param(
        [string]$Source,
        [string]$Text
    )

    if ($Source -eq 'CISA KEV') {
        return 'HIGH'
    }

    if ($Text -match $StandaloneUrgentPattern) {
        return 'HIGH'
    }

    if ($Text -match '(?i)\bRCE\b|remote code execution|auth bypass|authentication bypass|privilege escalation|elevation of privilege|critical vulnerability|critical security flaw') {
        return 'HIGH'
    }

    return 'MEDIUM'
}

function Get-PrioritySort {
    param([string]$Priority)

    switch ($Priority) {
        'HIGH' { return 1 }
        'MEDIUM' { return 2 }
        default { return 3 }
    }
}

function Get-ShortSnippet {
    param(
        [string]$Text,
        [int]$MaxLength = 450
    )

    $clean = ConvertFrom-SourceText -Text $Text

    if ([string]::IsNullOrWhiteSpace($clean)) {
        return ''
    }

    if ($clean.Length -le $MaxLength) {
        return $clean
    }

    return ($clean.Substring(0, $MaxLength) + '...')
}

function New-CandidateItem {
    param(
        [string]$Source,
        [string]$Title,
        [string]$Date,
        [string]$Url,
        [string]$Text,
        [switch]$ForceRelevant,
        [switch]$SuppressCveExtraction
    )

    $cleanTitle = ConvertFrom-SourceText -Text $Title
    $cleanText = ConvertFrom-SourceText -Text $Text

    if ([string]::IsNullOrWhiteSpace($cleanTitle)) {
        $cleanTitle = $Source
    }

    $combined = "$cleanTitle. $cleanText"

    if (-not (Test-RelevantText -Text $combined -ForceRelevant:$ForceRelevant)) {
        return $null
    }

    $priority = Get-Priority -Source $Source -Text $combined
    $dateUtc = ConvertTo-UtcDate -Value $Date
    $dateSort = if ($dateUtc) { $dateUtc.Ticks } else { 0 }
    $cves = if ($SuppressCveExtraction) { 'See source page' } else { Get-CveIds -Text $combined }

    $keyText = if (-not [string]::IsNullOrWhiteSpace($cves) -and $cves -ne 'See source page') {
        "$Source|$cves|$cleanTitle|$Url"
    }
    else {
        $snippetForKey = Get-ShortSnippet -Text $combined -MaxLength 900
        "$Source|$cleanTitle|$Url|$snippetForKey"
    }

    return [pscustomobject][ordered]@{
        Source          = $Source
        Priority        = $priority
        PrioritySort    = Get-PrioritySort -Priority $priority
        Date            = $Date
        DateSort        = $dateSort
        Title           = $cleanTitle
        Url             = $Url
        MatchedKeywords = Get-MatchedKeywords -Text $combined
        CVEs            = $cves
        Snippet         = Get-ShortSnippet -Text $combined -MaxLength $MaxSnippetLength
        ItemKey         = Get-StableHash -Text $keyText
    }
}

function Get-WebText {
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$NvdApiKey = ''
    )

    $headers = @{
        'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) MME-CVEKeywordCollector/2.1'
        'Accept' = 'text/html,application/xhtml+xml,application/xml,application/rss+xml,application/atom+xml,application/json,*/*'
    }

    if (-not [string]::IsNullOrWhiteSpace($NvdApiKey)) {
        $headers['apiKey'] = $NvdApiKey
    }

    $params = @{
        Uri = $Url
        Method = 'GET'
        Headers = $headers
        TimeoutSec = 60
        ErrorAction = 'Stop'
    }

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $params['UseBasicParsing'] = $true
    }

    $response = Invoke-WebRequest @params

    return [pscustomobject]@{
        StatusCode = [string]$response.StatusCode
        Content = [string]$response.Content
    }
}

function Get-XmlChildText {
    param(
        [System.Xml.XmlNode]$Node,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        foreach ($child in @($Node.ChildNodes)) {
            if ($child.LocalName -eq $name) {
                $value = [string]$child.InnerText
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    return $value
                }
            }
        }
    }

    return ''
}

function Get-XmlItemLink {
    param([System.Xml.XmlNode]$Node)

    foreach ($child in @($Node.ChildNodes)) {
        if ($child.LocalName -ne 'link') {
            continue
        }

        if ($child -is [System.Xml.XmlElement]) {
            $href = [string]$child.GetAttribute('href')
            $rel = [string]$child.GetAttribute('rel')

            if (-not [string]::IsNullOrWhiteSpace($href)) {
                if ([string]::IsNullOrWhiteSpace($rel) -or $rel -eq 'alternate') {
                    return $href
                }
            }
        }

        $text = [string]$child.InnerText
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            return $text
        }
    }

    return Get-XmlChildText -Node $Node -Names @('guid', 'id')
}

function Test-WithinLookback {
    param(
        [string]$DateText,
        [datetime]$CutoffUtc
    )

    $dateUtc = ConvertTo-UtcDate -Value $DateText

    if ($null -eq $dateUtc) {
        return $true
    }

    return ($dateUtc -ge $CutoffUtc)
}

function Get-FeedCandidateItems {
    param(
        [string]$Source,
        [string]$SourceUrl,
        [string]$RawContent,
        [datetime]$CutoffUtc
    )

    $items = @()
    $cleanXml = ConvertTo-CleanXmlContent -Content $RawContent
    [xml]$xml = $cleanXml

    $nodes = @()
    $nodes += @($xml.SelectNodes("//*[local-name()='item']"))
    $nodes += @($xml.SelectNodes("//*[local-name()='entry']"))

    foreach ($node in $nodes) {
        $title = Get-XmlChildText -Node $node -Names @('title')
        $summary = Get-XmlChildText -Node $node -Names @('description', 'summary', 'content', 'encoded')
        $date = Get-XmlChildText -Node $node -Names @('pubDate', 'published', 'updated')
        $link = Get-XmlItemLink -Node $node

        if (-not (Test-WithinLookback -DateText $date -CutoffUtc $CutoffUtc)) {
            continue
        }

        if ([string]::IsNullOrWhiteSpace($link)) {
            $link = $SourceUrl
        }

        if ($Source -eq 'Chrome Releases') {
            $chromeText = "$title $summary"

            if ($chromeText -match '(?i)\bdev channel\b|\bbeta channel\b|\bcanary\b|Chrome Dev') {
                if ($chromeText -notmatch '(?i)security|CVE-\d{4}-\d{4,7}|zero[- ]day|0-day|exploit|stable') {
                    continue
                }
            }

            if ($chromeText -notmatch '(?i)security|CVE-\d{4}-\d{4,7}|zero[- ]day|0-day|exploit|stable|extended stable') {
                continue
            }
        }

        $candidate = New-CandidateItem `
            -Source $Source `
            -Title $title `
            -Date $date `
            -Url $link `
            -Text $summary

        if ($null -ne $candidate) {
            $items += $candidate
        }
    }

    return $items
}

function Get-CisaKevCandidateItems {
    param(
        [string]$Source,
        [string]$SourceUrl,
        [string]$RawContent,
        [int]$LookbackHours
    )

    $items = @()
    $cutoff = (Get-Date).ToUniversalTime().AddHours(-[math]::Abs($LookbackHours))
    $json = $RawContent | ConvertFrom-Json

    foreach ($vuln in @($json.vulnerabilities)) {
        $dateAdded = ConvertTo-UtcDate -Value $vuln.dateAdded

        if ($dateAdded -and $dateAdded -lt $cutoff) {
            continue
        }

        $cve = [string]$vuln.cveID
        $vendorProduct = "$($vuln.vendorProject) $($vuln.product)".Trim()
        $title = "$cve - $($vuln.vulnerabilityName)"
        $text = "Vendor/Product: $vendorProduct. $($vuln.shortDescription) Required action: $($vuln.requiredAction)"

        $candidate = New-CandidateItem `
            -Source $Source `
            -Title $title `
            -Date ([string]$vuln.dateAdded) `
            -Url $SourceUrl `
            -Text $text `
            -ForceRelevant

        if ($null -ne $candidate) {
            $items += $candidate
        }
    }

    return $items
}

function Get-NvdCandidateItems {
    param(
        [string]$Source,
        [string]$RawContent
    )

    $items = @()
    $json = $RawContent | ConvertFrom-Json

    foreach ($wrapper in @($json.vulnerabilities)) {
        $cveObj = $wrapper.cve
        $cveId = [string]$cveObj.id
        $published = [string]$cveObj.published

        if ([string]::IsNullOrWhiteSpace($cveId)) {
            continue
        }

        $descObj = @($cveObj.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1)
        $desc = [string]$descObj.value
        $itemUrl = "https://nvd.nist.gov/vuln/detail/$cveId"

        $candidate = New-CandidateItem `
            -Source $Source `
            -Title "$cveId - NVD published CVE" `
            -Date $published `
            -Url $itemUrl `
            -Text $desc

        if ($null -ne $candidate) {
            $items += $candidate
        }
    }

    return $items
}

function Get-PageCandidateItems {
    param(
        [string]$Source,
        [string]$SourceUrl,
        [string]$RawContent
    )

    $items = @()
    $title = Get-PageTitle -RawContent $RawContent -Fallback $Source
    $plain = ConvertFrom-SourceText -Text $RawContent

    if (-not (Test-RelevantText -Text $plain)) {
        return $items
    }

    $candidate = New-CandidateItem `
        -Source $Source `
        -Title $title `
        -Date '' `
        -Url $SourceUrl `
        -Text $plain `
        -SuppressCveExtraction

    if ($null -ne $candidate) {
        $items += $candidate
    }

    return $items
}

function Build-Digest {
    param(
        [array]$Items,
        [int]$MaxItems
    )

    if ($Items.Count -eq 0) {
        return [pscustomobject][ordered]@{
            RelevantItems   = 0
            IncludedItems   = 0
            AdditionalItems = 0
            HighestPriority = ''
            MatchedKeywords = ''
            CVEs            = ''
            Digest          = 'No new relevant watched vendor/product/security keyword hits found.'
            FullDetails     = 'No new relevant watched vendor/product/security keyword hits found.'
            ItemKeys        = ''
        }
    }

    $sorted = @($Items | Sort-Object PrioritySort, @{ Expression = 'DateSort'; Descending = $true }, Title)
    $included = @($sorted | Select-Object -First $MaxItems)
    $additional = [math]::Max(0, $Items.Count - $included.Count)

    $digestParts = @()
    $fullDetailParts = @()

    foreach ($item in $included) {
        $dateText = if ([string]::IsNullOrWhiteSpace($item.Date)) { 'Date: unknown' } else { "Date: $($item.Date)" }
        $cveText = if ([string]::IsNullOrWhiteSpace($item.CVEs)) { 'CVEs: None found in relevant item text' } else { "CVEs: $($item.CVEs)" }
        $keywordText = if ([string]::IsNullOrWhiteSpace($item.MatchedKeywords)) { 'Matched: None' } else { "Matched: $($item.MatchedKeywords)" }

        $digestParts += "[{0}] {1} - {2}. {3}. {4}. {5}. Snippet: {6}. Link: {7}" -f `
            $item.Priority,
            $item.Source,
            $item.Title,
            $dateText,
            $keywordText,
            $cveText,
            $item.Snippet,
            $item.Url
    }

    if ($additional -gt 0) {
        $digestParts += "+$additional additional new relevant item(s) found for this source. Review the FullDetails column in this CSV for all new relevant items."
    }

    $detailIndex = 0

    foreach ($item in $sorted) {
        $detailIndex++
        $dateText = if ([string]::IsNullOrWhiteSpace($item.Date)) { 'Date: unknown' } else { "Date: $($item.Date)" }
        $cveText = if ([string]::IsNullOrWhiteSpace($item.CVEs)) { 'CVEs: None found in relevant item text' } else { "CVEs: $($item.CVEs)" }
        $keywordText = if ([string]::IsNullOrWhiteSpace($item.MatchedKeywords)) { 'Matched: None' } else { "Matched: $($item.MatchedKeywords)" }
        $includedText = if ($detailIndex -le $included.Count) { 'IncludedInDigest: True' } else { 'IncludedInDigest: False' }

        $fullDetailParts += "[Item {0} of {1}] [{2}] {3}. {4}. {5}. {6}. {7}. ItemKey: {8}. Snippet: {9}. Link: {10}" -f `
            $detailIndex,
            $sorted.Count,
            $item.Priority,
            $item.Title,
            $dateText,
            $keywordText,
            $cveText,
            $includedText,
            $item.ItemKey,
            $item.Snippet,
            $item.Url
    }

    $allKeywords = @($Items | ForEach-Object { $_.MatchedKeywords } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '
    $allKeywordList = @($allKeywords -split '; ' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

    $allCves = @($included | ForEach-Object { $_.CVEs } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '
    $allCveMatches = [regex]::Matches($allCves, 'CVE-\d{4}-\d{4,7}', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $allCveList = @($allCveMatches | ForEach-Object { $_.Value.ToUpperInvariant() } | Sort-Object -Unique)

    if ($allCves -match 'See source page') {
        if ($allCveList.Count -gt 0) {
            $allCveList += 'See source page'
        }
        else {
            $allCveList = @('See source page')
        }
    }

    $itemKeys = @($Items | ForEach-Object { $_.ItemKey } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

    return [pscustomobject][ordered]@{
        RelevantItems   = $Items.Count
        IncludedItems   = $included.Count
        AdditionalItems = $additional
        HighestPriority = $sorted[0].Priority
        MatchedKeywords = ($allKeywordList -join '; ')
        CVEs            = ($allCveList -join '; ')
        Digest          = ($digestParts -join ' || ')
        FullDetails     = ($fullDetailParts -join ' || ')
        ItemKeys        = ($itemKeys -join '; ')
    }
}


function Limit-TextLength {
    param(
        [string]$Text,
        [int]$MaxLength = 12000
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    if ($Text.Length -le $MaxLength) {
        return $Text
    }

    return ($Text.Substring(0, $MaxLength) + "`n`n[Truncated for Teams. Review the CSV FullDetails column for complete local details.]")
}

function New-TeamsDigestText {
    param([Parameter(Mandatory)][object]$Row)

    $source = [string]$Row.Source
    $priority = if ([string]::IsNullOrWhiteSpace([string]$Row.HighestPriority)) { 'N/A' } else { [string]$Row.HighestPriority }

    $additionalNote = ''
    $additionalItems = 0

    try {
        $additionalItems = [int]$Row.AdditionalItems
    }
    catch {
        $additionalItems = 0
    }

    if ($additionalItems -gt 0) {
        $additionalNote = "`n`nAdditional items were found. Review the FullDetails column in C:\MME\ThreatIntel\CVE_Keyword_Hits.csv for all local details."
    }

    if ([string]$Row.SourceType -eq 'Page') {
        $message = @"
Threat Feed - $source

Priority: $priority
New relevant items: $($Row.RelevantItems)
Included in digest: $($Row.IncludedItems)
Additional items: $($Row.AdditionalItems)
Source URL: $($Row.Url)

Page-based source matched watched/security terms.

CVEs: $($Row.CVEs)
Matched: $($Row.MatchedKeywords)

This source is page-scraped, so the Teams post is intentionally shortened to avoid page-boilerplate/card-formatting issues.

Review the source page and the FullDetails column in:
C:\MME\ThreatIntel\CVE_Keyword_Hits.csv$additionalNote
"@

        return (Limit-TextLength -Text $message -MaxLength 12000)
    }

    $digest = [string]$Row.Digest
    $digest = $digest -replace '\s*\|\|\s*', "`n`n"

    $message = @"
Threat Feed - $source

Priority: $priority
New relevant items: $($Row.RelevantItems)
Included in digest: $($Row.IncludedItems)
Additional items: $($Row.AdditionalItems)
Source URL: $($Row.Url)

$digest$additionalNote
"@

    return (Limit-TextLength -Text $message -MaxLength 12000)
}

function Send-TeamsDigestPost {
    param(
        [Parameter(Mandatory)][string]$WebhookUrl,
        [Parameter(Mandatory)][object]$Row
    )

    if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
        return 'Not configured'
    }

    $title = "Threat Feed - $($Row.Source)"
    $message = New-TeamsDigestText -Row $Row

    $payload = [ordered]@{
        type = 'message'
        attachments = @(
            [ordered]@{
                contentType = 'application/vnd.microsoft.card.adaptive'
                contentUrl = $null
                content = [ordered]@{
                    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                    type = 'AdaptiveCard'
                    version = '1.4'
                    msteams = [ordered]@{
                        width = 'Full'
                    }
                    body = @(
                        [ordered]@{
                            type = 'TextBlock'
                            text = $title
                            weight = 'Bolder'
                            size = 'Medium'
                            wrap = $true
                        },
                        [ordered]@{
                            type = 'FactSet'
                            facts = @(
                                [ordered]@{ title = 'Priority'; value = [string]$Row.HighestPriority },
                                [ordered]@{ title = 'New relevant items'; value = [string]$Row.RelevantItems },
                                [ordered]@{ title = 'Included'; value = [string]$Row.IncludedItems },
                                [ordered]@{ title = 'Additional'; value = [string]$Row.AdditionalItems },
                                [ordered]@{ title = 'Source'; value = [string]$Row.Source }
                            )
                        },
                        [ordered]@{
                            type = 'TextBlock'
                            text = $message
                            wrap = $true
                        }
                    )
                }
            }
        )
    }

    $json = $payload | ConvertTo-Json -Depth 20

    Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType 'application/json' -Body $json -ErrorAction Stop | Out-Null
    return 'Sent'
}

function Convert-ToCsvOutputRow {
    param([object]$Row)

    $foundRelevant = [string]$Row.FoundRelevantItems
    if ([string]::IsNullOrWhiteSpace($foundRelevant)) {
        $foundRelevant = [string]$Row.RelevantItems
    }

    $duplicateItems = [string]$Row.DuplicateItems
    if ([string]::IsNullOrWhiteSpace($duplicateItems)) {
        $duplicateItems = '0'
    }

    return [pscustomobject][ordered]@{
        RunTime            = [string]$Row.RunTime
        Source             = [string]$Row.Source
        SourceType         = [string]$Row.SourceType
        Url                = [string]$Row.Url
        Status             = [string]$Row.Status
        HttpStatus         = [string]$Row.HttpStatus
        FoundRelevantItems = $foundRelevant
        RelevantItems      = [string]$Row.RelevantItems
        DuplicateItems     = $duplicateItems
        IncludedItems      = [string]$Row.IncludedItems
        AdditionalItems    = [string]$Row.AdditionalItems
        HighestPriority    = [string]$Row.HighestPriority
        MatchedKeywords    = [string]$Row.MatchedKeywords
        CVEs               = [string]$Row.CVEs
        TitleOrPage        = [string]$Row.TitleOrPage
        Digest             = [string]$Row.Digest
        FullDetails        = [string]$Row.FullDetails
        ItemKeys           = [string]$Row.ItemKeys
        TeamsPostStatus   = [string]$Row.TeamsPostStatus
        Error              = [string]$Row.Error
    }
}

try {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        # Continue if TLS setting is unavailable.
    }

    Ensure-Directory -Path $IntelRoot
    Ensure-Directory -Path $LogRoot

    $cutoffUtc = (Get-Date).ToUniversalTime().AddHours(-[math]::Abs($LookbackHours))
    $endUtc = (Get-Date).ToUniversalTime()

    $nvdUrl = New-QueryUrl -BaseUrl 'https://services.nvd.nist.gov/rest/json/cves/2.0' -Query @{
        pubStartDate   = Format-NvdDate -Date $cutoffUtc
        pubEndDate     = Format-NvdDate -Date $endUtc
        resultsPerPage = 2000
        startIndex     = 0
    }

    $sources = @(
        [pscustomobject]@{ Source = 'CISA KEV'; Type = 'CisaKevJson'; Url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
        [pscustomobject]@{ Source = 'CISA Advisories'; Type = 'Feed'; Url = 'https://www.cisa.gov/cybersecurity-advisories/all.xml' },
        [pscustomobject]@{ Source = 'NVD Recent CVEs'; Type = 'NvdJson'; Url = $nvdUrl },
        [pscustomobject]@{ Source = 'Microsoft MSRC'; Type = 'Feed'; Url = 'https://api.msrc.microsoft.com/update-guide/rss' },
        [pscustomobject]@{ Source = 'Chrome Releases'; Type = 'Feed'; Url = 'https://chromereleases.googleblog.com/feeds/posts/default' },
        [pscustomobject]@{ Source = 'WatchGuard Advisories'; Type = 'Page'; Url = 'https://www.watchguard.com/wgrd-psirt/advisories' },
        [pscustomobject]@{ Source = 'ConnectWise Bulletins'; Type = 'Page'; Url = 'https://www.connectwise.com/company/trust/security-bulletins' },
        [pscustomobject]@{ Source = 'Reddit r/netsec'; Type = 'Feed'; Url = 'https://www.reddit.com/r/netsec/.rss' },
        [pscustomobject]@{ Source = 'Reddit r/cybersecurity'; Type = 'Feed'; Url = 'https://www.reddit.com/r/cybersecurity/.rss' },
        [pscustomobject]@{ Source = 'BleepingComputer'; Type = 'Feed'; Url = 'https://www.bleepingcomputer.com/feed/' },
        [pscustomobject]@{ Source = 'The Hacker News'; Type = 'Feed'; Url = 'https://feeds.feedburner.com/TheHackersNews' },
        [pscustomobject]@{ Source = 'KrebsOnSecurity'; Type = 'Feed'; Url = 'https://krebsonsecurity.com/feed/' },
        [pscustomobject]@{ Source = "Tom's Hardware"; Type = 'Feed'; Url = 'https://www.tomshardware.com/feeds/all' }
    )

    $existingRows = @()
    $existingItemKeys = @{}

    if (Test-Path -LiteralPath $OutputCsv) {
        try {
            $existingRows = @(Import-Csv -LiteralPath $OutputCsv -ErrorAction Stop)

            foreach ($existingRow in $existingRows) {
                $keysText = [string]$existingRow.ItemKeys

                foreach ($key in @($keysText -split ';')) {
                    $cleanKey = ([string]$key).Trim()

                    if (-not [string]::IsNullOrWhiteSpace($cleanKey)) {
                        $existingItemKeys[$cleanKey] = $true
                    }
                }
            }

            Write-Log -Message "Loaded existing CSV state. ExistingRows=$($existingRows.Count); ExistingItemKeys=$($existingItemKeys.Count)."
        }
        catch {
            Write-Log -Level 'WARN' -Message "Existing CSV could not be imported for de-duplication. Continuing with empty de-dupe state. Error: $($_.Exception.Message)"
            $existingRows = @()
            $existingItemKeys = @{}
        }
    }

    $rows = @()
    $checked = 0
    $newRelevantSources = 0
    $foundRelevantItemsTotal = 0
    $newRelevantItemsTotal = 0
    $duplicateItemsTotal = 0
    $errors = 0
    $runTime = Get-Date

    Write-Log -Message "Starting keyword collector. LookbackHours=$LookbackHours; MaxItemsPerSource=$MaxItemsPerSource."

    foreach ($source in $sources) {
        $checked++

        try {
            Write-Log -Message "Checking $($source.Source): $($source.Url)"

            $result = Get-WebText -Url $source.Url -NvdApiKey $NvdApiKey
            $candidateItems = @()

            switch ($source.Type) {
                'CisaKevJson' {
                    $candidateItems = @(Get-CisaKevCandidateItems `
                        -Source $source.Source `
                        -SourceUrl $source.Url `
                        -RawContent $result.Content `
                        -LookbackHours $LookbackHours)
                }

                'NvdJson' {
                    $candidateItems = @(Get-NvdCandidateItems `
                        -Source $source.Source `
                        -RawContent $result.Content)
                }

                'Feed' {
                    try {
                        $candidateItems = @(Get-FeedCandidateItems `
                            -Source $source.Source `
                            -SourceUrl $source.Url `
                            -RawContent $result.Content `
                            -CutoffUtc $cutoffUtc)
                    }
                    catch {
                        Write-Log -Level 'WARN' -Message "$($source.Source) feed parse failed, falling back to page scan: $($_.Exception.Message)"

                        $candidateItems = @(Get-PageCandidateItems `
                            -Source $source.Source `
                            -SourceUrl $source.Url `
                            -RawContent $result.Content)
                    }
                }

                default {
                    $candidateItems = @(Get-PageCandidateItems `
                        -Source $source.Source `
                        -SourceUrl $source.Url `
                        -RawContent $result.Content)
                }
            }

            $foundRelevantItemsTotal += $candidateItems.Count
            $newCandidateItems = @()
            $duplicateItemsForSource = 0

            foreach ($candidateItem in $candidateItems) {
                $candidateKey = [string]$candidateItem.ItemKey

                if ([string]::IsNullOrWhiteSpace($candidateKey)) {
                    $newCandidateItems += $candidateItem
                    continue
                }

                if ($existingItemKeys.ContainsKey($candidateKey)) {
                    $duplicateItemsForSource++
                    continue
                }

                $existingItemKeys[$candidateKey] = $true
                $newCandidateItems += $candidateItem
            }

            $duplicateItemsTotal += $duplicateItemsForSource
            $digest = Build-Digest -Items $newCandidateItems -MaxItems $MaxItemsPerSource

            if ($digest.RelevantItems -gt 0) {
                $newRelevantSources++
                $newRelevantItemsTotal += $digest.RelevantItems

                $rows += [pscustomobject][ordered]@{
                    RunTime            = $runTime.ToString('yyyy-MM-dd HH:mm:ss')
                    Source             = $source.Source
                    SourceType         = $source.Type
                    Url                = $source.Url
                    Status             = 'OK'
                    HttpStatus         = $result.StatusCode
                    FoundRelevantItems = $candidateItems.Count
                    RelevantItems      = $digest.RelevantItems
                    DuplicateItems     = $duplicateItemsForSource
                    IncludedItems      = $digest.IncludedItems
                    AdditionalItems    = $digest.AdditionalItems
                    HighestPriority    = $digest.HighestPriority
                    MatchedKeywords    = $digest.MatchedKeywords
                    CVEs               = $digest.CVEs
                    TitleOrPage        = Get-PageTitle -RawContent $result.Content -Fallback $source.Source
                    Digest             = $digest.Digest
                    FullDetails        = $digest.FullDetails
                    ItemKeys           = $digest.ItemKeys
                    TeamsPostStatus   = 'Not attempted'
                    Error              = 'No error'
                }
            }
            else {
                Write-Log -Message "$($source.Source) had no new relevant items. FoundRelevantItems=$($candidateItems.Count); DuplicateItems=$duplicateItemsForSource."
            }
        }
        catch {
            $errors++

            Write-Log -Level 'ERROR' -Message "$($source.Source) failed: $($_.Exception.Message)"

            $rows += [pscustomobject][ordered]@{
                RunTime            = $runTime.ToString('yyyy-MM-dd HH:mm:ss')
                Source             = $source.Source
                SourceType         = $source.Type
                Url                = $source.Url
                Status             = 'ERROR'
                HttpStatus         = ''
                FoundRelevantItems = 0
                RelevantItems      = 0
                DuplicateItems     = 0
                IncludedItems      = 0
                AdditionalItems    = 0
                HighestPriority    = ''
                MatchedKeywords    = ''
                CVEs               = ''
                TitleOrPage        = $source.Source
                Digest             = ''
                FullDetails        = ''
                ItemKeys           = ''
                TeamsPostStatus   = 'Not attempted'
                Error              = $_.Exception.Message
            }
        }
    }


    $teamsPosts = 0
    $teamsErrors = 0

    if (-not [string]::IsNullOrWhiteSpace($TeamsWebhookUrl)) {
        Write-Log -Message "Teams webhook configured. Sending one digest post per new source row. NewRows=$($rows.Count)."

        foreach ($row in $rows) {
            if ([string]$row.Status -ne 'OK') {
                $row.TeamsPostStatus = 'Skipped: Source error row'
                continue
            }

            try {
                $postStatus = Send-TeamsDigestPost -WebhookUrl $TeamsWebhookUrl -Row $row
                $row.TeamsPostStatus = $postStatus

                if ($postStatus -eq 'Sent') {
                    $teamsPosts++
                    Write-Log -Message "Teams post sent for $($row.Source)."
                }
            }
            catch {
                $teamsErrors++
                $row.TeamsPostStatus = "Failed: $($_.Exception.Message)"
                Write-Log -Level 'ERROR' -Message "Teams post failed for $($row.Source): $($_.Exception.Message)"
            }
        }
    }
    else {
        foreach ($row in $rows) {
            $row.TeamsPostStatus = 'Not configured'
        }

        Write-Log -Message 'Teams webhook not configured. Skipping Teams posts.'
    }

    $finalRows = @()

    foreach ($existingRow in $existingRows) {
        $finalRows += Convert-ToCsvOutputRow -Row $existingRow
    }

    foreach ($newRow in $rows) {
        $finalRows += Convert-ToCsvOutputRow -Row $newRow
    }

    if ($finalRows.Count -gt 0) {
        $finalRows | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding UTF8
    }

    Write-Log -Message "Completed. Checked=$checked; NewRelevantSources=$newRelevantSources; FoundRelevantItems=$foundRelevantItemsTotal; NewRelevantItems=$newRelevantItemsTotal; DuplicateItems=$duplicateItemsTotal; Errors=$errors; TeamsPosts=$teamsPosts; TeamsErrors=$teamsErrors; NewRows=$($rows.Count); Csv=$OutputCsv"

    Write-Output "RESULT | Checked=$checked; NewRelevantSources=$newRelevantSources; NewRelevantItems=$newRelevantItemsTotal; DuplicateItems=$duplicateItemsTotal; Errors=$errors; TeamsPosts=$teamsPosts; TeamsErrors=$teamsErrors; Csv=$OutputCsv"
    exit 0
}
catch {
    try {
        Write-Log -Level 'ERROR' -Message "Unexpected script error: $($_.Exception.Message)"
    }
    catch {
        # If logging fails, still output the error.
    }

    Write-Output "ERROR | Unexpected script error occurred. $($_.Exception.Message)"
    exit 0
}