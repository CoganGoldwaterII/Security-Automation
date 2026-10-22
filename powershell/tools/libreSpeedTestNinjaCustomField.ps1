# ============================================================================
# NAME: LibreSpeed Internet Speed Test
# AUTHORED BY: Cogan Goldwater
# TYPE: Diagnostic Utility
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: Internal configuration values for server discovery, latency,
#             download/upload concurrency, timing, request sizes, benchmarking,
#             time_auto, and logging. No NinjaOne input parameters.
#
# OUTPUT TOKENS:
#   RESULT    | Not currently emitted
#   NO_ACTION | Not currently emitted
#   ERROR     | Not currently emitted
#   Actual output: Write-Host progress and results; errors shown by Write-Host.
#   The script has no explicit exit statement.
#
# CUSTOM FIELDS:
#   Reads: None
#   Writes: internetSpeedTest (WYSIWYG)
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\MME\AutoLogs\LibreSpeed_Internet_Speed_Test.log
#
# DESCRIPTION:
#   Retrieves LibreSpeed's public server list, probes server latency,
#   selects the lowest reported selector ping, and tests ping, jitter,
#   multistream download throughput, and multistream upload throughput.
#   Uses HTTP requests, runspace-based workers, LibreSpeed-style timing,
#   and overhead factors. Writes detailed diagnostics to the log.
#   On successful completion, writes an HTML summary to the NinjaOne
#   internetSpeedTest field using Ninja-Property-Set-Piped.
#   Requires external network access and can generate substantial traffic.
#   Field write failures are logged as warnings without failing the test.
#   Configuration includes benchmark and payload-probing variables whose
#   associated functions are not currently invoked by the main execution.
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

[Net.ServicePointManager]::SecurityProtocol =
    [Net.SecurityProtocolType]::Tls12

[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::DefaultConnectionLimit = 32

# -------------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------------

$ServerListUrl =
    'https://librespeed.org/backend-servers/servers.php'

# LibreSpeed documented defaults.
$PingCount = 10
$TimeAuto = $true

# LibreSpeed browser-style download behavior.
$DownloadStreamCount = 5
$DownloadStreamDelayMS = 300
$DownloadGraceSeconds = 1.5
$DownloadTestSeconds = 15
$DownloadOverheadFactor = 1.06
$DownloadRequestSizeMB = 100

# LibreSpeed browser defaults for upload behavior.
$UploadStreamCount = 3
$UploadStreamDelayMS = 300
$UploadGraceSeconds = 3
$UploadTestSeconds = 15
$UploadOverheadFactor = 1.06

# LibreSpeed browser upload blob size: 20 MB.
$UploadPayloadKB = 20480

# HttpClient copy buffer.
$UploadWriteBufferKB = 1024

# LibreSpeed MPOT server selector defaults.
$ServerSelectorPingCount = 3
$ServerSelectorTimeoutMS = 2000

$UploadBenchmarkCandidateCount = 5
$UploadBenchmarkSeconds = 6

# HttpClient copy buffer. The HTTP request body itself is selected separately
# and may be as large as 20 MB.
$UploadWriteBufferKB = 1024

# Candidate validation uses a conservative 1 MB POST.
$UploadProbePayloadKB = 1024

# The selected server is tested from smallest to largest. The timed upload
# test uses the largest payload accepted without an HTTP error.
$UploadPayloadCandidatesKB = @(
    1024,
    2048,
    4096,
    8192,
    12288,
    16384,
    20480
)

$DiscoveryTimeoutMS = 2500
$CandidateSuccessTarget = 5
$MaximumCandidateAttempts = 15

$LogDirectory =
    'C:\MME\AutoLogs'

$LogPath =
    Join-Path `
        -Path $LogDirectory `
        -ChildPath 'LibreSpeed_Internet_Speed_Test.log'

# -------------------------------------------------------------------------
# Functions
# -------------------------------------------------------------------------

function Initialize-Log {
    try {
        if (
            -not (
                Test-Path `
                    -LiteralPath $LogDirectory
            )
        ) {
            New-Item `
                -Path $LogDirectory `
                -ItemType Directory `
                -Force `
                -ErrorAction Stop |
                Out-Null
        }
    }
    catch {
        # Logging must never break the speed test.
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'INFO',
            'WARN',
            'ERROR',
            'DEBUG'
        )]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    try {
        Initialize-Log

        $Timestamp =
            Get-Date `
                -Format 'yyyy-MM-dd HH:mm:ss.fff'

        Add-Content `
            -LiteralPath $LogPath `
            -Value (
                '{0} [{1}] {2}' -f
                $Timestamp,
                $Level,
                $Message
            ) `
            -Encoding UTF8 `
            -ErrorAction Stop
    }
    catch {
        # Logging failure must not change script control flow.
    }
}

function Write-LiveLine {
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [switch]$Final
    )

    $IsInteractiveTerminal = $false

    try {
        $IsInteractiveTerminal = (
            [Environment]::UserInteractive -and
            $Host.Name -eq 'ConsoleHost' -and
            -not [Console]::IsOutputRedirected
        )
    }
    catch {
        $IsInteractiveTerminal = $false
    }

    if (-not $IsInteractiveTerminal) {
        if ($Final) {
            Write-Host $Text
        }

        return
    }

    try {
        $Width = [Math]::Max(
            40,
            $Host.UI.RawUI.WindowSize.Width - 1
        )
    }
    catch {
        $Width = 100
    }

    Write-Host "`r$($Text.PadRight($Width))" -NoNewline
}

function New-SpeedRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET'
    )

    $Request = [System.Net.HttpWebRequest]::Create($Uri)

    $Request.Method = $Method
    $Request.UserAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell-SpeedTest'

    $Request.Timeout = 300000
    $Request.ReadWriteTimeout = 300000
    $Request.KeepAlive = $true

    $Request.CachePolicy = New-Object `
        System.Net.Cache.RequestCachePolicy `
        -ArgumentList (
            [System.Net.Cache.RequestCacheLevel]::NoCacheNoStore
        )

    if ($Request.Proxy) {
        $Request.Proxy.Credentials =
            [System.Net.CredentialCache]::DefaultCredentials
    }

    return $Request
}

function Join-SpeedUrl {
    param(
        [Parameter(Mandatory)]
        [string]$Base,

        [Parameter(Mandatory)]
        [string]$Path
    )

    if (
        [Uri]::IsWellFormedUriString(
            $Path,
            [UriKind]::Absolute
        )
    ) {
        return $Path
    }

    $CleanBase = $Base.TrimEnd('/')
    $CleanPath = $Path.TrimStart('/')

    return '{0}/{1}' -f $CleanBase, $CleanPath
}

function Add-SpeedQuery {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$Query
    )

    if ($Uri.Contains('?')) {
        return '{0}&{1}' -f $Uri, $Query
    }

    return '{0}?{1}' -f $Uri, $Query
}

function Get-LibreSpeedServerList {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $Request = New-SpeedRequest -Uri $Uri
    $Request.Timeout = 30000
    $Request.ReadWriteTimeout = 30000

    $Request.AutomaticDecompression = (
        [System.Net.DecompressionMethods]::GZip -bor
        [System.Net.DecompressionMethods]::Deflate
    )

    $Response = $null
    $ResponseStream = $null
    $Reader = $null

    try {
        $Response = $Request.GetResponse()
        $ResponseStream = $Response.GetResponseStream()

        $Reader = New-Object `
            System.IO.StreamReader `
            -ArgumentList $ResponseStream

        $Json = $Reader.ReadToEnd()
    }
    finally {
        if ($Reader) {
            $Reader.Dispose()
        }

        if ($ResponseStream) {
            $ResponseStream.Dispose()
        }

        if ($Response) {
            $Response.Dispose()
        }
    }

    if ([string]::IsNullOrWhiteSpace($Json)) {
        throw 'LibreSpeed returned an empty server list.'
    }

    $ParsedServerList =
        ConvertFrom-Json -InputObject $Json

    $RawServers = @()

    foreach ($ParsedServer in $ParsedServerList) {
        $RawServers += $ParsedServer
    }

    if ($RawServers.Count -eq 0) {
        throw 'LibreSpeed returned no server records.'
    }

    $NormalizedServers = @()

    foreach ($RawServer in $RawServers) {
        try {
            $Base = [string]$RawServer.server
            $DownloadPath = [string]$RawServer.dlURL
            $UploadPath = [string]$RawServer.ulURL
            $PingPath = [string]$RawServer.pingURL

            if (
                [string]::IsNullOrWhiteSpace($Base) -or
                [string]::IsNullOrWhiteSpace($DownloadPath) -or
                [string]::IsNullOrWhiteSpace($UploadPath) -or
                [string]::IsNullOrWhiteSpace($PingPath)
            ) {
                continue
            }

            if ($Base -match '^//') {
                $Base = 'https:{0}' -f $Base
            }
            elseif ($Base -notmatch '^https?://') {
                $Base = 'https://{0}' -f $Base.TrimStart('/')
            }

            $Name = [string]$RawServer.name

            if ([string]::IsNullOrWhiteSpace($Name)) {
                $Name = $Base
            }

            $NormalizedServers += [pscustomobject]@{
                Id = $RawServer.id
                Name = $Name
                Base = $Base.TrimEnd('/')

                PingUrl = Join-SpeedUrl `
                    -Base $Base `
                    -Path $PingPath

                DownloadUrl = Join-SpeedUrl `
                    -Base $Base `
                    -Path $DownloadPath

                UploadUrl = Join-SpeedUrl `
                    -Base $Base `
                    -Path $UploadPath
            }
        }
        catch {
            # Ignore malformed individual records.
        }
    }

    if ($NormalizedServers.Count -eq 0) {
        throw 'No valid LibreSpeed server records could be normalized.'
    }

    return $NormalizedServers
}


function Measure-LibreSpeedSelectorPing {
    param(
        [Parameter(Mandatory)]
        [psobject]$Server,

        [ValidateRange(1, 10)]
        [int]$Samples = 3,

        [ValidateRange(250, 10000)]
        [int]$TimeoutMS = 2000
    )

    Add-Type `
        -AssemblyName System.Net.Http `
        -ErrorAction Stop

    $Handler = $null
    $Client = $null

    try {
        $Handler =
            New-Object `
                System.Net.Http.HttpClientHandler

        $Handler.AllowAutoRedirect = $true
        $Handler.UseCookies = $false
        $Handler.UseProxy = $true

        try {
            $DefaultProxy =
                [System.Net.WebRequest]::DefaultWebProxy

            if ($DefaultProxy) {
                $DefaultProxy.Credentials =
                    [System.Net.CredentialCache]::
                        DefaultNetworkCredentials

                $Handler.Proxy =
                    $DefaultProxy
            }
        }
        catch {
        }

        $Client =
            New-Object `
                System.Net.Http.HttpClient `
                -ArgumentList $Handler

        $Client.Timeout =
            [TimeSpan]::FromMilliseconds(
                $TimeoutMS
            )

        [void]$Client.
            DefaultRequestHeaders.
            TryAddWithoutValidation(
                'User-Agent',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell-SpeedTest'
            )

        [double]$BestPing = -1

        for (
            $Index = 1
            $Index -le $Samples
            $Index++
        ) {
            $Uri =
                Add-SpeedQuery `
                    -Uri $Server.PingUrl `
                    -Query (
                        'cors=true&r={0}' -f
                        [Guid]::NewGuid().ToString()
                    )

            $Request =
                New-Object `
                    System.Net.Http.HttpRequestMessage `
                    -ArgumentList (
                        [System.Net.Http.HttpMethod]::Get,
                        $Uri
                    )

            $Response = $null
            $Timer =
                [System.Diagnostics.Stopwatch]::
                    StartNew()

            try {
                $Response =
                    $Client.
                        SendAsync(
                            $Request,
                            [System.Net.Http.HttpCompletionOption]::
                                ResponseContentRead
                        ).
                        GetAwaiter().
                        GetResult()

                $Timer.Stop()

                # LibreSpeed's selector expects an empty response body.
                $Body =
                    $Response.
                        Content.
                        ReadAsStringAsync().
                        GetAwaiter().
                        GetResult()

                if ($Body.Length -ne 0) {
                    throw 'Selector ping returned a non-empty response.'
                }

                $CurrentPing =
                    $Timer.Elapsed.TotalMilliseconds

                if (
                    $BestPing -lt 0 -or
                    $CurrentPing -lt $BestPing
                ) {
                    $BestPing =
                        $CurrentPing
                }

                Write-Log `
                    -Level 'DEBUG' `
                    -Message (
                        'Server selector ping. Server="{0}" Sample={1}/{2} RTTms={3:N2} BestMs={4:N2}' -f
                        $Server.Name,
                        $Index,
                        $Samples,
                        $CurrentPing,
                        $BestPing
                    )
            }
            catch {
                Write-Log `
                    -Level 'WARN' `
                    -Message (
                        'Server selector ping failed. Server="{0}" Sample={1}/{2} Error="{3}"' -f
                        $Server.Name,
                        $Index,
                        $Samples,
                        $_.Exception.Message
                    )

                # LibreSpeed stops checking this server if selector ping fails.
                break
            }
            finally {
                if ($Timer.IsRunning) {
                    $Timer.Stop()
                }

                if ($Response) {
                    $Response.Dispose()
                }

                if ($Request) {
                    $Request.Dispose()
                }
            }
        }

        return $BestPing
    }
    finally {
        if ($Client) {
            $Client.Dispose()
        }

        if ($Handler) {
            $Handler.Dispose()
        }
    }
}

function Measure-SpeedLatency {
    param(
        [Parameter(Mandatory)]
        [psobject]$Server,

        [ValidateRange(1, 30)]
        [int]$Samples = 10,

        [ValidateRange(500, 30000)]
        [int]$TimeoutMS = 5000
    )

    Add-Type `
        -AssemblyName System.Net.Http `
        -ErrorAction Stop

    $Handler = $null
    $Client = $null

    try {
        $Handler =
            New-Object `
                System.Net.Http.HttpClientHandler

        $Handler.AllowAutoRedirect =
            $true

        $Handler.UseCookies =
            $false

        $Handler.UseProxy =
            $true

        try {
            $DefaultProxy =
                [System.Net.WebRequest]::
                    DefaultWebProxy

            if ($DefaultProxy) {
                $DefaultProxy.Credentials =
                    [System.Net.CredentialCache]::
                        DefaultNetworkCredentials

                $Handler.Proxy =
                    $DefaultProxy
            }
        }
        catch {
            # Preserve default proxy behavior if inspection fails.
        }

        $Client =
            New-Object `
                System.Net.Http.HttpClient `
                -ArgumentList $Handler

        $Client.Timeout =
            [TimeSpan]::FromMilliseconds(
                $TimeoutMS
            )

        [void]$Client.
            DefaultRequestHeaders.
            TryAddWithoutValidation(
                'User-Agent',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell-SpeedTest'
            )

        $MaximumAttempts =
            [Math]::Max(
                ($Samples * 3),
                10
            )

        [int]$SuccessfulPingIndex = 0
        [int]$Attempt = 0

        [double]$Ping = 0
        [double]$Jitter = 0
        [double]$PreviousInstantPing = 0
        [double]$LatestSuccessfulPing = 0

        $MeasuredPings =
            New-Object `
                System.Collections.Generic.List[double]

        while (
            $SuccessfulPingIndex -lt $Samples -and
            $Attempt -lt $MaximumAttempts
        ) {
            $Attempt++

            $PingUri =
                Add-SpeedQuery `
                    -Uri $Server.PingUrl `
                    -Query (
                        'cors=true&r={0}' -f
                        [Guid]::NewGuid().ToString()
                    )

            $Response = $null

            $Timer =
                [System.Diagnostics.Stopwatch]::
                    StartNew()

            try {
                # ResponseHeadersRead is the closest .NET equivalent to
                # LibreSpeed measuring request -> response start.
                $Response =
                    $Client.
                        SendAsync(
                            (
                                New-Object `
                                    System.Net.Http.HttpRequestMessage `
                                    -ArgumentList (
                                        [System.Net.Http.HttpMethod]::Get,
                                        $PingUri
                                    )
                            ),
                            [System.Net.Http.HttpCompletionOption]::
                                ResponseHeadersRead
                        ).
                        GetAwaiter().
                        GetResult()

                # LibreSpeed's ping worker treats receipt of the HTTP
                # response as the pong; it does not reject based on status.
                $Timer.Stop()

                [double]$InstantPing =
                    $Timer.Elapsed.TotalMilliseconds

                $LatestSuccessfulPing =
                    $InstantPing

                if ($SuccessfulPingIndex -eq 0) {
                    # LibreSpeed's first pong establishes the baseline.
                    Write-Log `
                        -Level 'DEBUG' `
                        -Message (
                            'Ping warm-up. Server="{0}" RTTms={1:N2}' -f
                            $Server.Name,
                            $InstantPing
                        )
                }
                else {
                    # Direct translation of speedtest_worker.js.
                    if ($InstantPing -lt 1) {
                        $InstantPing =
                            $PreviousInstantPing
                    }

                    if ($InstantPing -lt 1) {
                        $InstantPing = 1
                    }

                    [double]$InstantJitter =
                        [Math]::Abs(
                            $InstantPing -
                            $PreviousInstantPing
                        )

                    if ($SuccessfulPingIndex -eq 1) {
                        $Ping =
                            $InstantPing
                    }
                    else {
                        if ($InstantPing -lt $Ping) {
                            $Ping =
                                $InstantPing
                        }

                        if ($SuccessfulPingIndex -eq 2) {
                            $Jitter =
                                $InstantJitter
                        }
                        else {
                            if ($InstantJitter -gt $Jitter) {
                                $Jitter =
                                    ($Jitter * 0.3) +
                                    ($InstantJitter * 0.7)
                            }
                            else {
                                $Jitter =
                                    ($Jitter * 0.8) +
                                    ($InstantJitter * 0.2)
                            }
                        }
                    }

                    $PreviousInstantPing =
                        $InstantPing

                    $MeasuredPings.Add(
                        $InstantPing
                    )

                    Write-Log `
                        -Level 'DEBUG' `
                        -Message (
                            'Ping sample. Server="{0}" Sample={1}/{2} RTTms={3:N2} PingMs={4:N2} JitterMs={5:N2}' -f
                            $Server.Name,
                            ($SuccessfulPingIndex + 1),
                            $Samples,
                            $InstantPing,
                            $Ping,
                            $Jitter
                        )
                }

                $SuccessfulPingIndex++
            }
            catch {
                Write-Log `
                    -Level 'WARN' `
                    -Message (
                        'Ping request failed and will be retried. Server="{0}" Attempt={1}/{2} Error="{3}"' -f
                        $Server.Name,
                        $Attempt,
                        $MaximumAttempts,
                        $_.Exception.Message
                    )
            }
            finally {
                if ($Timer.IsRunning) {
                    $Timer.Stop()
                }

                if ($Response) {
                    $Response.Dispose()
                }
            }
        }

        if ($SuccessfulPingIndex -lt $Samples) {
            throw (
                'Only {0} of {1} required LibreSpeed ping requests succeeded after {2} attempts.' -f
                $SuccessfulPingIndex,
                $Samples,
                $Attempt
            )
        }

        # Discovery uses one quick sample only. The full selected-server test
        # below uses LibreSpeed's documented count of 10.
        if ($Samples -eq 1) {
            return [pscustomobject]@{
                Average = $LatestSuccessfulPing
                Ping = $LatestSuccessfulPing
                Jitter = 0
                Samples = 1
            }
        }

        Write-Log `
            -Level 'INFO' `
            -Message (
                'Ping/jitter complete. Method="LibreSpeed worker math over persistent HttpClient" Server="{0}" SuccessfulPings={1} PingMs={2:N2} JitterMs={3:N2} Samples="{4}"' -f
                $Server.Name,
                $Samples,
                $Ping,
                $Jitter,
                (
                    (
                        $MeasuredPings |
                        ForEach-Object {
                            '{0:N2}' -f $_
                        }
                    ) -join ','
                )
            )

        return [pscustomobject]@{
            Average = $Ping
            Ping = $Ping
            Jitter = $Jitter
            Samples = $Samples
        }
    }
    finally {
        if ($Client) {
            $Client.Dispose()
        }

        if ($Handler) {
            $Handler.Dispose()
        }
    }
}


function Test-SpeedUpload {
    param(
        [Parameter(Mandatory)]
        [psobject]$Server,

        [Parameter(Mandatory)]
        [byte[]]$Payload,

        [ValidateRange(1000, 60000)]
        [int]$TimeoutMS = 15000
    )

    $UploadUri = Add-SpeedQuery `
        -Uri $Server.UploadUrl `
        -Query (
            'r={0}' -f
            [Guid]::NewGuid().ToString()
        )

    $Request = New-SpeedRequest `
        -Uri $UploadUri `
        -Method POST

    $Request.ContentType = 'application/octet-stream'
    $Request.ContentLength = $Payload.Length
    $Request.AllowWriteStreamBuffering = $false
    $Request.SendChunked = $false
    $Request.Timeout = $TimeoutMS
    $Request.ReadWriteTimeout = $TimeoutMS

    $RequestStream = $null
    $Response = $null

    try {
        $RequestStream = $Request.GetRequestStream()

        $RequestStream.Write(
            $Payload,
            0,
            $Payload.Length
        )

        $RequestStream.Dispose()
        $RequestStream = $null

        $Response = $Request.GetResponse()
    }
    finally {
        if ($RequestStream) {
            $RequestStream.Dispose()
        }

        if ($Response) {
            $Response.Dispose()
        }
    }
}


function Get-MaxAcceptedUploadPayloadKB {
    param(
        [Parameter(Mandatory)]
        [psobject]$Server,

        [Parameter(Mandatory)]
        [int[]]$CandidatePayloadKB
    )

    $AcceptedPayloadKB = $null

    foreach (
        $CurrentPayloadKB in
        ($CandidatePayloadKB | Sort-Object)
    ) {
        if ($CurrentPayloadKB -lt 1) {
            continue
        }

        [int]$CurrentPayloadBytes =
            $CurrentPayloadKB * 1KB

        $Payload =
            New-Object byte[] $CurrentPayloadBytes

        $Random =
            New-Object `
                System.Security.Cryptography.RNGCryptoServiceProvider

        try {
            $Random.GetBytes($Payload)
        }
        finally {
            $Random.Dispose()
        }

        try {
            Test-SpeedUpload `
                -Server $Server `
                -Payload $Payload `
                -TimeoutMS 30000

            $AcceptedPayloadKB = $CurrentPayloadKB

            Write-Host (
                '  {0,4:N0} MB accepted' -f
                ($CurrentPayloadKB / 1024)
            )
        }
        catch {
            Write-Host (
                '  {0,4:N0} MB rejected' -f
                ($CurrentPayloadKB / 1024)
            )

            break
        }
    }

    if ($null -eq $AcceptedPayloadKB) {
        throw (
            'The selected LibreSpeed server rejected every configured upload payload size.'
        )
    }

    return [int]$AcceptedPayloadKB
}

function Invoke-DurationBasedDownloadTest {
    param(
        [Parameter(Mandatory)]
        [psobject]$Server,

        [ValidateRange(1, 10)]
        [int]$StreamCount = 5,

        [ValidateRange(0, 2000)]
        [int]$StreamDelayMS = 300,

        [ValidateRange(0, 30)]
        [double]$GraceSeconds = 1.5,

        [ValidateRange(5, 60)]
        [int]$TestSeconds = 15,

        [ValidateRange(1, 1000)]
        [int]$RequestSizeMB = 100,

        [ValidateRange(1.0, 1.5)]
        [double]$OverheadFactor = 1.06,

        [bool]$TimeAuto = $true
    )

    Write-Log `
        -Level 'INFO' `
        -Message (
            'Download test start. BrowserMethod=True Server="{0}" Streams={1} StreamDelayMS={2} GraceSeconds={3} MaxSeconds={4} TimeAuto={5} RequestSizeMB={6} OverheadFactor={7}' -f
            $Server.Name,
            $StreamCount,
            $StreamDelayMS,
            $GraceSeconds,
            $TestSeconds,
            $TimeAuto,
            $RequestSizeMB,
            $OverheadFactor
        )

    $SharedState =
        [hashtable]::Synchronized(@{})

    $SharedState['Stop'] =
        $false

    $StartGate = New-Object `
        System.Threading.ManualResetEventSlim `
        -ArgumentList $false

    $RunspacePool =
        [System.Management.Automation.Runspaces.RunspaceFactory]::
            CreateRunspacePool(
                1,
                $StreamCount
            )

    $RunspacePool.Open()

    $Workers = @()

    for (
        $StreamIndex = 1
        $StreamIndex -le $StreamCount
        $StreamIndex++
    ) {
        $SharedState["Bytes_$StreamIndex"] =
            [long]0

        $SharedState["Ready_$StreamIndex"] =
            $false

        $SharedState["Done_$StreamIndex"] =
            $false

        $SharedState["Errors_$StreamIndex"] =
            0

        $SharedState["LastError_$StreamIndex"] =
            $null

        $SharedState["Requests_$StreamIndex"] =
            0
    }

    $WorkerScript = {
        param(
            [string]$DownloadUrl,
            [int]$StreamId,
            [int]$StreamDelayMS,
            [int]$RequestSizeMB,
            [hashtable]$State,
            [System.Threading.ManualResetEventSlim]$Gate
        )

        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'

        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12

        [Net.ServicePointManager]::Expect100Continue =
            $false

        [Net.ServicePointManager]::DefaultConnectionLimit =
            32

        function New-DownloadConnection {
            param(
                [string]$BaseUrl,
                [int]$SizeMB,
                [int]$CurrentStream
            )

            $Separator = '?'

            if ($BaseUrl.Contains('?')) {
                $Separator = '&'
            }

            $Uri = (
                '{0}{1}cors=true&r={2}&ckSize={3}&stream={4}' -f
                $BaseUrl,
                $Separator,
                [Guid]::NewGuid().ToString(),
                $SizeMB,
                $CurrentStream
            )

            $Request =
                [System.Net.HttpWebRequest]::Create(
                    $Uri
                )

            $Request.Method = 'GET'

            $Request.UserAgent =
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell-SpeedTest'

            $Request.Timeout = 30000
            $Request.ReadWriteTimeout = 10000
            $Request.KeepAlive = $true

            $Request.AutomaticDecompression =
                [System.Net.DecompressionMethods]::None

            $Request.CachePolicy = New-Object `
                System.Net.Cache.RequestCachePolicy `
                -ArgumentList (
                    [System.Net.Cache.RequestCacheLevel]::NoCacheNoStore
                )

            if ($Request.Proxy) {
                $Request.Proxy.Credentials =
                    [System.Net.CredentialCache]::
                        DefaultCredentials
            }

            $Response =
                $Request.GetResponse()

            $Stream =
                $Response.GetResponseStream()

            return [pscustomobject]@{
                Request = $Request
                Response = $Response
                Stream = $Stream
            }
        }

        $Connection = $null
        $Buffer =
            New-Object byte[] (1MB)

        try {
            $State["Ready_$StreamId"] =
                $true

            $Gate.Wait()

            $ThisStreamDelayMS =
                ($StreamId - 1) *
                $StreamDelayMS

            if ($ThisStreamDelayMS -gt 0) {
                Start-Sleep `
                    -Milliseconds $ThisStreamDelayMS
            }

            while (-not $State['Stop']) {
                if ($null -eq $Connection) {
                    try {
                        $State["Requests_$StreamId"] =
                            [int]$State[
                                "Requests_$StreamId"
                            ] +
                            1

                        $Connection =
                            New-DownloadConnection `
                                -BaseUrl $DownloadUrl `
                                -SizeMB $RequestSizeMB `
                                -CurrentStream $StreamId
                    }
                    catch {
                        $State["Errors_$StreamId"] =
                            [int]$State[
                                "Errors_$StreamId"
                            ] +
                            1

                        $State["LastError_$StreamId"] =
                            $_.Exception.Message

                        if (-not $State['Stop']) {
                            Start-Sleep `
                                -Milliseconds 100
                        }

                        continue
                    }
                }

                if ($State['Stop']) {
                    break
                }

                try {
                    [int]$BytesRead =
                        $Connection.Stream.Read(
                            $Buffer,
                            0,
                            $Buffer.Length
                        )
                }
                catch {
                    $State["Errors_$StreamId"] =
                        [int]$State[
                            "Errors_$StreamId"
                        ] +
                        1

                    $State["LastError_$StreamId"] =
                        $_.Exception.Message

                    try {
                        $Connection.Stream.Dispose()
                    }
                    catch {
                    }

                    try {
                        $Connection.Response.Dispose()
                    }
                    catch {
                    }

                    try {
                        $Connection.Request.Abort()
                    }
                    catch {
                    }

                    $Connection = $null
                    continue
                }

                if ($BytesRead -gt 0) {
                    $State["Bytes_$StreamId"] =
                        [long]$State[
                            "Bytes_$StreamId"
                        ] +
                        $BytesRead

                    continue
                }

                # Payload completed. Immediately recycle this worker onto
                # another request while the shared test remains active.
                try {
                    $Connection.Stream.Dispose()
                }
                catch {
                }

                try {
                    $Connection.Response.Dispose()
                }
                catch {
                }

                try {
                    $Connection.Request.Abort()
                }
                catch {
                }

                $Connection = $null
            }
        }
        catch {
            $State["Errors_$StreamId"] =
                [int]$State[
                    "Errors_$StreamId"
                ] +
                1

            $State["LastError_$StreamId"] =
                $_.Exception.Message
        }
        finally {
            if ($Connection) {
                try {
                    $Connection.Stream.Dispose()
                }
                catch {
                }

                try {
                    $Connection.Response.Dispose()
                }
                catch {
                }

                try {
                    $Connection.Request.Abort()
                }
                catch {
                }
            }

            $State["Done_$StreamId"] =
                $true
        }
    }

    try {
        for (
            $StreamIndex = 1
            $StreamIndex -le $StreamCount
            $StreamIndex++
        ) {
            $PowerShell =
                [PowerShell]::Create()

            $PowerShell.RunspacePool =
                $RunspacePool

            [void]$PowerShell.AddScript(
                $WorkerScript
            )

            [void]$PowerShell.AddArgument(
                $Server.DownloadUrl
            )

            [void]$PowerShell.AddArgument(
                $StreamIndex
            )

            [void]$PowerShell.AddArgument(
                $StreamDelayMS
            )

            [void]$PowerShell.AddArgument(
                $RequestSizeMB
            )

            [void]$PowerShell.AddArgument(
                $SharedState
            )

            [void]$PowerShell.AddArgument(
                $StartGate
            )

            $Handle =
                $PowerShell.BeginInvoke()

            $Workers +=
                [pscustomobject]@{
                    StreamId =
                        $StreamIndex

                    PowerShell =
                        $PowerShell

                    Handle =
                        $Handle
                }
        }

        $PreparationTimer =
            [System.Diagnostics.Stopwatch]::
                StartNew()

        while (
            $PreparationTimer.
                Elapsed.
                TotalSeconds -lt 15
        ) {
            $ReadyCount = 0

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                if (
                    $SharedState[
                        "Ready_$StreamIndex"
                    ]
                ) {
                    $ReadyCount++
                }
            }

            Write-LiveLine (
                'Preparing download streams: {0}/{1}' -f
                $ReadyCount,
                $StreamCount
            )

            if (
                $ReadyCount -ge
                $StreamCount
            ) {
                break
            }

            Start-Sleep `
                -Milliseconds 100
        }

        $PreparationTimer.Stop()

        $ReadyCount = 0

        for (
            $StreamIndex = 1
            $StreamIndex -le $StreamCount
            $StreamIndex++
        ) {
            if (
                $SharedState[
                    "Ready_$StreamIndex"
                ]
            ) {
                $ReadyCount++
            }
        }

        if ($ReadyCount -lt $StreamCount) {
            throw (
                'Only {0} of {1} download streams initialized.' -f
                $ReadyCount,
                $StreamCount
            )
        }

        # Release all workers. They then stagger themselves by stream index.
        $StartGate.Set()

        # Warm-up period. Data transferred here intentionally does not count
        # toward the displayed download result.
        $GraceTimer =
            [System.Diagnostics.Stopwatch]::
                StartNew()

        $LastGraceLogSecond =
            -1

        while (
            $GraceTimer.
                Elapsed.
                TotalSeconds -lt
            $GraceSeconds
        ) {
            [long]$GraceCurrentBytes = 0

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                $GraceCurrentBytes +=
                    [long]$SharedState[
                        "Bytes_$StreamIndex"
                    ]
            }

            $GraceWholeSecond =
                [Math]::Floor(
                    $GraceTimer.
                        Elapsed.
                        TotalSeconds
                )

            if (
                $GraceWholeSecond -gt
                $LastGraceLogSecond
            ) {
                $LastGraceLogSecond =
                    $GraceWholeSecond

                Write-Log `
                    -Level 'DEBUG' `
                    -Message (
                        'Download grace. Elapsed={0:N2}s TotalMB={1:N1}' -f
                        $GraceTimer.Elapsed.TotalSeconds,
                        ($GraceCurrentBytes / 1MB)
                    )
            }

            Write-LiveLine (
                'Download warm-up: {0:N1}/{1:N1} sec  Received: {2:N1} MB' -f
                $GraceTimer.Elapsed.TotalSeconds,
                $GraceSeconds,
                ($GraceCurrentBytes / 1MB)
            )

            Start-Sleep `
                -Milliseconds 100
        }

        $GraceTimer.Stop()

        [long]$GraceBytes = 0

        for (
            $StreamIndex = 1
            $StreamIndex -le $StreamCount
            $StreamIndex++
        ) {
            $GraceBytes +=
                [long]$SharedState[
                    "Bytes_$StreamIndex"
                ]
        }

        Write-Log `
            -Level 'INFO' `
            -Message (
                'Download grace complete. GraceSeconds={0} DiscardedMB={1:N1}' -f
                $GraceSeconds,
                ($GraceBytes / 1MB)
            )

        $DownloadTimer =
            [System.Diagnostics.Stopwatch]::
                StartNew()

        [double]$LastDownloadLogSecond =
            -1

        [double]$DownloadBonusMS = 0

        while ($true) {
            [long]$CurrentTotalBytes = 0
            [int]$ActiveStreams = 0

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                $CurrentTotalBytes +=
                    [long]$SharedState[
                        "Bytes_$StreamIndex"
                    ]

                if (
                    -not $SharedState[
                        "Done_$StreamIndex"
                    ]
                ) {
                    $ActiveStreams++
                }
            }

            [long]$CurrentMeasuredBytes =
                [Math]::Max(
                    0,
                    ($CurrentTotalBytes - $GraceBytes)
                )

            $CurrentElapsed =
                [Math]::Max(
                    $DownloadTimer.
                        Elapsed.
                        TotalSeconds,
                    0.001
                )

            $CurrentSpeedBytesPerSecond =
                $CurrentMeasuredBytes /
                $CurrentElapsed

            $CurrentMbps = (
                (
                    $CurrentSpeedBytesPerSecond * 8
                ) /
                1000000
            ) * $OverheadFactor

            # Direct translation of LibreSpeed time_auto:
            # bonus = (5 * bytes/sec) / 100000, capped at 400 ms
            # every 200 ms status tick.
            if ($TimeAuto) {
                $CurrentBonusMS =
                    (5.0 * $CurrentSpeedBytesPerSecond) /
                    100000

                if ($CurrentBonusMS -gt 400) {
                    $CurrentBonusMS = 400
                }

                $DownloadBonusMS +=
                    $CurrentBonusMS
            }

            Write-LiveLine (
                'Download: {0,8:N1} Mbps  Measured: {1,7:N1} MB  Streams: {2}/{3}' -f
                $CurrentMbps,
                ($CurrentMeasuredBytes / 1MB),
                $ActiveStreams,
                $StreamCount
            )

            $CurrentWholeSecond =
                [Math]::Floor(
                    $CurrentElapsed
                )

            if (
                $CurrentWholeSecond -gt
                $LastDownloadLogSecond
            ) {
                $LastDownloadLogSecond =
                    $CurrentWholeSecond

                $StreamDetails = @()

                for (
                    $DiagnosticStreamIndex = 1
                    $DiagnosticStreamIndex -le $StreamCount
                    $DiagnosticStreamIndex++
                ) {
                    $StreamDetails += (
                        'S{0}[Bytes={1:N1}MB Req={2} Err={3}]' -f
                        $DiagnosticStreamIndex,
                        (
                            [long]$SharedState[
                                "Bytes_$DiagnosticStreamIndex"
                            ] / 1MB
                        ),
                        [int]$SharedState[
                            "Requests_$DiagnosticStreamIndex"
                        ],
                        [int]$SharedState[
                            "Errors_$DiagnosticStreamIndex"
                        ]
                    )
                }

                Write-Log `
                    -Level 'DEBUG' `
                    -Message (
                        'Download measured progress. Elapsed={0:N2}s Mbps={1:N1} MeasuredMB={2:N1} GraceDiscardedMB={3:N1} ActiveStreams={4}/{5} {6}' -f
                        $CurrentElapsed,
                        $CurrentMbps,
                        ($CurrentMeasuredBytes / 1MB),
                        ($GraceBytes / 1MB),
                        $ActiveStreams,
                        $StreamCount,
                        ($StreamDetails -join ' ')
                    )
            }

            $EffectiveDownloadSeconds =
                $CurrentElapsed +
                ($DownloadBonusMS / 1000)

            if (
                $EffectiveDownloadSeconds -gt
                $TestSeconds
            ) {
                break
            }

            Start-Sleep `
                -Milliseconds 200
        }

        $DownloadTimer.Stop()

        $DownloadMeasuredSeconds =
            [Math]::Max(
                $DownloadTimer.Elapsed.TotalSeconds,
                0.001
            )

        $SharedState['Stop'] =
            $true

        [long]$FinalTotalBytes = 0

        for (
            $StreamIndex = 1
            $StreamIndex -le $StreamCount
            $StreamIndex++
        ) {
            $FinalTotalBytes +=
                [long]$SharedState[
                    "Bytes_$StreamIndex"
                ]
        }

        [long]$MeasuredDownloadedBytes =
            [Math]::Max(
                0,
                ($FinalTotalBytes - $GraceBytes)
            )

        $WorkerExitTimer =
            [System.Diagnostics.Stopwatch]::
                StartNew()

        while (
            $WorkerExitTimer.
                Elapsed.
                TotalSeconds -lt 5
        ) {
            $DoneCount = 0

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                if (
                    $SharedState[
                        "Done_$StreamIndex"
                    ]
                ) {
                    $DoneCount++
                }
            }

            if (
                $DoneCount -ge
                $StreamCount
            ) {
                break
            }

            Start-Sleep `
                -Milliseconds 100
        }

        $WorkerExitTimer.Stop()

        foreach ($Worker in $Workers) {
            try {
                if (
                    $Worker.
                        Handle.
                        IsCompleted
                ) {
                    [void]$Worker.
                        PowerShell.
                        EndInvoke(
                            $Worker.Handle
                        )
                }
                else {
                    $Worker.
                        PowerShell.
                        Stop()
                }
            }
            catch {
                # Worker-level errors are captured in shared state.
            }
        }

        $WorkerErrors = @()

        for (
            $DiagnosticStreamIndex = 1
            $DiagnosticStreamIndex -le $StreamCount
            $DiagnosticStreamIndex++
        ) {
            if (
                [int]$SharedState[
                    "Errors_$DiagnosticStreamIndex"
                ] -gt 0 -and
                $SharedState[
                    "LastError_$DiagnosticStreamIndex"
                ]
            ) {
                $WorkerErrors += (
                    'Stream {0}: {1}' -f
                    $DiagnosticStreamIndex,
                    $SharedState[
                        "LastError_$DiagnosticStreamIndex"
                    ]
                )
            }
        }

        if ($MeasuredDownloadedBytes -le 0) {
            if ($WorkerErrors.Count -gt 0) {
                throw (
                    'Parallel download measured no data. {0}' -f
                    ($WorkerErrors -join ' | ')
                )
            }

            throw (
                'Parallel download measured no data.'
            )
        }

        $DownloadMbps = (
            (
                ($MeasuredDownloadedBytes * 8) /
                $DownloadMeasuredSeconds
            ) /
            1000000
        ) * $OverheadFactor

        Write-Log `
            -Level 'INFO' `
            -Message (
                'Download test complete. BrowserMethod=True Mbps={0:N1} MeasuredMB={1:N1} TotalMB={2:N1} GraceDiscardedMB={3:N1} Streams={4} StreamDelayMS={5} GraceSeconds={6} ActualMeasuredSeconds={7:N2} MaxSeconds={8} TimeAuto={9} BonusMS={10:N0} RequestSizeMB={11} OverheadFactor={12}' -f
                $DownloadMbps,
                ($MeasuredDownloadedBytes / 1MB),
                ($FinalTotalBytes / 1MB),
                ($GraceBytes / 1MB),
                $StreamCount,
                $StreamDelayMS,
                $GraceSeconds,
                $DownloadMeasuredSeconds,
                $TestSeconds,
                $TimeAuto,
                $DownloadBonusMS,
                $RequestSizeMB,
                $OverheadFactor
            )

        return [pscustomobject]@{
            Mbps =
                $DownloadMbps

            Bytes =
                $MeasuredDownloadedBytes

            TotalBytes =
                $FinalTotalBytes

            GraceBytes =
                $GraceBytes

            Seconds =
                $DownloadMeasuredSeconds

            MaxSeconds =
                $TestSeconds

            TimeAuto =
                $TimeAuto

            BonusMS =
                $DownloadBonusMS

            GraceSeconds =
                $GraceSeconds

            Streams =
                $StreamCount

            StreamDelayMS =
                $StreamDelayMS

            RequestSizeMB =
                $RequestSizeMB

            OverheadFactor =
                $OverheadFactor

            WorkerErrors =
                $WorkerErrors
        }
    }
    finally {
        $SharedState['Stop'] =
            $true

        foreach ($Worker in $Workers) {
            if ($Worker.PowerShell) {
                try {
                    $Worker.
                        PowerShell.
                        Dispose()
                }
                catch {
                }
            }
        }

        if ($RunspacePool) {
            try {
                $RunspacePool.Close()
            }
            catch {
            }

            try {
                $RunspacePool.Dispose()
            }
            catch {
            }
        }

        if ($StartGate) {
            $StartGate.Dispose()
        }
    }
}


function Invoke-DurationBasedUploadTest {
    param(
        [Parameter(Mandatory)]
        [psobject]$Server,

        [ValidateRange(1, 8)]
        [int]$StreamCount = 3,

        [ValidateRange(0, 2000)]
        [int]$StreamDelayMS = 300,

        [ValidateRange(0, 30)]
        [int]$GraceSeconds = 3,

        [ValidateRange(5, 60)]
        [int]$TestSeconds = 15,

        [ValidateRange(64, 32768)]
        [int]$PayloadKB = 20480,

        [ValidateRange(64, 4096)]
        [int]$WriteBufferKB = 1024,

        [ValidateRange(1.0, 1.5)]
        [double]$OverheadFactor = 1.06,

        [bool]$TimeAuto = $true
    )

    Write-Log `
        -Level 'INFO' `
        -Message (
            'Upload test start. Transport=HttpClient BrowserMethod=True Server="{0}" Streams={1} StreamDelayMS={2} GraceSeconds={3} MaxSeconds={4} TimeAuto={5} PayloadKB={6} WriteBufferKB={7} OverheadFactor={8}' -f
            $Server.Name,
            $StreamCount,
            $StreamDelayMS,
            $GraceSeconds,
            $TestSeconds,
            $TimeAuto,
            $PayloadKB,
            $WriteBufferKB,
            $OverheadFactor
        )

    # LibreSpeed MPOT performs one empty POST before the upload test so
    # cross-origin response headers are established. The worker proceeds
    # whether this preflight succeeds or fails.
    try {
        Add-Type `
            -AssemblyName System.Net.Http `
            -ErrorAction Stop

        $PreflightClient =
            New-Object System.Net.Http.HttpClient

        $PreflightContent =
            New-Object System.Net.Http.ByteArrayContent `
                -ArgumentList (
                    [byte[]]@()
                )

        try {
            $PreflightResponse =
                $PreflightClient.
                    PostAsync(
                        $Server.UploadUrl,
                        $PreflightContent
                    ).
                    GetAwaiter().
                    GetResult()

            Write-Log `
                -Level 'DEBUG' `
                -Message (
                    'MPOT upload preflight complete. Server="{0}" Status={1}' -f
                    $Server.Name,
                    [int]$PreflightResponse.StatusCode
                )

            $PreflightResponse.Dispose()
        }
        finally {
            $PreflightContent.Dispose()
            $PreflightClient.Dispose()
        }
    }
    catch {
        Write-Log `
            -Level 'DEBUG' `
            -Message (
                'MPOT upload preflight returned error; continuing like LibreSpeed worker. Server="{0}" Error="{1}"' -f
                $Server.Name,
                $_.Exception.Message
            )
    }

    $SharedState =
        [hashtable]::Synchronized(@{})

    $SharedState['Stop'] = $false

    $StartGate = New-Object `
        System.Threading.ManualResetEventSlim `
        -ArgumentList $false

    $RunspacePool =
        [System.Management.Automation.Runspaces.RunspaceFactory]::
            CreateRunspacePool(
                1,
                $StreamCount
            )

    $RunspacePool.Open()

    $Workers = @()

    for (
        $StreamIndex = 1
        $StreamIndex -le $StreamCount
        $StreamIndex++
    ) {
        $SharedState["Bytes_$StreamIndex"] =
            [long]0

        $SharedState["Ready_$StreamIndex"] =
            $false

        $SharedState["Done_$StreamIndex"] =
            $false

        $SharedState["Errors_$StreamIndex"] =
            0

        $SharedState["LastError_$StreamIndex"] =
            $null

        $SharedState["Requests_$StreamIndex"] =
            0

        $SharedState["Responses_$StreamIndex"] =
            0
    }

    $WorkerScript = {
        param(
            [string]$UploadUrl,
            [int]$StreamId,
            [int]$StreamDelayMS,
            [int]$PayloadKB,
            [int]$WriteBufferKB,
            [hashtable]$State,
            [System.Threading.ManualResetEventSlim]$Gate
        )

        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'

        Add-Type `
            -AssemblyName System.Net.Http `
            -ErrorAction Stop

        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12

        [Net.ServicePointManager]::Expect100Continue =
            $false

        [Net.ServicePointManager]::DefaultConnectionLimit =
            32

        [int]$PayloadBytes =
            $PayloadKB * 1KB

        [int]$WriteBufferBytes =
            [Math]::Min(
                ($WriteBufferKB * 1KB),
                $PayloadBytes
            )

        $Payload =
            New-Object byte[] $PayloadBytes

        $Random =
            New-Object `
                System.Security.Cryptography.RNGCryptoServiceProvider

        try {
            $Random.GetBytes($Payload)
        }
        finally {
            $Random.Dispose()
        }

        $Handler = $null
        $Client = $null

        try {
            $Handler =
                New-Object `
                    System.Net.Http.HttpClientHandler

            $Handler.AllowAutoRedirect = $true
            $Handler.UseCookies = $false
            $Handler.UseProxy = $true

            try {
                $DefaultProxy =
                    [System.Net.WebRequest]::DefaultWebProxy

                if ($DefaultProxy) {
                    $DefaultProxy.Credentials =
                        [System.Net.CredentialCache]::
                            DefaultNetworkCredentials

                    $Handler.Proxy =
                        $DefaultProxy
                }
            }
            catch {
                # Continue with default handler proxy behavior.
            }

            $Client =
                New-Object `
                    System.Net.Http.HttpClient `
                    -ArgumentList $Handler

            $Client.Timeout =
                [TimeSpan]::FromSeconds(60)

            [void]$Client.DefaultRequestHeaders.
                TryAddWithoutValidation(
                    'User-Agent',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell-SpeedTest'
                )

            $Client.DefaultRequestHeaders.ExpectContinue =
                $false

            $State["Ready_$StreamId"] =
                $true

            $Gate.Wait()

            # LibreSpeed starts upload streams with a 300 ms stagger:
            # stream 1 = 0 ms, stream 2 = 300 ms, stream 3 = 600 ms.
            $ThisStreamDelayMS =
                ($StreamId - 1) * $StreamDelayMS

            if ($ThisStreamDelayMS -gt 0) {
                Start-Sleep `
                    -Milliseconds $ThisStreamDelayMS
            }

            while (-not $State['Stop']) {
                $Separator = '?'

                if ($UploadUrl.Contains('?')) {
                    $Separator = '&'
                }

                $Uri = (
                    '{0}{1}cors=true&r={2}&stream={3}' -f
                    $UploadUrl,
                    $Separator,
                    [Guid]::NewGuid().ToString(),
                    $StreamId
                )

                $PayloadStream = $null
                $Content = $null
                $Request = $null
                $Response = $null
                $SendTask = $null

                try {
                    $PayloadStream =
                        New-Object `
                            System.IO.MemoryStream `
                            -ArgumentList (
                                $Payload,
                                $false
                            )

                    $Content =
                        New-Object `
                            System.Net.Http.StreamContent `
                            -ArgumentList (
                                $PayloadStream,
                                $WriteBufferBytes
                            )

                    # LibreSpeed's browser uploader explicitly requests
                    # identity content encoding. Do not add a Content-Type
                    # header here; a default Blob has no explicit type.
                    $Content.Headers.ContentEncoding.Add(
                        'identity'
                    )

                    $Request =
                        New-Object `
                            System.Net.Http.HttpRequestMessage `
                            -ArgumentList (
                                [System.Net.Http.HttpMethod]::Post,
                                $Uri
                            )

                    $Request.Content =
                        $Content

                    $State["Requests_$StreamId"] =
                        [int]$State[
                            "Requests_$StreamId"
                        ] +
                        1

                    $SendTask =
                        $Client.SendAsync(
                            $Request,
                            [System.Net.Http.HttpCompletionOption]::
                                ResponseHeadersRead
                        )

                    [long]$LastPosition = 0

                    while (-not $SendTask.IsCompleted) {
                        [long]$CurrentPosition =
                            $PayloadStream.Position

                        if (
                            $CurrentPosition -gt
                            $LastPosition
                        ) {
                            [long]$Delta =
                                $CurrentPosition -
                                $LastPosition

                            $State["Bytes_$StreamId"] =
                                [long]$State[
                                    "Bytes_$StreamId"
                                ] +
                                $Delta

                            $LastPosition =
                                $CurrentPosition
                        }

                        if ($State['Stop']) {
                            try {
                                $Client.CancelPendingRequests()
                            }
                            catch {
                            }

                            break
                        }

                        Start-Sleep `
                            -Milliseconds 5
                    }

                    [long]$FinalPosition =
                        $PayloadStream.Position

                    if (
                        $FinalPosition -gt
                        $LastPosition
                    ) {
                        [long]$FinalDelta =
                            $FinalPosition -
                            $LastPosition

                        $State["Bytes_$StreamId"] =
                            [long]$State[
                                "Bytes_$StreamId"
                            ] +
                            $FinalDelta
                    }

                    if ($State['Stop']) {
                        break
                    }

                    $Response =
                        $SendTask.
                            GetAwaiter().
                            GetResult()

                    [void]$Response.
                        EnsureSuccessStatusCode()

                    $State["Responses_$StreamId"] =
                        [int]$State[
                            "Responses_$StreamId"
                        ] +
                        1
                }
                catch {
                    if (-not $State['Stop']) {
                        $State["Errors_$StreamId"] =
                            [int]$State[
                                "Errors_$StreamId"
                            ] +
                            1

                        $State["LastError_$StreamId"] =
                            $_.Exception.Message

                        Start-Sleep `
                            -Milliseconds 50
                    }
                }
                finally {
                    if ($Response) {
                        try {
                            $Response.Dispose()
                        }
                        catch {
                        }
                    }

                    if ($Request) {
                        try {
                            $Request.Dispose()
                        }
                        catch {
                        }
                    }

                    if ($Content) {
                        try {
                            $Content.Dispose()
                        }
                        catch {
                        }
                    }

                    if ($PayloadStream) {
                        try {
                            $PayloadStream.Dispose()
                        }
                        catch {
                        }
                    }
                }
            }
        }
        catch {
            $State["Errors_$StreamId"] =
                [int]$State[
                    "Errors_$StreamId"
                ] +
                1

            $State["LastError_$StreamId"] =
                $_.Exception.Message
        }
        finally {
            if ($Client) {
                try {
                    $Client.CancelPendingRequests()
                }
                catch {
                }

                try {
                    $Client.Dispose()
                }
                catch {
                }
            }

            if ($Handler) {
                try {
                    $Handler.Dispose()
                }
                catch {
                }
            }

            $State["Done_$StreamId"] =
                $true
        }
    }

    try {
        for (
            $StreamIndex = 1
            $StreamIndex -le $StreamCount
            $StreamIndex++
        ) {
            $PowerShell =
                [PowerShell]::Create()

            $PowerShell.RunspacePool =
                $RunspacePool

            [void]$PowerShell.AddScript(
                $WorkerScript
            )

            [void]$PowerShell.AddArgument(
                $Server.UploadUrl
            )

            [void]$PowerShell.AddArgument(
                $StreamIndex
            )

            [void]$PowerShell.AddArgument(
                $StreamDelayMS
            )

            [void]$PowerShell.AddArgument(
                $PayloadKB
            )

            [void]$PowerShell.AddArgument(
                $WriteBufferKB
            )

            [void]$PowerShell.AddArgument(
                $SharedState
            )

            [void]$PowerShell.AddArgument(
                $StartGate
            )

            $Handle =
                $PowerShell.BeginInvoke()

            $Workers +=
                [pscustomobject]@{
                    StreamId =
                        $StreamIndex

                    PowerShell =
                        $PowerShell

                    Handle =
                        $Handle
                }
        }

        $PreparationTimer =
            [System.Diagnostics.Stopwatch]::
                StartNew()

        while (
            $PreparationTimer.
                Elapsed.
                TotalSeconds -lt 15
        ) {
            $ReadyCount = 0

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                if (
                    $SharedState[
                        "Ready_$StreamIndex"
                    ]
                ) {
                    $ReadyCount++
                }
            }

            Write-LiveLine (
                'Preparing upload streams: {0}/{1}' -f
                $ReadyCount,
                $StreamCount
            )

            if (
                $ReadyCount -ge
                $StreamCount
            ) {
                break
            }

            Start-Sleep `
                -Milliseconds 100
        }

        $PreparationTimer.Stop()

        $ReadyCount = 0

        for (
            $StreamIndex = 1
            $StreamIndex -le $StreamCount
            $StreamIndex++
        ) {
            if (
                $SharedState[
                    "Ready_$StreamIndex"
                ]
            ) {
                $ReadyCount++
            }
        }

        if ($ReadyCount -lt $StreamCount) {
            $PreparationErrors = @()

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                if (
                    $SharedState[
                        "LastError_$StreamIndex"
                    ]
                ) {
                    $PreparationErrors += (
                        'Stream {0}: {1}' -f
                        $StreamIndex,
                        $SharedState[
                            "LastError_$StreamIndex"
                        ]
                    )
                }
            }

            if ($PreparationErrors.Count -gt 0) {
                throw (
                    'Only {0} of {1} HttpClient upload streams initialized. {2}' -f
                    $ReadyCount,
                    $StreamCount,
                    ($PreparationErrors -join ' | ')
                )
            }

            throw (
                'Only {0} of {1} HttpClient upload streams initialized.' -f
                $ReadyCount,
                $StreamCount
            )
        }

        # Release workers. Each worker then applies its own 300 ms stagger.
        $StartGate.Set()

        # LibreSpeed browser methodology uses a grace period, then resets
        # both the timer and byte counter before actual measurement.
        $GraceTimer =
            [System.Diagnostics.Stopwatch]::
                StartNew()

        $LastGraceLogSecond = -1

        while (
            $GraceTimer.
                Elapsed.
                TotalSeconds -lt
            $GraceSeconds
        ) {
            [long]$GraceCurrentBytes = 0

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                $GraceCurrentBytes +=
                    [long]$SharedState[
                        "Bytes_$StreamIndex"
                    ]
            }

            $GraceWholeSecond =
                [Math]::Floor(
                    $GraceTimer.
                        Elapsed.
                        TotalSeconds
                )

            if (
                $GraceWholeSecond -gt
                $LastGraceLogSecond
            ) {
                $LastGraceLogSecond =
                    $GraceWholeSecond

                Write-Log `
                    -Level 'DEBUG' `
                    -Message (
                        'Upload grace. Elapsed={0:N2}s TotalMB={1:N1}' -f
                        $GraceTimer.Elapsed.TotalSeconds,
                        ($GraceCurrentBytes / 1MB)
                    )
            }

            Write-LiveLine (
                'Upload warm-up: {0:N1}/{1:N1} sec  Sent: {2:N1} MB' -f
                $GraceTimer.Elapsed.TotalSeconds,
                $GraceSeconds,
                ($GraceCurrentBytes / 1MB)
            )

            Start-Sleep `
                -Milliseconds 100
        }

        $GraceTimer.Stop()

        # Snapshot bytes already sent and exclude them from measurement.
        [long]$GraceBytes = 0

        for (
            $StreamIndex = 1
            $StreamIndex -le $StreamCount
            $StreamIndex++
        ) {
            $GraceBytes +=
                [long]$SharedState[
                    "Bytes_$StreamIndex"
                ]
        }

        Write-Log `
            -Level 'INFO' `
            -Message (
                'Upload grace complete. GraceSeconds={0} DiscardedMB={1:N1}' -f
                $GraceSeconds,
                ($GraceBytes / 1MB)
            )

        $UploadTimer =
            [System.Diagnostics.Stopwatch]::
                StartNew()

        [double]$LastUploadLogSecond = -1

        [double]$UploadBonusMS = 0

        while ($true) {
            [long]$CurrentTotalBytes = 0
            [int]$ActiveStreams = 0

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                $CurrentTotalBytes +=
                    [long]$SharedState[
                        "Bytes_$StreamIndex"
                    ]

                if (
                    -not $SharedState[
                        "Done_$StreamIndex"
                    ]
                ) {
                    $ActiveStreams++
                }
            }

            [long]$CurrentMeasuredBytes =
                [Math]::Max(
                    0,
                    ($CurrentTotalBytes - $GraceBytes)
                )

            $CurrentElapsed =
                [Math]::Max(
                    $UploadTimer.
                        Elapsed.
                        TotalSeconds,
                    0.001
                )

            $CurrentSpeedBytesPerSecond =
                $CurrentMeasuredBytes /
                $CurrentElapsed

            $CurrentMbps = (
                (
                    $CurrentSpeedBytesPerSecond * 8
                ) /
                1000000
            ) * $OverheadFactor

            if ($TimeAuto) {
                $CurrentBonusMS =
                    (5.0 * $CurrentSpeedBytesPerSecond) /
                    100000

                if ($CurrentBonusMS -gt 400) {
                    $CurrentBonusMS = 400
                }

                $UploadBonusMS +=
                    $CurrentBonusMS
            }

            Write-LiveLine (
                'Upload:   {0,8:N1} Mbps  Measured: {1,7:N1} MB  Streams: {2}/{3}' -f
                $CurrentMbps,
                ($CurrentMeasuredBytes / 1MB),
                $ActiveStreams,
                $StreamCount
            )

            $CurrentWholeSecond =
                [Math]::Floor(
                    $CurrentElapsed
                )

            if (
                $CurrentWholeSecond -gt
                $LastUploadLogSecond
            ) {
                $LastUploadLogSecond =
                    $CurrentWholeSecond

                $StreamDetails = @()

                for (
                    $DiagnosticStreamIndex = 1
                    $DiagnosticStreamIndex -le $StreamCount
                    $DiagnosticStreamIndex++
                ) {
                    $StreamDetails += (
                        'S{0}[Bytes={1:N1}MB Req={2} Resp={3} Err={4}]' -f
                        $DiagnosticStreamIndex,
                        (
                            [long]$SharedState[
                                "Bytes_$DiagnosticStreamIndex"
                            ] / 1MB
                        ),
                        [int]$SharedState[
                            "Requests_$DiagnosticStreamIndex"
                        ],
                        [int]$SharedState[
                            "Responses_$DiagnosticStreamIndex"
                        ],
                        [int]$SharedState[
                            "Errors_$DiagnosticStreamIndex"
                        ]
                    )
                }

                Write-Log `
                    -Level 'DEBUG' `
                    -Message (
                        'Upload measured progress. Elapsed={0:N2}s Mbps={1:N1} MeasuredMB={2:N1} GraceDiscardedMB={3:N1} ActiveStreams={4}/{5} {6}' -f
                        $CurrentElapsed,
                        $CurrentMbps,
                        ($CurrentMeasuredBytes / 1MB),
                        ($GraceBytes / 1MB),
                        $ActiveStreams,
                        $StreamCount,
                        ($StreamDetails -join ' ')
                    )
            }

            $EffectiveUploadSeconds =
                $CurrentElapsed +
                ($UploadBonusMS / 1000)

            if (
                $EffectiveUploadSeconds -gt
                $TestSeconds
            ) {
                break
            }

            Start-Sleep `
                -Milliseconds 200
        }

        $UploadTimer.Stop()

        $UploadMeasuredSeconds =
            [Math]::Max(
                $UploadTimer.Elapsed.TotalSeconds,
                0.001
            )

        $SharedState['Stop'] = $true

        [long]$FinalTotalBytes = 0

        for (
            $StreamIndex = 1
            $StreamIndex -le $StreamCount
            $StreamIndex++
        ) {
            $FinalTotalBytes +=
                [long]$SharedState[
                    "Bytes_$StreamIndex"
                ]
        }

        [long]$MeasuredUploadedBytes =
            [Math]::Max(
                0,
                ($FinalTotalBytes - $GraceBytes)
            )

        $WorkerExitTimer =
            [System.Diagnostics.Stopwatch]::
                StartNew()

        while (
            $WorkerExitTimer.
                Elapsed.
                TotalSeconds -lt 5
        ) {
            $DoneCount = 0

            for (
                $StreamIndex = 1
                $StreamIndex -le $StreamCount
                $StreamIndex++
            ) {
                if (
                    $SharedState[
                        "Done_$StreamIndex"
                    ]
                ) {
                    $DoneCount++
                }
            }

            if (
                $DoneCount -ge
                $StreamCount
            ) {
                break
            }

            Start-Sleep `
                -Milliseconds 100
        }

        $WorkerExitTimer.Stop()

        foreach ($Worker in $Workers) {
            try {
                if (
                    $Worker.
                        Handle.
                        IsCompleted
                ) {
                    [void]$Worker.
                        PowerShell.
                        EndInvoke(
                            $Worker.Handle
                        )
                }
                else {
                    $Worker.
                        PowerShell.
                        Stop()
                }
            }
            catch {
                # Worker-level errors are captured in shared state.
            }
        }

        $WorkerErrors = @()
        $PerStreamDiagnostics = @()

        for (
            $DiagnosticStreamIndex = 1
            $DiagnosticStreamIndex -le $StreamCount
            $DiagnosticStreamIndex++
        ) {
            if (
                [int]$SharedState[
                    "Errors_$DiagnosticStreamIndex"
                ] -gt 0 -and
                $SharedState[
                    "LastError_$DiagnosticStreamIndex"
                ]
            ) {
                $WorkerErrors += (
                    'Stream {0}: {1}' -f
                    $DiagnosticStreamIndex,
                    $SharedState[
                        "LastError_$DiagnosticStreamIndex"
                    ]
                )
            }

            $PerStreamDiagnostics +=
                [pscustomobject]@{
                    Stream =
                        $DiagnosticStreamIndex

                    Bytes =
                        [long]$SharedState[
                            "Bytes_$DiagnosticStreamIndex"
                        ]

                    Requests =
                        [int]$SharedState[
                            "Requests_$DiagnosticStreamIndex"
                        ]

                    Responses =
                        [int]$SharedState[
                            "Responses_$DiagnosticStreamIndex"
                        ]

                    Errors =
                        [int]$SharedState[
                            "Errors_$DiagnosticStreamIndex"
                        ]

                    LastError =
                        $SharedState[
                            "LastError_$DiagnosticStreamIndex"
                        ]
                }
        }

        if ($MeasuredUploadedBytes -le 0) {
            if ($WorkerErrors.Count -gt 0) {
                throw (
                    'HttpClient browser-method upload measured no data. {0}' -f
                    ($WorkerErrors -join ' | ')
                )
            }

            throw (
                'HttpClient browser-method upload measured no data.'
            )
        }

        # LibreSpeed reports decimal Mbps and applies the configured
        # overhead compensation factor to estimated raw link speed.
        $UploadMbps = (
            (
                ($MeasuredUploadedBytes * 8) /
                $UploadMeasuredSeconds
            ) /
            1000000
        ) * $OverheadFactor

        $FinalStreamLog = @()

        foreach (
            $StreamDiagnostic in
            $PerStreamDiagnostics
        ) {
            $FinalStreamLog += (
                'S{0}[MB={1:N1} Req={2} Resp={3} Err={4} LastError="{5}"]' -f
                $StreamDiagnostic.Stream,
                ($StreamDiagnostic.Bytes / 1MB),
                $StreamDiagnostic.Requests,
                $StreamDiagnostic.Responses,
                $StreamDiagnostic.Errors,
                $StreamDiagnostic.LastError
            )
        }

        Write-Log `
            -Level 'INFO' `
            -Message (
                'Upload test complete. BrowserMethod=True Mbps={0:N1} MeasuredMB={1:N1} TotalMB={2:N1} GraceDiscardedMB={3:N1} Streams={4} StreamDelayMS={5} GraceSeconds={6} ActualMeasuredSeconds={7:N2} MaxSeconds={8} TimeAuto={9} BonusMS={10:N0} PayloadKB={11} WriteBufferKB={12} OverheadFactor={13} {14}' -f
                $UploadMbps,
                ($MeasuredUploadedBytes / 1MB),
                ($FinalTotalBytes / 1MB),
                ($GraceBytes / 1MB),
                $StreamCount,
                $StreamDelayMS,
                $GraceSeconds,
                $UploadMeasuredSeconds,
                $TestSeconds,
                $TimeAuto,
                $UploadBonusMS,
                $PayloadKB,
                $WriteBufferKB,
                $OverheadFactor,
                ($FinalStreamLog -join ' ')
            )

        return [pscustomobject]@{
            Mbps =
                $UploadMbps

            Bytes =
                $MeasuredUploadedBytes

            TotalBytes =
                $FinalTotalBytes

            GraceBytes =
                $GraceBytes

            Seconds =
                $UploadMeasuredSeconds

            MaxSeconds =
                $TestSeconds

            TimeAuto =
                $TimeAuto

            BonusMS =
                $UploadBonusMS

            GraceSeconds =
                $GraceSeconds

            Streams =
                $StreamCount

            StreamDelayMS =
                $StreamDelayMS

            PayloadKB =
                $PayloadKB

            WriteBufferKB =
                $WriteBufferKB

            OverheadFactor =
                $OverheadFactor

            Transport =
                'HttpClient-BrowserMethod'

            WorkerErrors =
                $WorkerErrors

            PerStream =
                $PerStreamDiagnostics
        }
    }
    finally {
        $SharedState['Stop'] =
            $true

        foreach ($Worker in $Workers) {
            if ($Worker.PowerShell) {
                try {
                    $Worker.
                        PowerShell.
                        Dispose()
                }
                catch {
                }
            }
        }

        if ($RunspacePool) {
            try {
                $RunspacePool.Close()
            }
            catch {
            }

            try {
                $RunspacePool.Dispose()
            }
            catch {
            }
        }

        if ($StartGate) {
            $StartGate.Dispose()
        }
    }
}

# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------

try {
    Initialize-Log

    Write-Log `
        -Level 'INFO' `
        -Message (
            '===== LibreSpeed Internet Speed Test START ====='
        )

    $SystemNetHttpVersion = 'Unknown'

    try {
        Add-Type `
            -AssemblyName System.Net.Http `
            -ErrorAction Stop

        $SystemNetHttpVersion =
            [System.Net.Http.HttpClient].
                Assembly.
                GetName().
                Version.
                ToString()
    }
    catch {
        $SystemNetHttpVersion =
            'LoadFailed: {0}' -f
            $_.Exception.Message
    }

    Write-Log `
        -Level 'INFO' `
        -Message (
            'Environment. Computer="{0}" User="{1}" Host="{2}" PSVersion={3} CLRVersion={4} Process64Bit={5} OS64Bit={6} System.Net.Http={7} DefaultConnectionLimit={8}' -f
            $env:COMPUTERNAME,
            [Environment]::UserName,
            $Host.Name,
            $PSVersionTable.PSVersion,
            [Environment]::Version,
            [Environment]::Is64BitProcess,
            [Environment]::Is64BitOperatingSystem,
            $SystemNetHttpVersion,
            [Net.ServicePointManager]::DefaultConnectionLimit
        )

    Write-Log `
        -Level 'INFO' `
        -Message (
            'Configuration. PingCount={0} TimeAuto={1} DownloadStreams={2} DownloadStreamDelayMS={3} DownloadGraceSeconds={4} DownloadMaxSeconds={5} DownloadOverheadFactor={6} DownloadRequestMB={7} UploadStreams={8} UploadStreamDelayMS={9} UploadGraceSeconds={10} UploadMaxSeconds={11} UploadOverheadFactor={12} UploadPayloadKB={13} UploadWriteBufferKB={14} SelectorPingCount={15} SelectorTimeoutMS={16}' -f
            $PingCount,
            $TimeAuto,
            $DownloadStreamCount,
            $DownloadStreamDelayMS,
            $DownloadGraceSeconds,
            $DownloadTestSeconds,
            $DownloadOverheadFactor,
            $DownloadRequestSizeMB,
            $UploadStreamCount,
            $UploadStreamDelayMS,
            $UploadGraceSeconds,
            $UploadTestSeconds,
            $UploadOverheadFactor,
            $UploadPayloadKB,
            $UploadWriteBufferKB,
            $ServerSelectorPingCount,
            $ServerSelectorTimeoutMS
        )

    Write-Host ''
    Write-Host 'LibreSpeed Internet Speed Test'
    Write-Host '============================='
    Write-Host ''
    Write-Host 'Retrieving LibreSpeed server list...'

    $Servers = @(
        Get-LibreSpeedServerList `
            -Uri $ServerListUrl
    )

    Write-Host (
        'Discovered {0} server records.' -f
        $Servers.Count
    )

    Write-Log `
        -Level 'INFO' `
        -Message (
            'Server discovery complete. Records={0}' -f
            $Servers.Count
        )

    Write-Host ''
    Write-Host 'Measuring initial server latency...'

    $InitialResults = @()
    $ProbeNumber = 0

    foreach ($Server in $Servers) {
        $ProbeNumber++

        Write-LiveLine (
            'Probing servers: {0}/{1}  Reachable: {2}' -f
            $ProbeNumber,
            $Servers.Count,
            $InitialResults.Count
        )

        try {
            $InitialLatency = Measure-SpeedLatency `
                -Server $Server `
                -Samples 1 `
                -TimeoutMS $DiscoveryTimeoutMS

            $InitialResults += [pscustomobject]@{
                Server = $Server
                InitialLatency = $InitialLatency.Average
            }
        }
        catch {
            # Unreachable servers are excluded.
        }
    }

    Write-LiveLine (
        'Initial probe complete: {0} of {1} servers reachable.' -f
        $InitialResults.Count,
        $Servers.Count
    ) -Final

    Write-Host ''

    Write-Log `
        -Level 'INFO' `
        -Message (
            'Initial latency probe complete. Reachable={0} Total={1}' -f
            $InitialResults.Count,
            $Servers.Count
        )

    if ($InitialResults.Count -eq 0) {
        throw 'No LibreSpeed servers responded to the initial probe.'
    }

    Write-Host ''
    Write-Host (
        'Selecting LibreSpeed server by lowest ping ({0} pings/server)...' -f
        $ServerSelectorPingCount
    )

    $SelectorResults = @()

    foreach ($Server in $Servers) {
        try {
            $SelectorPing =
                Measure-LibreSpeedSelectorPing `
                    -Server $Server `
                    -Samples $ServerSelectorPingCount `
                    -TimeoutMS $ServerSelectorTimeoutMS

            if ($SelectorPing -ge 0) {
                $SelectorResults +=
                    [pscustomobject]@{
                        Server = $Server
                        Ping = $SelectorPing
                    }

                Write-Host (
                    '  {0,-55} {1,7:N1} ms' -f
                    $Server.Name,
                    $SelectorPing
                )
            }
            else {
                Write-Host (
                    '  {0,-55} unavailable' -f
                    $Server.Name
                )
            }
        }
        catch {
            Write-Host (
                '  {0,-55} unavailable' -f
                $Server.Name
            )

            Write-Log `
                -Level 'WARN' `
                -Message (
                    'Server selector failed. Server="{0}" Error="{1}"' -f
                    $Server.Name,
                    $_.Exception.Message
                )
        }
    }

    if ($SelectorResults.Count -eq 0) {
        throw (
            'No LibreSpeed server passed the MPOT selector.'
        )
    }

    $BestSelectorResult =
        $SelectorResults |
        Sort-Object Ping |
        Select-Object -First 1

    $Selected =
        $BestSelectorResult.Server

    $SelectedUploadPayloadKB =
        $UploadPayloadKB

    Write-Host ''
    Write-Host (
        'Selected: {0}' -f
        $Selected.Name
    )

    Write-Host (
        'Selector latency: {0:N1} ms' -f
        $BestSelectorResult.Ping
    )

    Write-Host (
        'Upload payload: {0:N0} MB' -f
        ($SelectedUploadPayloadKB / 1024)
    )

    Write-Log `
        -Level 'INFO' `
        -Message (
            'MPOT server selected by lowest ping. Server="{0}" SelectorPingMs={1:N2} SelectorPingsPerServer={2} SelectorTimeoutMS={3} PayloadKB={4}' -f
            $Selected.Name,
            $BestSelectorResult.Ping,
            $ServerSelectorPingCount,
            $ServerSelectorTimeoutMS,
            $SelectedUploadPayloadKB
        )

    Write-Host ''
    Write-Host (
        'Measuring LibreSpeed ping/jitter with {0} HTTP pings...' -f
        $PingCount
    )

    $FinalPingResult =
        Measure-SpeedLatency `
            -Server $Selected `
            -Samples $PingCount `
            -TimeoutMS 7000

    $Selected |
        Add-Member `
            -NotePropertyName Latency `
            -NotePropertyValue $FinalPingResult.Ping `
            -Force

    $Selected |
        Add-Member `
            -NotePropertyName Jitter `
            -NotePropertyValue $FinalPingResult.Jitter `
            -Force

    Write-Host (
        'Latency:  {0:N1} ms' -f
        $Selected.Latency
    )

    Write-Host (
        'Jitter:   {0:N1} ms' -f
        $Selected.Jitter
    )

    Write-Log `
        -Level 'INFO' `
        -Message (
            'Server final ping/jitter. Server="{0}" LatencyMs={1:N1} JitterMs={2:N1} PingCount={3} PingMethod="LibreSpeed worker math; MPOT cors=true; HTTP response is pong"' -f
            $Selected.Name,
            $Selected.Latency,
            $Selected.Jitter,
            $PingCount
        )


    # =====================================================================
    # Duration-based multi-stream download
    # =====================================================================

    Write-Host ''
    Write-Host (
        'Testing download with LibreSpeed browser methodology: {0} streams, {1} ms stagger, {2}s grace, auto duration (max {3}s)...' -f
        $DownloadStreamCount,
        $DownloadStreamDelayMS,
        $DownloadGraceSeconds,
        $DownloadTestSeconds
    )

    $DownloadResult = Invoke-DurationBasedDownloadTest `
        -Server $Selected `
        -StreamCount $DownloadStreamCount `
        -StreamDelayMS $DownloadStreamDelayMS `
        -GraceSeconds $DownloadGraceSeconds `
        -TestSeconds $DownloadTestSeconds `
        -RequestSizeMB $DownloadRequestSizeMB `
        -OverheadFactor $DownloadOverheadFactor `
        -TimeAuto $TimeAuto

    $DownloadMbps = $DownloadResult.Mbps
    $DownloadedBytes = $DownloadResult.Bytes

    Write-LiveLine (
        'Download: {0:N1} Mbps  Received: {1:N1} MB  Streams: {2}' -f
        $DownloadMbps,
        ($DownloadedBytes / 1MB),
        $DownloadResult.Streams
    ) -Final

    Write-Log `
        -Level 'INFO' `
        -Message (
            'Download result accepted. Server="{0}" Mbps={1:N1}' -f
            $Selected.Name,
            $DownloadMbps
        )

    Write-Host ''

    # =====================================================================
    # Duration-based multi-stream upload
    # =====================================================================

    Write-Host ''
    Write-Host (
        'Testing upload with LibreSpeed browser methodology: {0} streams, {1} ms stagger, {2}s grace, auto duration (max {3}s)...' -f
        $UploadStreamCount,
        $UploadStreamDelayMS,
        $UploadGraceSeconds,
        $UploadTestSeconds
    )

    $UploadResult = Invoke-DurationBasedUploadTest `
        -Server $Selected `
        -StreamCount $UploadStreamCount `
        -StreamDelayMS $UploadStreamDelayMS `
        -GraceSeconds $UploadGraceSeconds `
        -TestSeconds $UploadTestSeconds `
        -PayloadKB $SelectedUploadPayloadKB `
        -WriteBufferKB $UploadWriteBufferKB `
        -OverheadFactor $UploadOverheadFactor `
        -TimeAuto $TimeAuto

    $UploadMbps = $UploadResult.Mbps
    $UploadedBytes = $UploadResult.Bytes

    Write-LiveLine (
        'Upload:   {0:N1} Mbps  Sent: {1:N1} MB  Streams: {2}' -f
        $UploadMbps,
        ($UploadedBytes / 1MB),
        $UploadResult.Streams
    ) -Final

    Write-Host ''
    Write-Host ''
    Write-Host 'Results'
    Write-Host '-------'
    Write-Host ('Server:   {0}' -f $Selected.Name)
    Write-Host ('Latency:  {0:N1} ms' -f $Selected.Latency)
    Write-Host ('Jitter:   {0:N1} ms' -f $Selected.Jitter)

    Write-Host (
        'Download: {0:N1} Mbps ({1} streams, {2} ms stagger, {3}s grace, {4:N1}s measured, auto, x{5} overhead)' -f
        $DownloadMbps,
        $DownloadStreamCount,
        $DownloadStreamDelayMS,
        $DownloadGraceSeconds,
        $DownloadResult.Seconds,
        $DownloadOverheadFactor
    )

    Write-Host (
        'Upload:   {0:N1} Mbps ({1} streams, {2} ms stagger, {3}s grace, {4:N1}s measured, auto, {5:N0} MB payload, x{6} overhead)' -f
        $UploadMbps,
        $UploadStreamCount,
        $UploadStreamDelayMS,
        $UploadGraceSeconds,
        $UploadResult.Seconds,
        ($SelectedUploadPayloadKB / 1024),
        $UploadOverheadFactor
    )

    Write-Log `
        -Level 'INFO' `
        -Message (
            'FINAL RESULT. Server="{0}" LatencyMs={1:N1} JitterMs={2:N1} DownloadMbps={3:N1} UploadMbps={4:N1}' -f
            $Selected.Name,
            $Selected.Latency,
            $Selected.Jitter,
            $DownloadMbps,
            $UploadMbps
        )

    # ---------------------------------------------------------------------
    # NinjaOne WYSIWYG custom field
    # ---------------------------------------------------------------------

    try {
        $EncodedServer =
            [System.Net.WebUtility]::HtmlEncode(
                [string]$Selected.Name
            )

        # Scale throughput bars to the next 100 Mbps above the faster result.
        $ChartMaximumMbps =
            [Math]::Max(
                100,
                (
                    [Math]::Ceiling(
                        (
                            [Math]::Max(
                                $DownloadMbps,
                                $UploadMbps
                            )
                        ) / 100
                    ) * 100
                )
            )

        $DownloadPercent =
            [Math]::Min(
                100,
                [Math]::Max(
                    0,
                    (($DownloadMbps / $ChartMaximumMbps) * 100)
                )
            )

        $UploadPercent =
            [Math]::Min(
                100,
                [Math]::Max(
                    0,
                    (($UploadMbps / $ChartMaximumMbps) * 100)
                )
            )

        $InvariantCulture =
            [System.Globalization.CultureInfo]::InvariantCulture

        $DownloadPercentText =
            $DownloadPercent.ToString(
                '0.##',
                $InvariantCulture
            )

        $UploadPercentText =
            $UploadPercent.ToString(
                '0.##',
                $InvariantCulture
            )

        $DownloadDisplay =
            $DownloadMbps.ToString('N1')

        $UploadDisplay =
            $UploadMbps.ToString('N1')

        $PingDisplay =
            $Selected.Latency.ToString('N1')

        $JitterDisplay =
            $Selected.Jitter.ToString('N1')

        $ChartMaximumDisplay =
            $ChartMaximumMbps.ToString('N0')

        $HTML = @"
<div class='row g-3'>

    <div class='col-xl-6 col-lg-6 col-md-6 col-sm-12'>
        <div style='border-width: 1px; border-style: solid; border-color: #5f5f5f; border-radius: 6px; padding: 12px; height: 92px; box-sizing: border-box;'>
            <div style='font-size: 15px; margin-bottom: 8px;'>
                <i class='fa-solid fa-download'></i>&nbsp;&nbsp;<strong>Download</strong>
            </div>
            <div style='font-size: 28px; white-space: nowrap;'>
                $DownloadDisplay <span style='font-size: 15px;'>Mbps</span>
            </div>
        </div>
    </div>

    <div class='col-xl-6 col-lg-6 col-md-6 col-sm-12'>
        <div style='border-width: 1px; border-style: solid; border-color: #5f5f5f; border-radius: 6px; padding: 12px; height: 92px; box-sizing: border-box;'>
            <div style='font-size: 15px; margin-bottom: 8px;'>
                <i class='fa-solid fa-upload'></i>&nbsp;&nbsp;<strong>Upload</strong>
            </div>
            <div style='font-size: 28px; white-space: nowrap;'>
                $UploadDisplay <span style='font-size: 15px;'>Mbps</span>
            </div>
        </div>
    </div>

</div>

<div style='border-width: 1px; border-style: solid; border-color: #5f5f5f; border-radius: 6px; padding: 14px; margin-top: 12px; box-sizing: border-box;'>

    <div style='font-size: 16px; margin-bottom: 14px;'>
        <i class='fa-solid fa-chart-simple'></i>&nbsp;&nbsp;<strong>Throughput</strong>
        <span style='font-size: 13px;'>&nbsp;&nbsp;Scale: $ChartMaximumDisplay Mbps</span>
    </div>

    <div style='margin-bottom: 14px;'>
        <div style='display: flex; justify-content: space-between; margin-bottom: 5px;'>
            <span><strong>Download</strong></span>
            <span>$DownloadDisplay Mbps</span>
        </div>
        <div style='width: 100%; height: 18px; background-color: #333333; border-radius: 4px; overflow-wrap: normal;'>
            <div style='width: $DownloadPercentText%; height: 18px; background-color: #3b82f6; border-radius: 4px;'></div>
        </div>
    </div>

    <div>
        <div style='display: flex; justify-content: space-between; margin-bottom: 5px;'>
            <span><strong>Upload</strong></span>
            <span>$UploadDisplay Mbps</span>
        </div>
        <div style='width: 100%; height: 18px; background-color: #333333; border-radius: 4px; overflow-wrap: normal;'>
            <div style='width: $UploadPercentText%; height: 18px; background-color: #22a699; border-radius: 4px;'></div>
        </div>
    </div>

</div>

<div class='row g-3' style='margin-top: 0px;'>

    <div class='col-xl-6 col-lg-6 col-md-6 col-sm-12'>
        <div style='border-width: 1px; border-style: solid; border-color: #5f5f5f; border-radius: 6px; padding: 12px; height: 78px; box-sizing: border-box;'>
            <div style='font-size: 14px; margin-bottom: 6px;'>
                <i class='fa-solid fa-gauge-high'></i>&nbsp;&nbsp;<strong>Ping</strong>
            </div>
            <div style='font-size: 23px; white-space: nowrap;'>
                $PingDisplay <span style='font-size: 14px;'>ms</span>
            </div>
        </div>
    </div>

    <div class='col-xl-6 col-lg-6 col-md-6 col-sm-12'>
        <div style='border-width: 1px; border-style: solid; border-color: #5f5f5f; border-radius: 6px; padding: 12px; height: 78px; box-sizing: border-box;'>
            <div style='font-size: 14px; margin-bottom: 6px;'>
                <i class='fa-solid fa-wave-square'></i>&nbsp;&nbsp;<strong>Jitter</strong>
            </div>
            <div style='font-size: 23px; white-space: nowrap;'>
                $JitterDisplay <span style='font-size: 14px;'>ms</span>
            </div>
        </div>
    </div>

</div>

<div style='border-width: 1px; border-style: solid; border-color: #5f5f5f; border-radius: 6px; padding: 10px 12px; margin-top: 12px; box-sizing: border-box;'>
    <i class='fa-solid fa-server'></i>&nbsp;&nbsp;<strong>Server:</strong>&nbsp;$EncodedServer
</div>
"@

        $HTML |
            Ninja-Property-Set-Piped `
                -Name 'internetSpeedTest'

        Write-Log `
            -Level 'INFO' `
            -Message (
                'NinjaOne custom field updated. Field="internetSpeedTest" ChartMaximumMbps={0:N0}' -f
                $ChartMaximumMbps
            )
    }
    catch {
        Write-Log `
            -Level 'WARN' `
            -Message (
                'NinjaOne custom field update failed. Field="internetSpeedTest" Error="{0}"' -f
                $_.Exception.Message
            )
    }

    Write-Log `
        -Level 'INFO' `
        -Message (
            '===== LibreSpeed Internet Speed Test END ====='
        )
}
catch {
    $FailureMessage =
        $_.Exception.Message

    Write-Log `
        -Level 'ERROR' `
        -Message (
            'Speed test failed. Error="{0}" ScriptStackTrace="{1}"' -f
            $FailureMessage,
            $_.ScriptStackTrace
        )

    Write-Log `
        -Level 'INFO' `
        -Message (
            '===== LibreSpeed Internet Speed Test END - ERROR ====='
        )

    Write-Host ''
    Write-Host ''

    Write-Host (
        'Speed test failed: {0}' -f
        $FailureMessage
    ) -ForegroundColor Red
}