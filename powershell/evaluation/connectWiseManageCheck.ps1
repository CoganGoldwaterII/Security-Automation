# ============================================================================
# NAME: ConnectWise Manage Client 64-bit - Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows endpoints / NinjaOne evaluation automation
# VARIABLES:
#   ExpectedName = ConnectWise Manage Client 64-bit
# OUTPUT TOKENS:
#   TRIGGER   | ConnectWise Manage Client 64-bit not installed
#   NO_ACTION | ConnectWise Manage Client 64-bit installed
#   ERROR     | Not emitted; exceptions use Write-Error and exit 1
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None; output written to the execution console.
# DESCRIPTION:
#   Evaluates whether ConnectWise Manage Client 64-bit is installed.
#   Searches both native and WOW6432Node Windows uninstall registry
#   locations for an exact application display name match.
#   Reports installed version information when available.
#   Emits TRIGGER when the application is absent and NO_ACTION when
#   installed, regardless of installed version.
#   Exits 0 for evaluation results and 1 on caught exceptions.
# ============================================================================

$ErrorActionPreference = 'Stop'

$ExpectedName = 'ConnectWise Manage Client 64-bit'

try {
    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $hits = foreach ($path in $registryPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -and $_.DisplayName -eq $ExpectedName
            } |
            Select-Object DisplayName, DisplayVersion, Publisher, PSChildName
    }

    if ($hits) {
        $versions = ($hits |
            ForEach-Object { $_.DisplayVersion } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique) -join ', '

        if ([string]::IsNullOrWhiteSpace($versions)) {
            Write-Output "NO_ACTION | $ExpectedName installed"
        }
        else {
            Write-Output "NO_ACTION | $ExpectedName installed ($versions)"
        }

        exit 0
    }

    Write-Output "TRIGGER | $ExpectedName not installed"
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}