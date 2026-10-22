# ============================================================================
# NAME: CBS Assembly Missing Error Check
# AUTHORED BY: Cogan Goldwater
# TYPE: Diagnostic Utility
# SCOPE: Windows endpoints / NinjaOne manual execution
# VARIABLES:
#   Required: None
#   Optional: None
# OUTPUT TOKENS:
#   None; diagnostic messages are written to console output.
#   Reports matching ERROR_SXS_ASSEMBLY_MISSING entries when found.
# CUSTOM FIELDS:
#   Reads: None
#   Writes: None
# FILE TRANSFERS:
#   Required: No
#   Files: None
# LOGGING PATH:
#   None; results are written to console output.
# SOURCE LOG:
#   C:\Windows\Logs\CBS\CBS.log
# DESCRIPTION:
#   Searches the Windows Component-Based Servicing (CBS) log for
#   entries containing ERROR_SXS_ASSEMBLY_MISSING.
#
#   Displays matching log entries when present or reports that
#   no matching entries were found.
#
#   Reports when CBS.log is missing or cannot be read.
#
#   This utility is read-only and performs no remediation.
#   It does not modify the component store or execute DISM/SFC.
# ============================================================================

# Define the source path for the CBS log
$sourcePath = "$($env:windir)\Logs\CBS\CBS.log"

# Check if the CBS log exists
if (Test-Path $sourcePath) {
    try {
        # Read the CBS log file and search for lines containing 'ERROR_SXS_ASSEMBLY_MISSING'
        $logContents = Get-Content -Path $sourcePath
        $errorEntries = $logContents | Select-String -Pattern 'ERROR_SXS_ASSEMBLY_MISSING'

        # Check if any entries were found
        if ($errorEntries) {
            Write-Host "Found the following 'ERROR_SXS_ASSEMBLY_MISSING' entries in CBS.log:"
            $errorEntries | ForEach-Object { Write-Host $_ }
        } else {
            Write-Host "No 'ERROR_SXS_ASSEMBLY_MISSING' entries were found in CBS.log."
        }
    } catch {
        Write-Host "An error occurred while reading the CBS log: $_"
    }
} else {
    Write-Host "CBS log does not exist at the specified location."
}