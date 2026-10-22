# ============================================================================
# NAME: Browser and Native Password Manager Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   RESULT    | Browser password remediation performed or purge deferred
#   NO_ACTION | No remediation required
#   ERROR     | One or more browser remediations failed
#
#   Actual output begins with a bare token followed by browser details.
#   Script exits 0 upon normal completion.
#
# CUSTOM FIELDS:
#   Reads: remediationSummary
#   Writes: browsermanagedPasswordsDetected, lastRemediationDate,
#           remediationSummary
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\MME\AutoLogs\Browser_Password_Remediation.log
#
# DESCRIPTION:
#   Independently remediates Chrome, Edge, Brave, and Firefox.
#
#   For installed browsers:
#     - Disables password synchronization using machine-level policies.
#     - Disables native password saving using machine-level policies.
#     - Preserves other browser synchronization categories where supported.
#
#   For browser profiles containing saved passwords:
#     - Deletes local password stores when the browser is not running.
#     - Defers password deletion when the browser is running.
#     - Does not terminate or restart browser processes.
#
#   Safety order:
#     1. Enforce and verify password synchronization restrictions.
#     2. Enforce and verify password-saving restrictions.
#     3. Purge local passwords only when the browser is not running.
#
#   Chromium policies:
#     SyncTypesListDisabled\<numeric value> = passwords
#     PasswordManagerEnabled = 0
#
#   Firefox policies:
#     Sync\Passwords = 0
#     Sync\Locked = 1
#     PasswordManagerEnabled = 0
#
#   Firefox requires major version 150 or later for the configured
#   granular password synchronization policy.
#
#   Uses Windows SQLite APIs to count Chromium passwords without
#   decrypting or displaying credential contents.
#
#   Removes Chromium Login Data and Login Data For Account databases,
#   including transaction sidecars, when eligible for deletion.
#
#   Removes Firefox logins.json and logins-backup.json files when
#   eligible for deletion.
#
#   Clears browsermanagedPasswordsDetected at remediation startup.
#   Updates lastRemediationDate and appends to remediationSummary
#   when policy changes or password-store removal occur.
#
#   Uses temporary SQLite snapshots under the process TEMP directory.
#   Deletes temporary snapshots during normal cleanup.
#
#   WARNING:
#   Password-store removal permanently deletes locally stored
#   browser credentials. No backup or rollback is performed.
#   Existing executable logic has been preserved.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "Browser_Password_Remediation.log"
$TempRoot = Join-Path $env:TEMP ("MME-BrowserPasswordRemediation-" + [guid]::NewGuid().ToString("N"))

# ============================================================
# Basic helpers
# ============================================================

function New-Dir {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

New-Dir $LogRoot
New-Dir $TempRoot

"Browser Password Remediation - $(Get-Date -Format s)" |
    Set-Content -Path $LogPath -Encoding UTF8

function Write-Log {
    param([string]$Message)

    "$(Get-Date -Format s) | $Message" |
        Add-Content -Path $LogPath -Encoding UTF8
}


# Clear the detection field as soon as remediation runs.
# The evaluation script will repopulate it on the next evaluation if
# browser-managed passwords are still detected.
try {
    Ninja-Property-Set `
        -Name "browsermanagedPasswordsDetected" `
        -Value ""

    Write-Log "Custom field cleared | browsermanagedPasswordsDetected"
}
catch {
    Write-Log "WARNING | Failed to clear browsermanagedPasswordsDetected | $($_.Exception.Message)"
}

function Read-SharedText {
    param(
        [string]$Path,
        [int]$Retries = 5
    )

    for ($Attempt = 1; $Attempt -le $Retries; $Attempt++) {
        $Stream = $null
        $Reader = $null

        try {
            $Share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete

            $Stream = [System.IO.FileStream]::new(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                $Share
            )

            $Reader = [System.IO.StreamReader]::new($Stream)
            return $Reader.ReadToEnd()
        }
        catch {
            if ($Attempt -lt $Retries) {
                Start-Sleep -Milliseconds 200
            }
            else {
                throw
            }
        }
        finally {
            if ($Reader) {
                $Reader.Dispose()
            }
            elseif ($Stream) {
                $Stream.Dispose()
            }
        }
    }
}

function Copy-SharedFile {
    param(
        [string]$Source,
        [string]$Destination
    )

    $InputStream = $null
    $OutputStream = $null

    try {
        $Share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete

        $InputStream = [System.IO.FileStream]::new(
            $Source,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            $Share
        )

        $OutputStream = [System.IO.FileStream]::new(
            $Destination,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )

        $InputStream.CopyTo($OutputStream)
        $OutputStream.Flush()
    }
    finally {
        if ($OutputStream) { $OutputStream.Dispose() }
        if ($InputStream)  { $InputStream.Dispose() }
    }
}

# ============================================================
# Windows user profiles
# ============================================================

function Get-WindowsProfiles {
    $ProfileList = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

    $Profiles = foreach ($Key in Get-ChildItem -Path $ProfileList -ErrorAction SilentlyContinue) {
        $Properties = Get-ItemProperty -Path $Key.PSPath -ErrorAction SilentlyContinue

        if (-not $Properties.ProfileImagePath) {
            continue
        }

        $Path = [Environment]::ExpandEnvironmentVariables([string]$Properties.ProfileImagePath)
        $UserName = Split-Path $Path -Leaf

        if (
            $Path -like "C:\Users\*" -and
            $UserName -notin @(
                "Public",
                "Default",
                "Default User",
                "All Users",
                "defaultuser0"
            )
        ) {
            [PSCustomObject]@{
                SID         = $Key.PSChildName
                UserName    = $UserName
                ProfilePath = $Path
            }
        }
    }

    return @($Profiles)
}

$WindowsProfiles = @(Get-WindowsProfiles)

# ============================================================
# Registry policy helpers
# ============================================================

function Get-RegistryDWORD {
    param(
        [string]$RegistryPath,
        [string]$ValueName
    )

    try {
        if (-not (Test-Path -LiteralPath $RegistryPath)) {
            return $null
        }

        return [int](Get-ItemPropertyValue `
            -LiteralPath $RegistryPath `
            -Name $ValueName `
            -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

function Set-RegistryDWORDVerified {
    param(
        [string]$RegistryPath,
        [string]$ValueName,
        [int]$DesiredValue
    )

    $Current = Get-RegistryDWORD `
        -RegistryPath $RegistryPath `
        -ValueName $ValueName

    if ($Current -eq $DesiredValue) {
        return $false
    }

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    New-ItemProperty `
        -LiteralPath $RegistryPath `
        -Name $ValueName `
        -PropertyType DWord `
        -Value $DesiredValue `
        -Force |
        Out-Null

    $Verify = Get-RegistryDWORD `
        -RegistryPath $RegistryPath `
        -ValueName $ValueName

    if ($Verify -ne $DesiredValue) {
        throw "Policy verification failed: $RegistryPath\$ValueName expected $DesiredValue, found $Verify"
    }

    return $true
}

function Test-RegistryListContainsString {
    param(
        [string]$RegistryPath,
        [string]$DesiredValue
    )

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        return $false
    }

    $Properties = Get-ItemProperty -LiteralPath $RegistryPath -ErrorAction SilentlyContinue

    if (-not $Properties) {
        return $false
    }

    foreach ($Property in $Properties.PSObject.Properties) {
        if ($Property.Name -like 'PS*') {
            continue
        }

        if ([string]$Property.Value -ceq $DesiredValue) {
            return $true
        }
    }

    return $false
}

function Add-RegistryListStringVerified {
    param(
        [string]$RegistryPath,
        [string]$DesiredValue
    )

    if (Test-RegistryListContainsString `
        -RegistryPath $RegistryPath `
        -DesiredValue $DesiredValue) {
        return $false
    }

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    $UsedNumbers = @(
        (Get-ItemProperty -LiteralPath $RegistryPath -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -match '^\d+$' } |
            ForEach-Object { [int]$_.Name }
    )

    $NextNumber = 1
    while ($UsedNumbers -contains $NextNumber) {
        $NextNumber++
    }

    New-ItemProperty `
        -LiteralPath $RegistryPath `
        -Name ([string]$NextNumber) `
        -PropertyType String `
        -Value $DesiredValue `
        -Force |
        Out-Null

    if (-not (Test-RegistryListContainsString `
        -RegistryPath $RegistryPath `
        -DesiredValue $DesiredValue)) {
        throw "Policy verification failed: $RegistryPath does not contain '$DesiredValue'"
    }

    return $true
}

function Test-BrowserRunning {
    param([string]$ProcessName)

    return @(
        Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    ).Count -gt 0
}

# ============================================================
# Windows built-in SQLite API - count only
# ============================================================

$SQLiteInitError = $null

if (-not ("MME.BrowserRemediationSQLite" -as [type])) {

    $SQLiteCode = @'
using System;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

namespace MME
{
    public static class BrowserRemediationSQLite
    {
        private const int SQLITE_OK     = 0;
        private const int SQLITE_BUSY   = 5;
        private const int SQLITE_LOCKED = 6;
        private const int SQLITE_ROW    = 100;
        private const int SQLITE_DONE   = 101;

        private const int SQLITE_OPEN_READONLY  = 0x00000001;
        private const int SQLITE_OPEN_READWRITE = 0x00000002;
        private const int SQLITE_OPEN_CREATE    = 0x00000004;

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_open_v2(
            IntPtr filename,
            out IntPtr database,
            int flags,
            IntPtr vfs
        );

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_close(IntPtr database);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_busy_timeout(
            IntPtr database,
            int milliseconds
        );

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_errmsg(IntPtr database);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_backup_init(
            IntPtr destinationDatabase,
            IntPtr destinationName,
            IntPtr sourceDatabase,
            IntPtr sourceName
        );

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_backup_step(
            IntPtr backup,
            int pages
        );

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_backup_finish(IntPtr backup);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_prepare_v2(
            IntPtr database,
            IntPtr sql,
            int bytes,
            out IntPtr statement,
            IntPtr tail
        );

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_step(IntPtr statement);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern long sqlite3_column_int64(
            IntPtr statement,
            int column
        );

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_finalize(IntPtr statement);

        private static IntPtr ToUtf8(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text + "\0");
            IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }

        private static string Utf8ToString(IntPtr pointer)
        {
            if (pointer == IntPtr.Zero)
                return "Unknown SQLite error";

            int length = 0;
            while (Marshal.ReadByte(pointer, length) != 0)
                length++;

            byte[] bytes = new byte[length];
            Marshal.Copy(pointer, bytes, 0, length);
            return Encoding.UTF8.GetString(bytes);
        }

        private static string GetError(IntPtr database)
        {
            if (database == IntPtr.Zero)
                return "SQLite database handle unavailable";

            return Utf8ToString(sqlite3_errmsg(database));
        }

        public static void Backup(
            string sourcePath,
            string destinationPath,
            int maxWaitMilliseconds
        )
        {
            IntPtr sourceDb = IntPtr.Zero;
            IntPtr destinationDb = IntPtr.Zero;
            IntPtr sourcePathPtr = IntPtr.Zero;
            IntPtr destinationPathPtr = IntPtr.Zero;
            IntPtr mainNamePtr = IntPtr.Zero;
            IntPtr backup = IntPtr.Zero;

            try
            {
                sourcePathPtr = ToUtf8(sourcePath);
                destinationPathPtr = ToUtf8(destinationPath);
                mainNamePtr = ToUtf8("main");

                int rc = sqlite3_open_v2(
                    sourcePathPtr,
                    out sourceDb,
                    SQLITE_OPEN_READONLY,
                    IntPtr.Zero
                );

                if (rc != SQLITE_OK)
                    throw new Exception("Source open failed: " + GetError(sourceDb));

                rc = sqlite3_open_v2(
                    destinationPathPtr,
                    out destinationDb,
                    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                    IntPtr.Zero
                );

                if (rc != SQLITE_OK)
                    throw new Exception("Snapshot open failed: " + GetError(destinationDb));

                sqlite3_busy_timeout(sourceDb, 1000);
                sqlite3_busy_timeout(destinationDb, 1000);

                backup = sqlite3_backup_init(
                    destinationDb,
                    mainNamePtr,
                    sourceDb,
                    mainNamePtr
                );

                if (backup == IntPtr.Zero)
                    throw new Exception("Backup initialization failed: " + GetError(destinationDb));

                DateTime deadline = DateTime.UtcNow.AddMilliseconds(maxWaitMilliseconds);

                while (true)
                {
                    rc = sqlite3_backup_step(backup, 32);

                    if (rc == SQLITE_DONE)
                        break;

                    if (rc == SQLITE_OK)
                        continue;

                    if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED)
                    {
                        if (DateTime.UtcNow >= deadline)
                            throw new Exception("Source database remained locked during online backup");

                        Thread.Sleep(50);
                        continue;
                    }

                    throw new Exception(
                        "Online backup failed with SQLite code " +
                        rc.ToString() + ": " + GetError(destinationDb)
                    );
                }

                rc = sqlite3_backup_finish(backup);
                backup = IntPtr.Zero;

                if (rc != SQLITE_OK)
                    throw new Exception(
                        "Backup finalization failed with SQLite code " +
                        rc.ToString() + ": " + GetError(destinationDb)
                    );
            }
            finally
            {
                if (backup != IntPtr.Zero)
                    sqlite3_backup_finish(backup);

                if (destinationDb != IntPtr.Zero)
                    sqlite3_close(destinationDb);

                if (sourceDb != IntPtr.Zero)
                    sqlite3_close(sourceDb);

                if (mainNamePtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(mainNamePtr);

                if (destinationPathPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(destinationPathPtr);

                if (sourcePathPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(sourcePathPtr);
            }
        }

        public static long ScalarInt64(
            string databasePath,
            string sql,
            bool readOnly
        )
        {
            IntPtr db = IntPtr.Zero;
            IntPtr statement = IntPtr.Zero;
            IntPtr pathPtr = IntPtr.Zero;
            IntPtr sqlPtr = IntPtr.Zero;

            try
            {
                pathPtr = ToUtf8(databasePath);

                int flags = readOnly
                    ? SQLITE_OPEN_READONLY
                    : SQLITE_OPEN_READWRITE;

                int rc = sqlite3_open_v2(
                    pathPtr,
                    out db,
                    flags,
                    IntPtr.Zero
                );

                if (rc != SQLITE_OK)
                    throw new Exception("Snapshot query open failed: " + GetError(db));

                sqlite3_busy_timeout(db, 2000);
                sqlPtr = ToUtf8(sql);

                rc = sqlite3_prepare_v2(
                    db,
                    sqlPtr,
                    -1,
                    out statement,
                    IntPtr.Zero
                );

                if (rc != SQLITE_OK)
                    throw new Exception("Snapshot query prepare failed: " + GetError(db));

                rc = sqlite3_step(statement);

                if (rc != SQLITE_ROW)
                    throw new Exception("Snapshot query failed: " + GetError(db));

                return sqlite3_column_int64(statement, 0);
            }
            finally
            {
                if (statement != IntPtr.Zero)
                    sqlite3_finalize(statement);

                if (db != IntPtr.Zero)
                    sqlite3_close(db);

                if (sqlPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(sqlPtr);

                if (pathPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(pathPtr);
            }
        }
    }
}
'@

    try {
        Add-Type -TypeDefinition $SQLiteCode -ErrorAction Stop
    }
    catch {
        $SQLiteInitError = $_.Exception.Message
        Write-Log "SQLite API initialization failed | $SQLiteInitError"
    }
}

# ============================================================
# Chromium count helpers
# ============================================================

$ChromiumCountQueries = @(
@"
SELECT COUNT(*)
FROM logins
WHERE blocked_by_user = 0
AND password_value IS NOT NULL
AND length(password_value) > 0;
"@,
@"
SELECT COUNT(*)
FROM logins
WHERE blacklisted_by_user = 0
AND password_value IS NOT NULL
AND length(password_value) > 0;
"@,
@"
SELECT COUNT(*)
FROM logins
WHERE password_value IS NOT NULL
AND length(password_value) > 0;
"@
)

function Get-SnapshotPasswordCount {
    param(
        [string]$SnapshotPath,
        [bool]$ReadOnly = $true
    )

    $LastError = $null

    foreach ($Query in $ChromiumCountQueries) {
        try {
            return [long][MME.BrowserRemediationSQLite]::ScalarInt64(
                $SnapshotPath,
                $Query,
                $ReadOnly
            )
        }
        catch {
            $LastError = $_.Exception.Message

            if ($LastError -match "no such column") {
                continue
            }

            throw
        }
    }

    throw "No compatible Chromium password table schema found. Last error: $LastError"
}

function New-SharedChromiumSnapshot {
    param(
        [string]$DatabasePath,
        [string]$SnapshotPath
    )

    Copy-SharedFile -Source $DatabasePath -Destination $SnapshotPath

    foreach ($Suffix in @("-wal", "-journal")) {
        $SourceSidecar = "$DatabasePath$Suffix"
        $DestinationSidecar = "$SnapshotPath$Suffix"

        if (Test-Path -LiteralPath $SourceSidecar) {
            Copy-SharedFile -Source $SourceSidecar -Destination $DestinationSidecar
        }
    }
}

function Get-ChromiumDatabaseCount {
    param(
        [string]$DatabasePath,
        [string]$Browser,
        [string]$ProfileLabel
    )

    if ($SQLiteInitError) {
        throw "Windows SQLite API initialization failed: $SQLiteInitError"
    }

    if (-not (Test-Path -LiteralPath $DatabasePath)) {
        return [PSCustomObject]@{
            Count  = [long]0
            Method = "NotPresent"
        }
    }

    $BackupError = $null

    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        $SnapshotPath = Join-Path $TempRoot ([guid]::NewGuid().ToString("N") + ".sqlite")

        try {
            [MME.BrowserRemediationSQLite]::Backup(
                $DatabasePath,
                $SnapshotPath,
                5000
            )

            $Count = Get-SnapshotPasswordCount `
                -SnapshotPath $SnapshotPath `
                -ReadOnly $true

            return [PSCustomObject]@{
                Count  = [long]$Count
                Method = "OnlineBackup"
            }
        }
        catch {
            $BackupError = $_.Exception.Message

            if ($Attempt -lt 3) {
                Start-Sleep -Milliseconds 250
            }
        }
        finally {
            Remove-Item -LiteralPath $SnapshotPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$SnapshotPath-wal" -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$SnapshotPath-shm" -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$SnapshotPath-journal" -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log "$Browser | $ProfileLabel | Online backup unavailable, using shared-read snapshot | $BackupError"

    $PreviousCount = $null
    $StableMatches = 0
    $FallbackError = $null

    for ($Attempt = 1; $Attempt -le 8; $Attempt++) {
        $SnapshotPath = Join-Path $TempRoot ([guid]::NewGuid().ToString("N") + ".sqlite")

        try {
            New-SharedChromiumSnapshot `
                -DatabasePath $DatabasePath `
                -SnapshotPath $SnapshotPath

            $CurrentCount = Get-SnapshotPasswordCount `
                -SnapshotPath $SnapshotPath `
                -ReadOnly $false

            if ($null -ne $PreviousCount -and $CurrentCount -eq $PreviousCount) {
                $StableMatches++
            }
            else {
                $StableMatches = 0
            }

            $PreviousCount = [long]$CurrentCount

            if ($StableMatches -ge 1) {
                return [PSCustomObject]@{
                    Count  = [long]$CurrentCount
                    Method = "SharedReadSnapshot"
                }
            }
        }
        catch {
            $FallbackError = $_.Exception.Message
            $PreviousCount = $null
            $StableMatches = 0
        }
        finally {
            Remove-Item -LiteralPath $SnapshotPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$SnapshotPath-wal" -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$SnapshotPath-shm" -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$SnapshotPath-journal" -Force -ErrorAction SilentlyContinue
        }

        Start-Sleep -Milliseconds 200
    }

    throw "Could not obtain a stable password count from $DatabasePath. Backup error: $BackupError. Snapshot error: $FallbackError"
}

function Test-ChromiumInstalled {
    param(
        [string[]]$MachineExecutables,
        [string]$UserExecutableRelativePath
    )

    foreach ($Exe in $MachineExecutables) {
        if ($Exe -and (Test-Path -LiteralPath $Exe)) {
            return $true
        }
    }

    foreach ($User in $WindowsProfiles) {
        $UserExe = Join-Path $User.ProfilePath $UserExecutableRelativePath

        if (Test-Path -LiteralPath $UserExe) {
            return $true
        }
    }

    return $false
}

function Get-ChromiumState {
    param(
        [string]$Browser,
        [string]$UserDataRelativePath,
        [string[]]$MachineExecutables,
        [string]$UserExecutableRelativePath
    )

    $Installed = Test-ChromiumInstalled `
        -MachineExecutables $MachineExecutables `
        -UserExecutableRelativePath $UserExecutableRelativePath

    $ProfileCount = 0
    [long]$TotalPasswords = 0
    $SavedProfiles = New-Object System.Collections.Generic.List[string]

    foreach ($User in $WindowsProfiles) {
        $UserData = Join-Path $User.ProfilePath $UserDataRelativePath

        if (-not (Test-Path -LiteralPath $UserData)) {
            continue
        }

        $BrowserProfiles = @(
            Get-ChildItem `
                -LiteralPath $UserData `
                -Directory `
                -Force `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -eq "Default" -or
                $_.Name -like "Profile *" -or
                (Test-Path -LiteralPath (Join-Path $_.FullName "Login Data")) -or
                (Test-Path -LiteralPath (Join-Path $_.FullName "Login Data For Account"))
            }
        )

        foreach ($Profile in $BrowserProfiles) {
            $ProfileCount++

            $LocalResult = Get-ChromiumDatabaseCount `
                -DatabasePath (Join-Path $Profile.FullName "Login Data") `
                -Browser $Browser `
                -ProfileLabel "$($User.UserName)\$($Profile.Name)\Login Data"

            $AccountResult = Get-ChromiumDatabaseCount `
                -DatabasePath (Join-Path $Profile.FullName "Login Data For Account") `
                -Browser $Browser `
                -ProfileLabel "$($User.UserName)\$($Profile.Name)\Login Data For Account"

            $ProfilePasswords = [long]$LocalResult.Count + [long]$AccountResult.Count
            $TotalPasswords += $ProfilePasswords

            if ($ProfilePasswords -gt 0) {
                $SavedProfiles.Add("$($User.UserName)\$($Profile.Name) ($ProfilePasswords)")
            }
        }
    }

    return [PSCustomObject]@{
        Installed             = $Installed
        Profiles              = $ProfileCount
        PasswordCount         = [long]$TotalPasswords
        SavedPasswordProfiles = @($SavedProfiles)
    }
}

# ============================================================
# Firefox count helpers
# ============================================================

function Get-FirefoxPasswordCount {
    param([string]$LoginFile)

    if (-not (Test-Path -LiteralPath $LoginFile)) {
        return [long]0
    }

    $LastError = $null

    for ($Attempt = 1; $Attempt -le 8; $Attempt++) {
        try {
            $Text = Read-SharedText -Path $LoginFile -Retries 2
            $Json = $Text | ConvertFrom-Json -ErrorAction Stop

            if ($null -eq $Json.logins) {
                return [long]0
            }

            return [long]@($Json.logins).Count
        }
        catch {
            $LastError = $_.Exception.Message

            if ($Attempt -lt 8) {
                Start-Sleep -Milliseconds 200
            }
        }
    }

    throw "Unable to obtain Firefox password count from $LoginFile. Last error: $LastError"
}

function Test-FirefoxInstalled {
    $MachineExecutables = @(
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    )

    foreach ($Exe in $MachineExecutables) {
        if ($Exe -and (Test-Path -LiteralPath $Exe)) {
            return $true
        }
    }

    return $false
}

function Get-FirefoxInstalledVersion {
    $MachineExecutables = @(
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    )

    foreach ($Exe in $MachineExecutables) {
        if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) {
            continue
        }

        try {
            $VersionText = [string](Get-Item -LiteralPath $Exe -ErrorAction Stop).VersionInfo.ProductVersion
            $VersionText = $VersionText.Trim()

            if ($VersionText) {
                return [version]$VersionText
            }
        }
        catch {
            throw "Could not determine Firefox version from $Exe | $($_.Exception.Message)"
        }
    }

    return $null
}

function Get-FirefoxState {
    $Installed = Test-FirefoxInstalled

    $ProfileCount = 0
    [long]$TotalPasswords = 0
    $SavedProfiles = New-Object System.Collections.Generic.List[string]

    foreach ($User in $WindowsProfiles) {
        $ProfilesRoot = Join-Path $User.ProfilePath "AppData\Roaming\Mozilla\Firefox\Profiles"

        if (-not (Test-Path -LiteralPath $ProfilesRoot)) {
            continue
        }

        $Profiles = @(
            Get-ChildItem `
                -LiteralPath $ProfilesRoot `
                -Directory `
                -Force `
                -ErrorAction SilentlyContinue
        )

        foreach ($Profile in $Profiles) {
            $ProfileCount++

            $Count = Get-FirefoxPasswordCount `
                -LoginFile (Join-Path $Profile.FullName "logins.json")

            $TotalPasswords += $Count

            if ($Count -gt 0) {
                $SavedProfiles.Add("$($User.UserName)\$($Profile.Name) ($Count)")
            }
        }
    }

    return [PSCustomObject]@{
        Installed             = $Installed
        Profiles              = $ProfileCount
        PasswordCount         = [long]$TotalPasswords
        SavedPasswordProfiles = @($SavedProfiles)
    }
}

# ============================================================
# Password-store purge helpers
# ============================================================

function Remove-ChromiumPasswordStores {
    param(
        [string]$UserDataRelativePath
    )

    $RemovedFiles = 0

    foreach ($User in $WindowsProfiles) {
        $UserData = Join-Path $User.ProfilePath $UserDataRelativePath

        if (-not (Test-Path -LiteralPath $UserData)) {
            continue
        }

        $BrowserProfiles = @(
            Get-ChildItem `
                -LiteralPath $UserData `
                -Directory `
                -Force `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -eq "Default" -or
                $_.Name -like "Profile *" -or
                (Test-Path -LiteralPath (Join-Path $_.FullName "Login Data")) -or
                (Test-Path -LiteralPath (Join-Path $_.FullName "Login Data For Account"))
            }
        )

        foreach ($Profile in $BrowserProfiles) {
            foreach ($DatabaseName in @("Login Data", "Login Data For Account")) {
                $DatabasePath = Join-Path $Profile.FullName $DatabaseName

                foreach ($Suffix in @("", "-wal", "-shm", "-journal")) {
                    $Target = "$DatabasePath$Suffix"

                    if (Test-Path -LiteralPath $Target) {
                        Remove-Item `
                            -LiteralPath $Target `
                            -Force `
                            -ErrorAction Stop

                        $RemovedFiles++
                    }
                }
            }
        }
    }

    return $RemovedFiles
}

function Remove-FirefoxPasswordStores {
    $RemovedFiles = 0

    foreach ($User in $WindowsProfiles) {
        $ProfilesRoot = Join-Path $User.ProfilePath "AppData\Roaming\Mozilla\Firefox\Profiles"

        if (-not (Test-Path -LiteralPath $ProfilesRoot)) {
            continue
        }

        foreach ($Profile in Get-ChildItem `
            -LiteralPath $ProfilesRoot `
            -Directory `
            -Force `
            -ErrorAction SilentlyContinue) {

            foreach ($FileName in @("logins.json", "logins-backup.json")) {
                $Target = Join-Path $Profile.FullName $FileName

                if (Test-Path -LiteralPath $Target) {
                    Remove-Item `
                        -LiteralPath $Target `
                        -Force `
                        -ErrorAction Stop

                    $RemovedFiles++
                }
            }
        }
    }

    return $RemovedFiles
}

# ============================================================
# Policy helpers
# ============================================================


# ============================================================
# Remediation result helpers
# ============================================================

function New-RemediationErrorResult {
    param(
        [string]$Browser,
        [string]$Message,
        [object]$Installed = $null,
        [object]$BeforeCount = $null,
        [string]$SyncPolicy = "Unknown",
        [string]$PasswordPolicy = "Unknown",
        [bool]$Changed = $false
    )

    return [PSCustomObject]@{
        Browser          = $Browser
        Status           = "ERROR"
        Installed        = $Installed
        BeforeCount      = $BeforeCount
        AfterCount       = $BeforeCount
        SyncPolicy       = $SyncPolicy
        PasswordPolicy   = $PasswordPolicy
        PurgeStatus      = "NotCompleted"
        RemovedFiles     = 0
        Changed          = [bool]$Changed
        ErrorMessage     = $Message
    }
}

function Format-RemediationResult {
    param([object]$Result)

    if ($Result.Status -eq "ERROR") {
        return "$($Result.Browser): ERROR | $($Result.ErrorMessage)"
    }

    $InstalledText = if ($Result.Installed) { "Yes" } else { "No" }

    return (
        "$($Result.Browser): Installed=$InstalledText | " +
        "Password Sync Policy=$($Result.SyncPolicy) | " +
        "Password Saving Policy=$($Result.PasswordPolicy) | " +
        "Passwords Before=$($Result.BeforeCount) | " +
        "Passwords Remaining=$($Result.AfterCount) | " +
        "Purge=$($Result.PurgeStatus)"
    )
}

# ============================================================
# Chromium remediation
# ============================================================

function Invoke-ChromiumRemediation {
    param(
        [string]$Browser,
        [string]$ProcessName,
        [string]$UserDataRelativePath,
        [string]$PolicyPath,
        [string[]]$MachineExecutables,
        [string]$UserExecutableRelativePath
    )

    $Installed = Test-ChromiumInstalled `
        -MachineExecutables $MachineExecutables `
        -UserExecutableRelativePath $UserExecutableRelativePath

    $SyncChanged = $false
    $PasswordChanged = $false
    $Before = $null
    $SyncPolicy = if ($Installed) { "NotEnforced" } else { "N/A" }
    $PasswordPolicy = if ($Installed) { "NotEnforced" } else { "N/A" }

    try {
        # Safety order: disable PASSWORD sync only, then disable password saving.
        # Do this before touching or even depending on successful password-store inspection.
        if ($Installed) {
            $PasswordSyncListPath = Join-Path $PolicyPath "SyncTypesListDisabled"

            $SyncChanged = Add-RegistryListStringVerified `
                -RegistryPath $PasswordSyncListPath `
                -DesiredValue "passwords"

            $SyncPolicy = if (
                Test-RegistryListContainsString `
                    -RegistryPath $PasswordSyncListPath `
                    -DesiredValue "passwords"
            ) { "Enforced" } else { "NotEnforced" }

            if ($SyncPolicy -ne "Enforced") {
                throw "$Browser password-sync policy verification failed"
            }

            $PasswordChanged = Set-RegistryDWORDVerified `
                -RegistryPath $PolicyPath `
                -ValueName "PasswordManagerEnabled" `
                -DesiredValue 0

            $PasswordPolicy = if (
                (Get-RegistryDWORD -RegistryPath $PolicyPath -ValueName "PasswordManagerEnabled") -eq 0
            ) { "Enforced" } else { "NotEnforced" }

            if ($PasswordPolicy -ne "Enforced") {
                throw "$Browser password-manager policy verification failed"
            }
        }

        $Before = Get-ChromiumState `
            -Browser $Browser `
            -UserDataRelativePath $UserDataRelativePath `
            -MachineExecutables $MachineExecutables `
            -UserExecutableRelativePath $UserExecutableRelativePath

        $PurgeStatus = "NotNeeded"
        $RemovedFiles = 0
        [long]$AfterCount = $Before.PasswordCount

        if ($Before.PasswordCount -gt 0) {
            if (Test-BrowserRunning -ProcessName $ProcessName) {
                $PurgeStatus = "Deferred-BrowserRunning"
                Write-Log "$Browser | Password purge deferred because $ProcessName is running"
            }
            else {
                # Installed browsers must have both policies verified before purge.
                if ($Installed) {
                    $PasswordSyncListPath = Join-Path $PolicyPath "SyncTypesListDisabled"

                    if (
                        -not (Test-RegistryListContainsString `
                            -RegistryPath $PasswordSyncListPath `
                            -DesiredValue "passwords") -or
                        (Get-RegistryDWORD -RegistryPath $PolicyPath -ValueName "PasswordManagerEnabled") -ne 0
                    ) {
                        throw "$Browser password policies were not verified before password purge"
                    }
                }

                # Close the race window as much as possible without interrupting users.
                if (Test-BrowserRunning -ProcessName $ProcessName) {
                    $PurgeStatus = "Deferred-BrowserStarted"
                    Write-Log "$Browser | Password purge deferred because $ProcessName started before purge"
                }
                else {
                    $RemovedFiles = Remove-ChromiumPasswordStores `
                        -UserDataRelativePath $UserDataRelativePath

                    $After = Get-ChromiumState `
                        -Browser $Browser `
                        -UserDataRelativePath $UserDataRelativePath `
                        -MachineExecutables $MachineExecutables `
                        -UserExecutableRelativePath $UserExecutableRelativePath

                    $AfterCount = [long]$After.PasswordCount

                    if ($AfterCount -ne 0) {
                        throw "$Browser password purge verification failed. Remaining count: $AfterCount"
                    }

                    $PurgeStatus = "Purged"
                }
            }
        }

        $Changed = (
            $SyncChanged -or
            $PasswordChanged -or
            $PurgeStatus -eq "Purged"
        )

        Write-Log (
            "$Browser | Installed=$Installed | " +
            "PasswordSyncPolicy=$SyncPolicy | PasswordPolicy=$PasswordPolicy | " +
            "Before=$($Before.PasswordCount) | After=$AfterCount | " +
            "Purge=$PurgeStatus | Changed=$Changed"
        )

        return [PSCustomObject]@{
            Browser          = $Browser
            Status           = "OK"
            Installed        = $Installed
            BeforeCount      = [long]$Before.PasswordCount
            AfterCount       = [long]$AfterCount
            SyncPolicy       = $SyncPolicy
            PasswordPolicy   = $PasswordPolicy
            PurgeStatus      = $PurgeStatus
            RemovedFiles     = [int]$RemovedFiles
            Changed          = [bool]$Changed
            ErrorMessage     = $null
        }
    }
    catch {
        $Message = $_.Exception.Message
        $Changed = ($SyncChanged -or $PasswordChanged)
        $BeforeCount = if ($null -ne $Before) { $Before.PasswordCount } else { $null }

        Write-Log "$Browser | ERROR | $Message | ChangedBeforeError=$Changed"

        return New-RemediationErrorResult `
            -Browser $Browser `
            -Message $Message `
            -Installed $Installed `
            -BeforeCount $BeforeCount `
            -SyncPolicy $SyncPolicy `
            -PasswordPolicy $PasswordPolicy `
            -Changed $Changed
    }
}

# ============================================================
# Firefox remediation
# ============================================================

function Invoke-FirefoxRemediation {
    $Installed = Test-FirefoxInstalled
    $PolicyPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox"

    $SyncChanged = $false
    $PasswordChanged = $false
    $Before = $null
    $SyncPolicy = if ($Installed) { "NotEnforced" } else { "N/A" }
    $PasswordPolicy = if ($Installed) { "NotEnforced" } else { "N/A" }

    try {
        # Safety order: disable PASSWORD sync only, then disable password saving.
        if ($Installed) {
            $FirefoxVersion = Get-FirefoxInstalledVersion

            if (-not $FirefoxVersion) {
                throw "Firefox is installed but its version could not be determined"
            }

            if ($FirefoxVersion.Major -lt 150) {
                throw "Firefox $FirefoxVersion does not support the granular enterprise Sync\Passwords policy required for safe password-only sync blocking"
            }

            $FirefoxSyncPolicyPath = Join-Path $PolicyPath "Sync"

            $PasswordSyncChanged = Set-RegistryDWORDVerified `
                -RegistryPath $FirefoxSyncPolicyPath `
                -ValueName "Passwords" `
                -DesiredValue 0

            $SyncLockChanged = Set-RegistryDWORDVerified `
                -RegistryPath $FirefoxSyncPolicyPath `
                -ValueName "Locked" `
                -DesiredValue 1

            $SyncChanged = ($PasswordSyncChanged -or $SyncLockChanged)

            $SyncPolicy = if (
                (Get-RegistryDWORD -RegistryPath $FirefoxSyncPolicyPath -ValueName "Passwords") -eq 0 -and
                (Get-RegistryDWORD -RegistryPath $FirefoxSyncPolicyPath -ValueName "Locked") -eq 1
            ) { "Enforced" } else { "NotEnforced" }

            if ($SyncPolicy -ne "Enforced") {
                throw "Firefox password-sync policy verification failed"
            }

            $PasswordChanged = Set-RegistryDWORDVerified `
                -RegistryPath $PolicyPath `
                -ValueName "PasswordManagerEnabled" `
                -DesiredValue 0

            $PasswordPolicy = if (
                (Get-RegistryDWORD -RegistryPath $PolicyPath -ValueName "PasswordManagerEnabled") -eq 0
            ) { "Enforced" } else { "NotEnforced" }

            if ($PasswordPolicy -ne "Enforced") {
                throw "Firefox password-manager policy verification failed"
            }
        }

        $Before = Get-FirefoxState

        $PurgeStatus = "NotNeeded"
        $RemovedFiles = 0
        [long]$AfterCount = $Before.PasswordCount

        if ($Before.PasswordCount -gt 0) {
            if (Test-BrowserRunning -ProcessName "firefox") {
                $PurgeStatus = "Deferred-BrowserRunning"
                Write-Log "Firefox | Password purge deferred because firefox is running"
            }
            else {
                if ($Installed) {
                    $FirefoxSyncPolicyPath = Join-Path $PolicyPath "Sync"

                    if (
                        (Get-RegistryDWORD -RegistryPath $FirefoxSyncPolicyPath -ValueName "Passwords") -ne 0 -or
                        (Get-RegistryDWORD -RegistryPath $FirefoxSyncPolicyPath -ValueName "Locked") -ne 1 -or
                        (Get-RegistryDWORD -RegistryPath $PolicyPath -ValueName "PasswordManagerEnabled") -ne 0
                    ) {
                        throw "Firefox password policies were not verified before password purge"
                    }
                }

                if (Test-BrowserRunning -ProcessName "firefox") {
                    $PurgeStatus = "Deferred-BrowserStarted"
                    Write-Log "Firefox | Password purge deferred because firefox started before purge"
                }
                else {
                    $RemovedFiles = Remove-FirefoxPasswordStores

                    $After = Get-FirefoxState
                    $AfterCount = [long]$After.PasswordCount

                    if ($AfterCount -ne 0) {
                        throw "Firefox password purge verification failed. Remaining count: $AfterCount"
                    }

                    $PurgeStatus = "Purged"
                }
            }
        }

        $Changed = (
            $SyncChanged -or
            $PasswordChanged -or
            $PurgeStatus -eq "Purged"
        )

        Write-Log (
            "Firefox | Installed=$Installed | " +
            "PasswordSyncPolicy=$SyncPolicy | PasswordPolicy=$PasswordPolicy | " +
            "Before=$($Before.PasswordCount) | After=$AfterCount | " +
            "Purge=$PurgeStatus | Changed=$Changed"
        )

        return [PSCustomObject]@{
            Browser          = "Firefox"
            Status           = "OK"
            Installed        = $Installed
            BeforeCount      = [long]$Before.PasswordCount
            AfterCount       = [long]$AfterCount
            SyncPolicy       = $SyncPolicy
            PasswordPolicy   = $PasswordPolicy
            PurgeStatus      = $PurgeStatus
            RemovedFiles     = [int]$RemovedFiles
            Changed          = [bool]$Changed
            ErrorMessage     = $null
        }
    }
    catch {
        $Message = $_.Exception.Message
        $Changed = ($SyncChanged -or $PasswordChanged)
        $BeforeCount = if ($null -ne $Before) { $Before.PasswordCount } else { $null }

        Write-Log "Firefox | ERROR | $Message | ChangedBeforeError=$Changed"

        return New-RemediationErrorResult `
            -Browser "Firefox" `
            -Message $Message `
            -Installed $Installed `
            -BeforeCount $BeforeCount `
            -SyncPolicy $SyncPolicy `
            -PasswordPolicy $PasswordPolicy `
            -Changed $Changed
    }
}

# ============================================================
# Remediation ledger helper
# ============================================================

function Update-RemediationLedger {
    param([string]$Message)

    $Date = Get-Date -Format "yyyy-MM-dd"
    $Entry = "$Date | $Message"

    Ninja-Property-Set `
        -Name "lastRemediationDate" `
        -Value $Date

    $Existing = ""

    try {
        $Existing = [string](Ninja-Property-Get "remediationSummary")
    }
    catch {
        Write-Log "WARNING | Could not read remediationSummary before append | $($_.Exception.Message)"
        $Existing = ""
    }

    $Existing = $Existing.Trim()

    $NewValue = if ([string]::IsNullOrWhiteSpace($Existing)) {
        $Entry
    }
    else {
        "$Existing`r`n$Entry"
    }

    Ninja-Property-Set `
        -Name "remediationSummary" `
        -Value $NewValue

    Write-Log "Remediation ledger updated | $Entry"
}

# ============================================================
# Main - EACH BROWSER IS AN INDEPENDENT REMEDIATION
# ============================================================

$Results = New-Object System.Collections.Generic.List[object]

# ------------------------------------------------------------
# Chrome
# ------------------------------------------------------------

try {
    $Results.Add(
        (Invoke-ChromiumRemediation `
            -Browser "Chrome" `
            -ProcessName "chrome" `
            -UserDataRelativePath "AppData\Local\Google\Chrome\User Data" `
            -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" `
            -MachineExecutables @(
                "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
            ) `
            -UserExecutableRelativePath "AppData\Local\Google\Chrome\Application\chrome.exe")
    )
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Chrome | ERROR | $Message"
    $Results.Add((New-RemediationErrorResult -Browser "Chrome" -Message $Message))
}

# ------------------------------------------------------------
# Edge
# ------------------------------------------------------------

try {
    $Results.Add(
        (Invoke-ChromiumRemediation `
            -Browser "Edge" `
            -ProcessName "msedge" `
            -UserDataRelativePath "AppData\Local\Microsoft\Edge\User Data" `
            -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
            -MachineExecutables @(
                "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
                "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
            ) `
            -UserExecutableRelativePath "AppData\Local\Microsoft\Edge\Application\msedge.exe")
    )
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Edge | ERROR | $Message"
    $Results.Add((New-RemediationErrorResult -Browser "Edge" -Message $Message))
}

# ------------------------------------------------------------
# Brave
# ------------------------------------------------------------

try {
    $Results.Add(
        (Invoke-ChromiumRemediation `
            -Browser "Brave" `
            -ProcessName "brave" `
            -UserDataRelativePath "AppData\Local\BraveSoftware\Brave-Browser\User Data" `
            -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave" `
            -MachineExecutables @(
                "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
                "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe"
            ) `
            -UserExecutableRelativePath "AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe")
    )
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Brave | ERROR | $Message"
    $Results.Add((New-RemediationErrorResult -Browser "Brave" -Message $Message))
}

# ------------------------------------------------------------
# Firefox
# ------------------------------------------------------------

try {
    $Results.Add((Invoke-FirefoxRemediation))
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Firefox | ERROR | $Message"
    $Results.Add((New-RemediationErrorResult -Browser "Firefox" -Message $Message))
}

# ============================================================
# Custom field / ledger
# ============================================================

$AnyErrors = @(
    $Results | Where-Object { $_.Status -eq "ERROR" }
).Count -gt 0

$AnyChanges = @(
    $Results |
        Where-Object { $_.Changed -eq $true }
).Count -gt 0

$AnyDeferred = @(
    $Results |
        Where-Object {
            $_.Status -eq "OK" -and
            $_.PurgeStatus -like "Deferred-*"
        }
).Count -gt 0

if ($AnyChanges) {
    $LedgerParts = New-Object System.Collections.Generic.List[string]

    foreach ($Result in $Results) {
        if (-not $Result.Changed) {
            continue
        }

        $Part = "$($Result.Browser):PasswordSync=$($Result.SyncPolicy),PasswordPolicy=$($Result.PasswordPolicy)"

        if ($Result.PurgeStatus -eq "Purged") {
            $Part += ",PasswordsRemoved=$($Result.BeforeCount)"
        }
        elseif ($Result.PurgeStatus -like "Deferred-*") {
            $Part += ",PurgeDeferred"
        }

        $LedgerParts.Add($Part)
    }

    $LedgerMessage = "Browser password remediation | " + ($LedgerParts -join " | ")

    try {
        Update-RemediationLedger -Message $LedgerMessage
    }
    catch {
        Write-Log "WARNING | Failed to update remediation ledger | $($_.Exception.Message)"
    }
}

# ============================================================
# Final output token
# ============================================================

if ($AnyErrors) {
    $Token = "ERROR"
}
elseif ($AnyChanges -or $AnyDeferred) {
    $Token = "RESULT"
}
else {
    $Token = "NO_ACTION"
}

$OutputLines = New-Object System.Collections.Generic.List[string]
$OutputLines.Add($Token)

foreach ($Result in $Results) {
    $OutputLines.Add((Format-RemediationResult -Result $Result))
}

if ($AnyDeferred) {
    $OutputLines.Add("NOTE: Password purge deferred for running browsers. Policies are enforced; rerun after the browser is fully closed.")
}

Write-Output ($OutputLines -join "`r`n")

# ============================================================
# Cleanup
# ============================================================

Remove-Item `
    -LiteralPath $TempRoot `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

exit 0