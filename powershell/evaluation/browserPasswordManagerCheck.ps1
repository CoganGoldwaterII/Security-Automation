# ============================================================================
# NAME: Browser and Native Password Manager Detection
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Windows Endpoints / NinjaOne Automation
#
# VARIABLES:
#   Required: None
#   Optional: None
#
# OUTPUT TOKENS:
#   TRIGGER   | Stored passwords detected or machine policy not enforced
#   NO_ACTION | No stored passwords and required policies enforced
#   ERROR     | Browser checks incomplete without a confirmed trigger
#
#   Actual output begins with a bare token followed by browser details.
#   Script exits 0 upon normal completion.
#
# CUSTOM FIELDS:
#   Reads: None
#   Writes: browsermanagedPasswordsDetected
#
# FILE TRANSFERS:
#   Required: No
#   Files: None
#
# LOGGING PATH:
#   C:\MME\AutoLogs\Browser_Password_Evaluation.log
#
# DESCRIPTION:
#   Independently evaluates Chrome, Edge, Brave, and Firefox for:
#     - Installed state
#     - Browser profile count
#     - Mandatory machine-level password-saving policy
#     - Total stored-password count
#     - Profiles containing stored passwords
#
#   TRIGGER conditions:
#     - Any browser profile contains stored passwords.
#     - Any installed browser lacks mandatory machine enforcement
#       of PasswordManagerEnabled=0.
#
#   Returns ERROR only when no trigger condition is confirmed
#   and one or more browser evaluations fail.
#
#   Returns NO_ACTION when all browser evaluations complete,
#   no stored passwords are found, and installed browsers
#   have the required machine policy enforced.
#
#   Uses the Windows SQLite API to create temporary snapshots
#   of Chromium login databases. Falls back to shared-read
#   snapshots when necessary.
#
#   Reads Firefox logins.json files for stored-password counts.
#   Does not decrypt or output password contents or credentials.
#
#   Writes detected password counts to the NinjaOne device
#   custom field browsermanagedPasswordsDetected.
#
#   Removes temporary database snapshots during normal cleanup.
#   Does not stop browsers or modify stored browser credentials.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$LogRoot = "C:\MME\AutoLogs"
$LogPath = Join-Path $LogRoot "Browser_Password_Evaluation.log"
$TempRoot = Join-Path $env:TEMP ("MME-BrowserPasswordEval-" + [guid]::NewGuid().ToString("N"))

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

"Browser Password Evaluation - $(Get-Date -Format s)" |
    Set-Content -Path $LogPath -Encoding UTF8

function Write-Log {
    param([string]$Message)

    "$(Get-Date -Format s) | $Message" |
        Add-Content -Path $LogPath -Encoding UTF8
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
# Registry helpers
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

        $Value = Get-ItemPropertyValue `
            -LiteralPath $RegistryPath `
            -Name $ValueName `
            -ErrorAction Stop

        return [int]$Value
    }
    catch {
        return $null
    }
}

# ============================================================
# Windows built-in SQLite API
# ============================================================

$SQLiteInitError = $null

if (-not ("MME.WinSQLite" -as [type])) {

    $SQLiteCode = @'
using System;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

namespace MME
{
    public static class WinSQLite
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
                    // Small page batches keep source read locks short.
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
# Chromium password-count helpers
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
            return [long][MME.WinSQLite]::ScalarInt64(
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

    # Copy transaction data when present. Do not copy -shm; SQLite can rebuild
    # shared-memory state for our writable temporary snapshot.
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

    # --------------------------------------------------------
    # Primary: SQLite Online Backup API against the live DB.
    # --------------------------------------------------------

    $BackupError = $null

    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        $SnapshotPath = Join-Path $TempRoot ([guid]::NewGuid().ToString("N") + ".sqlite")

        try {
            [MME.WinSQLite]::Backup(
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

    # --------------------------------------------------------
    # Fallback for browsers such as Brave that may hold a
    # persistent SQLite lock: copy the live files through a
    # shared-read handle and query only the temporary copy.
    #
    # Require the same count from two consecutive snapshots.
    # This prevents a changing live DB from producing a one-off
    # inconsistent result.
    # --------------------------------------------------------

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

# ============================================================
# Chromium settings / profile helpers
# ============================================================

function Get-ChromiumBrowserResult {
    param(
        [string]$Browser,
        [string]$UserDataRelativePath,
        [string]$PolicyPath,
        [string[]]$MachineExecutables,
        [string]$UserExecutableRelativePath
    )

    # Installed means an executable exists. Residual profile data is still
    # scanned for stored passwords even if the browser was later uninstalled.
    $Installed = $false

    foreach ($Exe in $MachineExecutables) {
        if ($Exe -and (Test-Path -LiteralPath $Exe)) {
            $Installed = $true
            break
        }
    }

    if (-not $Installed) {
        foreach ($User in $WindowsProfiles) {
            $UserExe = Join-Path $User.ProfilePath $UserExecutableRelativePath

            if (Test-Path -LiteralPath $UserExe) {
                $Installed = $true
                break
            }
        }
    }

    $MachinePolicy = Get-RegistryDWORD `
        -RegistryPath $PolicyPath `
        -ValueName "PasswordManagerEnabled"

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

            $ProfilePasswords = [long]0

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

            Write-Log (
                "$Browser | User=$($User.UserName) | Profile=$($Profile.Name) | " +
                "PasswordManagerPolicy=$MachinePolicy | Passwords=$ProfilePasswords | " +
                "LocalMethod=$($LocalResult.Method) | AccountMethod=$($AccountResult.Method)"
            )

            if ($ProfilePasswords -gt 0) {
                $SavedProfiles.Add("$($User.UserName)\$($Profile.Name) ($ProfilePasswords)")
            }
        }
    }

    if (-not $Installed) {
        $PasswordSaving = "N/A"
    }
    elseif ($MachinePolicy -eq 0) {
        $PasswordSaving = "Disabled"
    }
    else {
        # Not configured or explicitly enabled means the browser is not
        # centrally prevented from saving passwords.
        $PasswordSaving = "Enabled"
    }

    return [PSCustomObject]@{
        Browser               = $Browser
        Status                = "OK"
        Installed             = $Installed
        Profiles              = $ProfileCount
        PasswordSaving        = $PasswordSaving
        PasswordCount         = [long]$TotalPasswords
        SavedPasswordProfiles = @($SavedProfiles)
        ErrorMessage          = $null
    }
}

# ============================================================
# Firefox helpers
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

function Get-FirefoxResult {
    $Installed = $false

    $MachineExecutables = @(
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    )

    foreach ($Exe in $MachineExecutables) {
        if ($Exe -and (Test-Path -LiteralPath $Exe)) {
            $Installed = $true
            break
        }
    }

    $MachinePolicy = Get-RegistryDWORD `
        -RegistryPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox" `
        -ValueName "PasswordManagerEnabled"

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

            Write-Log (
                "Firefox | User=$($User.UserName) | Profile=$($Profile.Name) | " +
                "PasswordManagerPolicy=$MachinePolicy | Passwords=$Count"
            )

            if ($Count -gt 0) {
                $SavedProfiles.Add("$($User.UserName)\$($Profile.Name) ($Count)")
            }
        }
    }

    if (-not $Installed) {
        $PasswordSaving = "N/A"
    }
    elseif ($MachinePolicy -eq 0) {
        $PasswordSaving = "Disabled"
    }
    else {
        # Not configured or explicitly enabled means Firefox is not
        # centrally prevented from saving passwords.
        $PasswordSaving = "Enabled"
    }

    return [PSCustomObject]@{
        Browser               = "Firefox"
        Status                = "OK"
        Installed             = $Installed
        Profiles              = $ProfileCount
        PasswordSaving        = $PasswordSaving
        PasswordCount         = [long]$TotalPasswords
        SavedPasswordProfiles = @($SavedProfiles)
        ErrorMessage          = $null
    }
}

# ============================================================
# Result helpers
# ============================================================

function New-BrowserErrorResult {
    param(
        [string]$Browser,
        [string]$Message
    )

    return [PSCustomObject]@{
        Browser               = $Browser
        Status                = "ERROR"
        Installed             = $null
        Profiles              = $null
        PasswordSaving        = $null
        PasswordCount         = $null
        SavedPasswordProfiles = @()
        ErrorMessage          = $Message
    }
}

function Format-BrowserResult {
    param([object]$Result)

    if ($Result.Status -eq "ERROR") {
        return "$($Result.Browser): ERROR | $($Result.ErrorMessage)"
    }

    $InstalledText = if ($Result.Installed) { "Yes" } else { "No" }

    $Output = "$($Result.Browser): Installed=$InstalledText | Profiles=$($Result.Profiles) | Password Saving=$($Result.PasswordSaving) | Passwords Count=$($Result.PasswordCount)"

    if ($Result.SavedPasswordProfiles.Count -gt 0) {
        $Output += "`r`n  Saved Password Profiles: " + ($Result.SavedPasswordProfiles -join ", ")
    }

    return $Output
}

# ============================================================
# Main - EACH BROWSER IS AN INDEPENDENT CHECK
# ============================================================

$Results = New-Object System.Collections.Generic.List[object]

# ------------------------------------------------------------
# Chrome
# ------------------------------------------------------------

try {
    $ChromeResult = Get-ChromiumBrowserResult `
        -Browser "Chrome" `
        -UserDataRelativePath "AppData\Local\Google\Chrome\User Data" `
        -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" `
        -MachineExecutables @(
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        ) `
        -UserExecutableRelativePath "AppData\Local\Google\Chrome\Application\chrome.exe"

    $Results.Add($ChromeResult)
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Chrome | ERROR | $Message"
    $Results.Add((New-BrowserErrorResult -Browser "Chrome" -Message $Message))
}

# ------------------------------------------------------------
# Edge
# ------------------------------------------------------------

try {
    $EdgeResult = Get-ChromiumBrowserResult `
        -Browser "Edge" `
        -UserDataRelativePath "AppData\Local\Microsoft\Edge\User Data" `
        -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" `
        -MachineExecutables @(
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
        ) `
        -UserExecutableRelativePath "AppData\Local\Microsoft\Edge\Application\msedge.exe"

    $Results.Add($EdgeResult)
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Edge | ERROR | $Message"
    $Results.Add((New-BrowserErrorResult -Browser "Edge" -Message $Message))
}

# ------------------------------------------------------------
# Brave
# ------------------------------------------------------------

try {
    $BraveResult = Get-ChromiumBrowserResult `
        -Browser "Brave" `
        -UserDataRelativePath "AppData\Local\BraveSoftware\Brave-Browser\User Data" `
        -PolicyPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave" `
        -MachineExecutables @(
            "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
            "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe"
        ) `
        -UserExecutableRelativePath "AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe"

    $Results.Add($BraveResult)
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Brave | ERROR | $Message"
    $Results.Add((New-BrowserErrorResult -Browser "Brave" -Message $Message))
}

# ------------------------------------------------------------
# Firefox
# ------------------------------------------------------------

try {
    $FirefoxResult = Get-FirefoxResult
    $Results.Add($FirefoxResult)
}
catch {
    $Message = $_.Exception.Message
    Write-Log "Firefox | ERROR | $Message"
    $Results.Add((New-BrowserErrorResult -Browser "Firefox" -Message $Message))
}

# ============================================================
# Final evaluation token
# ============================================================

$AnyStoredPasswords = @(
    $Results |
        Where-Object {
            $_.Status -eq "OK" -and
            $null -ne $_.PasswordCount -and
            $_.PasswordCount -gt 0
        }
).Count -gt 0

$AnyPolicyNotEnforced = @(
    $Results |
        Where-Object {
            $_.Status -eq "OK" -and
            $_.Installed -eq $true -and
            $_.PasswordSaving -ne "Disabled"
        }
).Count -gt 0

$AnyErrors = @(
    $Results |
        Where-Object { $_.Status -eq "ERROR" }
).Count -gt 0

if ($AnyStoredPasswords -or $AnyPolicyNotEnforced) {
    $Token = "TRIGGER"
}
elseif ($AnyErrors) {
    $Token = "ERROR"
}
else {
    $Token = "NO_ACTION"
}

$OutputLines = New-Object System.Collections.Generic.List[string]
$OutputLines.Add($Token)

foreach ($Result in $Results) {
    $OutputLines.Add((Format-BrowserResult -Result $Result))
}

# ============================================================
# Write detected password counts to Ninja custom field
# ============================================================

$DetectedPasswords = @(
    $Results |
    Where-Object {
        $_.Installed -and
        $_.PasswordCount -gt 0
    } |
    ForEach-Object {
        "$($_.Browser): $($_.PasswordCount)"
    }
)

if ($DetectedPasswords.Count -gt 0) {
    $CustomFieldValue = $DetectedPasswords -join " | "
}
else {
    $CustomFieldValue = "None"
}

try {
    Ninja-Property-Set `
        -Name "browsermanagedPasswordsDetected" `
        -Value $CustomFieldValue

    Write-Log "Custom field browsermanagedPasswordsDetected updated: $CustomFieldValue"
}
catch {
    Write-Log "WARNING | Failed to update browsermanagedPasswordsDetected | $($_.Exception.Message)"
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