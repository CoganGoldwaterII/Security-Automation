# ============================================================================
# NAME: AUTOMATION - Video Port Inventory
# AUTHORED BY:
# TYPE: Standalone inventory / custom-field reporting
# SCOPE: Windows / NinjaOne SYSTEM / Local endpoint
# VARIABLES: None
# OUTPUT TOKENS: RESULT | ERROR
# CUSTOM FIELDS: videoPorts (Text by default; Multi-line optional; read/write)
# LOGGING PATH: C:\MME\AutoLogs\Video_Port_Inventory.log
# DESCRIPTION: Count active Windows display connections by output technology.
#              Inventory firmware, AMD board layouts and NVIDIA VBIOS DCB
#              connector records on supported desktops. Count each board once.
#              Never count NVIDIA logical output IDs or Windows display targets
#              as physical sockets. Reject ambiguous DCB tables; preserve known
#              board-reported counts as Partial when a source is unavailable.
#              Cross-check connected target/base types without adding sockets.
#              Unresolved discrepancies flagged Check. Firmware ownership and
#              completeness are not guaranteed. VBT/ACPI evidence is log-only.
#              Overwrite and verify videoPorts. No downloads, external lookups,
#              display changes or ledger changes. Physically validate all results!
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ScriptBuild = '2026.11.25-v15'
$Disclaimer = 'Physically validate all results!'
$LogFile = 'C:\MME\AutoLogs\Video_Port_Inventory.log'
$Field = 'videoPorts'
# Keep false for existing Text field; true only for a Multi-line field.
$UseMultilineField = $false
$Final = 'ERROR | Inventory did not complete'
$script:LogFailed = $false

function Safe-Text {
    param([AllowNull()][object]$Value)
    return (([string]$Value -replace '[\r\n|]+', ' ') -replace '\s{2,}', ' ').Trim()
}

function Write-Log {
    param([string]$Level, [string]$Message)
    try {
        Add-Content -LiteralPath $LogFile -Encoding UTF8 -Value (
            '{0} | {1} | {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, (Safe-Text $Message)
        ) -ErrorAction Stop
    } catch {
        $script:LogFailed = $true
    }
}

function Get-DisplayType {
    param([uint32]$Code)
    switch ($Code) {
        0 { 'VGA' }
        1 { 'S-Video' }
        2 { 'Composite' }
        3 { 'Component' }
        4 { 'DVI' }
        5 { 'HDMI' }
        6 { 'Internal' }
        8 { 'D-JPN' }
        9 { 'SDI' }
        10 { 'DP' }
        11 { 'Internal' }
        12 { 'UDI' }
        13 { 'Internal' }
        14 { 'TV dongle' }
        15 { 'Wireless' }
        16 { 'Indirect wired' }
        17 { 'Virtual' }
        18 { 'DP USB tunnel' }
        2147483648 { 'Internal' }
        default { 'Other video' }
    }
}

# Read-only board topology probes. Never treat these records as verified sockets.
function Write-EvidenceBlob {
    param([string]$Name,[byte[]]$Bytes)
    $sha=[Security.Cryptography.SHA256]::Create()
    $ms=New-Object IO.MemoryStream
    try {
        $hash=[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')
        if ($script:EvidenceHashes.ContainsKey($hash)) { Write-Log INFO "Evidence duplicate: $Name; SHA256=$hash"; return }
        $gz=[IO.Compression.GZipStream]::new($ms,[IO.Compression.CompressionMode]::Compress,$true)
        try { $gz.Write($Bytes,0,$Bytes.Length) } finally { $gz.Dispose() }
        $encoded=[Convert]::ToBase64String($ms.ToArray())
        if ($script:EvidenceChars+$encoded.Length -gt 1500000) { Write-Log WARN "Evidence budget exceeded: $Name"; return }
        $script:EvidenceHashes[$hash]=$true
        $script:EvidenceChars+=$encoded.Length
        $parts=[int][Math]::Ceiling($encoded.Length/2048.0)
        Write-Log INFO "Evidence Name=$Name; SHA256=$hash; Bytes=$($Bytes.Length); Encoding=GzipBase64; Parts=$parts"
        for ($i=0;$i -lt $parts;$i++) {
            $offset=$i*2048; $chunk=$encoded.Substring($offset,[Math]::Min(2048,$encoded.Length-$offset))
            Write-Log INFO "EVIDENCE SHA256=$hash; Part=$($i+1)/$parts; Data=$chunk"
        }
    } finally { $sha.Dispose(); $ms.Dispose() }
}
function Read-IntelVbtEvidence {
    param([byte[]]$Bytes,[string]$Source)
    # VBT header and BDB general definitions; child devices describe routing.
    if ($Bytes.Length -lt 48) { return }
    $ascii=[Text.Encoding]::ASCII.GetString($Bytes); $start=0; $found=0
    while ($start -lt $ascii.Length) {
        $p=$ascii.IndexOf('$VBT',$start,[StringComparison]::Ordinal)
        if ($p -lt 0) { break }; $start=$p+4
        if ($p+48 -gt $Bytes.Length) { continue }
        $header=[BitConverter]::ToUInt16($Bytes,$p+22); $size=[BitConverter]::ToUInt16($Bytes,$p+24)
        $rel=[BitConverter]::ToUInt32($Bytes,$p+28)
        if ($header -lt 48 -or $size -lt $header -or $p+$size -gt $Bytes.Length -or $rel -lt $header -or $rel+22 -gt $size) { continue }
        $bdb=$p+[int]$rel
        if ($ascii.Substring($bdb,15) -cne 'BIOS_DATA_BLOCK') { continue }
        $ver=[BitConverter]::ToUInt16($Bytes,$bdb+16); $bh=[BitConverter]::ToUInt16($Bytes,$bdb+18); $bs=[BitConverter]::ToUInt16($Bytes,$bdb+20)
        if ($bh -lt 22 -or $bs -lt $bh -or $rel+$bs -gt $size) { continue }
        $found++; $script:VbtFound++
        $vbt=New-Object byte[] $size; [Array]::Copy($Bytes,$p,$vbt,0,$size)
        $sum=0; foreach ($b in $vbt) { $sum=($sum+[int]$b) -band 255 }
        Write-Log INFO "Intel VBT Source=$Source; Offset=$p; Size=$size; BDBVersion=$ver; ChecksumRemainder=$sum; candidate topology only"
        Write-EvidenceBlob -Name "IntelVBT:$Source" -Bytes $vbt
        $pos=$bdb+$bh; $end=$bdb+$bs
        while ($pos+3 -le $end) {
            $block=[int]$Bytes[$pos]; $len=[int][BitConverter]::ToUInt16($Bytes,$pos+1); $data=$pos+3
            if ($data+$len -gt $end) { Write-Log WARN 'VBT block out of bounds.'; break }
            if ($block -eq 2) {
                if ($len -lt 5) { Write-Log WARN 'VBT general definitions truncated.'; break }
                $stride=[int]$Bytes[$data+4]
                if ($stride -lt 4 -or ($len-5)%$stride -ne 0) { Write-Log WARN "VBT child record size unresolved: $stride"; break }
                $n=[int](($len-5)/$stride)
                for ($j=0;$j -lt $n;$j++) {
                    $e=$data+5+$j*$stride; $handle=[BitConverter]::ToUInt16($Bytes,$e); $type=[BitConverter]::ToUInt16($Bytes,$e+2)
                    if ($type -eq 0) { continue }
                    $dvo='Unknown'; if ($stride -ge 17 -and $ver -ge 155) { $dvo=[string]$Bytes[$e+16] }
                    Write-Log INFO ("Intel VBT child Index={0}; Handle=0x{1:X4}; DeviceType=0x{2:X4}; DvoPort={3}; AnalogFlag={4}; DPFlag={5}; TMDSFlag={6}; Raw={7}" -f $j,$handle,$type,$dvo,[bool]($type -band 1),[bool]($type -band 4),[bool]($type -band 16),[BitConverter]::ToString($Bytes,$e,$stride))
                }
                break
            }
            if ($block -eq 53) { Write-Log WARN 'VBT variable MIPI block encountered; no further decoding.'; break }
            $pos=$data+$len
        }
        if ($found -ge 8) { break }
    }
}
function Read-NvidiaDcbEvidence {
    param([byte[]]$Bytes,[string]$Source,[string]$InstanceId)
    # NVIDIA DCB 4.x public spec: legacy ROM, device entries and connector table.
    # Accept only a matching adapter cache and ordinary add-in card layouts.
    # One connector-table index, not one display path, is one board candidate.
    if ($Bytes.Length -lt 64 -or $Bytes[0] -ne 0x55 -or $Bytes[1] -ne 0xaa) { throw 'No supported PCI ROM header.' }
    $pcir=[int][BitConverter]::ToUInt16($Bytes,0x18)
    if ($pcir -lt 0x1a -or $pcir+0x18 -gt $Bytes.Length -or [Text.Encoding]::ASCII.GetString($Bytes,$pcir,4) -cne 'PCIR') { throw 'Invalid PCI ROM data header.' }
    if ($InstanceId -notmatch '(?i)VEN_10DE&DEV_([0-9A-F]{4})') { throw 'NVIDIA device ID unavailable.' }
    $expected=[Convert]::ToUInt16($Matches[1],16)
    if ([BitConverter]::ToUInt16($Bytes,$pcir+4) -ne 0x10de -or [BitConverter]::ToUInt16($Bytes,$pcir+6) -ne $expected) { throw 'Cached ROM does not match adapter PCI ID.' }
    $size=[int][BitConverter]::ToUInt16($Bytes,$pcir+0x10)*512
    if ($size -lt 64 -or $size -gt $Bytes.Length -or $pcir+0x18 -gt $size -or $Bytes[$pcir+0x14] -ne 0) { throw 'Unsupported/truncated legacy ROM image.' }
    # PCI legacy ROM checksum. A failed check never contributes socket counts.
    $sum=0; for ($i=0;$i -lt $size;$i++) { $sum=($sum+[int]$Bytes[$i]) -band 255 }
    if ($sum -ne 0) { throw 'Cached legacy ROM checksum failed.' }
    $dcb=[int][BitConverter]::ToUInt16($Bytes,0x36)
    if ($dcb -lt 0x38 -or $dcb+23 -gt $size -or $Bytes[$dcb] -lt 0x40 -or $Bytes[$dcb] -ge 0x50 -or [BitConverter]::ToUInt32($Bytes,$dcb+6) -ne 0x4edcbdcb) { throw 'Supported DCB 4.x signature unavailable.' }
    $dh=[int]$Bytes[$dcb+1]; $dn=[int]$Bytes[$dcb+2]; $ds=[int]$Bytes[$dcb+3]
    if ($dh -lt 23 -or $ds -ne 8 -or $dn -lt 1 -or $dn -gt 64 -or $dcb+$dh+$dn*$ds -gt $size) { throw 'Invalid DCB device table.' }
    $conn=[int][BitConverter]::ToUInt16($Bytes,$dcb+0x14)
    if ($conn -lt 0x38 -or $conn+5 -gt $size) { throw 'Invalid connector table pointer.' }
    $ver=[int]$Bytes[$conn]; $hdr=[int]$Bytes[$conn+1]; $n=[int]$Bytes[$conn+2]; $stride=[int]$Bytes[$conn+3]
    if ($ver -ne 0x40 -or $hdr -lt 5 -or $stride -ne 4 -or $n -lt 1 -or $n -gt 16 -or $conn+$hdr+$n*$stride -gt $size) { throw 'Malformed/unsupported connector table.' }
    $platform=[int]$Bytes[$conn+4]
    if ($platform -notin @(0,1)) { throw 'Nonstandard/configurable NVIDIA board layout.' }
    $referenced=@{}
    for ($i=0;$i -lt $dn;$i++) {
        $path=[BitConverter]::ToUInt32($Bytes,$dcb+$dh+$i*$ds)
        $kind=$path -band 15
        if ($kind -eq 14) { break }
        if ($kind -eq 15 -or ($path -band 0x10000000) -ne 0) { continue }
        if ($kind -notin @(0,1,2,3,5,6)) { throw "Unknown DCB display path type $kind" }
        $index=($path -shr 12) -band 15
        if ($index -ge $n) { throw 'DCB display path refers outside connector table.' }
        $referenced[[int]$index]=$true
    }
    $counts=@{}; $locations=@{}; $unresolved=$false
    Write-Log INFO ("NVIDIA DCB Source={0}; Adapter={1}; Version=0x{2:X2}; Platform=0x{3:X2}; Entries={4}" -f $Source,$InstanceId,$ver,$platform,$n)
    for ($i=0;$i -lt $n;$i++) {
        $e=$conn+$hdr+$i*$stride; $code=[int]$Bytes[$e]; $loc=[int]$Bytes[$e+1] -band 15
        # Maintain existing family labels (mini-DP grouped with DP).
        $type=switch ($code) { 0x00 {'VGA'} 0x01 {'DVI'} 0x30 {'DVI'} 0x31 {'DVI'} 0x46 {'DP'} 0x48 {'DP'} 0x61 {'HDMI'} 0x63 {'HDMI'} 0xFF {'Skip'} 0x70 {'Virtual'} default {'Unknown'} }
        Write-Log INFO ("NVIDIA DCB connector Index={0}; Code=0x{1:X2}; Location={2}; Type={3}; Referenced={4}; Raw={5}" -f $i,$code,$loc,$type,$referenced.ContainsKey($i),[BitConverter]::ToString($Bytes,$e,$stride))
        if ($type -in @('Skip','Virtual')) { if ($referenced.ContainsKey($i)) { $unresolved=$true }; continue }
        # Unreferenced entries and colliding bracket locations cannot establish
        # unique installed sockets. Reject the board rather than guess.
        if ($type -eq 'Unknown' -or -not $referenced.ContainsKey($i) -or $locations.ContainsKey($loc)) { $unresolved=$true; continue }
        $locations[$loc]=$true
        if (-not $counts.ContainsKey($type)) { $counts[$type]=0 }; $counts[$type]++
    }
    $table=New-Object byte[] ($hdr+$n*$stride); [Array]::Copy($Bytes,$conn,$table,0,$table.Length)
    Write-EvidenceBlob -Name "NvidiaDCB:$InstanceId" -Bytes $table
    $text=(@(foreach ($type in ($counts.Keys | Sort-Object)) { '{0} x{1}' -f $type,$counts[$type] }) -join ', ')
    if ($unresolved -or $counts.Count -eq 0) { throw "NVIDIA DCB ambiguous or incomplete: $text" }
    # Repeated identical registry reads are not independent boards. Conflicting
    # caches for one adapter invalidate the candidate for the entire run.
    $identity=[BitConverter]::ToString($table)
    if ($script:DcbRejected.ContainsKey($InstanceId)) { return }
    if ($script:DcbIdentities.ContainsKey($InstanceId) -and $script:DcbIdentities[$InstanceId] -cne $identity) {
        $script:DcbRejected[$InstanceId]=$true
        $script:DcbCandidates.Remove($InstanceId)
        throw 'Conflicting cached connector tables for one NVIDIA adapter.'
    }
    $script:DcbIdentities[$InstanceId]=$identity
    $script:DcbCandidates[$InstanceId]=$counts.Clone()
    Write-Log INFO "NVIDIA DCB board candidate: Adapter=$InstanceId; $text; cached firmware not independently verified."
}
function Inspect-AcpiTable {
    param([byte[]]$Bytes,[string]$Source)
    if ($Bytes.Length -lt 36 -or $Bytes.Length -gt 2097152) { return }
    $sig=[Text.Encoding]::ASCII.GetString($Bytes,0,4)
    if ($sig -notin @('DSDT','SSDT') -or [BitConverter]::ToUInt32($Bytes,4) -ne $Bytes.Length) { return }
    $ascii=[Text.Encoding]::ASCII.GetString($Bytes)
    $hits=@(foreach ($token in @('_DOD','_DOS','_ADR','_DCS','_DGS','_DSS','GFX0','IGPU','PEGP','VGA_','CRT_')) { $n=[regex]::Matches($ascii,[regex]::Escape($token)).Count; if ($n -gt 0) { "$token=$n" } })
    $sum=0; foreach ($b in $Bytes) { $sum=($sum+[int]$b) -band 255 }
    Write-Log INFO "ACPI AML Source=$Source; Signature=$sig; Bytes=$($Bytes.Length); ChecksumRemainder=$sum; Tokens=$($hits -join ','); names are not evaluated devices."
    if ($ascii -match '_DOD|_DOS|GFX0|IGPU|PEGP|VGA_|CRT_') { Write-EvidenceBlob -Name "ACPI:$Source" -Bytes $Bytes }
    Read-IntelVbtEvidence -Bytes $Bytes -Source "ACPI:$Source"
}
function Read-AcpiEvidence {
    if (-not ('MME.VideoInventory.FirmwareRead' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace MME.VideoInventory {
    public static class FirmwareRead {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint EnumSystemFirmwareTables(uint provider, [Out] byte[] buffer, uint size);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint GetSystemFirmwareTable(uint provider, uint id, [Out] byte[] buffer, uint size);
    }
}
'@
    }
    $provider=[uint32]0x41435049
    $n=[MME.VideoInventory.FirmwareRead]::EnumSystemFirmwareTables($provider,$null,0)
    if ($n -eq 0 -or $n -gt 65536 -or $n%4 -ne 0) { throw "Invalid ACPI enumeration size $n" }
    $ids=New-Object byte[] $n
    if ([MME.VideoInventory.FirmwareRead]::EnumSystemFirmwareTables($provider,$ids,$n) -ne $n) { throw 'ACPI enumeration failed or changed.' }
    $sigs=@(for ($i=0;$i -lt $n;$i+=4) { [Text.Encoding]::ASCII.GetString($ids,$i,4) })
    Write-Log INFO "ACPI signatures: $($sigs -join ',')"
    foreach ($sig in @('DSDT','SSDT')) {
        $occ=@($sigs | Where-Object { $_ -eq $sig }).Count
        if ($occ -eq 0) { Write-Log WARN "ACPI $sig absent from API enumeration; attempting direct read." }
        if ($occ -gt 1) { Write-Log WARN "ACPI $sig occurrences=$occ; API returns first only." }
        try {
            $id=[BitConverter]::ToUInt32([Text.Encoding]::ASCII.GetBytes($sig),0)
            $size=[MME.VideoInventory.FirmwareRead]::GetSystemFirmwareTable($provider,$id,$null,0)
            if ($size -lt 36 -or $size -gt 2097152) { throw "Invalid table size $size" }
            $bytes=New-Object byte[] $size
            if ([MME.VideoInventory.FirmwareRead]::GetSystemFirmwareTable($provider,$id,$bytes,$size) -ne $size) { throw 'ACPI table read failed or changed size.' }
            Inspect-AcpiTable -Bytes $bytes -Source "API:$sig"
        } catch { Write-Log WARN "ACPI $sig unavailable: $($_.Exception.Message)" }
    }
}
function Invoke-BoardDiagnostics {
    $script:EvidenceHashes=@{}; $script:EvidenceChars=0; $script:DcbCandidates=@{}; $script:DcbIdentities=@{}; $script:DcbRejected=@{}; $script:VbtFound=0
    Write-Log INFO 'Board diagnostic start; no settings or custom-field changes.'
    try { Read-AcpiEvidence } catch { Write-Log WARN "ACPI API unavailable: $($_.Exception.Message)" }
    foreach ($name in @('DSDT','SSDT')) {
        try {
            $root="HKLM:\HARDWARE\ACPI\$name"
            if (-not (Test-Path -LiteralPath $root)) { Write-Log INFO "ACPI registry $name absent."; continue }
            $keys=@(Get-Item -LiteralPath $root; Get-ChildItem -LiteralPath $root -Recurse | Select-Object -First 128)
            foreach ($key in $keys) { foreach ($v in $key.GetValueNames()) {
                if ($key.GetValueKind($v) -eq [Microsoft.Win32.RegistryValueKind]::Binary) { Inspect-AcpiTable -Bytes ($key.GetValue($v)) -Source "Registry:$($key.Name):$v" }
            } }
        } catch { Write-Log WARN "ACPI registry $name unavailable: $($_.Exception.Message)" }
    }
    try { foreach ($r in @(Get-CimInstance -ClassName Win32_PortConnector)) { Write-Log INFO "SMBIOS WMI record External=$($r.ExternalReferenceDesignator); Internal=$($r.InternalReferenceDesignator); PortType=$($r.PortType); ConnectorType=$($r.ConnectorType -join ',')" } } catch { Write-Log WARN "Full firmware inventory unavailable: $($_.Exception.Message)" }
    try { $devices=@(Get-PnpDevice -Class Display -PresentOnly) } catch { Write-Log WARN "Board PnP unavailable: $($_.Exception.Message)"; return }
    foreach ($device in $devices) {
        $instance=[string]$device.InstanceId
        if ($instance -notmatch '(?i)^PCI\\VEN_(8086|10DE)&') { continue }; $vendor=$Matches[1].ToUpperInvariant()
        try {
            $driver=[string](Get-PnpDeviceProperty -InstanceId $instance -KeyName 'DEVPKEY_Device_Driver').Data
            if ($driver -notmatch '^\{4d36e968-e325-11ce-bfc1-08002be10318\}\\\d{4}$') { throw "Unexpected driver key $driver" }
            $root="HKLM:\SYSTEM\CurrentControlSet\Control\Class\$driver"
            Write-Log INFO "Board driver key Adapter=$instance; Vendor=$vendor; Key=$driver"
            $keys=@(Get-Item -LiteralPath $root; Get-ChildItem -LiteralPath $root -Recurse | Select-Object -First 128)
            $binaryCount=0; $scanned=0; $before=$script:VbtFound
            foreach ($key in $keys) {
                foreach ($v in $key.GetValueNames()) {
                    if ($key.GetValueKind($v) -ne [Microsoft.Win32.RegistryValueKind]::Binary) { continue }; $binaryCount++
                    if ($vendor -eq '10DE' -and ($key.Name -notmatch '(?i)\\Session$' -or $v -ine 'vbios')) { continue }
                    $bytes=$key.GetValue($v)
                    if ($bytes -isnot [byte[]] -or $bytes.Length -lt 48 -or $bytes.Length -gt 4194304) { continue }
                    if ($scanned+$bytes.Length -gt 16777216) { Write-Log WARN 'Driver registry scan budget reached.'; continue }; $scanned+=$bytes.Length
                    $source="$($key.Name):$v"
                    if ($vendor -eq '8086') { Read-IntelVbtEvidence -Bytes $bytes -Source $source }
                    else { try { Read-NvidiaDcbEvidence -Bytes $bytes -Source $source -InstanceId $instance } catch { $script:DcbRejected[$instance]=$true; $script:DcbCandidates.Remove($instance); Write-Log WARN "NVIDIA DCB unavailable: $($_.Exception.Message)" } }
                }
            }
            Write-Log INFO "Board driver scan complete: Adapter=$instance; BinaryValues=$binaryCount; ScannedBytes=$scanned"
            if ($vendor -eq '8086' -and $script:VbtFound -eq $before) { Write-Log WARN "Intel driver registry VBT not recovered: $instance" }
            if ($vendor -eq '10DE' -and -not $script:DcbCandidates.ContainsKey($instance)) { Write-Log WARN "NVIDIA Session VBIOS DCB candidate unavailable: $instance" }
        } catch { Write-Log WARN "Board driver evidence unavailable: Adapter=$instance; $($_.Exception.Message)" }
    }
    Write-Log INFO "Board diagnostic end; VBTMatches=$script:VbtFound; DCBAdapters=$($script:DcbCandidates.Count); EvidenceEncodedChars=$script:EvidenceChars"
}

try {
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $LogFile) -Force
    Write-Log INFO "Start Build=$ScriptBuild Device=$env:COMPUTERNAME"
    if ($script:LogFailed) { throw 'Required log is not writable.' }

    $active = @{}
    $issues = @()
    $monitors = @()
    $displayReadOk = $false

    try {
        $monitors = @(Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorConnectionParams)
        foreach ($monitor in $monitors) {
            if ($null -eq $monitor.Active -or $null -eq $monitor.VideoOutputTechnology) { throw 'Monitor state or connection type missing.' }
            $code = [uint32]$monitor.VideoOutputTechnology
            $type = Get-DisplayType -Code $code
            Write-Log INFO "Display Active=$($monitor.Active); Technology=$code; Classified=$type"
            if ($monitor.Active) {
                if (-not $active.ContainsKey($type)) { $active[$type] = 0 }
                $active[$type]++
            }
        }
        $displayReadOk = $true
        if ($active.ContainsKey('Other video')) { $issues += 'Unclassified active display connection' }
    } catch {
        $active.Clear()
        $issues += 'Active display query failed'
        Write-Log ERROR "Display query: $($_.Exception.Message)"
    }

    $activeSummary = 'N/A'
    if ($displayReadOk) {
        $activeSummary = 'None detected'
        if ($active.Count -gt 0) {
            $activeSummary = (@(foreach ($type in ($active.Keys | Sort-Object)) {
                '{0} x{1}' -f $type, $active[$type]
            }) -join ', ')
        }
    }
    try { Invoke-BoardDiagnostics } catch { Write-Log WARN "Board diagnostic incomplete: $($_.Exception.Message)" }
    # Physical inventory is a separate, best-effort operation. Never use
    # unqualified logical driver target counts as physical socket counts.
    $availableSummary = 'N/A'
    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem
        Write-Log INFO "System Manufacturer=$($system.Manufacturer); Model=$($system.Model)"
        $adapters = @(Get-CimInstance -ClassName Win32_VideoController)
        $present = @(Get-PnpDevice -Class Display -PresentOnly)
        if ($adapters.Count -eq 0 -or $present.Count -eq 0) { throw 'No display adapter inventory.' }
        $presentIds = @($present | ForEach-Object { [string]$_.InstanceId } | Sort-Object -Unique)
        $controllerIds = @($adapters | ForEach-Object { [string]$_.PNPDeviceID } | Sort-Object -Unique)
        $adapterInventoryMismatch = @(Compare-Object $presentIds $controllerIds).Count -ne 0
        if ($adapterInventoryMismatch) { Write-Log WARN 'PnP and video-controller inventories differ; present PnP sources will be evaluated.' }
        $onboard = @()
        $cards = @()
        $nvidiaCards = @()
        $inventoryPartial = $adapterInventoryMismatch
        $nvidiaTypes = @{}
        $physicalByAdapter = @{}
        foreach ($adapter in $present) {
            $id = [string]$adapter.InstanceId
            try {
                if ($adapter.Status -ne 'OK' -or $id -notmatch '^PCI\\VEN_([0-9A-F]{4})&') { throw "Unresolved display adapter: $id" }
                $vendor = $Matches[1].ToUpperInvariant()
                $paths = @((Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_LocationPaths').Data)
                $bus = [int](Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_BusNumber').Data
                $address = [uint32](Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_Address').Data
                $device = [int]($address -shr 16)
                $function = [int]($address -band 0xffff)
                Write-Log INFO "Adapter PNP=$id; Paths=$($paths -join ','); PCI=$bus`:$device`:$function"
                # Classic Intel integrated graphics at PCI 00:02.0; deliberately
                # do not infer integrated/discrete from the marketing name.
                if ($vendor -eq '8086' -and $bus -eq 0 -and $device -eq 2 -and $function -eq 0 -and
                    @($paths | Where-Object { $_ -match '^PCIROOT\([0-9A-F]+\)#PCI\(0200\)$' }).Count -gt 0) {
                    $onboard += $adapter
                } elseif ($vendor -eq '1002' -and @($paths | Where-Object { $_ -match '^PCIROOT\([0-9A-F]+\)(#PCI\([0-9A-F]+\)){2,}$' }).Count -gt 0) {
                    $cards += [pscustomobject]@{ Id=$id; Bus=$bus; Device=$device; Function=$function }
                } elseif ($vendor -eq '10DE' -and @($paths | Where-Object { $_ -match '^PCIROOT\([0-9A-F]+\)(#PCI\([0-9A-F]+\)){2,}$' }).Count -gt 0) {
                    if ($id -notmatch '(?i)DEV_([0-9A-F]{4})&SUBSYS_([0-9A-F]{8})') { throw "NVIDIA PCI identity incomplete: $id" }
                    $nvidiaCards += [pscustomobject]@{ Id=$id; Bus=$bus; Device=$device; Function=$function; PciId=[Convert]::ToUInt32(($Matches[1] + '10DE'),16); Subsystem=[Convert]::ToUInt32($Matches[2],16) }
                } else {
                    throw "No supported physical connector source for adapter $id"
                }
            } catch {
                $inventoryPartial = $true
                Write-Log WARN "Adapter inventory incomplete: $id; $($_.Exception.Message)"
            }
        }
        # Restrict the firmware + card combination to conventional desktops.
        # Laptop muxes, internal panels, docks and optional USB-C video routes
        # cannot be reconciled with this method.
        $chassis = @(Get-CimInstance -ClassName Win32_SystemEnclosure | ForEach-Object { $_.ChassisTypes })
        if ($chassis.Count -eq 0 -or @($chassis | Where-Object { $_ -notin @(3,4,5,6,7,15,16,35) }).Count -gt 0) {
            throw "Unsupported or ambiguous chassis type: $($chassis -join ',')"
        }
        $physical = @{}
        try {
            if ($onboard.Count -ne 1) { throw 'Exactly one identified motherboard GPU is required for firmware/card reconciliation.' }
            $names = @{}
            $connectors = @(Get-CimInstance -ClassName Win32_PortConnector)
            foreach ($connector in $connectors) {
                $external = ([string]$connector.ExternalReferenceDesignator).Trim()
                if ($external -match '(?i)USB[- ]?C|Type[- ]?C|Thunderbolt|dock') { throw "Firmware has ambiguous video-capable connector: $external" }
                if ($external -notmatch '(?i)display\s*port|\bDP\b|HDMI|DVI|VGA|video|miniDP' -and $connector.PortType -ne 28) { continue }
                $type = switch -Regex ($external) {
                    '^(?i)(?:(?:rear|front|onboard|motherboard)\s+)?(?:mini\s*display\s*port|mini\s*DP)(?:[\s#_-]*\d+)?$' { 'DP'; break }
                    '^(?i)(?:(?:rear|front|onboard|motherboard)\s+)?(?:display\s*port|DP)(?:[\s#_-]*\d+)?$' { 'DP'; break }
                    '^(?i)(?:(?:rear|front|onboard|motherboard)\s+)?HDMI(?:[\s#_-]*\d+)?$' { 'HDMI'; break }
                    '^(?i)(?:(?:rear|front|onboard|motherboard)\s+)?DVI(?:-[DI])?(?:[\s#_-]*\d+)?$' { 'DVI'; break }
                    '^(?i)(?:(?:rear|front|onboard|motherboard)\s+)?VGA(?:[\s#_-]*\d+)?$' { 'VGA'; break }
                    default { '' }
                }
                if ([string]::IsNullOrEmpty($type) -or $names.ContainsKey($external)) { throw "Ambiguous or duplicate firmware video connector: $external" }
                $names[$external] = $true
                if (-not $physical.ContainsKey($type)) { $physical[$type] = 0 }
                $physical[$type]++
                Write-Log INFO "Motherboard firmware connector candidate External=$external; Type=$type"
            }
            if ($physical.Count -eq 0) { throw 'No identifiable motherboard video connectors in firmware.' }
            # Firmware provides no explicit owner for generic port labels. On the
            # supported conventional desktop topology we treat these as board
            # connectors; do not claim independently certified completeness.
            $motherboardId = [string]$onboard[0].InstanceId
            $physicalByAdapter[$motherboardId] = $physical.Clone()
            Write-Log INFO 'Motherboard source=SMBIOS Type 8; generic firmware labels assumed to describe motherboard connectors on supported desktop topology. Optional or unlisted sockets cannot be ruled out.'
        } catch {
            $physical.Clear()
            $inventoryPartial = $true
            Write-Log WARN "Motherboard inventory incomplete: $($_.Exception.Message)"
        }
        foreach ($card in $cards) {
            try {
                if (-not [Environment]::Is64BitProcess) { throw 'AMD board layout requires 64-bit PowerShell in this build.' }
                $dll = Join-Path ([Environment]::SystemDirectory) 'atiadlxx.dll'
                if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) { throw 'Installed AMD ADL driver library is unavailable.' }
                $sig = Get-AuthenticodeSignature -LiteralPath $dll
                if ($sig.Status -ne 'Valid') { throw "AMD driver library signature not valid: $($sig.Status)" }
                if (-not ('MME.VideoInventory.Adl' -as [type])) {
                    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace MME.VideoInventory {
  public static class Adl {
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr Alloc(int size);
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi)]
    private struct Adapter {
      public int Size, Index;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string Udid;
      public int Bus, Device, Function, Vendor;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string Name;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string Display;
      public int Present, Exists;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string DriverPath;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string DriverPathExt;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string Pnp;
      public int OSDisplayIndex;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct Connector { public int Index, Id, Slot, Type, Offset, Length; }
    [DllImport("atiadlxx.dll", CallingConvention=CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int ADL_Main_Control_Create(Alloc callback, int connectedOnly);
    [DllImport("atiadlxx.dll", CallingConvention=CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int ADL_Main_Control_Destroy();
    [DllImport("atiadlxx.dll", CallingConvention=CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int ADL_Adapter_NumberOfAdapters_Get(out int count);
    [DllImport("atiadlxx.dll", CallingConvention=CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int ADL_Adapter_AdapterInfo_Get(IntPtr info, int size);
    [DllImport("atiadlxx.dll", CallingConvention=CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int ADL_Adapter_BoardLayout_Get(int index, out int flags, out int slots, out IntPtr bracket, out int count, out IntPtr connectors);
    private static void Check(int rc, string stage) {
      if (rc != 0) throw new InvalidOperationException(stage + " returned ADL status " + rc);
    }
    public static Connector[] Read(int bus, int device, int function) {
      var memory = new Dictionary<IntPtr,int>();
      Alloc alloc = delegate(int size) {
        if (size <= 0 || size > 16777216) return IntPtr.Zero;
        try { IntPtr p = Marshal.AllocHGlobal(size); lock(memory) memory.Add(p,size); return p; }
        catch { return IntPtr.Zero; }
      };
      bool initialized = false;
      IntPtr info = IntPtr.Zero;
      try {
        Check(ADL_Main_Control_Create(alloc, 0), "ADL initialize"); initialized = true;
        int count; Check(ADL_Adapter_NumberOfAdapters_Get(out count), "ADL adapter count");
        if (count <= 0 || count > 128) throw new InvalidOperationException("Invalid ADL adapter count");
        int size = Marshal.SizeOf(typeof(Adapter));
        info = Marshal.AllocHGlobal(size * count);
        byte[] zero = new byte[size * count]; Marshal.Copy(zero,0,info,zero.Length);
        for (int i=0;i<count;i++) Marshal.WriteInt32(info,i*size,size);
        Check(ADL_Adapter_AdapterInfo_Get(info,size*count), "ADL adapter information");
        var indices = new HashSet<int>();
        for (int i=0;i<count;i++) {
          Adapter a = (Adapter)Marshal.PtrToStructure(IntPtr.Add(info,i*size),typeof(Adapter));
          if (a.Exists == 1 && a.Bus == bus && a.Device == device && a.Function == function &&
              (a.Vendor == 1002 || a.Vendor == 0x1002)) indices.Add(a.Index);
        }
        if (indices.Count == 0) throw new InvalidOperationException("ADL could not match the Windows PCI adapter");
        Connector[] result = null;
        foreach (int index in indices) {
          int flags, slots, n; IntPtr bracket, ptr;
          Check(ADL_Adapter_BoardLayout_Get(index,out flags,out slots,out bracket,out n,out ptr), "ADL board layout");
          int stride = Marshal.SizeOf(typeof(Connector)); int allocated;
          if (n <= 0 || n > 64 || ptr == IntPtr.Zero || !memory.TryGetValue(ptr,out allocated) || allocated < n*stride)
            throw new InvalidOperationException("Invalid ADL connector array");
          if ((flags & 1) == 0 || slots <= 0 || slots > 16) throw new InvalidOperationException("ADL board slot layout is not valid");
          var current = new Connector[n]; var keys = new HashSet<int>();
          for (int i=0;i<n;i++) {
            Connector c = (Connector)Marshal.PtrToStructure(IntPtr.Add(ptr,i*stride),typeof(Connector));
            if (c.Index < 0 || c.Slot < 0 || c.Slot >= slots || !keys.Add(c.Index)) throw new InvalidOperationException("Ambiguous ADL connector index or slot");
            current[i]=c;
          }
          Array.Sort(current,delegate(Connector a,Connector b){return a.Index.CompareTo(b.Index);});
          if (result != null) {
            if (result.Length != current.Length) throw new InvalidOperationException("ADL logical adapter layouts disagree");
            for (int i=0;i<result.Length;i++) if (result[i].Index != current[i].Index || result[i].Type != current[i].Type || result[i].Slot != current[i].Slot)
              throw new InvalidOperationException("ADL logical adapter connectors disagree");
          }
          result=current;
        }
        return result;
      } finally {
        try { if(initialized) ADL_Main_Control_Destroy(); }
        finally { if(info!=IntPtr.Zero) Marshal.FreeHGlobal(info); foreach(IntPtr p in memory.Keys) Marshal.FreeHGlobal(p); GC.KeepAlive(alloc); }
      }
    }
  }
}
'@
                }
                $cardCounts = @{}
                $layout = @([MME.VideoInventory.Adl]::Read($card.Bus,$card.Device,$card.Function))
                if ($layout.Count -eq 0) { throw "No AMD physical connector records for $($card.Id)" }
                foreach ($port in $layout) {
                    $type = switch ([int]$port.Type) {
                        1 { 'VGA' } 2 { 'DVI' } 3 { 'DVI' }
                        8 { 'HDMI' } 9 { 'HDMI' } 10 { 'DP' } 12 { 'DP' }
                        14 { 'USB-C' } default { '' }
                    }
                    Write-Log INFO "AMD physical connector PCI=$($card.Bus):$($card.Device):$($card.Function); Index=$($port.Index); Slot=$($port.Slot); Code=$($port.Type); Type=$type"
                    if ([string]::IsNullOrEmpty($type)) { throw "Unknown or nonexternal AMD connector type $($port.Type)" }
                    if (-not $cardCounts.ContainsKey($type)) { $cardCounts[$type] = 0 }
                    $cardCounts[$type]++
                }
                foreach ($type in $cardCounts.Keys) {
                    if (-not $physical.ContainsKey($type)) { $physical[$type] = 0 }
                    $physical[$type] += $cardCounts[$type]
                }
                $physicalByAdapter[[string]$card.Id] = $cardCounts.Clone()
            } catch {
                $inventoryPartial = $true
                Write-Log WARN "AMD adapter inventory incomplete: $($card.Id); $($_.Exception.Message)"
            }
        }
        # NVIDIA: use only an adapter-bound, validated DCB connector table.
        # Neither display IDs nor GPU output bitmasks prove physical sockets.
        foreach ($card in $nvidiaCards) {
            try {
                $adapterId=[string]$card.Id
                if (-not $script:DcbCandidates.ContainsKey($adapterId) -or $script:DcbRejected.ContainsKey($adapterId)) {
                    throw 'No usable adapter-bound VBIOS connector table; logical output counts excluded.'
                }
                $cardCounts=$script:DcbCandidates[$adapterId]
                foreach ($type in $cardCounts.Keys) {
                    if (-not $physical.ContainsKey($type)) { $physical[$type] = 0 }
                    $physical[$type] += $cardCounts[$type]
                    $nvidiaTypes[$type] = $true
                }
                $physicalByAdapter[$adapterId]=$cardCounts.Clone()
                Write-Log INFO "NVIDIA board inventory source=VBIOS DCB; Adapter=$adapterId; no logical outputs counted."
            } catch {
                $inventoryPartial=$true
                Write-Log WARN "NVIDIA adapter inventory incomplete: $($card.Id); $($_.Exception.Message)"
            }
        }
        if ($physical.Count -eq 0) { throw 'No usable motherboard or graphics-card connector inventory.' }
        # Cross-validation only. Neither connected nor disconnected logical
        # targets can establish additional physical sockets. GET_TARGET_BASE_TYPE
        # (6) returns a 24-byte structure (20-byte header; technology at 20).
        $qualifiers = @{}
        foreach ($type in $nvidiaTypes.Keys) { $qualifiers[$type] = 'DCB' }
        $reviewTypes = @{}
        $validationIncomplete = $false
        $comparisonReliable = $true
        $connectedTypes = @{}
        $baseByAdapter = @{}
        $convertedTypes = @{}
        $seenTargets = @{}
        $manager = $null
        try {
            if (-not ('MME.VideoInventory.PortProbe' -as [type])) {
                Add-Type -Language CSharp -TypeDefinition @'
using System.Runtime.InteropServices;
namespace MME.VideoInventory {
    public static class PortProbe {
        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern int DisplayConfigGetDeviceInfo([In, Out] byte[] packet);
    }
}
'@
            }
            $manager = [Windows.Devices.Display.Core.DisplayManager,Windows.Devices.Display.Core,ContentType=WindowsRuntime]::Create(0)
            $targets = @($manager.GetCurrentTargets())
            if ($targets.Count -eq 0 -and $active.Count -gt 0) { throw 'No display targets returned for active monitors.' }
            foreach ($target in $targets) {
                $adapter = [string]$target.Adapter.DeviceInterfacePath
                $targetId = [uint32]$target.AdapterRelativeId
                $connected = [bool]$target.IsConnected
                if ($target.IsStale) {
                    if ($connected) { $comparisonReliable = $false; $validationIncomplete = $true }
                    Write-Log WARN "Validation skipped stale target Adapter=$adapter; Target=$targetId; Connected=$connected"
                    continue
                }
                $id = $target.Adapter.Id
                $key = '{0}:{1}:{2}' -f $id.HighPart, $id.LowPart, $targetId
                if ($seenTargets.ContainsKey($key)) { continue }
                $seenTargets[$key] = $true
                # DISPLAYCONFIG_TARGET_DEVICE_NAME (2), 420 bytes.
                $buffer = New-Object byte[] 420
                [BitConverter]::GetBytes([uint32]2).CopyTo($buffer, 0)
                [BitConverter]::GetBytes([uint32]420).CopyTo($buffer, 4)
                [BitConverter]::GetBytes([uint32]$id.LowPart).CopyTo($buffer, 8)
                [BitConverter]::GetBytes([int32]$id.HighPart).CopyTo($buffer, 12)
                [BitConverter]::GetBytes($targetId).CopyTo($buffer, 16)
                $rc = [MME.VideoInventory.PortProbe]::DisplayConfigGetDeviceInfo($buffer)
                if ($rc -ne 0) {
                    if ($connected) { $comparisonReliable = $false; $validationIncomplete = $true }
                    Write-Log WARN "Target validation Adapter=$adapter; Target=$targetId; Connected=$connected; Return=$rc"
                    continue
                }
                $technology = [BitConverter]::ToUInt32($buffer, 24)
                $instance = [BitConverter]::ToUInt32($buffer, 32)
                $reportedType = Get-DisplayType -Code $technology
                $baseBuffer = New-Object byte[] 24
                [Array]::Copy($buffer,0,$baseBuffer,0,20)
                [BitConverter]::GetBytes([uint32]6).CopyTo($baseBuffer, 0)
                [BitConverter]::GetBytes([uint32]24).CopyTo($baseBuffer, 4)
                $baseRc = [MME.VideoInventory.PortProbe]::DisplayConfigGetDeviceInfo($baseBuffer)
                $baseType = 'Unknown'
                if ($baseRc -eq 0) { $baseType = Get-DisplayType -Code ([BitConverter]::ToUInt32($baseBuffer, 20)) }
                Write-Log INFO "Target validation Adapter=$adapter; Target=$targetId; Connected=$connected; Type=$reportedType; Code=$technology; Connector=$instance; BaseType=$baseType; BaseReturn=$baseRc"
                if (-not $connected) {
                    if ($reportedType -eq 'VGA' -or $baseType -eq 'VGA') {
                        Write-Log INFO 'Disconnected logical VGA observed; no physical socket added.'
                    }
                    continue
                }
                if (-not $connectedTypes.ContainsKey($reportedType)) { $connectedTypes[$reportedType] = 0 }
                $connectedTypes[$reportedType]++
                # Match interface path to the PnP instance ID, not just vendor ID.
                $pnpId = ''
                if ($adapter -match '(?i)PCI#([^#]+)#([^#]+)#') { $pnpId = 'PCI\{0}\{1}' -f $Matches[1],$Matches[2] }
                if ($baseRc -ne 0 -or $baseType -in @('Unknown','Other video') -or -not $physicalByAdapter.ContainsKey($pnpId)) {
                    $comparisonReliable = $false
                    $validationIncomplete = $true
                    Write-Log WARN "Connected target base/adapter evidence incomplete: Adapter=$adapter; Target=$targetId; Type=$reportedType; BaseType=$baseType"
                    continue
                }
                if (-not $baseByAdapter.ContainsKey($pnpId)) { $baseByAdapter[$pnpId] = @{} }
                $baseCounts = $baseByAdapter[$pnpId]
                if (-not $baseCounts.ContainsKey($baseType)) { $baseCounts[$baseType] = 0 }
                $baseCounts[$baseType]++
                if ($reportedType -ne $baseType) {
                    if (-not $convertedTypes.ContainsKey($reportedType)) { $convertedTypes[$reportedType] = 0 }
                    $convertedTypes[$reportedType]++
                    Write-Log INFO "Possible output conversion: Adapter=$pnpId; Target=$targetId; Reported=$reportedType; Base=$baseType; not proof of physical socket mapping."
                }
            }
        } catch {
            $comparisonReliable = $false
            $validationIncomplete = $true
            Write-Log WARN "Target cross-validation unavailable; baseline inventory retained: $($_.Exception.Message)"
        } finally {
            if ($manager -is [IDisposable]) {
                try { $manager.Dispose() } catch { Write-Log WARN "Target validation cleanup: $($_.Exception.Message)" }
            }
        }
        # Check aggregate connected target observations against the unchanged
        # WMI inventory. Connected targets need not all be active monitors.
        if (-not $displayReadOk) {
            $comparisonReliable = $false
            $validationIncomplete = $true
            Write-Log WARN 'Active inventory unavailable for comparison; physical baseline retained.'
        } else {
            foreach ($type in (@($active.Keys) + @($connectedTypes.Keys) | Sort-Object -Unique)) {
                $a = [int]$active[$type]
                $c = [int]$connectedTypes[$type]
                if ($a -ne $c) {
                    $comparisonReliable = $false
                    $validationIncomplete = $true
                    Write-Log WARN "WMI/connected target discrepancy: Type=$type; Active=$a; ConnectedTargets=$c"
                }
            }
        }
        # Check underlying connected types per adapter without assigning any
        # logical target to an individual physical socket (MST may share one).
        foreach ($pnpId in $baseByAdapter.Keys) {
            foreach ($type in $baseByAdapter[$pnpId].Keys) {
                $count = [int]$baseByAdapter[$pnpId][$type]
                $baseline = [int]$physicalByAdapter[$pnpId][$type]
                if ($count -gt $baseline) {
                    $comparisonReliable = $false
                    $reviewTypes[$type] = $true
                    Write-Log WARN "Adapter base discrepancy: Adapter=$pnpId; Type=$type; ConnectedBaseTargets=$count; PhysicalBaseline=$baseline; no socket added."
                }
            }
        }
        foreach ($type in ($active.Keys | Sort-Object)) {
            $baselineCount = [int]$physical[$type]
            $activeCount = [int]$active[$type]
            if ($activeCount -le $baselineCount) { continue }
            $gap = $activeCount - $baselineCount
            if ($comparisonReliable -and -not $inventoryPartial -and [int]$convertedTypes[$type] -ge $gap) {
                Write-Log INFO "Connector discrepancy consistent with output conversion: Type=$type; Active=$activeCount; PhysicalBaseline=$baselineCount; no socket added."
            } else {
                $reviewTypes[$type] = $true
                Write-Log WARN "Unresolved connector discrepancy: Type=$type; Active=$activeCount; PhysicalBaseline=$baselineCount; no socket added."
            }
        }
        $availableSummary = (@(foreach ($type in ($physical.Keys | Sort-Object)) {
            $entry = '{0} x{1}' -f $type, $physical[$type]
            if ($qualifiers.ContainsKey($type)) { $entry += " ($($qualifiers[$type]))" }
            $entry
        }) -join ', ')
        if ($inventoryPartial) { $availableSummary += ' (Partial)' }
        if ($reviewTypes.Count -gt 0) {
            $availableSummary += ' (Check: ' + (($reviewTypes.Keys | Sort-Object) -join ', ') + ')'
        } elseif ($validationIncomplete) {
            $availableSummary += ' (Check)'
        }
        Write-Log INFO "Available inventory (firmware + local GPU driver evidence; qualifiers indicate uncertainty): $availableSummary"
    } catch {
        $availableSummary = 'N/A'
        Write-Log WARN "Available Ports=N/A; $($_.Exception.Message)"
    }

    $separator = '; '
    if ($UseMultilineField) { $separator = "`n" }
    $value = "Active Ports: $activeSummary${separator}Available Ports: $availableSummary${separator}$Disclaimer"
    Write-Log INFO "Inventory: $value"
    foreach ($issue in ($issues | Sort-Object -Unique)) { Write-Log WARN $issue }
    if ($script:LogFailed) { throw 'Required logging failed before field update.' }
    $limit = 199
    if ($UseMultilineField) { $limit = 9999 }
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt $limit) {
        throw 'Inventory is empty or exceeds configured field limit; full inventory in log. Field not updated.'
    }

    $null = Get-Command -Name Ninja-Property-Set -ErrorAction Stop
    $null = Get-Command -Name Ninja-Property-Get -ErrorAction Stop
    Write-Log INFO "Updating custom field $Field"
    $null = Ninja-Property-Set -Name $Field -Value $value
    $readBack = Ninja-Property-Get -Name $Field
    $readBackText = (@($readBack) -join "`n") -replace "`r`n", "`n"
    if ($readBackText -cne $value) { throw 'Custom field read-back mismatch.' }
    Write-Log INFO 'Local custom field read-back verified.'
    if ($issues.Count -gt 0) {
        $Final = "ERROR | PartialInventory; $(Safe-Text $value)"
    } else {
        $Final = "RESULT | $(Safe-Text $value)"
    }
} catch {
    Write-Log ERROR $_.Exception.Message
    $Final = 'ERROR | ' + (Safe-Text $_.Exception.Message)
} finally {
    if (-not $Final.EndsWith($Disclaimer, [StringComparison]::Ordinal)) { $Final += "; $Disclaimer" }
    Write-Log INFO "Final: $Final"
    if ($script:LogFailed) { $Final = "ERROR | Required logging failed; see available log and verify field state; $Disclaimer" }
    Write-Output $Final
}
exit 0
