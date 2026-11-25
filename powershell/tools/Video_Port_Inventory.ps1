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
#              Inventory local firmware, AMD board layouts and NVIDIA
#              driver outputs on conventional desktops. NVIDIA output counts
#              and supplemental logical VGA are labeled Inferred. Failed or
#              unsupported adapter sources preserve usable counts as Partial.
#              N/A if no usable baseline or active reconciliation is unavailable;
#              active physical-type counts exceeding baseline are labeled
#              Unverified. These are not verified or additive socket counts.
#              A failed or negative supplemental query retains baseline counts.
#              Firmware ownership is assumed for this limited topology.
#              Overwrite and verify videoPorts. No monitor details, vendor
#              lookups, downloads, display changes or ledger changes.
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ScriptBuild = '2026.11.25-v11'
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
        if (@(Compare-Object $presentIds $controllerIds).Count -ne 0) { throw 'PnP and video-controller inventories differ.' }
        $onboard = @()
        $cards = @()
        $nvidiaCards = @()
        $inventoryPartial = $false
        $nvidiaTypes = @{}
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
            Write-Log INFO 'Motherboard source=SMBIOS Type 8; generic firmware labels assumed to describe motherboard connectors on supported desktop topology.'
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
            } catch {
                $inventoryPartial = $true
                Write-Log WARN "AMD adapter inventory incomplete: $($card.Id); $($_.Exception.Message)"
            }
        }
        # NVIDIA NVAPI: driver-reported possible outputs, not certified sockets.
        # Use documented display IDs, discard dynamic MST sinks, and collapse
        # identical GPU output IDs when the driver exposes that mapping.
        foreach ($card in $nvidiaCards) {
            try {
                if (-not [Environment]::Is64BitProcess) { throw 'NVIDIA query requires 64-bit PowerShell.' }
                $dll = Join-Path ([Environment]::SystemDirectory) 'nvapi64.dll'
                if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) { throw 'Installed NVIDIA NVAPI library is unavailable.' }
                $sig = Get-AuthenticodeSignature -LiteralPath $dll
                if ($sig.Status -ne 'Valid') { throw "NVIDIA driver library signature not valid: $($sig.Status)" }
                if (-not ('MME.VideoInventory.NvApi' -as [type])) {
                    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace MME.VideoInventory {
  public static class NvApi {
    [DllImport("nvapi64.dll", EntryPoint="nvapi_QueryInterface", CallingConvention=CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr Query(uint id);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Simple();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int EnumGpu([Out, MarshalAs(UnmanagedType.LPArray, SizeConst=64)] IntPtr[] handles, out uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int GetBus(IntPtr gpu, out uint bus);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int GetPci(IntPtr gpu, out uint device, out uint subsystem, out uint revision, out uint extended);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int GetIds(IntPtr gpu, IntPtr data, ref uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int MapId(uint displayId, out IntPtr gpu, out uint output);
    private static T Bind<T>(uint id) where T: class {
      IntPtr p=Query(id);
      if(p==IntPtr.Zero) throw new InvalidOperationException("NVAPI interface missing: "+id.ToString("X8"));
      return Marshal.GetDelegateForFunctionPointer(p,typeof(T)) as T;
    }
    private static void Check(int rc,string stage) { if(rc!=0) throw new InvalidOperationException(stage+" returned NVAPI status "+rc); }
    public struct Output {
      public uint DisplayId, Flags, OutputId;
      public int ConnectorType, MapStatus;
    }
    public static Output[] Read(uint bus,uint pci,uint subsystem) {
      var init=Bind<Simple>(0x0150e828); var unload=Bind<Simple>(0xd22bdd7e);
      Check(init(),"NVAPI initialize");
      try {
        var enumerate=Bind<EnumGpu>(0xe5ac921f);
        var getBus=Bind<GetBus>(0x1be0b8e5); var getPci=Bind<GetPci>(0x2ddfb66e);
        var getIds=Bind<GetIds>(0x785210a2);
        MapId map=null; try { map=Bind<MapId>(0x112ba1a5); } catch(InvalidOperationException) {}
        IntPtr[] handles=new IntPtr[64]; uint count;
        Check(enumerate(handles,out count),"NVAPI enumerate GPUs");
        if(count==0 || count>64) throw new InvalidOperationException("Invalid NVAPI GPU count");
        var matches=new HashSet<IntPtr>();
        for(int i=0;i<(int)count;i++) {
          uint b,d,s,r,e;
          Check(getBus(handles[i],out b),"NVAPI PCI bus");
          Check(getPci(handles[i],out d,out s,out r,out e),"NVAPI PCI identifiers");
          if(b==bus && d==pci && s==subsystem) matches.Add(handles[i]);
        }
        if(matches.Count!=1) throw new InvalidOperationException("NVIDIA PCI identity not uniquely matched");
        IntPtr gpu=IntPtr.Zero; foreach(IntPtr h in matches) gpu=h;
        uint n=0; Check(getIds(gpu,IntPtr.Zero,ref n),"NVAPI output count");
        if(n==0 || n>1024) throw new InvalidOperationException("Invalid NVAPI display ID count");
        const int stride=16; const int version=0x00030010; // NV_GPU_DISPLAYIDS_VER2 (version number 3)
        int capacity=(int)n; IntPtr data=Marshal.AllocHGlobal(capacity*stride);
        try {
          Marshal.Copy(new byte[capacity*stride],0,data,capacity*stride);
          for(int i=0;i<capacity;i++) Marshal.WriteInt32(data,i*stride,version);
          Check(getIds(gpu,data,ref n),"NVAPI all display IDs");
          if(n==0 || n>(uint)capacity) throw new InvalidOperationException("Invalid returned NVAPI display ID count");
          var result=new List<Output>();
          for(int i=0;i<(int)n;i++) {
            int off=i*stride;
            Output o=new Output();
            o.ConnectorType=Marshal.ReadInt32(data,off+4);
            o.DisplayId=unchecked((uint)Marshal.ReadInt32(data,off+8));
            o.Flags=unchecked((uint)Marshal.ReadInt32(data,off+12));
            o.MapStatus=-1;
            if(map!=null && (o.Flags&1)==0) {
              IntPtr owner; uint output;
              o.MapStatus=map(o.DisplayId,out owner,out output);
              if(o.MapStatus==0 && owner==gpu && output!=0 && (output&(output-1))==0) o.OutputId=output;
              else if(o.MapStatus==0) o.MapStatus=-1;
            }
            result.Add(o);
          }
          return result.ToArray();
        } finally { Marshal.FreeHGlobal(data); }
      } finally { Check(unload(),"NVAPI unload"); }
    }
  }
}
'@
                }
                $outputs = @([MME.VideoInventory.NvApi]::Read($card.Bus,$card.PciId,$card.Subsystem))
                $groups = @{}
                $staticOutputs = @()
                foreach ($output in $outputs) {
                    Write-Log INFO "NVIDIA output PCI=$($card.Bus):$($card.Device):$($card.Function); DisplayId=$($output.DisplayId); Code=$($output.ConnectorType); Flags=$($output.Flags); OutputId=$($output.OutputId); MapStatus=$($output.MapStatus)"
                    if (($output.Flags -band 1) -ne 0) { continue } # MST downstream logical sink
                    $staticOutputs += $output
                }
                if ($staticOutputs.Count -eq 0) { throw 'No non-dynamic NVIDIA outputs.' }
                $mapped = @($staticOutputs | Where-Object { $_.OutputId -ne 0 }).Count
                if ($mapped -eq 0) {
                    $inventoryPartial = $true
                    Write-Log WARN 'NVIDIA output mapping unavailable; distinct non-dynamic display IDs used as inferred counts.'
                }
                foreach ($output in $staticOutputs) {
                    # Avoid mixing mapped and unmapped keys: an unmapped ID may
                    # be a second representation of a mapped output.
                    if ($mapped -gt 0 -and $output.OutputId -eq 0) {
                        $inventoryPartial = $true
                        Write-Log WARN "NVIDIA unmapped display ID omitted: $($output.DisplayId)"
                        continue
                    }
                    $key = if ($mapped -gt 0) { "Output:$($output.OutputId)" } else { "Display:$($output.DisplayId)" }
                    $type = switch ([int]$output.ConnectorType) {
                        1 { 'VGA' } 2 { 'Component' } 3 { 'S-Video' } 4 { 'HDMI' }
                        5 { 'DVI' } 7 { 'DP' } 8 { 'Composite' } default { '' }
                    }
                    if (-not $groups.ContainsKey($key)) { $groups[$key] = @() }
                    $groups[$key] += $type
                }
                $cardCounts = @{}
                foreach ($key in $groups.Keys) {
                    $types = @($groups[$key] | Sort-Object -Unique)
                    if ($types.Count -ne 1 -or [string]::IsNullOrEmpty($types[0])) {
                        $inventoryPartial = $true
                        Write-Log WARN "NVIDIA ambiguous connector omitted: $key; Types=$($types -join ',')"
                        continue
                    }
                    $type = $types[0]
                    if (-not $cardCounts.ContainsKey($type)) { $cardCounts[$type] = 0 }
                    $cardCounts[$type]++
                }
                if ($cardCounts.Count -eq 0) { throw 'No classifiable NVIDIA outputs.' }
                foreach ($type in $cardCounts.Keys) {
                    if (-not $physical.ContainsKey($type)) { $physical[$type] = 0 }
                    $physical[$type] += $cardCounts[$type]
                    $nvidiaTypes[$type] = $true
                }
                Write-Log WARN "NVIDIA inferred output inventory; PCI=$($card.Bus):$($card.Device):$($card.Function); Mapped=$mapped; Static=$($staticOutputs.Count); socket count not independently verified."
            } catch {
                $inventoryPartial = $true
                Write-Log WARN "NVIDIA adapter inventory incomplete: $($card.Id); $($_.Exception.Message)"
            }
        }
        if ($physical.Count -eq 0) { throw 'No usable motherboard or graphics-card connector inventory.' }
        # Preserve baseline VGA count before supplemental VGA heuristic.
        $baselineVgaCount = 0
        if ($physical.ContainsKey('VGA')) { $baselineVgaCount = [int]$physical['VGA'] }
        $vgaQualifier = ''
        # Supplemental VGA heuristic approved for the v8 pilot. This is the
        # same Windows target-name query tested in Ninja Background PowerShell.
        # Logical VGA targets may represent compatibility modes, not sockets.
        # Add at most one VGA system-wide, only if baseline sources found none.
        if (-not $physical.ContainsKey('VGA')) {
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
                $vgaCandidates = @{}
                $targets = @($manager.GetCurrentTargets())
                if ($targets.Count -eq 0) { throw 'No display targets returned.' }
                foreach ($target in $targets) {
                    $adapter = [string]$target.Adapter.DeviceInterfacePath
                    $targetId = [uint32]$target.AdapterRelativeId
                    $connected = $target.IsConnected
                    if ($target.IsStale) {
                        Write-Log WARN "VGA probe skipped stale target Adapter=$adapter; Target=$targetId"
                        continue
                    }
                    $id = $target.Adapter.Id
                    # DISPLAYCONFIG_TARGET_DEVICE_NAME: 420 bytes; header type
                    # 2 = GET_TARGET_NAME; outputTechnology at 24, connectorInstance at 32.
                    $buffer = New-Object byte[] 420
                    [BitConverter]::GetBytes([uint32]2).CopyTo($buffer, 0)
                    [BitConverter]::GetBytes([uint32]420).CopyTo($buffer, 4)
                    [BitConverter]::GetBytes([uint32]$id.LowPart).CopyTo($buffer, 8)
                    [BitConverter]::GetBytes([int32]$id.HighPart).CopyTo($buffer, 12)
                    [BitConverter]::GetBytes($targetId).CopyTo($buffer, 16)
                    $rc = [MME.VideoInventory.PortProbe]::DisplayConfigGetDeviceInfo($buffer)
                    if ($rc -ne 0) {
                        Write-Log WARN "VGA probe Adapter=$adapter; Target=$targetId; Return=$rc"
                        continue
                    }
                    $technology = [BitConverter]::ToInt32($buffer, 24)
                    $instance = [BitConverter]::ToUInt32($buffer, 32)
                    Write-Log INFO "VGA probe Adapter=$adapter; Target=$targetId; Connected=$connected; Return=$rc; Type=$technology; Connector=$instance"
                    if ($technology -eq 0) {
                        $key = '{0}:{1}:{2}' -f $id.HighPart, $id.LowPart, $targetId
                        $vgaCandidates[$key] = $true
                    }
                }
                if ($vgaCandidates.Count -gt 0) {
                    $physical['VGA'] = 1
                    $vgaQualifier = 'Inferred'
                    Write-Log WARN "Supplemental VGA inferred=1; LogicalCandidates=$($vgaCandidates.Count); physical socket not independently verified."
                } else {
                    Write-Log INFO 'Supplemental VGA probe found no VGA target; baseline inventory retained.'
                }
            } catch {
                Write-Log WARN "Supplemental VGA probe unavailable; baseline inventory retained: $($_.Exception.Message)"
            } finally {
                if ($manager -is [IDisposable]) {
                    try { $manager.Dispose() } catch { Write-Log WARN "VGA probe cleanup: $($_.Exception.Message)" }
                }
            }
        } else {
            Write-Log INFO 'Supplemental VGA probe skipped; VGA already present in baseline inventory.'
        }
        # Reconcile all identifiable physical video connector types, not
        # just VGA. Active connections can use adapters or MST; reported
        # unverified counts are connection evidence, not additional sockets.
        if (-not $displayReadOk) { throw 'Active display data unavailable for reconciliation.' }
        $qualifiers = @{}
        foreach ($type in $nvidiaTypes.Keys) { $qualifiers[$type] = 'Inferred' }
        if ($vgaQualifier -ne '') { $qualifiers['VGA'] = $vgaQualifier }
        $physicalTypes = @('VGA','DP','DVI','HDMI','USB-C','S-Video','Composite','Component','D-JPN','SDI','UDI')
        foreach ($type in ($active.Keys | Sort-Object)) {
            $baselineCount = 0
            if ($type -eq 'VGA') {
                # Active VGA evidence supersedes the earlier logical inference.
                $baselineCount = $baselineVgaCount
            } elseif ($physical.ContainsKey($type)) {
                $baselineCount = [int]$physical[$type]
            }
            if ([int]$active[$type] -le $baselineCount) { continue }
            if ($type -notin $physicalTypes) {
                # Do not invent physical sockets for virtual, wireless,
                # internal or otherwise unmapped display technologies.
                throw "Active display technology cannot be mapped to a physical connector: $type"
            }
            $physical[$type] = [int]$active[$type]
            $qualifiers[$type] = 'Unverified'
            Write-Log WARN "Connector discrepancy: Type=$type; PhysicalBaseline=$baselineCount; ActiveDisplays=$($active[$type]); ReportedCount=$($physical[$type]); physical socket count unverified; may overlap other connector types."
        }
        $availableSummary = (@(foreach ($type in ($physical.Keys | Sort-Object)) {
            $entry = '{0} x{1}' -f $type, $physical[$type]
            if ($qualifiers.ContainsKey($type)) { $entry += " ($($qualifiers[$type]))" }
            $entry
        }) -join ', ')
        if ($inventoryPartial) { $availableSummary += ' (Partial)' }
        Write-Log INFO "Available inventory (firmware + local GPU driver evidence; qualifiers indicate uncertainty): $availableSummary"
    } catch {
        $availableSummary = 'N/A'
        Write-Log WARN "Available Ports=N/A; $($_.Exception.Message)"
    }

    $separator = '; '
    if ($UseMultilineField) { $separator = "`n" }
    $value = "Active Ports: $activeSummary${separator}Available Ports: $availableSummary"
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
    Write-Log INFO "Final: $Final"
    if ($script:LogFailed) { $Final = 'ERROR | Required logging failed; see available log and verify field state.' }
    Write-Output $Final
}
exit 0
