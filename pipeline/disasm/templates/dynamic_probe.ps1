<#
=============================================================================
 dynamic_probe.ps1  --  per-driver dynamic confirmation template
=============================================================================
 Role in the flow (dynamic-first):
   collect -> analyze -> walker builds artifacts (.c / disasm.txt / summary.md,
   extracts symlink+SDDL+candidate IOCTLs+report-desc) -> AI picks ONE candidate,
   reads the pseudo-C, confirms in asm, and FILLS the CONFIG block below ->
   run THIS in a VM -> safe-load gates -> (c) reachability -> (b) injection sweep.

 The walker is the scrivener (evidence + candidates), the VM is the judge.

 SAFETY: loads a kernel driver. Run ONLY in a disposable VM or snapshotted host.
   - must pass -IAmInADisposableVM (refuses otherwise)
   - run elevated (UAC); driver load needs admin
   - if any gate fails (load error / device absent), it STOPS before the sweep
=============================================================================
#>
param(
  [switch]$IAmInADisposableVM,

  # ---- CONFIG: AI fills these from summary.md + <name>.c (one driver) ----
  [ValidateSet('service','pnp')]
  [string]  $LoadMode    = 'service',                 # 'service' = sc start (strongest c); 'pnp' = devcon install INF
  [string]  $SysPath     = 'FILL\<name>.sys',         # absolute path to the .sys
  [string]  $ServiceName = 'FILLsvc',                 # short kernel-service name (service mode)
  [string]  $InfPath     = '',                        # pnp mode: path to .inf
  [string]  $HardwareId  = 'root\FILL',               # pnp mode: devnode to install
  [string]  $DeviceUser  = '\\.\FILL',                # user-mode device: \DosDevices\X  ->  \\.\X
  [string]  $ExpectSid   = 'WD',                      # SID we expect to be granted (sanity: WD=Everyone)
  [uint32[]]$Ioctls      = @(),                        # candidate IOCTL codes read from the dispatch in <name>.c
  # payloads to try as INJECT buffers (tailor to the report descriptor). dX/dY!=0 => injects.
  [System.Collections.IDictionary]$Payloads = [ordered]@{
    'mouse4 btn,dx,dy,whl' = [byte[]](0x00,0x32,0x00,0x00)
    'mouse5 id2,...'       = [byte[]](0x02,0x00,0x32,0x00,0x00)
  },
  # ------------------------------------------------------------------------

  [int]    $TimeoutMs = 300,
  [switch] $Cleanup   = $true
)

$ErrorActionPreference = 'Continue'
if (-not $IAmInADisposableVM) {
  Write-Host "REFUSING: pass -IAmInADisposableVM to confirm this is a disposable VM / snapshotted host." -ForegroundColor Red
  exit 2
}

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class Nq {
  [DllImport("kernel32",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFileW(string n,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
  [DllImport("kernel32",SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr h,uint code,byte[] inb,uint ins,byte[] outb,uint outs,out uint ret,byte[] ov);
  [DllImport("kernel32",SetLastError=true)] public static extern IntPtr CreateEventW(IntPtr a,bool m,bool i,string n);
  [DllImport("kernel32",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr h,uint ms);
  [DllImport("kernel32",SetLastError=true)] public static extern bool CancelIoEx(IntPtr h,byte[] ov);
  [DllImport("kernel32",SetLastError=true)] public static extern bool GetOverlappedResult(IntPtr h,byte[] ov,out uint ret,bool wait);
  [DllImport("kernel32",SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern uint GetNamedSecurityInfoW(string n,int ot,uint si,IntPtr o,IntPtr g,out IntPtr dacl,IntPtr sacl,out IntPtr sd);
  [DllImport("advapi32",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd,uint rev,uint si,out IntPtr str,out int len);
  [DllImport("user32")] public static extern bool GetCursorPos(out POINT p);
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
}
'@

$INVALID=[IntPtr](-1); $FILE_FLAG_OVERLAPPED=0x40000000; $GENERIC_RW=[uint32]'0xC0000000'; $PENDING=997; $WAIT_TIMEOUT=0x102
$hEvent=[Nq]::CreateEventW([IntPtr]::Zero,$true,$false,$null)

function Get-DevSddl([string]$dev){
  $d=[IntPtr]::Zero;$sd=[IntPtr]::Zero
  $r=[Nq]::GetNamedSecurityInfoW($dev,1,4,[IntPtr]::Zero,[IntPtr]::Zero,[ref]$d,[IntPtr]::Zero,[ref]$sd)
  if($r -ne 0){ return $null }
  $s=[IntPtr]::Zero;$l=0
  [void][Nq]::ConvertSecurityDescriptorToStringSecurityDescriptorW($sd,1,4,[ref]$s,[ref]$l)
  [Runtime.InteropServices.Marshal]::PtrToStringUni($s)
}
function Dio([IntPtr]$h,[uint32]$code,[byte[]]$pl){
  $outb=New-Object byte[] 64; $ov=New-Object byte[] 32
  [BitConverter]::GetBytes([int64]$hEvent).CopyTo($ov,24); $ret=0
  $b=New-Object Nq+POINT;[void][Nq]::GetCursorPos([ref]$b)
  $ok=[Nq]::DeviceIoControl($h,$code,$pl,[uint32]$pl.Length,$outb,64,[ref]$ret,$ov)
  $err=[Runtime.InteropServices.Marshal]::GetLastWin32Error();$to=$false
  if(-not $ok -and $err -eq $PENDING){
    if([Nq]::WaitForSingleObject($hEvent,$TimeoutMs) -eq $WAIT_TIMEOUT){[void][Nq]::CancelIoEx($h,$ov);$to=$true}
    else{$ok=[Nq]::GetOverlappedResult($h,$ov,[ref]$ret,$false);$err=[Runtime.InteropServices.Marshal]::GetLastWin32Error()}
  }
  Start-Sleep -Milliseconds 50
  $a=New-Object Nq+POINT;[void][Nq]::GetCursorPos([ref]$a)
  [pscustomobject]@{IOCTL=('0x{0:X}' -f $code);Len=$pl.Length;OK=$ok;Pend=$to;Err=$err;BytesRet=$ret;dX=($a.X-$b.X);dY=($a.Y-$b.Y)}
}

# ===================== A. SAFE LOAD (gates) =====================
Write-Host "=== A. load ($LoadMode) ===" -ForegroundColor Cyan
if($LoadMode -eq 'service'){
  & sc.exe create $ServiceName type= kernel binPath= "$SysPath" start= demand | Out-Host
  $start = & sc.exe start $ServiceName 2>&1 | Out-String
  Write-Host $start
  $q = & sc.exe query $ServiceName 2>&1 | Out-String
  if($q -notmatch 'RUNNING'){
    Write-Host "GATE FAIL: service not RUNNING (load error / WDF bind). Not sweeping." -ForegroundColor Red
    Write-Host $q
    if($Cleanup){ & sc.exe delete $ServiceName | Out-Null }
    exit 1
  }
  Write-Host "gate ok: service RUNNING" -ForegroundColor Green
} else {
  $devcon = Join-Path (Split-Path $InfPath) 'devcon.exe'
  & $devcon install $InfPath $HardwareId | Out-Host
  Start-Sleep -Milliseconds 800
}

# device object must exist, else the driver didn't create the user-reachable device
$sddl = Get-DevSddl $DeviceUser
if(-not $sddl){
  Write-Host "GATE FAIL: $DeviceUser not present (no user-reachable device). Not sweeping." -ForegroundColor Red
  if($Cleanup){ if($LoadMode -eq 'service'){ & sc.exe stop $ServiceName|Out-Null; & sc.exe delete $ServiceName|Out-Null } }
  exit 1
}
Write-Host "gate ok: device present" -ForegroundColor Green

# ===================== B. (c) REACHABILITY =====================
Write-Host "`n=== B. (c) reachability ===" -ForegroundColor Cyan
Write-Host "SDDL: $sddl"
Write-Host ("grants $ExpectSid : {0}" -f ($sddl -match [regex]::Escape($ExpectSid)))
$h=[Nq]::CreateFileW($DeviceUser,$GENERIC_RW,3,[IntPtr]::Zero,3,$FILE_FLAG_OVERLAPPED,[IntPtr]::Zero)
if($h -eq $INVALID){ Write-Host ("OPEN FAILED err={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) -ForegroundColor Red }
else { Write-Host ("OPEN OK handle=0x{0:X}  => (c) TRUE" -f [int64]$h) -ForegroundColor Green }

# ===================== C. (b) INJECTION SWEEP =====================
if($h -ne $INVALID -and $Ioctls.Count -gt 0){
  Write-Host "`n=== C. (b) sweep (cursor delta; $TimeoutMs ms timeout) ===" -ForegroundColor Cyan
  foreach($code in $Ioctls){ foreach($pn in $Payloads.Keys){
    $r=Dio $h ([uint32]$code) ([byte[]]$Payloads[$pn])
    Write-Host ("{0,-9} {1,-22} OK={2,-5} Pend={3,-5} Err={4,-5} Bytes={5,-4} dX={6,-4} dY={7}" -f `
      $r.IOCTL,$pn,$r.OK,$r.Pend,$r.Err,$r.BytesRet,$r.dX,$r.dY)
  }}
  Write-Host ">>> dX/dY != 0 => (b) INJECTS. Pend=True => blocking read. Bytes>0 no-move => read/intercept." -ForegroundColor Yellow
} elseif($Ioctls.Count -eq 0){ Write-Host "`n(no IOCTLs configured; (b) sweep skipped)" -ForegroundColor DarkYellow }

if($h -ne $INVALID){ [void][Nq]::CloseHandle($h) }

# ===================== D. CLEANUP =====================
if($Cleanup){
  Write-Host "`n=== D. cleanup ===" -ForegroundColor Cyan
  if($LoadMode -eq 'service'){ & sc.exe stop $ServiceName|Out-Null; & sc.exe delete $ServiceName|Out-Null; Write-Host "service removed" }
  else { $devcon=Join-Path (Split-Path $InfPath) 'devcon.exe'; & $devcon remove $HardwareId|Out-Null; Write-Host "pnp device removed" }
  Write-Host "(revert the snapshot for a fully clean state)"
}
