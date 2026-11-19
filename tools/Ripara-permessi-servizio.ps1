#requires -version 5.1
[CmdletBinding()]
param([switch]$Apply)

# Riparazione locale per il passaggio dalla 2.3.2. Senza -Apply non scrive.
function Get-LegacyParentPlan([Security.AccessControl.RawSecurityDescriptor]$descriptor) {
    $trusted = @('S-1-5-18','S-1-5-32-544')
    if (!$descriptor.Owner -or $trusted -notcontains $descriptor.Owner.Value -or $null -eq $descriptor.DiscretionaryAcl) {
        throw 'Proprietario o DACL del padre non riconosciuti.'
    }
    $legacy = 0
    $full = @{}
    $stock = $true
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        $flags = [int]$ace.AceFlags
        if ($ace.AceType -eq 'AccessDenied') { $stock = $false; continue }
        if ($ace.AceType -ne 'AccessAllowed') { throw 'ACE inattesa sul padre.' }
        $sid = $ace.SecurityIdentifier.Value
        if ($trusted -contains $sid) {
            if (($flags -band 15) -eq 3 -and $ace.AccessMask -eq 0x1f01ff) { $full[$sid] = $true }
            else { $stock = $false }
            continue
        }
        if ($sid -eq 'S-1-3-0' -and ($flags -band 8)) { continue }
        if ($sid -eq 'S-1-5-32-545' -and $flags -eq 0x12 -and $ace.AccessMask -eq 0x116) { $legacy++; continue }
        if ($ace.AccessMask -band (-bnot 0xA01200A9)) { throw 'Permessi di scrittura estranei.' }
        if ($sid -ne 'S-1-5-32-545') { $stock = $false }
    }
    if (!$legacy) { return 'Safe' }
    if ($legacy -ne 1 -or !$stock -or !$full['S-1-5-18'] -or !$full['S-1-5-32-544'] -or
        ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)) {
        throw 'La DACL non corrisponde al profilo legacy riconosciuto.'
    }
    return 'Legacy'
}

function New-ParentDescriptor([Security.AccessControl.RawSecurityDescriptor]$descriptor) {
    if ((Get-LegacyParentPlan $descriptor) -ne 'Legacy') { throw 'Riparazione non necessaria.' }
    $buffer = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($buffer,0)
    $copy = [Security.AccessControl.RawSecurityDescriptor]::new($buffer,0)
    for ($i = $copy.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) {
        $ace = $copy.DiscretionaryAcl[$i]
        if ($ace.AceType -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -eq 'S-1-5-32-545' -and
            [int]$ace.AceFlags -eq 0x12 -and $ace.AccessMask -eq 0x116) {
            $copy.DiscretionaryAcl.RemoveAce($i)
        } else { $ace.AceFlags = [Security.AccessControl.AceFlags]([int]$ace.AceFlags -band (-bnot 16)) }
    }
    $copy.SetFlags($copy.ControlFlags -bor [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
    if ((Get-LegacyParentPlan $copy) -ne 'Safe') { throw 'Descrittore di destinazione non valido.' }
    return $copy
}

function Initialize-RepairNative {
    if ('RemoteDeskRepair.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace RemoteDeskRepair {
    public static class Native {
        [DllImport("shell32.dll", CharSet=CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int SHGetFolderPathW(IntPtr w, int id, IntPtr token, uint flags, StringBuilder output);
        public static string Folder(int id) {
            var s = new StringBuilder(260);
            if (SHGetFolderPathW(IntPtr.Zero,id,IntPtr.Zero,0,s)!=0 || s.Length==0) throw new IOException("Cartella Windows sconosciuta.");
            return Path.GetFullPath(s.ToString());
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInfoNative {
            public uint Attr; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, HighSize, LowSize, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle h, out FileInfoNative info);
        public static void SingleFile(string p) {
            using (var h = CreateFileW(p,0x80,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero)) {
                FileInfoNative info;
                if (h.IsInvalid || !GetFileInformationByHandle(h,out info)) throw new Win32Exception();
                if ((info.Attr & 0x410) != 0 || info.Links != 1) throw new IOException("File reindirizzato o con nomi aggiuntivi.");
            }
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
        public static SafeFileHandle PinDirectory(string p, bool apply) {
            // No FILE_SHARE_DELETE. L'identita' di questa directory resta fissata durante la verifica.
            var h = CreateFileW(p,apply ? 0x02000000u : 0x80u,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            try {
                FileInfoNative info;
                if (h.IsInvalid || !GetFileInformationByHandle(h,out info)) throw new Win32Exception();
                if ((info.Attr & 0x410)!=0x10) throw new IOException("Directory reindirizzata.");
                var resolved = new StringBuilder(32768);
                uint size = GetFinalPathNameByHandleW(h,resolved,(uint)resolved.Capacity,0);
                if (size==0 || size>=resolved.Capacity) throw new Win32Exception();
                if (!String.Equals(resolved.ToString(),@"\\?\"+Path.GetFullPath(p),StringComparison.OrdinalIgnoreCase))
                    throw new IOException("La directory non corrisponde al percorso locale verificato.");
                return h;
            } catch { h.Dispose(); throw; }
        }
        [DllImport("advapi32.dll", SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr acl, out bool defaulted);
        [DllImport("advapi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint SetSecurityInfo(SafeFileHandle h,uint type,uint parts,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
        public static void ProtectParent(SafeFileHandle h, byte[] descriptor) {
            var pinned=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
            try {
                bool present,defaulted; IntPtr acl;
                if (!GetSecurityDescriptorDacl(pinned.AddrOfPinnedObject(),out present,out acl,out defaulted) ||
                    !present || acl==IntPtr.Zero) throw new IOException("DACL di destinazione assente.");
                // SetSecurityInfo con un handle MAXIMUM_ALLOWED non propaga ACE ai figli esistenti.
                uint err=SetSecurityInfo(h,1,0x80000004u,IntPtr.Zero,IntPtr.Zero,acl,IntPtr.Zero);
                if (err!=0) throw new Win32Exception((int)err);
            } finally { pinned.Free(); }
        }
    }
}
'@
}

function Get-RepairPaths {
    $common = [RemoteDeskRepair.Native]::Folder(0x23)
    $programs = [RemoteDeskRepair.Native]::Folder(0x26)
    foreach ($path in $common,$programs) {
        $root = [IO.Path]::GetPathRoot($path)
        if ($root -notmatch '^[a-zA-Z]:\\$') { throw 'Cartella non locale.' }
        $drive = [IO.DriveInfo]::new($root)
        if ($drive.DriveType -ne 'Fixed' -or $drive.DriveFormat -ne 'NTFS') { throw 'Richiesto volume NTFS locale.' }
    }
    $parent = [IO.Path]::Combine($common,'RemoteDesk')
    return [pscustomobject]@{Common=$common;Programs=$programs;Install=[IO.Path]::Combine($programs,'RemoteDesk');
                             Parent=$parent;Data=[IO.Path]::Combine($parent,'data')}
}

function Get-RdDescriptor([string]$p) {
    $attributes = [IO.File]::GetAttributes($p)
    if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Rilevato un reparse point.' }
    $security = if ($attributes -band [IO.FileAttributes]::Directory) { [IO.Directory]::GetAccessControl($p) }
                else { [IO.File]::GetAccessControl($p) }
    return [Security.AccessControl.RawSecurityDescriptor]::new($security.GetSecurityDescriptorBinaryForm(),0)
}

function Assert-RdOwner($sd, $trusted) {
    if (!$sd.Owner -or $trusted -notcontains $sd.Owner.Value -or $null -eq $sd.DiscretionaryAcl) {
        throw 'Proprietario estraneo o DACL assente.'
    }
}

function Assert-RdReadOnly($sd, $trusted, [switch]$Ancestor, [switch]$StockCommon) {
    Assert-RdOwner $sd $trusted
    foreach ($ace in $sd.DiscretionaryAcl) {
        $flags = [int]$ace.AceFlags
        if ($ace.AceType -eq 'AccessDenied' -or ($Ancestor -and ($flags -band 8))) { continue }
        if ($ace.AceType -ne 'AccessAllowed') { throw 'ACE non riconosciuta.' }
        if ($trusted -contains $ace.SecurityIdentifier.Value) { continue }
        if (($flags -band 8) -and $ace.SecurityIdentifier.Value -eq 'S-1-3-0') { continue }
        if ($StockCommon -and $ace.SecurityIdentifier.Value -eq 'S-1-5-32-545' -and $ace.AccessMask -eq 0x116) { continue }
        $forbidden = if ($Ancestor) { 0x500D0150 } else { 0x500D0156 }
        if ($ace.AccessMask -band $forbidden) { throw 'Gerarchia modificabile da un soggetto non attendibile.' }
    }
}

function Assert-RdAncestry([string]$p,[string]$common,$trusted) {
    $chain = [Collections.Generic.Stack[string]]::new()
    while ($p) {
        $chain.Push($p)
        $p = [IO.Path]::GetDirectoryName($p)
    }
    while ($chain.Count) {
        $p = $chain.Pop()
        Assert-RdReadOnly (Get-RdDescriptor $p) $trusted -Ancestor -StockCommon:($p -eq $common)
    }
}

function Assert-RdTree([string]$root,[switch]$Private) {
    $trusted = @('S-1-5-18','S-1-5-32-544')
    if (!$Private) { $trusted += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
    $queue = [Collections.Generic.Stack[string]]::new()
    $queue.Push($root)
    $count = 0
    while ($queue.Count) {
        $p = $queue.Pop()
        if (++$count -gt 65536) { throw 'Troppi oggetti: verifica amministrativa necessaria.' }
        $sd = Get-RdDescriptor $p
        $dir = [IO.Directory]::Exists($p)
        if ($Private) {
            Assert-RdOwner $sd $trusted
            if ($p -eq $root -and !($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)) {
                throw 'La DACL della directory data non e protetta.'
            }
            $inherits = @{}
            foreach ($ace in $sd.DiscretionaryAcl) {
                if ($ace.AceType -eq 'AccessDenied') { continue }
                if ($ace.AceType -ne 'AccessAllowed' -or $trusted -notcontains $ace.SecurityIdentifier.Value) {
                    throw 'Dati esistenti con permessi estranei.'
                }
                if (([int]$ace.AceFlags -band 7) -eq 3 -and ($ace.AccessMask -band 0x1f01ff) -eq 0x1f01ff) {
                    $inherits[$ace.SecurityIdentifier.Value]=$true
                }
            }
            if ($dir -and (!$inherits['S-1-5-18'] -or !$inherits['S-1-5-32-544'])) { throw 'Ereditarieta privata incompleta.' }
        } else { Assert-RdReadOnly $sd $trusted }
        if ($dir) {
            foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($p)) { $queue.Push($child) }
        } else { [RemoteDeskRepair.Native]::SingleFile($p) }
    }
}

function Assert-RdService($paths) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\RemoteDesk',$false)
    if (!$key) { throw 'Servizio RemoteDesk non registrato.' }
    try {
        if ($key.GetValueKind('Service') -ne 'DWord' -or $key.GetValue('Service') -ne 1) { throw 'Marker servizio non valido.' }
        $regSd = [Security.AccessControl.RawSecurityDescriptor]::new($key.GetAccessControl().GetSecurityDescriptorBinaryForm(),0)
        Assert-RdOwner $regSd @('S-1-5-18','S-1-5-32-544')
        foreach ($ace in $regSd.DiscretionaryAcl) {
            if ($ace.AceType -eq 'AccessDenied' -or ([int]$ace.AceFlags -band 8)) { continue }
            if ($ace.AceType -ne 'AccessAllowed' -or
                ($ace.SecurityIdentifier.Value -notin 'S-1-5-18','S-1-5-32-544' -and ($ace.AccessMask -band (-bnot 0xA0120019)))) {
                throw 'Marker servizio modificabile.'
            }
        }
    } finally { $key.Dispose() }
    $scheduler=New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $task=$scheduler.GetFolder('\').GetTask('RemoteDesk')
    $def=$task.Definition
    $sid=$def.Principal.UserId
    if ($sid -ne 'S-1-5-18') { $sid=[Security.Principal.NTAccount]::new($sid).Translate([Security.Principal.SecurityIdentifier]).Value }
    if ($task.Path -ne '\RemoteDesk' -or !$task.Enabled -or $sid -ne 'S-1-5-18' -or $def.Principal.LogonType -ne 5 -or
        $def.Principal.RunLevel -ne 1 -or $def.Triggers.Count -ne 1 -or $def.Triggers.Item(1).Type -ne 8 -or $def.Actions.Count -ne 1) {
        throw 'Attivita servizio non riconosciuta.'
    }
    $acl = [Security.AccessControl.RawSecurityDescriptor]::new($task.GetSecurityDescriptor(7))
    Assert-RdReadOnly $acl @('S-1-5-18','S-1-5-32-544')
    $a=$def.Actions.Item(1)
    $py=[IO.Path]::Combine($paths.Install,'runtime\pythonw.exe')
    $entry=[IO.Path]::Combine($paths.Install,'app\remotedesk.py')
    $argsExpected='"' + $entry + '" --service --data "' + $paths.Data + '"'
    if ($a.Type -ne 0 -or $a.Path -ne $py -or $a.WorkingDirectory -ne $paths.Install -or
        ($a.Arguments -cne $argsExpected -and $a.Arguments -cne ('-E -s '+$argsExpected))) {
        throw 'Percorso o argomenti dell attivita non riconosciuti.'
    }
}

function Assert-RdOnlyData($paths) {
    $children = @([IO.Directory]::EnumerateFileSystemEntries($paths.Parent))
    if ($children.Count -ne 1 -or $children[0] -ne $paths.Data -or ![IO.Directory]::Exists($paths.Data)) {
        throw 'Layout estraneo: il padre legacy deve contenere soltanto la directory data.'
    }
}

function Get-VerifiedRepairState($paths,[switch]$ForApply) {
    $owners = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    Assert-RdAncestry $paths.Common $paths.Common $owners
    Assert-RdAncestry $paths.Programs $paths.Common $owners
    $parent = Get-RdDescriptor $paths.Parent
    $plan = Get-LegacyParentPlan $parent
    if ($plan -eq 'Safe') { return [pscustomobject]@{Plan=$plan;Descriptor=$parent} }
    $pins = [Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    try {
    $pins.Add([RemoteDeskRepair.Native]::PinDirectory($paths.Common,$false))
    $parentHandle = [RemoteDeskRepair.Native]::PinDirectory($paths.Parent,[bool]$ForApply)
    $pins.Add($parentHandle)
    $pins.Add([RemoteDeskRepair.Native]::PinDirectory($paths.Data,$false))
    $parent = Get-RdDescriptor $paths.Parent
    if ((Get-LegacyParentPlan $parent) -ne 'Legacy') { throw 'Directory cambiata: ripetere la verifica.' }
    Assert-RdAncestry $paths.Common $paths.Common $owners
    Assert-RdOnlyData $paths
    Assert-RdTree $paths.Data -Private
    foreach ($item in 'config.json','machine.key') {
        if (![IO.File]::Exists([IO.Path]::Combine($paths.Data,$item))) { throw 'Identita servizio esistente assente.' }
    }
    Assert-RdTree $paths.Install
    foreach ($item in 'app\remotedesk.py','app\rd\common.py','runtime\pythonw.exe','RemoteDesk.exe') {
        if (![IO.File]::Exists([IO.Path]::Combine($paths.Install,$item))) { throw 'Installazione incompleta.' }
    }
    $source = [IO.Path]::Combine($paths.Install,'app\rd\common.py')
    if ([IO.FileInfo]::new($source).Length -gt 262144 -or
        [IO.File]::ReadAllText($source) -notmatch '(?m)^VERSION = "2\.3\.2"\r?$') { throw 'Installazione diversa dalla 2.3.2.' }
    Assert-RdService $paths
    return [pscustomobject]@{Plan=$plan;Descriptor=$parent;Pins=$pins;ParentHandle=$parentHandle}
    } catch {
        foreach ($handle in $pins) { $handle.Dispose() }
        throw
    }
}

function Set-ParentDacl($paths,[Security.AccessControl.RawSecurityDescriptor]$original,$parentHandle) {
    $sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
    $current = Get-RdDescriptor $paths.Parent
    if ($current.GetSddlForm($sections) -cne $original.GetSddlForm($sections)) { throw 'DACL cambiata: ripetere la verifica.' }
    Assert-RdOnlyData $paths
    $changed = New-ParentDescriptor $current
    $bytes = New-Object byte[] $changed.BinaryLength
    $changed.GetBinaryForm($bytes,0)
    [RemoteDeskRepair.Native]::ProtectParent($parentHandle,$bytes)
    $actual = Get-RdDescriptor $paths.Parent
    if ($actual.GetSddlForm($sections) -cne $changed.GetSddlForm($sections)) { throw 'DACL finale inattesa: verifica amministrativa richiesta.' }
    Assert-RdOnlyData $paths
}

function Test-RepairContext {
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or ![Environment]::Is64BitProcess) {
        throw 'Usare Windows PowerShell 5.1 a 64 bit sul PC interessato.'
    }
    if (Get-Variable PSSenderInfo -ErrorAction SilentlyContinue) { throw 'Eseguire dalla console locale.' }
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($id)
    if ($id.IsSystem -or !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Aprire una console locale elevata con un account amministratore.'
    }
}

function Invoke-RemoteDeskRepair([switch]$Apply) {
    $ErrorActionPreference='Stop'
    Test-RepairContext
    Initialize-RepairNative
    $paths=Get-RepairPaths
    $state=Get-VerifiedRepairState $paths -ForApply:$Apply
    try {
        if ($state.Plan -eq 'Safe') { 'SAFE - ACL del padre gia conforme.'; return }
        if (!$Apply) { 'REPAIRABLE - layout 2.3.2 e permesso storico verificati. Usare -Apply per la correzione.'; return }
        Set-ParentDacl $paths $state.Descriptor $state.ParentHandle
        'REPAIRED - rimossa la sola autorizzazione storica sul padre. Riprovare l aggiornamento.'
    } finally {
        foreach ($handle in $state.Pins) { $handle.Dispose() }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-RemoteDeskRepair -Apply:$Apply }
    catch { [Console]::Error.WriteLine('DA VERIFICARE - ' + $_.Exception.Message); exit 1 }
}
