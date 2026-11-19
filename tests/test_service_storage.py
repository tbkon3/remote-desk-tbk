"""Avvio privilegiato con cartelle temporanee e controlli Windows simulati."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import rd
from rd import common, service
from rd.updater import system_tool


class ServiceStorageTests(unittest.TestCase):
    def run_repair_fixture(self, cases, fixture_dir=None):
        script = Path(__file__).resolve().parents[1] / "tools" / "Ripara-permessi-servizio.ps1"
        # Import only function definitions. No entry point, elevation, scheduler or host ACLs.
        fixture = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:RD_TEST_REPAIR, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw $errors[0].Message }
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -is [Management.Automation.Language.FunctionDefinitionAst]) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}
$trusted = @('S-1-5-18','S-1-5-32-544')
$required = '(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)'
$readable = '(A;OICIID;0x1200a9;;;BU)(A;OICIIOID;GA;;;CO)'
$legacy = '(A;CIID;0x116;;;BU)'
function Descriptor([string]$sddl) {
    [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
}
function Inspect-ReleaseParent($raw) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($raw.GetSddlForm('All'))
    function Get-Item { param($LiteralPath,[switch]$Force)
        return [pscustomobject]@{PSIsContainer=$true; Attributes=[IO.FileAttributes]::Directory}
    }
    function Get-Acl { param($LiteralPath) return $acl }
    Inspect-DataParent 'C:\Synthetic\ProgramData\RemoteDesk'
}
"""
        shell = system_tool(r"WindowsPowerShell\v1.0\powershell.exe")
        env = {**os.environ, "RD_TEST_REPAIR": str(script)}
        if fixture_dir is not None:
            env["RD_TEST_DIR"] = str(fixture_dir)
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command",
             "& ([ScriptBlock]::Create([Console]::In.ReadToEnd()))"],
            input=fixture + common.WINDOWS_PRIVATE_DIRECTORY_POLICY + "\n" + cases,
            text=True, capture_output=True, timeout=30, env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    @unittest.skipUnless(os.name == "nt", "descrittori di sicurezza Windows")
    def test_repair_removes_only_legacy_ace_and_satisfies_released_policy(self):
        self.run_repair_fixture(r"""
function Entries($raw) {
    # Protecting the DACL can materialize inherited ACEs. Compare everything else, including order.
    foreach ($entry in $raw.DiscretionaryAcl) {
        $bytes = [byte[]]::new($entry.BinaryLength)
        $entry.GetBinaryForm($bytes, 0)
        $bytes[1] = $bytes[1] -band 0xef
        [Convert]::ToBase64String($bytes)
    }
}
foreach ($owner in 'BA','SY') {
    $before = Descriptor ("O:" + $owner + "G:SYD:AI" + $required + $legacy + $readable + 'S:(AU;SA;FR;;;WD)')
    $original = $before.GetSddlForm('All')
    if ((Get-LegacyParentPlan $before) -ne 'Legacy') { throw 'historical descriptor not recognized' }
    $releaseRejected = $false
    try { Inspect-ReleaseParent $before }
    catch { if ($_.Exception.Message -ne 'parent mutable') { throw }; $releaseRejected = $true }
    if (!$releaseRejected) { throw 'fixture did not reproduce the 2.4.0 error' }

    $expected = Descriptor ($original)
    for ($i = 0; $i -lt $expected.DiscretionaryAcl.Count; $i++) {
        $ace = $expected.DiscretionaryAcl[$i]
        if ($ace.SecurityIdentifier.Value -eq 'S-1-5-32-545' -and $ace.AccessMask -eq 0x116) {
            $expected.DiscretionaryAcl.RemoveAce($i)
            break
        }
    }
    $after = New-ParentDescriptor $before
    if ($before.GetSddlForm('All') -cne $original) { throw 'plan mutated its input' }
    if (($after.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) {
        throw 'future inheritance still enabled'
    }
    if (($after.GetSddlForm('Owner,Group,Audit') -cne $before.GetSddlForm('Owner,Group,Audit')) -or
        ((@(Entries $after) -join ' ') -cne (@(Entries $expected) -join ' '))) { throw 'unexpected descriptor change' }
    if ((Get-LegacyParentPlan $after) -ne 'Safe') { throw 'second run would modify the DACL' }
    Inspect-ReleaseParent $after
}
""")

    @unittest.skipUnless(os.name == "nt", "descrittori di sicurezza Windows")
    def test_repair_only_recognizes_the_exact_historical_parent(self):
        self.run_repair_fixture(r"""
$base = 'O:BAG:SYD:AI' + $required + $readable
$invalid = @(
    ($base + '(A;CI;0x116;;;BU)'),
    ($base + '(A;OICIID;0x116;;;BU)'),
    ($base + '(A;CIIOID;0x116;;;BU)'),
    ($base + '(A;CINPID;0x116;;;BU)'),
    ($base + '(A;CIID;0x116;;;AU)'),
    ($base + $legacy + $legacy),
    ($base + $legacy + '(A;;DC;;;AU)'),
    ($base + $legacy + '(A;;GW;;;WD)'),
    ('O:BAG:SYD:AI(D;;DC;;;AN)' + $required + $readable + $legacy),
    ('O:BAG:SYD:AI(A;;FR;;;AU)' + $required + $readable + $legacy),
    ('O:BUG:SYD:AI' + $required + $readable + $legacy),
    ('O:BAG:SYD:PAI' + $required + $readable + $legacy),
    ('O:BAG:SYD:AI(A;OICIID;FA;;;SY)' + $readable + $legacy),
    'O:BAG:SY'
)
foreach ($mask in '0x2','0x4','0x100','0x156','0x10116','0x40116','0x80116') {
    $invalid += $base + "(A;CIID;$mask;;;BU)"
}
foreach ($sddl in $invalid) {
    $raw = Descriptor $sddl
    $original = $raw.GetSddlForm('All')
    $rejected = $false
    try { $state = Get-LegacyParentPlan $raw } catch { $rejected = $true }
    if (!$rejected -and $state -in 'Safe','Legacy') { throw "accepted unexpected descriptor $sddl" }
    if ($raw.GetSddlForm('All') -cne $original) { throw 'inspection altered a rejected descriptor' }
}
""")

    @unittest.skipUnless(os.name == "nt", "dispatcher PowerShell Windows")
    def test_repair_is_read_only_by_default_and_aborts_before_writing(self):
        self.run_repair_fixture(r"""
$script:paths = [pscustomobject]@{Parent='C:\Synthetic\ProgramData\RemoteDesk'}
$script:approved = Descriptor ('O:BAG:SYD:AI' + $required + $legacy + $readable)
function Test-RepairContext {}
function Initialize-RepairNative {}
function Get-RepairPaths { return $script:paths }
function Get-VerifiedRepairState($target) {
    if ($target -ne $script:paths) { throw 'wrong paths' }
    $script:checks++
    if ($script:state -eq 'Rejected') { throw 'resources not trusted' }
    return [pscustomobject]@{Plan=$script:state;Descriptor=$script:approved}
}
function Set-ParentDacl($target,$descriptor) {
    if ($target -ne $script:paths -or $descriptor -ne $script:approved) { throw 'wrong target or descriptor' }
    $script:writes++
}
foreach ($case in 'audit','apply','safe','rejected') {
    $script:checks = $script:writes = 0
    $script:state = switch ($case) {'safe' {'Safe'}; 'rejected' {'Rejected'}; default {'Legacy'}}
    $rejected = $false
    try {
        $outcome = if ($case -eq 'audit') { Invoke-RemoteDeskRepair } else { Invoke-RemoteDeskRepair -Apply }
    } catch { if ($_.Exception.Message -ne 'resources not trusted') { throw }; $rejected = $true }
    $pattern = switch ($case) {'audit' {'^REPAIRABLE'}; 'apply' {'^REPAIRED'}; 'safe' {'^SAFE'}}
    if (($case -ne 'rejected' -and $outcome -notmatch $pattern) -or $rejected -ne ($case -eq 'rejected') -or
        $script:checks -ne 1 -or $script:writes -ne [int]($case -eq 'apply')) { throw "unexpected actions: $case" }
}
""")

    @unittest.skipUnless(os.name == "nt", "descrittori di sicurezza Windows")
    def test_repair_aborts_if_parent_dacl_changes_after_audit(self):
        self.run_repair_fixture(r"""
$original = Descriptor ('O:BAG:SYD:AI' + $required + $legacy + $readable)
$script:observed = Descriptor ('O:BAG:SYD:AI' + $required + $legacy + $readable + '(A;;DC;;;WD)')
function Get-RdDescriptor($p) { return $script:observed }
function Assert-RdOnlyData($paths) { throw 'write preparation must not be reached' }
$rejected = $false
try { Set-ParentDacl ([pscustomobject]@{Parent='C:\Synthetic\ProgramData\RemoteDesk'}) $original }
catch {
    if ($_.Exception.Message -notmatch 'DACL cambiata') { throw }
    $rejected = $true
}
if (!$rejected) { throw 'changed descriptor accepted' }
""")

    @unittest.skipUnless(os.name == "nt", "collegamenti NTFS Windows")
    def test_repair_refuses_existing_junction_and_hardlinked_file(self):
        import _winapi
        with tempfile.TemporaryDirectory(prefix="rd-links-") as temporary:
            root = Path(temporary)
            real_data = root / "fixture-data"
            real_data.mkdir()
            (real_data / "marker").write_bytes(b"private fixture")
            original = root / "original.txt"
            original.write_bytes(b"linked fixture")
            os.link(original, root / "alias.txt")
            junction = root / "data"
            _winapi.CreateJunction(str(real_data), str(junction))
            try:
                self.run_repair_fixture(r"""
$rejected = $false
try { Assert-RdTree ([IO.Path]::Combine($env:RD_TEST_DIR,'data')) -Private }
catch { if ($_.Exception.Message -notmatch 'reparse point') { throw }; $rejected = $true }
if (!$rejected) { throw 'preexisting junction accepted' }
Initialize-RepairNative
[RemoteDeskRepair.Native]::SingleFile([IO.Path]::Combine($env:RD_TEST_DIR,'fixture-data','marker'))
$rejected = $false
try { [RemoteDeskRepair.Native]::SingleFile([IO.Path]::Combine($env:RD_TEST_DIR,'alias.txt')) }
catch { if ($_.Exception.Message -notmatch 'nomi aggiuntivi') { throw }; $rejected = $true }
if (!$rejected) { throw 'hard link accepted' }
""", root)
            finally:
                junction.rmdir()
            self.assertEqual((real_data / "marker").read_bytes(), b"private fixture")
            self.assertEqual(original.read_bytes(), b"linked fixture")

    @unittest.skipUnless(os.name == "nt", "Task Scheduler Windows simulato")
    def test_migrates_only_known_task_and_preserves_dacl(self):
        # Intercetta la creazione COM: nessun accesso allo scheduler della macchina.
        fixture = r"""
$ErrorActionPreference = 'Stop'
$env:RD_INSTALL = 'C:\Synthetic App'
$env:RD_PYW = 'C:\Synthetic App\runtime\pythonw.exe'
$env:RD_LEGACY_ARGS = '"C:\Synthetic App\app\remotedesk.py" --service --data "C:\Synthetic Data"'
$env:RD_MODERN_ARGS = '-E -s ' + $env:RD_LEGACY_ARGS
function New-Object { param($ComObject) if ($ComObject -ne 'Schedule.Service') { throw 'unexpected COM' }; return $script:scheduler }
$script:scheduler = [pscustomobject]@{}
$scheduler | Add-Member ScriptMethod Connect {}
$scheduler | Add-Member ScriptMethod GetFolder { param($path) if ($path -ne '\') { throw 'unexpected folder' }; return $script:folder }
$script:folder = [pscustomobject]@{}
$folder | Add-Member ScriptMethod GetTask { param($name) if ($name -ne 'RemoteDesk') { throw 'unexpected task' }; return $script:task }
$folder | Add-Member ScriptMethod RegisterTaskDefinition {
    param($name,$def,$flags,$user,$password,$logon,$sddl)
    if ($name -ne 'RemoteDesk' -or $flags -ne 52 -or $logon -ne 5 -or $null -ne $sddl -or
        $null -ne $password -or $def.Actions.Item(1).Arguments -cne $env:RD_MODERN_ARGS) { throw 'unexpected update' }
    $script:changes++
}
$actions = [pscustomobject]@{Count=1}
$actions | Add-Member ScriptMethod Item { param($index) if ($index -ne 1) { throw 'bad index' }; return $script:action }
$triggers = [pscustomobject]@{Count=1}
$triggers | Add-Member ScriptMethod Item { param($index) return [pscustomobject]@{Type=8} }
$principal = [pscustomobject]@{UserId='S-1-5-18';LogonType=5;RunLevel=1}
$script:task = [pscustomobject]@{Path='\RemoteDesk';Enabled=$true;Definition=[pscustomobject]@{Actions=$actions;Triggers=$triggers;Principal=$principal}}
$task | Add-Member ScriptMethod GetSecurityDescriptor { param($sections) if ($sections -ne 7) { throw 'bad sections' }; return $script:sddl }
"""
        cases = r"""
foreach ($case in 'legacy','current','custom','mutable') {
    $script:sddl = 'O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    $arg = $env:RD_LEGACY_ARGS
    if ($case -eq 'current') { $arg = $env:RD_MODERN_ARGS }
    if ($case -eq 'custom') { $arg = '--different' }
    if ($case -eq 'mutable') { $script:sddl = 'O:BAG:SYD:P(A;;FA;;;SY)(A;;GW;;;BU)' }
    $script:action = [pscustomobject]@{Type=0;Path=$env:RD_PYW;WorkingDirectory=$env:RD_INSTALL;Arguments=$arg}
    $script:changes = 0
    $rejected = $false
    try { & $migration } catch { $rejected = $true }
    if ($rejected -ne ($case -in 'custom','mutable') -or $script:changes -ne [int]($case -eq 'legacy')) { throw "case $case" }
}
"""
        with patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0)) as capture:
            service.prepare_existing_task()
        command = capture.call_args.args[0][-1]
        shell = system_tool(r"WindowsPowerShell\v1.0\powershell.exe")
        proc = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command",
                               "& ([ScriptBlock]::Create([Console]::In.ReadToEnd()))"],
                              input=fixture + "\n$migration = {\n" + command + "\n}\n" + cases,
                              text=True, capture_output=True, timeout=25)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    @unittest.skipUnless(os.name == "nt", "descrittori di sicurezza Windows")
    def test_windows_ancestry_checks_synthetic_descriptors(self):
        # Intercetta i due cmdlet di lettura. Oggetti e DACL sono solo in memoria.
        fixture = r"""
$ErrorActionPreference='Stop'
function Get-Item { param($LiteralPath,[switch]$Force) return [pscustomobject]@{PSIsContainer=$true;Attributes=[IO.FileAttributes]::Directory} }
function Get-Acl { param($LiteralPath) return $script:descriptor }
$script:descriptor=[Security.AccessControl.DirectorySecurity]::new()
"""
        cases = r"""
$script:descriptor.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;0x4;;;WD)')
Assert-TrustedAncestry 'C:\Synthetic\Test'
$script:descriptor.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;0x40;;;WD)')
try { Assert-TrustedAncestry 'C:\Synthetic\Test'; exit 5 } catch { if ($_.Exception.Message -notmatch 'ancestor replacement') { throw } }
$trusted = @('S-1-5-18','S-1-5-32-544')
$script:descriptor.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;GA;;;CO)')
Inspect-DataParent 'C:\Synthetic\Test'
try { Inspect 'C:\Synthetic\Test'; exit 7 } catch { if ($_.Exception.Message -notmatch 'ACE') { throw } }
foreach ($rights in '0x2','0x4','0x40','0x100','0x40000','0x80000','GW') {
    $script:descriptor.SetSecurityDescriptorSddlForm("O:BAD:P(A;;FA;;;SY)(A;;$rights;;;BU)")
    try { Inspect-DataParent 'C:\Synthetic\Test'; exit 8 } catch { if ($_.Exception.Message -notmatch 'parent mutable') { throw } }
}
$script:descriptor.SetSecurityDescriptorSddlForm('O:BUD:P(A;;FA;;;SY)')
try { Inspect-DataParent 'C:\Synthetic\Test'; exit 9 } catch { if ($_.Exception.Message -notmatch 'parent owner') { throw } }
$script:descriptor.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
Inspect 'C:\Synthetic\Test'
$script:descriptor.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
try { Inspect 'C:\Synthetic\Test'; exit 6 } catch { if ($_.Exception.Message -notmatch 'inheritance') { throw } }
$public = 'C:\Synthetic\ProgramData'
$baseline = [Security.AccessControl.DirectorySecurity]::new()
$baseline.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;0x1200a9;;;BU)')
$mutable = [Security.AccessControl.DirectorySecurity]::new()
$mutable.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;0x10000;;;BU)')
$script:anchorRemovable = $false
function Get-Acl { param($LiteralPath)
    if ($LiteralPath -eq $public) { return $script:descriptor }
    if ($LiteralPath -like "$public\*" -and $script:anchorRemovable) { return $mutable }
    return $baseline
}
$script:descriptor.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;0x116;;;BU)')
Assert-TrustedAncestry $public $public
try { Assert-TrustedAncestry $public; exit 10 } catch { if ($_.Exception.Message -notmatch 'ancestor replacement') { throw } }
$script:anchorRemovable = $true
try { Assert-TrustedAncestry $public $public; exit 11 } catch { if ($_.Exception.Message -notmatch 'ancestor replacement') { throw } }
$script:anchorRemovable = $false
foreach ($mask in '0x156','0x10116','0x40116','0x80116') {
    $script:descriptor.SetSecurityDescriptorSddlForm("O:BAD:P(A;;FA;;;SY)(A;;$mask;;;BU)")
    try { Assert-TrustedAncestry $public $public; exit 12 } catch { if ($_.Exception.Message -notmatch 'ancestor replacement') { throw } }
}
try { Inspect-DataParent $public; exit 13 } catch { if ($_.Exception.Message -notmatch 'parent mutable') { throw } }
exit 0
"""
        shell = system_tool(r"WindowsPowerShell\v1.0\powershell.exe")
        functions = common.WINDOWS_ANCESTOR_POLICY + common.WINDOWS_PRIVATE_DIRECTORY_POLICY
        result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command",
                                 "& ([ScriptBlock]::Create([Console]::In.ReadToEnd()))"],
                                input=fixture + functions + cases,
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_privileged_override_never_falls_back(self):
        with (tempfile.TemporaryDirectory() as tmp, patch.object(common, "WIN", True),
              patch.object(common, "PROGRAM_DATA", str(Path(tmp) / "managed" / "data")),
              patch.object(common, "secure_dir") as secure):
            with self.assertRaises(ValueError):
                common.pick_data_dir(str(Path(tmp) / "user-data"), service=True)
            secure.assert_not_called()
            self.assertEqual(common.pick_data_dir(service=True), common.PROGRAM_DATA)
            secure.assert_called_once_with(common.PROGRAM_DATA)
            with patch.object(common, "WIN", False), self.assertRaises(ValueError):
                common.pick_data_dir(str(Path(tmp) / "unsupported"), service=True)
            self.assertFalse((Path(tmp) / "unsupported").exists())

    def test_outside_staging_rejected_without_subprocess(self):
        with (tempfile.TemporaryDirectory() as tmp, patch.object(common, "WIN", True),
              patch.object(common, "PROGRAM_DATA", str(Path(tmp) / "managed" / "data")),
              patch.object(subprocess, "run") as launch):
            with self.assertRaises(ValueError):
                common.secure_dir(str(Path(tmp) / "managed-elsewhere"))
            launch.assert_not_called()

    def test_failed_acl_check_stops_before_file_inspection(self):
        with (tempfile.TemporaryDirectory() as tmp, patch.object(common, "WIN", True),
              patch.object(common, "PROGRAM_DATA", str(Path(tmp) / "managed" / "data")),
              patch("rd.updater.system_tool", side_effect=lambda name: str(Path(tmp) / "system" / name)),
              patch.object(subprocess, "run", return_value=SimpleNamespace(
                  returncode=1, stdout=b"RDACL system parent; ancestor replacement; S-1-5-32-545; 00000040\r\n")) as launch,
              patch.object(common, "_private_files_single_link") as inspect):
            with self.assertRaisesRegex(PermissionError, "ancestor replacement.*00000040"):
                common.secure_dir(common.PROGRAM_DATA)
            self.assertEqual(launch.call_args.kwargs["env"]["RD_DATA_TARGET"], common.PROGRAM_DATA)
            self.assertEqual(launch.call_args.kwargs["env"]["RD_COMMON_ROOT"], str(Path(common.PROGRAM_DATA).parent.parent))
            self.assertNotIn("GetFolderPath", launch.call_args.args[0][-1])
            inspect.assert_not_called()

    def test_only_single_link_files_in_private_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "managed" / "data"
            data.mkdir(parents=True)
            log = data / "service.log"
            log.write_text("test")
            common._private_files_single_link(data)
            linked = SimpleNamespace(st_nlink=2, st_mode=log.stat().st_mode, st_file_attributes=0)
            with patch.object(common.os, "lstat", return_value=linked), self.assertRaises(PermissionError):
                common._private_files_single_link(data)

    def test_supervisor_never_spawns_from_unverified_tree(self):
        fake = Mock()
        with (tempfile.TemporaryDirectory() as tmp, patch.object(rd, "winapi", fake, create=True),
              patch.object(service, "INSTALL_DIR", tmp), patch.object(service, "ROOT_DIR", tmp),
              patch.object(service.sys, "executable", str(Path(tmp) / "runtime" / "pythonw.exe")),
              patch.object(service, "_verify_installation", side_effect=PermissionError("DACL")) as verify,
              patch.object(service, "secure_dir") as data):
            for path in service.installed_paths():
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).touch()
            with self.assertRaises(PermissionError):
                service.run_supervisor()
            verify.assert_called_once()
            fake.spawn_in_session.assert_not_called()
            data.assert_not_called()


if __name__ == "__main__":
    unittest.main()
