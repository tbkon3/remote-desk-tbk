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
              patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=1)) as launch,
              patch.object(common, "_private_files_single_link") as inspect):
            with self.assertRaises(PermissionError):
                common.secure_dir(common.PROGRAM_DATA)
            self.assertEqual(launch.call_args.kwargs["env"]["RD_DATA_TARGET"], common.PROGRAM_DATA)
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
