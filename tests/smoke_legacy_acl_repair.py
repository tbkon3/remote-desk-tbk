"""Real NTFS regression, restricted to a clean elevated GitHub-hosted Windows runner.

python tests/smoke_legacy_acl_repair.py --legacy-zip dist/RemoteDesk-2.3.2.zip \
    --candidate-zip dist/RemoteDesk-2.4.0.zip --legacy-manifest path/to/2.3.2-latest.json
"""
import argparse
import ctypes
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

import smoke_legacy_service as fixture


CANDIDATE_SIZE = 53535321
CANDIDATE_HASH = "3e58471929b5e4144c47be617689c2cd5498b6008115e00f6bfb9d8fb803f976"
PRIVATE = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
USERS = "S-1-5-32-545"
SID_ADMIN = "S-1-5-32-544"


def snapshot(parent):
    # The staging runtime is copied only after this test finishes its repair assertions.
    # Record every existing private directory, file, descriptor and content hash.
    payload = fixture.powershell(r"""
$base = [IO.DirectoryInfo]::new($env:RD_TEST_PARENT)
$sections = [Security.AccessControl.AccessControlSections]'Owner,Group,Access'
$rootAcl = $base.GetAccessControl($sections)
$raw = [Security.AccessControl.RawSecurityDescriptor]::new($rootAcl.GetSecurityDescriptorBinaryForm(), 0)
$entries = @(foreach ($entry in $raw.DiscretionaryAcl) {
    [pscustomobject]@{sid=$entry.SecurityIdentifier.Value; type=[int]$entry.AceType;
        flags=[int]$entry.AceFlags; mask=$entry.AccessMask}
})
$tree = @(foreach ($f in ($base.EnumerateFileSystemInfos('*',[IO.SearchOption]::AllDirectories) | Sort-Object FullName)) {
    $hash = ''
    if ($f -is [IO.FileInfo]) {
        $stream = $f.OpenRead()
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') }
            finally { $sha.Dispose() }
        } finally { $stream.Dispose() }
    }
    [pscustomobject]@{path=$f.FullName.Substring($base.FullName.Length);
        acl=$f.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections); sha=$hash}
})
[pscustomobject]@{owner=$raw.Owner.Value; group=$raw.Group.Value; protected=$rootAcl.AreAccessRulesProtected;
    sddl=$rootAcl.GetSecurityDescriptorSddlForm($sections); entries=$entries; tree=$tree} | ConvertTo-Json -Depth 5 -Compress
""", dict(os.environ, RD_TEST_PARENT=str(parent)))
    return json.loads(payload)


def run_repair(apply, expected):
    from rd.updater import system_tool
    shell = system_tool(r"WindowsPowerShell\v1.0\powershell.exe")
    script = fixture.REPO / "tools/Ripara-permessi-servizio.ps1"
    args = [shell, "-NoProfile", "-NonInteractive", "-File", script]
    if apply:
        args.append("-Apply")
    result = fixture.run(args, timeout=360)
    lines = result.stdout.decode("utf-8-sig", errors="replace").splitlines()
    fixture.require(any(line.split(maxsplit=1)[0].rstrip(":") == expected for line in lines if line.strip()),
                    f"Esito strumento inatteso: atteso {expected}, ricevuto {lines[:3]}")


def historical_parent(seed, target, marker):
    from rd.updater import plain_path
    # Reproduce the inheritable entry under our own NTFS ancestor. Renaming on the same
    # volume preserves the child descriptor. Never edit the actual ProgramData ACL.
    ancestor = seed / "seed"
    fixture.create_owned(ancestor, PRIVATE + "(A;OICI;0x1200a9;;;BU)(A;CIIO;0x116;;;BU)", marker)
    child = ancestor / "RemoteDesk"
    child.mkdir()
    fixture.require(plain_path(child).is_dir() and not os.path.lexists(target), "Cartella dati già presente")
    child_id = (child.stat().st_dev, child.stat().st_ino)
    fixture.require(child_id[1] != 0 and child_id[0] == target.parent.stat().st_dev, "Richiesto rename sul medesimo NTFS")
    child.rename(target)
    return child_id


@contextmanager
def owned_registry(marker):
    import winreg
    from ctypes import wintypes as wt
    adv = ctypes.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    create = adv.RegCreateKeyExW
    create.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.DWORD, wt.LPWSTR, wt.DWORD, wt.DWORD,
                       wt.LPVOID, ctypes.POINTER(wt.HANDLE), ctypes.POINTER(wt.DWORD)]
    create.restype = wt.LONG
    close = adv.RegCloseKey
    close.argtypes = [wt.HANDLE]
    close.restype = wt.LONG
    handle, disposition = wt.HANDLE(), wt.DWORD()
    key_name = r"SOFTWARE\RemoteDesk"
    # HKEY_LOCAL_MACHINE is a sign-extended predefined handle on 64-bit Windows.
    from rd.local_access_win import _SecurityAttributes, _Windows
    win = _Windows()
    descriptor = wt.LPVOID()
    if not win.descriptor("O:BAG:BAD:P(A;CI;KA;;;BA)(A;CI;KA;;;SY)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        result = create(wt.HANDLE(-2147483646), key_name, 0, None, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY,
                        ctypes.byref(sa), ctypes.byref(handle), ctypes.byref(disposition))
    finally:
        win.free(descriptor)
    if result:
        raise ctypes.WinError(result)
    key = handle.value
    try:
        fixture.require(disposition.value == 1, "Chiave del servizio preesistente: prova annullata")
        winreg.SetValueEx(key, "RD-CI-Owner", 0, winreg.REG_SZ, marker)
        try:
            winreg.SetValueEx(key, "Service", 0, winreg.REG_DWORD, 1)
            yield
        finally:
            fixture.require(winreg.QueryValueEx(key, "RD-CI-Owner") == (marker, winreg.REG_SZ)
                            and winreg.QueryInfoKey(key)[0] == 0, "Cleanup registro rifiutato")
            winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, key_name, winreg.KEY_WOW64_64KEY)
    finally:
        # RegDeleteKeyEx marks an open key for deletion. Release the handle created by
        # RegCreateKeyExW with its matching API after the ownership check and deletion.
        result = close(handle)
        if result:
            raise ctypes.WinError(result)


def preflight(new, data, installed, temp, before):
    # Before repair use the published candidate's own data validator. After staging call
    # its complete service preflight and task-definition migration, never the updater main.
    script = r"""
import os, subprocess, sys, traceback
from pathlib import Path
from types import SimpleNamespace
root, target, data, trace = map(Path, sys.argv[1:5])
sys.path.insert(0, str(root / "app"))
try:
    from rd import common, updater
    if sys.argv[5] == "before":
        try:
            common.secure_dir(str(data), existing=True)
        except PermissionError as exc:
            msg = str(exc)
            direct = "RDACL app parent; parent mutable; S-1-5-32-545; 00000116"
            ancestor = "RDACL system parent; ancestor replacement; S-1-5-32-545; 00000116"
            if ancestor in msg:
                # Some runner images also inherit this precise ACE on ProgramData/Microsoft.
                # Prove both the missing stable ancestor and the candidate's own direct
                # rejection of the RemoteDesk parent before accepting that earlier failure.
                checks = r'''
$ErrorActionPreference='Stop'
$trusted=@('S-1-5-18','S-1-5-32-544')
$owners=$trusted + 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$parent=$env:RD_SMOKE_PARENT
$common=[IO.Path]::GetDirectoryName($parent)
$ms=Get-Acl -LiteralPath ([IO.Path]::Combine($common,'Microsoft'))
$raw=[Security.AccessControl.RawSecurityDescriptor]::new($ms.GetSecurityDescriptorBinaryForm(),0)
$matches=@($raw.DiscretionaryAcl | Where-Object {
    $_.AceType -eq 'AccessAllowed' -and $_.SecurityIdentifier.Value -eq 'S-1-5-32-545' -and
    $_.AccessMask -eq 0x116 -and ([int]$_.AceFlags -band 24) -eq 16
})
if (!$matches.Count -or (Test-NonemptyNtfsDataRoot $common $owners)) { throw 'Ancestor failure not corroborated' }
try { Inspect-DataParent $parent; throw 'Expected rejection' }
catch {
    if ($_.Exception.Message -ne 'parent mutable' -or $script:aclSid -ne 'S-1-5-32-545' -or
        $script:aclMask -ne '00000116') { throw }
}
'''
                cmd = common.WINDOWS_ANCESTOR_POLICY + common.WINDOWS_PRIVATE_DIRECTORY_POLICY + checks
                shell = updater.system_tool(r"WindowsPowerShell\v1.0\powershell.exe")
                subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", cmd], check=True, timeout=45,
                               env=dict(os.environ, RD_SMOKE_PARENT=str(data.parent)))
            elif direct not in msg:
                raise
        else:
            raise AssertionError("2.4.0 ha accettato il descrittore storico")
    else:
        updater.ARGS = SimpleNamespace(mode="service", log=str(data / "logs/update.log"))
        updater.preflight_service(updater.plain_path(root), updater.plain_path(target))()
except Exception:
    trace.write_text(traceback.format_exc(), encoding="utf-8")
    raise
"""
    trace = temp / ("failure-before.txt" if before else "failure-after.txt")
    try:
        fixture.run([new / "runtime/pythonw.exe", "-I", "-B", "-c", script, new, installed, data, trace,
                     "before" if before else "after"], cwd=temp, timeout=480)
    except RuntimeError:
        if trace.is_file():
            print(trace.read_text("utf-8"), file=sys.stderr)
        raise


def exercise(old, new, temp):
    from rd import common
    from rd.updater import plain_path, system_tool
    installed, data = Path(common.INSTALL_DIR), Path(common.PROGRAM_DATA)
    parent = data.parent
    fixture.require(parent.name == installed.name == "RemoteDesk" and data.name == "data", "Cartelle Windows inattese")
    fixture.task_absent()
    fixture.require(not any(os.path.lexists(p) for p in (installed, parent)), "Runner con installazione già presente")
    marker = "RemoteDesk-CI-" + secrets.token_hex(16)
    owner_id, made_install, made_task = None, False, False
    task = system_tool("schtasks.exe")
    try:
        fixture.create_owned(installed, PRIVATE + "(A;OICI;0x1200a9;;;BU)", marker)
        made_install = True
        shutil.copytree(old, installed, dirs_exist_ok=True, copy_function=shutil.copyfile)
        fixture.run([system_tool("icacls.exe"), installed, "/setowner", "*" + SID_ADMIN, "/T", "/Q"])
        with tempfile.TemporaryDirectory(prefix="rd-acl-ci-seed-", dir=plain_path(parent.parent)) as seed:
            owner_id = historical_parent(Path(seed), parent, marker)
        fixture.create_owned(data, PRIVATE, marker)
        (data / "logs").mkdir()
        (data / "config.json").write_text('{"id":"321654987","networks":[],"update_url":"","auto_update":false}', encoding="ascii")
        (data / "machine.key").write_text(secrets.token_urlsafe(32), encoding="ascii")
        (data / "logs/update.log").write_text("file di prova\n", encoding="ascii")
        fixture.run([system_tool("icacls.exe"), parent, "/setowner", "*" + SID_ADMIN, "/T", "/Q"])
        xml = fixture.make_xml(installed, data, temp, marker)
        fixture.task_absent()
        fixture.run([task, "/Create", "/TN", "RemoteDesk", "/XML", xml])
        made_task = True
        original_task = fixture.inspect_task(marker)
        with owned_registry(marker):
            original = snapshot(parent)
            legacy_ace = {"sid": USERS, "mask": 0x116, "type": 0, "flags": 0x12}  # CI + INHERITED
            fixture.require(not original["protected"] and original["owner"] == SID_ADMIN and original["entries"].count(legacy_ace) == 1,
                            "Il filesystem del runner non ha riprodotto l'ACE 0x116 ereditata")
            preflight(new, data, installed, temp, before=True)
            run_repair(False, "REPAIRABLE")
            fixture.require(snapshot(parent) == original and fixture.inspect_task(marker) == original_task, "Il check ha modificato lo stato")
            run_repair(True, "REPAIRED")
            repaired = snapshot(parent)
            wanted = [dict(entry, flags=entry["flags"] & ~0x10) for entry in original["entries"] if entry != legacy_ace]
            fixture.require(repaired["protected"] and repaired["entries"] == wanted and repaired["owner"] == original["owner"]
                            and repaired["group"] == original["group"] and repaired["tree"] == original["tree"],
                            "La riparazione ha modificato diritti o file estranei all'ACE storica")
            run_repair(False, "SAFE")
            run_repair(True, "SAFE")
            fixture.require(snapshot(parent) == repaired and fixture.inspect_task(marker) == original_task, "Riparazione non idempotente")
            staged = data / "update/nuovo/RemoteDesk"
            shutil.copytree(new, staged, copy_function=shutil.copyfile)
            fixture.run([system_tool("icacls.exe"), data, "/setowner", "*" + SID_ADMIN, "/T", "/Q"])
            preflight(staged, data, installed, temp, before=False)
            after = fixture.inspect_task(marker)
            fixture.require(after["arguments"] == "-E -s " + original_task["arguments"] and after["security"] == original_task["security"],
                            "Migrazione reale del task non riuscita")
        print("OK: ACE storica realmente ereditata, check senza mutazioni, applicazione idempotente, preflight 2.4.0 superato")
    finally:
        try:
            if made_task:
                fixture.inspect_task(marker)
                fixture.run([task, "/Delete", "/TN", "RemoteDesk", "/F"])
        finally:
            try:
                if owner_id is not None:
                    plain = plain_path(parent)
                    fixture.require(plain == parent and (plain.stat().st_dev, plain.stat().st_ino) == owner_id,
                                    "Cleanup rifiutato: identificativo directory NTFS diverso")
                    shutil.rmtree(plain)
            finally:
                if made_install:
                    fixture.remove_owned(installed, Path(common.INSTALL_DIR), marker)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-zip", type=Path, required=True)
    parser.add_argument("--candidate-zip", type=Path, required=True)
    parser.add_argument("--legacy-manifest", type=Path, required=True)
    args = parser.parse_args()
    fixture.hosted_only()
    fixture.verify_legacy(args.legacy_zip, args.legacy_manifest)
    fixture.require(args.candidate_zip.stat().st_size == CANDIDATE_SIZE and fixture.digest(args.candidate_zip) == CANDIDATE_HASH,
                    "Il candidato deve essere lo ZIP 2.4.0 pubblicato")
    sys.path.insert(0, str(fixture.REPO / "app"))
    from rd.release_package import extract_package
    from rd.updater import system_tool
    # This process only launches Desktop PowerShell 5.1. A pwsh 7 Actions step can
    # export incompatible module paths. Do not change the runner or user's configuration.
    from unittest.mock import patch
    modules = Path(system_tool(r"WindowsPowerShell\v1.0\powershell.exe")).parent / "Modules"
    fixture.require(modules.is_dir(), "Cartella moduli Windows PowerShell di sistema assente")
    with tempfile.TemporaryDirectory(prefix="rd-acl-ci-", dir=os.environ["RUNNER_TEMP"]) as td:
        temp = Path(td).resolve()
        old = Path(extract_package(args.legacy_zip, temp / "legacy"))
        new = Path(extract_package(args.candidate_zip, temp / "published"))
        with patch.dict(os.environ, {"PSModulePath": str(modules)}):
            exercise(old, new, temp)


if __name__ == "__main__":
    main()
