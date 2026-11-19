"""Prova manuale CI della migrazione 2.3.2 -> 2.4.0. Richiede un runner Windows GitHub-hosted vergine.

python tests/smoke_legacy_service.py --legacy-zip RemoteDesk-2.3.2.zip --candidate-zip RemoteDesk-2.4.0.zip

Dopo la promozione si può passare il manifesto storico con --legacy-manifest. L'attività
è inerte: trigger e avvio su richiesta sono disabilitati, l'agente non viene mai avviato.
"""
import argparse
import ast
import base64
import ctypes
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LEGACY_HASH = "76e054528ff95a3d7f323fb72963b9645108c919a79c63c90b0d9d67b3f3e1b5"
LEGACY_SIZE = 53306324
RELEASE_PUB = "jcnWg1NX5p1JIB/bSvlcKQZjzrT+xb8WoVdxFJ+noVQ="
TAG = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def hosted_only():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Windows"
            and os.environ.get("GITHUB_REPOSITORY", "").lower() == "tbkon3/remote-desk-tbk"
            and re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
            and os.environ.get("RUNNER_TEMP"), "Consentito solo nel job Windows GitHub-hosted del progetto")
    require(ctypes.windll.shell32.IsUserAnAdmin(), "Runner elevato necessario")


def digest(file):
    with file.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_legacy(archive, manifest):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    body = json.loads(manifest.read_text(encoding="utf-8-sig"))
    signature = base64.b64decode(body.pop("sig"), validate=True)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    Ed25519PublicKey.from_public_bytes(base64.b64decode(RELEASE_PUB)).verify(signature, canonical)
    require(body["version"] == "2.3.2" and body["size"] == LEGACY_SIZE and body["sha256"] == LEGACY_HASH,
            "Serve il manifesto firmato storico 2.3.2")
    require(archive.stat().st_size == LEGACY_SIZE and digest(archive) == LEGACY_HASH, "Archivio 2.3.2 diverso")


def hashes(root):
    return {p.relative_to(root).as_posix(): digest(p) for p in root.rglob("*") if p.is_file()}


def tracked_app_hashes():
    # Su Windows il working tree può usare CRLF. La sorgente attestata è il blob Git del commit.
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    listing = run(["git", "-C", REPO, "ls-tree", "-rz", "HEAD", "--", "app"], env=env).stdout
    result = {}
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        header, name = entry.split(b"\t", 1)
        mode, kind, oid = header.split()
        require(kind == b"blob" and mode in (b"100644", b"100755") and name.startswith(b"app/"),
                "Tipo di file applicativo inatteso nel commit")
        raw = run(["git", "-C", REPO, "cat-file", "blob", oid.decode("ascii")], env=env).stdout
        result[name[4:].decode("utf8")] = hashlib.sha256(raw).hexdigest()
    require(result, "Checkout Git privo dell'applicazione")
    return result


def validate_candidate(old, new):
    require(hashes(old / "runtime") == hashes(new / "runtime"), "Runtime candidato diverso dalla base firmata")
    require(tracked_app_hashes() == hashes(new / "app"), "App candidata diversa dai blob Git del commit")
    module = ast.parse((new / "app" / "rd" / "common.py").read_text("utf8"))
    versions = [n.value.value for n in module.body if isinstance(n, ast.Assign)
                and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "VERSION"]
    require(versions == ["2.4.0"], "Questa prova copre il passaggio 2.3.2 -> 2.4.0")


def run(args, **kw):
    result = subprocess.run(args, timeout=kw.pop("timeout", 240), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    if result.returncode:
        detail = (result.stderr or result.stdout)[-1600:].decode("utf-8", errors="replace")
        raise RuntimeError(f"{Path(args[0]).name} ha restituito {result.returncode}. {detail}")
    return result


def powershell(cmd, env=None):
    from rd.updater import system_tool
    shell = system_tool(r"WindowsPowerShell\v1.0\powershell.exe")
    return run([shell, "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; " + cmd],
               env=env).stdout


def task_absent():
    powershell(r"$s=New-Object -ComObject Schedule.Service; $s.Connect(); "
               r"foreach($t in $s.GetFolder('\').GetTasks(1)){if($t.Name -in 'RemoteDesk','RemoteDeskUpdate'){throw 'Task esistente'}}")


def create_owned(path, parent_acl, marker):
    from rd.updater import plain_path
    require(not os.path.lexists(path) and plain_path(path.parent).is_dir(), "Percorso di prova non libero")
    env = dict(os.environ, RD_SMOKE_PATH=str(path), RD_SMOKE_ACL=parent_acl)
    powershell(r"""$acl=[Security.AccessControl.DirectorySecurity]::new();
$acl.SetSecurityDescriptorSddlForm($env:RD_SMOKE_ACL);
[void][IO.Directory]::CreateDirectory($env:RD_SMOKE_PATH,$acl)""", env)
    require(plain_path(path).parent == plain_path(path.parent), "Percorso inatteso")
    (path / ".rd-ci-owner").write_text(marker, encoding="ascii")


def remove_owned(path, expected, marker):
    from rd.updater import plain_path
    require(path == expected and path.name == "RemoteDesk" and plain_path(path).parent == plain_path(expected.parent),
            "Rimozione annullata: destinazione inattesa")
    require((path / ".rd-ci-owner").read_text("ascii") == marker, "Rimozione annullata: marker diverso")
    shutil.rmtree(path)


def make_xml(installed, data, temporary, marker):
    # Importare solo il generatore XML originale dalla distribuzione firmata.
    code = ("import sys;sys.path.insert(0,sys.argv[1]);from rd import service;"
            "sys.stdout.buffer.write(service._task_xml().encode('utf-16'))")
    output = run([installed / "runtime/python.exe", "-I", "-B", "-c", code, installed / "app"], cwd=temporary)
    doc = ET.fromstring(output.stdout)
    require(len(doc.findall(f"{TAG}Triggers/*")) == 1 and len(doc.findall(f"{TAG}Actions/*")) == 1, "Layout task inatteso")
    args = doc.findtext(f"{TAG}Actions/{TAG}Exec/{TAG}Arguments")
    require(args == f'"{installed / "app/remotedesk.py"}" --service --data "{data}"', "Task diverso da 2.3.2")
    doc.find(f"{TAG}RegistrationInfo/{TAG}Description").text = marker
    doc.find(f"{TAG}Triggers/{TAG}BootTrigger/{TAG}Enabled").text = "false"
    doc.find(f"{TAG}Settings/{TAG}AllowStartOnDemand").text = "false"
    xml = temporary / "task.xml"
    ET.register_namespace("", TAG[1:-1])
    ET.ElementTree(doc).write(xml, encoding="utf-16", xml_declaration=True)
    return xml


def inspect_task(marker):
    env = dict(os.environ, RD_SMOKE_MARKER=marker)
    data = powershell(r"""
$s=New-Object -ComObject Schedule.Service; $s.Connect(); $t=$s.GetFolder('\').GetTask('RemoteDesk');
$d=$t.Definition; $trigger=$d.Triggers.Item(1);
if($d.RegistrationInfo.Description -cne $env:RD_SMOKE_MARKER -or $t.State -eq 4 -or
   $d.Settings.AllowDemandStart -or $trigger.Enabled -or $d.Triggers.Count -ne 1){throw 'Task estraneo o attivo'};
[pscustomobject]@{arguments=$d.Actions.Item(1).Arguments; security=$t.GetSecurityDescriptor(7)} | ConvertTo-Json -Compress
""", env)
    return json.loads(data.decode("ascii"))


def smoke(old, new, temp):
    from rd import common
    from rd.updater import plain_path, system_tool
    installed, data = Path(common.INSTALL_DIR), Path(common.PROGRAM_DATA)
    container = data.parent
    require(installed.name == container.name == "RemoteDesk" and data.name == "data", "Cartelle OS inattese")
    task_absent()
    require(not any(os.path.lexists(p) for p in (installed, container)), "Runner con installazione preesistente")
    marker = "RemoteDesk-CI-" + secrets.token_hex(16)
    owners = []
    registered = False
    scheduler = system_tool("schtasks.exe")
    private = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    try:
        create_owned(installed, private + "(A;OICI;0x1200a9;;;BU)", marker)
        owners.append(installed)
        create_owned(container, private + "(A;;0x1200a9;;;BU)", marker)
        owners.append(container)
        create_owned(data, private, marker)
        (data / "logs").mkdir()
        # Copia normale: i file ereditano DACL della destinazione.
        shutil.copytree(old, installed, dirs_exist_ok=True, copy_function=shutil.copyfile)
        staged = data / "update" / "nuovo" / "RemoteDesk"
        shutil.copytree(new, staged, copy_function=shutil.copyfile)
        for directory in (installed, container):
            run([system_tool("icacls.exe"), directory, "/setowner", "*S-1-5-32-544", "/T", "/Q"])
        xml = make_xml(installed, data, temp, marker)
        task_absent()
        run([scheduler, "/Create", "/TN", "RemoteDesk", "/XML", xml])
        registered = True
        before = inspect_task(marker)
        # Non chiamare main(), stop_old(), start() o qualsiasi agente.
        driver = """
import sys, traceback
from pathlib import Path
from types import SimpleNamespace
source, target, log, trace = map(Path, sys.argv[1:])
try:
    sys.path.insert(0, str(source / "app"))
    from rd import updater
    updater.ARGS = SimpleNamespace(mode="service", log=str(log))
    updater.preflight_service(updater.plain_path(source), updater.plain_path(target))()
except Exception:
    trace.write_text(traceback.format_exc(), encoding="utf8")
    raise
"""
        trace = temp / "preflight-error.txt"
        for _ in range(2):
            try:
                run([staged / "runtime/pythonw.exe", "-I", "-B", "-c", driver, staged, installed, data / "logs/update.log", trace],
                    cwd=plain_path(temp), timeout=450)
            except RuntimeError:
                if trace.is_file():
                    print(trace.read_text("utf8"), file=sys.stderr)
                raise
            after = inspect_task(marker)
            require(after["arguments"] == "-E -s " + before["arguments"] and after["security"] == before["security"],
                    "Definizione o ACL del task migrato non corrispondenti")
        print("OK: task 2.3.2 inerte, DACL NTFS reali, preflight 2.4.0 e seconda esecuzione idempotente")
    finally:
        if registered:
            inspect_task(marker)
            run([scheduler, "/Delete", "/TN", "RemoteDesk", "/F"])
        for directory in reversed(owners):
            remove_owned(directory, installed if directory == installed else container, marker)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-zip", type=Path, required=True)
    parser.add_argument("--candidate-zip", type=Path, required=True)
    parser.add_argument("--legacy-manifest", type=Path, default=REPO / "dist/latest.json")
    args = parser.parse_args()
    hosted_only()
    verify_legacy(args.legacy_zip, args.legacy_manifest)
    sys.path.insert(0, str(REPO / "app"))
    from rd.release_package import extract_package
    root = Path(os.environ["RUNNER_TEMP"])
    with tempfile.TemporaryDirectory(prefix="rd-service-ci-", dir=root) as td:
        temp = Path(td)
        old = Path(extract_package(args.legacy_zip, temp / "verified-legacy"))
        new = Path(extract_package(args.candidate_zip, temp / "candidate"))
        validate_candidate(old, new)
        smoke(old, new, temp)


if __name__ == "__main__":
    main()
