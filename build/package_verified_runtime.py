"""Build an unsigned Windows package from committed sources and the signed 2.3.2 runtime."""
import argparse
import ast
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE = "70b260c46250fdbd38cf0eaf12ceb9cacc38f897"
BASE_SHA256 = "76e054528ff95a3d7f323fb72963b9645108c919a79c63c90b0d9d67b3f3e1b5"
RELEASE_PUB = "jcnWg1NX5p1JIB/bSvlcKQZjzrT+xb8WoVdxFJ+noVQ="
BASE_FILE = "RemoteDesk-2.3.2.zip"
VERSION = "2.4.0"
FILE = f"RemoteDesk-{VERSION}.zip"
VERSIONS = (VERSION, "2.4.1")
FEED = "https://raw.githubusercontent.com/tbkon3/remote-desk-tbk/main/dist/"
ABI_INPUTS = ("requirements.txt", "build/requirements-windows.txt", "build/launcher.c",
              "build/launcher.rc", "build/icon.ico", "build/icon256.png")
APP_FILE = re.compile(r"app/(?:remotedesk\.py|rd/[a-zA-Z0-9_]+\.py|web/[a-zA-Z0-9_-]+\.(?:html|css|js|ico|png))\Z")
DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³])(?:\.|$)", re.I)
NOTES = ("Aggiornare entrambi i PC per usare il protocollo 2. Dopo il primo passaggio dalla 2.3.2 "
         "riaprire la console dall'icona di RemoteDesk, autenticarsi e avviare una nuova sessione.")


def git(repo, *args, output=subprocess.PIPE):
    return subprocess.run(["git", "--no-replace-objects", "-C", str(repo), *args], stdout=output,
                          check=True).stdout


def blob(repo, ref, path):
    return git(repo, "cat-file", "blob", f"{ref}:{path}")


def constant(data, name):
    module = ast.parse(data)
    return [ast.literal_eval(stmt.value) for stmt in module.body if isinstance(stmt, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets)]


def source_files(repo, ref, version=VERSION):
    if version not in VERSIONS:
        raise ValueError("Versione di destinazione non supportata")
    if not re.fullmatch("[0-9a-f]{40}", ref) or git(repo, "rev-parse", "HEAD").decode().strip() != ref:
        raise ValueError("Il sorgente deve corrispondere allo SHA completo del checkout")
    git(repo, "merge-base", "--is-ancestor", BASE, ref)
    for path in ABI_INPUTS:
        if blob(repo, BASE, path) != blob(repo, ref, path):
            raise ValueError(f"Prerequisito del runtime/launcher modificato: {path}")
    for rev in (BASE, ref):
        if re.findall(rb"(?m)^PYVER=(\S+)\r?$", blob(repo, rev, "build/build_bundle.sh")) != [b"3.12.10"]:
            raise ValueError("Versione runtime Python incompatibile")
        if constant(blob(repo, rev, "app/rd/update.py"), "RELEASE_PUB") != [RELEASE_PUB]:
            raise ValueError("Chiave pubblica dell'updater differente")
    if constant(blob(repo, ref, "app/rd/common.py"), "VERSION") != [version]:
        raise ValueError("Versione applicativa incompatibile")
    if constant(blob(repo, ref, "app/rd/update.py"), "DEFAULT_URL") != [FEED + "latest.json"]:
        raise ValueError("Il feed predefinito deve essere quello stabile")
    objects = {}
    listing = git(repo, "ls-tree", "-r", "-l", "-z", ref, "--", "app", "build/LEGGIMI.txt")
    size_total = 0
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, raw_name = record.split(b"\t", 1)
        mode, kind, oid, size = meta.decode("ascii").split()
        path = raw_name.decode("utf-8")
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError(f"Oggetto sorgente non regolare: {path}")
        size_total += int(size)
        if int(size) > 8 * 1024**2 or size_total > 32 * 1024**2:
            raise ValueError("Sorgenti del pacchetto troppo grandi")
        if path == "build/LEGGIMI.txt":
            path = "LEGGIMI.txt"
        elif not APP_FILE.fullmatch(path):
            raise ValueError(f"File imprevisto sotto app/ (dati, chiavi e cache non ammessi): {path}")
        objects["RemoteDesk/" + path] = oid
    required = ("LEGGIMI.txt", "app/remotedesk.py", "app/rd/updater.py",
                "app/web/icon.png", "app/web/icon-active.png")
    if any("RemoteDesk/" + name not in objects for name in required):
        raise ValueError("File applicativo o icona mancante nel commit")
    return objects


def verify_baseline(raw_manifest, archive):
    def unique(pairs):
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError("Chiave duplicata nel manifesto")
        return dict(pairs)
    body = json.loads(raw_manifest, object_pairs_hook=unique)
    signature = base64.b64decode(body.pop("sig"), validate=True)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    Ed25519PublicKey.from_public_bytes(base64.b64decode(RELEASE_PUB)).verify(signature, canonical)
    if (body["version"] != "2.3.2" or body["file"] != BASE_FILE or body["url"] != FEED + BASE_FILE
            or body["sha256"] != BASE_SHA256 or body["size"] != archive.stat().st_size
            or not 0 < body["size"] <= 300 * 1024**2):
        raise ValueError("Manifesto diverso dalla baseline 2.3.2")
    with archive.open("rb") as handle:
        if hashlib.file_digest(handle, "sha256").hexdigest() != BASE_SHA256:
            raise ValueError("SHA-256 della baseline non valido")


def validate_names(entries):
    seen, kinds = set(), {}
    total = 0
    if len(entries) > 16000:
        raise ValueError("Troppe voci ZIP")
    for entry in entries:
        name = entry.orig_filename
        parts = name.removesuffix("/").split("/")
        if (len(name) > 240 or parts[0] != "RemoteDesk" or any(
                not part or part.endswith((".", " ")) or DEVICE.match(part)
                or any(ord(c) < 32 or c in '\\:<>\"|?*~' for c in part) for part in parts)):
            raise ValueError("Percorso ZIP non valido")
        kind = stat.S_IFMT(entry.external_attr >> 16)
        total += entry.file_size
        if (kind not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG)
                or entry.external_attr & 0x400 or entry.flag_bits & 1
                or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or total > 1024**3 or entry.file_size > 256 * 1024**2 or entry.is_dir() and entry.file_size):
            raise ValueError("Voce ZIP non ammessa")
        for length in range(1, len(parts) + 1):
            path = "/".join(parts[:length])
            key = path.casefold()
            value = (path, length < len(parts) or entry.is_dir())
            if kinds.setdefault(key, value) != value:
                raise ValueError("Percorsi ZIP ambigui")
        if key in seen:
            raise ValueError("Voce ZIP duplicata")
        seen.add(key)


def member(name):
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((stat.S_IFDIR | 0o755) << 16 | 0x10) if info.is_dir() else (stat.S_IFREG | 0o644) << 16
    return info


def assemble(repo, old_path, objects, output):
    with zipfile.ZipFile(old_path) as old, zipfile.ZipFile(output, "x") as new:
        validate_names(old.infolist())
        retained = {e.filename: e for e in old.infolist()
                    if e.filename == "RemoteDesk/RemoteDesk.exe" or e.filename.startswith("RemoteDesk/runtime/")}
        if any("RemoteDesk/" + name not in retained for name in ("RemoteDesk.exe", "runtime/python.exe", "runtime/pythonw.exe")):
            raise ValueError("Baseline senza runtime completo o launcher")
        names = sorted([*retained, *objects])
        validate_names([member(name) for name in names])
        for name in names:
            with new.open(member(name), "w") as target:
                if name in retained:
                    with old.open(retained[name]) as source:
                        shutil.copyfileobj(source, target, length=1024**2)
                else:
                    data = git(repo, "cat-file", "blob", objects[name])
                    if name == "RemoteDesk/LEGGIMI.txt":
                        data = data.decode("utf-8-sig").replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8-sig")
                    target.write(data)
    if output.stat().st_size > 300 * 1024**2:
        raise ValueError("Pacchetto troppo grande")
    with zipfile.ZipFile(output) as finished:
        validate_names(finished.infolist())


def build(repo, ref, output, issued, expires, version=VERSION):
    now = int(time.time())
    if issued > now + 300 or expires <= now or not 0 < expires - issued <= 31 * 86400:
        raise ValueError("Finestra temporale del manifesto non valida")
    output = output.resolve()
    repo = repo.resolve()
    if output.is_relative_to(repo) and not output.is_relative_to(repo / "target"):
        raise ValueError("Usare una directory esterna al checkout o target/")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("La directory di uscita deve essere nuova o vuota")
    objects = source_files(repo, ref, version)
    filename = f"RemoteDesk-{version}.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as work:
        old = Path(work) / BASE_FILE
        with old.open("xb") as handle:
            git(repo, "cat-file", "blob", f"{BASE}:dist/{BASE_FILE}", output=handle)
        verify_baseline(blob(repo, BASE, "dist/latest.json"), old)
        stage = Path(work) / "result"
        stage.mkdir()
        package = stage / filename
        assemble(repo, old, objects, package)
        with package.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        (stage / "SHA256SUMS").write_bytes(f"{digest}  {filename}\n".encode("ascii"))
        notes = NOTES if version == VERSION else (
            "La copia portabile si aggiorna nella cartella da cui è stata avviata. "
            "Chiudi le sessioni prima del riavvio. Se parti dalla 2.3.2, aggiorna entrambi i PC "
            "e apri una nuova sessione dalla console della nuova versione.")
        body = dict(version=version, file=filename, url=FEED + filename, size=package.stat().st_size, sha256=digest,
                    issued=issued, expires=expires, date=datetime.fromtimestamp(issued, timezone.utc).date().isoformat(),
                    notes=notes)
        (stage / "latest.unsigned.json").write_bytes((json.dumps(body, indent=2, ensure_ascii=False) + "\n").encode())
        if output.exists():
            output.rmdir()  # Requires an empty directory, including if another builder raced us.
        os.rename(stage, output)
    return body


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=VERSIONS, default=VERSION)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--issued-at", type=int, required=True)
    parser.add_argument("--expires-at", type=int)
    args = parser.parse_args()
    expires = args.expires_at if args.expires_at is not None else args.issued_at + 30 * 86400
    print(json.dumps(build(Path(__file__).resolve().parents[1], args.source_ref, args.output_dir,
                           args.issued_at, expires, args.version)))
