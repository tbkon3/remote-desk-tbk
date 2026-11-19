"""Validazione offline del formato di rilascio Windows."""
import os
import re
import stat
import zipfile
from pathlib import Path
from urllib.parse import urlsplit


MAX_PACKAGE = 300 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024
MAX_MEMBER = 256 * 1024 * 1024
MAX_ENTRIES = 16000
MAX_LIFETIME = 31 * 86400
REQUIRED = ("runtime/pythonw.exe", "app/remotedesk.py", "app/rd/updater.py", "RemoteDesk.exe")
RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³])(?:\.|$)", re.I)


def version_tuple(version):
    if not isinstance(version, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}", version):
        raise ValueError("versione non valida")
    return tuple(map(int, version.split(".")))


def https_url(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) <= 32 for c in url):
        raise ValueError("URL di aggiornamento non valido")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("richiesto URL HTTPS senza credenziali")
    return url


def validate_manifest(body, current, now):
    newer = version_tuple(body["version"]) > version_tuple(current)
    https_url(body["url"])
    if type(body["size"]) is not int or not 0 < body["size"] <= MAX_PACKAGE:
        raise ValueError("dimensione del rilascio non valida")
    if not isinstance(body["sha256"], str) or not re.fullmatch(r"[a-fA-F0-9]{64}", body["sha256"]):
        raise ValueError("impronta del rilascio non valida")
    if not isinstance(body.get("notes", ""), str) or len(body.get("notes", "")) > 8192:
        raise ValueError("note del rilascio non valide")
    if newer or "issued" in body or "expires" in body:
        issued, expires = body.get("issued"), body.get("expires")
        if (type(issued) is not int or type(expires) is not int or issued > now + 300
                or expires <= now or not 0 < expires - issued <= MAX_LIFETIME):
            raise ValueError("manifesto scaduto o data di validita' assente")


def extract_package(archive, destination):
    """Controlla l'intero indice prima di creare file. destination deve essere nuova."""
    dest = Path(destination)
    kinds = {}
    seen = set()
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ValueError("troppe voci nel pacchetto")
        total = 0
        for entry in entries:
            name = entry.orig_filename
            parts = name.removesuffix("/").split("/")
            if (parts[0] != "RemoteDesk" or len(name) > 240 or
                    any(not p or p.endswith((".", " ")) or RESERVED.match(p)
                        or any(ord(c) < 32 or c in '\\:<>"|?*~' for c in p) for p in parts)):
                raise ValueError("nome nel pacchetto non valido")
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if (kind not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG)
                    or (entry.external_attr & 0x400) or entry.flag_bits & 1
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise ValueError("tipo di voce non ammesso")
            total += entry.file_size
            if total > MAX_EXPANDED or entry.file_size > MAX_MEMBER or (entry.is_dir() and entry.file_size):
                raise ValueError("dimensione estratta eccessiva")
            for i in range(1, len(parts) + 1):
                path = "/".join(parts[:i])
                key = path.casefold()
                is_dir = i < len(parts) or entry.is_dir()
                if key in kinds and kinds[key] != (path, is_dir):
                    raise ValueError("collisione di percorsi nel pacchetto")
                kinds[key] = (path, is_dir)
            if key in seen:
                raise ValueError("voce duplicata nel pacchetto")
            seen.add(key)
        for required in REQUIRED:
            path = "RemoteDesk/" + required
            if kinds.get(path.casefold()) != (path, False):
                raise ValueError("pacchetto incompleto: " + required)
        dest.mkdir()
        for entry in entries:
            target = dest.joinpath(*entry.filename.rstrip("/").split("/"))
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with package.open(entry) as source, target.open("xb") as output:
                copied = 0
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > entry.file_size:
                        raise ValueError("dimensione estratta incoerente")
                    output.write(chunk)
                if copied != entry.file_size:
                    raise ValueError("voce troncata")
    return os.fspath(dest / "RemoteDesk")
