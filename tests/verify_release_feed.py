"""Verify the signed stable Windows 2.4.0 feed against the bytes in this checkout."""
import base64
import hashlib
import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
from rd import auth
from rd.release_package import validate_manifest

PUB = "jcnWg1NX5p1JIB/bSvlcKQZjzrT+xb8WoVdxFJ+noVQ="
PACKAGE = "RemoteDesk-2.4.0.zip"
URL = "https://raw.githubusercontent.com/tbkon3/remote-desk-tbk/main/dist/" + PACKAGE

def verify():
    directory = ROOT / "dist"
    manifest = json.loads((directory / "latest.json").read_text(encoding="utf-8"))
    sig = manifest.pop("sig")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(PUB, validate=True)).verify(
        base64.b64decode(sig, validate=True), auth.canon(manifest))
    validate_manifest(manifest, "2.3.2", time.time())
    if manifest["version"] != "2.4.0" or manifest["file"] != PACKAGE or manifest["url"] != URL:
        raise ValueError("Unexpected signed release destination")
    if manifest["date"] != datetime.fromtimestamp(manifest["issued"], timezone.utc).date().isoformat():
        raise ValueError("Inconsistent release date")
    archive = directory / PACKAGE
    with archive.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    if archive.stat().st_size != manifest["size"] or digest != manifest["sha256"]:
        raise ValueError("Archive does not match the signed feed")
    if (directory / (PACKAGE + ".sha256")).read_text(encoding="ascii") != f"{digest}  {PACKAGE}\n":
        raise ValueError("Checksum sidecar does not match the archive")
    print("Windows stable feed verified:", PACKAGE, manifest["size"], digest)

if __name__ == "__main__":
    verify()
