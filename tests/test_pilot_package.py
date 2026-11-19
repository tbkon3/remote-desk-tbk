"""Offline tests for release packaging with a disposable Git history and signing identity."""
import base64
import hashlib
import importlib.util
import json
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

path = Path(__file__).resolve().parents[1] / "build/package_verified_runtime.py"
spec = importlib.util.spec_from_file_location("package_verified_runtime", path)
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)


class PilotPackage(unittest.TestCase):
    def test_stable_verifier_requires_publisher_signature_and_exact_packaged_bytes(self):
        verify_spec = importlib.util.spec_from_file_location("verify_release_feed", path.parents[1] / "tests/verify_release_feed.py")
        verifier = importlib.util.module_from_spec(verify_spec)
        verify_spec.loader.exec_module(verifier)
        key = Ed25519PrivateKey.generate()
        pub = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        name = "RemoteDesk-2.4.1.zip"
        data = b"fixture package"
        digest = hashlib.sha256(data).hexdigest()
        now = int(time.time())
        signed = {"version": "2.4.1", "file": name, "url": pack.FEED + name, "size": len(data),
                  "sha256": digest, "issued": now, "expires": now + 86400,
                  "date": datetime.fromtimestamp(now, timezone.utc).date().isoformat()}
        signed["sig"] = base64.b64encode(key.sign(verifier.auth.canon(signed))).decode("ascii")
        with tempfile.TemporaryDirectory() as tmp, patch.multiple(verifier, PUB=pub, ROOT=Path(tmp)):
            dist = Path(tmp) / "dist"
            dist.mkdir()
            manifest = dist / "latest.json"
            manifest.write_text(json.dumps(signed), encoding="utf-8")
            (dist / name).write_bytes(data)
            (dist / (name + ".sha256")).write_bytes(f"{digest}  {name}\n".encode("ascii"))
            with patch("builtins.print"):
                verifier.verify("2.4.1")
            with self.assertRaisesRegex(ValueError, "destination"):
                verifier.verify("2.4.0")
            (dist / name).write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "Archive"):
                verifier.verify("2.4.1")
            manifest.write_text(json.dumps(dict(signed, sha256="a" * 64)), encoding="utf-8")
            with self.assertRaises(InvalidSignature):
                verifier.verify("2.4.1")

    def test_rejects_archive_collisions_extra_roots_and_links(self):
        bad = [
            ["RemoteDesk/app/a", "RemoteDesk/App/b"],
            ["RemoteDesk/a/", "RemoteDesk/a/"],
            ["RemoteDesk/a", "RemoteDesk/a/sub"],
            ["RemoteDesk/runtime/pythonw.exe", "Other/runtime/data"],
            ["RemoteDesk/runtime/../secret"], ["RemoteDesk/runtime/CON.txt"], ["RemoteDesk/a:b"],
        ]
        for names in bad:
            with self.subTest(names=names), self.assertRaises(ValueError):
                pack.validate_names([pack.member(name) for name in names])
        link = pack.member("RemoteDesk/runtime/library")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError):
            pack.validate_names([link])

    @unittest.skipUnless(shutil.which("git"), "Git richiesto")
    def test_reproducible_git_overlay_and_authenticated_baseline(self):
        with tempfile.TemporaryDirectory() as work:
            repo = Path(work) / "checkout"
            repo.mkdir()

            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.STDOUT).decode().strip()

            def write(name, data):
                dest = repo / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)

            def commit(message):
                git("add", "-A")
                git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "-c", "commit.gpgSign=false", "commit", "-qm", message)
                return git("rev-parse", "HEAD")

            git("init", "-q")
            git("config", "core.autocrlf", "false")
            for f in pack.ABI_INPUTS:
                write(f, b"unchanged")
            write("build/build_bundle.sh", b"PYVER=3.12.10\n")
            write("build/LEGGIMI.txt", b"Portable application\n")
            secret = Ed25519PrivateKey.generate()
            pub = base64.b64encode(secret.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
            update = f'RELEASE_PUB = "{pub}"\nDEFAULT_URL = "{pack.FEED}latest.json"\n'.encode()
            write("app/rd/update.py", update)
            write("app/remotedesk.py", b"# entry point\n")
            write("app/rd/updater.py", b"# updater\n")
            write("app/rd/common.py", b'VERSION = "2.3.2"\n')
            write("app/web/icon.png", b"icon")
            write("app/web/icon-active.png", b"active")
            archive = repo / "dist" / pack.BASE_FILE
            archive.parent.mkdir()
            with zipfile.ZipFile(archive, "x") as old:
                old.writestr("RemoteDesk/RemoteDesk.exe", b"original stub")
                old.writestr("RemoteDesk/runtime/pythonw.exe", b"original pythonw")
                old.writestr("RemoteDesk/runtime/python.exe", b"original python")
                old.writestr("RemoteDesk/runtime/empty/", b"")
                old.writestr("RemoteDesk/app/obsolete.py", b"obsolete")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            body = dict(version="2.3.2", file=pack.BASE_FILE, url=pack.FEED + pack.BASE_FILE,
                        sha256=digest, size=archive.stat().st_size)
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            body["sig"] = base64.b64encode(secret.sign(canonical)).decode()
            write("dist/latest.json", json.dumps(body).encode())
            baseline = commit("fixture 2.3.2")
            write("app/rd/common.py", b'VERSION = "2.4.0"\n')
            write("app/web/view.js", b"tracked")
            head = commit("fixture 2.4.0")
            write("app/web/view.js", b"dirty source")
            write("app/local-private.key", b"untracked")
            now = int(time.time())
            with patch.multiple(pack, BASE=baseline, BASE_SHA256=digest, RELEASE_PUB=pub):
                a, b = (Path(work) / n for n in ("first", "second"))
                first = pack.build(repo, head, a, now, now + 86400)
                self.assertEqual(pack.build(repo, head, b, now, now + 86400), first)
                self.assertEqual((a / pack.FILE).read_bytes(), (b / pack.FILE).read_bytes())
                self.assertEqual(set(p.name for p in a.iterdir()), {pack.FILE, "latest.unsigned.json", "SHA256SUMS"})
                self.assertNotIn("sig", first)
                self.assertEqual(first["url"], pack.FEED + pack.FILE)
                self.assertEqual((a / "SHA256SUMS").read_text().strip(), f"{first['sha256']}  {pack.FILE}")
                with zipfile.ZipFile(a / pack.FILE) as new:
                    self.assertEqual(new.read("RemoteDesk/RemoteDesk.exe"), b"original stub")
                    self.assertEqual(new.read("RemoteDesk/runtime/pythonw.exe"), b"original pythonw")
                    self.assertIn("RemoteDesk/runtime/empty/", new.namelist())
                    self.assertEqual(new.read("RemoteDesk/app/web/view.js"), b"tracked")
                    self.assertEqual(new.read("RemoteDesk/app/web/icon-active.png"), b"active")
                    self.assertNotIn("RemoteDesk/app/obsolete.py", new.namelist())
                    self.assertNotIn("RemoteDesk/app/local-private.key", new.namelist())
                with self.assertRaises(ValueError):
                    pack.build(repo, head, a, now, now + 3600)
                with self.assertRaises(ValueError):
                    pack.build(repo, head, Path(work) / "expired", now - 60, now - 1)
                pilot_name = "RemoteDesk-2.4.1.zip"
                pilot = Path(work) / "portable-pilot"
                with self.assertRaisesRegex(ValueError, "Versione applicativa"):
                    pack.build(repo, head, pilot, now, now + 86400, "2.4.1")
                (repo / "app/local-private.key").unlink()
                write("app/rd/common.py", b'VERSION = "2.4.1"\n')
                pilot_ref = commit("portable 2.4.1")
                pilot_body = pack.build(repo, pilot_ref, pilot, now, now + 86400, "2.4.1")
                self.assertEqual(pilot_body["version"], "2.4.1")
                self.assertEqual(pilot_body["file"], pilot_name)
                self.assertEqual(pilot_body["url"], pack.FEED + pilot_name)
                self.assertNotIn("sig", pilot_body)
                self.assertEqual(set(p.name for p in pilot.iterdir()), {pilot_name, "latest.unsigned.json", "SHA256SUMS"})
                self.assertEqual(hashlib.sha256((pilot / pilot_name).read_bytes()).hexdigest(), pilot_body["sha256"])
                self.assertEqual(json.loads((pilot / "latest.unsigned.json").read_bytes()), pilot_body)
                with zipfile.ZipFile(pilot / pilot_name) as new, zipfile.ZipFile(archive) as old:
                    for name in old.namelist():
                        if name.endswith("RemoteDesk.exe") or name.startswith("RemoteDesk/runtime/"):
                            self.assertEqual(new.read(name), old.read(name))
                    self.assertEqual(new.read("RemoteDesk/app/rd/common.py"), b'VERSION = "2.4.1"\n')
                self.assertEqual((a / pack.FILE).read_bytes(), (b / pack.FILE).read_bytes())
                with self.assertRaisesRegex(ValueError, "Versione di destinazione"):
                    pack.source_files(repo, pilot_ref, "../../latest.json")
                write("app/rd/update.py", update.replace(pack.FEED.encode(), b"https://invalid.test/"))
                wrong_feed = commit("incorrect default feed")
                with self.assertRaisesRegex(ValueError, "feed predefinito"):
                    pack.build(repo, wrong_feed, Path(work) / "wrong-feed", now, now + 86400, "2.4.1")
                write("app/rd/update.py", update)
                tampered = dict(body, size=1)
                with self.assertRaises(InvalidSignature):
                    pack.verify_baseline(json.dumps(tampered), archive)
                archive.write_bytes(bytes(archive.stat().st_size))
                with self.assertRaises(ValueError):
                    pack.verify_baseline(json.dumps(body), archive)
                # Newly tracked secrets and changed runtime inputs must fail closed.
                write("app/local-private.key", b"tracked")
                bad = commit("bad inputs")
                with self.assertRaisesRegex(ValueError, "File imprevisto"):
                    pack.source_files(repo, bad, "2.4.1")
                write("build/launcher.c", b"changed")
                changed = commit("launcher changed")
                with self.assertRaisesRegex(ValueError, "Prerequisito"):
                    pack.source_files(repo, changed, "2.4.1")


if __name__ == "__main__":
    unittest.main()
