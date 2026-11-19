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
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

path = Path(__file__).resolve().parents[1] / "build/package_verified_runtime.py"
spec = importlib.util.spec_from_file_location("package_verified_runtime", path)
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)


class PilotPackage(unittest.TestCase):
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
            write("app/rd/update.py", f'RELEASE_PUB = "{pub}"\n'.encode())
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
                tampered = dict(body, size=1)
                with self.assertRaises(InvalidSignature):
                    pack.verify_baseline(json.dumps(tampered), archive)
                archive.write_bytes(bytes(archive.stat().st_size))
                with self.assertRaises(ValueError):
                    pack.verify_baseline(json.dumps(body), archive)
                # Newly tracked secrets and changed runtime inputs must fail closed.
                bad = commit("bad inputs")
                with self.assertRaisesRegex(ValueError, "File imprevisto"):
                    pack.source_files(repo, bad)
                write("build/launcher.c", b"changed")
                changed = commit("launcher changed")
                with self.assertRaisesRegex(ValueError, "Prerequisito"):
                    pack.source_files(repo, changed)


if __name__ == "__main__":
    unittest.main()
