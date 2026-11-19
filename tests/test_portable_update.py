import asyncio
import base64
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
from rd import updater as helper


class PortableUpdateTests(unittest.TestCase):
    def setUp(self):
        # Filesystem objects, sharing and renames are real. ACL and instance
        # ownership have dedicated native/offline tests and a Windows smoke test.
        private = patch("rd.portable_storage.private_dir", side_effect=lambda path, **kw: Path(path).mkdir(mode=0o700, exist_ok=True))
        private.start()
        self.addCleanup(private.stop)
        lock = patch.object(helper, "_copy_instance", side_effect=lambda *_: contextlib.nullcontext())
        lock.start()
        self.addCleanup(lock.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.target = self.work / "directory with personal files"
        self.source = self.work / "signed staging"
        for folder, version in [(self.target, "old"), (self.source, "new")]:
            (folder / "app").mkdir(parents=True)
            (folder / "runtime").mkdir()
            for name in ["app/remotedesk.py", "runtime/pythonw.exe", "RemoteDesk.exe", "LEGGIMI.txt"]:
                (folder / name).write_text(version)
        self.data = self.target / "private data"
        self.data.mkdir()
        self.note = self.target / "personal record.txt"
        self.note.write_text("keep")
        self.meta = helper._metadata(self.target)
        self.args = SimpleNamespace(pid=0, prepare_token=None, version="2.4.1")

    def launch(self, healthy):
        def start(_target, _args):
            if healthy:
                receipt = helper._read_receipt(helper._receipt_path(self.data, "pending"))
                helper._write_receipt(helper._receipt_path(self.data, "ready"), receipt)
            return Mock(poll=Mock(return_value=0))
        with (patch.object(helper, "ARGS", self.args, create=True), patch.object(helper, "log"),
              patch.object(helper, "_start_portable", side_effect=start) as app):
            result = helper._exchange_portable(self.target, self.meta, self.source, self.data, [])
        return result, app.call_count

    def test_update_preserves_personal_items_and_previous_managed_tree(self):
        (self.target / "runtime" / "custom.pth").write_text("private extra")
        (self.target / "app" / "personal-document").write_text("private extra")
        (self.data / "device").write_text("existing identity")
        self.assertEqual(self.launch(True), (0, 1))
        self.assertEqual((self.target / "RemoteDesk.exe").read_text(), "new")
        self.assertEqual(self.note.read_text(), "keep")
        self.assertEqual((self.data / "device").read_text(), "existing identity")
        self.assertFalse((self.target / "runtime/custom.pth").exists())
        previous, = self.meta.glob("*/previous")
        self.assertEqual((previous / "runtime/custom.pth").read_text(), "private extra")
        self.assertEqual((previous / "app/personal-document").read_text(), "private extra")
        self.assertFalse((self.meta / "current.json").exists())

    def test_failed_start_restores_current_copy_only(self):
        self.assertEqual(self.launch(False), (2, 2))
        for name in ["RemoteDesk.exe", "app/remotedesk.py", "runtime/pythonw.exe"]:
            self.assertEqual((self.target / name).read_text(), "old")
        self.assertEqual(self.note.read_text(), "keep")
        self.assertEqual(next(self.meta.glob("*/rejected/RemoteDesk.exe")).read_text(), "new")

    def test_identical_launcher_keeps_file_id_and_recovery_uses_staging(self):
        binary = self.target / "RemoteDesk.exe"
        before = binary.stat().st_ino
        (self.source / "RemoteDesk.exe").write_bytes(binary.read_bytes())
        self.assertEqual(self.launch(True), (0, 1))
        self.assertEqual(binary.stat().st_ino, before)
        recovery, = self.meta.glob("*/RECUPERO.json")
        instructions = json.loads(recovery.read_bytes())
        self.assertEqual(Path(instructions["executable"]), self.source / "runtime/python.exe")
        self.assertIn("--recover", instructions["arguments"])
        self.assertFalse((recovery.parent / "previous/RemoteDesk.exe").exists())

    def interrupted(self):
        job = self.meta / ("1" * 32)
        for name in ["previous", "candidate", "rejected"]:
            (job / name).mkdir(parents=True)
        state = helper._prepare_members(self.target, self.source, job)
        state["phase"] = "swapping"
        helper._write_receipt(self.meta / "current.json", state)
        for name in ("app", "runtime"):
            helper._move_member(self.target, job / "previous", name, state["old"][name])
            if name == "app":
                helper._move_member(job / "candidate", self.target, name, state["new"][name])
        return job

    def test_interrupt_between_renames_and_idempotent_retry(self):
        self.interrupted()
        self.assertTrue(helper._recover_portable(self.target, self.meta))
        self.assertFalse(helper._recover_portable(self.target, self.meta))
        self.assertEqual((self.target / "app/remotedesk.py").read_text(), "old")
        self.assertEqual((self.target / "runtime/pythonw.exe").read_text(), "old")
        self.assertEqual(self.note.read_text(), "keep")

    def test_recovery_does_not_replace_a_new_user_directory(self):
        job = self.interrupted()
        (self.target / "runtime").mkdir()
        (self.target / "runtime/document").write_text("keep")
        with self.assertRaises(RuntimeError):
            helper._recover_portable(self.target, self.meta)
        self.assertEqual((self.target / "runtime/document").read_text(), "keep")
        self.assertTrue((job / "previous/runtime/pythonw.exe").exists())
        self.assertTrue((self.meta / "current.json").exists())

    def test_preflight_root_identity_metadata_and_permissions(self):
        install = self.work / "system" / "app"
        machine = self.work / "system" / "RemoteDesk" / "data"
        executable = self.target / "runtime/pythonw.exe"
        helper.portable_preflight(self.target, self.data, install, machine, executable)
        with self.assertRaisesRegex(RuntimeError, "interprete"):
            helper.portable_preflight(self.target, self.data, install, machine, self.source / "runtime/pythonw.exe")
        with self.assertRaisesRegex(RuntimeError, "amministrata"):
            helper.portable_preflight(self.target, self.data, self.target, machine, executable)
        with patch.object(helper, "_metadata", side_effect=PermissionError("permesso negato")), self.assertRaises(RuntimeError):
            helper.portable_preflight(self.target, self.data, install, machine, executable)
        (self.meta / "format").write_bytes(b"mine")
        with self.assertRaisesRegex(RuntimeError, "estranei"):
            helper.portable_preflight(self.target, self.data, install, machine, executable)
        self.assertEqual((self.meta / "format").read_bytes(), b"mine")
        self.assertEqual(self.note.read_text(), "keep")

    def test_relaunch_has_no_service_or_other_profile(self):
        for args in [["--install-service"], ["--session-agent"], ["--data", str(self.source)], ["--port", "99999"]]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                helper._portable_args(json.dumps(args), self.data)
        self.assertEqual(helper._portable_args('["--agent-only","--port","49200"]', self.data),
                         ["--agent-only", "--port", "49200", "--minimized", "--data", str(self.data)])

    def test_lock_per_copy_exclusive(self):
        with helper._local_lock(self.meta / "lock"):
            with self.assertRaises(OSError), helper._local_lock(self.meta / "lock"):
                self.fail("Concurrent update lock acquired")

    def test_redirected_source_is_rejected_before_switch(self):
        victim = self.work / "other.txt"
        victim.write_text("keep")
        try:
            os.symlink(victim, self.source / "app/link")
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(PermissionError):
            self.launch(True)
        self.assertEqual((self.target / "RemoteDesk.exe").read_text(), "old")
        self.assertEqual(victim.read_text(), "keep")


class AutoUpdateTests(unittest.IsolatedAsyncioTestCase):
    async def test_periodic_auto_update_of_the_active_custom_copy(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from rd import update

        with tempfile.TemporaryDirectory() as work:
            root = Path(work).resolve()
            target = root / "my active copy"
            data = root / "my profile"
            data.mkdir()
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for name in ("app/remotedesk.py", "runtime/pythonw.exe", "app/rd/updater.py", "RemoteDesk.exe", "LEGGIMI.txt"):
                    dest = target / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(b"old")
                    archive.writestr("RemoteDesk/" + name, b"new")
            raw_zip = stream.getvalue()
            now = int(time.time())
            body = dict(version="99.1.1", file="RemoteDesk-99.1.1.zip", sha256=hashlib.sha256(raw_zip).hexdigest(),
                        size=len(raw_zip), url="https://updates.invalid/candidate.zip", issued=now, expires=now + 3600)
            signer = Ed25519PrivateKey.generate()
            pub = base64.b64encode(signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
            sig = signer.sign(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
            manifest = json.dumps(dict(body, sig=base64.b64encode(sig).decode())).encode()
            feed = "https://updates.invalid/latest.json"
            requests = []

            class Response:
                status = 200
                def __init__(self, url):
                    self.content = self
                    self.url = url
                async def __aenter__(self):
                    return self
                async def __aexit__(self, *_):
                    pass
                async def iter_chunked(self, size):
                    yield manifest if self.url == feed else raw_zip

            class Transport:
                def __init__(self, **_):
                    pass
                async def __aenter__(self):
                    return self
                async def __aexit__(self, *_):
                    pass
                def get(self, url, **kwargs):
                    self_test.assertFalse(kwargs["allow_redirects"])
                    self_test.assertIn(url, [feed, body["url"]])
                    requests.append(url)
                    return Response(url)

            self_test = self
            agent = SimpleNamespace(data_dir=str(data), service_mode=False, cfg={"update_url": feed, "auto_update": True},
                                    sessions={}, pending_approvals={}, nets={}, leases={}, audit=Mock(), log_event=Mock(),
                                    port=48000, stop_event=asyncio.Event())
            manager = update.Updater(agent)

            def launch(staged, version, *, prepare_token):
                self.assertEqual(version, body["version"])
                self.assertEqual(update.ROOT_DIR, str(target))
                self.assertTrue(Path(staged).is_relative_to(data / "update"))
                self.assertEqual((Path(staged) / "RemoteDesk.exe").read_bytes(), b"new")
                helper._write_receipt(Path(staged).parent / ".prepared", {"nonce": prepare_token})
                return Mock(poll=Mock(return_value=None))

            async def sleep(seconds):
                if seconds == update.CHECK_EVERY:
                    raise asyncio.CancelledError

            with (patch.object(update, "WIN", True), patch.object(update, "ROOT_DIR", str(target)),
                  patch.object(sys, "executable", str(target / "runtime/pythonw.exe")), patch.object(update, "RELEASE_PUB", pub),
                  patch.object(update, "ClientSession", Transport), patch.object(asyncio, "sleep", sleep),
                  patch("rd.portable_storage.private_dir", side_effect=lambda p, **kw: Path(p).mkdir(mode=0o700, exist_ok=True)),
                  patch.object(manager, "_launch_updater", side_effect=launch) as started):
                for auto, busy in [(False, False), (True, True), (True, False)]:
                    agent.cfg["auto_update"] = auto
                    agent.sessions = {"live": Mock()} if busy else {}
                    before = requests.count(body["url"])
                    with self.assertRaises(asyncio.CancelledError):
                        await manager.loop()
                    self.assertEqual(requests.count(body["url"]) - before, int(auto and not busy))
                started.assert_called_once()
                self.assertTrue(agent.stop_event.is_set())
                self.assertEqual((target / "RemoteDesk.exe").read_bytes(), b"old")
