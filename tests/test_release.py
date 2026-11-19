"""Verifiche offline con archivi sintetici e processi simulati."""
import asyncio
import importlib.util
import io
import json
from functools import wraps
import os
import stat
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
from rd import auth, common, release_package as package, updater as installer

# Il test della macchina a stati sostituisce sempre il trasporto HTTP.
spec = importlib.util.spec_from_file_location("rd._update_under_test", ROOT / "app/rd/update.py")
update = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"aiohttp": SimpleNamespace(ClientSession=Mock(), ClientTimeout=Mock())}):
    spec.loader.exec_module(update)


class PackageTests(unittest.TestCase):
    def build(self, entries=()):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as out:
            for name in package.REQUIRED:
                out.writestr("RemoteDesk/" + name, b"fixture")
            for entry in entries:
                out.writestr(entry, b"fixture")
        stream.seek(0)
        return stream

    def test_extract(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(package.extract_package(self.build(), Path(temp) / "new"))
            for required in package.REQUIRED:
                self.assertEqual((root / required).read_bytes(), b"fixture")

    def test_rejects_unsafe_entries_before_writing(self):
        symlink = zipfile.ZipInfo("RemoteDesk/link")
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for member in ("RemoteDesk/../other", "RemoteDesk/AUX.dll", "RemoteDesk/Bad.",
                       "RemoteDesk/APP/resource", "RemoteDesk/runtime/pythonw.exe/child",
                       "RemoteDesk/n:stream", symlink):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as temp:
                dest = Path(temp) / "new"
                with self.assertRaises(ValueError):
                    package.extract_package(self.build([member]), dest)
                self.assertFalse(dest.exists())

    def test_backslash_encoded_in_original_archive(self):
        raw = self.build(["RemoteDesk/wrong/name"]).getvalue()
        archive = io.BytesIO(raw.replace(b"RemoteDesk/wrong/name", b"RemoteDesk/wrong\\name"))
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            package.extract_package(archive, Path(temp) / "new")

    def test_archive_limits(self):
        for field, limit in (("MAX_MEMBER", 5), ("MAX_ENTRIES", 3), ("MAX_EXPANDED", 20)):
            with self.subTest(field=field), patch.object(package, field, limit), tempfile.TemporaryDirectory() as temp:
                with self.assertRaises(ValueError):
                    package.extract_package(self.build(), Path(temp) / "new")

    def test_legacy_manifest_and_tamper(self):
        signed = json.loads((ROOT / "dist/latest.json").read_text("utf-8"))
        self.assertTrue(update.verify_manifest(signed))
        self.assertFalse(update.verify_manifest(dict(signed, size=1)))
        package.validate_manifest(signed, signed["version"], time.time())
        if "expires" not in signed:
            with self.assertRaises(ValueError):
                package.validate_manifest(signed, "0.0.0", time.time())

    def test_fresh_metadata(self):
        now = 200000
        manifest = dict(version="3.0.0", url="https://release.example.test/package", sha256="a" * 64,
                        size=16, issued=now - 5, expires=now + 500)
        package.validate_manifest(manifest, "2.3.2", now)
        for change in (dict(expires=now), dict(issued=now+400), dict(expires=now+40*86400),
                       dict(size=True), dict(url="http://example.test/"), dict(version="3.0evil.0")):
            with self.subTest(change=change), self.assertRaises(ValueError):
                package.validate_manifest(dict(manifest, **change), "2.3.2", now)


class ReceiptTests(unittest.TestCase):
    def test_cleanup_only_finished_owned_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            active = base / "release-active"
            finished = base / "release-finished"
            unrelated = base / "manually-created"
            for job in (active, finished, unrelated):
                (job / "nuovo" / "RemoteDesk").mkdir(parents=True)
            for job in (finished, unrelated):
                installer.mark_stage_finished(job / "nuovo" / "RemoteDesk", base)
            installer.clear_finished_stages(base)
            self.assertEqual(set(base.iterdir()), {active, unrelated})

    @unittest.skipUnless(os.name == "nt", "lock di kernel Windows")
    def test_independent_update_handles_are_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "RemoteDesk"
            with installer.installation_lock(target):
                with self.assertRaises(OSError), installer.installation_lock(target):
                    self.fail("lock concorrente concesso")
            with installer.installation_lock(target):
                pass

    def test_binds_nonce_to_target_and_version(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "update").mkdir()
            pending = installer._receipt_path(root, "pending")
            ready = installer._receipt_path(root, "ready")
            receipt = dict(nonce="a" * 64, version="3.0.0", target=os.path.normcase(os.path.realpath(root)))
            installer._write_receipt(pending, receipt)
            self.assertFalse(installer.acknowledge_start(root, root / "other", "3.0.0"))
            self.assertFalse(installer.acknowledge_start(root, root, "2.0.0"))
            self.assertFalse(Path(ready).exists())
            self.assertTrue(installer.acknowledge_start(root, root, "3.0.0"))
            self.assertEqual(installer._read_receipt(ready), receipt)

    def test_stale_confirmation_restores_old_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target, backup, failed, source, ready = [root / name for name in ("app", "backup", "failed", "src", "ready")]
            for folder, data in ((target, "old"), (source, "new")):
                folder.mkdir()
                (folder / "version").write_text(data)
            ready.write_text('{"nonce":"old"}')
            args = SimpleNamespace(mode="user", source=source, version="3.0.0")
            with (patch.object(installer, "ARGS", args, create=True),
                  patch.object(installer, "stop_old"), patch.object(installer, "start") as start,
                  patch.object(installer, "log"), patch.object(installer.time, "sleep")):
                self.assertEqual(installer.replace_and_verify(target, backup, failed, ready, {"nonce": "new"}), 2)
                self.assertEqual(start.call_count, 2)
            self.assertEqual((target / "version").read_text(), "old")
            self.assertEqual((failed / "version").read_text(), "new")


def immediate(test):
    # I trasporti sono sostituiti e nessuna attesa reale e' ammessa, neppure il
    # socketpair di wakeup creato implicitamente dal loop Windows.
    @wraps(test)
    def run(self):
        task = test(self)
        try:
            with self.assertRaises(StopIteration):
                task.send(None)
        finally:
            task.close()
    return run


class UpdateStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.agent = SimpleNamespace(cfg={}, data_dir=self.temp.name, sessions={}, pending_approvals={},
                                     nets={}, leases={}, service_mode=False,
                                     audit=Mock(), log_event=Mock(), stop_event=asyncio.Event())
        self.u = update.Updater(self.agent)
        self.populate()

    def populate(self):
        self.u.info = {"version": "99.0.0", "expires": int(time.time()+1000)}
        self.u.checked_at, self.u.checked_url = time.monotonic(), self.u.url

    def test_negotiating_or_active_role_pauses_automatic_update(self):
        self.agent.cfg.update(auto_update=True)
        for field, value in (("sessions", {"id": object()}), ("pending_approvals", {"id": object()}),
                             ("nets", {"n": SimpleNamespace(pending={"offer": object()})}),
                             ("leases", {"token": {"until": time.monotonic() + 30}})):
            with self.subTest(field=field), patch.object(self.agent, field, value):
                self.assertFalse(self.u._maintenance_allowed(True))
        self.assertTrue(self.u._maintenance_allowed(True))

    @immediate
    async def test_disabled_and_failed_check_drop_cached_offer(self):
        self.assertTrue(self.u.available())
        self.agent.cfg["update_url"] = ""
        self.assertFalse(self.u.available())
        self.assertIsNone(await self.u.check())
        self.assertIsNone(self.u.info)
        self.agent.cfg["update_url"] = "http://invalid.test/"
        self.populate()
        with self.assertLogs(update.log, level="WARNING"):
            self.assertIsNone(await self.u.check())
        self.assertFalse(self.u.available())

    @immediate
    async def test_on_air_and_concurrent_install_do_not_download(self):
        self.u._check = AsyncMock()
        self.u._download_and_stage = AsyncMock()
        with patch.object(update, "WIN", True):
            self.agent.cfg["on_air"] = True
            with self.assertRaises(RuntimeError):
                await self.u.install("test")
            self.agent.cfg["on_air"] = False
            async with self.u.lock:
                with self.assertRaises(RuntimeError):
                    await self.u.install("test")
        self.u._check.assert_not_awaited()
        self.u._download_and_stage.assert_not_awaited()

    @immediate
    async def test_maintenance_toggle_during_transfer_prevents_commit(self):
        async def stage(info, folder):
            self.agent.cfg["on_air"] = True
            return folder
        self.u._check = AsyncMock()
        self.u._download_and_stage = stage
        with (patch.object(update, "WIN", True), patch.object(self.u, "_launch_updater") as launch,
              self.assertLogs(update.log, level="ERROR"), self.assertRaises(RuntimeError)):
            await self.u.install("test")
        launch.assert_not_called()
        self.assertEqual(list((Path(self.temp.name) / "update").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
