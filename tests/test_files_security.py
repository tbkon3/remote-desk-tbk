import asyncio
import contextlib
import io
import json
import os
import stat
import struct
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd import files
from rd.file_scope import Scope, TEMP_PREFIX, _plain, component


class Channel:
    def __init__(self):
        self.readyState = "open"
        self.bufferedAmount = 0
        self.handlers = {}
        self.sent = []

    def on(self, name, handler):
        self.handlers[name] = handler

    def send(self, data):
        self.sent.append(json.loads(data) if isinstance(data, str) else data)

    def close(self):
        self.readyState = "closed"
        self.handlers["close"]()


class FileSecurity(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / "Downloads"
        self.root.mkdir()
        self.private = self.root / "agent-private"
        self.private.mkdir()
        self.agent = SimpleNamespace(user_home=lambda: self.home, cfg={"incoming_dir": ""},
                                     service_mode=False, data_dir=self.private,
                                     audit=SimpleNamespace(add=lambda *_args, **_kwargs: None))
        self.grant = {"files": True, "files_write": True, "files_delete": True}
        self.session = SimpleNamespace(perms=lambda: self.grant, refresh_authorization=lambda: self.grant["files"],
                                       sid="s", mode="files", net=SimpleNamespace(nid="test"),
                                       user="tester", peer_name="test")
        self.agent.sessions = {"s": self.session}
        self.dc = Channel()
        self.server = files.FileServer(self.agent, self.session, self.dc)

    async def asyncTearDown(self):
        self.dc.close()
        await self.server.wait_closed()

    def message(self, op, rid=1, **fields):
        self.dc.handlers["message"](json.dumps(dict(op=op, rid=rid, **fields)))

    async def result(self, rid, op):
        for _ in range(300):
            for msg in self.dc.sent:
                if isinstance(msg, dict) and msg["rid"] == rid:
                    if msg["op"] == op:
                        self.dc.sent.remove(msg)
                        return msg
                    if msg["op"] == "err":
                        self.fail(str(msg))
            await asyncio.sleep(.01)
        self.fail(f"Missing response {op}/{rid}: {self.dc.sent}")

    async def test_roots_navigation_and_protection(self):
        (self.root / "visible.txt").write_text("content")
        self.message("roots")
        self.assertEqual([i["p"] for i in (await self.result(1, "roots"))["entries"]], [str(self.root)])
        self.message("ls", 2, path=str(self.root))
        listing = await self.result(2, "ls")
        self.assertEqual(listing["parent"], "")
        self.assertEqual([i["n"] for i in listing["entries"]], ["visible.txt"])
        for rid, op, path in [(3, "get", self.private), (4, "ls", self.home), (5, "del", self.root)]:
            self.message(op, rid, path=str(path))
            await self.result(rid, "err")

    @unittest.skipUnless(os.name == "nt", "Windows short names")
    async def test_host_short_root_and_peer_aliases(self):
        import ctypes
        from ctypes import wintypes

        get_short = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
        get_short.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        def short_name(path):
            buf = ctypes.create_unicode_buffer(32768)
            length = get_short(str(path), buf, len(buf))
            self.assertTrue(0 < length < len(buf))
            alias = Path(buf.value)
            if alias.name.casefold() == path.name.casefold():
                self.skipTest("Il volume non genera nomi brevi 8.3")
            return alias

        root = self.home / "Long shared folder for the agent"
        root.mkdir()
        private = root / "Long private application data"
        private.mkdir()
        (private / "secret").write_bytes(b"private")
        normal = root / "Normal long document.txt"
        normal.write_bytes(b"public")
        alias, private_alias, normal_alias = map(short_name, (root, private, normal))
        self.agent.cfg["incoming_dir"] = str(alias)
        self.agent.data_dir = private
        self.dc = Channel()
        self.server = files.FileServer(self.agent, self.session, self.dc)
        self.message("roots")
        self.assertEqual((await self.result(1, "roots"))["incoming"], str(alias))
        self.message("ls", 2, path=str(alias))
        self.assertEqual([e["n"] for e in (await self.result(2, "ls"))["entries"]], [normal.name])
        self.message("get", 3, path=str(alias / normal.name))
        await self.result(3, "end")
        self.message("get", 4, path=str(alias / private_alias.name / "secret"))
        await self.result(4, "err")
        self.message("get", 5, path=str(alias / normal_alias.name))
        await self.result(5, "err")
        self.message("put", 6, path=str(alias), name="fresh", size=0)
        self.message("end", 6)
        await self.result(6, "done")
        self.assertTrue((root / "fresh").is_file())
        forbidden = Scope(private_alias, [private])
        with self.assertRaises(PermissionError):
            with forbidden.directory(private_alias):
                self.fail("Protected root was available using its DOS alias")

    def test_paths_and_reserved_names(self):
        for invalid in ["a:b", "NUL.txt", "Lpt1", "nested\\name", "..", "s.", ".rd-transfer-test", "\0"]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                component(invalid)
        for invalid in [r"\\machine\share", str(self.root / ".." / "x"), str(self.home / "DownloadsSuffix")]:
            with self.subTest(invalid=invalid), self.assertRaises((ValueError, PermissionError)):
                self.server.scope.check(invalid)
        with self.assertRaises(PermissionError):
            Scope(self.private, [self.private])

    async def test_ordered_upload_collisions_and_download(self):
        name = "nested/report.txt"
        for rid, data in [(1, b"first"), (2, b"second")]:
            self.message("put", rid, name=name, path=str(self.root), size=len(data))
            self.dc.handlers["message"](struct.pack(">I", rid) + data)
            self.message("end", rid)
            await self.result(rid, "done")
        self.assertEqual((self.root / name).read_bytes(), b"first")
        self.assertEqual((self.root / "nested/report (1).txt").read_bytes(), b"second")
        self.message("get", 3, path=str(self.root / "nested"))
        await self.result(3, "end")
        payload = b"".join(item[4:] for item in self.dc.sent if isinstance(item, bytes))
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(archive.read("nested/report.txt"), b"first")
            self.assertEqual(archive.read("nested/report (1).txt"), b"second")
        self.assertFalse(list(self.root.rglob(TEMP_PREFIX + "*")))

    async def test_failed_uploads_and_occupied_name(self):
        self.message("put", name="file.txt", size=1)
        await self.result(1, "ready")
        self.dc.handlers["message"](struct.pack(">I", 1) + b"too long")
        await self.result(1, "err")
        self.message("put", 2, name="file.txt", size=2)
        self.message("end", 2)
        await self.result(2, "err")
        self.message("put", 3, name="file.txt", size=0)
        await self.result(3, "ready")
        (self.root / "file.txt").write_bytes(b"existing")
        self.message("end", 3)
        committed = await self.result(3, "done")
        self.assertEqual(Path(committed["path"]).name, "file (1).txt")
        self.assertEqual((self.root / "file.txt").read_bytes(), b"existing")
        self.assertFalse(list(self.root.rglob(TEMP_PREFIX + "*")))

    async def test_revocation_while_preparing_cleans_temporary(self):
        entered, proceed = threading.Event(), threading.Event()
        prepare = self.server._prepare

        def pause(*args):
            upload = prepare(*args)
            entered.set()
            proceed.wait(timeout=5)
            return upload

        with patch.object(self.server, "_prepare", side_effect=pause):
            self.message("put", name="file", size=0)
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                self.grant["files"] = False
                self.server.close()
            finally:
                proceed.set()
            await self.server.wait_closed()
        self.assertEqual(list(self.root.iterdir()), [self.private])
        self.assertFalse(self.dc.sent)

    async def test_worker_cancellation_joins_an_inflight_open(self):
        entered, proceed = threading.Event(), threading.Event()
        prepare = self.server._prepare
        def pause(*args):
            up = prepare(*args)
            entered.set()
            proceed.wait(timeout=4)
            return up
        with patch.object(self.server, "_prepare", side_effect=pause):
            self.message("put", name="interrupted", size=0)
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                self.server.worker.cancel()
                await asyncio.sleep(0)
            finally:
                proceed.set()
            await self.server.wait_closed()
        self.assertFalse(list(self.root.glob(TEMP_PREFIX + "*")))
        self.assertFalse((self.root / "interrupted").exists())

    async def test_changed_logon_can_only_cleanup_as_original_owner(self):
        import rd
        from rd import win_identity

        self.server.service_user = True
        self.server.logon = (2, b"original")
        current = [b"original"]
        cleanup_calls = []
        win = SimpleNamespace(process_session=lambda: 2, as_session_user=lambda sid:
                              contextlib.nullcontext(SimpleNamespace(tok=current[0])))

        class Owner:
            def __init__(self, token):
                self.token = token

            def discard(self, action):
                cleanup_calls.append(self.token)
                action()

            def close(self):
                pass

        with (patch.object(rd, "winapi", win, create=True),
              patch.object(win_identity, "logon_id", side_effect=lambda token: token),
              patch.object(files, "CleanupIdentity", Owner)):
            self.message("put", name="new", size=0)
            await self.result(1, "ready")
            current[0] = b"replacement"
            self.message("end")
            await self.result(1, "err")
            self.assertEqual(cleanup_calls, [b"original"])
            self.assertFalse((self.root / "new").exists())
            self.assertFalse(list(self.root.rglob(TEMP_PREFIX + "*")))

    async def test_limits_and_duplicate_rid(self):
        self.message("put", name="file", size=files.MAX_FILE + 1)
        await self.result(1, "err")
        self.message("put", 2, name="file", size=0)
        self.message("put", 2, name="other", size=0)
        await self.result(2, "err")
        self.assertFalse(list(self.root.rglob(TEMP_PREFIX + "*")))
        self.dc.handlers["message"](bytes(files.CHUNK + 5))
        self.assertEqual(self.dc.readyState, "closed")

    async def test_cancel_download_while_channel_is_full(self):
        path = self.root / "paused"
        path.write_bytes(b"visible")
        self.dc.bufferedAmount = files.HIGH_WATER + 1
        self.message("get", path=str(path))
        await self.result(1, "meta")
        self.message("cancel")
        await self.result(1, "err")
        self.assertFalse(any(isinstance(m, bytes) for m in self.dc.sent))

    async def test_legacy_read_only_and_independent_change_grants(self):
        original = self.root / "existing.txt"
        original.write_text("original")
        self.grant.pop("files_write")
        self.grant.pop("files_delete")
        self.message("get", path=str(original))
        await self.result(1, "end")
        for rid, op, fields in [(2, "del", {"path": str(original)}),
                                (3, "rename", {"path": str(original), "name": "other.txt"}),
                                (4, "mkdir", {"path": str(self.root), "name": "nested"}),
                                (5, "put", {"name": "other.txt", "size": 0})]:
            self.message(op, rid, **fields)
            await self.result(rid, "err")
        self.grant["files_write"] = True
        self.message("put", 6, name=original.name, overwrite=True, size=0)
        await self.result(6, "err")
        self.message("mkdir", 7, name="new", path=str(self.root))
        await self.result(7, "ok")
        self.assertEqual(original.read_text(), "original")
        self.grant.update(files_write=False, files_delete=True)
        self.message("rename", 8, path=str(original), name="renamed.txt")
        await self.result(8, "err")
        self.message("del", 9, path=str(original))
        await self.result(9, "ok")
        self.assertFalse(original.exists())

    async def test_write_revoked_at_commit_preserves_original(self):
        path = self.root / "existing.txt"
        path.write_bytes(b"original")
        entered, proceed = threading.Event(), threading.Event()
        commit = files.Upload.commit
        def pause(up, require):
            entered.set()
            proceed.wait(timeout=4)
            return commit(up, require)
        self.message("put", name=path.name, overwrite=True, size=0)
        await self.result(1, "ready")
        with patch.object(files.Upload, "commit", pause):
            self.message("end")
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                self.grant["files_delete"] = False
                self.server.recheck_permissions()
            finally:
                proceed.set()
            await self.result(1, "err")
        self.assertEqual(path.read_bytes(), b"original")
        self.assertFalse(list(self.root.glob(TEMP_PREFIX + "*")))
        self.message("get", 2, path=str(path))
        await self.result(2, "end")

    async def test_idle_upload_is_discarded_on_permission_notification(self):
        self.message("put", name="staged", size=8)
        await self.result(1, "ready")
        self.grant["files_write"] = False
        self.server.recheck_permissions()
        await self.result(1, "err")
        await asyncio.gather(*self.server.cleanup_tasks)
        self.assertFalse(list(self.root.glob(TEMP_PREFIX + "*")))
        self.assertFalse((self.root / "staged").exists())

    def test_link_attributes(self):
        for st in [SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=2),
                   SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)]:
            with self.assertRaises(PermissionError):
                _plain(st)

    async def test_hard_link(self):
        outside = self.home / "outside.txt"
        outside.write_bytes(b"private")
        try:
            os.link(outside, self.root / "hard")
        except PermissionError as exc:
            self.skipTest(str(exc))
        normal = self.root / "normal.txt"
        normal.write_bytes(b"public")
        self.message("get", 10, path=str(normal))
        await self.result(10, "end")
        self.message("get", path=str(self.root / "hard"))
        await self.result(1, "err")

    async def test_nonempty_directory(self):
        directory = self.root / "nested"
        directory.mkdir()
        (directory / "kept").write_text("ok")
        self.message("del", 2, path=str(directory))
        await self.result(2, "err")
        self.assertTrue((directory / "kept").exists())

    async def test_symbolic_link(self):
        outside = self.home / "outside.txt"
        outside.write_bytes(b"private")
        try:
            os.symlink(outside, self.root / "link")
        except OSError as exc:
            self.skipTest(str(exc))
        normal = self.root / "normal.txt"
        normal.write_bytes(b"public")
        self.message("get", 10, path=str(normal))
        await self.result(10, "end")
        self.message("get", 3, path=str(self.root / "link"))
        await self.result(3, "err")


if __name__ == "__main__":
    unittest.main()
