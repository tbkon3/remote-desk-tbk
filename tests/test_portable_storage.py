"""Portable profile DACLs and link handling, only on disposable fixtures."""
from contextlib import contextmanager
import ctypes as ct
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd import portable_storage as storage


class PortableAclPolicy(unittest.TestCase):
    def test_ordinary_private_profile_and_stock_windows_ancestors(self):
        user = "user"
        private = [(0, 19, 0x1f01ff, sid) for sid in (storage.SYSTEM, storage.ADMINS, user)]
        storage._check_acl(user, private, user, private=True, directory=True)
        inherited = [(0, 0, 0x1200a9, "Users"), (0, 0, 4, "authenticated-users"),
                     (0, 11, 0x10000000, storage.CREATOR_OWNER)]
        storage._check_acl(storage.TRUSTED_INSTALLER, inherited, user, private=False, directory=True)
        # A grant for future children can expose a new config as soon as it's created.
        for unsafe in ((0, 0, 1, "foreign"), (0, 9, 0x80000000, "foreign"),
                       (5, 0, 0, "foreign")):
            with self.subTest(ace=unsafe), self.assertRaises(PermissionError):
                storage._check_acl(user, private + [unsafe], user, private=True, directory=True)

    def test_null_acl_replacement_and_untrusted_owner_are_rejected(self):
        for owner, entries in (("user", None), ("foreign", []),
                               ("user", [(0, 0, 0x40, "Everyone")]),
                               ("user", [(0, 0, 0x100, "Users")])):
            with self.subTest(owner=owner, entries=entries), self.assertRaises(PermissionError):
                storage._check_acl(owner, entries, "user", private=False, directory=True)


@unittest.skipUnless(os.name == "nt", "Native Windows object security")
class NativePortableStorage(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "our-private-fixture"
        self.win = storage._Storage()
        self.win.create_private(self.root)
        # CI runners and app sandboxes can use shared TEMP parents. The fixture
        # starts at a directory created atomically with the real protected DACL.
        # The release smoke exercises unmodified ancestry under a standard user.
        inspect = storage._Storage.inspect
        @contextmanager
        def fixture_ancestry(win, path, **kwargs):
            if path in self.root.parents:
                yield
            else:
                with inspect(win, path, **kwargs):
                    yield
        self.enterContext(patch.object(storage._Storage, "inspect", fixture_ancestry))

    def create_readable(self, path, *, directory=False):
        win = self.win
        descriptor = storage.PTR()
        sddl = f"D:P(A;OICI;FA;;;{win.user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FR;;;WD)"
        storage._require(win.descriptor(sddl, 1, ct.byref(descriptor), None))
        try:
            access = storage._SecurityAttributes(ct.sizeof(storage._SecurityAttributes), descriptor, 0)
            if directory:
                storage._require(win.mkdir(str(path), ct.byref(access)))
            else:
                handle = win.open_path(str(path), 0x40000000, 7, ct.byref(access), 1, 0x80, None)
                if handle == storage.PTR(-1).value:
                    raise ct.WinError(ct.get_last_error())
                win.close(handle)
        finally:
            win.free(descriptor)

    def make_hardlink(self, original, link):
        try:
            os.link(original, link)
        except PermissionError:
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise
            self.skipTest("Il filesystem di test blocca la creazione di hardlink")

    def test_native_creation_existing_file_and_file_type(self):
        data = self.root / "nested" / "data"
        storage.private_dir(data, profile=True)
        data.joinpath("config.json").write_text("{}")
        storage.private_dir(data, profile=True)
        data.joinpath("machine.key").mkdir()
        with self.assertRaises(PermissionError):
            storage.private_dir(data, profile=True)

    def test_native_hardlink_refused_without_changes(self):
        data = self.root / "profile"
        storage.private_dir(data)
        outside = self.root / "original"
        outside.write_text("fixture")
        self.make_hardlink(outside, data / "machine.key")
        with self.assertRaises(PermissionError):
            storage.private_dir(data, profile=True)
        self.assertEqual(outside.read_text(), "fixture")
    def test_native_readable_file_and_directory_refused(self):
        data = self.root / "profile"
        storage.private_dir(data)
        key = data / "local.token"
        self.create_readable(key)
        with self.assertRaises(PermissionError) as denied:
            storage.private_dir(data, profile=True)
        message = str(denied.exception)
        for detail in ("oggetto privato", str(key), "SID=S-1-1-0", "mask=0x", "vietati=0x"):
            self.assertIn(detail, message)
        exposed = self.root / "weak-directory"
        self.create_readable(exposed, directory=True)
        with self.assertRaises(PermissionError):
            storage.private_dir(exposed)

    def test_junction_as_parent_and_sensitive_directory_is_rejected(self):
        data = self.root / "profile"
        outside = self.root / "target"
        for path in (data, outside):
            storage.private_dir(path)
        junction = data / "logs"
        command = [os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"),
                   "/d", "/c", "mklink", "/j", str(junction), str(outside)]
        created = subprocess.run(command, capture_output=True)
        if created.returncode and os.environ.get("GITHUB_ACTIONS") != "true":
            self.skipTest("Il filesystem di test blocca la creazione di junction")
        created.check_returncode()
        self.addCleanup(junction.rmdir)
        for target in (data, junction / "new"):
            with self.subTest(target=target), self.assertRaises(PermissionError):
                storage.private_dir(target, profile=True)
        self.assertFalse((outside / "new").exists())

    def test_containers_only_check_named_metadata(self):
        foreign = self.root / "other-profile"
        foreign.mkdir()
        original = foreign / "customer-file"
        self.create_readable(original)
        original.write_text("fixture")
        storage.private_dir(self.root, files=("legacy.json",))
        metadata = self.root / "legacy.json"
        self.create_readable(metadata)
        with self.assertRaises(PermissionError):
            storage.private_dir(self.root, files=("legacy.json",))
        self.assertEqual(original.read_text(), "fixture")


if __name__ == "__main__":
    unittest.main()
