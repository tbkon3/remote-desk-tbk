"""Portable coordination, private instance authentication and package dispatch on synthetic paths."""
import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import remotedesk
from rd import local_access, portable


class PortableIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp = Path(self.temp.name)
        self.root = self.tmp / "Prima copia"
        self.default = self.tmp / "local" / "RemoteDesk" / "portable" / "data"
        self.legacy = self.default.parent.parent / "data"
        self.service = self.tmp / "ProgramData" / "RemoteDesk" / "data"
        self.installed = self.tmp / "Program Files" / "RemoteDesk"
        for name, value in (("PROGRAM_DATA", str(self.service)), ("INSTALL_DIR", str(self.installed))):
            self.enterContext(patch.object(portable, name, value))
        self.enterContext(patch.object(portable, "default_profile", return_value=self.default))
        self.registered = self.enterContext(patch.object(portable, "service_installed", return_value=False))
        self.autostart = self.enterContext(patch.object(portable, "_legacy_autostart", return_value=False))
        self.inactive = self.enterContext(patch.object(portable, "_legacy_inactive", return_value=True))
        self.actor = self.enterContext(patch.object(portable, "current_logon", return_value="user/logon-A"))
        self.enterContext(patch.object(portable, "private_dir", side_effect=lambda p, **kw: Path(p).mkdir(parents=True, exist_ok=True)))
        self.sock = Mock()
        self.sock.getsockname.return_value = ("127.0.0.1", 50101)
        self.sock.__enter__ = Mock(return_value=self.sock)
        self.sock.__exit__ = Mock(return_value=False)
        self.bind = self.enterContext(patch.object(portable, "_listener", return_value=self.sock))

    def mark_ready(self, inst):
        inst.reserve(None)
        inst.ready()

    def test_stable_profile_and_exclusive_copy_even_with_registered_service(self):
        self.registered.return_value = True
        with portable.Instance(self.root) as first:
            self.assertTrue(first.owner)
            self.mark_ready(first)
            self.assertEqual(first.profile, self.default)
            with portable.Instance(self.root) as second:
                self.assertFalse(second.owner)
                self.assertEqual(second.existing_port(), 50101)
            with portable.Instance(self.tmp / "Altra") as other:
                self.assertFalse(other.owner)
                with self.assertRaisesRegex(RuntimeError, "aperto da"):
                    other.existing_port()
            with self.assertRaisesRegex(RuntimeError, "altro profilo"):
                with portable.Instance(self.root, self.tmp / "other-data"):
                    pass
            self.actor.return_value = "user/logon-B"
            with portable.Instance(self.root) as other_logon:
                with self.assertRaisesRegex(RuntimeError, "sessione Windows"):
                    other_logon.existing_port()
        self.assertFalse((self.default / "instance.json").exists())
        with portable.Instance(self.tmp / "Altra") as moved:
            self.assertTrue(moved.owner)
            self.assertEqual(moved.profile, self.default)

    def test_valid_legacy_receipt_preserves_one_identity_but_never_adopts_service_identity(self):
        self.legacy.mkdir(parents=True)
        (self.legacy / "config.json").write_text('{"id":"123456789"}')
        (self.legacy / "machine.key").write_bytes(base64.b64encode(bytes(32)))
        with portable.Instance(self.root) as fresh:
            self.assertEqual(fresh.profile, self.default)
        receipt = {"target": portable._canonical(self.root), "version": portable.VERSION, "nonce": "a"*64}
        (self.legacy / ".update-pending.json").write_text(json.dumps(receipt))
        with portable.Instance(self.root) as upgraded:
            self.assertEqual(upgraded.profile, self.legacy)
            upgraded.reserve(None)
        (self.legacy / ".update-pending.json").unlink()
        with portable.Instance(self.tmp / "spostata") as moved:
            self.assertEqual(moved.profile, self.legacy)
        self.registered.return_value = True
        with portable.Instance(self.root) as separate:
            self.assertEqual(separate.profile, self.default)
        self.assertFalse((self.default / "machine.key").exists())

    def test_legacy_autostart_requires_known_copy_and_inactive_agent(self):
        self.legacy.mkdir(parents=True)
        (self.legacy / "config.json").write_text('{"id":"123456789"}')
        (self.legacy / "machine.key").write_bytes(base64.b64encode(bytes(32)))
        self.autostart.return_value = True
        self.inactive.return_value = False
        with portable.Instance(self.root) as busy:
            self.assertEqual(busy.profile, self.default)
        self.inactive.return_value = True
        with portable.Instance(self.root) as adopted:
            self.assertEqual(adopted.profile, self.legacy)
            adopted.reserve(None)
        separate = portable.installed_profile(None)
        self.assertNotEqual(portable._canonical(separate), portable._canonical(self.legacy))
        with self.assertRaises(PermissionError):
            portable.installed_profile(self.legacy)

    def test_updater_explicit_legacy_profile_is_reused_by_the_next_normal_launch(self):
        self.legacy.mkdir(parents=True)
        (self.legacy / "config.json").write_text('{"id":"123456789"}')
        (self.legacy / "machine.key").write_bytes(base64.b64encode(bytes(32)))
        with portable.Instance(self.root, self.legacy) as first:
            first.reserve(None)
        with portable.Instance(self.root) as next_boot:
            self.assertEqual(next_boot.profile, self.legacy)

    def test_new_profile_auto_updates_existing_opt_out_survives(self):
        self.default.mkdir(parents=True)
        fresh = remotedesk.load_config(str(self.default), True)
        self.assertIs(fresh.get("auto_update"), True)
        fresh.update(auto_update=False)
        self.assertIs(remotedesk.load_config(str(self.default), True).get("auto_update"), False)
        older = self.tmp / "older"
        older.mkdir()
        (older / "config.json").write_text('{"id":"123456789"}')
        restored = remotedesk.load_config(str(older), True)
        self.assertIsNone(restored.get("auto_update"))

    def test_external_profile_and_dedicated_subdirectory_are_supported(self):
        for location in (self.tmp / "alt-data", self.root / "my-profile"):
            with portable.Instance(self.root, location) as instance:
                self.assertTrue(instance.owner)
                self.assertEqual(instance.profile, location)

    def test_protected_explicit_paths_rejected_before_creation(self):
        for folder in (self.root, self.root / "runtime" / "data", self.root / "app" / "data", self.root / ".remotedesk-update",
                       self.tmp, self.installed, self.service, self.service.parent / "logs"):
            with self.subTest(folder=folder), self.assertRaises(PermissionError):
                with portable.Instance(self.root, folder):
                    pass
        self.assertFalse(self.service.exists())
        self.assertFalse(self.root.exists())
        self.bind.assert_not_called()

    def test_stale_rendezvous_removed_without_attaching_after_failed_bind(self):
        self.default.mkdir(parents=True)
        (self.default / "instance.json").write_text('{"port":47800}')
        self.bind.side_effect = OSError("occupied")
        with self.assertRaisesRegex(OSError, "occupied"):
            with portable.Instance(self.root) as instance:
                self.assertTrue(instance.owner)
                instance.reserve(51001)
        self.assertFalse((self.default / "instance.json").exists())
        self.assertFalse((self.default / "config.json").exists())

    def test_reserved_or_wrong_port_rejected(self):
        with self.assertRaisesRegex(ValueError, "riservata"):
            _real_listener(portable.DEFAULT_PORT)
        with self.assertRaises(ValueError):
            _real_listener(65536)

    def test_loopback_socket_is_reserved_exclusively_before_publication(self):
        first, second = Mock(), Mock()
        first.getsockname.return_value = ("127.0.0.1", portable.DEFAULT_PORT)
        second.getsockname.return_value = ("127.0.0.1", 50310)
        with patch.object(portable.socket, "socket", side_effect=[first, second]):
            self.assertIs(_real_listener(None), second)
        first.close.assert_called_once()
        second.bind.assert_called_once_with(("127.0.0.1", 0))
        if os.name == "nt":
            second.setsockopt.assert_called_once_with(portable.socket.SOL_SOCKET, portable.socket.SO_EXCLUSIVEADDRUSE, 1)
        second.listen.assert_called_once()
        second.setblocking.assert_called_once_with(False)

    def test_owner_only_does_not_attempt_desktop_or_any_other_profile(self):
        role_calls = []
        def reply(port, role, nonce):
            role_calls.append(role)
            return {"mapping":"", "proof":local_access._signature(b"foreign-key", "server", port, role, nonce, "")}
        self.default.mkdir(parents=True)
        (self.default / "local.token").write_bytes(b"our-test-key-" * 3)
        with patch.object(local_access, "_challenge", side_effect=reply), \
                patch.object(local_access.local_access_win, "read_desktop", side_effect=AssertionError("foreign desktop")), \
                self.assertRaises(PermissionError):
            local_access.native_headers(50400, "/api/ping", "GET", self.default, owner_only=True)
        self.assertEqual(role_calls, ["owner"])

    def test_portable_tray_always_owns_its_agent(self):
        from types import SimpleNamespace
        inst = Mock()
        app = remotedesk.App(SimpleNamespace(port=50101), str(self.default), inst)
        with patch.object(remotedesk, "service_installed", side_effect=AssertionError("service")), \
                patch.object(remotedesk, "agent_alive", side_effect=AssertionError("foreign agent")), \
                patch.object(remotedesk, "AgentThread") as thread:
            app.ensure_agent()
            thread.assert_called_once_with(str(self.default), 50101, inst)
            self.assertFalse(app.service_installed())

    def test_packaged_entry_point_routes_portable_and_rejects_privileged_modes_before_data_access(self):
        for name in ("RemoteDesk.exe", "runtime/pythonw.exe", "app/remotedesk.py"):
            component = self.root / name
            component.parent.mkdir(parents=True, exist_ok=True)
            component.touch()
        from rd import common
        with patch.object(remotedesk, "WIN", True), patch.object(common, "ROOT_DIR", str(self.root)), \
                patch.object(common, "INSTALL_DIR", str(self.installed)), patch.object(remotedesk, "run_portable") as launch, \
                patch.object(remotedesk, "pick_data_dir", side_effect=AssertionError("profilo servizio")):
            for options in ([], ["--agent-only"], ["--no-tray", "--no-browser"], ["--port", "50500"]):
                with patch.object(sys, "argv", ["RemoteDesk.exe", *options]):
                    remotedesk.main()
                self.assertEqual(launch.call_args.args[1], str(self.root))
            self.assertEqual(launch.call_args.args[0].port, 50500)
            for flag in ("--service", "--session-agent", "--install-service", "--uninstall-service"):
                with patch.object(sys, "argv", ["RemoteDesk.exe", flag]), self.assertRaises(PermissionError):
                    remotedesk.main()


_real_listener = portable._listener
