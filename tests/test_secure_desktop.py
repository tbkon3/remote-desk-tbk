"""Synthetic Win32 desktop switches. No screen, keyboard, mouse or real dialog is accessed."""
from contextlib import nullcontext
import ctypes
import importlib.util
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))


@unittest.skipUnless(sys.platform == "win32" and importlib.util.find_spec("mss") and importlib.util.find_spec("av"),
                     "runtime Windows RemoteDesk richiesto")
class SecureDesktopTests(unittest.TestCase):
    def setUp(self):
        from rd import platform_io, winapi
        self.io, self.w = platform_io, winapi

    def test_only_worker_default_on_winsta0_and_correct_input_session(self):
        w = self.w
        user = Mock()
        user.GetProcessWindowStation.return_value = 11
        user.GetThreadDesktop.return_value = 12
        ident = {11: "WinSta0", 12: "Default"}
        def set_active(handle, kind, output, size, needed):
            self.assertEqual((handle, kind), (12, 6))
            ctypes.cast(output, ctypes.POINTER(w.wt.BOOL))[0] = 1
            return 1
        user.GetUserObjectInformationW.side_effect = set_active
        with patch.object(w, "user32", user), patch.object(w, "kernel32", Mock()), \
                patch.object(w, "_desk_name", side_effect=ident.get), patch.object(w, "process_session", return_value=4), \
                patch.object(w, "active_console_session", return_value=4) as console, \
                patch.object(w, "_foreground_is_user_level", return_value=True) as foreground:
            self.assertTrue(w.default_desktop_active(True))
            foreground.return_value = False
            self.assertFalse(w.default_desktop_active(True))
            foreground.return_value = True
            console.return_value = 5
            self.assertFalse(w.default_desktop_active(True))
            console.return_value = 4
            for name in ("Winlogon", "Consent", ""):
                ident[12] = name
                self.assertFalse(w.default_desktop_active(True))
            ident[12] = "Default"
            user.GetUserObjectInformationW.side_effect = None
            user.GetUserObjectInformationW.return_value = False
            self.assertFalse(w.default_desktop_active(True))
        user.SetThreadDesktop.assert_not_called()
        user.OpenInputDesktop.assert_not_called()

    def test_capture_discards_stale_and_mid_grab_frames(self):
        io = self.io
        capturer = io.Capturer(service_mode=True, expected_logon=(1, b"logon"))
        img = Mock(width=2, height=2, bgra=b"x" * 16)
        sct = Mock()
        sct.monitors = [dict(left=0, top=0, width=2, height=2)]
        sct.grab.return_value = img
        with patch.object(io, "_desktop_ok", side_effect=[True, True, False, True, False]), \
                patch.object(io, "_user_context", return_value=nullcontext()) as token, \
                patch.object(io, "_new_mss", return_value=sct):
            self.assertEqual(capturer.grab(0), ((img.bgra, 2, 2), True))
            self.assertEqual(capturer.grab(0), (None, True))
            self.assertIsNone(capturer.last)
            self.assertEqual(capturer.grab(0), (None, True))
            self.assertIsNone(capturer.last)
            self.assertEqual(sct.grab.call_count, 2)
            token.assert_called_with(True, (1, b"logon"))

    def test_unidentified_or_changed_user_blocks_capture_before_mss(self):
        from rd import win_identity
        io, w = self.io, self.w
        session = Mock(tok="fixture")
        with patch.object(w, "process_session", return_value=5), patch.object(w, "as_session_user", return_value=nullcontext(session)), \
                patch.object(win_identity, "logon_id", return_value=b"other-logon"), patch.object(io, "_new_mss") as grabber:
            for expected in (None, (4, b"other-logon"), (5, b"previous-logon")):
                self.assertEqual(io.Capturer(True, expected).grab(0), (None, True))
            grabber.assert_not_called()

    def test_prompt_drain_releases_held_input_and_refuses_queued_messages(self):
        io, w = self.io, self.w
        with patch.object(io, "_desktop_ok", return_value=True), patch.object(w, "block_input", return_value=True) as block:
            injector = io.Injector()
            down = threading.Event()
            def mod(key, state):
                if state:
                    down.set()
            injector.mod_key = Mock(side_effect=mod)
            injector.button = Mock()
            try:
                injector.set_block(True)
                injector.put({"t": "mod", "k": "ctrl", "d": True})
                self.assertTrue(down.wait(1))
                injector.pause_and_drain()
                self.assertEqual(injector.mod_key.call_args.args, ("ctrl", False))
                self.assertFalse(injector.blocked)
                self.assertEqual(block.call_args.args, (False,))
                injector.pause_and_drain()
                injector.resume()
                injector.put({"t": "mod", "k": "alt", "d": True})
                injector.resume()
                injector.pause_and_drain()
                self.assertEqual(injector.mod_key.call_count, 2)
                injector.resume()
            finally:
                injector.close()

    def test_text_rechecks_before_each_batch_and_foreign_input_never_reaches_os(self):
        w = self.w
        fake = Mock()
        fake.SendInput.side_effect = lambda count, events, stride: count
        check = Mock(side_effect=[True, False])
        with patch.object(w, "user32", fake), w.input_guard(check):
            with self.assertRaises(PermissionError):
                w.type_text("x" * 96)
        self.assertEqual(fake.SendInput.call_count, 1)
        self.assertEqual(check.call_count, 2)

    def test_revocation_aborts_in_flight_text_and_discards_pending_input(self):
        io, w = self.io, self.w
        entered, proceed = threading.Event(), threading.Event()
        native = Mock()
        def send(count, events, stride):
            entered.set()
            if not proceed.wait(2):
                raise OSError("La prova non ha revocato l'input")
            return count
        native.SendInput.side_effect = send
        with patch.object(io, "_desktop_ok", return_value=True), patch.object(w, "user32", native):
            injector = io.Injector()
            try:
                injector.put({"t": "txt", "text": "abc" * 100}, authorized=lambda: True)
                self.assertTrue(entered.wait(1))
                injector.put({"t": "txt", "text": "in coda"}, authorized=lambda: True)
                injector.release_all()
                proceed.set()
                injector.pause_and_drain()
                injector.resume()
                self.assertEqual(native.SendInput.call_count, 1)
                injector.put({"t": "txt", "text": "revocato"}, authorized=lambda: False)
                injector.pause_and_drain()
                self.assertEqual(native.SendInput.call_count, 1)
            finally:
                proceed.set()
                injector.close()

    def test_consent_defaults_to_no_and_timeout_is_not_approval(self):
        w = self.w
        fake = Mock()
        fake.MessageBoxTimeoutW.return_value = 32000
        with patch.object(w, "user32", fake), patch.object(w, "default_desktop_active", return_value=True):
            self.assertFalse(w.message_box("Consentire?", ask=True, timeout_ms=100))
            args = fake.MessageBoxTimeoutW.call_args.args
            self.assertEqual(args[3] & 0x300, 0x100)
            self.assertEqual(args[-1], 100)
            fake.MessageBoxTimeoutW.return_value = 6
            with patch.object(w.time, "monotonic", side_effect=[10, 11]):
                self.assertFalse(w.message_box("Consentire?", ask=True, timeout_ms=100))
            del fake.MessageBoxTimeoutW
            self.assertFalse(w.message_box("Consentire?", ask=True))
            fake.MessageBoxW.assert_not_called()
