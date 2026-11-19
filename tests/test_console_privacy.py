import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd import auth
from rd.agent import Agent
from rd.audit import Audit
from rd.common import Config
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class ConsolePrivacy(unittest.TestCase):
    def test_new_network_login_does_not_restore_an_expired_grant(self):
        agent = Agent.__new__(Agent)
        private = Ed25519PrivateKey.generate()
        reg = SimpleNamespace(user=lambda _: {"pub": auth.pub_of(private)})
        agent.logins = {}
        agent.nets = {nid: SimpleNamespace(reg=reg) for nid in ("a", "b")}
        first = agent.add_login(None, "a", "tech", private)
        agent.get_login(first)["a"]["act"] = time.monotonic() - agent.IDLE - 1
        second = agent.add_login(first, "b", "tech", private)
        self.assertNotEqual(first, second)
        self.assertFalse(agent.get_login(first))
        self.assertEqual(set(agent.get_login(second)), {"b"})

    def test_chat_has_exactly_one_recipient(self):
        agent = Agent.__new__(Agent)
        agent.logged_user = lambda: "Local"
        a, b = Mock(sid="a", connected=True, mode="control"), Mock(sid="b", connected=True, mode="view")
        agent.sessions = {"a": a, "b": b}
        agent.chat, agent.chat_seq = [], 0
        with self.assertRaises(RuntimeError):
            agent.chat_send_local("test")
        agent.chat_send_local("test", "b")
        a.send.assert_not_called()
        b.send.assert_called_once()
        self.assertEqual(agent.chat[0]["sid"], "b")

    def test_existing_clipboard_records_are_redacted_on_disk(self):
        with tempfile.TemporaryDirectory() as folder:
            audit_path = Path(folder) / "audit.jsonl"
            audit_path.write_text(json.dumps({"t":int(time.time()), "k":"clip_in", "text":"old private text"}) + "\n",
                                  encoding="utf8")
            audit = Audit(folder)
            audit.add("clip_out", text="new private text")
            self.assertTrue(all("text" not in row for row in audit.query()))
            self.assertNotIn("private text", audit_path.read_text(encoding="utf8"))

    def test_upgrade_requires_opt_in_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text('{"id":"123456789","ask_confirm":false,"allow_files":true}', encoding="utf8")
            cfg = Config(folder)
            self.assertTrue(cfg["ask_confirm"])
            self.assertFalse(cfg["allow_files"])
            self.assertEqual(cfg["id"], "123456789")
            cfg.update(allow_files=True)
            self.assertTrue(Config(folder)["allow_files"])

    def test_unreadable_identity_never_reopens_provisioning(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text("{", encoding="utf8")
            with self.assertRaises(RuntimeError):
                Config(folder)
            self.assertEqual(path.read_text(encoding="utf8"), "{")
            backup = Path(str(path) + ".bak")
            backup.write_text('{"id":"123456789","security_defaults":1}', encoding="utf8")
            self.assertEqual(Config(folder)["id"], "123456789")
