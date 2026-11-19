"""Verifica ICE e credenziali coturn senza risolvere nomi o aprire socket."""
import base64
import hashlib
import hmac
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd import ice


class IceTests(unittest.TestCase):
    def test_stun_disabled_and_normalized(self):
        self.assertEqual(ice.servers({"stun": [], "turn_url": ""}), [])
        urls = ["stun:ICE.example.test:03478", "stun:ice.example.test:3478", "stun:192.0.2.1"]
        self.assertEqual(ice.validate_stun(urls), ["stun:ice.example.test:3478", "stun:192.0.2.1"])
        self.assertEqual(ice.servers({"stun": urls})[0], {"urls": "stun:ice.example.test:3478"})

    def test_bad_stun(self):
        for value in (None, "stun:host", ["stun:host"] * 9, ["turn:host"], ["stun:host?transport=tcp"],
                      ["stun://host"], ["stun:localhost:0"], ["stun:999.1.1.1"], ["stun:-host"], ["stun:a..b"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ice.validate_stun(value)

    def test_turn_transport(self):
        for url in ("turns:relay.example.test:443", "turns:relay:5349?transport=tcp",
                    "turn:relay?transport=udp", "turn:192.0.2.2?transport=tcp", ""):
            self.assertEqual(ice.validate_turn_url(url), url)
        for bad in (None, [], "stun:host", "turns:relay?transport=udp", "turn:relay?transport=tls",
                    "turns:relay:65536", "turn:user@host", "turn:host/path", "turn:host#fragment", "turn:host\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ice.validate_turn_url(bad)

    def test_static_and_partial_credentials(self):
        cfg = {"turn_url": "turn:relay.example.test", "turn_user": "u", "turn_pass": "pass"}
        self.assertEqual(ice.servers(cfg), [{"urls": cfg["turn_url"], "username": "u", "credential": "pass"}])
        for change in ({"turn_secret": "short"}, {"turn_user": ""}, {"turn_pass": ""}, {"turn_pass": ["pass"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                ice.servers(dict(cfg, **change))

    def test_coturn_ephemeral_secrets(self):
        secret = "fixture" * 8
        cfg = dict(turn_url="turns:relay.example.test:443?transport=tcp",
                   turn_user="static-user", turn_pass="static-pass", turn_secret=secret)
        with patch.object(ice.time, "time", return_value=1000):
            first, second = ice.servers(cfg)[0], ice.servers(cfg)[0]
        self.assertNotEqual(first["username"], second["username"])
        self.assertEqual(first["username"].split(":")[0], str(1000 + ice.TURN_LIFETIME))
        expected = hmac.new(secret.encode(), first["username"].encode(), hashlib.sha1).digest()
        self.assertEqual(base64.b64decode(first["credential"], validate=True), expected)
        self.assertEqual(set(first), {"urls", "username", "credential"})
        for sensitive in (secret, cfg["turn_user"], cfg["turn_pass"]):
            self.assertNotIn(sensitive, str(first))


if __name__ == "__main__":
    unittest.main()
