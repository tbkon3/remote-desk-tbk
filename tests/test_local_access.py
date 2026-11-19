"""Loopback authentication tests with synthetic requests, registry-free OS token and mapping fixtures."""
import ctypes as ct
from functools import wraps
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd import local_access as access
from rd import local_access_win as win


class Forbidden(Exception):
    pass


class BadRequest(Exception):
    pass


def reply(data, headers=None):
    return SimpleNamespace(text=json.dumps(data), headers=headers or {})


class Request(dict):
    def __init__(self, *, method="GET", path="/api/public", headers=None, query=None, data=None):
        super().__init__()
        self.headers = headers or {}
        self.cookies = {}
        self.query = query or {}
        self.method = method
        self.raw_path = path
        self.data = data
        self.content_type = "application/json"
        self.content_length = len(json.dumps(data).encode())

    async def json(self):
        return self.data


def no_io(coroutine):
    """Synthetic request bodies resolve immediately. Reject any real asynchronous I/O."""
    @wraps(coroutine)
    def run(self):
        task = coroutine(self)
        try:
            task.send(None)
        except StopIteration:
            return
        finally:
            task.close()
        self.fail("Il test ha richiesto I/O reale")
    return run


class LocalAccessTests(unittest.TestCase):
    def setUp(self):
        self.port = 47800
        self.owner = b"o" * 32
        self.desk = b"d" * 32
        self.mapping = "a" * 32
        self.access = access.LocalAccess(self.owner, self.port, True)
        self.os = Mock()
        self.os.current.return_value = self.desk, self.mapping
        self.access.desktop = self.os
        self.enterContext(patch.object(win, "running_as_system", return_value=False))
        try:
            from aiohttp import web
        except ImportError:
            web = SimpleNamespace(HTTPForbidden=Forbidden, HTTPBadRequest=BadRequest, json_response=reply)
            self.enterContext(patch.dict(sys.modules, {"aiohttp": SimpleNamespace(web=web)}))
        self.web = web
        self.clock = self.enterContext(patch.object(access.time, "time", return_value=20000))

    def claim_request(self, ticket):
        return Request(method="POST", path="/api/local/claim", data=ticket,
                       headers={"Origin": f"http://127.0.0.1:{self.port}"})

    def challenge_reply(self, port, role, nonce):
        key, mapping = self.access._key(role)
        return {"mapping": mapping, "proof": access._signature(key, "server", port, role, nonce, mapping)}

    @no_io
    async def test_challenge_only_proves_server_and_rejects_unknown_roles(self):
        nonce = "0" * 32
        response = await self.access.challenge(Request(query={"role": "desktop", "nonce": nonce}))
        body = json.loads(response.text)
        self.assertEqual(body, self.challenge_reply(self.port, "desktop", nonce))
        self.assertNotIn(self.desk.decode(), response.text)
        with self.assertRaises(self.web.HTTPBadRequest):
            await self.access.challenge(Request(query={"role": "admin", "nonce": nonce}))
        forged = {"role": "desktop", "nonce": nonce, "ts": 20000, "sig": body["proof"], "path": "/chat"}
        with self.assertRaises(self.web.HTTPForbidden):
            await self.access.claim(self.claim_request(forged))

    @no_io
    async def test_desktop_bootstrap_native_to_browser_role_scope_and_rotation(self):
        with patch.object(access, "_challenge", side_effect=self.challenge_reply), \
                patch.object(win, "read_desktop", return_value=self.desk) as reader, \
                patch.object(access, "_owner_keys", side_effect=AssertionError("owner key requested")):
            url = urlsplit(access.open_ticket(self.port, "/chat", desktop_only=True))
        reader.assert_called_once_with(self.port, self.mapping)
        self.assertEqual((url.hostname, url.path, url.query), ("127.0.0.1", "/local/start", ""))
        proof = json.loads(unquote(url.fragment))
        result = await self.access.claim(self.claim_request(proof))
        body = json.loads(result.text)
        self.assertNotIn("Set-Cookie", result.headers)
        self.assertEqual(body["path"], "/chat")
        headers = {"X-RD-Local": body["token"]}
        self.assertEqual(self.access.authenticate(Request(headers=headers)), "desktop")
        with self.assertRaises(self.web.HTTPForbidden):
            await self.access.claim(self.claim_request(proof))
        upgraded = {"X-RD-Local": body["token"].replace("desktop.", "owner.")}
        self.assertIsNone(self.access.authenticate(Request(headers=upgraded)))
        wrong_port = access.LocalAccess(self.owner, self.port + 1, True)
        wrong_port.desktop = self.os
        self.assertIsNone(wrong_port.authenticate(Request(headers=headers)))
        self.os.current.return_value = b"x" * 32, "b" * 32
        self.assertIsNone(self.access.authenticate(Request(headers=headers)))

    @no_io
    async def test_native_header_binds_method_path_query_and_is_single_use(self):
        path = "/api/chat?sid=4"
        with patch.object(access, "_challenge", side_effect=self.challenge_reply), \
                patch.object(access, "_owner_keys", return_value=[self.owner]):
            headers = access.native_headers(self.port, path, "GET")
        for method, changed in (("POST", path), ("GET", "/api/chat?sid=5"), ("GET", "/api/chat")):
            self.assertIsNone(self.access.authenticate(Request(method=method, path=changed, headers=headers)))
        request = Request(path=path, headers=headers)
        self.assertEqual(self.access.authenticate(request), "owner")
        self.assertEqual(self.access.authenticate(request), "owner")
        self.assertIsNone(self.access.authenticate(Request(path=path, headers=headers)))
        self.assertIsNone(self.access.authenticate(Request(path=path, headers={"X-RD-Local": headers[access.NATIVE_HEADER]})))

    @no_io
    async def test_rejects_spoofed_loopback_and_arbitrary_redirect(self):
        def unrelated(port, role, nonce):
            return {"mapping": self.mapping if role == "desktop" else "", "proof": "9" * 64}
        with patch.object(access, "_challenge", side_effect=unrelated), \
                patch.object(access, "_owner_keys", return_value=[self.owner]), \
                patch.object(win, "read_desktop", return_value=self.desk):
            with self.assertRaises(PermissionError):
                access.open_ticket(self.port, "/")
            with self.assertRaises(PermissionError):
                access.native_headers(self.port, "/api/public", "GET")
            with self.assertRaises(ValueError):
                access.open_ticket(self.port, "//example.test/")

    @no_io
    async def test_expiry_origin_page_substitution_and_failure_on_nonce_saturation(self):
        ticket = access._make_proof(self.owner, "claim", self.port, "owner", "/")
        ticket["path"] = "/"
        req = self.claim_request(ticket)
        req.headers["Origin"] = "http://127.0.0.1:47801"
        with self.assertRaises(self.web.HTTPForbidden):
            await self.access.claim(req)
        with self.assertRaises(self.web.HTTPForbidden):
            await self.access.claim(self.claim_request(dict(ticket, path="/chat")))
        with patch.object(access, "MAX_NONCES", 1):
            await self.access.claim(self.claim_request(ticket))
            second = dict(access._make_proof(self.owner, "claim", self.port, "owner", "/"), path="/")
            with self.assertRaises(self.web.HTTPForbidden):
                await self.access.claim(self.claim_request(second))
            self.clock.return_value += access.TICKET_SECONDS + 1
            with self.assertRaises(self.web.HTTPForbidden):
                await self.access.claim(self.claim_request(second))
            fresh = dict(access._make_proof(self.owner, "claim", self.port, "owner", "/"), path="/")
            await self.access.claim(self.claim_request(fresh))

    @no_io
    async def test_unavailable_service_session_fails_closed_for_desktop(self):
        self.os.current.side_effect = PermissionError()
        with self.assertRaises(self.web.HTTPForbidden):
            await self.access.challenge(Request(query={"role": "desktop", "nonce": "0" * 32}))
        self.assertEqual(self.access._key("owner"), (self.owner, ""))
        portable = access.LocalAccess(self.owner, self.port, False)
        self.assertEqual(portable._key("desktop"), (None, ""))

    def test_system_does_not_open_a_browser_or_publish_a_ticket(self):
        with patch.object(access.os, "name", "nt"), patch.object(win, "running_as_system", return_value=True), \
                patch.object(access, "_verified", side_effect=AssertionError("ticket requested")):
            for desktop_only in (True, False):
                with self.assertRaises(PermissionError):
                    access.open_ticket(self.port, "/chat", desktop_only=desktop_only)


class MappingTests(unittest.TestCase):
    def test_reader_verifies_system_owner_before_mapping_and_closes(self):
        fake = Mock()
        fake.open.return_value = 9
        fake.verify_owner.side_effect = PermissionError("wrong owner")
        with patch.object(win, "_Windows", return_value=fake):
            with self.assertRaises(PermissionError):
                win.read_desktop(47800, "a" * 32)
        fake.open.assert_called_once_with(0x20004, 0, r"Local\RemoteDesk-Desktop-47800-" + "a" * 32)
        fake.map.assert_not_called()
        fake.close.assert_called_once_with(9)

    def test_publisher_grants_only_logon_sid_read_and_discards_stale_mapping(self):
        fake = Mock()
        sid = "S-1-5-5-100-200"
        fake.logon_sid.side_effect = [sid, sid, OSError("logged out")]
        fake.create.return_value = 9
        storage = ct.create_string_buffer(32)
        fake.map.return_value = ct.addressof(storage)
        with patch.object(win, "_Windows", return_value=fake), \
                patch.object(ct, "set_last_error", create=True), patch.object(ct, "get_last_error", return_value=0, create=True):
            desktop = win.DesktopMapping(47800)
            key, identifier = desktop.current()
            self.assertEqual(storage.raw, key)
            self.assertEqual(desktop.current(), (key, identifier))
            self.assertEqual(fake.descriptor.call_args.args[0], f"O:SYD:P(A;;GA;;;SY)(A;;0x00020004;;;{sid})")
            with self.assertRaises(OSError):
                desktop.current()
            self.assertIsNone(desktop.secret)
            fake.close.assert_called_once_with(9)


if __name__ == "__main__":
    unittest.main()
