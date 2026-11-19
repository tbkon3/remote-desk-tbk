"""Exercise the installed aiohttp router and authorization middleware without opening a socket."""
import asyncio
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd import local_access as access


@unittest.skipUnless(all(importlib.util.find_spec(dep) for dep in ("aiohttp", "aiortc")), "runtime RemoteDesk richiesto")
class WebAuthIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from rd.agent import Agent
        from rd.web import make_app
        self.port = 47800
        self.key = b"o" * 32
        self.desktop_key = b"d" * 32
        self.agent = Agent.__new__(Agent)
        self.agent.local_token = self.key.decode()
        self.agent.cfg, self.agent.logins = {}, {}
        self.agent.service_mode = True
        self.agent.close_sessions = AsyncMock()
        self.quit = Mock()
        self.app = make_app(self.agent, self.port, self.quit)
        self.mapping = Mock()
        self.mapping.current.return_value = self.desktop_key, "a" * 32
        self.enterContext(patch.object(access.local_access_win, "DesktopMapping", return_value=self.mapping))

    async def dispatch(self, method, path, headers=None, body=None):
        from aiohttp.test_utils import make_mocked_request
        headers = {"Host": f"127.0.0.1:{self.port}", **(headers or {})}
        payload = Mock()
        payload.at_eof.return_value = body is None
        if body is not None:
            raw = json.dumps(body).encode()
            headers.update({"Content-Length": str(len(raw)), "Content-Type": "application/json"})
            payload.readany = AsyncMock(side_effect=[raw, b""])
        req = make_mocked_request(method, path, headers=headers, app=self.app, payload=payload)
        match = await self.app.router.resolve(req)
        return await self.app.middlewares[0](req, match.handler)

    async def browser(self, role):
        key = self.key if role == "owner" else self.desktop_key
        ticket = dict(access._make_proof(key, "claim", self.port, role, "/"), path="/")
        response = await self.dispatch("POST", "/api/local/claim", {"Origin": f"http://127.0.0.1:{self.port}"}, ticket)
        self.assertEqual(response.status, 200)
        return {"X-RD-Local": json.loads(response.text)["token"]}

    async def test_real_router_desktop_stop_and_owner_settings_boundary(self):
        stop = "/api/sessions/close"
        self.assertEqual((await self.dispatch("POST", stop, body={})).status, 403)
        headers = await self.browser("desktop")
        self.assertEqual((await self.dispatch("POST", stop, headers, {"sid": "A"})).status, 200)
        self.agent.close_sessions.assert_awaited_once_with("A")
        self.assertEqual((await self.dispatch("POST", "/api/settings", headers, {})).status, 403)
        self.assertEqual((await self.dispatch("POST", stop, {**headers, "Origin": "http://127.0.0.1:47801"}, {})).status, 403)

    async def test_real_logout_drops_grants_and_clears_browser_header(self):
        headers = await self.browser("desktop")
        token = "test-only-login"
        self.agent.logins[token] = {"nets": {"A": {}, "B": {}}}
        headers["X-RD-Login"] = token
        response = await self.dispatch("POST", "/api/logout", headers, {"nid": "A"})
        self.assertEqual(response.status, 200)
        self.assertNotIn("X-RD-Login", response.headers)
        self.assertEqual(self.agent.logins[token]["nets"], {"B": {}})
        response = await self.dispatch("POST", "/api/logout", headers, {})
        self.assertEqual(response.headers["X-RD-Login"], "")
        self.assertNotIn(token, self.agent.logins)

    async def test_handover_requires_native_single_use_owner_proof(self):
        path = "/api/handover"
        browser = await self.browser("owner")
        self.assertEqual((await self.dispatch("POST", path, browser)).status, 403)
        self.assertEqual((await self.dispatch("POST", path, {"X-RD-Token": self.key.decode()})).status, 403)
        desktop = access._make_proof(self.desktop_key, "native", self.port, "desktop", "POST", path)
        self.assertEqual((await self.dispatch("POST", path, {access.NATIVE_HEADER: access._compact(desktop)})).status, 403)
        owner = access._make_proof(self.key, "native", self.port, "owner", "POST", path)
        native = {access.NATIVE_HEADER: access._compact(owner)}
        loop = asyncio.get_running_loop()
        with patch.object(loop, "call_later") as schedule:
            self.assertEqual((await self.dispatch("POST", path, native)).status, 200)
            schedule.assert_called_once_with(0.3, self.quit)
        self.assertEqual((await self.dispatch("POST", path, native)).status, 403)
