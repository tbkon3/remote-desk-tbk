"""Exercise the installed aiohttp router and authorization middleware without opening a socket."""
import asyncio
import importlib.util
import json
import sys
import tempfile
import unittest
from collections import defaultdict
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
        self.agent.cfg, self.agent.logins = defaultdict(str), {}
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

    async def test_update_target_is_private_and_portable_controls_do_not_touch_windows(self):
        owner, desktop = await self.browser("owner"), await self.browser("desktop")
        portable_dir, service_dir = r"C:\fixture\portable", r"C:\fixture\managed"
        self.agent.cfg.update(name="fixture", id="111222333")
        self.agent.nets, self.agent.sessions, self.agent.events = {}, {}, []
        self.agent.data_dir, self.agent.cloned = "data-fixture", False
        self.agent.logged_user = lambda: "fixture"
        self.agent.incoming_dir = lambda: "fixture-shared"
        self.agent.updater = Mock()
        self.agent.updater.status.return_value = {"current":"1", "latest":"2", "error":portable_dir, "auto":True}
        self.enterContext(patch("rd.web.ROOT_DIR", portable_dir))
        self.enterContext(patch("rd.web.INSTALL_DIR", service_dir))
        marker = self.enterContext(patch("rd.web.service_installed", return_value=True))
        elevate = self.enterContext(patch("rd.web.svc.elevate"))
        from rd import web as console_web
        if console_web.WIN:
            autorun = self.enterContext(patch.object(console_web.W, "autostart_set"))
        for portable, service, mode, location in ((True, False, "portable", portable_dir),
                                                  (False, True, "service", service_dir),
                                                  (False, False, "user", portable_dir)):
            self.agent.portable, self.agent.service_mode = portable, service
            response = await self.dispatch("GET", "/api/update/local", owner)
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.text)["update_target"], {"mode":mode, "path":location})
            self.assertEqual((await self.dispatch("GET", "/api/update/local", desktop)).status, 403)
            marker.reset_mock()
            public = await self.dispatch("GET", "/api/public", desktop)
            self.assertEqual(public.status, 200, public.text)
            data = json.loads(public.text)
            self.assertNotIn("update_target", data)
            self.assertNotIn("service_setup", data)
            self.assertNotIn("error", data["update"])
            self.assertEqual(data["service"]["installed"], not portable)
            if portable:
                marker.assert_not_called()
                self.assertNotIn("auto_update", self.agent.cfg)
                setting = await self.dispatch("POST", "/api/settings", owner, {"auto_update":True})
                self.assertEqual(setting.status, 200)
                self.assertIs(self.agent.cfg["auto_update"], True)
                for route in ("/api/service", "/api/autostart"):
                    self.assertEqual((await self.dispatch("POST", route, owner, {})).status, 403)
                elevate.assert_not_called()
                if console_web.WIN:
                    autorun.assert_not_called()
        mismatch = await self.dispatch("POST", "/api/update/install", owner,
                                       {"expected_target":{"mode":"service", "path":service_dir}})
        self.assertEqual(mismatch.status, 409)
        self.agent.updater.install.assert_not_called()
        network = Mock()
        network.name = "fixture"
        network.reg.version = 1
        network.reg.machines.return_value = {}
        network.reg.users.return_value = {}
        network.reg.is_admin.side_effect = lambda user: user == "admin"
        self.agent.nets = {"n":network}
        self.agent.get_login = lambda token, **kwargs: {"n":{"user":token}} if token in ("admin","viewer") else {}
        self.agent.is_any_admin = lambda grants: (grants.get("n") or {}).get("user") == "admin"
        self.assertEqual((await self.dispatch("GET", "/api/update/local", owner)).status, 403)
        for identity, user, visible in ((owner,"admin",True),(desktop,"admin",False),(owner,"viewer",False)):
            headers = {**identity, "X-RD-Login":user}
            self.agent.portable = True
            response = await self.dispatch("GET", "/api/state", headers)
            self.assertEqual(response.status, 200)
            self.assertEqual("update_target" in json.loads(response.text), visible)
            self.assertEqual("local_update" in json.loads(response.text), visible)

    async def test_portable_can_request_install_only_for_a_prepared_unregistered_service(self):
        owner, desktop = await self.browser("owner"), await self.browser("desktop")
        self.agent.portable, self.agent.service_mode, self.agent.nets = True, False, {}
        setup_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        paths = tuple(setup_dir / name for name in ("pythonw.exe", "remotedesk.py", "RemoteDesk.exe"))
        rd = setup_dir / "rd"
        rd.mkdir()
        version_file = rd / "common.py"
        from rd import service
        registered = self.enterContext(patch("rd.web.service_installed", return_value=False))
        self.enterContext(patch("rd.web.WIN", True))
        self.enterContext(patch("rd.web.INSTALL_DIR", str(setup_dir)))
        self.enterContext(patch("rd.web.svc.installed_paths", return_value=paths))
        elevate = self.enterContext(patch("rd.web.svc.elevate", return_value=True))
        install = "/api/service"
        body = {"action": "install", "path": "user-supplied-location"}
        self.assertEqual((await self.dispatch("POST", install, desktop, body)).status, 403)
        result = await self.dispatch("POST", install, owner, body)
        self.assertEqual(result.status, 409)
        self.assertIn(str(setup_dir), json.loads(result.text)["error"])
        for path in paths:
            path.touch()
        version_file.write_text('VERSION = "2.3.2"\n', encoding="utf-8")
        self.assertEqual((await self.dispatch("POST", install, owner, body)).status, 409)
        version_file.write_text(f'VERSION = "{service.VERSION}"\n', encoding="utf-8")
        registered.return_value = True
        self.assertEqual((await self.dispatch("POST", install, owner, body)).status, 409)
        self.assertEqual((await self.dispatch("POST", install, owner, {"action": "uninstall"})).status, 403)
        elevate.assert_not_called()
        registered.return_value = False
        result = await self.dispatch("POST", install, owner, body)
        self.assertEqual(result.status, 200)
        self.assertEqual(json.loads(result.text), {"ok": True})
        elevate.assert_called_once_with("--install-service")

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
