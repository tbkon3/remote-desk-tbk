"""Authenticate the loopback agent to its native launcher and the OS user to its browser."""
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import quote, urlencode

from . import local_access_win

TICKET_SECONDS = 45
SESSION_SECONDS = 8 * 3600
MAX_NONCES = 8192
_PAGES = {"/", "/chat"}
_ROLES = {"desktop", "owner"}
_HEX32 = re.compile("[0-9a-f]{32}")
_HEX64 = re.compile("[0-9a-f]{64}")
NATIVE_HEADER = "X-RemoteDesk-Proof"
_BROWSER = "X-RD-Local"
_REQ_ROLE = "rd_local_authenticated_role"
_LANDING = """<!doctype html><html lang="it"><head><meta charset="utf-8">
<meta name="referrer" content="no-referrer"><title>RemoteDesk</title>
<script defer src="/web/bootstrap.js"></script></head><body>
<p id="status" role="status">Apertura di RemoteDesk…</p></body></html>"""


def _signature(key, purpose, *parts):
    payload = json.dumps(["rd-local-v1", purpose, *parts], separators=(",", ":")).encode("ascii")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _matches(expected, actual):
    return isinstance(actual, str) and bool(_HEX64.fullmatch(actual)) and hmac.compare_digest(expected, actual)


def _valid_time(stamp, lifetime):
    return type(stamp) is int and -5 <= int(time.time()) - stamp <= lifetime


def _valid_nonce(nonce):
    return isinstance(nonce, str) and bool(_HEX32.fullmatch(nonce))


def _make_proof(key, purpose, port, role, *fields):
    stamp, nonce = int(time.time()), secrets.token_hex(16)
    return {"role": role, "ts": stamp, "nonce": nonce,
            "sig": _signature(key, purpose, port, role, stamp, nonce, *fields)}


class LocalAccess:
    def __init__(self, owner_secret, port, service_mode):
        self.owner_key = owner_secret.encode("ascii") if isinstance(owner_secret, str) else owner_secret
        if not isinstance(self.owner_key, bytes) or len(self.owner_key) < 24:
            raise ValueError("Chiave proprietario locale non valida")
        self.port = port
        self.service_mode = service_mode
        self.desktop = None
        self.used = {}

    def _key(self, role):
        if role == "owner":
            return self.owner_key, ""
        if role == "desktop" and self.service_mode:
            try:
                if self.desktop is None:
                    self.desktop = local_access_win.DesktopMapping(self.port)
                return self.desktop.current()
            except OSError:
                pass  # Session can legitimately be on the logon screen. Retry after logon.
        return None, ""

    def _consume(self, role, nonce, stamp):
        # Executed on the HTTP event-loop thread, with no await between check and insert.
        key = (role, nonce)
        now = int(time.time())
        if key in self.used:
            return False
        if len(self.used) >= MAX_NONCES:
            self.used = {k: expiry for k, expiry in self.used.items() if expiry >= now}
            if len(self.used) >= MAX_NONCES:
                return False
        self.used[key] = stamp + TICKET_SECONDS
        return True

    def _validate(self, data, purpose, fields, lifetime, one_use):
        if not isinstance(data, dict):
            return None
        role, stamp, nonce = data.get("role"), data.get("ts"), data.get("nonce")
        if not isinstance(role, str) or role not in _ROLES or not _valid_time(stamp, lifetime) or not _valid_nonce(nonce):
            return None
        key, _ = self._key(role)
        if key is None or not _matches(_signature(key, purpose, self.port, role, stamp, nonce, *fields), data.get("sig")):
            return None
        if one_use and not self._consume(role, nonce, stamp):
            return None
        return role, key

    def authenticate(self, req):
        if _REQ_ROLE in req:
            return req[_REQ_ROLE]
        native = req.headers.get(NATIVE_HEADER)
        value = native if native is not None else req.headers.get(_BROWSER, "")
        role = None
        if len(value) < 192:
            try:
                name, stamp, nonce, sig = value.split(".")
                proof = {"role": name, "ts": int(stamp), "nonce": nonce, "sig": sig}
                if native is not None:
                    verified = self._validate(proof, "native", (req.method, req.raw_path), TICKET_SECONDS, True)
                else:
                    verified = self._validate(proof, "browser", (), SESSION_SECONDS, False)
                if verified is not None:
                    role = verified[0]
            except ValueError:
                pass
        req[_REQ_ROLE] = role
        return role

    async def challenge(self, req):
        from aiohttp import web
        nonce, role = req.query.get("nonce"), req.query.get("role")
        if not _valid_nonce(nonce) or role not in _ROLES:
            raise web.HTTPBadRequest()
        key, mapping = self._key(role)
        if key is None:
            raise web.HTTPForbidden()
        return web.json_response({"mapping": mapping, "proof": _signature(key, "server", self.port, role, nonce, mapping)},
                                 headers={"Cache-Control": "no-store"})

    async def claim(self, req):
        from aiohttp import web
        if req.headers.get("Origin") != f"http://127.0.0.1:{self.port}" or req.content_type != "application/json":
            raise web.HTTPForbidden()
        # Browser requests have Content-Length. Refuse chunked or oversized requests before parsing.
        if req.content_length is None or not 0 < req.content_length <= 1024:
            raise web.HTTPBadRequest()
        try:
            data = await req.json()
        except (ValueError, UnicodeError):
            raise web.HTTPBadRequest() from None
        path = data.get("path") if isinstance(data, dict) else None
        if not isinstance(path, str) or path not in _PAGES:
            raise web.HTTPForbidden()
        verified = self._validate(data, "claim", (path,), TICKET_SECONDS, True)
        if verified is None:
            raise web.HTTPForbidden()
        role, key = verified
        token = _compact(_make_proof(key, "browser", self.port, role))
        return web.json_response({"path": path, "token": token}, headers={"Cache-Control": "no-store"})

    async def landing(self, req):
        from aiohttp import web
        return web.Response(text=_LANDING, content_type="text/html",
                            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    async def cleanup(self, app):
        if self.desktop is not None:
            self.desktop.close()
        self.used.clear()


def _compact(proof):
    return "{role}.{ts}.{nonce}.{sig}".format_map(proof)


def _challenge(port, role, nonce):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=1.5)
    try:
        query = urlencode({"role": role, "nonce": nonce})
        client.request("GET", "/api/local/challenge?" + query)
        response = client.getresponse()
        raw = response.read(1025)
        if response.status != 200 or len(raw) > 1024:
            raise PermissionError("Verifica del servizio locale fallita")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("Risposta locale non valida")
        return result
    finally:
        client.close()


def _owner_keys(data_dir):
    from .common import PROGRAM_DATA, user_data_dir
    roots = [data_dir] if data_dir is not None else [user_data_dir()]
    if os.name == "nt":
        roots.append(PROGRAM_DATA)
    for root in dict.fromkeys(roots):
        try:
            with (Path(root) / "local.token").open("rb") as stream:
                key = stream.read(129).strip()
            if re.fullmatch(b"[0-9A-Za-z_-]{24,128}", key):
                yield key
        except OSError:
            continue


def _verified(port, data_dir, desktop_only):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Porta locale non valida")
    roles = ("desktop",) if desktop_only else ("owner", "desktop")
    for role in roles:
        nonce = secrets.token_hex(16)
        try:
            result = _challenge(port, role, nonce)
            mapping = result.get("mapping")
            if role == "owner":
                if mapping != "":
                    continue
                keys = _owner_keys(data_dir)
            else:
                if not _valid_nonce(mapping):
                    continue
                keys = (local_access_win.read_desktop(port, mapping),)
            for key in keys:
                if _matches(_signature(key, "server", port, role, nonce, mapping), result.get("proof")):
                    return role, key
        except (OSError, ValueError, http.client.HTTPException):
            continue
    raise PermissionError("Impossibile verificare l'identità dell'agente RemoteDesk locale")


def open_ticket(port, path, data_dir=None, *, desktop_only=False):
    if path not in _PAGES:
        raise ValueError("Pagina locale non valida")
    if os.name == "nt" and local_access_win.running_as_system():
        # Only the interactive tray should launch a browser. A SYSTEM browser is privileged
        # even when its RemoteDesk bearer is limited to the desktop role.
        raise PermissionError("Aprire la console dall'icona della sessione Windows")
    role, key = _verified(port, data_dir, desktop_only)
    ticket = _make_proof(key, "claim", port, role, path)
    ticket["path"] = path
    fragment = quote(json.dumps(ticket, separators=(",", ":")), safe="")
    return f"http://127.0.0.1:{port}/local/start#{fragment}"


def native_headers(port, path, method, data_dir=None):
    if not isinstance(path, str) or not path.startswith("/api/") or "#" in path or method not in ("GET", "POST"):
        raise ValueError("Richiesta locale non valida")
    role, key = _verified(port, data_dir, False)
    return {NATIVE_HEADER: _compact(_make_proof(key, "native", port, role, method, path))}
