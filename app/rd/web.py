"""Server HTTP locale (solo 127.0.0.1): console, finestre di sessione e API.

Accesso: le API che danno controllo richiedono il login (cookie HttpOnly, SameSite=Strict).
Senza login si vedono solo lo stato di questo PC e chi e' collegato (per poterlo scollegare)."""
import asyncio
import logging
import re
import os
import sys
import time

from aiohttp import web

from . import auth
from . import service as svc
from .agent import service_marker
from .common import VERSION, WEB_DIR, WIN, fmt_id, os_label, service_installed

if WIN:
    from . import winapi as W

log = logging.getLogger("rd.web")
MACHINE_SETTINGS = {"name", "accept_incoming", "ask_confirm", "allow_control", "allow_files", "allow_clipboard",
                    "signal", "turn_url", "turn_user", "turn_pass", "incoming_dir"}
COOKIE = "rdtok"


def make_app(agent, port, on_quit):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    cfg = agent.cfg

    @web.middleware
    async def guard(req, handler):
        # protezione da DNS-rebinding e da richieste di siti esterni
        if req.host not in allowed_hosts:
            return web.Response(status=403, text="host non permesso")
        origin = req.headers.get("Origin")
        if req.method != "GET" and origin and origin not in allowed_origins:
            return web.Response(status=403, text="origine non permessa")
        if req.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            return web.Response(status=403, text="richiesta cross-site")
        try:
            resp = await handler(req)
        except web.HTTPException as e:
            resp = e
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                                   "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                                                   "media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'")
        return resp

    app = web.Application(middlewares=[guard], client_max_size=8 * 1024 * 1024)

    def login_of(req):
        # solo le operazioni (POST) contano come attivita': il polling non tiene vivo il login
        return agent.get_login(req.cookies.get(COOKIE), touch=req.method == "POST")   # {nid: {user, priv}}

    def need_login(req):
        lg = login_of(req)
        if not lg:
            raise web.HTTPUnauthorized(text='{"error":"login richiesto"}', content_type="application/json")
        return lg

    def need_net(req, nid, admin=False):
        """Login sulla rete nid (ed eventualmente da amministratore): ritorna (rete, login)."""
        lgs = need_login(req)
        n = agent.nets.get(nid or "")
        lg = lgs.get(nid or "")
        if not n or not lg:
            raise web.HTTPForbidden(text='{"error":"non hai effettuato l\'accesso a questa rete"}',
                                    content_type="application/json")
        if admin and not n.reg.is_admin(lg["user"]):
            raise web.HTTPForbidden(text='{"error":"serve un amministratore di questa rete"}',
                                    content_type="application/json")
        return n, lg

    def need_local_admin(req):
        """Impostazioni di QUESTO PC: libere finche' non e' in nessuna rete, poi admin di una sua rete."""
        if not agent.nets:
            return
        if not agent.is_any_admin(login_of(req)):
            raise web.HTTPForbidden(text='{"error":"serve un amministratore di una delle reti di questo PC"}',
                                    content_type="application/json")

    def err(e):
        return web.json_response({"error": str(e)})

    def with_cookie(resp, tok):
        resp.set_cookie(COOKIE, tok, httponly=True, samesite="Strict", path="/")
        return resp

    def page(name):
        async def h(_):
            return web.FileResponse(os.path.join(WEB_DIR, name))
        return h

    # ------------------------------------------------------------------ pubblico
    async def public(req):
        lgs = login_of(req)
        nets = []
        for n in agent.nets.values():
            lg = lgs.get(n.nid)
            nets.append({"nid": n.nid, "name": n.name, "state": n.state, "conflict": n.conflict,
                         "registered": cfg["id"] in n.reg.machines(),
                         "login": {"user": lg["user"], "admin": n.reg.is_admin(lg["user"]),
                                   "name": (n.reg.user(lg["user"]) or {}).get("name")} if lg else None})
        return web.json_response({
            "version": VERSION,
            "me": {"id": cfg["id"], "fid": fmt_id(cfg["id"]), "name": cfg["name"], "os": os_label(),
                   "user": agent.logged_user()},
            "networks": nets,
            "configured": bool(agent.nets),
            "logged": bool(lgs),
            "admin_any": agent.is_any_admin(lgs),
            "can_add_network": not agent.nets or agent.is_any_admin(lgs),
            "cloned": agent.cloned,
            "sessions": [{"sid": s.sid, "peer": s.peer, "peer_name": s.peer_name, "user": s.user, "mode": s.mode,
                          "net": s.net.name, "since": int(s.started), "connected": s.connected}
                         for s in agent.sessions.values()],
            "events": agent.events[-30:],
            "service": {"installed": service_installed(agent.data_dir),
                        "active": agent.service_mode, "supported": WIN},
            "platform": sys.platform,
        })

    async def ping(_):
        return web.json_response({"app": "remotedesk", "id": cfg["id"], "service": agent.service_mode})

    async def login(req):
        b = await req.json()
        try:
            tok = await agent.login(req.cookies.get(COOKIE), b.get("nid"), str(b.get("user", "")),
                                    str(b.get("password", "")))
        except Exception as e:
            return err(e)
        return with_cookie(web.json_response({"ok": True}), tok)

    async def logout(req):
        b = await req.json() if req.can_read_body else {}
        agent.logout(req.cookies.get(COOKIE), b.get("nid"))
        resp = web.json_response({"ok": True})
        if not b.get("nid"):
            resp.del_cookie(COOKIE, path="/")
        return resp

    async def setup(req):
        """Crea una rete nuova o entra in una esistente. Se il PC e' gia' in qualche rete serve
        il login di un amministratore di una di quelle reti (nessuno puo' 'regalare' il PC a
        un'altra rete di nascosto)."""
        if agent.nets and not agent.is_any_admin(login_of(req)):
            return err("Per aggiungere questo PC a un'altra rete accedi come amministratore di una delle sue reti")
        b = await req.json()
        user, pw = str(b.get("user", "")).strip(), str(b.get("password", ""))
        if len(pw) < 10 or not user:
            return err("Utente obbligatorio e password di almeno 10 caratteri")
        if not str(b.get("network", "")).strip():
            return err("Nome rete obbligatorio")
        try:
            if b.get("action") == "create":
                if any(n.name.lower() == b["network"].strip().lower() for n in agent.nets.values()):
                    return err("Esiste gia' una rete con questo nome su questo PC")
                n, key, priv = await agent.create_network(b["network"], user, pw, str(b.get("pcname", "")).strip())
            else:
                if not str(b.get("key", "")).strip():
                    return err("Inserisci la chiave di rete")
                n, priv = await agent.join_network(b["network"], b["key"], user, pw, str(b.get("pcname", "")).strip())
                key = None
        except Exception as e:
            return err(e)
        agent.cloned = False
        tok = agent.add_login(req.cookies.get(COOKIE), n.nid, user, priv)
        return with_cookie(web.json_response({"ok": True, "key": key, "nid": n.nid}), tok)

    async def leave(req):
        b = await req.json()
        nid = b.get("nid")
        lgs = login_of(req)
        n = agent.nets.get(nid or "")
        if not n:
            return err("Rete sconosciuta")
        if not (n.reg.is_admin((lgs.get(nid) or {}).get("user", "")) or agent.is_any_admin(lgs)):
            return err("Serve un amministratore")
        await agent.leave_network(nid, lgs.get(nid))
        return web.json_response({"ok": True})

    async def close_sessions(req):
        b = await req.json() if req.can_read_body else {}
        await agent.close_sessions(b.get("sid"))
        return web.json_response({"ok": True})

    async def handover(req):
        import hmac
        if req.headers.get("Origin") or not hmac.compare_digest(req.headers.get("X-RD-Token", ""), agent.local_token):
            return web.Response(status=403, text="non permesso")
        log.info("handover richiesto: chiudo l'agente locale")
        asyncio.get_running_loop().call_later(0.3, on_quit)
        return web.json_response({"ok": True})

    # ------------------------------------------------------------------ utente loggato
    async def state(req):
        lgs = need_login(req)
        now = time.time()
        machines, admin_nets = [], {}
        for nid, lg in lgs.items():
            n = agent.nets[nid]
            reg = n.reg
            for mid, mm in reg.machines().items():
                if mid == cfg["id"]:
                    continue
                r = reg.rights(lg["user"], mid)
                if not r:
                    continue
                p = n.machines.get(mid)
                on = bool(p and now - p["last_seen"] < 150)
                machines.append({"nid": nid, "net": n.name, "id": mid,
                                 "name": (p or mm).get("name") or mm.get("name"), "online": on,
                                 "os": (p or {}).get("os", ""), "user": (p or {}).get("user", ""),
                                 "service": (p or {}).get("service"), "sessions": (p or {}).get("sessions"),
                                 "accept": (p or {}).get("accept", True), "rights": sorted(r),
                                 "last_seen": int(p["last_seen"]) if p else 0})
            if reg.is_admin(lg["user"]):
                admin_nets[nid] = {
                    "name": n.name, "v": reg.version, "key": n.entry["key"],
                    "users": {u: {"name": x.get("name"), "admin": bool(x.get("admin")), "perms": x.get("perms", {})}
                              for u, x in reg.users().items()},
                    "machines": {mid: {"name": (n.machines.get(mid) or x).get("name") or x.get("name"),
                                       "online": bool(n.machines.get(mid) and
                                                      now - n.machines[mid]["last_seen"] < 150)}
                                 for mid, x in reg.machines().items()},
                }
        machines.sort(key=lambda x: (not x["online"], x["net"].lower(), (x["name"] or "").lower()))
        return web.json_response({
            "machines": machines,
            "admin_nets": admin_nets,
            "settings": {k: cfg[k] for k in MACHINE_SETTINGS},
            "incoming_default": agent.incoming_dir(),
            "autostart": bool(W.autostart_get()) if WIN else False,
            "ice": agent.ice_for_browser(),
            "admin": agent.is_any_admin(lgs),
        })

    async def connect(req):
        b = await req.json()
        n, lg = need_net(req, b.get("nid"))
        to = str(b["to"]).replace(" ", "")
        mode = b.get("mode", "control")
        if mode not in n.reg.rights(lg["user"], to):
            return err("Non hai il permesso per questa operazione su questa macchina")
        try:
            sdp = await n.connect(to, b["sdp"], mode, lg["user"], lg["priv"])
            return web.json_response({"sdp": sdp})
        except Exception as e:
            return err(e)

    async def clip_get(req):
        need_login(req)
        text = await asyncio.get_running_loop().run_in_executor(None, agent.clipboard.get)
        return web.json_response({"text": text})

    async def clip_set(req):
        need_login(req)
        b = await req.json()
        await asyncio.get_running_loop().run_in_executor(None, agent.clipboard.set, str(b.get("text", "")))
        return web.json_response({"ok": True})

    # ------------------------------------------------------------------ amministratore
    async def settings(req):
        need_local_admin(req)
        b = await req.json()
        upd = {}
        for k, v in b.items():
            if k not in MACHINE_SETTINGS:
                continue
            if k in ("accept_incoming", "ask_confirm", "allow_control", "allow_files", "allow_clipboard"):
                upd[k] = bool(v)
            else:
                upd[k] = str(v or "").strip()[:500]
        if "signal" in upd and not re.match(r"^https?://[^\s/]+", upd["signal"]):
            return err("Server di segnalazione non valido (deve iniziare con http:// o https://)")
        if "name" in upd and not upd["name"]:
            return err("Il nome del PC non puo' essere vuoto")
        old_name, old_signal = cfg["name"], cfg["signal"]
        cfg.update(**upd)
        if cfg["signal"] != old_signal:   # tutte le reti si spostano sul nuovo server
            for n in agent.nets.values():
                n.restart()
        if cfg["name"] != old_name:
            for n in agent.nets.values():
                if n.state == "online":
                    asyncio.ensure_future(n._safe_presence())
        return web.json_response({"ok": True})

    async def autostart(req):
        need_local_admin(req)
        b = await req.json()
        if not WIN:
            return err("solo Windows")
        W.autostart_set(svc.launch_command("--minimized") if b.get("on") else None)
        return web.json_response({"ok": True})

    async def service(req):
        need_local_admin(req)
        b = await req.json()
        if not WIN:
            return err("La modalita' servizio e' disponibile solo su Windows")
        if agent.service_mode:
            return err("Il servizio si rimuove dal menu dell'icona di RemoteDesk (tasto destro > Rimuovi servizio): "
                       "Windows chiedera' le credenziali di amministratore")
        ok = svc.elevate("--install-service" if b.get("action") == "install" else "--uninstall-service",
                         user_data=agent.data_dir)
        return web.json_response({"ok": True} if ok else {"error": "Elevazione annullata o non riuscita"})

    async def user_save(req):
        b = await req.json()
        n, lg = need_net(req, b.get("nid"), admin=True)
        u = auth.norm_user(str(b.get("user", "")))
        if not u or not all(c.isalnum() or c in "._-@" for c in u):
            return err("Nome utente non valido (lettere, numeri, . _ - @)")
        exists = u in n.reg.users()
        pw = str(b.get("password") or "")
        if pw and len(pw) < 10:
            return err("La password deve avere almeno 10 caratteri")
        if not exists and not pw:
            return err("Imposta una password per il nuovo utente")
        perms = {}
        for mid, rights in (b.get("perms") or {}).items():
            r = [x for x in rights if x in auth.RIGHTS]
            if r:
                perms[str(mid)] = r
        admin = bool(b.get("admin"))
        if u == lg["user"] and not admin:
            return err("Non puoi togliere i diritti di amministratore a te stesso")
        pub = auth.pub_of(await n.derive(u, pw)) if pw else None
        if not exists and pw and len(u) > 64:
            return err("Nome utente troppo lungo")

        def mut(doc):
            x = doc["users"].get(u, {})
            x.update({"name": str(b.get("name") or u)[:80], "admin": admin, "perms": perms})
            if pub:
                x["pub"] = pub
            doc["users"][u] = x
        new_priv = await n.derive(u, pw) if (pw and u == lg["user"]) else None
        try:
            await n.admin_update(lg, mut)
        except Exception as e:
            return err(e)
        if new_priv:   # la mia password e' cambiata: il login prosegue con la nuova chiave
            agent.add_login(req.cookies.get(COOKIE), n.nid, u, new_priv)
        return web.json_response({"ok": True})

    async def user_delete(req):
        b = await req.json()
        n, lg = need_net(req, b.get("nid"), admin=True)
        u = auth.norm_user(str(b.get("user", "")))
        if u == lg["user"]:
            return err("Non puoi eliminare te stesso")
        await n.admin_update(lg, lambda doc: doc["users"].pop(u, None))
        return web.json_response({"ok": True})

    async def machine_delete(req):
        b = await req.json()
        n, lg = need_net(req, b.get("nid"), admin=True)
        mid = str(b.get("id", ""))
        if mid == cfg["id"]:
            return err("Non puoi rimuovere la macchina su cui stai lavorando")

        def mut(doc):
            doc["machines"].pop(mid, None)
            for x in doc["users"].values():
                x.get("perms", {}).pop(mid, None)
        await n.admin_update(lg, mut)
        return web.json_response({"ok": True})

    # ------------------------------------------------------------------ chat (lato PC assistito: pubblica)
    async def chat_state(_):
        return web.json_response({
            "me": agent.logged_user() or "Utente",
            "sessions": [{"sid": s.sid, "name": s.display_user(), "peer_name": s.peer_name}
                         for s in agent.sessions.values() if s.connected and s.mode != "files"],
            "messages": agent.chat[-100:], "unread": agent.chat_unread(),
            "window": time.time() - agent.chat_seen < 5,
        })

    async def chat_send(req):
        b = await req.json()
        text = str(b.get("text", "")).strip()[:4000]
        if not text:
            return err("messaggio vuoto")
        try:
            agent.chat_send_local(text, b.get("sid"))
        except Exception as e:
            return err(e)
        return web.json_response({"ok": True})

    async def chat_seen(req):
        b = await req.json() if req.can_read_body else {}
        agent.chat_seen = time.time()
        if b.get("read"):
            agent.chat_read = agent.chat_seq
        return web.json_response({"ok": True})

    # ------------------------------------------------------------------ registro accessi (admin)
    async def audit_q(req):
        b = await req.json()
        n, lg = need_net(req, b.get("nid"), admin=True)
        since = int(b.get("since") or time.time() - 7 * 86400)
        until = int(b.get("until") or time.time() + 60)
        try:
            res = await agent.audit_query(n, lg, since, until)
        except Exception as e:
            return err(e)
        machines = {mid: (n.machines.get(mid) or m).get("name") or m.get("name")
                    for mid, m in n.reg.machines().items()}
        return web.json_response({"results": res, "machines": machines})

    r = app.router
    r.add_get("/chat", page("chat.html"))
    r.add_get("/api/chat", chat_state)
    r.add_post("/api/chat/send", chat_send)
    r.add_post("/api/chat/seen", chat_seen)
    r.add_post("/api/audit", audit_q)
    r.add_get("/", page("console.html"))
    r.add_get("/session", page("session.html"))
    r.add_static("/web/", WEB_DIR)
    r.add_get("/api/ping", ping)
    r.add_get("/api/public", public)
    r.add_post("/api/login", login)
    r.add_post("/api/logout", logout)
    r.add_post("/api/setup", setup)
    r.add_post("/api/networks/leave", leave)
    r.add_post("/api/sessions/close", close_sessions)
    r.add_post("/api/handover", handover)
    r.add_post("/api/quit", handover)
    r.add_get("/api/state", state)
    r.add_post("/api/connect", connect)
    r.add_get("/api/clip", clip_get)
    r.add_post("/api/clip", clip_set)
    r.add_post("/api/settings", settings)
    r.add_post("/api/autostart", autostart)
    r.add_post("/api/service", service)
    r.add_post("/api/users/save", user_save)
    r.add_post("/api/users/delete", user_delete)
    r.add_post("/api/machines/delete", machine_delete)
    return app
