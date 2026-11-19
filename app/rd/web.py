"""Server HTTP locale (solo 127.0.0.1): console, finestre di sessione e API.

Il launcher verifica l'agente, quindi il browser invia la prova locale tramite header.
Le funzioni di controllo richiedono anche l'accesso alla rete selezionata."""
import asyncio
import base64
import hashlib
import logging
import re
import os
import sys
import time

from aiohttp import web

from . import auth
from . import service as svc
from .agent import service_marker
from .common import INSTALL_DIR, ROOT_DIR, VERSION, WEB_DIR, WIN, fmt_id, os_label, service_installed

if WIN:
    from . import winapi as W

log = logging.getLogger("rd.web")
MACHINE_SETTINGS = {"name", "accept_incoming", "ask_confirm", "allow_control", "allow_files", "allow_clipboard",
                    "allow_inventory", "allow_power", "allow_local_block", "allow_sas", "on_air",
                    "signal", "stun", "turn_url", "turn_user", "turn_pass", "turn_secret", "incoming_dir", "update_url", "auto_update"}
BOOLEAN_SETTINGS = {"accept_incoming", "ask_confirm", "allow_control", "allow_files", "allow_clipboard",
                    "allow_inventory", "allow_power", "allow_local_block", "allow_sas", "on_air", "auto_update"}
LOGIN_HEADER = "X-RD-Login"


def make_app(agent, port, on_quit):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    cfg = agent.cfg
    from .local_access import LocalAccess, NATIVE_HEADER
    access = LocalAccess(agent.local_token, port, agent.service_mode)
    from pathlib import Path
    scripts = set()
    for page_file in Path(WEB_DIR).glob("*.html"):
        source = page_file.read_text(encoding="utf-8")
        for script in re.findall(r"<script>(.*?)</script>", source, re.DOTALL | re.IGNORECASE):
            digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
            scripts.add("'sha256-" + digest + "'")
    script_policy = "script-src 'self' " + " ".join(sorted(scripts))

    @web.middleware
    async def guard(req, handler):
        # protezione da DNS-rebinding e da richieste di siti esterni
        if req.host not in allowed_hosts:
            return web.Response(status=403, text="host non permesso")
        origin = req.headers.get("Origin")
        if origin and origin not in allowed_origins:
            return web.Response(status=403, text="origine non permessa")
        if req.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            return web.Response(status=403, text="richiesta cross-site")
        if req.path.startswith("/api/") and req.path not in (
                "/api/ping", "/api/local/challenge", "/api/local/claim"):
            req["local_role"] = access.authenticate(req)
            if req["local_role"] not in ("owner", "desktop"):
                return web.json_response({"error": "Apri RemoteDesk dall'icona sul PC"}, status=403,
                                         headers={"Cache-Control": "no-store"})
        try:
            resp = await handler(req)
        except (ValueError, TypeError, KeyError) as exc:
            log.debug("Richiesta non valida (%s)", type(exc).__name__)
            resp = web.json_response({"error": "Richiesta non valida"}, status=400)
        except web.HTTPException as e:
            resp = e
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; " + script_policy + "; base-uri 'none'; object-src 'none'; "
                                                   "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                                                   "media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    app = web.Application(middlewares=[guard], client_max_size=8 * 1024 * 1024)

    def login_of(req):
        return agent.get_login(req.headers.get(LOGIN_HEADER))

    def machine_owner(req):
        return req.get("local_role") == "owner"

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
        if req.method == "POST":
            agent.get_login(req.headers.get(LOGIN_HEADER), touch=nid)
        return n, lg

    def need_local_admin(req):
        """Impostazioni di QUESTO PC: libere finche' non e' in nessuna rete, poi admin di una sua rete."""
        if not machine_owner(req):
            raise web.HTTPForbidden(text='{"error":"Serve il proprietario locale"}', content_type="application/json")
        if not agent.nets:
            return
        if not agent.is_any_admin(login_of(req)):
            raise web.HTTPForbidden(text='{"error":"serve un amministratore di una delle reti di questo PC"}',
                                    content_type="application/json")

    def err(e):
        return web.json_response({"error": str(e)})

    def with_login(resp, tok):
        resp.headers[LOGIN_HEADER] = tok
        return resp

    def page(name):
        async def h(_):
            return web.FileResponse(os.path.join(WEB_DIR, name))
        return h

    def update_target():
        # Stessa scelta di Updater._install: conta il processo che risponde alla console.
        if agent.service_mode:
            return {"mode": "service", "path": INSTALL_DIR}
        return {"mode": "portable" if getattr(agent, "portable", False) else "user", "path": ROOT_DIR}

    def service_setup():
        if not WIN or agent.service_mode:
            return None
        return {"path": INSTALL_DIR, "registered": service_installed(),
                "ready": svc.installation_ready()}

    def local_update_status():
        return {"update_target": update_target(), "local_update": agent.updater.status(),
                "service_setup": service_setup()}

    async def update_local(req):
        need_local_admin(req)
        return web.json_response(local_update_status())

    # ------------------------------------------------------------------ pubblico
    async def public(req):
        lgs = login_of(req)
        portable = getattr(agent, "portable", False)
        update = agent.updater.status()
        nets = []
        for n in agent.nets.values():
            lg = lgs.get(n.nid)
            nets.append({"nid": n.nid, "name": n.name, "state": n.state, "conflict": n.conflict,
                         "limited": n.limited, "quota": n.quota, "relays": n.relay_status(),
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
            "can_add_network": machine_owner(req) and (not agent.nets or agent.is_any_admin(lgs)),
            "cloned": agent.cloned,
            "sessions": [{"sid": s.sid, "peer": s.peer, "peer_name": s.peer_name, "user": s.user, "mode": s.mode,
                          "net": s.net.name, "since": int(s.started), "connected": s.connected}
                         for s in agent.sessions.values()],
            "events": agent.events[-30:],
            "service": {"installed": not portable and service_installed(agent.data_dir),
                        "active": not portable and agent.service_mode, "supported": WIN and not portable},
            "platform": sys.platform,
            "update": {key: update.get(key) for key in ("current", "latest", "available", "supported")},
        })

    async def ping(_):
        return web.json_response({"app": "remotedesk"})

    async def login(req):
        b = await req.json()
        try:
            tok = await agent.login(req.headers.get(LOGIN_HEADER), b.get("nid"), str(b.get("user", "")),
                                    str(b.get("password", "")))
        except Exception as e:
            return err(e)
        return with_login(web.json_response({"ok": True}), tok)

    async def logout(req):
        b = await req.json() if req.can_read_body else {}
        agent.logout(req.headers.get(LOGIN_HEADER), b.get("nid"))
        resp = web.json_response({"ok": True})
        if not b.get("nid"):
            resp.headers[LOGIN_HEADER] = ""
        return resp

    async def setup(req):
        """Crea una rete nuova o entra in una esistente. Se il PC e' gia' in qualche rete serve
        il login di un amministratore di una di quelle reti (nessuno puo' 'regalare' il PC a
        un'altra rete di nascosto)."""
        need_local_admin(req)
        b = await req.json()
        user, pw = str(b.get("user", "")).strip(), str(b.get("password", ""))
        if not 10 <= len(pw) <= 1024 or not 1 <= len(user) <= 64:
            return err("Utente da 1 a 64 caratteri e password da 10 a 1024 caratteri")
        if (not isinstance(b.get("network"), str) or not 1 <= len(b["network"].strip()) <= 80
                or len(str(b.get("key", ""))) > 512 or len(str(b.get("pcname", ""))) > 128):
            return err("Nome rete, chiave o nome PC non valido")
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
        tok = agent.add_login(req.headers.get(LOGIN_HEADER), n.nid, user, priv)
        return with_login(web.json_response({"ok": True, "key": key, "nid": n.nid}), tok)

    async def leave(req):
        b = await req.json()
        nid = b.get("nid")
        need_local_admin(req)
        n, lg = need_net(req, nid, admin=True)
        await agent.leave_network(nid, lg)
        return web.json_response({"ok": True})

    async def close_sessions(req):
        b = await req.json() if req.can_read_body else {}
        await agent.close_sessions(b.get("sid"))
        return web.json_response({"ok": True})

    async def handover(req):
        if req.headers.get("Origin") or NATIVE_HEADER not in req.headers or not machine_owner(req):
            return web.Response(status=403, text="non permesso")
        log.info("handover richiesto: chiudo l'agente locale")
        asyncio.get_running_loop().call_later(0.3, on_quit)
        return web.json_response({"ok": True})

    # ------------------------------------------------------------------ utente loggato
    async def state(req):
        lgs = need_login(req)
        agent.console_seen = time.time()
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
                mine = now - agent.outgoing.get((nid, mid), 0) < 60   # sessione aperta da questo PC
                on = n.is_online(mid) or mine
                machines.append({"nid": nid, "net": n.name, "id": mid,
                                 "name": (p or mm).get("name") or mm.get("name"), "online": on,
                                 "os": (p or {}).get("os", ""), "user": (p or {}).get("user", ""),
                                 "service": (p or {}).get("service"), "sessions": (p or {}).get("sessions"),
                                 "accept": (p or {}).get("accept", True), "rights": sorted(r),
                                 "session_protocol": (p or {}).get("session_protocol"),
                                 "inventory": (p or {}).get("inventory") is True,
                                 "last_seen": int(p["last_seen"]) if p else 0, "my_session": mine,
                                 "ver": (p or {}).get("ver", ""), "admin": reg.is_admin(lg["user"])})
            if reg.is_admin(lg["user"]):
                admin_nets[nid] = {
                    "name": n.name, "v": reg.version,
                    "users": {u: {"name": x.get("name"), "admin": bool(x.get("admin")), "perms": x.get("perms", {})}
                              for u, x in reg.users().items()},
                    "machines": {mid: {"name": (n.machines.get(mid) or x).get("name") or x.get("name"),
                                       "online": n.is_online(mid)}
                                 for mid, x in reg.machines().items()},
                }
        machines.sort(key=lambda x: (not x["online"], x["net"].lower(), (x["name"] or "").lower()))
        admin = agent.is_any_admin(lgs)
        can_configure = machine_owner(req) and (not agent.nets or admin)
        return web.json_response({
            "machines": machines,
            "admin_nets": admin_nets,
            "can_configure": can_configure,
            **(local_update_status() if can_configure else {}),
            "settings": {k: cfg[k] for k in MACHINE_SETTINGS - {"turn_pass", "turn_secret"}} if can_configure else {},
            "turn_secret_set": can_configure and bool(cfg["turn_secret"]),
            "turn_password_set": can_configure and bool(cfg["turn_pass"]),
            "incoming_default": agent.incoming_dir() if can_configure else "",
            "autostart": bool(W.autostart_get()) if can_configure and WIN and not getattr(agent, "portable", False) else False,
            "admin": admin,
        })

    next_key_check = {}

    async def network_key(req):
        b = await req.json()
        n, lg = need_net(req, b.get("nid"), admin=True)
        password = b.get("password")
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            return err("Conferma la password del tuo utente di rete")
        now = time.monotonic()
        if now < next_key_check.get(n.nid, 0):
            return err("Attendi qualche secondo prima di riprovare")
        next_key_check[n.nid] = now + 3
        private = await n.derive(lg["user"], password)
        current, identity = need_net(req, n.nid, admin=True)
        user = current.reg.user(identity["user"])
        if current is not n or identity["user"] != lg["user"] or not user or auth.pub_of(private) != user["pub"]:
            return err("Verifica della password non riuscita")
        return web.json_response({"key": n.entry["key"]})

    def session_target(req, b):
        n, lg = need_net(req, b.get("nid"))
        to = str(b.get("to", "")).replace(" ", "")
        machines = n.reg.machines()
        if (n.conflict or getattr(n, "leaving", False) or
                machines.get(cfg["id"], {}).get("pub") != agent.mpub):
            raise web.HTTPConflict(text='{"error":"Identità della rete non verificata"}', content_type="application/json")
        mode = b.get("mode", "control")
        right = auth.MODE_RIGHTS.get(mode) if isinstance(mode, str) else None
        if to not in n.reg.machines() or to == cfg["id"] or right not in n.reg.rights(lg["user"], to):
            raise web.HTTPForbidden(text='{"error":"Operazione non autorizzata su questa macchina"}',
                                    content_type="application/json")
        if "expected_pub" in b and b["expected_pub"] != machines[to].get("pub"):
            raise web.HTTPConflict(text='{"error":"Identità del PC cambiata. Verifica il dispositivo nella rubrica."}',
                                   content_type="application/json")
        peer = n.machines.get(to) or {}
        if peer.get("pub") != machines[to].get("pub"):
            raise web.HTTPConflict(text='{"error":"In attesa della presenza firmata del PC"}', content_type="application/json")
        if not n.is_online(to):
            raise web.HTTPConflict(text='{"code":"peer_offline","error":"PC offline. Aggiorna la rubrica e riprova."}',
                                   content_type="application/json")
        if peer.get("session_protocol") != auth.SESSION_PROTOCOL:
            raise web.HTTPConflict(text='{"error":"Aggiorna RemoteDesk sul PC remoto per aprire una sessione."}',
                                   content_type="application/json")
        if mode == "manage" and peer.get("inventory") is not True:
            raise web.HTTPForbidden(text='{"error":"Inventario non abilitato sul PC Windows remoto"}',
                                    content_type="application/json")
        return n, lg, to, mode

    async def session_ice(req):
        net, _, target, _ = session_target(req, await req.json())
        peer = net.machines[target]
        result = {"ice": agent.ice_for_browser()}
        stamp = peer.get("signed_at")
        if type(stamp) is int and 0 < stamp < 2**53:
            result.update(peer_presence=stamp, peer_pub=peer["pub"])
            version = peer.get("ver")
            if isinstance(version, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", version):
                result["peer_version"] = version
        return web.json_response(result)

    async def connect(req):
        b = await req.json()
        n, lg, to, mode = session_target(req, b)
        pub = n.reg.machines()[to].get("pub")
        try:
            sdp, remote_sid = await n.connect(to, b["sdp"], mode, lg["user"], lg["priv"])
        except Exception as e:
            return err(e)
        current = agent.get_login(req.headers.get(LOGIN_HEADER)).get(n.nid)
        machines = n.reg.machines()
        if (agent.nets.get(n.nid) is not n or current is not lg or n.conflict or getattr(n, "leaving", False) or
                machines.get(cfg["id"], {}).get("pub") != agent.mpub or machines.get(to, {}).get("pub") != pub
                or auth.MODE_RIGHTS[mode] not in n.reg.rights(lg["user"], to)):
            return web.json_response({"error": "Autorizzazione revocata"}, status=403)
        return web.json_response({"sdp": sdp, "lease": agent.issue_lease(n, lg, to, mode, remote_sid)})

    async def update_check(req):
        need_local_admin(req)
        await agent.updater.check()
        return web.json_response(agent.updater.status())

    async def update_install(req):
        need_local_admin(req)
        request = await req.json() if req.can_read_body else {}
        if "expected_target" in request and request["expected_target"] != update_target():
            return web.json_response({"error": "La copia attiva è cambiata. Aggiorna la console e verifica di nuovo la cartella."},
                                     status=409)
        if not agent.updater.available():
            await agent.updater.check()
        if not agent.updater.available():
            return err(agent.updater.error or "Nessun aggiornamento disponibile")
        user = ", ".join(sorted({x["user"] for x in login_of(req).values()})) or "console"

        async def go():
            try:
                await agent.updater.install(f"{user} (da questo PC)")
            except Exception as e:
                log.warning("aggiornamento: %s", e)
        asyncio.ensure_future(go())
        return web.json_response({"ok": True})

    async def machine_update(req):
        b = await req.json()
        n, lg = need_net(req, b.get("nid"), admin=True)
        mid = str(b.get("id", ""))
        if mid == cfg["id"]:
            return await update_install(req)
        try:
            await n.send_update(mid, lg)
        except Exception as e:
            return err(e)
        return web.json_response({"ok": True})

    async def refresh(req):
        lgs = need_login(req)
        sent = [await agent.nets[nid].refresh() for nid in lgs if nid in agent.nets]
        return web.json_response({"ok": True, "sent": any(sent)})

    def lease_for(req, body, clipboard=False):
        lease = agent.check_lease(req.headers.get(LOGIN_HEADER), body.get("lease"))
        if not lease or (clipboard and (lease["mode"] != "control" or not cfg["allow_clipboard"])):
            raise web.HTTPForbidden(text='{"error":"Sessione scaduta o operazione non consentita"}',
                                    content_type="application/json")
        return lease

    async def session_lease(req):
        lease = lease_for(req, await req.json())
        agent.outgoing[(lease["net"].nid, lease["peer"])] = time.time()
        grant = lease["grant"]
        proof = lease["net"].lease_proof(lease["sid"], lease["peer"], lease["mode"], grant["user"], grant["priv"])
        return web.json_response({"ok": True, "proof": proof})

    async def clip_get(req):
        body = await req.json()
        lease_for(req, body, clipboard=True)
        text = await asyncio.to_thread(agent.clipboard.get)
        lease_for(req, body, clipboard=True)
        if not isinstance(text, str) or len(text.encode("utf-8")) > 60000:
            return err("Gli appunti devono contenere al massimo 60 KB di testo")
        return web.json_response({"text": text})

    async def clip_set(req):
        body = await req.json()
        lease_for(req, body, clipboard=True)
        text = body.get("text")
        if not isinstance(text, str) or len(text.encode("utf-8")) > 60000:
            return err("Testo non valido o troppo grande")
        agent.clipboard.set(text)
        return web.json_response({"ok": True})

    # ------------------------------------------------------------------ amministratore
    async def settings(req):
        need_local_admin(req)
        b = await req.json()
        upd = {}
        for k, v in b.items():
            if k not in MACHINE_SETTINGS:
                continue
            if k in ("turn_url", "stun"):
                from .ice import validate_stun, validate_turn_url
                try:
                    upd[k] = validate_stun(v) if k == "stun" else validate_turn_url(v)
                except ValueError as exc:
                    return err(exc)
            elif k in ("turn_secret", "turn_pass", "turn_user"):
                if (not isinstance(v, str) or len(v.encode("utf8")) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in v)
                        or (k == "turn_secret" and v and len(v.encode("utf8")) < 32)):
                    return err("Credenziali TURN non valide. Il segreto coturn richiede almeno 32 byte")
                upd[k] = v
            elif k in BOOLEAN_SETTINGS:
                if type(v) is not bool:
                    return err("Il valore deve essere vero o falso")
                upd[k] = v
            else:
                upd[k] = str(v or "").strip()[:500]
        if "signal" in upd:
            from .relays import parse_signal
            lst = parse_signal(upd["signal"])
            if not lst:
                return err("Indica un server HTTPS o WSS per ntfy, oppure MQTTS per MQTT. "
                           "HTTP e MQTT richiedono un indirizzo IP di loopback.")
            upd["signal"] = ", ".join(lst)
        if upd.get("update_url") and not upd["update_url"].startswith("https://"):
            return err("L'indirizzo degli aggiornamenti deve iniziare con https://")
        if "name" in upd and not upd["name"]:
            return err("Il nome del PC non puo' essere vuoto")
        old_name, old_signal = cfg["name"], cfg["signal"]
        cfg.update(**upd)
        for n in agent.nets.values():
            agent.registry_changed(n)
        if cfg["signal"] != old_signal:   # tutte le reti si spostano sul nuovo server
            for n in agent.nets.values():
                n.restart()
        if cfg["name"] != old_name or "allow_inventory" in upd or "accept_incoming" in upd:
            for n in agent.nets.values():
                if n.state == "online":
                    asyncio.ensure_future(n._safe_presence())
        return web.json_response({"ok": True})

    async def autostart(req):
        need_local_admin(req)
        if getattr(agent, "portable", False):
            return web.json_response({"error": "Avvio automatico di Windows non disponibile per questa copia portabile."}, status=403)
        b = await req.json()
        if not WIN:
            return err("solo Windows")
        W.autostart_set(svc.launch_command("--minimized") if b.get("on") else None)
        return web.json_response({"ok": True})

    service_request = asyncio.Lock()

    async def service(req):
        need_local_admin(req)
        body = await req.json()
        action = body.get("action") if isinstance(body, dict) else None
        if getattr(agent, "portable", False) and action != "install":
            return web.json_response({"error": "Gestisci il servizio già registrato dalla sua icona."}, status=403)
        if not WIN:
            return err("La modalità servizio è disponibile solo su Windows")
        if agent.service_mode:
            return err("Per rimuovere il servizio, usa il menu dell'icona RemoteDesk.")
        if action not in ("install", "uninstall"):
            return web.json_response({"error": "Operazione servizio non valida"}, status=400)
        if service_request.locked():
            return web.json_response({"error": "Una richiesta per il servizio è già in corso."}, status=409)
        async with service_request:
            if action == "install":
                setup = service_setup()
                if setup["registered"]:
                    return web.json_response({"error": "Il servizio è già registrato. Apri la console dalla sua icona."},
                                             status=409)
                if not setup["ready"]:
                    return web.json_response({"error": f"Estrai il pacchetto ufficiale verificato di RemoteDesk {VERSION} in " + setup["path"]},
                                             status=409)
            flag = "--install-service" if action == "install" else "--uninstall-service"
            ok = await asyncio.to_thread(svc.elevate, flag)
        return web.json_response({"ok": True} if ok else {"error": "Elevazione annullata o non riuscita"})

    async def user_save(req):
        b = await req.json()
        n, lg = need_net(req, b.get("nid"), admin=True)
        u = auth.norm_user(str(b.get("user", "")))
        if not u or not all(c.isalnum() or c in "._-@" for c in u):
            return err("Nome utente non valido (lettere, numeri, . _ - @)")
        exists = u in n.reg.users()
        pw = str(b.get("password") or "")
        if pw and not 10 <= len(pw) <= 1024:
            return err("La password deve contenere da 10 a 1024 caratteri")
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
            token = agent.add_login(req.headers.get(LOGIN_HEADER), n.nid, u, new_priv)
            return with_login(web.json_response({"ok": True}), token)
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
    async def chat_state(req):
        sid = req.query.get("sid", "")
        active = {s.sid: s for s in agent.sessions.values() if s.connected and s.mode in ("control", "view")
                  and s.lease_active() and s.refresh_authorization()}
        return web.json_response({
            "sessions": [{"sid": s.sid, "name": s.display_user(), "peer_name": s.peer_name}
                         for s in active.values()],
            "messages": [m for m in agent.chat if m["sid"] == sid][-100:] if sid in active else [],
            "unread": agent.chat_unread(), "latest": agent.chat_seq, "window": time.time() - agent.chat_seen < 5,
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
        sid = b.get("sid")
        if b.get("read") and isinstance(sid, str) and sid in agent.sessions:
            agent.chat_read[sid] = agent.chat_seq
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
        current, grant = need_net(req, n.nid, admin=True)
        if current is not n or grant is not lg:
            raise web.HTTPForbidden(text='{"error":"Accesso al registro revocato"}', content_type="application/json")
        machines = {mid: (n.machines.get(mid) or m).get("name") or m.get("name")
                    for mid, m in n.reg.machines().items()}
        return web.json_response({"results": res, "machines": machines})

    app.on_cleanup.append(access.cleanup)
    r = app.router
    r.add_get("/local/start", access.landing)
    r.add_get("/api/local/challenge", access.challenge)
    r.add_post("/api/local/claim", access.claim)
    r.add_get("/chat", page("chat.html"))
    r.add_get("/api/chat", chat_state)
    r.add_post("/api/chat/send", chat_send)
    r.add_post("/api/chat/seen", chat_seen)
    r.add_post("/api/audit", audit_q)
    r.add_get("/", page("console.html"))
    r.add_get("/session", page("session.html"))
    r.add_get("/manage", page("manage.html"))
    r.add_static("/web/", WEB_DIR)
    r.add_get("/api/ping", ping)
    r.add_get("/api/public", public)
    r.add_post("/api/login", login)
    r.add_post("/api/logout", logout)
    r.add_post("/api/setup", setup)
    r.add_post("/api/networks/leave", leave)
    r.add_post("/api/networks/key", network_key)
    r.add_post("/api/sessions/close", close_sessions)
    r.add_post("/api/handover", handover)
    r.add_post("/api/quit", handover)
    r.add_get("/api/state", state)
    r.add_post("/api/connect", connect)
    r.add_post("/api/session/ice", session_ice)
    r.add_post("/api/refresh", refresh)
    r.add_post("/api/update/check", update_check)
    r.add_get("/api/update/local", update_local)
    r.add_post("/api/update/install", update_install)
    r.add_post("/api/machines/update", machine_update)
    r.add_post("/api/session/lease", session_lease)
    r.add_post("/api/clip/read", clip_get)
    r.add_post("/api/clip", clip_set)
    r.add_post("/api/settings", settings)
    r.add_post("/api/autostart", autostart)
    r.add_post("/api/service", service)
    r.add_post("/api/users/save", user_save)
    r.add_post("/api/users/delete", user_delete)
    r.add_post("/api/machines/delete", machine_delete)
    return app
