"""La "rete" RemoteDesk: presenza delle macchine e scambio offerte/risposte WebRTC.

Nessun server proprio: i messaggi passano da un topic ntfy (pubblico, configurabile)
ma sono cifrati AES-256-GCM con una chiave derivata da nome rete + password.
Chi non conosce la password non vede ne' le macchine ne' le connessioni."""
import asyncio
import json
import re
import logging
import random
import secrets
import time

from aiohttp import ClientSession, ClientTimeout

from . import auth, session_policy
from .relays import DEFAULT_SIGNAL, make_relay, parse_signal
from .common import VERSION, WIN, NetKey, current_user, os_label

log = logging.getLogger("rd.net")
PRESENCE_EVERY = 1800     # annuncio di sicurezza ogni 30 minuti; per il resto si annuncia solo quando serve
CONSOLE_HELLO = 600       # con una console aperta, ogni 10 minuti si chiede alle macchine di ripresentarsi
OFFLINE_AFTER = 900       # offline se nessun segno di vita da 15 minuti (lo spegnimento regolare e' immediato)


def net_id(name, key):
    return NetKey(name, key).topic[4:16]


class Network:
    """Una rete a cui la macchina partecipa. Ogni rete ha chiave, registro (utenti,
    permessi, macchine) e canale di segnalazione propri: le reti non si vedono tra loro."""

    def __init__(self, agent, entry):
        self.agent = agent
        self.cfg = agent.cfg
        self.entry = entry                 # {nid, name, key, registry}
        self.nid = entry["nid"]
        self.name = entry["name"]
        self.reg = auth.Registry.from_cache(entry.get("registry"))
        self.key = None
        self.task = None
        self.state = "ferma"
        self.machines = {}         # id -> info + last_seen (tempo locale)
        self.pending = {}          # sid -> Future(risposta)
        self.offset = 0.0          # orologio server ntfy - orologio locale
        self.session = None
        self.seen_sids = {}        # anti-replay
        self.db_asked = {}         # versione -> quando l'ho chiesta
        self.db_waiters = []       # Future in attesa di un registro (ingresso in rete)
        self.audit_waiters = {}    # rid -> lista risposte registro accessi
        self.audit_task = None
        self.conflict = entry.get("conflict") is True
        self.last_presence = 0    # ultimo annuncio inviato
        self.last_hello = 0       # ultima richiesta di ripresentarsi
        self.limited = False      # il server ha rifiutato per troppi messaggi
        self.relays = []          # server di segnalazione usati in parallelo
        self.recent = {}          # impronte dei messaggi gia' elaborati (arrivano da piu' server)
        self.announced = False

    # ------------------------------------------------------------------ ciclo di vita
    def restart(self):
        self.stop()
        self.key = NetKey(self.entry["name"], self.entry["key"])
        self.relays = [make_relay(u, self.key.topic) for u in parse_signal(self.cfg["signal"] or DEFAULT_SIGNAL)]
        if not self.relays:
            self.state = "configurazione relay non valida"
            return
        self.announced = False
        self.task = asyncio.ensure_future(self._main())

    def stop(self):
        for future, *_ in self.pending.values():
            if not future.done():
                future.set_exception(RuntimeError("Connessione di segnalazione terminata"))
        if self.task:
            self.task.cancel()
            self.task = None
        self.machines.clear()
        self.state = "ferma"

    # ------------------------------------------------------------------ registro firmato
    def on_registry(self, doc):
        if self.reg.doc and doc.get("v") == self.reg.version:
            if auth.doc_hash(doc) != auth.doc_hash(self.reg.doc):
                prev = next((d for d in reversed(self.entry.get("history", [])) if isinstance(d, dict)
                             and d.get("v") == self.reg.version - 1 and auth.doc_hash(d) == self.reg.doc["prev"]), None)
                authenticated = (auth.Registry(prev).check_new(doc) if prev else
                                 self.reg.version == 1 and auth.Registry().check_new(
                                     doc, pinned_admin_pub=(self.reg.user(self.reg.doc["signer"]) or {}).get("pub")))
                if authenticated and not self.conflict:
                    self.conflict = True
                    self.entry["conflict"] = True
                    self.agent.registry_changed(self)
                    self.agent.save_networks()
                    self.agent.log_event(f"Rete {self.name}: ricevute due versioni firmate incompatibili del registro")
            return False
        if not self.reg.check_new(doc):
            return False
        self.apply_registry(doc)
        return True

    def apply_registry(self, doc):
        self.reg.doc = doc
        self.entry["registry"] = doc
        hist = [d for d in (self.entry.get("history") or []) if d.get("v", 0) < doc["v"]] + [doc]
        self.entry["history"] = hist[-100:]     # catena recente, per chi deve recuperare versioni
        self.agent.registry_changed(self)
        self.agent.save_networks()
        log.info("[%s] registro aggiornato alla versione %s (firmato da %s)", self.name, doc["v"], doc.get("signer"))

    async def publish_registry(self):
        try:
            await self.publish({"type": "db", "docs": [self.reg.doc]})
        except Exception as e:
            log.warning("pubblicazione registro: %s", e)

    async def derive(self, user, password):
        return await asyncio.get_running_loop().run_in_executor(
            None, auth.derive_user_key, self.name, user, password)

    async def admin_update(self, lg, mutate):
        if self.conflict:
            raise RuntimeError("Riconciliare il conflitto nel registro prima di modificarlo")
        if not lg or not self.reg.is_admin(lg["user"]):
            raise RuntimeError("Serve un amministratore di questa rete")
        doc = self.reg.signed_update(lg["user"], lg["priv"], mutate)
        if not self.reg.check_new(doc):   # es. password cambiata altrove: la firma non sarebbe accettata
            raise RuntimeError("Le tue credenziali non sono piu' valide su questa rete: rifai il login")
        self.apply_registry(doc)
        await self.publish_registry()

    @property
    def state(self):
        if not self.relays or not self.task:
            return self._state
        if any(r.online for r in self.relays):
            return "online"
        return "offline (riprovo...)"

    @state.setter
    def state(self, v):
        self._state = v

    @property
    def limited(self):
        """Nessun server utilizzabile e almeno uno per quota esaurita: da segnalare all'utente."""
        return bool(self.relays and self.task) and not any(r.online for r in self.relays) and \
            any(r.state == "quota" for r in self.relays)

    @limited.setter
    def limited(self, v):
        pass

    @property
    def quota(self):
        for r in self.relays:
            if getattr(r, "quota", None):
                return r.quota
        return None

    @quota.setter
    def quota(self, v):
        pass

    def relay_status(self):
        return [r.status() for r in self.relays]

    async def _main(self):
        tasks = [asyncio.ensure_future(r.run(self._on_relay_message)) for r in self.relays]
        tasks += [asyncio.ensure_future(self._heartbeat()), asyncio.ensure_future(self._console_hello())]
        try:
            await asyncio.gather(*tasks)
        finally:
            try:
                await asyncio.wait_for(self.publish({"type": "bye"}), 5)
            except BaseException:
                pass
            for t in tasks:
                t.cancel()

    async def _on_relay_message(self, relay, body, server_time):
        import hashlib
        h = hashlib.sha256(body.encode()).hexdigest()[:20]
        now = time.time()
        if h in self.recent:          # stesso messaggio arrivato da un altro server
            return
        self.recent[h] = now
        if len(self.recent) > 3000:
            self.recent.pop(next(iter(self.recent)))
        ev = {"message": body, "time": server_time if isinstance(server_time, int) else int(self.server_now())}
        try:
            await self._on_event(ev)
        except Exception as e:        # un messaggio malformato non ferma nulla
            log.debug("evento scartato: %s", e)

    async def _heartbeat(self):
        while not any(r.online for r in self.relays):
            await asyncio.sleep(1)
        await asyncio.sleep(1)
        await self._safe_publish({"type": "hello"})       # all'avvio: chi c'e' si ripresenta
        await self._safe_publish(self.presence())
        self.announced = True
        while True:
            await asyncio.sleep(PRESENCE_EVERY + random.uniform(-60, 60))
            await self._safe_publish(self.presence())

    async def _console_hello(self):
        """Solo quando qualcuno guarda la console chiedo alle macchine di ripresentarsi."""
        was_active = False
        while True:
            await asyncio.sleep(10)
            active = time.time() - self.agent.console_seen < 30
            if active and (time.time() - self.last_hello > CONSOLE_HELLO or
                           (not was_active and time.time() - self.last_hello > 60)):
                await self.refresh(force=True)
            was_active = active

    def _verified_update(self, m):
        body = {k: m.get(k) for k in ("frm", "to", "user", "ats", "cmd", "rid", "net", "protocol")}
        if (self.conflict or not self.cfg.get("auto_update") or self.cfg.get("on_air")
                or body["cmd"] != "update" or body["net"] != self.nid or body["protocol"] != auth.SESSION_PROTOCOL
                or body["to"] != self.cfg["id"] or type(body["ats"]) is not int or abs(time.time() - body["ats"]) > 120
                or not isinstance(body["rid"], str) or not re.fullmatch(r"[0-9a-f]{24}", body["rid"])
                or not isinstance(body["user"], str) or not self.reg.is_admin(body["user"])):
            return False
        machine = self.reg.machines().get(body["frm"])
        return bool(machine and (self.reg.machines().get(self.cfg["id"]) or {}).get("pub") == self.agent.mpub
                    and auth.verify(machine["pub"], body, m.get("msig", ""))
                    and auth.verify(self.reg.user(body["user"])["pub"], body, m.get("sig", "")))

    async def _run_update(self, m):
        if not self._verified_update(m):
            return
        user = m["user"]
        try:
            await self.agent.updater.install(f"{user} (rete {self.name})", automatic=True)
        except Exception as e:
            log.warning("aggiornamento richiesto da %s non eseguito: %s", user, e)
            self.agent.log_event(f"Aggiornamento richiesto da {user} non eseguito: {e}")

    async def send_update(self, to, lg):
        """Chiede alla macchina 'to' di aggiornarsi (comando firmato dall'amministratore)."""
        if self.conflict or not self.reg.is_admin(lg["user"]):
            raise RuntimeError("Serve un amministratore di questa rete")
        if to not in self.reg.machines() or self.machines.get(to, {}).get("session_protocol") != auth.SESSION_PROTOCOL:
            raise RuntimeError("Serve un dispositivo registrato con protocollo di sessione 2")
        body = {"frm": self.cfg["id"], "to": to, "user": lg["user"], "ats": int(time.time()), "cmd": "update",
                "rid": secrets.token_hex(12), "net": self.nid, "protocol": auth.SESSION_PROTOCOL}
        await self.publish({"type": "updcmd", **body, "sig": auth.sign(lg["priv"], body),
                            "msig": auth.sign(self.agent.mkey, body)})

    async def refresh(self, force=False):
        """Chiede a tutte le macchine della rete di ripresentarsi (al massimo ogni 15 secondi)."""
        if (not force and time.time() - self.last_hello < 15) or self.state != "online":
            return False
        self.last_hello = time.time()
        await self._safe_publish({"type": "hello"})
        return True

    def alive(self, frm):
        """Segno di vita autenticato (risposta firmata ecc.): la macchina e' sicuramente accesa."""
        if frm in self.machines:
            self.machines[frm]["last_seen"] = time.time()
        elif frm in self.reg.machines():
            self.machines[frm] = {"id": frm, "name": self.reg.machines()[frm].get("name"), "os": "", "user": "",
                                  "ver": "", "service": False, "sessions": 0, "accept": True, "dbv": 0,
                                  "last_seen": time.time()}

    def is_online(self, mid):
        p = self.machines.get(mid)
        return bool(p and time.time() - p["last_seen"] < OFFLINE_AFTER)

    def presence(self):
        a = self.agent
        return {"type": "presence", "name": self.cfg["name"], "os": os_label(),
                "user": a.logged_user() or current_user(), "ver": VERSION, "service": a.service_mode,
                "session_protocol": auth.SESSION_PROTOCOL, "inventory": WIN and bool(self.cfg.get("allow_inventory")),
                "sessions": len(a.sessions), "accept": bool(self.cfg["accept_incoming"]),
                "dbv": self.reg.version, "dbh": (auth.doc_hash(self.reg.doc) or "")[:16], "mpub": a.mpub}

    def server_now(self):
        return time.time() + self.offset

    async def publish(self, obj, session=None):
        """Pubblica su tutti i server; basta che uno accetti."""
        if not self.key or not self.relays:
            raise RuntimeError("rete non connessa")
        obj = dict(obj, frm=self.cfg["id"], ts=int(time.time()))
        if obj.get("type") in ("presence", "bye"):
            obj["net"] = self.nid
            obj["msig"] = auth.sign(self.agent.mkey, obj)
        blob = self.key.seal(obj)

        async def one(r):
            t = await r.publish(blob)
            if isinstance(t, int):
                self.offset = t - time.time()
            return True
        res = await asyncio.gather(*(one(r) for r in self.relays), return_exceptions=True)
        if not any(x is True for x in res):
            errs = "; ".join(f"{r.name}: {e}" for r, e in zip(self.relays, res) if e is not True)
            raise RuntimeError(f"nessun server di segnalazione ha accettato il messaggio ({errs})")
        if obj.get("type") == "presence":
            self.last_presence = time.time()

    async def _on_event(self, ev):
        body = ev.get("message", "")
        try:
            m = self.key.unseal(body)
        except Exception:
            return
        if not isinstance(m, dict):
            return
        frm = m.get("frm")
        if not isinstance(frm, str) or not frm or frm == self.cfg["id"]:
            return
        age = self.server_now() - ev.get("time", self.server_now())
        t = m.get("type")
        log.debug("ricevuto %s da %s (eta' %.0fs)", t, frm, age)
        if t in ("presence", "bye"):
            mach = self.reg.machines().get(frm)   # presenza valida solo se firmata da una macchina registrata
            if (not mach or ("net" in m and m["net"] != self.nid) or type(m.get("ts")) is not int
                    or abs(time.time() - m["ts"]) > OFFLINE_AFTER or abs(age) > OFFLINE_AFTER
                    or m["ts"] < self.machines.get(frm, {}).get("signed_at", 0)
                    or not auth.verify(mach["pub"], {k: v for k, v in m.items() if k != "msig"}, m.get("msig", ""))):
                return
        if t == "presence":
            if age > OFFLINE_AFTER:
                return

            def txt(v, n=80):
                return str(v or "")[:n]
            try:
                sessions = max(0, int(m.get("sessions") or 0))
            except (TypeError, ValueError):
                sessions = 0
            dbv_raw = m.get("dbv")
            info = {"name": txt(m.get("name")), "os": txt(m.get("os")), "user": txt(m.get("user")),
                    "ver": txt(m.get("ver"), 20), "service": bool(m.get("service")), "sessions": sessions,
                    "signed_at": m["ts"], "pub": mach["pub"],
                    "session_protocol": m.get("session_protocol") if m.get("net") == self.nid and type(m.get("session_protocol")) is int else 0,
                    "inventory": m.get("net") == self.nid and m.get("inventory") is True,
                    "accept": bool(m.get("accept", True)), "dbv": dbv_raw if isinstance(dbv_raw, int) else 0}
            info["id"] = frm
            info["last_seen"] = time.time() - max(age, 0)
            self.machines[frm] = info
            dbv = info["dbv"]
            my_h = (auth.doc_hash(self.reg.doc) or "")[:16]
            if (m.get("net") == self.nid and dbv == self.reg.version and m.get("dbh") and m.get("dbh") != my_h
                    and not self.conflict and time.time() - self.db_asked.get(dbv, 0) > 30):
                # A device can advertise a different hash. Require an actual admin-signed fork.
                self.db_asked[dbv] = time.time()
                asyncio.create_task(self._safe_publish({"type": "dbreq", "to": frm, "have": max(0, dbv - 1)}))
            if dbv > self.reg.version and self.reg.version and \
                    time.time() - self.db_asked.get(dbv, 0) > 30:
                self.db_asked[dbv] = time.time()
                asyncio.ensure_future(self._safe_publish({"type": "dbreq", "to": frm, "have": self.reg.version}))
        elif t == "db":
            docs = m.get("docs") if isinstance(m.get("docs"), list) else [m.get("doc")]
            if len(docs) > 2048:
                return
            docs = [d for d in docs if isinstance(d, dict) and isinstance(d.get("v"), int)]
            for fut in list(self.db_waiters):
                fut.set_result(docs)
            for d in sorted(docs, key=lambda d: d["v"]):   # applico la catena in ordine
                self.on_registry(d)
        elif t == "dbreq":
            if m.get("to") in (self.cfg["id"], "*") and self.reg.doc:
                have = m.get("have") if isinstance(m.get("have"), int) else 0
                docs = [d for d in (self.entry.get("history") or [self.reg.doc]) if d.get("v", 0) > have] or [self.reg.doc]
                delay = random.uniform(0, 1.5) if m.get("to") == "*" else 0
                chunk, size = [], 0
                for d in reversed(docs):      # dal piu' recente; blocchi da ~120 KB
                    n = len(json.dumps(d))
                    if chunk and size + n > 120_000:
                        asyncio.ensure_future(self._safe_publish({"type": "db", "docs": list(reversed(chunk))}, delay=delay))
                        chunk, size, delay = [], 0, delay + 0.5
                    chunk.append(d)
                    size += n
                if chunk:
                    asyncio.ensure_future(self._safe_publish({"type": "db", "docs": list(reversed(chunk))}, delay=delay))
        elif t == "auditreq":
            if (abs(age) <= 45 and (not self.audit_task or self.audit_task.done())
                    and self.agent.verified_audit_request(self, m) and self.remember_once(m["rid"])):
                self.audit_task = asyncio.create_task(self.agent.audit_answer(self, m))
        elif t == "auditrep":
            rid, box = m.get("rid"), m.get("box")
            waiter = self.audit_waiters.get(rid) if isinstance(rid, str) else None
            machine = self.reg.machines().get(frm)
            if (waiter is None or self.conflict or abs(age) > 45 or not machine or frm in waiter["responses"]
                    or len(waiter["responses"]) >= 256 or m.get("net") != self.nid
                    or m.get("protocol") != auth.SESSION_PROTOCOL or m.get("to") != self.cfg["id"]
                    or not isinstance(box, dict) or set(box) != {"epk", "n", "c"}
                    or not all(isinstance(v, str) for v in box.values())
                    or len(box["epk"]) != 44 or len(box["n"]) != 16 or len(box["c"]) > 512 * 1024
                    or len(box["c"]) + waiter["size"] > 8 * 1024 * 1024):
                return
            body = auth.audit_reply_body(self.nid, frm, self.cfg["id"], rid, box)
            if auth.verify(machine["pub"], body, m.get("msig", "")):
                waiter["responses"][frm] = (machine["pub"], box)
                waiter["size"] += len(box["c"])
        elif t == "hello":
            if age < 60 and time.time() - self.last_presence > 10:   # niente risposte doppie a richieste simultanee
                asyncio.get_running_loop().call_later(random.uniform(0.2, 2.5),
                                                      lambda: asyncio.ensure_future(self._safe_presence()))
        elif t == "bye":
            if frm in self.machines:
                self.machines[frm]["last_seen"] = 0
                self.machines[frm]["signed_at"] = m["ts"]
        elif m.get("to") != self.cfg["id"]:
            return
        elif t == "updcmd":
            # comando di aggiornamento: solo da un amministratore di questa rete, firmato e recente
            if abs(age) <= 45 and self._verified_update(m) and self.remember_once(m["rid"]):
                asyncio.create_task(self._run_update(m))
        elif t == "offer":
            sid = m.get("sid")
            if (m.get("protocol") != auth.SESSION_PROTOCOL or not isinstance(sid, str)
                    or not re.fullmatch(r"[0-9a-f]{32}", sid) or type(m.get("uts")) is not int
                    or not isinstance(m.get("sdp"), str) or len(m["sdp"]) > 256 * 1024):
                return
            if abs(self.server_now() - m["uts"]) > 120 or abs(time.time() - m["uts"]) > 120 or abs(age) > 45:
                return
            # Only signed requests are answered or consume a replay entry.
            if self.agent.verified_offer(self, m) and self.remember_once(sid):
                asyncio.ensure_future(self._answer_offer(m))
        elif t == "answer":
            p = self.pending.get(m.get("sid"))
            if (not p or p[0].done() or frm != p[1] or m.get("protocol") != auth.SESSION_PROTOCOL
                    or m.get("mode") != p[2] or ("sdp" in m) == ("error" in m)):
                return
            mach = self.reg.machines().get(frm)
            if not isinstance(m.get("sdp", m.get("error")), str):
                return
            if mach and mach.get("pub") == p[3] and auth.verify(p[3], auth.answer_body(self.nid, m), m.get("msig", "")):
                self.alive(frm)
                p[0].set_result(m)

    def remember_once(self, request_id):
        seen = self.agent.seen_sids
        now = time.time()
        for key in [key for key, stamp in seen.items() if now - stamp > 600]:
            del seen[key]
        if request_id in seen or len(seen) >= 4096:
            return False
        seen[request_id] = now
        return True

    async def _safe_publish(self, obj, delay=0):
        try:
            if delay:
                await asyncio.sleep(delay)
            await self.publish(obj)
        except Exception as e:
            log.debug("pubblicazione: %s", e)

    async def _safe_presence(self):
        try:
            await self.publish(self.presence())
        except Exception:
            pass

    async def _answer_offer(self, m):
        reply = {"type": "answer", "frm": self.cfg["id"], "to": m["frm"], "sid": m["sid"],
                 "protocol": auth.SESSION_PROTOCOL, "mode": m["mode"]}
        try:
            reply["sdp"] = await self.agent.accept_offer(self, m)
        except Exception as e:
            log.info("connessione rifiutata: %s", e)
            reply["error"] = str(e)[:500]
        reply["msig"] = auth.sign(self.agent.mkey, auth.answer_body(self.nid, reply))
        await self.publish(reply)

    # ------------------------------------------------------------------ lato console
    async def connect(self, to, sdp, mode, user, priv):
        if not self.key:
            raise RuntimeError("Rete non configurata")
        reg = self.reg
        mach = reg.machines().get(to)
        if self.conflict or not mach:
            raise RuntimeError("Macchina non registrata nella rete")
        peer = self.machines.get(to, {})
        if (peer.get("session_protocol") != auth.SESSION_PROTOCOL or peer.get("pub") != mach.get("pub")
                or time.time() - peer.get("last_seen", 0) > OFFLINE_AFTER):
            raise RuntimeError("Aggiorna entrambi i PC e ricarica l'elenco: serve il protocollo di sessione 2")
        if auth.MODE_RIGHTS.get(mode) not in reg.rights(user, to):
            raise RuntimeError("Permesso di sessione mancante")
        session_policy.validate_sdp(sdp, mode)
        sid = secrets.token_hex(16)
        fut = asyncio.get_running_loop().create_future()
        target_pub = mach["pub"]
        self.pending[sid] = (fut, to, mode, target_pub, user, auth.pub_of(priv))
        offer = {"type": "offer", "frm": self.cfg["id"], "to": to, "sid": sid, "user": user,
                 "protocol": auth.SESSION_PROTOCOL, "mode": mode, "sdp": sdp, "uts": int(time.time())}
        signed = auth.offer_body(self.nid, offer)
        offer.update(usig=auth.sign(priv, signed), msig=auth.sign(self.agent.mkey, signed))
        try:
            await self.publish(offer)
            m = await asyncio.wait_for(fut, 45)
        except asyncio.TimeoutError:
            raise RuntimeError("Nessuna risposta: la macchina e' offline o non raggiungibile")
        finally:
            self.pending.pop(sid, None)
        if "error" in m:
            raise RuntimeError(m["error"])
        if (self.conflict or auth.MODE_RIGHTS.get(mode) not in reg.rights(user, to)
                or (reg.user(user) or {}).get("pub") != auth.pub_of(priv)
                or (reg.machines().get(to) or {}).get("pub") != target_pub
                or (reg.machines().get(self.cfg["id"]) or {}).get("pub") != self.agent.mpub):
            raise RuntimeError("Autorizzazione revocata durante la connessione")
        session_policy.validate_sdp(m["sdp"], mode)
        return m["sdp"], sid

    def lease_proof(self, sid, target, mode, user, priv):
        if (self.conflict or (self.reg.machines().get(self.cfg["id"]) or {}).get("pub") != self.agent.mpub
                or not self.reg.machines().get(target) or auth.MODE_RIGHTS.get(mode) not in self.reg.rights(user, target)
                or (self.reg.user(user) or {}).get("pub") != auth.pub_of(priv)):
            raise RuntimeError("Autorizzazione di sessione revocata")
        body = auth.renewal_body(self.nid, self.cfg["id"], target, sid, mode, user, int(time.time()))
        return dict(body, usig=auth.sign(priv, body), msig=auth.sign(self.agent.mkey, body))

    async def fetch_registry(self, timeout=25):
        """Chiede le catene di registro alle macchine della rete; ritorna tutti i documenti ricevuti."""
        got = []
        fut = asyncio.get_running_loop().create_future()

        class _W:
            size = 0
            overflow = False

            def set_result(self, docs):
                if self.overflow:
                    return
                self.size += sum(len(auth.canon(doc)) for doc in docs)
                if self.size > 8 * 1024 * 1024 or len(got) + len(docs) > 2048:
                    self.overflow = True
                    got.clear()
                else:
                    got.extend(docs)
                if not fut.done():
                    fut.set_result(True)
        w = _W()
        self.db_waiters.append(w)
        try:
            for _ in range(int(timeout / 5)):
                if self.state == "online":
                    try:
                        await self.publish({"type": "dbreq", "to": "*", "have": 0})
                    except Exception:
                        pass
                try:
                    await asyncio.wait_for(asyncio.shield(fut), 5)
                    await asyncio.sleep(2.5)  # aspetto altre risposte
                    if w.overflow:
                        raise RuntimeError("Risposta del registro oltre i limiti consentiti")
                    return got
                except asyncio.TimeoutError:
                    continue
            raise RuntimeError("Nessuna macchina della rete ha risposto: verifica nome rete e chiave, "
                               "e che almeno un'altra macchina della rete sia accesa")
        finally:
            self.db_waiters.remove(w)
