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

from . import auth
from .relays import DEFAULT_SIGNAL, make_relay, parse_signal
from .common import VERSION, NetKey, current_user, os_label

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
        self.reg = auth.Registry(entry.get("registry"))
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
        self.audit_seen = {}
        self.conflict = False
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
        self.relays = [make_relay(u, self.key.topic) for u in (parse_signal(self.cfg["signal"]) or
                                                               parse_signal(DEFAULT_SIGNAL))]
        self.announced = False
        self.task = asyncio.ensure_future(self._main())

    def stop(self):
        if self.task:
            self.task.cancel()
            self.task = None
        self.machines.clear()
        self.state = "ferma"

    # ------------------------------------------------------------------ registro firmato
    def on_registry(self, doc):
        if not self.reg.check_new(doc):
            return False
        self.apply_registry(doc)
        return True

    def apply_registry(self, doc):
        self.reg.doc = doc
        self.entry["registry"] = doc
        hist = [d for d in (self.entry.get("history") or []) if d.get("v", 0) < doc["v"]] + [doc]
        self.entry["history"] = hist[-100:]     # catena recente, per chi deve recuperare versioni
        self.agent.save_networks()
        log.info("[%s] registro aggiornato alla versione %s (firmato da %s)", self.name, doc["v"], doc.get("signer"))
        self.agent.registry_changed(self)

    async def publish_registry(self):
        try:
            await self.publish({"type": "db", "docs": [self.reg.doc]})
        except Exception as e:
            log.warning("pubblicazione registro: %s", e)

    async def derive(self, user, password):
        return await asyncio.get_running_loop().run_in_executor(
            None, auth.derive_user_key, self.name, user, password)

    async def admin_update(self, lg, mutate):
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
            for k, t0 in list(self.recent.items()):
                if now - t0 > 900:
                    self.recent.pop(k, None)
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

    async def _run_update(self, user):
        try:
            await self.agent.updater.install(f"{user} (rete {self.name})")
        except Exception as e:
            log.warning("aggiornamento richiesto da %s non eseguito: %s", user, e)
            self.agent.log_event(f"Aggiornamento richiesto da {user} non eseguito: {e}")

    async def send_update(self, to, lg):
        """Chiede alla macchina 'to' di aggiornarsi (comando firmato dall'amministratore)."""
        if not self.reg.is_admin(lg["user"]):
            raise RuntimeError("Serve un amministratore di questa rete")
        if to not in self.reg.machines():
            raise RuntimeError("Macchina non registrata")
        body = {"frm": self.cfg["id"], "to": to, "user": lg["user"], "ats": int(self.server_now()), "cmd": "update",
                "rid": secrets.token_hex(12)}
        await self.publish({"type": "updcmd", **body, "sig": auth.sign(lg["priv"], body)})

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
            if not mach or not auth.verify(mach["pub"], {k: v for k, v in m.items() if k != "msig"}, m.get("msig", "")):
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
                    "accept": bool(m.get("accept", True)), "dbv": dbv_raw if isinstance(dbv_raw, int) else 0}
            info["id"] = frm
            info["last_seen"] = time.time() - max(age, 0)
            self.machines[frm] = info
            dbv = info["dbv"]
            my_h = (auth.doc_hash(self.reg.doc) or "")[:16]
            if dbv == self.reg.version and m.get("dbh") and m.get("dbh") != my_h and not self.conflict:
                # stessa versione ma contenuto diverso: qualcuno ha biforcato il registro
                self.conflict = True
                log.error("[%s] CONFLITTO nel registro con la macchina %s (versione %s)", self.name, frm, dbv)
                self.agent.log_event(f"ATTENZIONE: registro della rete {self.name} in conflitto con un altro PC")
            if dbv > self.reg.version and self.reg.version and \
                    time.time() - self.db_asked.get(dbv, 0) > 30:
                self.db_asked[dbv] = time.time()
                asyncio.ensure_future(self._safe_publish({"type": "dbreq", "to": frm, "have": self.reg.version}))
        elif t == "db":
            docs = m.get("docs") if isinstance(m.get("docs"), list) else [m.get("doc")]
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
            rid = m.get("rid")
            if rid in self.audit_seen or self.reg.version == 0:
                return
            self.audit_seen[rid] = time.time()
            rep = self.agent.audit_answer(self, m, ev.get("time", self.server_now()))
            if rep:
                asyncio.ensure_future(self._safe_publish(rep, delay=random.uniform(0, 2)))
        elif t == "auditrep":
            box = self.audit_waiters.get(m.get("rid"))
            if box is not None and m.get("to") == self.cfg["id"]:
                box.append((frm, m))
        elif t == "hello":
            if age < 60 and time.time() - self.last_presence > 10:   # niente risposte doppie a richieste simultanee
                asyncio.get_running_loop().call_later(random.uniform(0.2, 2.5),
                                                      lambda: asyncio.ensure_future(self._safe_presence()))
        elif t == "bye":
            if frm in self.machines:
                self.machines[frm]["last_seen"] = 0
        elif m.get("to") != self.cfg["id"]:
            return
        elif t == "updcmd":
            # comando di aggiornamento: solo da un amministratore di questa rete, firmato e recente
            body = {k: m.get(k) for k in ("frm", "to", "user", "ats", "cmd", "rid")}
            u = self.reg.user(m.get("user") or "")
            seen = self.agent.seen_sids
            if (body["cmd"] != "update" or not self.reg.is_admin(m.get("user") or "") or not isinstance(body["ats"], int)
                    or abs(ev.get("time", 0) - body["ats"]) > 120 or body["rid"] in seen
                    or not auth.verify(u["pub"], body, m.get("sig", ""))):
                return
            seen[body["rid"]] = time.time()
            asyncio.ensure_future(self._run_update(body["user"]))
        elif t == "offer":
            sid = m.get("sid")
            # anti-replay: firma recente, rispetto all'orario del server, e sid mai visto
            seen = self.agent.seen_sids   # anti-replay comune a tutte le reti
            if not isinstance(sid, str) or not isinstance(m.get("uts"), int) or not isinstance(m.get("sdp"), str):
                return
            if age > 45 or abs(ev.get("time", 0) - m["uts"]) > 120 or sid in seen:
                return
            seen[sid] = time.time()
            for k, t0 in list(seen.items()):
                if time.time() - t0 > 600:
                    seen.pop(k, None)
            asyncio.ensure_future(self._answer_offer(m))
        elif t == "answer":
            p = self.pending.get(m.get("sid"))
            if not p or p[0].done() or frm != p[1]:
                return
            mach = self.reg.machines().get(frm)
            body = {"frm": frm, "to": self.cfg["id"], "sid": m.get("sid")}
            body.update({"h": auth.sdp_hash(m["sdp"])} if isinstance(m.get("sdp"), str) else {"err": str(m.get("error"))})
            if mach and auth.verify(mach["pub"], body, m.get("msig", "")):   # risposte non firmate: ignorate
                self.alive(frm)
                p[0].set_result(m)

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
        try:
            sdp = await self.agent.accept_offer(self, m)
            reply = {"type": "answer", "to": m["frm"], "sid": m.get("sid"), "sdp": sdp,
                     "msig": auth.sign(self.agent.mkey, {"frm": self.cfg["id"], "to": m["frm"], "sid": m.get("sid"),
                                                          "h": auth.sdp_hash(sdp)})}
        except Exception as e:
            log.info("connessione rifiutata: %s", e)
            reply = {"type": "answer", "to": m["frm"], "sid": m.get("sid"), "error": str(e),
                     "msig": auth.sign(self.agent.mkey, {"frm": self.cfg["id"], "to": m["frm"], "sid": m.get("sid"),
                                                          "err": str(e)})}
        await self.publish(reply)

    # ------------------------------------------------------------------ lato console
    async def connect(self, to, sdp, mode, user, priv):
        if not self.key:
            raise RuntimeError("Rete non configurata")
        reg = self.reg
        mach = reg.machines().get(to)
        if not mach:
            raise RuntimeError("Macchina non registrata nella rete")
        sid = secrets.token_hex(16)
        fut = asyncio.get_running_loop().create_future()
        self.pending[sid] = (fut, to)
        ts = int(self.server_now())
        signed = {"frm": self.cfg["id"], "to": to, "sid": sid, "mode": mode, "user": user, "ts": ts,
                  "h": auth.sdp_hash(sdp)}
        try:
            await self.publish({"type": "offer", "to": to, "sid": sid, "sdp": sdp, "mode": mode,
                                "name": self.cfg["name"], "user": user, "uts": ts,
                                "usig": auth.sign(priv, signed)})
            m = await asyncio.wait_for(fut, 45)
        except asyncio.TimeoutError:
            raise RuntimeError("Nessuna risposta: la macchina e' offline o non raggiungibile")
        finally:
            self.pending.pop(sid, None)
        if m.get("error"):
            raise RuntimeError(m["error"])
        return m["sdp"]   # gia' verificata (firma della macchina) prima di risolvere l'attesa

    async def fetch_registry(self, timeout=25):
        """Chiede le catene di registro alle macchine della rete; ritorna tutti i documenti ricevuti."""
        got = []
        fut = asyncio.get_running_loop().create_future()

        class _W:
            def set_result(self, docs):
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
                    return got
                except asyncio.TimeoutError:
                    continue
            raise RuntimeError("Nessuna macchina della rete ha risposto: verifica nome rete e chiave, "
                               "e che almeno un'altra macchina della rete sia accesa")
        finally:
            self.db_waiters.remove(w)
