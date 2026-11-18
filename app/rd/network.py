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
from .common import VERSION, NetKey, current_user, os_label

log = logging.getLogger("rd.net")
PRESENCE_EVERY = 300      # annuncio periodico ogni 5 minuti (i server ntfy pubblici limitano i messaggi al giorno)
OFFLINE_AFTER = 720       # offline se nessun segno di vita da 12 minuti (lo spegnimento regolare e' immediato)


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
        self.quota = None         # {"used", "limit"} messaggi di oggi sul server, se lo comunica

    # ------------------------------------------------------------------ ciclo di vita
    def restart(self):
        self.stop()
        self.key = NetKey(self.entry["name"], self.entry["key"])
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
    def server(self):
        return self.cfg["signal"].rstrip("/")

    async def _main(self):
        timeout = ClientTimeout(total=None, sock_connect=15, sock_read=150)   # ntfy manda un keepalive ogni 45 s
        since = f"{OFFLINE_AFTER}s"
        async with ClientSession(timeout=timeout, trust_env=True) as s:
            self.session = s
            beat = asyncio.ensure_future(self._heartbeat())
            try:
                while True:
                    try:
                        self.state = "connessione..."
                        async with s.get(f"{self.server}/{self.key.topic}/json", params={"since": since}) as r:
                            r.raise_for_status()
                            self.state = "online"
                            await self.publish({"type": "hello"})
                            await self.publish(self.presence())
                            async for line in r.content:
                                try:
                                    ev = json.loads(line)
                                except Exception:
                                    continue
                                if isinstance(ev, dict) and ev.get("event") == "message":
                                    since = ev.get("id", since)
                                    try:
                                        await self._on_event(ev)
                                    except Exception as e:   # un messaggio malformato non chiude lo stream
                                        log.debug("evento scartato: %s", e)
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        self.state = "offline (riprovo...)"
                        log.warning("segnalazione: %s", e)
                    await asyncio.sleep(5)
            finally:
                beat.cancel()
                try:
                    await self.publish({"type": "bye"}, session=s)
                except BaseException:
                    pass
                if self.session is s:  # un riavvio potrebbe aver gia' aperto una nuova sessione
                    self.session = None

    async def _heartbeat(self):
        asyncio.ensure_future(self._quota_loop())
        while True:
            await asyncio.sleep(PRESENCE_EVERY + random.uniform(-20, 20))
            if self.state == "online":
                try:
                    await self.publish(self.presence())
                except Exception as e:
                    log.debug("presence: %s", e)

    async def _quota_loop(self):
        """Messaggi usati oggi sul server ntfy (endpoint /v1/account, se disponibile)."""
        while True:
            if not (self.session and self.state == "online"):
                await asyncio.sleep(10)
                continue
            try:
                if True:
                    async with self.session.get(f"{self.server}/v1/account", timeout=ClientTimeout(total=15)) as r:
                        if r.status == 200:
                            d = await r.json(content_type=None)
                            lim = (d.get("limits") or {}).get("messages")
                            used = (d.get("stats") or {}).get("messages")
                            if isinstance(lim, int) and isinstance(used, int):
                                self.quota = {"used": used, "limit": lim}
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            await asyncio.sleep(600)

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

    async def refresh(self):
        """Chiede a tutte le macchine della rete di ripresentarsi (al massimo ogni 15 secondi)."""
        if time.time() - self.last_hello < 15 or self.state != "online":
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
        session = session or self.session
        if not self.key or not session:
            raise RuntimeError("rete non connessa")
        obj = dict(obj, frm=self.cfg["id"], ts=int(time.time()))
        if obj.get("type") in ("presence", "bye"):
            obj["msig"] = auth.sign(self.agent.mkey, obj)
        async with session.post(f"{self.server}/{self.key.topic}", data=self.key.seal(obj)) as r:
            if r.status == 429:
                if not self.limited:
                    log.warning("[%s] il server di segnalazione rifiuta i messaggi: limite giornaliero raggiunto", self.name)
                    self.agent.log_event(f"Rete {self.name}: limite di messaggi del server di segnalazione raggiunto")
                self.limited = True
                raise RuntimeError("limite messaggi del server di segnalazione raggiunto")
            if r.status >= 300:
                raise RuntimeError(f"HTTP {r.status}")
            self.limited = False
            if obj.get("type") == "presence":
                self.last_presence = time.time()
            try:
                ev = await r.json(content_type=None)
                if ev.get("time"):
                    self.offset = ev["time"] - time.time()
            except Exception:
                pass

    async def _on_event(self, ev):
        body = ev.get("message", "")
        att = ev.get("attachment") or {}
        if att.get("url"):
            # solo allegati del nostro server di segnalazione e di dimensione ragionevole
            url = str(att["url"])
            if not url.startswith(self.server + "/file/") or int(att.get("size") or 0) > 4 * 1024 * 1024:
                return
            try:
                async with self.session.get(url, timeout=ClientTimeout(total=30)) as r:
                    data = await r.content.read(4 * 1024 * 1024 + 1)
                if len(data) > 4 * 1024 * 1024:
                    return
                body = data.decode("utf-8", "replace")
            except Exception:
                return
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
                docs = [d for d in (self.entry.get("history") or [self.reg.doc]) if d.get("v", 0) > have]
                asyncio.ensure_future(self._safe_publish({"type": "db", "docs": docs or [self.reg.doc]},
                                                         delay=random.uniform(0, 1.5) if m.get("to") == "*" else 0))
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
            if age < 60 and time.time() - self.last_presence > 20:   # niente risposte doppie se ho appena annunciato
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
