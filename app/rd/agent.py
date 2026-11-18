"""Agente: accetta sessioni in ingresso (schermo, input, appunti, file) e fa da
backend locale per la console (lista macchine, connessioni in uscita)."""
import asyncio
import json
import re
import logging
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction

from aiortc import (RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription,
                    VideoStreamTrack)

from . import auth
from .audio import SystemAudioTrack
from .audit import Audit
from .common import WIN, current_user, fmt_id
from .files import FileServer
from .network import Network, net_id
from .platform_io import ALL, Capturer, Clipboard, Injector, black_frame, list_monitors, primary_index, to_frame

if WIN:
    from . import winapi as W

# Bitrate piu' alto del default aiortc: uno schermo con testo ne ha bisogno
try:
    import aiortc.codecs.vpx as _vpx
    _vpx.DEFAULT_BITRATE, _vpx.MIN_BITRATE, _vpx.MAX_BITRATE = 2_000_000, 300_000, 8_000_000
    import aiortc.codecs.h264 as _h264
    _h264.DEFAULT_BITRATE, _h264.MIN_BITRATE, _h264.MAX_BITRATE = 2_000_000, 300_000, 8_000_000
except Exception:
    pass

log = logging.getLogger("rd.agent")
INPUT_TYPES = {"mm", "md", "mu", "w", "mod", "ch", "k", "txt", "combo"}


class ScreenTrack(VideoStreamTrack):
    """Cattura lo schermo; se nulla cambia rallenta (meno CPU e banda)."""

    def __init__(self, session):
        super().__init__()
        self.s = session
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="capture")
        self.cap = None
        self.start_t = None
        self.next_t = 0
        self.last_sent = 0
        self.last_frame = None

    def _grab(self):
        if self.cap is None:
            self.cap = Capturer()
        arr, changed = self.cap.grab(self.s.monitor)
        return arr, changed

    async def recv(self):
        try:
            return await self._recv()
        except RuntimeError as e:   # sessione chiusa mentre catturavo: fine del flusso, non un errore
            from aiortc.mediastreams import MediaStreamError
            raise MediaStreamError from e

    async def _recv(self):
        loop = asyncio.get_running_loop()
        if self.start_t is None:
            self.start_t = self.next_t = time.time()
        while True:
            wait = self.next_t - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            fps = max(self.s.fps, 30) if time.time() < self.s.boost_until else self.s.fps
            self.next_t = max(self.next_t + 1.0 / fps, time.time() - 0.5)
            arr, changed = await loop.run_in_executor(self.pool, self._grab)
            force = self.s.force_frame or time.time() - self.last_sent > 1.0 or self.last_frame is None
            if changed or force:
                break
        self.s.force_frame = False
        if not self.s.can_view():
            arr = None
            self.last_frame = black_frame()
        if arr is not None:
            frame = await loop.run_in_executor(self.pool, to_frame, arr, self.s.scale)
            self.last_frame = frame
        else:
            frame = self.last_frame or black_frame()
        frame.pts = int((time.time() - self.start_t) * 90000)
        frame.time_base = Fraction(1, 90000)
        self.last_sent = time.time()
        return frame

    def _cleanup(self):
        if self.cap:
            self.cap._reset()
            d = getattr(self.cap, "desk", None)
            if d and d.h and WIN:
                W.user32.CloseDesktop(d.h)
                d.h = None

    def stop(self):
        super().stop()
        try:
            self.pool.submit(self._cleanup)
        except RuntimeError:
            pass
        self.pool.shutdown(wait=False)


class Session:
    def __init__(self, agent, net, m):
        self.agent = agent
        self.net = net
        self.rsid = m.get("sid")                 # id della richiesta remota
        self.sid = auth.secrets.token_hex(12)    # chiave locale: mai decisa dall'esterno
        self.peer = m.get("frm")
        self.peer_name = m.get("name") or fmt_id(self.peer)
        self.mode = m.get("mode", "control")
        self.user = m.get("user", "")
        self.rights = set(m.get("_rights", []))
        self.boost_until = 0
        self.cursor_key = None    # ultima forma del cursore inviata a questa sessione
        try:
            self.monitor = primary_index(list_monitors())
        except Exception:
            self.monitor = 0
        self.fps, self.scale = 15, 1.0
        self.audio = None
        self.clip = True
        self.force_frame = False
        self.pc = self.ctl = self.files = self.track = None
        self.started = time.time()
        self.connected = False

    def send(self, obj):
        try:
            if self.ctl and self.ctl.readyState == "open":
                self.ctl.send(json.dumps(obj))
        except Exception as e:  # messaggio troppo grande o canale in chiusura: non deve rompere nulla
            log.debug("invio ctl fallito: %s", e)

    def can_view(self):
        return self.mode in ("control", "view") and "view" in self.rights

    def perms(self):
        c = self.agent.cfg
        ctl = bool(c["allow_control"]) and self.mode == "control" and "control" in self.rights
        return {"control": ctl, "files": bool(c["allow_files"]) and "files" in self.rights,
                "clipboard": ctl and bool(c["allow_clipboard"])}

    def send_info(self):
        try:
            mons = list_monitors()
        except Exception as e:
            log.warning("monitor non leggibili: %s", e)
            mons = []
        self.send({"t": "info", "current": self.monitor, "perms": self.perms(), "name": self.agent.cfg["name"],
                   "os": sys.platform, "service": self.agent.service_mode, "audio": self.audio is not None,
                   "monitors": [{"x": m["left"], "y": m["top"], "w": m["width"], "h": m["height"],
                                 "primary": m.get("primary", False)} for m in mons]})

    async def start(self, sdp):
        pc = RTCPeerConnection(RTCConfiguration(iceServers=self.agent.ice_servers()))
        self.pc = pc

        @pc.on("datachannel")
        def on_dc(ch):
            if ch.label == "ctl":
                self.ctl = ch
                ch.on("message", self.on_ctl)
                self.send_info()
            elif ch.label == "mm":  # movimenti mouse: canale non affidabile, latenza minima
                ch.on("message", self.on_ctl)
            elif ch.label == "files":
                self.files = FileServer(self.agent, self, ch)   # ogni messaggio ricontrolla il permesso

        @pc.on("connectionstatechange")
        async def on_state():
            st = pc.connectionState
            log.info("sessione %s con %s: %s", self.sid, self.peer_name, st)
            if st == "connected" and not self.connected:
                self.connected = True
                self.agent.log_event(f"{self.user}@{self.peer_name} ({fmt_id(self.peer)}) collegato - {self.mode}")
                self.agent.audit.add("session_start", net=self.net.nid, user=self.user, peer=self.peer,
                                     peer_name=self.peer_name, mode=self.mode)
            elif st in ("failed", "closed"):
                await self.close()

        await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="offer"))
        if self.can_view():   # schermo e audio solo a chi ha il diritto di vedere
            if "m=video" in sdp:
                self.track = ScreenTrack(self)
                pc.addTrack(self.track)
            if "m=audio" in sdp:
                self.audio = SystemAudioTrack(self)
                pc.addTrack(self.audio)
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        return pc.localDescription.sdp

    def on_ctl(self, raw):
        try:
            m = json.loads(raw)
        except Exception:
            return
        t = m.get("t")
        a = self.agent
        if t in INPUT_TYPES:
            self.boost_until = time.time() + 2
            if self.perms()["control"]:
                m["mon"] = self.monitor
                a.injector().put(m)
        elif t == "rel":
            a.injector().release_all()
        elif t == "mon":
            i = int(m.get("i", 0))
            self.monitor = ALL if i == ALL else max(0, min(i, len(list_monitors()) - 1))
            self.force_frame = True
            self.send_info()
        elif t == "q":
            self.fps = max(2, min(int(m.get("fps", 15)), 30))
            self.scale = max(0.25, min(float(m.get("scale", 1.0)), 1.0))
            self.force_frame = True
        elif t == "clipmode":
            self.clip = bool(m.get("on"))
        elif t == "clip":
            if self.clip and self.perms()["clipboard"]:
                text = str(m.get("text", ""))[:1_000_000]
                a.set_clipboard(text)
                a.audit.add("clip_in", net=self.net.nid, user=self.user, peer_name=self.peer_name, text=text)
        elif t == "audio":
            if self.audio and self.can_view():
                e = self.audio.set_active(bool(m.get("on")))
                if e:
                    self.send({"t": "notice", "text": e})
        elif t == "chat":
            a.chat_add(self, "tech", str(m.get("text", ""))[:4000])
        elif t == "cad":
            if self.perms()["control"]:
                asyncio.ensure_future(self.cad())
        elif t == "action":
            if self.perms()["control"]:
                asyncio.ensure_future(self.action(m.get("a"), m.get("v")))
        elif t == "bye":
            asyncio.ensure_future(self.close(notify=False))

    async def cad(self):
        ok = False
        if WIN:
            ok = await asyncio.get_running_loop().run_in_executor(None, W.send_sas)
            ok = ok and self.agent.service_mode
        if not ok:
            self.send({"t": "notice", "text": "Ctrl+Alt+Canc richiede che sul PC remoto sia installata la "
                                              "modalita' servizio (Impostazioni > Servizio di sistema)."})

    async def action(self, a, v):
        loop = asyncio.get_running_loop()
        if not WIN:
            self.send({"t": "notice", "text": "Azione disponibile solo su Windows"})
            return
        if a == "lock":
            await loop.run_in_executor(None, W.lock_workstation)
        elif a in ("reboot", "shutdown"):
            self.send({"t": "notice", "text": "Comando inviato. Se il servizio e' installato, il PC "
                                              "tornera' disponibile dopo il riavvio."})
            flag = "/r" if a == "reboot" else "/s"
            W.run_hidden(["shutdown", flag, "/f", "/t", "3"])
        elif a == "block":
            self.agent.block_owner = self.sid if v else None
            self.agent.injector().set_block(bool(v))
            self.send({"t": "notice", "text": "Input dell'utente remoto " + ("BLOCCATO" if v else "sbloccato") +
                       ("" if self.agent.service_mode else " (richiede modalita' servizio)")})

    async def close(self, notify=True):
        if self.agent.sessions.get(self.sid) is not self:
            return
        self.agent.sessions.pop(self.sid, None)
        if notify:
            self.send({"t": "bye"})
        self.agent.injector().release_all()
        if self.agent.block_owner == self.sid or not any(s.perms()["control"] for s in self.agent.sessions.values()):
            self.agent.block_owner = None
            self.agent.injector().set_block(False)
        if self.files:
            self.files.close()
        if self.track:
            self.track.stop()
        if self.audio:
            self.audio.stop()
        if self.pc:
            await self.pc.close()
        if self.connected:
            self.agent.log_event(f"{self.peer_name} disconnesso")
            self.agent.audit.add("session_end", net=self.net.nid, user=self.user, peer=self.peer,
                                 peer_name=self.peer_name, mode=self.mode, dur=int(time.time() - self.started))
            self.agent.chat_system(self, f"{self.display_user()} si e' disconnesso")

    def display_user(self):
        u = self.net.reg.user(self.user) or {}
        return u.get("name") or self.user


class Agent:
    def __init__(self, cfg, data_dir, service_mode=False):
        self.cfg = cfg
        self.data_dir = data_dir
        self.service_mode = service_mode
        self.sessions = {}
        self.events = []
        self._injector = None
        self.clipboard = Clipboard()
        self.clip_last = None
        self.stop_event = asyncio.Event()
        self.cloned = self._check_clone()
        self._migrate()
        self.nets = {}             # nid -> Network
        self.mkey = auth.load_machine_key(data_dir)
        self.mpub = auth.pub_of(self.mkey)
        self.logins = {}           # token -> {"nets": {nid: {user, priv}}, "exp"}
        from .common import write_private
        self.local_token = auth.secrets.token_urlsafe(24)   # per comandi locali privilegiati (handover)
        write_private(os.path.join(data_dir, "local.token"), self.local_token)
        self.audit = Audit(data_dir)
        self.block_owner = None
        self.seen_sids = {}        # anti-replay delle offerte, comune a tutte le reti
        self.outgoing = {}         # (rete, macchina) -> ultimo segnale da una finestra di sessione aperta qui
        self.chat = []             # messaggi chat (in memoria)
        self.chat_seq = 0
        self.chat_seen = 0         # ultimo segnale di vita della finestra chat locale
        self.chat_read = 0         # ultimo messaggio letto localmente
        self.fail = []             # orari dei login falliti

    # ------------------------------------------------------------------ utilita'
    def injector(self):
        if self._injector is None:
            self._injector = Injector()
        return self._injector

    def log_event(self, text):
        self.events = (self.events + [{"t": int(time.time()), "text": text}])[-40:]
        log.info(text)

    # ------------------------------------------------------------------ identita' e reti
    def _check_clone(self):
        """Se la cartella e' stata copiata da un altro PC, creo una nuova identita'."""
        from .common import legacy_fingerprint, machine_fingerprint
        fp = machine_fingerprint()
        old = self.cfg.get("fp")
        if fp is None:          # impronta non disponibile: non rischio di azzerare nulla
            return False
        if old and old != fp and old == legacy_fingerprint():
            self.cfg.update(fp=fp)  # formato vecchio, stesso PC
            return False
        if old and old != fp:
            import shutil  # copia di sicurezza prima di creare la nuova identita'
            stamp = int(time.time())
            for f in ("config.json", "machine.key"):
                src = os.path.join(self.data_dir, f)
                if os.path.exists(src):
                    shutil.copy2(src, f"{src}.bak-{stamp}")
            log.warning("cartella copiata da un altro PC: creo una nuova identita' per questa macchina")
            try:
                os.remove(os.path.join(self.data_dir, "machine.key"))
            except OSError:
                pass
            import secrets as _s
            self.cfg.data.update(id=str(_s.randbelow(900_000_000) + 100_000_000), networks=[], network="",
                                 password="", registry=None, name=__import__("socket").gethostname())
            self.cfg.update(fp=fp)
            return True
        if not old:
            self.cfg.update(fp=fp)
        return False

    def _migrate(self):
        """Configurazione 2.0/2.1 (una sola rete) -> elenco di reti."""
        if self.cfg.get("networks") is None:
            nets = []
            if self.cfg.get("network") and self.cfg.get("password"):
                nets.append({"nid": net_id(self.cfg["network"], self.cfg["password"]), "name": self.cfg["network"],
                             "key": self.cfg["password"], "registry": self.cfg["registry"]})
            self.cfg.data.update(networks=nets, network="", password="", registry=None)
            self.cfg.save()

    def start_networks(self):
        for e in self.cfg.get("networks") or []:
            n = Network(self, e)
            self.nets[n.nid] = n
            n.restart()

    def save_networks(self):
        self.cfg.data["networks"] = [n.entry for n in self.nets.values()]
        self.cfg.save()

    def net(self, nid):
        n = self.nets.get(nid or "")
        if not n:
            raise RuntimeError("Rete sconosciuta")
        return n

    def registry_changed(self, net):
        for s in list(self.sessions.values()):  # permessi revocati: chiudo subito
            if s.net is not net:
                continue
            r = net.reg.rights(s.user, self.cfg["id"])
            if s.mode not in r or self.cfg["id"] not in net.reg.machines():
                asyncio.ensure_future(s.close())
            else:
                s.rights = r
                if "files" not in r and s.files:
                    s.files.close()
                s.send_info()

    async def create_network(self, name, admin, password, pcname):
        name = name.strip()
        key = auth.new_network_key()
        nid = net_id(name, key)
        if pcname:
            self.cfg.update(name=pcname)
        n = Network(self, {"nid": nid, "name": name, "key": key, "registry": None})
        priv = await n.derive(admin, password)
        u = auth.norm_user(admin)

        def mut(doc):
            doc["network"] = name
            doc["users"][u] = {"pub": auth.pub_of(priv), "admin": True, "name": admin.strip(), "perms": {}}
            doc["machines"][self.cfg["id"]] = {"pub": self.mpub, "name": self.cfg["name"]}
        self.nets[nid] = n
        n.apply_registry(n.reg.signed_update(u, priv, mut))
        n.restart()
        return n, key, priv

    async def join_network(self, name, key, admin, password, pcname):
        name, key = name.strip(), key.strip()
        if re.fullmatch(r"[A-Z2-9]{6}(-[A-Z2-9]{6}){3}", key.upper()):   # formato delle chiavi generate
            key = key.upper()
        nid = net_id(name, key)
        if nid in self.nets:
            raise RuntimeError("Questo PC fa gia' parte di questa rete")
        n = Network(self, {"nid": nid, "name": name, "key": key, "registry": None})
        n.restart()
        try:
            priv = await n.derive(admin, password)
            docs = await n.fetch_registry()
            reg = auth.trust_chain(docs, auth.pub_of(priv))
            if not reg:
                raise RuntimeError("Credenziali di amministratore non valide per questa rete (oppure le "
                                   "ultime modifiche le ha fatte un altro amministratore: entra con le sue credenziali)")
            if not reg.is_admin(admin):
                raise RuntimeError("Questo utente non e' piu' amministratore della rete")
        except BaseException:
            n.stop()
            raise
        if pcname:
            self.cfg.update(name=pcname)
        n.reg = reg
        n.entry["history"] = sorted([d for d in docs if isinstance(d, dict) and d.get("v", 0) <= reg.version
                                     and d.get("v") is not None], key=lambda d: d["v"])[-100:]
        self.nets[nid] = n
        u = auth.norm_user(admin)

        def mut(d):
            d["machines"][self.cfg["id"]] = {"pub": self.mpub, "name": self.cfg["name"]}
        n.apply_registry(n.reg.signed_update(u, priv, mut))
        await n.publish_registry()
        for other in self.nets.values():  # annuncio subito nome e versione del registro aggiornati
            asyncio.ensure_future(other._safe_presence())
        asyncio.ensure_future(n._safe_publish({"type": "hello"}, delay=1))   # le altre macchine si ripresentano
        return n, priv

    async def leave_network(self, nid, lg=None):
        n = self.net(nid)
        for s in list(self.sessions.values()):
            if s.net is n:
                await s.close()
        if lg and n.reg.is_admin(lg["user"]):  # mi tolgo anche dal registro della rete
            try:
                me = self.cfg["id"]

                def mut(d):
                    d["machines"].pop(me, None)
                    for x in d["users"].values():
                        x.get("perms", {}).pop(me, None)
                await n.admin_update(lg, mut)
            except Exception as e:
                log.warning("rimozione dal registro: %s", e)
        n.stop()
        self.nets.pop(nid, None)
        for lgs in self.logins.values():
            lgs["nets"].pop(nid, None)
        self.save_networks()
        self.log_event(f"Uscito dalla rete {n.name}")

    def ice_servers(self):
        ice = [RTCIceServer(urls=u) for u in (self.cfg["stun"] or [])]
        if self.cfg["turn_url"]:
            ice.append(RTCIceServer(urls=self.cfg["turn_url"], username=self.cfg["turn_user"] or None,
                                    credential=self.cfg["turn_pass"] or None))
        return ice

    def ice_for_browser(self):
        ice = [{"urls": self.cfg["stun"] or []}]
        if self.cfg["turn_url"]:
            ice.append({"urls": self.cfg["turn_url"], "username": self.cfg["turn_user"],
                        "credential": self.cfg["turn_pass"]})
        return ice

    def logged_user(self):
        if WIN and self.service_mode:
            return W.session_user(W.process_session())
        return current_user()

    def user_home(self):
        if WIN and self.service_mode:
            return W.session_profile_dir(W.process_session()) or os.path.join(
                os.environ.get("PUBLIC", r"C:\Users\Public"))
        return os.path.expanduser("~")

    def incoming_dir(self):
        d = self.cfg["incoming_dir"]
        if not d:
            home = self.user_home() or os.getcwd()
            d = os.path.join(home, "Downloads")
            if not os.path.isdir(d):
                d = home
        return d

    def set_clipboard(self, text):
        self.clip_last = text
        try:
            self.clipboard.set(text)
        except Exception as e:
            log.debug("clip set: %s", e)

    # ------------------------------------------------------------------ sessioni in ingresso
    async def accept_offer(self, net, m):
        cfg = self.cfg
        reg = net.reg
        if not cfg["accept_incoming"]:
            raise RuntimeError("Questo PC non accetta connessioni in ingresso")
        if cfg["id"] not in reg.machines():
            raise RuntimeError("Questo PC non e' registrato nella rete")
        frm = m.get("frm")
        if not (isinstance(frm, str) and frm.isdigit() and frm in reg.machines()):
            raise RuntimeError("Macchina chiamante non registrata nella rete")
        m["name"] = str(reg.machines()[frm].get("name") or fmt_id(frm))[:80]   # nome dal registro firmato
        user = auth.norm_user(str(m.get("user") or ""))[:64]
        u = reg.user(user)
        signed = {"frm": m.get("frm"), "to": cfg["id"], "sid": m.get("sid"), "mode": m.get("mode"),
                  "user": m.get("user"), "ts": m.get("uts"), "h": auth.sdp_hash(m.get("sdp", ""))}
        if not u or not auth.verify(u["pub"], signed, m.get("usig", "")):
            self.log_event(f"BLOCCATA richiesta con firma non valida (utente '{user}', da {fmt_id(m.get('frm'))})")
            self.audit.add("auth_fail", net=net.nid, user=user, peer=m.get("frm"), peer_name=m.get("name"), why="firma non valida")
            raise RuntimeError("Autenticazione non valida")
        mode = m.get("mode") if m.get("mode") in ("control", "view", "files") else "view"
        rights = reg.rights(user, cfg["id"])
        if mode not in rights:
            self.log_event(f"Accesso negato a {user}: permesso '{mode}' mancante")
            self.audit.add("auth_fail", net=net.nid, user=user, peer=m.get("frm"), peer_name=m.get("name"),
                           why=f"permesso '{mode}' mancante")
            raise RuntimeError(f"L'utente {user} non ha il permesso '{mode}' su questo PC")
        m["_rights"] = sorted(rights)
        m["mode"] = mode
        name = f"{u.get('name') or user} da {m.get('name') or fmt_id(m.get('frm'))}"
        if cfg["ask_confirm"] and WIN:
            what = {"control": "controllare", "view": "vedere lo schermo di", "files": "accedere ai file di"}[mode]
            ok = await asyncio.get_running_loop().run_in_executor(
                None, W.message_box,
                f"{name} (ID {fmt_id(m.get('frm'))}) chiede di {what} questo PC.\n\nConsentire?",
                "RemoteDesk - richiesta di accesso", True, 30000)
            if not ok:
                self.log_event(f"Accesso rifiutato a {name}")
                self.audit.add("auth_fail", net=net.nid, user=user, peer=m.get("frm"), peer_name=m.get("name"),
                               why="rifiutato dall'utente del PC")
                raise RuntimeError("Accesso rifiutato dall'utente remoto")
        s = Session(self, net, m)
        self.sessions[s.sid] = s
        try:
            sdp = await s.start(m["sdp"])
        except Exception:
            try:
                await s.close(notify=False)
            except Exception:
                pass
            raise
        asyncio.get_running_loop().call_later(40, lambda: asyncio.ensure_future(self._drop_if_stale(s)))
        return sdp

    async def _drop_if_stale(self, s):
        if s.sid in self.sessions and not s.connected:
            await s.close()

    # ------------------------------------------------------------------ login (uno per rete)
    async def login(self, tok, nid, user, password):
        n = self.net(nid)
        now = time.time()
        self.fail = [t for t in self.fail if now - t < 600]
        if len(self.fail) >= 5:
            await asyncio.sleep(min(30, 2 ** (len(self.fail) - 4)))
        u = n.reg.user(user)
        priv = await n.derive(user, password)
        if not u or auth.pub_of(priv) != u["pub"]:
            self.fail.append(now)
            self.log_event(f"Login fallito per '{auth.norm_user(user)}' (rete {n.name})")
            self.audit.add("login_fail", net=nid, user=auth.norm_user(user), where="console")
            raise RuntimeError("Utente o password non validi")
        tok = self.add_login(tok, nid, user, priv)
        self.log_event(f"Login di {auth.norm_user(user)} sulla console (rete {n.name})")
        return tok

    def add_login(self, tok, nid, user, priv):
        lg = self.logins.get(tok or "")
        if not lg:
            tok = auth.secrets.token_urlsafe(32)
            lg = self.logins[tok] = {"nets": {}, "exp": 0}
        lg["nets"][nid] = {"user": auth.norm_user(user), "priv": priv}
        lg["exp"] = time.time() + 12 * 3600
        lg["act"] = time.time()
        return tok

    IDLE = 2 * 3600   # login della console: scade dopo 2 ore senza operazioni (e comunque dopo 12)

    def get_login(self, tok, touch=False):
        """{nid: {user, priv}} delle reti in cui la console e' autenticata (vuoto se nessuna)."""
        lg = self.logins.get(tok or "")
        if not lg:
            return {}
        now = time.time()
        if now > lg["exp"] or now - lg.get("act", now) > self.IDLE:
            self.logins.pop(tok, None)
            return {}
        for nid, x in list(lg["nets"].items()):
            n = self.nets.get(nid)
            u = n.reg.user(x["user"]) if n else None
            if not u or auth.pub_of(x["priv"]) != u["pub"]:   # utente rimosso o password cambiata
                lg["nets"].pop(nid, None)
        if touch:
            lg["act"] = now
        return lg["nets"]

    def logout(self, tok, nid=None):
        lg = self.logins.get(tok or "")
        if lg:
            if nid:
                lg["nets"].pop(nid, None)
            else:
                self.logins.pop(tok, None)

    def is_any_admin(self, logins):
        return any(self.nets[nid].reg.is_admin(x["user"]) for nid, x in logins.items() if nid in self.nets)

    # ------------------------------------------------------------------ chat
    def _chat_push(self, s, who, text, name):
        self.chat_seq += 1
        msg = {"id": self.chat_seq, "t": int(time.time()), "sid": s.sid if s else None, "who": who,
               "name": name, "text": text}
        self.chat = (self.chat + [msg])[-200:]
        return msg

    def chat_add(self, s, who, text):
        if not text.strip():
            return
        self._chat_push(s, who, text, s.display_user())

    def chat_system(self, s, text):
        if any(m["sid"] == s.sid for m in self.chat):
            self._chat_push(s, "sys", text, "")

    def chat_send_local(self, text, sid=None):
        name = self.logged_user() or "Utente"
        targets = [s for s in self.sessions.values()
                   if s.connected and s.mode != "files" and (sid is None or s.sid == sid)]
        if not targets:
            raise RuntimeError("Nessun tecnico collegato")
        for s in targets:
            s.send({"t": "chat", "text": text, "name": name})
        self._chat_push(targets[0] if len(targets) == 1 else None, "local", text, name)
        self.chat_read = self.chat_seq

    def chat_unread(self):
        return sum(1 for m in self.chat if m["who"] == "tech" and m["id"] > self.chat_read)

    # ------------------------------------------------------------------ registro accessi in rete
    async def audit_query(self, net, lg, since, until):
        """Interroga tutte le macchine della rete (richiesta firmata, risposte cifrate per noi)."""
        if not lg or not net.reg.is_admin(lg["user"]):
            raise RuntimeError("Serve un amministratore di questa rete")
        from . import audit as A
        priv, epub = A.new_ephemeral()
        rid = auth.secrets.token_hex(12)
        ts = int(net.server_now())
        body = {"rid": rid, "user": lg["user"], "since": int(since), "until": int(until), "epub": epub, "ats": ts}
        results = {self.cfg["id"]: {"name": self.cfg["name"], "entries": self.audit.query(since, until, net=net.nid)}}
        fut_box = []
        net.audit_waiters[rid] = fut_box
        try:
            await net.publish({"type": "auditreq", "to": "*", **body, "sig": auth.sign(lg["priv"], body)})
            await asyncio.sleep(7)
        finally:
            net.audit_waiters.pop(rid, None)
        for frm, m in fut_box:
            mach = net.reg.machines().get(frm)
            if not mach or not auth.verify(mach["pub"], {"rid": rid, "frm": frm, "c": m["box"]["c"]}, m.get("msig", "")):
                continue
            try:
                data = A.open_with(priv, m["box"])
            except Exception:
                continue
            results[frm] = {"name": data.get("name"), "entries": data.get("entries", [])}
        return results

    def audit_answer(self, net, m, ev_time):
        """Risposta a una richiesta di registro: solo admin di QUELLA rete, firma valida, richiesta recente.
        Ogni rete vede solo gli eventi che la riguardano."""
        from . import audit as A
        body = {k: m.get(k) for k in ("rid", "user", "since", "until", "epub", "ats")}
        if not net.reg.is_admin(body["user"]) or abs(ev_time - (body["ats"] or 0)) > 120:
            return None
        if not auth.verify(net.reg.user(body["user"])["pub"], body, m.get("sig", "")):
            return None
        box = A.seal_for(body["epub"], {"name": self.cfg["name"],
                                        "entries": self.audit.query(body["since"], body["until"], net=net.nid)})
        return {"type": "auditrep", "to": m["frm"], "rid": body["rid"], "box": box,
                "msig": auth.sign(self.mkey, {"rid": body["rid"], "frm": self.cfg["id"], "c": box["c"]})}

    async def close_sessions(self, sid=None):
        for s in list(self.sessions.values()):
            if sid is None or s.sid == sid:
                await s.close()

    # ------------------------------------------------------------------ cicli di servizio
    async def cursor_watch(self):
        """Invia alle sessioni la forma del puntatore del PC (doppia freccia sui bordi, I nel testo, ecc.)."""
        if not WIN:
            return
        loop = asyncio.get_running_loop()
        cache = {}   # handle cursore personalizzato -> messaggio con immagine
        while True:
            targets = [s for s in self.sessions.values() if s.connected and s.can_view()]
            if not targets:
                await asyncio.sleep(0.5)
                continue
            await asyncio.sleep(0.06)
            try:
                st = await loop.run_in_executor(None, W.cursor_state)
            except Exception:
                continue
            if not st:
                continue
            css, h = st
            if css == "custom":
                if h not in cache:
                    if len(cache) > 64:
                        cache.clear()
                    cache[h] = await loop.run_in_executor(None, _custom_cursor_msg, h)
                msg, key = cache[h], ("custom", h)
            else:
                msg, key = {"t": "cur", "c": css}, (css, None)
            for s in targets:
                if s.cursor_key != key:
                    s.cursor_key = key
                    s.send(msg)

    async def clip_watch(self):
        loop = asyncio.get_running_loop()
        last_seq = None
        baseline = True   # all'inizio di una sessione non invio cio' che c'era gia' negli appunti
        while True:
            await asyncio.sleep(0.8)
            targets = [s for s in self.sessions.values() if s.clip and s.connected and s.perms()["clipboard"]]
            if not targets or not self.cfg["allow_clipboard"]:
                baseline = True
                continue
            try:
                if WIN:
                    seq = W.clip_seq()
                    if seq == last_seq:
                        continue
                    last_seq = seq
                text = await loop.run_in_executor(None, self.clipboard.get)
            except Exception:
                continue
            if baseline:
                baseline = False
                if self.clip_last is None or text is not None:
                    self.clip_last = text
                continue
            if not text or text == self.clip_last:
                continue
            self.clip_last = text
            out = text.encode("utf-8")[:200_000].decode("utf-8", "ignore")   # sotto il limite del data channel
            for s in targets:
                s.send({"t": "clip", "text": out, "trunc": len(out) < len(text)})
            try:
                for nid in {s.net.nid for s in targets}:
                    self.audit.add("clip_out", net=nid, text=text,
                                   user=",".join(sorted({s.user for s in targets if s.net.nid == nid})))
            except Exception as e:
                log.warning("registro: %s", e)

    async def housekeeping(self):
        while True:
            await asyncio.sleep(120)
            try:
                self.cfg.save()
            except Exception:
                pass
            if time.time() - getattr(self, "_pruned", 0) > 86400:
                self._pruned = time.time()
                try:
                    self.audit.prune()
                except Exception as e:
                    log.warning("pulizia registro: %s", e)

    async def watch_parent(self, pid):
        while True:
            await asyncio.sleep(5)
            if WIN and not W.pid_alive(pid):
                log.info("servizio terminato: chiudo l'agente")
                self.stop_event.set()
                return

    async def shutdown(self):
        await self.close_sessions()
        for n in list(self.nets.values()):
            t = n.task
            n.stop()
            if t:
                try:
                    await t
                except BaseException:
                    pass
        try:
            self.cfg.save()
        except Exception:
            pass


def _custom_cursor_msg(h):
    """Cursore personalizzato -> messaggio con immagine PNG (o freccia normale se non leggibile)."""
    try:
        import base64
        import io
        from PIL import Image
        r = W.cursor_image(h)
        if not r:
            return {"t": "cur", "c": "default"}
        rgba, w, hh, hx, hy = r
        buf = io.BytesIO()
        Image.frombytes("RGBA", (w, hh), rgba).save(buf, "PNG")
        return {"t": "cur", "c": "custom", "hx": int(hx), "hy": int(hy),
                "img": "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()}
    except Exception as e:
        log.debug("cursore personalizzato: %s", e)
        return {"t": "cur", "c": "default"}


def service_marker(data_dir):
    return os.path.join(data_dir, "service.json")


def open_console(port, path="/", size=(1180, 780), pos=None):
    url = f"http://127.0.0.1:{port}{path}"
    if WIN:
        b = W.find_browser()
        if b:
            prof = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "RemoteDesk", "browser")
            args = [b, f"--app={url}", f"--user-data-dir={prof}", "--no-first-run",
                    "--no-default-browser-check", f"--window-size={size[0]},{size[1]}"]
            if pos:
                args.append(f"--window-position={pos[0]},{pos[1]}")
            subprocess.Popen(args, creationflags=W.CREATE_NO_WINDOW)
            return
    import webbrowser
    webbrowser.open(url)


def open_chat_window(port):
    w, h = 380, 560
    pos = None
    if WIN:
        l, t, r, b = W.work_area()
        pos = (r - w - 12, b - h - 12)
    open_console(port, "/chat", (w, h), pos)
