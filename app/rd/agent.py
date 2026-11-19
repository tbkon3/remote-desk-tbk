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

from . import auth, session_policy
from .audio import SystemAudioTrack
from .audit import Audit
from .update import Updater
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
            self.cap = Capturer(service_mode=self.s.agent.service_mode, expected_logon=self.s.windows_logon)
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
            if not self.s.can_view():
                arr = None
                break
            arr, changed = await loop.run_in_executor(self.pool, self._grab)
            if arr is None:
                self.last_frame = None
                break
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
        if not self.s.can_view():
            frame = self.last_frame = black_frame()
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
        self.mode = m["mode"]
        self.user = m["user"]
        self.user_pub = net.reg.user(self.user)["pub"]
        self.peer_pub = net.reg.machines()[self.peer]["pub"]
        self.rights = session_policy.capabilities(agent.cfg, net.reg, self.user, self.mode, WIN)
        self.revoked = False
        self.lease_deadline = None
        self.lease_timer = None
        self.lease_issued = -1
        self.channel_labels = set()
        self.inventory_channel = None
        self.windows_logon = None
        self.boost_until = 0
        self.cursor_key = None    # ultima forma del cursore inviata a questa sessione
        self.monitor = 0
        self.fps, self.scale = 15, 1.0
        self.audio = None
        self.clip_read = None
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
        return self.lease_active() and self.agent.cfg["accept_incoming"] and "view" in self.rights

    def lease_active(self):
        return (not self.revoked and self.lease_issued >= 0 and self.lease_deadline is not None
                and time.monotonic() < self.lease_deadline and self.local_identity_current())

    def local_identity_current(self):
        if self.windows_logon is not None:
            from .win_identity import effective_logon
            try:
                if effective_logon() == self.windows_logon:
                    return True
            except OSError:
                pass
            self.revoked = True
            self.rights.clear()
            return False
        return True

    def command_active(self, right):
        # Called on the input worker between native batches, under its verified logon token.
        cfg = self.agent.cfg
        return (not self.revoked and not self.agent.active_prompts and self.lease_issued >= 0
                and self.lease_deadline is not None and time.monotonic() < self.lease_deadline
                and cfg["accept_incoming"] and cfg["allow_control"] and self.mode == "control"
                and right in self.rights and (right == "control" or
                    (right == "block_input" and cfg.get("allow_local_block") and not cfg.get("on_air"))))

    def refresh_authorization(self):
        """Never add capabilities to an already approved request."""
        reg, me = self.net.reg, self.agent.cfg["id"]
        if self.lease_deadline is not None and time.monotonic() >= self.lease_deadline:
            self.revoked = True
        if (self.net.conflict or getattr(self.net, "leaving", False) or not self.local_identity_current()
                or self.agent.nets.get(self.net.nid) is not self.net
                or (reg.user(self.user) or {}).get("pub") != self.user_pub
                or (reg.machines().get(self.peer) or {}).get("pub") != self.peer_pub
                or (reg.machines().get(me) or {}).get("pub") != self.agent.mpub):
            self.revoked = True
        self.rights.intersection_update(session_policy.capabilities(self.agent.cfg, reg, self.user, self.mode, WIN))
        if auth.MODE_RIGHTS[self.mode] not in self.rights:
            self.revoked = True
        if self.revoked:
            self.rights.clear()
        return not self.revoked

    def set_lease_deadline(self, deadline):
        self.lease_deadline = deadline
        if self.lease_timer:
            self.lease_timer.cancel()
        def expire():
            self.revoked = True
            self.rights.clear()
            asyncio.create_task(self.close(reason="lease_expired"))
        self.lease_timer = asyncio.get_running_loop().call_later(max(0, deadline - time.monotonic()), expire)

    def renew(self, msg):
        issued = msg.get("iat")
        now = time.time()
        if (type(issued) is not int or issued <= self.lease_issued or not now - 60 < issued <= now + 5
                or not self.refresh_authorization()):
            return
        body = auth.renewal_body(self.net.nid, self.peer, self.agent.cfg["id"], self.rsid,
                                 self.mode, self.user, issued)
        if (any(msg.get(key) != value for key, value in body.items())
                or not auth.verify(self.peer_pub, body, msg.get("msig", ""))
                or not auth.verify(self.user_pub, body, msg.get("usig", ""))):
            return
        initial = self.lease_issued < 0
        self.lease_issued = issued
        deadline = time.monotonic() + min(60, issued + 60 - now)
        if self.lease_deadline is None or deadline > self.lease_deadline:
            self.set_lease_deadline(deadline)
        if initial:
            self.send_info()

    def perms(self):
        c = self.agent.cfg
        live = self.lease_active() and c["accept_incoming"]
        ctl = bool(live and not self.agent.active_prompts and c["allow_control"] and "control" in self.rights)
        maintenance = ctl and not c.get("on_air")
        files = bool(live and c["allow_files"] and "files" in self.rights)
        return {"control": ctl, "files": files, "files_write": files and "files_write" in self.rights,
                "files_delete": files and "files_delete" in self.rights,
                "clipboard": bool(ctl and c["allow_clipboard"] and "clipboard" in self.rights),
                "power": bool(maintenance and c.get("allow_power") and "power" in self.rights),
                "block_input": bool(maintenance and c.get("allow_local_block") and "block_input" in self.rights),
                "secure_desktop": bool(maintenance and c.get("allow_sas") and "secure_desktop" in self.rights)}

    def send_info(self):
        if self.mode == "manage":
            return
        try:
            mons = list_monitors() if self.can_view() else []
        except Exception as e:
            log.warning("monitor non leggibili: %s", e)
            mons = []
        self.send({"t": "info", "lease_active": self.lease_active(), "current": self.monitor, "perms": self.perms(), "name": self.agent.cfg["name"],
                   "os": sys.platform, "service": self.agent.service_mode, "audio": self.audio is not None,
                   "monitors": [{"x": m["left"], "y": m["top"], "w": m["width"], "h": m["height"],
                                 "primary": m.get("primary", False)} for m in mons]})

    async def start(self, sdp):
        pc = RTCPeerConnection(RTCConfiguration(iceServers=self.agent.ice_servers()))
        self.pc = pc

        @pc.on("datachannel")
        def on_dc(ch):
            if (not self.refresh_authorization() or ch.label in self.channel_labels
                    or ch.label not in session_policy.permitted_channels(self.mode)):
                ch.close()
                return
            self.channel_labels.add(ch.label)
            if ch.label == "inventory":
                from .inventory_channel import InventoryChannel
                self.inventory_channel = InventoryChannel(self, ch)
            elif ch.label == "ctl":
                self.ctl = ch
                ch.on("message", self.on_ctl)
                self.send_info()
            elif ch.label == "mm":  # movimenti mouse: canale non affidabile, latenza minima
                ch.on("message", lambda raw: self.on_ctl(raw, mouse_only=True))
            elif ch.label == "files":
                try:
                    self.files = FileServer(self.agent, self, ch)
                except (OSError, ValueError) as exc:
                    ch.close()
                    log.warning("Accesso alla cartella di trasferimento non disponibile: %s", exc)

        @pc.on("connectionstatechange")
        async def on_state():
            st = pc.connectionState
            log.info("sessione %s con %s: %s", self.sid, self.peer_name, st)
            if st == "connected" and not self.connected and self.refresh_authorization():
                self.connected = True
                self.agent.log_event(f"{self.user}@{self.peer_name} ({fmt_id(self.peer)}) collegato - {self.mode}")
                self.agent.audit.add("session_start", net=self.net.nid, user=self.user, peer=self.peer,
                                     peer_name=self.peer_name, mode=self.mode)
            elif st in ("failed", "closed"):
                await self.close()

        await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="offer"))
        if not self.refresh_authorization():
            raise RuntimeError("Autorizzazione revocata")
        if "view" in self.rights:
            try:
                self.monitor = primary_index(list_monitors())
            except Exception:
                pass
            if "m=video" in sdp:
                self.track = ScreenTrack(self)
                pc.addTrack(self.track)
            if "audio" in self.rights and "m=audio" in sdp:
                self.audio = SystemAudioTrack(self)
                pc.addTrack(self.audio)
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        if not self.refresh_authorization():
            raise RuntimeError("Autorizzazione revocata")
        return pc.localDescription.sdp

    def on_ctl(self, raw, mouse_only=False):
        if self.revoked or self.mode == "manage" or not isinstance(raw, str) or len(raw) > 1_100_000:
            return
        try:
            m = json.loads(raw)
        except Exception:
            return
        if not isinstance(m, dict):
            return
        t = m.get("t")
        if t == "renew" and not mouse_only and len(raw) <= 8192:
            self.renew(m)
            return
        if not isinstance(t, str) or (self.mode == "files" and t != "bye"):
            return
        if mouse_only and t != "mm":
            return
        a = self.agent
        if t in INPUT_TYPES:
            self.boost_until = time.time() + 2
            if self.perms()["control"]:
                m["mon"] = self.monitor
                a.injector().put(m, expected_logon=self.windows_logon, authorized=lambda: self.command_active("control"))
        elif t == "rel" and self.perms()["control"]:
            a.injector().release_all()
        elif t == "mon" and self.can_view():
            i = int(m.get("i", 0))
            self.monitor = ALL if i == ALL else max(0, min(i, len(list_monitors()) - 1))
            self.force_frame = True
            self.send_info()
        elif t == "q" and self.can_view():
            self.fps = max(2, min(int(m.get("fps", 15)), 30))
            self.scale = max(0.25, min(float(m.get("scale", 1.0)), 1.0))
            self.force_frame = True
        elif t == "clipread":
            request_id = m.get("id")
            if (type(request_id) is int and 0 <= request_id < 2**31 and self.perms()["clipboard"]
                    and (self.clip_read is None or self.clip_read.done())):
                self.clip_read = asyncio.create_task(self.read_clipboard(request_id))
        elif t == "clip":
            if self.perms()["clipboard"] and isinstance(m.get("text"), str):
                text = m["text"]
                if len(text.encode("utf-8", errors="surrogatepass")) > 60_000:
                    return
                a.set_clipboard(text)
                a.audit.add("clip_in", net=self.net.nid, user=self.user, peer_name=self.peer_name, length=len(text))
        elif t == "audio":
            if self.audio and self.can_view() and "audio" in self.rights:
                e = self.audio.set_active(bool(m.get("on")))
                if e:
                    self.send({"t": "notice", "text": e})
        elif t == "chat" and self.can_view():
            a.chat_add(self, "tech", str(m.get("text", ""))[:4000])
        elif t == "cad":
            if self.perms()["secure_desktop"]:
                asyncio.ensure_future(self.cad())
        elif t == "action":
            if self.perms()["control"]:
                asyncio.ensure_future(self.action(m.get("a"), m.get("v")))
        elif t == "bye":
            asyncio.ensure_future(self.close(notify=False))

    async def cad(self):
        if not self.refresh_authorization() or not self.perms()["secure_desktop"]:
            return
        ok = False
        if WIN:
            ok = await asyncio.get_running_loop().run_in_executor(None, W.send_sas)
            ok = ok and self.agent.service_mode
        if not ok:
            self.send({"t": "notice", "text": "Ctrl+Alt+Canc richiede che sul PC remoto sia installata la "
                                              "modalita' servizio (Impostazioni > Servizio di sistema)."})

    async def read_clipboard(self, request_id):
        if not self.refresh_authorization() or not self.perms()["clipboard"]:
            return
        try:
            value = await asyncio.get_running_loop().run_in_executor(None, self.agent.clipboard.get)
        except Exception:
            self.send({"t": "notice", "text": "Lettura appunti non disponibile"})
            return
        if not self.refresh_authorization() or not self.perms()["clipboard"] or self.agent.sessions.get(self.sid) is not self:
            return
        value = value if isinstance(value, str) else ""
        # Keep even an escaped JSON payload within the SCTP message size.
        raw = value.encode("utf-8", errors="replace")
        text = raw[:60_000].decode("utf-8", errors="ignore")
        low, high = 0, len(text)
        while low < high:
            mid = (low + high + 1) // 2
            if len(json.dumps(text[:mid])) <= 64 * 1024 - 128:
                low = mid
            else:
                high = mid - 1
        text = text[:low]
        self.send({"t": "clip", "id": request_id, "text": text, "trunc": len(text) != len(value)})
        self.agent.audit.add("clip_out", net=self.net.nid, user=self.user, peer=self.peer, length=len(text))

    async def action(self, a, v):
        loop = asyncio.get_running_loop()
        if not WIN:
            self.send({"t": "notice", "text": "Azione disponibile solo su Windows"})
            return
        right = "block_input" if a == "block" else "power"
        if not self.refresh_authorization() or not self.perms()[right]:
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
            self.agent.injector().set_block(bool(v), expected_logon=self.windows_logon,
                                            authorized=lambda: self.command_active("block_input"))
            self.send({"t": "notice", "text": "Input dell'utente remoto " + ("BLOCCATO" if v else "sbloccato") +
                       ("" if self.agent.service_mode else " (richiede modalita' servizio)")})

    async def close(self, notify=True, reason=None):
        if self.agent.sessions.get(self.sid) is not self:
            return
        self.agent.sessions.pop(self.sid, None)
        self.revoked = True
        if self.lease_timer:
            self.lease_timer.cancel()
        if self.inventory_channel:
            self.inventory_channel.close()
        if notify:
            self.send({"t": "bye", "reason": reason} if reason else {"t": "bye"})
        if self.mode == "control" and self.agent._injector is not None:
            self.agent._injector.release_all()
        if self.agent.block_owner == self.sid:
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
        if self.files:
            await self.files.wait_closed()
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
        self.pending_approvals = {}
        self.active_prompts = 0
        self.events = []
        self._injector = None
        self.clipboard = Clipboard()
        self.stop_event = asyncio.Event()
        self.cloned = self._check_clone()
        self._migrate()
        self.nets = {}             # nid -> Network
        self.mkey = auth.load_machine_key(data_dir)
        self.mpub = auth.pub_of(self.mkey)
        self.logins = {}
        self.leases = {}
        self.local_token = auth.secrets.token_urlsafe(32)
        self.audit = Audit(data_dir)
        self.block_owner = None
        self.seen_sids = {}        # anti-replay delle offerte, comune a tutte le reti
        self.outgoing = {}         # (rete, macchina) -> ultimo segnale da una finestra di sessione aperta qui
        self.updater = Updater(self)
        self.console_seen = 0      # ultima volta che una console locale ha chiesto lo stato
        self.updating = False
        self.port = 0
        self.chat = []             # messaggi chat (in memoria)
        self.chat_seq = 0
        self.chat_seen = 0         # ultimo segnale di vita della finestra chat locale
        self.chat_read = {}        # sid -> ultimo messaggio letto
        self.fail = []
        self.login_busy = 0

    # ------------------------------------------------------------------ utilita'
    def injector(self):
        if self._injector is None:
            self._injector = Injector(service_mode=self.service_mode)
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
        """Configurazione 2.0/2.1 (una sola rete) -> elenco di reti; server di segnalazione multipli (2.3.1)."""
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
        for key, lease in list(self.leases.items()):
            if lease["net"] is not net:
                continue
            grant, peer = lease["grant"], lease["peer"]
            if (net.conflict or getattr(net, "leaving", False)
                    or (net.reg.machines().get(peer) or {}).get("pub") != lease["pub"]
                    or (net.reg.machines().get(self.cfg["id"]) or {}).get("pub") != self.mpub
                    or (net.reg.user(grant["user"]) or {}).get("pub") != auth.pub_of(grant["priv"])
                    or auth.MODE_RIGHTS[lease["mode"]] not in net.reg.rights(grant["user"], peer)):
                self.leases.pop(key, None)
        for future, target, mode, target_pub, user, user_pub in net.pending.values():
            if not future.done() and (net.conflict or getattr(net, "leaving", False)
                    or auth.MODE_RIGHTS[mode] not in net.reg.rights(user, target)
                    or (net.reg.user(user) or {}).get("pub") != user_pub
                    or (net.reg.machines().get(target) or {}).get("pub") != target_pub
                    or (net.reg.machines().get(self.cfg["id"]) or {}).get("pub") != self.mpub):
                future.set_exception(RuntimeError("Autorizzazione di sessione revocata"))
        for session in list(self.pending_approvals.values()):
            if session.net is net:
                session.refresh_authorization()
        for session in list(self.sessions.values()):
            if session.net is not net:
                continue
            allowed = session.refresh_authorization()
            if self.block_owner == session.sid and not session.perms()["block_input"]:
                self.block_owner = None
                self.injector().set_block(False)
            if session.files:
                if "files" not in session.rights:
                    session.files.close()
                elif session.lease_active():
                    session.files.recheck_permissions()
            if not allowed:
                asyncio.create_task(session.close(reason="revoked"))
            else:
                session.send_info()

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
        signed = n.reg.signed_update(u, priv, mut)
        self.nets[nid] = n
        n.apply_registry(signed)
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
            if (("network" in reg.doc and reg.doc["network"].strip().lower() != name.lower())
                    or (reg.user(admin) or {}).get("pub") != auth.pub_of(priv)):
                raise RuntimeError("Identità della rete o dell'amministratore cambiata")
            if nid in self.nets:
                raise RuntimeError("Questo PC fa gia' parte di questa rete")
            def mut(d):
                d["machines"][self.cfg["id"]] = {"pub": self.mpub, "name": pcname or self.cfg["name"]}
            signed = reg.signed_update(auth.norm_user(admin), priv, mut)
            if not reg.check_new(signed):
                raise RuntimeError("Registrazione del dispositivo non valida")
        except BaseException:
            n.stop()
            raise
        if pcname:
            self.cfg.update(name=pcname)
        n.reg = reg
        n.entry["history"] = reg.trusted_history
        self.nets[nid] = n
        n.apply_registry(signed)
        await n.publish_registry()
        for other in self.nets.values():  # annuncio subito nome e versione del registro aggiornati
            asyncio.ensure_future(other._safe_presence())
        asyncio.ensure_future(n._safe_publish({"type": "hello"}, delay=1))   # le altre macchine si ripresentano
        return n, priv

    async def leave_network(self, nid, lg=None):
        n = self.net(nid)
        n.leaving = True
        self.registry_changed(n)
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
        from .ice import servers
        return [RTCIceServer(**server) for server in servers(self.cfg)]

    def ice_for_browser(self):
        from .ice import servers
        return servers(self.cfg)

    def logged_user(self):
        if WIN and self.service_mode:
            return W.session_user(W.process_session())
        return current_user()

    def user_home(self):
        if WIN and self.service_mode:
            return W.session_profile_dir(W.process_session())
        return os.path.expanduser("~")

    def incoming_dir(self):
        if self.cfg["incoming_dir"]:
            return self.cfg["incoming_dir"]
        home = self.user_home()
        return os.path.join(home, "Downloads") if home else ""

    def set_clipboard(self, text):
        try:
            self.clipboard.set(text)
        except Exception as e:
            log.debug("clip set: %s", e)

    # ------------------------------------------------------------------ sessioni in ingresso
    def verified_offer(self, net, m):
        user, peer, mode = m.get("user"), m.get("frm"), m.get("mode")
        if (m.get("protocol") != auth.SESSION_PROTOCOL or not isinstance(mode, str) or mode not in auth.MODE_RIGHTS
                or not isinstance(user, str) or not (0 < len(user) <= 500) or auth.norm_user(user) != user
                or not isinstance(peer, str) or not re.fullmatch(r"[0-9]{9}", peer)
                or not isinstance(m.get("sid"), str) or not re.fullmatch(r"[0-9a-f]{32}", m["sid"])
                or type(m.get("uts")) is not int or abs(time.time() - m["uts"]) > 120
                or not isinstance(m.get("sdp"), str) or not (0 < len(m["sdp"]) <= 256 * 1024)
                or m.get("to") != self.cfg["id"]):
            return False
        operator, machine = net.reg.user(user), net.reg.machines().get(peer)
        if not operator or not machine:
            return False
        body = auth.offer_body(net.nid, m)
        return (auth.verify(machine.get("pub"), body, m.get("msig", ""))
                and auth.verify(operator.get("pub"), body, m.get("usig", "")))

    async def request_consent(self, session, text):
        # Pause existing inputs before showing a dialog reachable on the desktop.
        loop = asyncio.get_running_loop()
        injector = self._injector
        self.active_prompts += 1
        self.block_owner = None

        def show():
            try:
                if injector:
                    injector.pause_and_drain()
                if session.revoked or self.pending_approvals.get(session.sid) is not session:
                    return False
                return W.message_box(text, "RemoteDesk - richiesta di accesso", True, 30000)
            finally:
                if injector:
                    injector.resume()

        future = loop.run_in_executor(None, show)
        def finished(done):
            self.active_prompts -= 1
            if not done.cancelled():
                done.exception()
        future.add_done_callback(finished)
        # If the connection disappears, keep input blocked until the actual dialog has closed.
        return await asyncio.shield(future)

    async def accept_offer(self, net, m):
        if not self.verified_offer(net, m):
            raise RuntimeError("Identità del dispositivo o dell'operatore non valida")
        if len(self.sessions) + len(self.pending_approvals) >= 8:
            raise RuntimeError("Limite di sessioni raggiunto")
        machine = net.reg.machines()[m["frm"]]
        s = Session(self, net, dict(m, name=str(machine.get("name") or fmt_id(m["frm"]))[:80]))
        if not s.refresh_authorization():
            self.audit.add("auth_fail", net=net.nid, user=s.user, peer=s.peer, mode=s.mode, why="permesso mancante")
            raise RuntimeError("Sessione non autorizzata dai permessi utente e dalle impostazioni del PC")
        session_policy.validate_sdp(m["sdp"], s.mode)
        self.pending_approvals[s.sid] = s
        try:
            if self.service_mode:
                from .win_identity import interactive_logon
                s.windows_logon = interactive_logon()
            if self.cfg["ask_confirm"] or s.mode == "manage":
                if not WIN:
                    raise RuntimeError("Conferma locale non disponibile su questo sistema")
                details = session_policy.prompt_capabilities(s.rights)
                who = f"{s.display_user()} ({s.user}) da {s.peer_name} (ID {fmt_id(s.peer)})"
                ok = await self.request_consent(s, f"{who} chiede di {details}.\n\nConsentire?")
                if not ok:
                    self.audit.add("auth_fail", net=net.nid, user=s.user, peer=s.peer, why="consenso rifiutato")
                    raise RuntimeError("Accesso rifiutato dall'utente remoto")
                if s.windows_logon is not None and interactive_logon() != s.windows_logon:
                    raise RuntimeError("È cambiato l'utente locale durante la conferma")
            if not s.refresh_authorization():
                raise RuntimeError("Autorizzazione revocata durante la conferma")
        finally:
            self.pending_approvals.pop(s.sid, None)
        self.sessions[s.sid] = s
        s.set_lease_deadline(time.monotonic() + 60)
        try:
            sdp = await s.start(m["sdp"])
            if self.sessions.get(s.sid) is not s or not s.refresh_authorization():
                raise RuntimeError("Autorizzazione revocata durante la connessione")
            session_policy.validate_sdp(sdp, s.mode)
        except BaseException:
            await s.close(notify=False)
            raise
        asyncio.get_running_loop().call_later(40, lambda: asyncio.create_task(self._drop_if_stale(s)))
        return sdp

    async def _drop_if_stale(self, s):
        if s.sid in self.sessions and not s.connected:
            await s.close()

    # ------------------------------------------------------------------ login (uno per rete)
    async def login(self, tok, nid, user, password):
        n = self.net(nid)
        now = time.monotonic()
        self.fail = [t for t in self.fail if now - t < 60]
        if len(self.fail) >= 10 or self.login_busy >= 2:
            raise RuntimeError("Troppi tentativi. Riprova tra un minuto.")
        if not isinstance(password, str) or not 1 <= len(password) <= 1024 or not isinstance(user, str) or not 1 <= len(user) <= 64:
            raise RuntimeError("Utente o password non validi")
        self.login_busy += 1
        try:
            priv = await n.derive(user, password)
        finally:
            self.login_busy -= 1
        u = n.reg.user(user)
        if self.nets.get(nid) is not n or not u or auth.pub_of(priv) != u["pub"]:
            self.fail.append(now)
            self.audit.add("login_fail", net=nid, user=auth.norm_user(user), where="console")
            raise RuntimeError("Utente o password non validi")
        self.log_event(f"Login di {auth.norm_user(user)} sulla console (rete {n.name})")
        return self.add_login(tok, nid, user, priv)

    IDLE = 2 * 3600

    def add_login(self, tok, nid, user, priv):
        grants = self.get_login(tok).copy()
        self.logins.pop(tok, None)
        now = time.monotonic()
        grants[nid] = {"user": auth.norm_user(user), "priv": priv, "exp": now + 12 * 3600, "act": now}
        if len(self.logins) >= 128:
            self.logins.pop(next(iter(self.logins)))
        token = auth.secrets.token_urlsafe(32)
        self.logins[token] = {"nets": grants}
        return token

    def get_login(self, tok, touch=False):
        record = self.logins.get(tok)
        if record is None:
            return {}
        now = time.monotonic()
        grants = record["nets"]
        for nid, grant in list(grants.items()):
            n = self.nets.get(nid)
            u = n.reg.user(grant["user"]) if n else None
            if (not u or auth.pub_of(grant["priv"]) != u["pub"] or now >= grant["exp"]
                    or now - grant["act"] >= self.IDLE):
                del grants[nid]
            elif touch == nid:
                grant["act"] = now
        if not grants:
            self.logins.pop(tok, None)
        return grants

    def logout(self, tok, nid=None):
        record = self.logins.get(tok)
        if record:
            if nid:
                record["nets"].pop(nid, None)
            else:
                self.logins.pop(tok, None)

    def issue_lease(self, net, grant, peer, mode, remote_sid):
        now = time.monotonic()
        self.leases = {key: entry for key, entry in self.leases.items() if entry["until"] > now}
        if len(self.leases) >= 128:
            raise ValueError("Troppe sessioni aperte")
        key = auth.secrets.token_urlsafe(32)
        self.leases[key] = {"net": net, "grant": grant, "peer": peer, "mode": mode, "sid": remote_sid,
                            "pub": net.reg.machines()[peer]["pub"], "until": now + 60}
        return key

    def check_lease(self, token, key):
        entry = self.leases.get(key) if isinstance(key, str) else None
        if not entry:
            return None
        net, grant, peer = entry["net"], entry["grant"], entry["peer"]
        now = time.monotonic()
        if self.get_login(token).get(net.nid) is not grant:
            return None
        machines = net.reg.machines()
        if (entry["until"] <= now or self.nets.get(net.nid) is not net or net.conflict or getattr(net, "leaving", False)
                or machines.get(peer, {}).get("pub") != entry["pub"]
                or machines.get(self.cfg["id"], {}).get("pub") != self.mpub
                or auth.MODE_RIGHTS[entry["mode"]] not in net.reg.rights(grant["user"], peer)):
            self.leases.pop(key, None)
            return None
        entry["until"] = now + 30
        return entry

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
        s = self.sessions.get(sid) if isinstance(sid, str) else None
        if (not s or not s.connected or s.mode not in ("view", "control")
                or not s.lease_active() or not s.refresh_authorization()):
            raise RuntimeError("Seleziona un tecnico collegato")
        s.send({"t": "chat", "text": text, "name": name})
        self._chat_push(s, "local", text, name)

    def chat_unread(self):
        return sum(1 for m in self.chat if m["who"] == "tech" and m["sid"] in self.sessions
                   and m["id"] > self.chat_read.get(m["sid"], 0))

    # ------------------------------------------------------------------ registro accessi in rete
    async def audit_query(self, net, lg, since, until):
        """Interroga tutte le macchine della rete (richiesta firmata, risposte cifrate per noi)."""
        def authorized():
            return (lg and self.nets.get(net.nid) is net and not net.conflict and not getattr(net, "leaving", False)
                    and net.reg.is_admin(lg["user"]) and net.reg.user(lg["user"])["pub"] == auth.pub_of(lg["priv"])
                    and (net.reg.machines().get(self.cfg["id"]) or {}).get("pub") == self.mpub)
        if not authorized() or len(net.audit_waiters) >= 4:
            raise RuntimeError("Consultazione del registro non disponibile")
        from . import audit as A
        priv, epub = A.new_ephemeral()
        rid = auth.secrets.token_hex(12)
        body = {"type": "auditreq", "protocol": auth.SESSION_PROTOCOL, "net": net.nid, "frm": self.cfg["id"],
                "to": "*", "rid": rid, "user": lg["user"], "since": int(since), "until": int(until),
                "epub": epub, "ats": int(time.time())}
        waiter = {"responses": {}, "size": 0}
        net.audit_waiters[rid] = waiter
        try:
            await net.publish(dict(body, sig=auth.sign(lg["priv"], body), msig=auth.sign(self.mkey, body)))
            await asyncio.sleep(7)
        finally:
            net.audit_waiters.pop(rid, None)
        if not authorized():
            raise RuntimeError("Autorizzazione al registro revocata")
        results = {self.cfg["id"]: {"name": self.cfg["name"], "entries": self.audit.query(since, until, net=net.nid)}}
        for frm, (pub, box) in waiter["responses"].items():
            machine = net.reg.machines().get(frm) or {}
            if machine.get("pub") != pub:
                continue
            try:
                data = A.open_with(priv, box)
            except Exception:
                continue
            if isinstance(data, dict) and isinstance(data.get("entries"), list):
                results[frm] = {"name": machine.get("name"), "entries": [
                    A.Audit.minimize(e) for e in data["entries"][:5000] if isinstance(e, dict) and e.get("net") == net.nid]}
        return results

    def verified_audit_request(self, net, m):
        if (net.conflict or self.nets.get(net.nid) is not net or getattr(net, "leaving", False)
                or (net.reg.machines().get(self.cfg["id"]) or {}).get("pub") != self.mpub
                or m.get("type") != "auditreq" or m.get("protocol") != auth.SESSION_PROTOCOL
                or m.get("net") != net.nid or m.get("to") != "*"
                or type(m.get("ats")) is not int or abs(time.time() - m["ats"]) > 120
                or not isinstance(m.get("rid"), str) or not re.fullmatch(r"[0-9a-f]{24}", m["rid"])
                or not isinstance(m.get("epub"), str) or len(m["epub"]) != 44
                or any(type(m.get(k)) is not int or not 0 <= m[k] < 2**53 for k in ("since", "until"))
                or not isinstance(m.get("user"), str) or not net.reg.is_admin(m["user"])):
            return False
        machine = net.reg.machines().get(m["frm"])
        body = {k: m[k] for k in ("type", "protocol", "net", "frm", "to", "rid", "user", "since", "until", "epub", "ats")}
        return bool(machine and auth.verify(machine["pub"], body, m.get("msig", ""))
                    and auth.verify(net.reg.user(m["user"])["pub"], body, m.get("sig", "")))

    async def audit_answer(self, net, m):
        from . import audit as A
        if not self.verified_audit_request(net, m):
            return
        def read():
            entries = self.audit.query(m["since"], m["until"], net=net.nid)
            while True:
                box = A.seal_for(m["epub"], {"name": self.cfg["name"], "entries": entries})
                if len(box["c"]) <= 512 * 1024:
                    return box
                entries = entries[len(entries) // 2 + 1:]
        try:
            box = await asyncio.get_running_loop().run_in_executor(None, read)
            if not self.verified_audit_request(net, m):
                return
            body = auth.audit_reply_body(net.nid, self.cfg["id"], m["frm"], m["rid"], box)
            await net._safe_publish(dict(body, box=box, msig=auth.sign(self.mkey, body)))
        except (OSError, ValueError):
            log.warning("Risposta al registro non disponibile")

    async def close_sessions(self, sid=None, reason=None):
        for s in list(self.pending_approvals.values()):
            if sid is None or s.sid == sid:
                s.revoked = True
                s.rights.clear()
        for s in list(self.sessions.values()):
            if sid is None or s.sid == sid:
                await s.close(reason=reason)

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
                if s.can_view() and s.cursor_key != key:
                    s.cursor_key = key
                    s.send(msg)



    async def housekeeping(self):
        while True:
            await asyncio.sleep(120)
            for token in list(self.logins):
                self.get_login(token)
            self.chat_read = {sid: value for sid, value in self.chat_read.items() if sid in self.sessions}
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
        # con "update" le finestre di sessione non si chiudono: continuano a riprovare finche' torno
        await self.close_sessions(reason="update" if self.updating else None)
        if self._injector is not None:
            await asyncio.to_thread(self._injector.close)
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


def open_console(port, path="/", size=(1180, 780), pos=None, data_dir=None, desktop_only=False, *, owner_only=False):
    from .local_access import open_ticket
    try:
        url = open_ticket(port, path, data_dir=data_dir, desktop_only=desktop_only, owner_only=owner_only)
    except OSError:
        log.warning("Impossibile verificare l'identità dell'agente locale")
        return
    if WIN:
        b = W.find_browser()
        if b:
            prof = (os.path.join(data_dir, "browser") if owner_only else
                    os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "RemoteDesk", "browser"))
            args = [b, f"--app={url}", f"--user-data-dir={prof}", "--no-first-run",
                    "--no-default-browser-check", f"--window-size={size[0]},{size[1]}"]
            if pos:
                args.append(f"--window-position={pos[0]},{pos[1]}")
            subprocess.Popen(args, creationflags=W.CREATE_NO_WINDOW)
            return
    import webbrowser
    webbrowser.open(url)


def open_chat_window(port, data_dir=None, desktop_only=False, *, owner_only=False):
    w, h = 380, 560
    pos = None
    if WIN:
        l, t, r, b = W.work_area()
        pos = (r - w - 12, b - h - 12)
    open_console(port, "/chat", (w, h), pos, data_dir, desktop_only, owner_only=owner_only)
