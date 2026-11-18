"""File manager remoto sul data channel 'files'.

Messaggi testo (JSON) per i comandi, messaggi binari = 4 byte id richiesta + dati."""
import asyncio
import json
import logging
import os
import shutil
import string
import struct
import tempfile
import threading
import zipfile

from .common import WIN

log = logging.getLogger("rd.files")
CHUNK = 16 * 1024
HIGH_WATER = 1 * 1024 * 1024


def safe_join(base, rel):
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    parts = [p.replace(":", "_") for p in parts]
    return os.path.join(base, *parts) if parts else base


def roots(agent):
    out = []
    home = agent.user_home()
    if home:
        for label, sub in (("Desktop", "Desktop"), ("Documenti", "Documents"), ("Download", "Downloads")):
            p = os.path.join(home, sub)
            if os.path.isdir(p):
                out.append({"n": label, "p": p, "d": True, "k": "fav"})
        out.append({"n": "Cartella utente", "p": home, "d": True, "k": "fav"})
    if WIN:
        drives = os.listdrives() if hasattr(os, "listdrives") else \
            [f"{c}:\\" for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]
        for d in drives:
            out.append({"n": d, "p": d, "d": True, "k": "drive"})
    else:
        out.append({"n": "/", "p": "/", "d": True, "k": "drive"})
    return out


def listdir(path):
    entries = []
    with os.scandir(path) as it:
        for e in it:
            try:
                st = e.stat(follow_symlinks=False)
                isdir = e.is_dir()
                entries.append({"n": e.name, "p": e.path, "d": isdir, "s": 0 if isdir else st.st_size,
                                "m": int(st.st_mtime)})
            except OSError:
                continue
    entries.sort(key=lambda x: (not x["d"], x["n"].lower()))
    parent = os.path.dirname(path.rstrip("\\/")) if os.path.dirname(path.rstrip("\\/")) != path else ""
    if WIN and len(path.rstrip("\\")) <= 2:
        parent = ""
    return {"path": path, "parent": parent, "entries": entries}


def zip_dir(path, cancel):
    fd, tmp = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    tmp_real = os.path.realpath(tmp)
    tmpdir = os.path.realpath(tempfile.gettempdir())
    top = os.path.basename(path.rstrip("\\/")) or "root"
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
            for dirpath, dirnames, files in os.walk(path):
                if os.path.realpath(dirpath).startswith(tmpdir):   # mai dentro la cartella temporanea
                    dirnames[:] = []
                    continue
                for f in files:
                    if cancel.is_set():
                        raise RuntimeError("annullato")
                    full = os.path.join(dirpath, f)
                    if os.path.realpath(full) == tmp_real:
                        continue
                    try:
                        z.write(full, os.path.join(top, os.path.relpath(full, path)))
                    except Exception:
                        pass   # file bloccati o illeggibili: li salto
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return tmp
class FileServer:
    LS_CHUNK = 500

    def __init__(self, agent, session, dc):
        self.agent, self.session, self.dc = agent, session, dc
        self.uploads = {}   # rid -> {f, part, final, size, got, bad}
        self.cancel = threading.Event()
        dc.on("message", self.on_message)

    def allowed(self):
        return self.session.perms()["files"] and not self.cancel.is_set()

    def send(self, obj):
        try:
            if self.dc.readyState == "open":
                self.dc.send(json.dumps(obj))
        except Exception as e:
            log.debug("invio files fallito: %s", e)

    def audit(self, kind, **kw):
        try:
            self.agent.audit.add(kind, net=self.session.net.nid, user=self.session.user,
                                 peer_name=self.session.peer_name, **kw)
        except Exception as e:
            log.warning("registro: %s", e)

    async def io(self, fn, *a):
        """Esegue l'operazione su disco; in modalita' servizio con i diritti dell'utente collegato."""
        def run():
            if WIN and self.agent.service_mode:
                from . import winapi as W
                with W.as_session_user(W.process_session()):
                    return fn(*a)
            return fn(*a)
        return await asyncio.get_running_loop().run_in_executor(None, run)

    def on_message(self, msg):
        if isinstance(msg, (bytes, bytearray)):
            if len(msg) < 4:
                return
            rid = struct.unpack(">I", msg[:4])[0]
            up = self.uploads.get(rid)
            if not up or up["bad"]:
                return
            if not self.allowed():
                self._abort(rid, "Permesso file revocato")
                return
            try:
                up["f"].write(msg[4:])
                up["got"] += len(msg) - 4
                if up["got"] > up["size"]:
                    raise OSError("piu' dati del previsto")
            except OSError as e:
                self._abort(rid, f"Scrittura non riuscita: {e}")
            return
        try:
            m = json.loads(msg)
        except Exception:
            return
        if not isinstance(m, dict):
            return
        if not self.allowed():
            self.send({"op": "err", "rid": m.get("rid"), "msg": "Trasferimento file non consentito"})
            return
        asyncio.ensure_future(self.handle(m))

    def _abort(self, rid, msg):
        up = self.uploads.pop(rid, None)
        if up:
            up["bad"] = True
            try:
                up["f"].close()
                os.remove(up["part"])
            except OSError:
                pass
            self.audit("file_in", path=up["final"], size=up["got"], ok=False, why=msg)
        self.send({"op": "err", "rid": rid, "msg": msg})

    async def handle(self, m):
        op, rid = m.get("op"), m.get("rid")
        try:
            if op == "roots":
                self.send({"op": "roots", "rid": rid, "entries": roots(self.agent),
                           "incoming": self.agent.incoming_dir()})
            elif op == "ls":
                res = await self.io(listdir, str(m["path"]))
                ents = res["entries"]
                for k in range(0, max(len(ents), 1), self.LS_CHUNK):
                    self.send({"op": "ls", "rid": rid, "path": res["path"], "parent": res["parent"],
                               "entries": ents[k:k + self.LS_CHUNK], "more": k + self.LS_CHUNK < len(ents)})
            elif op == "mkdir":
                p = safe_join(str(m["path"]), str(m["name"]))
                await self.io(lambda: os.makedirs(p, exist_ok=True))
                self.audit("file_mkdir", path=p)
                self.send({"op": "ok", "rid": rid})
            elif op == "del":
                p = str(m["path"])
                await self.io(lambda: shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p))
                self.audit("file_del", path=p)
                self.send({"op": "ok", "rid": rid})
            elif op == "rename":
                p, name = str(m["path"]), str(m["name"])
                if not name or "/" in name or "\\" in name or name in (".", ".."):
                    raise ValueError("Nome non valido")
                dest = os.path.join(os.path.dirname(p), name.replace(":", "_"))

                def ren():
                    if os.path.lexists(dest):
                        raise FileExistsError("Esiste gia' un elemento con questo nome")
                    os.rename(p, dest)
                await self.io(ren)
                self.audit("file_ren", path=p, dest=dest)
                self.send({"op": "ok", "rid": rid})
            elif op == "get":
                await self.send_file(rid, str(m["path"]))
            elif op == "put":
                folder = str(m.get("path") or self.agent.incoming_dir())
                size = int(m.get("size") or 0)
                if size < 0:
                    raise ValueError("dimensione non valida")

                def prepare():
                    dest = safe_join(folder, str(m["name"]))
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    if os.path.exists(dest) and not m.get("overwrite"):
                        root, ext = os.path.splitext(dest)
                        n = 1
                        while os.path.exists(f"{root} ({n}){ext}"):
                            n += 1
                        dest = f"{root} ({n}){ext}"
                    part = dest + ".rdpart"
                    return dest, part, open(part, "wb")
                dest, part, f = await self.io(prepare)
                self.uploads[rid] = {"f": f, "part": part, "final": dest, "size": size, "got": 0, "bad": False}
                self.send({"op": "ready", "rid": rid, "path": dest})
            elif op == "end":
                up = self.uploads.pop(rid, None)
                if up:
                    up["f"].close()
                    if up["got"] != up["size"]:
                        os.remove(up["part"])
                        self.audit("file_in", path=up["final"], size=up["got"], ok=False, why="incompleto")
                        self.send({"op": "err", "rid": rid, "msg": "Trasferimento incompleto"})
                        return
                    await self.io(os.replace, up["part"], up["final"])
                    self.agent.log_event(f"File ricevuto: {up['final']}")
                    self.audit("file_in", path=up["final"], size=up["got"])
                    self.send({"op": "done", "rid": rid, "path": up["final"]})
            elif op == "cancel":
                up = self.uploads.pop(rid, None)
                if up:
                    up["f"].close()
                    try:
                        os.remove(up["part"])
                    except OSError:
                        pass
        except Exception as e:
            self.send({"op": "err", "rid": rid, "msg": str(e)})

    async def send_file(self, rid, path):
        loop = asyncio.get_running_loop()
        tmp = None
        orig = path
        name = os.path.basename(path.rstrip("\\/")) or "file"
        sent = size = 0
        try:
            if await self.io(os.path.isdir, path):
                tmp = await self.io(zip_dir, path, self.cancel)
                path, name = tmp, name + ".zip"
            f = await self.io(open, path, "rb")
            with f:
                size = os.fstat(f.fileno()).st_size
                self.send({"op": "meta", "rid": rid, "name": name, "size": size})
                head = struct.pack(">I", rid)
                while True:
                    data = await loop.run_in_executor(None, f.read, CHUNK)
                    if not data:
                        break
                    while self.dc.readyState == "open" and self.dc.bufferedAmount > HIGH_WATER:
                        await asyncio.sleep(0.02)
                    if self.dc.readyState != "open" or not self.allowed():
                        return
                    self.dc.send(head + data)
                    sent += len(data)
            self.send({"op": "end", "rid": rid})
        finally:
            self.audit("file_out", path=orig, size=sent, ok=sent == size and size >= 0)
            if tmp:
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    def close(self):
        self.cancel.set()
        for up in self.uploads.values():
            try:
                up["f"].close()
                os.remove(up["part"])
            except Exception:
                pass
            self.audit("file_in", path=up["final"], size=up["got"], ok=False, why="sessione chiusa")
        self.uploads.clear()
