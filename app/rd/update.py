"""Aggiornamenti automatici.

Il manifesto (dist/latest.json nella repository) e' FIRMATO con la chiave di rilascio Ed25519
(la privata resta al manutentore, la pubblica e' qui sotto): un PC installa solo pacchetti il cui
manifesto e' firmato e il cui zip corrisponde all'impronta SHA-256 indicata nel manifesto.

L'installazione vera e propria la fa rd/updater.py, avviato dalla copia NUOVA scaricata:
ferma RemoteDesk (o il servizio), sostituisce i file, riavvia e, se la nuova versione non
risponde, torna alla precedente."""
import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from xml.sax.saxutils import escape

from aiohttp import ClientSession, ClientTimeout

from . import auth
from .common import DEFAULT_PORT, INSTALL_DIR, PROGRAM_DATA, ROOT_DIR, VERSION, WIN

log = logging.getLogger("rd.update")

RELEASE_PUB = "jcnWg1NX5p1JIB/bSvlcKQZjzrT+xb8WoVdxFJ+noVQ="
DEFAULT_URL = "https://raw.githubusercontent.com/tbkon3/remote-desk-tbk/main/dist/latest.json"
CHECK_EVERY = 6 * 3600
MAX_SIZE = 300 * 1024 * 1024


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4]) or (0,)


def verify_manifest(m):
    if not isinstance(m, dict) or not isinstance(m.get("sig"), str):
        return False
    body = {k: v for k, v in m.items() if k != "sig"}
    return auth.verify(RELEASE_PUB, body, m["sig"])


class Updater:
    def __init__(self, agent):
        self.agent = agent
        self.info = None          # ultimo manifesto valido
        self.state = "idle"       # idle | checking | downloading | installing | error
        self.error = ""
        self.progress = 0
        self.last_check = 0

    @property
    def url(self):
        u = self.agent.cfg.get("update_url")
        return DEFAULT_URL if u is None else u

    def available(self):
        return bool(self.info and vtuple(self.info["version"]) > vtuple(VERSION))

    def status(self):
        return {"current": VERSION, "latest": (self.info or {}).get("version"), "available": self.available(),
                "notes": (self.info or {}).get("notes", ""), "state": self.state, "error": self.error,
                "progress": self.progress, "last_check": int(self.last_check), "enabled": bool(self.url),
                "auto": bool(self.agent.cfg.get("auto_update")), "supported": WIN}

    # ------------------------------------------------------------------ controllo
    async def check(self):
        if not self.url:
            return None
        self.state, self.error = "checking", ""
        try:
            async with ClientSession(timeout=ClientTimeout(total=30), trust_env=True) as s:
                async with s.get(self.url, headers={"Cache-Control": "no-cache"}) as r:
                    if r.status != 200:
                        raise RuntimeError(f"HTTP {r.status}")
                    m = json.loads(await r.content.read(64 * 1024))
            if not verify_manifest(m):
                raise RuntimeError("manifesto NON firmato con la chiave di rilascio: ignorato")
            for k in ("version", "url", "sha256", "size"):
                if k not in m:
                    raise RuntimeError(f"manifesto incompleto ({k})")
            self.info = m
            self.state = "idle"
        except Exception as e:
            self.state, self.error = "error", f"Controllo aggiornamenti non riuscito: {e}"
            log.warning(self.error)
        self.last_check = time.time()
        return self.info

    async def loop(self):
        await asyncio.sleep(60)
        while True:
            await self.check()
            if self.available() and self.agent.cfg.get("auto_update") and WIN and \
                    not any(s.connected for s in self.agent.sessions.values()):
                log.info("aggiornamento automatico a %s", self.info["version"])
                await self.install("automatico")
            await asyncio.sleep(CHECK_EVERY)

    # ------------------------------------------------------------------ installazione
    def staging_root(self):
        base = PROGRAM_DATA if self.agent.service_mode else self.agent.data_dir
        return os.path.join(base, "update")

    async def install(self, who):
        if not WIN:
            raise RuntimeError("Aggiornamento automatico disponibile solo su Windows")
        if self.state in ("downloading", "installing"):
            raise RuntimeError("Aggiornamento gia' in corso")
        if not self.available():
            await self.check()
        if not self.available():
            raise RuntimeError("Nessun aggiornamento disponibile")
        info = dict(self.info)
        self.state, self.error, self.progress = "downloading", "", 0
        try:
            staged = await self._download_and_stage(info)
            self.state = "installing"
            self.agent.log_event(f"Aggiornamento a RemoteDesk {info['version']} avviato ({who})")
            self.agent.audit.add("update", user=who, version=info["version"], old=VERSION)
            await asyncio.get_running_loop().run_in_executor(None, self._launch_updater, staged, info["version"])
        except Exception as e:
            self.state, self.error = "error", f"Aggiornamento non riuscito: {e}"
            log.exception(self.error)
            raise RuntimeError(self.error)
        # il programma di aggiornamento chiudera' questo processo: avviso le sessioni e mi fermo
        for s in list(self.agent.sessions.values()):
            s.send({"t": "notice", "text": f"Il PC remoto si sta aggiornando a RemoteDesk {info['version']}: "
                                           "la sessione si ricollega da sola tra poco."})
        await asyncio.sleep(1.5)
        self.agent.updating = True
        self.agent.stop_event.set()

    async def _download_and_stage(self, info):
        root = self.staging_root()
        shutil.rmtree(root, ignore_errors=True)   # residui di aggiornamenti precedenti
        os.makedirs(root, exist_ok=True)
        if not str(info["url"]).startswith("https://") and not os.environ.get("RD_UPDATE_ALLOW_HTTP"):
            raise RuntimeError("indirizzo di download non sicuro")
        size = int(info["size"])
        if not 0 < size <= MAX_SIZE:
            raise RuntimeError("dimensione non valida")
        zpath = os.path.join(root, "pacchetto.zip")
        h = hashlib.sha256()
        got = 0
        async with ClientSession(timeout=ClientTimeout(total=1800, sock_read=120), trust_env=True) as s:
            async with s.get(info["url"]) as r:
                if r.status != 200:
                    raise RuntimeError(f"download HTTP {r.status}")
                with open(zpath, "wb") as f:
                    async for chunk in r.content.iter_chunked(256 * 1024):
                        got += len(chunk)
                        if got > size:
                            raise RuntimeError("file piu' grande del previsto")
                        h.update(chunk)
                        f.write(chunk)
                        self.progress = int(got * 100 / size)
        if got != size or h.hexdigest() != str(info["sha256"]).lower():
            raise RuntimeError("impronta del pacchetto non corrispondente: scartato")
        dest = os.path.join(root, "nuovo")

        def extract():
            with zipfile.ZipFile(zpath) as z:
                z.extractall(dest)   # zipfile scarta percorsi assoluti e '..'
            os.remove(zpath)
            staged = os.path.join(dest, "RemoteDesk")
            for need in (r"runtime\pythonw.exe", r"app\remotedesk.py", r"app\rd\updater.py", "RemoteDesk.exe"):
                if not os.path.exists(os.path.join(staged, need)):
                    raise RuntimeError(f"pacchetto incompleto ({need})")
            return staged
        return await asyncio.get_running_loop().run_in_executor(None, extract)

    def _launch_updater(self, staged, version):
        from . import winapi as W
        pyw = os.path.join(staged, "runtime", "pythonw.exe")
        script = os.path.join(staged, "app", "rd", "updater.py")
        logf = os.path.join(self.agent.data_dir, "logs", "update.log")
        if self.agent.service_mode:
            # attivita' SYSTEM separata: sopravvive all'arresto del servizio che sta per essere aggiornato
            args = (f'"{script}" --mode service --target "{INSTALL_DIR}" --source "{staged}" '
                    f'--port {DEFAULT_PORT} --version {version} --log "{logf}"')
            xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>{escape(pyw)}</Command><Arguments>{escape(args)}</Arguments>
  <WorkingDirectory>{escape(staged)}</WorkingDirectory></Exec></Actions>
</Task>"""
            fd, x = tempfile.mkstemp(suffix=".xml")
            os.close(fd)
            with open(x, "w", encoding="utf-16") as f:
                f.write(xml)
            r = W.run_hidden(["schtasks", "/Create", "/TN", "RemoteDeskUpdate", "/XML", x, "/F"])
            os.remove(x)
            if r.returncode != 0:
                raise RuntimeError("creazione attivita' di aggiornamento: " + (r.stderr or r.stdout))
            r = W.run_hidden(["schtasks", "/Run", "/TN", "RemoteDeskUpdate"])
            if r.returncode != 0:
                raise RuntimeError("avvio aggiornamento: " + (r.stderr or r.stdout))
        else:
            # cartella dell'utente: nessun permesso speciale; il processo e' staccato da questo
            if not os.access(ROOT_DIR, os.W_OK):
                raise RuntimeError(f"la cartella {ROOT_DIR} non e' modificabile da questo utente")
            flags = 0x00000008 | 0x00000200 | W.CREATE_NO_WINDOW   # DETACHED, NEW_PROCESS_GROUP
            cmd = [pyw, script, "--mode", "user", "--target", ROOT_DIR, "--source", staged,
                   "--port", str(self.agent.port), "--version", version, "--log", logf, "--pid", str(os.getpid()),
                   "--args", json.dumps([a for a in sys.argv[1:] if a != "--minimized"])]
            try:
                subprocess.Popen(cmd, creationflags=flags | 0x01000000, close_fds=True, cwd=staged)  # fuori dal job
            except OSError:
                subprocess.Popen(cmd, creationflags=flags, close_fds=True, cwd=staged)
