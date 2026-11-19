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
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape

from aiohttp import ClientSession, ClientTimeout

from . import auth
from .common import DEFAULT_PORT, INSTALL_DIR, PROGRAM_DATA, ROOT_DIR, VERSION, WIN, secure_dir
from .release_package import MAX_PACKAGE, extract_package, https_url, validate_manifest, version_tuple
from .updater import acknowledge_start, clear_finished_stages, plain_path, stage_root, system_tool

log = logging.getLogger("rd.update")

RELEASE_PUB = "jcnWg1NX5p1JIB/bSvlcKQZjzrT+xb8WoVdxFJ+noVQ="
DEFAULT_URL = "https://raw.githubusercontent.com/tbkon3/remote-desk-tbk/main/dist/latest.json"
CHECK_EVERY = 6 * 3600


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
        self.checked_at = 0
        self.checked_url = None
        self.lock = asyncio.Lock()

    @property
    def url(self):
        u = self.agent.cfg.get("update_url")
        return DEFAULT_URL if u is None else u

    def available(self):
        return bool(self.info and self.url and self.url == self.checked_url
                    and time.monotonic() - self.checked_at <= CHECK_EVERY
                    and self.info.get("expires", 0) > time.time()
                    and version_tuple(self.info["version"]) > version_tuple(VERSION))

    def status(self):
        return {"current": VERSION, "latest": (self.info or {}).get("version"), "available": self.available(),
                "notes": (self.info or {}).get("notes", ""), "state": self.state, "error": self.error,
                "progress": self.progress, "last_check": int(self.last_check), "enabled": bool(self.url),
                "auto": bool(self.agent.cfg.get("auto_update")), "supported": WIN}

    # ------------------------------------------------------------------ controllo
    async def check(self):
        async with self.lock:
            if self.state == "installing":
                return None
            return await self._check()

    async def _check(self):
        self.info = self.checked_url = None
        url = self.url
        if not url:
            self.state, self.error = "idle", ""
            return None
        self.state, self.error = "checking", ""
        try:
            async with ClientSession(timeout=ClientTimeout(total=30), trust_env=True) as s:
                async with s.get(https_url(url), headers={"Cache-Control": "no-cache"}, allow_redirects=False) as r:
                    if r.status != 200:
                        raise RuntimeError(f"HTTP {r.status}")
                    raw = bytearray()
                    async for chunk in r.content.iter_chunked(8192):
                        if len(raw) + len(chunk) > 65536:
                            raise ValueError("manifesto troppo grande")
                        raw.extend(chunk)
                    m = json.loads(raw)
            if not verify_manifest(m):
                raise RuntimeError("manifesto NON firmato con la chiave di rilascio: ignorato")
            validate_manifest(m, VERSION, time.time())
            if self.url != url:
                raise RuntimeError("sorgente aggiornamenti cambiata")
            version = version_tuple(m["version"])
            highest = self.agent.cfg.get("update_highest", VERSION)
            if version < version_tuple(highest) and highest != VERSION:
                raise ValueError("rilascio precedente all'ultimo manifesto verificato")
            if version > version_tuple(highest):
                self.agent.cfg.update(update_highest=m["version"])
            self.info = m
            self.checked_url, self.checked_at = url, time.monotonic()
            self.state = "idle"
        except Exception as e:
            self.state, self.error = "error", f"Controllo aggiornamenti non riuscito: {e}"
            log.warning(self.error)
        self.last_check = time.time()
        return self.info

    async def loop(self):
        acknowledge_start(self.agent.data_dir, ROOT_DIR, VERSION)
        await asyncio.sleep(60)
        while True:
            try:
                await self.check()
                if self.available() and self.agent.cfg.get("auto_update") and WIN and self._maintenance_allowed(True):
                    await self.install("automatico", automatic=True)
            except Exception:
                log.exception("tentativo automatico non riuscito")
            await asyncio.sleep(CHECK_EVERY)

    # ------------------------------------------------------------------ installazione
    def staging_root(self):
        base = PROGRAM_DATA if self.agent.service_mode else self.agent.data_dir
        return stage_root(base, self.agent.service_mode)

    def _maintenance_allowed(self, automatic):
        if self.agent.cfg.get("on_air"):
            return False
        if not automatic:
            return True
        return (self.agent.cfg.get("auto_update") and not self.agent.sessions
                and not self.agent.pending_approvals and not any(net.pending for net in self.agent.nets.values())
                and not any(lease["until"] > time.monotonic() for lease in self.agent.leases.values()))

    async def install(self, who, *, automatic=False):
        if not WIN:
            raise RuntimeError("Aggiornamento automatico disponibile solo su Windows")
        if self.lock.locked() or self.state == "installing":
            raise RuntimeError("Controllo o aggiornamento gia' in corso")
        async with self.lock:
            return await self._install(who, automatic)

    async def _install(self, who, automatic):
        if not self._maintenance_allowed(automatic):
            raise RuntimeError("Manutenzione sospesa")
        await self._check()
        if not self.available():
            raise RuntimeError("Nessun aggiornamento disponibile")
        info = dict(self.info)
        self.state, self.error, self.progress = "downloading", "", 0
        stage_dir = None
        try:
            base = self.staging_root()
            target = INSTALL_DIR if self.agent.service_mode else ROOT_DIR
            if Path(base).resolve().is_relative_to(Path(target).resolve()):
                raise RuntimeError("I dati aggiornamento devono essere esterni alla cartella applicazione")
            if self.agent.service_mode:
                candidate = os.path.join(base, "release-" + secrets.token_hex(16))
                secure_dir(candidate)
                stage_dir = candidate
            else:
                os.makedirs(base, exist_ok=True)
            base = os.fspath(plain_path(base))
            clear_finished_stages(base)
            if stage_dir is None:
                stage_dir = tempfile.mkdtemp(prefix="release-", dir=base)
            staged = await self._download_and_stage(info, stage_dir)
            if not self.available() or not self._maintenance_allowed(automatic):
                raise RuntimeError("Aggiornamento sospeso prima dell'installazione")
            self.state = "installing"
            self.agent.log_event(f"Aggiornamento a RemoteDesk {info['version']} avviato ({who})")
            self.agent.audit.add("update", user=who, version=info["version"], old=VERSION)
            self._launch_updater(staged, info["version"])
            stage_dir = None  # l'installatore usa la copia fino al termine
        except Exception as e:
            self.state, self.error = "error", f"Aggiornamento non riuscito: {e}"
            log.exception(self.error)
            raise RuntimeError(self.error)
        finally:
            if stage_dir:
                shutil.rmtree(stage_dir, ignore_errors=True)
        # il programma di aggiornamento chiudera' questo processo: avviso le sessioni e mi fermo
        try:
            for s in list(self.agent.sessions.values()):
                s.send({"t": "notice", "reason": "update", "text": f"Il PC remoto si aggiorna a RemoteDesk {info['version']}. "
                         "La sessione verrà interrotta. Per ricollegarti servono versioni compatibili e un accesso valido alla rete."})
        finally:
            self.agent.updating = True
            self.agent.stop_event.set()

    async def _download_and_stage(self, info, root):
        https_url(info["url"])
        size = int(info["size"])
        if not 0 < size <= MAX_PACKAGE:
            raise RuntimeError("dimensione non valida")
        zpath = os.path.join(root, "pacchetto.zip")
        h = hashlib.sha256()
        got = 0
        async with ClientSession(timeout=ClientTimeout(total=1800, sock_read=120), trust_env=True) as s:
            async with s.get(info["url"], allow_redirects=False) as r:
                if r.status != 200:
                    raise RuntimeError(f"download HTTP {r.status}")
                with open(zpath, "xb") as f:
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
            staged = extract_package(zpath, dest)
            os.remove(zpath)
            return staged
        job = asyncio.get_running_loop().run_in_executor(None, extract)
        try:
            return await asyncio.shield(job)
        except asyncio.CancelledError:
            try:
                await job
            finally:
                raise

    def _launch_updater(self, staged, version):
        from . import winapi as W
        pyw = os.path.join(staged, "runtime", "pythonw.exe")
        script = os.path.join(staged, "app", "rd", "updater.py")
        logf = os.path.join(self.agent.data_dir, "logs", "update.log")
        if self.agent.service_mode:
            # attivita' SYSTEM separata: sopravvive all'arresto del servizio che sta per essere aggiornato
            args = (f'-I "{script}" --mode service --target "{INSTALL_DIR}" --source "{staged}" '
                    f'--port {DEFAULT_PORT} --version {version} --log "{logf}"')
            xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>{escape(pyw)}</Command><Arguments>{escape(args)}</Arguments>
  <WorkingDirectory>{escape(staged)}</WorkingDirectory></Exec></Actions>
</Task>"""
            fd, x = tempfile.mkstemp(suffix=".xml", dir=os.path.dirname(staged))
            os.close(fd)
            with open(x, "w", encoding="utf-16") as f:
                f.write(xml)
            scheduler = system_tool("schtasks.exe")
            try:
                r = W.run_hidden([scheduler, "/Create", "/TN", "RemoteDeskUpdate", "/XML", x, "/F"])
            finally:
                os.remove(x)
            if r.returncode != 0:
                raise RuntimeError("creazione attivita' di aggiornamento: " + (r.stderr or r.stdout))
            r = W.run_hidden([scheduler, "/Run", "/TN", "RemoteDeskUpdate"])
            if r.returncode != 0:
                W.run_hidden([scheduler, "/Delete", "/TN", "RemoteDeskUpdate", "/F"])
                raise RuntimeError("avvio aggiornamento: " + (r.stderr or r.stdout))
        else:
            # cartella dell'utente: nessun permesso speciale; il processo e' staccato da questo
            if not os.access(ROOT_DIR, os.W_OK):
                raise RuntimeError(f"la cartella {ROOT_DIR} non e' modificabile da questo utente")
            flags = 0x00000008 | 0x00000200 | W.CREATE_NO_WINDOW   # DETACHED, NEW_PROCESS_GROUP
            cmd = [pyw, "-I", script, "--mode", "user", "--target", ROOT_DIR, "--source", staged,
                   "--port", str(self.agent.port), "--version", version, "--log", logf, "--pid", str(os.getpid()),
                   "--args", json.dumps([a for a in sys.argv[1:] if a != "--minimized"])]
            try:
                subprocess.Popen(cmd, creationflags=flags | 0x01000000, close_fds=True, cwd=staged)  # fuori dal job
            except OSError:
                subprocess.Popen(cmd, creationflags=flags, close_fds=True, cwd=staged)
