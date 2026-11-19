"""Bounded, ordered transfers in the file area explicitly shared by this host."""
import asyncio
import contextlib
import json
import logging
import os
import shutil
import stat
import struct
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from .common import INSTALL_DIR, PROGRAM_DATA, ROOT_DIR, WIN
from .file_scope import Scope, TEMP_PREFIX, component

log = logging.getLogger("rd.files")
CHUNK = 16 * 1024
MAX_FILE = 512 * 1024 * 1024
MAX_ITEMS = 5000
MAX_QUEUE = 256
MAX_UPLOADS = 2
HIGH_WATER = 1024 * 1024
MIN_FREE = 32 * 1024 * 1024
_TRANSFER_SLOTS = threading.BoundedSemaphore(8)


class FileServer:
    def __init__(self, agent, session, dc):
        self.agent, self.session, self.dc = agent, session, dc
        self.queue = asyncio.Queue(maxsize=MAX_QUEUE)
        self.uploads = {}
        self.active_upload = None
        self.cleanup_tasks = set()
        self.downloads = {}
        self.read_cancel = None
        self.cancel = threading.Event()
        self.worker = None
        home = Path(agent.user_home())
        self.default_root = home / "Downloads"
        self.root = self.configured_root()
        self.service_user = WIN and agent.service_mode
        self.logon = getattr(session, "windows_logon", None)
        protected = [agent.data_dir, ROOT_DIR, home / ".local/share/RemoteDesk",
                     home / "AppData/Local/RemoteDesk"]
        if WIN:
            protected.extend((INSTALL_DIR, Path(PROGRAM_DATA).parent, home / "RemoteDesk/data"))
        self.scope = Scope(self.root, protected)
        dc.on("message", self.on_message)
        dc.on("close", self.close)

    def configured_root(self):
        return Path(self.agent.cfg["incoming_dir"] or self.default_root)

    def allowed(self):
        return (not self.cancel.is_set() and self.session.mode == "files"
                and self.agent.sessions.get(self.session.sid) is self.session and self.session.perms()["files"]
                and self.root == self.configured_root() and self.dc.readyState == "open")

    def require(self):
        if not self.allowed():
            raise PermissionError("Accesso ai file terminato")

    def require_change(self, *, write=False, delete=False):
        self.require()
        perms = self.session.perms()
        if (write and not perms.get("files_write")) or (delete and not perms.get("files_delete")):
            raise PermissionError("Permesso insufficiente per modificare i file")

    def require_upload(self, up):
        self.require_change(write=True, delete=up.overwrite)
        if up.revoked.is_set():
            raise PermissionError("Trasferimento revocato")

    def recheck_permissions(self):
        if not self.allowed():
            self.close()
            return
        for rid, up in list(self.uploads.items()):
            try:
                self.require_upload(up)
            except PermissionError:
                up.revoked.set()
                if self.active_upload is not up:
                    self.uploads.pop(rid)
                    task = asyncio.create_task(self._discard(up))
                    self.cleanup_tasks.add(task)
                    task.add_done_callback(self.cleanup_tasks.discard)
                    self.send(op="err", rid=rid, msg="Trasferimento revocato")

    def require_download(self):
        self.require()
        if self.read_cancel is not None and self.read_cancel.is_set():
            raise ValueError("Trasferimento annullato")

    def send(self, **message):
        if self.allowed():
            self.dc.send(json.dumps(message, ensure_ascii=False))

    def audit(self, kind, **fields):
        try:
            self.agent.audit.add(kind, net=self.session.net.nid, user=self.session.user,
                                 peer_name=self.session.peer_name, **fields)
        except Exception:
            log.exception("Scrittura registro trasferimenti")

    async def io(self, fn, *args, upload=False, opened=False):
        def run():
            self.require()
            if self.service_user:
                from . import winapi as W
                from .win_identity import logon_id
                sid = W.process_session()
                with W.as_session_user(sid) as user:
                    if self.logon != (sid, logon_id(user.tok)):
                        raise PermissionError("Utente Windows cambiato")
                    if upload:
                        owner = CleanupIdentity(user.tok)
                        try:
                            up = fn(*args)
                            up.owner = owner
                            return up
                        except BaseException:
                            owner.close()
                            raise
                    return fn(*args)
            return fn(*args)
        pending = asyncio.get_running_loop().run_in_executor(None, run)
        try:
            return await asyncio.shield(pending)
        except asyncio.CancelledError:
            # Cancelling a Future does not interrupt a running OS operation. Join
            # it before closing its handles or losing ownership of a new resource.
            self.cancel.set()
            while not pending.done():
                try:
                    await asyncio.shield(pending)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not pending.cancelled() and pending.exception() is None:
                result = pending.result()
                if upload:
                    await asyncio.to_thread(result.discard_as_owner)
                elif opened:
                    result[0].close()
            raise

    def on_message(self, msg):
        if not self.allowed() or not self.session.refresh_authorization():
            self.close()
            return
        if ((isinstance(msg, bytes) and 4 < len(msg) <= CHUNK + 4)
                or (isinstance(msg, str) and 0 < len(msg) <= 8192)):
            if isinstance(msg, str):
                try:
                    msg = json.loads(msg)
                except (ValueError, RecursionError):
                    return
                if not isinstance(msg, dict) or type(msg.get("rid")) is not int or not 0 <= msg["rid"] <= 0xffffffff:
                    return
                rid = msg["rid"]
                if msg.get("op") == "cancel" and rid in self.downloads:
                    self.downloads[rid].set()
                    return
                if msg.get("op") == "get":
                    if rid in self.downloads:
                        self.close()
                        self.dc.close()
                        return
                    self.downloads[rid] = threading.Event()
            try:
                self.queue.put_nowait(msg)
                if self.worker is None:
                    self.worker = asyncio.create_task(self._serve())
                return
            except asyncio.QueueFull:
                pass
        self.close()
        self.dc.close()

    async def _serve(self):
        empty = object()
        pending = empty
        try:
            while not self.cancel.is_set():
                for rid, up in list(self.uploads.items()):
                    if time.monotonic() - up.last_activity >= 60:
                        await self._abort(rid)
                        self.send(op="err", rid=rid, msg="Trasferimento scaduto")
                try:
                    timeout = min((up.last_activity + 60 - time.monotonic() for up in self.uploads.values()), default=None)
                    if pending is empty:
                        msg = await asyncio.wait_for(self.queue.get(), timeout)
                    else:
                        msg, pending = pending, empty
                except asyncio.TimeoutError:
                    continue
                if msg is None:
                    return
                rid = None
                try:
                    self.require()
                    if isinstance(msg, bytes):
                        rid = struct.unpack_from(">I", msg)[0]
                        chunks = bytearray(msg[4:])
                        while len(chunks) < 256 * 1024 and not self.queue.empty():
                            item = self.queue.get_nowait()
                            if not isinstance(item, bytes) or item[:4] != msg[:4]:
                                pending = item
                                break
                            chunks.extend(item[4:])
                        await self._write(rid, chunks)
                        continue
                    rid = msg["rid"]
                    await self.handle(msg, rid)
                except Exception as e:
                    if type(rid) is int:
                        if rid in self.uploads:
                            await self._abort(rid)
                        self.send(op="err", rid=rid, msg=self._message(e))
                finally:
                    if isinstance(msg, dict) and msg.get("op") == "get":
                        self.downloads.pop(rid, None)
        finally:
            self.cancel.set()
            for rid in list(self.uploads):
                await self._abort(rid)
            if self.cleanup_tasks:
                await asyncio.gather(*self.cleanup_tasks)

    @staticmethod
    def _message(error):
        if isinstance(error, OSError) and (getattr(error, "filename", None) or error.errno is not None):
            return "Operazione sul file non riuscita: verificare accesso, nome e spazio disponibile"
        return str(error)[:200] or "Operazione non riuscita"

    def close(self):
        if self.cancel.is_set():
            return
        self.cancel.set()
        self.downloads.clear()
        while not self.queue.empty():
            self.queue.get_nowait()
        self.queue.put_nowait(None)

    async def wait_closed(self):
        if self.worker is not None:
            try:
                await asyncio.shield(self.worker)
            except asyncio.CancelledError:
                if not self.worker.cancelled():
                    raise

    async def _abort(self, rid):
        up = self.uploads.pop(rid, None)
        if up is not None:
            await self._discard(up)

    async def _discard(self, up):
        try:
            await asyncio.to_thread(up.discard_as_owner)
        except Exception:
            # Never retry a pathname operation with the process identity.
            up.release()
            log.warning("Pulizia trasferimento interrotta", exc_info=True)
        finally:
            _TRANSFER_SLOTS.release()
        self.audit("file_in", path=str(up.final), size=up.got, ok=False)

    async def _write(self, rid, data):
        up = self.uploads.get(rid)
        if up is None:
            raise ValueError("Trasferimento sconosciuto")
        if up.got + len(data) > up.size:
            raise ValueError("Dimensione del trasferimento non valida")
        self.active_upload = up
        try:
            self.require_upload(up)
            await self.io(up.write, data, self.require_upload)
            up.got += len(data)
            up.last_activity = time.monotonic()
            self.require_upload(up)
        finally:
            self.active_upload = None

    async def handle(self, m, rid):
        op = m.get("op")
        if rid in self.uploads and op not in ("end", "cancel"):
            raise ValueError("Identificativo di trasferimento gia' in uso")
        if op == "roots":
            await self.io(self._check_root)
            self.send(op="roots", rid=rid, incoming=str(self.root),
                      entries=[{"n": "Cartella condivisa", "p": str(self.root), "d": True, "k": "fav"}])
        elif op == "ls":
            path = self.scope.check(m.get("path"))
            entries = await self.io(self._list, path)
            await self._listing(rid, path, entries)
        elif op in ("mkdir", "del", "rename"):
            event, fields = await self.io(self._change, op, m)
            self.audit(event, **fields)
            self.send(op="ok", rid=rid)
        elif op == "put":
            self.require_change(write=True, delete=m.get("overwrite") is True)
            size = m.get("size")
            if type(size) is not int or not 0 <= size <= MAX_FILE:
                raise ValueError("Dimensione massima per file: 512 MiB")
            if len(self.uploads) >= MAX_UPLOADS or not _TRANSFER_SLOTS.acquire(blocking=False):
                raise ValueError("Troppi trasferimenti in corso")
            try:
                up = await self.io(self._prepare, m, size, upload=True)
            except BaseException:
                _TRANSFER_SLOTS.release()
                raise
            self.uploads[rid] = up
            self.require_upload(up)
            self.send(op="ready", rid=rid, path=str(up.final))
        elif op == "end":
            up = self.uploads.get(rid)
            if not up or up.got != up.size:
                raise ValueError("Trasferimento incompleto")
            self.active_upload = up
            try:
                self.require_upload(up)
                await self.io(up.commit, lambda: self.require_upload(up))
            finally:
                self.active_upload = None
            del self.uploads[rid]
            _TRANSFER_SLOTS.release()
            self.audit("file_in", path=str(up.final), size=up.got, ok=True)
            self.send(op="done", rid=rid, path=str(up.final))
        elif op == "cancel":
            if rid in self.uploads:
                await self._abort(rid)
        elif op == "get":
            self.read_cancel = self.downloads.get(rid)
            try:
                self.require_download()
                await self._download(rid, self.scope.check(m.get("path")))
            finally:
                self.read_cancel = None
        else:
            raise ValueError("Operazione file sconosciuta")

    def _check_root(self):
        with self.scope.directory(self.root):
            pass

    async def _listing(self, rid, path, entries):
        base = dict(op="ls", rid=rid, path=str(path), parent="" if path == self.root else str(path.parent))
        # Path strings repeat in every entry. Count their encoded lengths so a
        # deeply nested folder stays below the WebRTC message size as well.
        budget = 64 * 1024 - len(json.dumps(base, ensure_ascii=False).encode()) - 64
        page, used = [], 0
        for entry in entries:
            size = len(json.dumps(entry, ensure_ascii=False).encode()) + 2
            if size > budget:
                raise ValueError("Percorso troppo lungo per la consultazione")
            if page and (used + size > budget or len(page) == 20):
                await self._wait_buffer(self.require)
                self.send(**base, entries=page, more=True)
                page, used = [], 0
            page.append(entry)
            used += size
        await self._wait_buffer(self.require)
        self.send(**base, entries=page, more=False)

    async def _wait_buffer(self, require):
        deadline = asyncio.get_running_loop().time() + 60
        require()
        while self.dc.bufferedAmount > HIGH_WATER:
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Trasferimento scaduto")
            await asyncio.sleep(.02)
            require()

    def _list(self, path):
        entries = []
        with self.scope.directory(path) as folder, folder.scan() as scan:
            for index, entry in enumerate(scan):
                if index >= MAX_ITEMS:
                    raise ValueError("Cartella troppo grande per la consultazione")
                try:
                    target = self.scope.check(path / entry.name)
                    st = folder.stat(entry.name)
                except (OSError, ValueError):
                    continue
                is_dir = stat.S_ISDIR(st.st_mode)
                entries.append({"n": entry.name, "p": str(target), "d": is_dir,
                                "s": 0 if is_dir else st.st_size, "m": int(st.st_mtime)})
        return sorted(entries, key=lambda item: (not item["d"], item["n"].casefold()))

    def _change(self, op, m):
        def authorize():
            self.require_change(write=op in ("mkdir", "rename"), delete=op in ("del", "rename"))
        authorize()
        path = self.scope.check(m.get("path"), mutating=op != "mkdir")
        if op == "mkdir":
            name = component(m.get("name"))
            target = self.scope.check(path / name, mutating=True)
            with self.scope.directory(path) as folder:
                authorize()
                os.mkdir(folder.arg(name), mode=0o700, dir_fd=folder.fd)
            return "file_mkdir", {"path": str(target)}
        with self.scope.directory(path.parent) as folder:
            folder.stat(path.name)
            authorize()
            if op == "del":
                folder.remove(path.name)
                return "file_del", {"path": str(path)}
            name = component(m.get("name"))
            dst = self.scope.check(path.parent / name, mutating=True)
            folder.move(path.name, name)
            return "file_ren", {"path": str(path), "dest": str(dst)}

    def _prepare(self, m, size):
        overwrite = m.get("overwrite") is True
        def authorize():
            self.require_change(write=True, delete=overwrite)
        authorize()
        path = self.scope.check(m.get("path") or self.root)
        relative = m.get("name")
        if not isinstance(relative, str) or len(relative) > 2048:
            raise ValueError("Nome non valido")
        names = [component(part) for part in relative.replace("\\", "/").split("/")]
        if len(names) > 32:
            raise ValueError("Troppe sottocartelle")
        target = self.scope.check(path.joinpath(*names), mutating=True)
        stack = contextlib.ExitStack()
        try:
            folder = stack.enter_context(self.scope.directory(target.parent, before_create=authorize))
            if shutil.disk_usage(folder.path).free < size + MIN_FREE:
                raise OSError("Spazio insufficiente per il trasferimento")
            if overwrite:
                try:
                    if stat.S_ISDIR(folder.stat(target.name).st_mode):
                        raise ValueError("La destinazione e' una cartella")
                except FileNotFoundError:
                    pass
            authorize()
            up = Upload(folder, stack, target, size, overwrite)
            if not overwrite:
                try:
                    up.available_name()
                except BaseException:
                    up.discard()
                    raise
            return up
        except BaseException:
            stack.close()
            raise

    def _open_download(self, path):
        with self.scope.directory(path if path == self.root else path.parent) as parent:
            is_dir = path == self.root or stat.S_ISDIR(parent.stat(path.name).st_mode)
            if not is_dir:
                return parent.reader(path.name), path.name
        with self.scope.directory(self.root) as shared:
            if not WIN and shared.fd is not None:
                # Unlink through the anchored descriptor before writing any user data.
                name, tmp = shared.temporary()
                try:
                    shared.unlink(name)
                except BaseException:
                    tmp.close()
                    raise
            else:
                tmp = tempfile.TemporaryFile(dir=self.root, prefix=TEMP_PREFIX)
            try:
                self._archive(path, tmp)
                tmp.seek(0)
                return tmp, path.name + ".zip"
            except BaseException:
                tmp.close()
                raise

    def _archive(self, path, output):
        # Stored ZIP bounds CPU and permits enforcing input/output and item budgets.
        total = 0
        count = 0
        pending = [path]
        with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
            while pending:
                directory = pending.pop()
                self.require_download()
                with self.scope.directory(directory) as folder, folder.scan() as scan:
                    for entry in scan:
                        self.require_download()
                        if entry.name.casefold().startswith(TEMP_PREFIX):
                            continue
                        count += 1
                        if count > MAX_ITEMS:
                            raise ValueError("Troppi file nella cartella")
                        candidate = self.scope.check(directory / entry.name)
                        st = folder.stat(entry.name)
                        name = str(candidate.relative_to(path.parent)).replace(os.sep, "/")
                        if stat.S_ISDIR(st.st_mode):
                            archive.writestr(name + "/", b"")
                            pending.append(candidate)
                            continue
                        if total + st.st_size > MAX_FILE or output.tell() + st.st_size > MAX_FILE:
                            raise ValueError("Archivio troppo grande")
                        if shutil.disk_usage(self.root).free < st.st_size + MIN_FREE:
                            raise OSError("Spazio insufficiente per l'archivio")
                        with folder.reader(entry.name) as src, archive.open(name, "w") as dest:
                            while chunk := src.read(64 * 1024):
                                self.require_download()
                                total += len(chunk)
                                if total > MAX_FILE:
                                    raise ValueError("Archivio troppo grande")
                                dest.write(chunk)
        if output.tell() > MAX_FILE:
            raise ValueError("Archivio troppo grande")

    async def _download(self, rid, path):
        if not _TRANSFER_SLOTS.acquire(blocking=False):
            raise ValueError("Troppi trasferimenti in corso")
        sent = 0
        ok = False
        file = None
        try:
            file, name = await self.io(self._open_download, path, opened=True)
            if self.service_user:
                await self.io(self.require)
            size = os.fstat(file.fileno()).st_size
            if size > MAX_FILE:
                raise ValueError("Dimensione massima per file: 512 MiB")
            self.require_download()
            self.send(op="meta", rid=rid, name=name, size=size)
            head = struct.pack(">I", rid)
            while sent < size:
                await self._wait_buffer(self.require_download)
                data = await self.io(file.read, min(CHUNK, size - sent))
                self.require_download()
                if not data:
                    raise ValueError("File cambiato durante la lettura")
                self.dc.send(head + data)
                sent += len(data)
            self.require_download()
            self.send(op="end", rid=rid)
            ok = True
        finally:
            try:
                if file:
                    file.close()
            finally:
                _TRANSFER_SLOTS.release()
                self.audit("file_out", path=str(path), size=sent, ok=ok)


class CleanupIdentity:
    """Retain the initiating user's impersonation token solely to discard one partial upload."""
    def __init__(self, token):
        import ctypes
        from ctypes import wintypes
        from . import winapi as W
        self.token = wintypes.HANDLE()
        if not W.advapi32.DuplicateToken(token, 2, ctypes.byref(self.token)):
            raise ctypes.WinError(ctypes.get_last_error())

    def discard(self, action):
        from . import winapi as W
        if not W.advapi32.ImpersonateLoggedOnUser(self.token):
            raise PermissionError("Ripristino identita' di trasferimento non riuscito")
        try:
            action()
        finally:
            if not W.advapi32.RevertToSelf():
                # A worker must never return to the shared executor with another identity.
                os._exit(1)

    def close(self):
        from . import winapi as W
        if self.token:
            W.kernel32.CloseHandle(self.token)
            self.token = None


class Upload:
    def __init__(self, folder, stack, target, size, overwrite):
        self.folder, self.stack, self.target = folder, stack, target
        self.size, self.got, self.overwrite = size, 0, overwrite
        self.last_activity = time.monotonic()
        self.final = target
        self.owner = None
        self.revoked = threading.Event()
        self.temp, self.file = folder.temporary()
        self.identity = os.fstat(self.file.fileno())

    def available_name(self):
        for number in range(1000):
            candidate = self.target if number == 0 else self.target.with_name(
                f"{self.target.stem} ({number}){self.target.suffix}")
            self.folder.scope.check(candidate, mutating=True)
            try:
                self.folder.stat(candidate.name)
            except FileNotFoundError:
                self.final = candidate
                return
        raise FileExistsError("Troppi file con lo stesso nome")

    def same_temp(self):
        st = self.folder.stat(self.temp, internal=True)
        if not os.path.samestat(st, self.identity):
            raise PermissionError("Temporaneo non piu' valido")

    def write(self, data, require):
        if self.got // HIGH_WATER != (self.got + len(data)) // HIGH_WATER:
            if shutil.disk_usage(self.folder.path).free < len(data) + MIN_FREE:
                raise OSError("Spazio insufficiente per il trasferimento")
        require(self)
        if self.file.write(data) != len(data):
            raise OSError("Scrittura incompleta")

    def commit(self, require):
        if os.fstat(self.file.fileno()).st_size != self.size:
            raise ValueError("Dimensione del file cambiata")
        self.file.close()
        self.same_temp()
        self.folder.scope.check(self.final, mutating=True)
        if not self.overwrite:
            self.available_name()
        require()
        self.folder.move(self.temp, self.final.name, overwrite=self.overwrite)
        self.release()

    def discard_as_owner(self):
        if self.owner:
            self.owner.discard(self.discard)
        else:
            self.discard()

    def discard(self):
        self.file.close()
        try:
            self.same_temp()
            self.folder.unlink(self.temp)
        except FileNotFoundError:
            pass
        finally:
            self.release()

    def release(self):
        try:
            self.file.close()
        finally:
            try:
                self.stack.close()
            finally:
                if self.owner:
                    self.owner.close()
