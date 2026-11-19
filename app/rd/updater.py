"""Installatore degli aggiornamenti (eseguito dalla copia NUOVA, mai da quella da sostituire).

Modalita' utente:  aspetta/chiude RemoteDesk, sostituisce la cartella, riavvia RemoteDesk.exe.
Modalita' servizio: ferma l'attivita' "RemoteDesk", sostituisce Program Files\\RemoteDesk,
                    riavvia il servizio e l'icona dell'utente collegato.
In entrambi i casi verifica che la nuova versione risponda; altrimenti ripristina la precedente.
Solo libreria standard: non importa nulla dalla cartella che sta sostituendo."""
import argparse
from contextlib import ExitStack, contextmanager
from functools import lru_cache
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time

NOWIN = 0x08000000
MANAGED = ("app", "runtime", "RemoteDesk.exe", "LEGGIMI.txt")
PORTABLE_META = ".remotedesk-update"


@lru_cache(maxsize=1)
def _file_scope():
    if __package__:
        from . import file_scope
        return file_scope
    # Isolated interpreter of the downloaded package. Load its own standard-
    # library-only path helper, without adding the installation to sys.path.
    import importlib.util
    spec = importlib.util.spec_from_file_location("_rd_update_scope", Path(__file__).with_name("file_scope.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def portable_anchor(path):
    path = Path(os.path.abspath(path))
    if os.name != "nt":
        yield plain_path(path)
        return
    scope = _file_scope()
    if len(path.drive) != 2 or scope._k32.GetDriveTypeW(path.anchor) not in (2, 3, 6):
        raise PermissionError("La copia portabile deve risiedere su un volume locale")
    with ExitStack() as stack:
        actual = Path(path.anchor)
        for part in (None, *path.parts[1:]):
            candidate = actual / scope.component(part, internal=True) if part is not None else actual
            handle, actual = scope.windows_handle(str(candidate), directory=True, host_alias=True)
            stack.callback(scope._k32.CloseHandle, handle)
        yield actual


def _item_id(path, *, folder):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    if (_redirected(st) or not (stat.S_ISDIR(st.st_mode) if folder else stat.S_ISREG(st.st_mode))
            or not folder and st.st_nlink != 1 or not st.st_ino):
        raise PermissionError(f"Elemento non aggiornabile o reindirizzato: {path.name}")
    return [st.st_dev, st.st_ino]


def portable_profile(target, data):
    data = plain_path(data)
    if (target == data or any(data.is_relative_to(target / n) for n in (*MANAGED, PORTABLE_META))
            or target.is_relative_to(data)):
        raise PermissionError("Il profilo dati deve essere separato dai componenti applicativi")
    return data


def _require_user_account():
    if os.name != "nt":
        return
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    a.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD)]
    a.IsWellKnownSid.argtypes = [wintypes.LPVOID, ctypes.c_int]
    token = wintypes.HANDLE()
    if not a.OpenProcessToken(k.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise PermissionError("Impossibile verificare l'identità del processo portabile")
    try:
        buf, size = ctypes.create_string_buffer(512), wintypes.DWORD()
        if not a.GetTokenInformation(token, 1, buf, len(buf), ctypes.byref(size)):
            raise PermissionError("Identità portabile sconosciuta")
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        if any(a.IsWellKnownSid(sid, kind) for kind in (22, 23, 24)):
            raise PermissionError("Gli account di servizio non possono aggiornare copie portabili")
    finally:
        k.CloseHandle(token)


def _can_rename_component(path):
    if os.name == "nt":
        scope = _file_scope()
        # Request only DELETE, under the current user, without changing the object.
        handle = scope._k32.CreateFileW(str(path), 0x10000, 7, None, 3, 0x02200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise PermissionError(f"Componente occupato o senza diritto di rinomina: {path.name}")
        scope._k32.CloseHandle(handle)


def portable_layout(target, data, install, machine_data, *, executable=None):
    if target.parent == target:
        raise PermissionError("Selezionare la cartella del programma, non la radice del volume")
    for reserved in (Path(install), Path(machine_data).parent):
        if target.is_relative_to(reserved) or reserved.is_relative_to(target):
            raise PermissionError("La copia amministrata richiede l'aggiornamento del servizio")
    portable_profile(target, data)
    if executable is not None and plain_path(executable) not in (
            target / "runtime/pythonw.exe", target / "runtime/python.exe"):
        raise PermissionError("L'interprete attivo non appartiene alla copia portabile")
    for name in MANAGED:
        identity = _item_id(target / name, folder=name in ("app", "runtime"))
        if identity is None and name != "LEGGIMI.txt":
            raise PermissionError("Copia portabile incompleta: " + name)
        if identity is not None:
            _can_rename_component(target / name)
    for name in ("app/remotedesk.py", "runtime/pythonw.exe"):
        if plain_path(target / name) != target / name:
            raise PermissionError("Percorso applicativo ambiguo")


def _metadata(target):
    meta = target / PORTABLE_META
    created = False
    try:
        meta.mkdir()
        created = True
    except FileExistsError:
        if _item_id(meta, folder=True) is None:
            raise
    with portable_anchor(meta) as pinned:
        marker = pinned / "format"
        if created:
            with marker.open("xb") as file:
                file.write(b"RDUP1")
        elif _item_id(marker, folder=False) is None:
            raise PermissionError(f"La cartella {PORTABLE_META} contiene dati estranei")
        else:
            with marker.open("rb") as file:
                if file.read(6) != b"RDUP1":
                    raise PermissionError(f"La cartella {PORTABLE_META} contiene dati estranei")
    return meta


@contextmanager
def _local_lock(path):
    if os.name == "nt":
        from ctypes import wintypes
        scope = _file_scope()
        # OPEN_ALWAYS, no sharing, no reparse traversal; no writing through the handle.
        h = scope._k32.CreateFileW(str(path), 0x80000000, 0, None, 4, 0x00200000, None)
        if h == ctypes.c_void_p(-1).value:
            raise OSError("Altra operazione in corso o file di lock non accessibile")
        try:
            attrs = (wintypes.DWORD * 2)()
            if not scope._k32.GetFileInformationByHandleEx(h, 9, attrs, ctypes.sizeof(attrs)) or attrs[0] & 0x410:
                raise PermissionError("Lock aggiornamento non regolare")
            yield
        finally:
            scope._k32.CloseHandle(h)
    else:
        import fcntl
        fd = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)


def portable_preflight(target, data, install, machine_data, executable):
    try:
        _require_user_account()
        with portable_anchor(target) as root, portable_anchor(data) as profile:
            portable_layout(root, profile, install, machine_data, executable=executable)
            with portable_anchor(_metadata(root)) as meta, _local_lock(meta / "lock"):
                state = _read_transaction(meta)
                if state and _transaction_complete(root, state, profile):
                    (meta / "current.json").unlink()
                elif state:
                    raise RuntimeError(f"Aggiornamento interrotto, recuperare la transazione in {meta}")
                # Test the actual create/rename/delete operations on our own disposable tree.
                with tempfile.TemporaryDirectory(prefix="probe-", dir=meta) as probe:
                    (Path(probe) / "before").mkdir()
                    (Path(probe) / "before").rename(Path(probe) / "after")
    except OSError as exc:
        raise RuntimeError(f"La copia portabile non è aggiornabile in {target}: {exc}") from exc


def system_tool(name):
    """Percorso assoluto dalla cartella di sistema restituita da Windows."""
    buf = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf))
    if not 0 < length < len(buf):
        raise OSError("cartella di sistema Windows non disponibile")
    return os.path.join(buf.value, name)


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    if not getattr(ARGS, "log_verified", False):
        if sys.stderr is not None:
            print(line, file=sys.stderr)
        return
    try:
        with open(ARGS.log, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def run(args):
    r = subprocess.run(args, capture_output=True, text=True, creationflags=NOWIN)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def pid_alive(pid):
    from ctypes import wintypes
    k = ctypes.windll.kernel32
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k.OpenProcess(0x00100000, False, pid)   # SYNCHRONIZE
    if not h:
        return False
    try:
        return k.WaitForSingleObject(h, 0) == 0x102
    finally:
        k.CloseHandle(h)


def kill_under(folder):
    """Termina soltanto l'avviatore e l'interprete del pacchetto."""
    executables = (os.path.join(folder, "RemoteDesk.exe"), os.path.join(folder, "runtime", "pythonw.exe"))
    paths = ",".join("'" + path.replace("'", "''") + "'" for path in executables)
    ps = ("$paths=@(" + paths + "); Get-CimInstance Win32_Process | "
          "Where-Object { $_.ExecutablePath -and ($paths -contains $_.ExecutablePath) } | "
          "ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }")
    run([system_tool(r"WindowsPowerShell\v1.0\powershell.exe"), "-NoProfile", "-Command", ps])


def _receipt_path(data_dir, name):
    return os.path.join(data_dir, ".update-" + name + ".json")


def stage_root(data_dir, service):
    # Il controllo di avvio del profilo SYSTEM esamina ricorsivamente i dati.
    # Il runtime in staging non fa parte dei dati operativi della macchina.
    return os.path.join(os.path.dirname(data_dir), "release-staging") if service else os.path.join(data_dir, "update")


def _redirected(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def plain_path(value):
    """Normalizza anche gli alias 8.3, solo dopo aver escluso reparse su ogni componente."""
    path = Path(os.path.abspath(value))
    for part in (*reversed(path.parents), path):
        if _redirected(part.lstat()):
            raise PermissionError("Percorso reindirizzato non consentito")
    return path.resolve(strict=True)


def _read_receipt(path):
    try:
        with open(path, "rb") as f:
            raw = f.read(4097)
        if len(raw) <= 4096:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return obj
    except (OSError, ValueError, RecursionError):
        pass
    return {}


def _write_receipt(path, obj):
    fd, temporary = tempfile.mkstemp(dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def mark_stage_finished(source, base):
    staged = plain_path(source)
    job = staged.parent.parent
    if (job.parent == plain_path(base) and job.name.startswith("release-")
            and staged == job / "nuovo" / "RemoteDesk"):
        _write_receipt(job / ".finished", {"version": 1})


def clear_finished_stages(base):
    base = plain_path(base)
    for job in base.glob("release-*"):
        try:
            job_info = job.lstat()
            if _redirected(job_info) or not stat.S_ISDIR(job_info.st_mode):
                continue
            marker = job / ".finished"
            marker_info = marker.lstat()
        except FileNotFoundError:
            continue
        if (not _redirected(marker_info) and stat.S_ISREG(marker_info.st_mode)
                and _read_receipt(marker) == {"version": 1}):
            shutil.rmtree(job, ignore_errors=True)


def acknowledge_start(data_dir, target, version):
    """L'agente pronto conferma il challenge attraverso il proprio archivio protetto."""
    request = _read_receipt(_receipt_path(data_dir, "pending"))
    if (request.get("target") != os.path.normcase(os.path.realpath(target)) or request.get("version") != version
            or not isinstance(request.get("nonce"), str) or len(request["nonce"]) != 64):
        return False
    try:
        _write_receipt(_receipt_path(data_dir, "ready"), request)
        return True
    except OSError:
        return False


def start_tray_for_user(exe):
    """Dal servizio (SYSTEM) avvia l'icona nella sessione dell'utente collegato, con i SUOI diritti."""
    import ctypes.wintypes as wt
    k, wts, adv = ctypes.windll.kernel32, ctypes.windll.wtsapi32, ctypes.windll.advapi32
    sess = k.WTSGetActiveConsoleSessionId()
    tok = wt.HANDLE()
    if sess == 0xFFFFFFFF or not wts.WTSQueryUserToken(sess, ctypes.byref(tok)):
        return False

    class SI(ctypes.Structure):
        _fields_ = [("cb", wt.DWORD), ("r", wt.LPWSTR), ("desk", wt.LPWSTR), ("t", wt.LPWSTR)] + \
                   [(f"d{i}", wt.DWORD) for i in range(8)] + [("w", wt.WORD), ("c", wt.WORD),
                                                              ("p", ctypes.c_void_p), ("h1", wt.HANDLE),
                                                              ("h2", wt.HANDLE), ("h3", wt.HANDLE)]

    class PI(ctypes.Structure):
        _fields_ = [("hp", wt.HANDLE), ("ht", wt.HANDLE), ("pid", wt.DWORD), ("tid", wt.DWORD)]
    si, pi = SI(), PI()
    si.cb = ctypes.sizeof(si)
    si.desk = "winsta0\\default"
    cmd = ctypes.create_unicode_buffer(f'"{exe}" --minimized')
    ok = adv.CreateProcessAsUserW(tok, None, cmd, None, None, False, 0x400, None, os.path.dirname(exe),
                                  ctypes.byref(si), ctypes.byref(pi))
    if ok:
        k.CloseHandle(pi.hp)
        k.CloseHandle(pi.ht)
    k.CloseHandle(tok)
    return bool(ok)


def stop_old():
    if ARGS.mode == "service":
        run([system_tool("schtasks.exe"), "/End", "/TN", "RemoteDesk"])
    else:
        t0 = time.time()
        while ARGS.pid and pid_alive(ARGS.pid) and time.time() - t0 < 20:
            time.sleep(0.5)
    time.sleep(1)
    kill_under(ARGS.target)
    time.sleep(1.5)


def start(target):
    exe = os.path.join(target, "RemoteDesk.exe")
    if ARGS.mode == "service":
        code, out = run([system_tool("schtasks.exe"), "/Run", "/TN", "RemoteDesk"])
        log(f"avvio servizio: {code} {out.strip()}")
        if code != 0:
            raise RuntimeError("riavvio del servizio non riuscito")
        log("icona utente: " + ("avviata" if start_tray_for_user(exe) else "nessun utente collegato"))
    else:
        extra = json.loads(ARGS.args or "[]")
        subprocess.Popen([exe, *extra, "--minimized"], cwd=target, creationflags=0x00000008, close_fds=True)


def plain_copy(src, dst, *, follow_symlinks=True):
    """Copia a blocchi (senza la copia veloce di sistema, che su alcuni ambienti si blocca)."""
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        shutil.copyfileobj(fi, fo, 1024 * 1024)
    try:
        st = os.stat(src)
        os.utime(dst, (st.st_atime, st.st_mtime))
    except OSError:
        pass
    return dst


def _raise_oserror(error):
    raise error


def move_with_retry(src, dst, tries=15):
    for i in range(tries):
        try:
            os.rename(src, dst)
            return True
        except OSError as e:
            if i == tries - 1:
                log(f"impossibile spostare {src}: {e}")
                return False
            kill_under(src)
            time.sleep(1)


@contextmanager
def installation_lock(target):
    """Lock di kernel per installazione, condiviso anche da profili dati distinti."""
    import msvcrt
    # Il kernel rilascia il lock dopo un crash. Il file resta per non scollegare
    # il lock di un altro processo che lo ha gia' aperto.
    path = Path(target).with_name("." + Path(target).name + ".update.lock")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_BINARY, 0o600)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        try:
            yield
        finally:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


def service_stage(source, data_dir):
    """Layout emesso da 2.3.2 oppure directory di transazione del nuovo formato."""
    data_dir, source = Path(data_dir), Path(source)
    if source == data_dir / "update" / "nuovo" / "RemoteDesk":
        return data_dir
    job = source.parent.parent
    if (job.parent == data_dir.parent / "release-staging" and re.fullmatch(r"release-[0-9a-f]{32}", job.name)
            and source == job / "nuovo" / "RemoteDesk"):
        return job
    raise PermissionError("Staging servizio non riconosciuto")


def preflight_service(source, target):
    if (plain_path(__file__) != source / "app" / "rd" / "updater.py"
            or plain_path(sys.executable) != source / "runtime" / "pythonw.exe"):
        raise PermissionError("Il processo di aggiornamento deve provenire dalla release verificata")
    # In modalita' -I il pacchetto applicativo non viene aggiunto automaticamente.
    sys.path.insert(0, os.fspath(source / "app"))
    try:
        from rd import common, service
    finally:
        sys.path.pop(0)
    data = plain_path(common.PROGRAM_DATA)
    log_path = Path(ARGS.log)
    if (target != plain_path(common.INSTALL_DIR) or log_path.name != "update.log"
            or plain_path(log_path.parent) != data / "logs"):
        raise PermissionError("Destinazione o log servizio non corrispondente alla copia amministrata")
    job = service_stage(source, data)
    common.secure_dir(common.PROGRAM_DATA, existing=True)
    ARGS.log_verified = True
    if job != data:
        common.secure_dir(job, existing=True)
    service._verify_installation()
    return service.prepare_existing_task


def _portable_args(raw, data):
    args = json.loads(raw or "[]")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("Opzioni di riavvio non valide")
    extra, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg in ("--agent-only", "--no-tray", "--no-browser", "-v", "--verbose"):
            extra.append(arg)
        elif arg in ("--data", "--port") and index + 1 < len(args):
            index += 1
            if arg == "--port":
                port = int(args[index])
                if not 1 <= port <= 65535:
                    raise ValueError("Porta di riavvio non valida")
                extra.extend(("--port", str(port)))
            elif Path(args[index]).is_absolute():
                with portable_anchor(args[index]) as requested:
                    if requested != data:
                        raise ValueError("Profilo di riavvio diverso dall'istanza attiva")
        elif arg != "--minimized":
            raise ValueError("Opzione non ammessa nella copia portabile: " + arg)
        index += 1
    return [*extra, "--minimized", "--data", str(data)]


def _regular_copy(source, destination):
    if os.name == "nt":
        import msvcrt
        scope = _file_scope()
        handle, _ = scope.windows_handle(str(source), directory=False)
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            scope._k32.CloseHandle(handle)
            raise
    else:
        fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as inp:
        info = os.fstat(inp.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PermissionError("File di staging non regolare")
        with destination.open("xb") as out:
            shutil.copyfileobj(inp, out, 1024 * 1024)


def _copy_member(source, dest, folder):
    if not folder:
        _regular_copy(source, dest)
        return
    with portable_anchor(source) as plain:
        dest.mkdir()
        with portable_anchor(dest) as destination:
            for child in plain.iterdir():
                info = child.lstat()
                if _redirected(info):
                    raise PermissionError("Collegamento nello staging verificato")
                if child.name == "__pycache__":
                    continue
                _copy_member(child, destination / child.name, stat.S_ISDIR(info.st_mode))


def _identity(root, name):
    return _item_id(root / name, folder=name in ("runtime", "app"))


def _move_member(origin, dest, name, expected):
    for attempt in range(12):
        if expected is None or _identity(origin, name) != expected or os.path.lexists(dest / name):
            raise PermissionError(f"Il componente {name} è cambiato durante l'aggiornamento")
        try:
            os.rename(origin / name, dest / name)
            return
        except OSError as exc:
            if attempt == 11 or getattr(exc, "winerror", None) not in (32, 33):
                raise
            time.sleep(.25)


def _read_transaction(meta):
    path = meta / "current.json"
    if _item_id(path, folder=False) is None:
        return None
    state = _read_receipt(path)
    if (not re.fullmatch("[a-f0-9]{32}", str(state.get("id", "")))
            or state.get("phase") not in ("prepared", "swapping", "confirmed")
            or any(not isinstance(state.get(key), dict) or set(state[key]) != set(MANAGED)
                   for key in ("old", "new"))):
        raise RuntimeError("Registro di aggiornamento danneggiato; conservare i backup")
    for table in (state["old"], state["new"]):
        for name, ident in table.items():
            if ident is None and name == "LEGGIMI.txt":
                continue
            if not isinstance(ident, list) or len(ident) != 2 or any(type(n) is not int for n in ident):
                raise RuntimeError("Identità non valida nel registro di aggiornamento")
    return state


def _rollback_members(target, job, state):
    # Each pair of renames can be interrupted. Inode/file IDs distinguish an
    # already completed step from an unrelated file created after the crash.
    with portable_anchor(job / "previous") as previous, portable_anchor(job / "rejected") as rejected:
        for name in reversed(MANAGED):
            old, new = state["old"][name], state["new"][name]
            live = _identity(target, name)
            if old == new:
                if live != old:
                    raise RuntimeError(f"Componente invariato modificato: {name}")
                continue
            if live is not None and live == new:
                _move_member(target, rejected, name, new)
                live = None
            if live == old:
                continue
            if live is not None or old is None:
                raise RuntimeError(f"Conflitto su {name}; copie di recupero in {job}")
            _move_member(previous, target, name, old)


def _transaction_complete(target, state, data):
    if all(_identity(target, name) == state["old"][name] for name in MANAGED):
        return True
    if not all(_identity(target, name) == state["new"][name] for name in MANAGED):
        return False
    receipt = state.get("receipt")
    return state["phase"] == "confirmed" or (
        data is not None and isinstance(receipt, dict) and receipt.get("target") == os.path.normcase(str(target))
        and isinstance(receipt.get("nonce"), str) and len(receipt["nonce"]) == 64
        and _read_receipt(_receipt_path(data, "ready")) == receipt)


def _recover_portable(target, meta, data=None):
    state = _read_transaction(meta)
    if state is None:
        return False
    with portable_anchor(meta / state["id"]) as job:
        if _transaction_complete(target, state, data):
            pass
        elif state["phase"] == "swapping":
            _rollback_members(target, job, state)
        else:
            raise RuntimeError(f"Copia modificata, controllare {job}")
    (meta / "current.json").unlink()
    return True


def _prepare_members(target, source, job):
    candidate = job / "candidate"
    old, new = {}, {}
    for name in MANAGED:
        old[name] = _identity(target, name)
        exists = _identity(source, name)
        if exists is None:
            raise ValueError(f"Pacchetto incompleto: {name}")
        _copy_member(source / name, candidate / name, name in ("app", "runtime"))
        new[name] = _identity(candidate, name)
        if name == "RemoteDesk.exe" and old[name] is not None:
            import hashlib
            # The small native stub is identical in many releases. Keeping it in
            # place avoids an unnecessary interval without a launcher after a crash.
            with (candidate / name).open("rb") as a, (target / name).open("rb") as b:
                if hashlib.file_digest(a, "sha256").digest() == hashlib.file_digest(b, "sha256").digest():
                    new[name] = old[name]
    return {"id": job.name, "phase": "prepared", "old": old, "new": new}


def _wait_old_portable(pid, target):
    # A process handle stays tied to the original identity if its PID is recycled.
    if not pid:
        return
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    h = k.OpenProcess(0x100000 | 0x1000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
    if not h:
        if ctypes.get_last_error() == 87:
            return
        raise PermissionError("Impossibile verificare il processo della copia attiva")
    try:
        buf = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buf))
        if not k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(length)):
            raise PermissionError("Identità del processo portabile non disponibile")
        if Path(buf.value) not in (target / "runtime/pythonw.exe", target / "runtime/python.exe"):
            return
        if k.WaitForSingleObject(h, 40000) != 0:
            raise RuntimeError("L'istanza portabile è ancora attiva: chiuderla e riprovare")
    finally:
        k.CloseHandle(h)


def _start_portable(target, args):
    binary, script = target / "runtime/pythonw.exe", target / "app/remotedesk.py"
    with portable_anchor(binary.parent), portable_anchor(script.parent), ExitStack() as stack:
        for path in (binary, script):
            if _item_id(path, folder=False) is None:
                raise FileNotFoundError(path)
            if os.name == "nt":
                scope = _file_scope()
                handle, _ = scope.windows_handle(str(path), directory=False)
                stack.callback(scope._k32.CloseHandle, handle)
        return subprocess.Popen([str(binary), "-E", "-s", str(script), *args], cwd=target,
                                close_fds=True, creationflags=0x00000008)


def _exchange_portable(target, meta, source, data, args):
    job = meta / secrets.token_hex(16)
    job.mkdir()
    with portable_anchor(job), ExitStack() as stack:
        for key in ("previous", "candidate", "rejected"):
            path = job / key
            path.mkdir()
            stack.enter_context(portable_anchor(path))
        return _exchange_members(target, meta, source, data, args, job)


def _exchange_members(target, meta, source, data, args, job):
    state = _prepare_members(target, source, job)
    recovery = {"executable": str(source / "runtime/python.exe"),
                "arguments": ["-I", str(source / "app/rd/updater.py"), "--recover", "--mode", "user",
                              "--source", str(source), "--target", str(target), "--version", ARGS.version,
                              "--log", str(data / "logs/update.log")]}
    _write_receipt(job / "RECUPERO.json", recovery)
    journal = meta / "current.json"
    _write_receipt(journal, state)
    nonce = getattr(ARGS, "prepare_token", None)
    if nonce is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise ValueError("Richiesta di preparazione non valida")
        _write_receipt(source.parent / ".prepared", {"nonce": nonce})
        deadline = time.monotonic() + 60
        while _read_receipt(source.parent / ".proceed") != {"nonce": nonce}:
            if time.monotonic() >= deadline:
                raise RuntimeError("L'istanza attiva non ha confermato l'aggiornamento")
            time.sleep(.1)
    _wait_old_portable(ARGS.pid, target)
    receipt = {"target": os.path.normcase(str(target)), "version": ARGS.version, "nonce": secrets.token_hex(32)}
    pending, ready = (Path(_receipt_path(data, key)) for key in ("pending", "ready"))
    state["phase"] = "swapping"
    state["receipt"] = receipt
    _write_receipt(journal, state)
    process = None
    try:
        _write_receipt(pending, receipt)
        for name in MANAGED:
            if state["new"][name] == state["old"][name]:
                if _identity(target, name) != state["old"][name]:
                    raise PermissionError("Avviatore attivo modificato")
                continue
            if state["old"][name] is not None:
                _move_member(target, job / "previous", name, state["old"][name])
            _move_member(job / "candidate", target, name, state["new"][name])
        process = _start_portable(target, args)
        for _ in range(240):
            if _read_receipt(ready) == receipt:
                state["phase"] = "confirmed"
                _write_receipt(journal, state)
                journal.unlink()
                log(f"nuova versione attiva: aggiornamento completato; componenti precedenti in {job / 'previous'}")
                return 0
            if process.poll() is not None:
                break
            time.sleep(.5)
        raise RuntimeError("La nuova versione non ha confermato l'avvio")
    except Exception as exc:
        log(f"{exc}; torno alla precedente")
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=20)
        _rollback_members(target, job, state)
        journal.unlink()
        _start_portable(target, args)
        return 2
    finally:
        for path in (pending, ready):
            if _read_receipt(path) == receipt:
                path.unlink(missing_ok=True)


def _portable_helper(source_path, target_path):
    _require_user_account()
    with (portable_anchor(source_path) as source, portable_anchor(target_path) as target,
          portable_anchor(Path(ARGS.log).parent.parent) as data, portable_anchor(data / "logs")):
        interpreters = [source / "runtime/pythonw.exe"]
        if getattr(ARGS, "recover", False):
            interpreters.append(source / "runtime/python.exe")
        if plain_path(__file__) != source / "app/rd/updater.py" or plain_path(sys.executable) not in interpreters:
            raise PermissionError("Avviare l'helper dal runtime di staging")
        if plain_path(Path(ARGS.log).parent) != data / "logs" or Path(ARGS.log).name != "update.log":
            raise PermissionError("Log aggiornamento non valido")
        _item_id(Path(ARGS.log), folder=False)
        ARGS.log_verified = True
        base = data / "update"
        job = source.parent.parent
        if source != base / "nuovo/RemoteDesk" and not (
                job.parent == base and re.fullmatch(r"release-(?:[a-z0-9_]{8}|[0-9a-f]{32})", job.name)
                and source == job / "nuovo/RemoteDesk"):
            raise PermissionError("Staging portabile non riconosciuto")
        if (target == target.parent or target == source or target.is_relative_to(source)
                or any(source.is_relative_to(target / n) for n in (*MANAGED, PORTABLE_META))):
            raise PermissionError("Staging sovrapposto ai componenti attivi")
        sys.path.insert(0, str(source / "app"))
        try:
            from rd.common import INSTALL_DIR, PROGRAM_DATA
        finally:
            sys.path.pop(0)
        portable_profile(target, data)
        for reserved in (Path(INSTALL_DIR), Path(PROGRAM_DATA).parent):
            if target.is_relative_to(reserved) or reserved.is_relative_to(target):
                raise PermissionError("Destinazione amministrata non ammessa in modalità portabile")
        args = _portable_args(ARGS.args, data)
        with portable_anchor(_metadata(target)) as meta, _local_lock(meta / "lock"), _local_lock(data / ".portable-update.lock"):
            _recover_portable(target, meta, data)
            portable_layout(target, data, INSTALL_DIR, PROGRAM_DATA)
            if getattr(ARGS, "recover", False):
                log("Recupero completato; la copia portabile può essere avviata")
                return 0
            try:
                result = _exchange_portable(target, meta, source, data, args)
            finally:
                state = _read_transaction(meta)
                if state and state["phase"] == "prepared":
                    (meta / "current.json").unlink()
            if result in (0, 2):
                mark_stage_finished(source, base)
            return result


def main():
    target = os.path.abspath(ARGS.target)
    if ARGS.mode == "user":
        return _portable_helper(ARGS.source, target)
    source_path, target_path = plain_path(ARGS.source), plain_path(target)
    if (source_path.is_relative_to(target_path) or target_path.is_relative_to(source_path)
            or target_path.parent == target_path
            or not (target_path / "app" / "remotedesk.py").is_file()
            or not (source_path / "RemoteDesk.exe").is_file()):
        raise ValueError("percorsi dell'aggiornamento non validi")
    prepare = preflight_service(source_path, target_path) if ARGS.mode == "service" else None
    with installation_lock(target_path):
        if prepare:
            prepare()
        return update_locked(os.fspath(target_path))


def update_locked(target):
    transaction = secrets.token_hex(8)
    backup = target + ".precedente-" + transaction
    failed = target + ".fallito-" + transaction
    data_dir = os.path.dirname(os.path.dirname(os.path.abspath(ARGS.log)))
    receipt = {"target": os.path.normcase(os.path.realpath(target)), "version": ARGS.version,
               "nonce": secrets.token_hex(32)}
    pending, ready = (_receipt_path(data_dir, name) for name in ("pending", "ready"))
    # Verifica l'accesso all'archivio protetto prima dell'interruzione.
    _write_receipt(pending, receipt)
    try:
        result = replace_and_verify(target, backup, failed, ready, receipt)
        if result in (0, 1, 2):
            try:
                mark_stage_finished(ARGS.source, stage_root(data_dir, ARGS.mode == "service"))
            except OSError:
                log("pulizia differita della cartella aggiornamento")
        return result
    finally:
        for path in (pending, ready):
            if _read_receipt(path) == receipt:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def replace_and_verify(target, backup, failed, ready, receipt):
    log(f"aggiornamento a {ARGS.version} ({ARGS.mode}) di {target}")
    stop_old()
    if not move_with_retry(target, backup):
        start(target)        # non sono riuscito a toccare nulla: riparto con la versione attuale
        return 1
    try:
        shutil.copytree(ARGS.source, target, ignore=shutil.ignore_patterns("__pycache__"), copy_function=plain_copy)
        old_data = os.path.join(backup, "data")   # vecchie versioni portabili con i dati accanto all'exe
        if ARGS.mode == "user" and os.path.isdir(old_data) and not os.path.exists(os.path.join(target, "data")):
            # Le installazioni portabili storiche possono avere dati accanto all'exe.
            # Un collegamento non deve far attraversare il confine del pacchetto.
            for parent, dirs, files in os.walk(old_data, followlinks=False, onerror=_raise_oserror):
                for path in (Path(parent), *(Path(parent) / name for name in dirs + files)):
                    if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                        raise ValueError("collegamento nei dati portabili")
            shutil.copytree(old_data, os.path.join(target, "data"), copy_function=plain_copy)
    except Exception as e:
        log(f"copia non riuscita: {e}: ripristino")
        if os.path.lexists(target) and not move_with_retry(target, failed):
            return 3
        if not move_with_retry(backup, target):
            return 3
        start(target)
        return 1
    try:
        start(target)
        for _ in range(60):
            time.sleep(2)
            if _read_receipt(ready) == receipt:
                log("nuova versione attiva: aggiornamento completato")
                shutil.rmtree(backup, ignore_errors=True)
                return 0
    except Exception as exc:
        log(f"avvio non riuscito: {exc}")
    log("la nuova versione non risponde: torno alla precedente")
    stop_old()
    if not move_with_retry(target, failed) or not move_with_retry(backup, target):
        log(f"ripristino incompleto. Copia precedente conservata in {backup}")
        return 3
    start(target)
    return 2


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["user", "service"], required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--port", type=int, default=47800)
    ap.add_argument("--version", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--args", default="[]", help="opzioni di avvio originali (modalita' utente)")
    ap.add_argument("--prepare-token", help=argparse.SUPPRESS)
    ap.add_argument("--recover", action="store_true", help="Ripristina la transazione interrotta senza avviare l'app")
    ARGS = ap.parse_args()
    try:
        code = main()
    except Exception as e:
        log(f"errore inatteso: {e}")
        code = 3
    if ARGS.mode == "service":
        run([system_tool("schtasks.exe"), "/Delete", "/TN", "RemoteDeskUpdate", "/F"])
    sys.exit(code)
