"""Installatore degli aggiornamenti (eseguito dalla copia NUOVA, mai da quella da sostituire).

Modalita' utente:  aspetta/chiude RemoteDesk, sostituisce la cartella, riavvia RemoteDesk.exe.
Modalita' servizio: ferma l'attivita' "RemoteDesk", sostituisce Program Files\\RemoteDesk,
                    riavvia il servizio e l'icona dell'utente collegato.
In entrambi i casi verifica che la nuova versione risponda; altrimenti ripristina la precedente.
Solo libreria standard: non importa nulla dalla cartella che sta sostituendo."""
import argparse
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time

NOWIN = 0x08000000


def system_tool(name):
    """Percorso assoluto dalla cartella di sistema restituita da Windows."""
    buf = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf))
    if not 0 < length < len(buf):
        raise OSError("cartella di sistema Windows non disponibile")
    return os.path.join(buf.value, name)


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    try:
        with open(ARGS.log, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def run(args):
    r = subprocess.run(args, capture_output=True, text=True, creationflags=NOWIN)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def pid_alive(pid):
    k = ctypes.windll.kernel32
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


def main():
    target = os.path.abspath(ARGS.target)
    source_path, target_path = plain_path(ARGS.source), plain_path(target)
    if (source_path.is_relative_to(target_path) or target_path.is_relative_to(source_path)
            or target_path.parent == target_path
            or not (target_path / "app" / "remotedesk.py").is_file()
            or not (source_path / "RemoteDesk.exe").is_file()):
        raise ValueError("percorsi dell'aggiornamento non validi")
    with installation_lock(target_path):
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
    ARGS = ap.parse_args()
    try:
        code = main()
    except Exception as e:
        log(f"errore inatteso: {e}")
        code = 3
    if ARGS.mode == "service":
        run([system_tool("schtasks.exe"), "/Delete", "/TN", "RemoteDeskUpdate", "/F"])
    sys.exit(code)
