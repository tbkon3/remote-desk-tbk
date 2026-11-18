"""Installatore degli aggiornamenti (eseguito dalla copia NUOVA, mai da quella da sostituire).

Modalita' utente:  aspetta/chiude RemoteDesk, sostituisce la cartella, riavvia RemoteDesk.exe.
Modalita' servizio: ferma l'attivita' "RemoteDesk", sostituisce Program Files\\RemoteDesk,
                    riavvia il servizio e l'icona dell'utente collegato.
In entrambi i casi verifica che la nuova versione risponda; altrimenti ripristina la precedente.
Solo libreria standard: non importa nulla dalla cartella che sta sostituendo."""
import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

NOWIN = 0x08000000


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
    """Chiude ogni processo il cui eseguibile sta in quella cartella."""
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith('"
          + folder.rstrip("\\").replace("'", "''") + "\\', 'OrdinalIgnoreCase') } | "
          "ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }")
    run(["powershell", "-NoProfile", "-Command", ps])


def ping(port, version):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/public", timeout=3) as r:
            return json.loads(r.read()).get("version") == version
    except Exception:
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
        run(["schtasks", "/End", "/TN", "RemoteDesk"])
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
        code, out = run(["schtasks", "/Run", "/TN", "RemoteDesk"])
        log(f"avvio servizio: {code} {out.strip()}")
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


def main():
    target = os.path.abspath(ARGS.target)
    backup = target + ".precedente"
    log(f"aggiornamento a {ARGS.version} ({ARGS.mode}) di {target}")
    stop_old()
    if os.path.exists(backup):
        shutil.rmtree(backup, ignore_errors=True)
    if not move_with_retry(target, backup):
        start(target)        # non sono riuscito a toccare nulla: riparto con la versione attuale
        return 1
    try:
        shutil.copytree(ARGS.source, target, ignore=shutil.ignore_patterns("__pycache__"), copy_function=plain_copy)
        old_data = os.path.join(backup, "data")   # vecchie versioni portabili con i dati accanto all'exe
        if os.path.isdir(old_data) and not os.path.exists(os.path.join(target, "data")):
            shutil.copytree(old_data, os.path.join(target, "data"), copy_function=plain_copy)
    except Exception as e:
        log(f"copia non riuscita: {e}: ripristino")
        shutil.rmtree(target, ignore_errors=True)
        move_with_retry(backup, target)
        start(target)
        return 1
    start(target)
    for _ in range(60):      # fino a 2 minuti per vedere la nuova versione rispondere
        time.sleep(2)
        if ping(ARGS.port, ARGS.version):
            log("nuova versione attiva: aggiornamento completato")
            shutil.rmtree(backup, ignore_errors=True)
            return 0
    log("la nuova versione non risponde: torno alla precedente")
    stop_old()
    failed = target + ".fallito"
    shutil.rmtree(failed, ignore_errors=True)
    move_with_retry(target, failed)
    move_with_retry(backup, target)
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
        run(["schtasks", "/Delete", "/TN", "RemoteDeskUpdate", "/F"])
    sys.exit(code)
