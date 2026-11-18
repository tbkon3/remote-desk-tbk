"""Modalita' servizio Windows.

Un'attivita' pianificata parte all'avvio come SYSTEM (sessione 0) ed esegue il
"supervisore", che lancia l'agente come SYSTEM dentro la sessione della console.
Cosi' l'agente vede e controlla anche la schermata di accesso, UAC e puo' inviare
Ctrl+Alt+Canc. Se l'utente cambia (logout/login) l'agente viene rilanciato."""
import json
import logging
import os
import sys
import tempfile
import time
import urllib.request
from xml.sax.saxutils import escape

import shutil

from .common import (APP_DIR, DEFAULT_PORT, IDENTITY_FILES, INSTALL_DIR, PROGRAM_DATA, ROOT_DIR, WIN,
                     secure_dir)

log = logging.getLogger("rd.service")
TASK = "RemoteDesk"


def pythonw():
    exe = sys.executable
    d = os.path.dirname(exe)
    w = os.path.join(d, "pythonw.exe")
    return w if os.path.exists(w) else exe


def script():
    return os.path.join(APP_DIR, "remotedesk.py")


def launch_command(*args):
    launcher = os.path.join(ROOT_DIR, "RemoteDesk.exe")
    if os.path.exists(launcher):
        return " ".join([f'"{launcher}"', *args])
    return " ".join([f'"{pythonw()}"', f'"{script()}"', *args])


def elevate(action, user_data=None):
    from . import winapi as W
    params = f'"{script()}" {action}'
    if user_data:
        params += f' --from-data "{user_data}"'
    return W.run_elevated(pythonw(), params, ROOT_DIR)


def installed_paths():
    """Percorsi della copia protetta in Program Files usata dal servizio."""
    pyw = os.path.join(INSTALL_DIR, "runtime", "pythonw.exe")
    return pyw, os.path.join(INSTALL_DIR, "app", "remotedesk.py"), os.path.join(INSTALL_DIR, "RemoteDesk.exe")


def _task_xml():
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>RemoteDesk - accesso remoto (servizio)</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>{escape(installed_paths()[0])}</Command>
    <Arguments>{escape(f'"{installed_paths()[1]}" --service --data "{PROGRAM_DATA}"')}</Arguments>
    <WorkingDirectory>{escape(INSTALL_DIR)}</WorkingDirectory>
  </Exec></Actions>
</Task>"""


def _post(path, token=""):
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{DEFAULT_PORT}{path}", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json", "X-RD-Token": token})
        urllib.request.urlopen(req, timeout=3).read()
        return True
    except Exception:
        return False


def _marker(values):
    import winreg
    k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\RemoteDesk", 0,
                           winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    for name, v in values.items():
        if v is None:
            try:
                winreg.DeleteValue(k, name)
            except OSError:
                pass
        else:
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD if isinstance(v, int) else winreg.REG_SZ, v)
    winreg.CloseKey(k)


def _marker_get(name):
    import winreg
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\RemoteDesk", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def install(user_data):
    """Eseguito con diritti di amministratore. Copia RemoteDesk in Program Files (non modificabile dagli
    utenti normali: il servizio SYSTEM non deve mai eseguire codice che un utente puo' cambiare),
    sposta l'identita' del PC in ProgramData (accessibile solo a SYSTEM e Amministratori) e crea
    l'attivita' pianificata."""
    from . import winapi as W
    import winreg
    W.run_hidden(["schtasks", "/End", "/TN", TASK])   # reinstallazione: fermo la versione precedente
    time.sleep(2)
    try:
        if os.path.normcase(os.path.abspath(ROOT_DIR)) != os.path.normcase(os.path.abspath(INSTALL_DIR)):
            shutil.copytree(ROOT_DIR, INSTALL_DIR, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("data", "logs", "__pycache__"))
        os.makedirs(PROGRAM_DATA, exist_ok=True)
        secure_dir(PROGRAM_DATA)
        if user_data and not os.path.exists(os.path.join(PROGRAM_DATA, "config.json")):
            for f in IDENTITY_FILES:   # stesso PC, stessa identita' e stesse reti
                src = os.path.join(user_data, f)
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(PROGRAM_DATA, f))
    except Exception as e:
        W.message_box(f"Installazione del servizio non riuscita (copia dei file): {e}")
        return False
    fd, xml = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    with open(xml, "w", encoding="utf-16") as f:
        f.write(_task_xml())
    r = W.run_hidden(["schtasks", "/Create", "/TN", TASK, "/XML", xml, "/F"])
    os.remove(xml)
    if r.returncode != 0:
        W.message_box("Installazione del servizio non riuscita:\n" + (r.stderr or r.stdout))
        return False
    try:
        W.enable_software_sas()
    except Exception as e:
        log.warning("criterio SAS: %s", e)
    pyw = installed_paths()[0]
    W.run_hidden(["netsh", "advfirewall", "firewall", "delete", "rule", "name=RemoteDesk"])
    W.run_hidden(["netsh", "advfirewall", "firewall", "add", "rule", "name=RemoteDesk", "dir=in", "action=allow",
                  f"program={pyw}", "enable=yes", "profile=any"])
    # icona nella barra per tutti gli utenti, dalla copia protetta (resta anche se il servizio viene rimosso)
    W.autostart_set(f'"{installed_paths()[2]}" --minimized', "RemoteDeskTray", winreg.HKEY_LOCAL_MACHINE)
    W.autostart_set(None)
    _marker({"Service": 1, "UserData": user_data or ""})
    token = ""
    try:
        with open(os.path.join(user_data, "local.token")) as f:
            token = f.read().strip()
    except (OSError, TypeError):
        pass
    _post("/api/handover", token)       # l'agente utente cede il posto
    time.sleep(1.5)
    W.run_hidden(["schtasks", "/Run", "/TN", TASK])
    W.message_box("Modalita' servizio installata in " + INSTALL_DIR + ".\n\nRemoteDesk ora parte con Windows "
                  "(anche prima dell'accesso) e consente Ctrl+Alt+Canc, UAC e schermata di accesso.")
    return True


def uninstall(user_data=None):
    from . import winapi as W
    W.run_hidden(["schtasks", "/End", "/TN", TASK])
    W.run_hidden(["schtasks", "/Delete", "/TN", TASK, "/F"])
    back = _marker_get("UserData") or user_data
    if back and os.path.isdir(PROGRAM_DATA):   # riporto identita' e reti aggiornate all'utente
        os.makedirs(back, exist_ok=True)
        for f in IDENTITY_FILES:
            src = os.path.join(PROGRAM_DATA, f)
            if os.path.exists(src):
                try:
                    shutil.copy2(src, os.path.join(back, f))
                except OSError as e:
                    log.warning("copia %s: %s", f, e)
    _marker({"Service": None})
    W.message_box("Modalita' servizio rimossa. RemoteDesk continua a partire all'accesso dell'utente "
                  "(senza Ctrl+Alt+Canc, UAC e schermata di accesso).")
    return True


def run_supervisor():
    """Gira come SYSTEM in sessione 0: mantiene l'agente vivo nella sessione della console."""
    from . import winapi as W
    child, child_sess, failures = None, None, 0
    log.info("supervisore avviato (pid %s)", os.getpid())
    secure_dir(PROGRAM_DATA)
    while True:
        try:
            sess = W.active_console_session()
            alive = child is not None and W.process_alive(child)
            if alive and (sess == child_sess or sess is None):   # "nessuna sessione" transitoria: non tocco nulla
                time.sleep(2)
                continue
            if child is not None:
                if alive:
                    log.info("sessione console cambiata %s -> %s: riavvio agente", child_sess, sess)
                    W.terminate(child)
                else:
                    failures += 1
                    W.kernel32.CloseHandle(child)
                child = None
            if sess is None:
                time.sleep(2)
                continue
            time.sleep(min(30, 1 + failures * 2))
            cmd = f'"{pythonw()}" "{script()}" --session-agent --parent {os.getpid()} --data "{PROGRAM_DATA}"'
            child, pid = W.spawn_in_session(sess, cmd, ROOT_DIR)
            child_sess = sess
            log.info("agente avviato nella sessione %s (pid %s)", sess, pid)
            time.sleep(5)
            if W.process_alive(child):
                failures = 0
        except Exception as e:
            log.exception("supervisore: %s", e)
            time.sleep(5)
