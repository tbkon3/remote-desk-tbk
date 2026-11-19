"""Modalita' servizio Windows.

Un'attivita' pianificata parte all'avvio come SYSTEM (sessione 0) ed esegue il
"supervisore", che lancia l'agente come SYSTEM dentro la sessione della console.
Cosi' l'agente vede e controlla anche la schermata di accesso, UAC e puo' inviare
Ctrl+Alt+Canc. Se l'utente cambia (logout/login) l'agente viene rilanciato."""
import logging
import os
import subprocess
import sys
import tempfile
import time
from xml.sax.saxutils import escape

from .common import APP_DIR, INSTALL_DIR, PROGRAM_DATA, ROOT_DIR, WINDOWS_ANCESTOR_POLICY, secure_dir
from .updater import system_tool

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
    if action not in ("--install-service", "--uninstall-service"):
        raise ValueError("operazione servizio non valida")
    try:
        _verify_installation()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        W.message_box(str(exc))
        return False
    pyw, entry, _ = installed_paths()
    return W.run_elevated(pyw, subprocess.list2cmdline(["-E", "-s", entry, action]), INSTALL_DIR)


def installed_paths():
    """Percorsi della copia protetta in Program Files usata dal servizio."""
    pyw = os.path.join(INSTALL_DIR, "runtime", "pythonw.exe")
    return pyw, os.path.join(INSTALL_DIR, "app", "remotedesk.py"), os.path.join(INSTALL_DIR, "RemoteDesk.exe")


def _verify_installation():
    """La registrazione SYSTEM accetta solo un albero predisposto da un amministratore."""
    for path in installed_paths():
        if not os.path.isfile(path) or os.path.normcase(os.path.realpath(path)) != os.path.normcase(os.path.abspath(path)):
            raise RuntimeError("Predisporre la release verificata in " + INSTALL_DIR)
    # Il proprietario puo' cambiare la DACL. Considerare anche i permessi che
    # erediterebbero i nuovi oggetti creati a esecuzione iniziata.
    command = WINDOWS_ANCESTOR_POLICY + r"""
$ErrorActionPreference = 'Stop'
$programs = [Environment]::GetFolderPath('ProgramFiles')
Assert-TrustedAncestry $programs
$root = Join-Path $programs 'RemoteDesk'
$trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$stack = New-Object 'System.Collections.Generic.Stack[string]'
$stack.Push($root)
while ($stack.Count) {
    $next = $stack.Pop()
    $attributes = [IO.File]::GetAttributes($next)
    if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse point' }
    $directory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    $acl = if ($directory) { [IO.Directory]::GetAccessControl($next) } else { [IO.File]::GetAccessControl($next) }
    if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'owner' }
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $sd.DiscretionaryAcl) { throw 'null DACL' }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -eq 'AccessDenied') { continue }
        if ($ace.AceType -ne 'AccessAllowed') { throw 'unsupported ACE' }
        if (([int]$ace.AceFlags -band 8) -and $ace.SecurityIdentifier.Value -eq 'S-1-3-0') { continue }
        if (($trusted -notcontains $ace.SecurityIdentifier.Value) -and ($ace.AccessMask -band 0x500D0156)) { throw 'write' }
    }
    if ($directory) { foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($next)) { $stack.Push($child) } }
}
"""
    # GetSystemDirectory evita PATH, CWD e variabili d'ambiente dell'utente.
    powershell = system_tool(r"WindowsPowerShell\v1.0\powershell.exe")
    system_dir = os.path.dirname(system_tool("schtasks.exe"))
    safe_env = {"SystemRoot": os.path.dirname(system_dir), "Path": system_dir,
                "PSModulePath": os.path.join(os.path.dirname(powershell), "Modules")}
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                            env=safe_env, cwd=system_dir, timeout=180, capture_output=True, creationflags=0x08000000)
    if result.returncode:
        raise RuntimeError("Verificare proprietario e permessi della copia protetta in " + INSTALL_DIR)


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
    <Arguments>{escape(f'-E -s "{installed_paths()[1]}" --service --data "{PROGRAM_DATA}"')}</Arguments>
    <WorkingDirectory>{escape(INSTALL_DIR)}</WorkingDirectory>
  </Exec></Actions>
</Task>"""


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


def install(user_data=None):
    """Registra una copia protetta; l'identita' macchina e' amministrata separatamente."""
    from . import winapi as W
    import winreg
    try:
        if os.path.normcase(os.path.realpath(ROOT_DIR)) != os.path.normcase(INSTALL_DIR):
            raise RuntimeError("Avviare la copia amministrata in " + INSTALL_DIR)
        _verify_installation()
        secure_dir(PROGRAM_DATA)
        with tempfile.NamedTemporaryFile(suffix=".xml", dir=PROGRAM_DATA, delete=False) as f:
            xml = f.name
            f.write(_task_xml().encode("utf-16"))
        try:
            result = W.run_hidden([system_tool("schtasks.exe"), "/Create", "/TN", TASK, "/XML", xml, "/F"])
        finally:
            os.unlink(xml)
        if result.returncode:
            raise RuntimeError(result.stderr or result.stdout)
        _marker({"Service": 1, "UserData": None})
        W.autostart_set(f'"{installed_paths()[2]}" --minimized', "RemoteDeskTray", winreg.HKEY_LOCAL_MACHINE)
        result = W.run_hidden([system_tool("schtasks.exe"), "/Run", "/TN", TASK])
        if result.returncode:
            raise RuntimeError("Attivita' registrata. Avvio non riuscito")
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        W.message_box(f"Installazione del servizio non completata: {exc}")
        return False
    W.message_box("Servizio registrato in " + INSTALL_DIR + ". Chiudere eventuali istanze portabili. "
                  "Configurare l'identita' servizio dal profilo amministrativo.")
    return True


def uninstall(user_data=None):
    from . import winapi as W
    W.run_hidden([system_tool("schtasks.exe"), "/End", "/TN", TASK])
    result = W.run_hidden([system_tool("schtasks.exe"), "/Delete", "/TN", TASK, "/F"])
    if result.returncode:
        W.message_box("Rimozione dell'attivita' non riuscita.")
        return False
    _marker({"Service": None, "UserData": None})
    W.message_box("Servizio rimosso. I dati servizio restano nel profilo protetto. "
                  "La modalita' utente usa la propria identita'.")
    return True


def run_supervisor():
    """Gira come SYSTEM in sessione 0: mantiene l'agente vivo nella sessione della console."""
    from . import winapi as W
    child, child_sess, failures = None, None, 0
    pyw, entry, _ = installed_paths()
    if (os.path.normcase(os.path.realpath(ROOT_DIR)) != os.path.normcase(INSTALL_DIR)
            or os.path.normcase(os.path.realpath(sys.executable)) != os.path.normcase(pyw)):
        raise PermissionError("Il supervisore richiede la copia protetta del servizio")
    _verify_installation()
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
            cmd = f'"{pyw}" -E -s "{entry}" --session-agent --parent {os.getpid()} --data "{PROGRAM_DATA}"'
            child, pid = W.spawn_in_session(sess, cmd, INSTALL_DIR)
            child_sess = sess
            log.info("agente avviato nella sessione %s (pid %s)", sess, pid)
            time.sleep(5)
            if W.process_alive(child):
                failures = 0
        except Exception as e:
            log.exception("supervisore: %s", e)
            time.sleep(5)
