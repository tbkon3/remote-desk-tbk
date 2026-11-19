"""Coordinate one user-owned portable identity and the bundle that currently serves it."""
import errno
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
from contextlib import ExitStack

from .common import DEFAULT_PORT, INSTALL_DIR, PROGRAM_DATA, VERSION, known_folder, write_private
from .portable_storage import private_dir


def _canonical(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def default_profile():
    return Path(known_folder(0x1c)) / "RemoteDesk" / "portable" / "data"


def is_bundle(root):
    base = Path(root)
    if _canonical(base) == _canonical(INSTALL_DIR):
        return False
    launcher = base / "RemoteDesk.exe"
    runtime = base / "runtime"
    if not os.path.lexists(launcher) and not os.path.lexists(runtime):
        return False
    if not launcher.is_file() or not (runtime / "pythonw.exe").is_file() or not (base / "app" / "remotedesk.py").is_file():
        raise RuntimeError("Copia portabile incompleta. Ripristinare RemoteDesk.exe e tutti i file dello ZIP.")
    return True


def _overlaps(first, second):
    a, b = Path(_canonical(first)), Path(_canonical(second))
    return a.is_relative_to(b) or b.is_relative_to(a)


def _profile_overlaps_program(profile, root):
    folder, package = Path(_canonical(profile)), Path(_canonical(root))
    if package.is_relative_to(folder):
        return True
    if folder.is_relative_to(package):
        return folder.relative_to(package).parts[0].casefold() in ("app", "runtime", ".remotedesk-update", "remotedesk.exe")
    return False


def _read(path):
    try:
        with path.open("rb") as stream:
            raw = stream.read(8193)
    except FileNotFoundError:
        return {}
    if len(raw) > 8192:
        raise ValueError("Stato dell'istanza portabile non valido")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Stato dell'istanza portabile non valido")
    return result


def _legacy_autostart(root):
    from .winapi import autostart_get
    command = autostart_get()
    expected = f'"{Path(root) / "RemoteDesk.exe"}" --minimized'
    return isinstance(command, str) and command.casefold() == expected.casefold()


def _service_may_own_legacy():
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\RemoteDesk", 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY) as key:
            value, kind = winreg.QueryValueEx(key, "Service")
        return kind != winreg.REG_DWORD or value != 0
    except FileNotFoundError:
        return False
    except OSError:
        # If the service registration is unreadable its historical key is ambiguous.
        return True


def _legacy_inactive():
    # Exclusive availability check only. Never connect to a listener or send it credentials.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if os.name == "nt":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(("127.0.0.1", DEFAULT_PORT))
        except OSError:
            return False
        return True


def _has_legacy_identity(folder):
    try:
        with (folder / "machine.key").open("rb") as key:
            raw = key.read(101)
            if len(raw) > 100 or len(base64.b64decode(raw.strip(), validate=True)) != 32:
                return False
    except (OSError, ValueError):
        return False
    for name in ("config.json", "config.json.bak"):
        try:
            with (folder / name).open(encoding="utf8") as config:
                doc = json.load(config)
            if isinstance(doc, dict) and re.fullmatch("[0-9]{9}", str(doc.get("id", ""))):
                return True
        except (OSError, ValueError, RecursionError):
            continue
    return False


def installed_profile(override, *, standalone=False):
    """Keep an installed user-mode tray from starting a second agent with a claimed identity."""
    base = default_profile().parent
    legacy = base.parent / "data"
    data = Path(override) if override else legacy
    if override and _overlaps(data, Path(PROGRAM_DATA).parent):
        raise PermissionError("Il profilo del servizio è riservato al servizio Windows.")
    if standalone and _canonical(data) == _canonical(legacy) and (_service_may_own_legacy() or not _legacy_inactive()):
        raise PermissionError("Il profilo storico può essere già usato dal servizio o dall'agente precedente. "
                              "Per avviare un agente indipendente, indicare una cartella dati dedicata con --data.")
    if not (data / "portable.lock").is_file():
        return override
    if override:
        raise PermissionError("Questa cartella dati è riservata a un'istanza portabile.")
    separate = base.parent / "installed-data"
    private_dir(separate, profile=True)
    return str(separate)


def current_logon():
    from ctypes import byref, sizeof
    from .local_access_win import _Windows, _SidAndAttributes, PTR, _require
    from .win_identity import logon_id
    win = _Windows()
    token = PTR()
    _require(win.process_token(PTR(-1), 8, byref(token)))
    try:
        sid_data = win.token_data(token, 1, sizeof(_SidAndAttributes))
        sid = win.sid_text(_SidAndAttributes.from_buffer(sid_data).sid)
        if sid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
            raise PermissionError("La copia portabile richiede un account utente Windows.")
        return sid + "/" + logon_id(token).hex()
    finally:
        win.close(token)


def _lock(stack, path):
    f = path.open("a+b")
    try:
        f.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        f.close()
        if exc.errno in (errno.EACCES, errno.EAGAIN) or getattr(exc, "winerror", None) == 33:
            return False
        raise
    stack.callback(f.close)
    return True


def _guard_legacy_writer(stack, profile):
    # 2.3.2 and 2.4.0 open this exact log for writing before loading any user
    # identity, including in --agent-only with a custom port. Deny concurrent
    # access from such a writer for as long as we use its historical profile.
    if os.name != "nt":
        return
    import ctypes as ct
    from .local_access_win import DWORD, PTR, _fn
    logs = profile / "logs"
    private_dir(logs, files=("app.log",))
    kernel = ct.WinDLL("kernel32", winmode=0x800, use_last_error=True)
    create = _fn(kernel, "CreateFileW", PTR, ct.c_wchar_p, DWORD, DWORD, PTR, DWORD, DWORD, PTR)
    close = _fn(kernel, "CloseHandle", ct.c_int, PTR)
    # FILE_READ_DATA | FILE_READ_ATTRIBUTES (participate in share checks),
    # FILE_SHARE_READ / OPEN_ALWAYS / OPEN_REPARSE_POINT.
    handle = create(str(logs / "app.log"), 0x81, 1, None, 4, 0x00200000, None)
    if handle == PTR(-1).value:
        error = ct.get_last_error()
        if error == 32:
            raise RuntimeError("Il profilo storico è in uso. Chiudere l'agente RemoteDesk precedente.")
        raise ct.WinError(error)
    stack.callback(close, handle)


def _listener(port):
    if port is not None and not 0 <= port <= 65535:
        raise ValueError("Porta non valida")
    if port == DEFAULT_PORT:
        raise ValueError("La porta del servizio è riservata. Scegliere un'altra porta per la copia portabile.")
    for _ in range(8):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "nt":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(("127.0.0.1", port or 0))
            if sock.getsockname()[1] != DEFAULT_PORT:
                sock.listen(socket.SOMAXCONN)
                sock.setblocking(False)
                return sock
        except BaseException:
            sock.close()
            raise
        sock.close()
    raise OSError("Nessuna porta locale disponibile")


class Instance:
    def __init__(self, root, override=None):
        self.root = _canonical(root)
        default = default_profile()
        self.base = default.parent
        self.legacy = self.base.parent / "data"
        self.registered = _service_may_own_legacy()
        self.override = override
        self.profile = Path(os.path.abspath(override)) if override else default
        self.actor = current_logon()
        self.sock = None
        self.port = None
        self.owner = False
        self.stack = ExitStack()

    def _select(self):
        # A profile previously assigned to portable stays assigned. A 2.3.2 service
        # could have copied the user machine key, so never adopt an ambiguous legacy profile.
        if self.override:
            if _canonical(self.profile) == _canonical(self.legacy) and self.registered:
                raise PermissionError("Il profilo storico può appartenere al servizio. Usare il profilo portabile.")
            return
        migrated = _read(self.base / "legacy.json").get("data") == _canonical(self.legacy)
        if self.registered and migrated:
            raise PermissionError("Il profilo portabile precedente può essere condiviso con il servizio Windows. "
                                  "Verificare le identità prima del ripristino. Per un'identità separata, "
                                  "indicare una cartella diversa con --data.")
        if self.registered or any((self.profile / name).exists() for name in ("config.json", "config.json.bak", "machine.key")):
            return
        if migrated:
            if not self.legacy.is_dir():
                raise RuntimeError("Profilo portabile precedente non disponibile. Verificare il percorso e il backup.")
            private_dir(self.legacy, profile=True)
            if not _has_legacy_identity(self.legacy):
                raise RuntimeError("Impossibile leggere l'identità portabile precedente. Verificare il profilo e il backup.")
            self.profile = self.legacy
            return
        if not self.legacy.is_dir():
            return
        try:
            private_dir(self.legacy, profile=True)
            receipt = _read(self.legacy / ".update-pending.json")
        except (OSError, ValueError):
            # A historical directory without established provenance cannot supply this identity.
            return
        updating = (receipt.get("version") == VERSION and receipt.get("target") == self.root
                    and isinstance(receipt.get("nonce"), str) and re.fullmatch("[a-f0-9]{64}", receipt["nonce"]))
        identified = (not updating and not Path(INSTALL_DIR, "RemoteDesk.exe").exists()
                      and _legacy_autostart(self.root) and _legacy_inactive())
        if updating or identified:
            if not _has_legacy_identity(self.legacy):
                raise RuntimeError("Il profilo utente precedente non contiene un'identità valida. Verificare il backup.")
            self.profile = self.legacy

    def __enter__(self):
        try:
            private_dir(self.base, files=("legacy.json",))
            self._select()
            if (str(self.profile).startswith("\\\\") or _overlaps(self.profile, Path(PROGRAM_DATA).parent)
                    or _overlaps(self.profile, INSTALL_DIR) or _profile_overlaps_program(self.profile, self.root)
                    or _overlaps(self.profile, self.base / "locks")):
                raise PermissionError("Il profilo portabile deve essere privato e separato da pacchetto e servizio")
            private_dir(self.profile, profile=True)
            lockdir = self.base / "locks"
            root_hash = hashlib.sha256(self.root.encode("utf8")).hexdigest()
            private_dir(lockdir, files=(root_hash + ".lock",))
            if not _lock(self.stack, lockdir / (root_hash + ".lock")):
                return self
            if not _lock(self.stack, self.profile / "portable.lock"):
                self.stack.close()
                return self
            self.owner = True
            if _canonical(self.profile) == _canonical(self.legacy):
                if not _legacy_inactive():
                    raise RuntimeError(f"La porta storica {DEFAULT_PORT} è occupata. Chiudere l'agente precedente "
                                       "prima di utilizzare nuovamente il suo profilo.")
            _guard_legacy_writer(self.stack, self.profile)
            self.state_path.unlink(missing_ok=True)
            return self
        except BaseException:
            self.stack.close()
            raise

    @property
    def state_path(self):
        return self.profile / "instance.json"

    def reserve(self, port):
        if not self.owner:
            raise RuntimeError("Il profilo è già in uso")
        self.sock = self.stack.enter_context(_listener(port))
        self.port = self.sock.getsockname()[1]
        if _canonical(self.profile) == _canonical(self.legacy):
            write_private(self.base / "legacy.json", json.dumps({"data": _canonical(self.profile)}))

    def ready(self):
        record = {"root": self.root, "port": self.port, "pid": os.getpid(), "logon": self.actor}
        write_private(self.state_path, json.dumps(record))

    def existing_port(self):
        obj = _read(self.state_path)
        if not obj:
            return None
        if obj.get("root") != self.root:
            raise RuntimeError(f"Il profilo portabile è aperto da {obj.get('root', '?')}. Chiudere quella copia prima di continuare.")
        if obj.get("logon") != self.actor:
            raise RuntimeError("Questa copia di RemoteDesk è attiva in un'altra sessione Windows.")
        port = obj.get("port")
        if type(port) is not int or not 1 <= port <= 65535 or port == DEFAULT_PORT:
            raise ValueError("Porta dell'istanza non valida")
        return port

    def withdraw(self):
        if self.owner:
            self.state_path.unlink(missing_ok=True)

    def __exit__(self, *exc):
        try:
            self.withdraw()
        finally:
            self.stack.close()
