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

from .common import DEFAULT_PORT, INSTALL_DIR, PROGRAM_DATA, VERSION, known_folder, service_installed, write_private
from .portable_storage import private_dir


def _canonical(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def default_profile():
    return Path(known_folder(0x1c)) / "RemoteDesk" / "portable" / "data"


def is_bundle(root):
    base = Path(root)
    return (_canonical(base) != _canonical(INSTALL_DIR) and (base / "RemoteDesk.exe").is_file()
            and (base / "runtime" / "pythonw.exe").is_file() and (base / "app" / "remotedesk.py").is_file())


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
    return (autostart_get() or "").casefold() == f'"{Path(root) / "RemoteDesk.exe"}" --minimized'.casefold()


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
            if len(base64.b64decode(key.read(100).strip(), validate=True)) != 32:
                return False
        with (folder / "config.json").open(encoding="utf8") as config:
            doc = json.load(config)
        return isinstance(doc, dict) and re.fullmatch("[0-9]{9}", str(doc.get("id", ""))) is not None
    except (OSError, ValueError, RecursionError):
        return False


def installed_profile(override):
    """Keep an installed user-mode tray from starting a second agent with a claimed identity."""
    base = default_profile().parent
    legacy = base.parent / "data"
    data = Path(override) if override else legacy
    if not (data / "portable.lock").is_file():
        return override
    if override:
        raise PermissionError("Questa cartella dati è riservata a un'istanza portabile.")
    separate = base.parent / "installed-data"
    private_dir(separate)
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
        self.registered = service_installed()
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
        if (self.profile / "config.json").exists() or self.registered:
            return
        if not (self.legacy / "config.json").is_file() or not (self.legacy / "machine.key").is_file():
            return
        private_dir(self.legacy, profile=True)
        receipt = _read(self.legacy / ".update-pending.json")
        migrated = _read(self.base / "legacy.json").get("data") == _canonical(self.legacy)
        updating = (receipt.get("version") == VERSION and receipt.get("target") == self.root
                    and isinstance(receipt.get("nonce"), str) and re.fullmatch("[a-f0-9]{64}", receipt["nonce"]))
        identified = (not migrated and not updating and not Path(INSTALL_DIR, "RemoteDesk.exe").exists()
                      and _legacy_autostart(self.root) and _legacy_inactive())
        if migrated or ((updating or identified) and _has_legacy_identity(self.legacy)):
            self.profile = self.legacy

    def __enter__(self):
        try:
            private_dir(self.base.parent)
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
            root_lock = _lock(self.stack, lockdir / (root_hash + ".lock"))
            profile_lock = _lock(self.stack, self.profile / "portable.lock")
            self.owner = root_lock and profile_lock
            if not self.owner and profile_lock:
                raise RuntimeError("Questa copia di RemoteDesk è già aperta con un altro profilo.")
            if self.owner:
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
