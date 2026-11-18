"""Percorsi, configurazione, log, crittografia e identita' della macchina."""
import base64
import getpass
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import secrets
import socket
import sys
import threading
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = "2.2.2"
WIN = sys.platform == "win32"
DEFAULT_PORT = 47800

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../app
ROOT_DIR = os.path.dirname(APP_DIR)                                     # cartella del pacchetto
WEB_DIR = os.path.join(APP_DIR, "web")

log = logging.getLogger("rd")


def _writable(d):
    try:
        os.makedirs(d, exist_ok=True)
        import tempfile
        with tempfile.NamedTemporaryFile(dir=d, delete=True):
            pass
        return True
    except Exception:
        return False


PROGRAM_DATA = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "RemoteDesk", "data")
INSTALL_DIR = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "RemoteDesk")
IDENTITY_FILES = ("config.json", "config.json.bak", "machine.key", "audit.jsonl")


def user_data_dir():
    """Dati dell'utente: su Windows nel profilo (privato), non accanto all'exe."""
    if WIN:
        d = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "RemoteDesk", "data")
        old = os.path.join(ROOT_DIR, "data")
        if not os.path.exists(os.path.join(d, "config.json")) and os.path.exists(os.path.join(old, "config.json")):
            import shutil  # migrazione dalla 2.0-2.2 (dati accanto all'exe)
            os.makedirs(d, exist_ok=True)
            for f in IDENTITY_FILES:
                if os.path.exists(os.path.join(old, f)):
                    shutil.copy2(os.path.join(old, f), os.path.join(d, f))
        os.makedirs(d, exist_ok=True)
        return d
    d = os.path.join(ROOT_DIR, "data")
    if _writable(d):
        return d
    d = os.path.join(os.path.expanduser("~/.local/share"), "RemoteDesk", "data")
    os.makedirs(d, exist_ok=True)
    return d


def pick_data_dir(override=None, service=False):
    if override:
        os.makedirs(override, exist_ok=True)
        return override
    if service and WIN:
        os.makedirs(PROGRAM_DATA, exist_ok=True)
        return PROGRAM_DATA
    return user_data_dir()


def secure_dir(d, include_user=False):
    """Windows: cartella leggibile solo da SYSTEM e Amministratori (piu' l'utente, se richiesto)."""
    if not WIN:
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        return
    import subprocess
    args = ["icacls", d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F"]
    if include_user:
        args += ["/grant:r", f"{os.environ.get('USERNAME', '')}:(OI)(CI)F"]
    subprocess.run(args, capture_output=True, creationflags=0x08000000)


def write_private(path, data):
    """Scrittura atomica di un file riservato."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def service_installed(data_dir=None):
    if WIN:
        import winreg
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\RemoteDesk", 0,
                               winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            v, _ = winreg.QueryValueEx(k, "Service")
            return bool(v)
        except OSError:
            return False
    return bool(data_dir) and os.path.exists(os.path.join(data_dir, "service.json"))


def setup_logging(data_dir, mode, verbose=False):
    if sys.stdout is None:  # pythonw.exe non ha console
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")
    logs = os.path.join(data_dir, "logs")
    os.makedirs(logs, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(
        os.path.join(logs, f"{mode}.log"), maxBytes=1_000_000, backupCount=2, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)
    for noisy in ("aioice", "aiortc", "aiohttp.access", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# --------------------------------------------------------------------------- config
DEFAULTS = {
    "name": socket.gethostname(),
    "network": "",
    "password": "",
    "accept_incoming": True,   # questo PC puo' essere controllato
    "ask_confirm": False,      # chiedi conferma all'utente prima di accettare
    "allow_control": True,     # mouse/tastiera (altrimenti solo visualizzazione)
    "allow_files": True,
    "allow_clipboard": True,
    "signal": "https://ntfy.sh",
    "stun": ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"],
    "turn_url": "", "turn_user": "", "turn_pass": "",
    "incoming_dir": "",        # vuoto = cartella Download dell'utente
    "known": {},               # rubrica: id -> ultime info viste
}


class Config:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "config.json")
        self.lock = threading.Lock()
        self.data = dict(DEFAULTS)
        self._load()
        if not self.data.get("id"):
            self.data["id"] = str(secrets.randbelow(900_000_000) + 100_000_000)
            self.save()

    def __getitem__(self, k):
        return self.data.get(k, DEFAULTS.get(k))

    def get(self, k, d=None):
        return self.data.get(k, d)

    def update(self, **kw):
        with self.lock:
            self.data.update(kw)
        self.save()

    def _load(self):
        import time as _t
        for attempt in range(5):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self.data.update(json.load(f))
                return
            except FileNotFoundError:
                return
            except ValueError as e:   # file rovinato: lo metto da parte e uso la copia di sicurezza
                log.error("config rovinata (%s): uso la copia di sicurezza", e)
                try:
                    os.replace(self.path, self.path + f".corrupt-{int(_t.time())}")
                    with open(self.path + ".bak", encoding="utf-8") as f:
                        self.data.update(json.load(f))
                except Exception:
                    pass
                return
            except OSError as e:      # file bloccato o senza permessi: non rigenero l'identita'
                if attempt == 4:
                    raise RuntimeError(f"Impossibile leggere {self.path}: {e}")
                _t.sleep(0.5)

    def reload(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data.update(json.load(f))
        except Exception:
            pass

    def save(self):
        with self.lock:
            data = json.dumps(self.data, indent=1)
            write_private(self.path, data)
            try:
                write_private(self.path + ".bak", data)
            except OSError:
                pass


def machine_fingerprint():
    """Identifica il PC fisico (per accorgersi di cartelle copiate da un altro PC)."""
    if os.environ.get("RD_FP"):
        return os.environ["RD_FP"]
    raw = ""
    if WIN:
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                               winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            raw = winreg.QueryValueEx(k, "MachineGuid")[0]
        except OSError:
            pass
    else:
        for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                raw = open(f).read().strip()
                break
            except OSError:
                pass
    if not raw:
        return None
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def legacy_fingerprint():
    """Formula della 2.2 preliminare (includeva il nome del PC)."""
    fp = machine_fingerprint()
    if fp is None or os.environ.get("RD_FP"):
        return None
    raw = ""
    if WIN:
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                               winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            raw = winreg.QueryValueEx(k, "MachineGuid")[0]
        except OSError:
            pass
    else:
        for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                raw = open(f).read().strip()
                break
            except OSError:
                pass
    return hashlib.sha256((raw + "|" + socket.gethostname().lower()).encode()).hexdigest()[:24]


def fmt_id(i):
    i = str(i)
    return " ".join(i[k:k + 3] for k in range(0, len(i), 3))


def os_label():
    if WIN:
        try:
            build = int(platform.version().split(".")[-1])
            return "Windows 11" if build >= 22000 else f"Windows {platform.release()}"
        except Exception:
            return "Windows"
    if sys.platform == "darwin":
        return "macOS " + platform.mac_ver()[0]
    return platform.system() + " " + platform.release()


def current_user():
    try:
        return getpass.getuser()
    except Exception:
        return ""


# --------------------------------------------------------------------------- crypto
class NetKey:
    """Chiave di rete: dal nome rete + password derivo topic (pubblico) e chiave AES."""

    def __init__(self, network, password):
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), ("rdnet:" + network.strip().lower()).encode(),
                                 150_000, dklen=52)
        self.key = AESGCM(dk[:32])
        self.topic = "rdn-" + dk[32:52].hex()

    def seal(self, obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        comp = c.compress(raw) + c.flush()
        nonce = os.urandom(12)
        return base64.urlsafe_b64encode(nonce + self.key.encrypt(nonce, comp, None)).decode().rstrip("=")

    def unseal(self, blob):
        blob = "".join(blob.split())
        data = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
        return json.loads(zlib.decompress(self.key.decrypt(data[:12], data[12:], None), -15))
