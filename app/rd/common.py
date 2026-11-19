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

VERSION = "2.4.0"
WIN = sys.platform == "win32"
DEFAULT_PORT = 47800

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../app
ROOT_DIR = os.path.dirname(APP_DIR)                                     # cartella del pacchetto
WEB_DIR = os.path.join(APP_DIR, "web")

log = logging.getLogger("rd")


def known_folder(csidl):
    import ctypes
    from pathlib import PureWindowsPath
    path = ctypes.create_unicode_buffer(260)
    shell = ctypes.WinDLL("shell32", winmode=0x800)  # LOAD_LIBRARY_SEARCH_SYSTEM32
    if shell.SHGetFolderPathW(None, csidl, None, 0, path) != 0 or not path.value:
        raise OSError("Cartella di sistema Windows non disponibile")
    anchor = PureWindowsPath(path.value).anchor
    if (len(anchor) != 3 or anchor[1:] != ":\\" or not anchor[0].isascii() or not anchor[0].isalpha()
            or ctypes.windll.kernel32.GetDriveTypeW(anchor) != 3):  # DRIVE_FIXED
        raise OSError("I dati e i programmi del servizio richiedono un volume locale fisso")
    return path.value


PROGRAM_DATA = os.path.join(known_folder(0x23) if WIN else "/var/lib", "RemoteDesk", "data")
INSTALL_DIR = os.path.join(known_folder(0x26) if WIN else "/opt", "RemoteDesk")
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
    d = os.path.expanduser("~/.local/share/RemoteDesk/data")
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def pick_data_dir(override=None, service=False):
    if service:
        if not WIN:
            raise ValueError("Modalita' servizio disponibile solo su Windows")
        if override and os.path.normcase(os.path.abspath(override)) != os.path.normcase(PROGRAM_DATA):
            raise ValueError("Percorso dati servizio non valido")
        secure_dir(PROGRAM_DATA)
        return PROGRAM_DATA
    if override:
        os.makedirs(override, mode=0o700, exist_ok=True)
        return override
    return user_data_dir()


def secure_dir(d, *, existing=False):
    if not WIN:
        if existing:
            if not os.path.isdir(d):
                raise FileNotFoundError(d)
        else:
            os.makedirs(d, mode=0o700, exist_ok=True)
            os.chmod(d, 0o700)
        return
    from pathlib import Path
    import subprocess
    from .updater import system_tool
    root = Path(PROGRAM_DATA).parent
    target = Path(os.path.abspath(d))
    if not target.is_relative_to(root) or target == root:
        raise ValueError("Percorso servizio non valido")
    shell = system_tool(r"WindowsPowerShell\v1.0\powershell.exe")
    system_dir = os.path.dirname(system_tool("whoami.exe"))
    env = {"SystemRoot": os.path.dirname(system_dir), "PATH": system_dir,
           "PSModulePath": os.path.join(os.path.dirname(shell), "Modules"), "RD_DATA_TARGET": str(target),
           "RD_COMMON_ROOT": str(root.parent),
           "RD_DATA_EXISTING": "1" if existing else "0"}
    command = "$ErrorActionPreference='Stop'\ntry {\n" + DATA_DIRECTORY_POLICY + r"""
} catch {
    $reason = $_.Exception.Message
    if ($reason -notmatch '^(base|path|owner|ACE|DACL|inheritance|missing directory|reparse point|(?:ancestor|parent) (?:owner|replacement|DACL|ACE|link|mutable))$') {
        $reason = $_.Exception.GetType().Name + ' in ' + $_.InvocationInfo.MyCommand.Name
    }
    [Console]::Out.WriteLine(('RDACL {0}; {1}; {2}; {3}' -f $script:aclNode,$reason,$script:aclSid,$script:aclMask))
    exit 1
}
"""
    result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command],
                            cwd=system_dir, env=env, timeout=120, capture_output=True, creationflags=0x08000000)
    if result.returncode:
        lines = getattr(result, "stdout", b"").decode("ascii", errors="replace").splitlines()
        detail = next((line[:180] for line in lines if line.startswith("RDACL ")), "codice " + str(result.returncode))
        raise PermissionError("Verificare proprietario, DACL e collegamenti della cartella dati del servizio (" + detail + ")")
    _private_files_single_link(target)


def _private_files_single_link(target):
    """Impedisce scritture indirette a un altro nome dello stesso file NTFS."""
    import stat

    def fail(error):
        raise error

    for parent, dirs, files in os.walk(target, onerror=fail, followlinks=False):
        for name in dirs + files:
            info = os.lstat(os.path.join(parent, name))
            if getattr(info, "st_file_attributes", 0) & 0x400:
                raise PermissionError("Collegamento nella cartella dati del servizio")
            if not stat.S_ISDIR(info.st_mode) and info.st_nlink != 1:
                raise PermissionError("File con piu' collegamenti nella cartella dati del servizio")


WINDOWS_ANCESTOR_POLICY = r"""
# Un diritto DeleteChild sul padre prevale sul permesso Delete del figlio.
# Su ProgramData Windows consente normalmente di creare nuove sottocartelle.
function Test-NonemptyNtfsDataRoot([string]$dir, $owners) {
    # Su NTFS un reparse point su una directory richiede che sia vuota.
    # Un figlio esistente e non rimovibile la mantiene non vuota anche dopo il controllo.
    if ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($dir)).DriveFormat -ne 'NTFS') { return $false }
    foreach ($name in 'RemoteDesk','Microsoft') {
        $child = [IO.Path]::Combine($dir,$name)
        $item = Get-Item -LiteralPath $child -Force -ErrorAction SilentlyContinue
        if (!$item -or !$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
        $acl = Get-Acl -LiteralPath $child
        if ($owners -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { continue }
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $raw.DiscretionaryAcl) { continue }
        $safe = $true
        foreach ($entry in $raw.DiscretionaryAcl) {
            if (([int]$entry.AceFlags -band 8) -or $entry.AceType -eq 'AccessDenied') { continue }
            if ($entry.AceType -ne 'AccessAllowed' -or
                (($owners -notcontains $entry.SecurityIdentifier.Value) -and ($entry.AccessMask -band 0x500D0150))) {
                $safe = $false
                break
            }
        }
        if ($safe) { return $true }
    }
    return $false
}
function Assert-TrustedAncestry([string]$p, [string]$stockDataRoot = '') {
$systemOwners = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
while ($p) {
    $script:aclNode = if ($p -eq [IO.Path]::GetPathRoot($p)) { 'volume' } else { 'system parent' }
    $obj = Get-Item -LiteralPath $p -Force
    if (!$obj.PSIsContainer -or ($obj.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'base' }
    $sd = Get-Acl -LiteralPath $p
    $script:aclSid = $sd.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($systemOwners -notcontains $script:aclSid) { throw 'ancestor owner' }
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($sd.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'ancestor DACL' }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if (([int]$ace.AceFlags -band 8) -or $ace.AceType -eq 'AccessDenied') { continue }
        if ($ace.AceType -ne 'AccessAllowed') { throw 'ancestor ACE' }
        if (($systemOwners -notcontains $ace.SecurityIdentifier.Value) -and ($ace.AccessMask -band 0x500D0150)) {
            if ($p -eq $stockDataRoot -and $ace.SecurityIdentifier.Value -eq 'S-1-5-32-545' -and
                $ace.AccessMask -eq 0x116 -and (Test-NonemptyNtfsDataRoot $p $systemOwners)) { continue }
            $script:aclSid = $ace.SecurityIdentifier.Value
            $script:aclMask = '{0:X8}' -f $ace.AccessMask
            throw 'ancestor replacement'
        }
    }
    $p = [IO.Path]::GetDirectoryName($p)
}
}
"""


WINDOWS_PRIVATE_DIRECTORY_POLICY = r"""
function Inspect-DataParent([string]$p) {
    $script:aclNode = 'app parent'
    $item = Get-Item -LiteralPath $p -Force
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'parent link' }
    $acl = Get-Acl -LiteralPath $p
    $script:aclSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $script:aclSid) { throw 'parent owner' }
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'parent DACL' }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace.AceType -eq 'AccessDenied') { continue }
        if ($ace.AceType -ne 'AccessAllowed') { throw 'parent ACE' }
        if ($trusted -contains $ace.SecurityIdentifier.Value) { continue }
        if (([int]$ace.AceFlags -band 8) -and $ace.SecurityIdentifier.Value -eq 'S-1-3-0') { continue }
        # GENERIC_READ, GENERIC_EXECUTE, READ_CONTROL, SYNCHRONIZE e lettura/attraversamento.
        if ($ace.AccessMask -band (-bnot 0xA01200A9)) {
            $script:aclSid = $ace.SecurityIdentifier.Value
            $script:aclMask = '{0:X8}' -f $ace.AccessMask
            throw 'parent mutable'
        }
    }
}
function Inspect([string]$p) {
    $script:aclNode = if ($p -eq $env:RD_DATA_TARGET) { 'data root' } elseif ($p -match '\\runtime\\') { 'runtime' } else { 'data child' }
    if ([IO.Path]::GetExtension($p) -eq '.pyc') { $script:aclNode = 'bytecode' }
    $obj = Get-Item -LiteralPath $p -Force
    if ($obj.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse point' }
    $sd = Get-Acl -LiteralPath $p
    $script:aclSid = $sd.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $script:aclSid) { throw 'owner' }
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($sd.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'DACL' }
    $inherits = @{}
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace.AceType -eq 'AccessDenied') { continue }
        if ($ace.AceType -ne 'AccessAllowed' -or ($trusted -notcontains $ace.SecurityIdentifier.Value)) {
            $script:aclSid = $ace.SecurityIdentifier.Value
            $script:aclMask = '{0:X8}' -f $ace.AccessMask
            throw 'ACE'
        }
        if (([int]$ace.AceFlags -band 7) -eq 3 -and ($ace.AccessMask -band 0x1f01ff) -eq 0x1f01ff) {
            $inherits[$ace.SecurityIdentifier.Value] = $true
        }
    }
    if ($obj.PSIsContainer -and (!$inherits['S-1-5-18'] -or !$inherits['S-1-5-32-544'])) { throw 'inheritance' }
}
"""


DATA_DIRECTORY_POLICY = WINDOWS_ANCESTOR_POLICY + r"""
$ErrorActionPreference = 'Stop'
$common = $env:RD_COMMON_ROOT
$base = Join-Path $common 'RemoteDesk'
$trusted = @('S-1-5-18','S-1-5-32-544')
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
""" + WINDOWS_PRIVATE_DIRECTORY_POLICY + r"""
Assert-TrustedAncestry $common $common
$dirs = @()
$p = $env:RD_DATA_TARGET
while ($p -ne $base) {
    $dirs = @($p) + $dirs
    $p = [IO.Path]::GetDirectoryName($p)
    if (!$p) { throw 'path' }
}
foreach ($p in (@($base) + $dirs)) {
    if (![IO.Directory]::Exists($p)) {
        if ($env:RD_DATA_EXISTING -eq '1') { throw 'missing directory' }
        [void][IO.Directory]::CreateDirectory($p, $acl)
    }
    if ($p -eq $base) { Inspect-DataParent $p } else { Inspect $p }
}
$queue = [Collections.Generic.Stack[string]]::new()
$queue.Push($env:RD_DATA_TARGET)
while ($queue.Count) {
    $p = $queue.Pop()
    Inspect $p
    if ([IO.Directory]::Exists($p)) {
        foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($p)) { $queue.Push($child) }
    }
}
"""


def write_private(path, data):
    """Scrittura atomica di un file riservato."""
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".rd-", dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


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
    "ask_confirm": True,
    "allow_control": True,     # mouse/tastiera (altrimenti solo visualizzazione)
    "allow_files": False,
    "allow_clipboard": False,
    "allow_inventory": False,
    "allow_power": False,
    "allow_local_block": False,
    "allow_sas": False,
    "on_air": False,
    "signal": "https://ntfy.sh, mqtts://broker.emqx.io:8883, mqtts://broker.hivemq.com:8883",
    "stun": ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"],
    "turn_url": "", "turn_user": "", "turn_pass": "", "turn_secret": "",
    "incoming_dir": "",        # vuoto = cartella Download dell'utente
    "known": {},               # rubrica: id -> ultime info viste
}


class Config:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "config.json")
        self.lock = threading.Lock()
        self.data = dict(DEFAULTS)
        self._load()
        if self.data.get("security_defaults") != 1:
            # Previous versions persisted even implicit defaults. Require an
            # explicit opt-in again on each endpoint after the schema upgrade.
            self.data.update(ask_confirm=True, allow_files=False, allow_clipboard=False,
                             allow_inventory=False, allow_power=False, allow_local_block=False,
                             allow_sas=False, security_defaults=1)
            self.save()
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
                    values = json.load(f)
                    if not isinstance(values, dict):
                        raise ValueError("configurazione non valida")
                    self.data.update(values)
                return
            except FileNotFoundError:
                if not os.path.isfile(self.path + ".bak"):
                    return
                self._recover()
                return
            except ValueError as e:   # file rovinato: lo metto da parte e uso la copia di sicurezza
                log.error("config rovinata (%s): uso la copia di sicurezza", e)
                self._recover()
                return
            except OSError as e:      # file bloccato o senza permessi: non rigenero l'identita'
                if attempt == 4:
                    raise RuntimeError(f"Impossibile leggere {self.path}: {e}")
                _t.sleep(0.5)

    def _recover(self):
        try:
            with open(self.path + ".bak", encoding="utf-8") as backup:
                values = json.load(backup)
            if not isinstance(values, dict) or not values.get("id"):
                raise ValueError("identità assente")
        except (ValueError, OSError) as exc:
            raise RuntimeError("Impossibile recuperare la configurazione: verificare il backup") from exc
        self.data.update(values)
        write_private(self.path, json.dumps(values, indent=1))

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
        if not isinstance(blob, str) or len(blob) > 4 * 1024 * 1024:
            raise ValueError("segnalazione troppo grande")
        blob = "".join(blob.split())
        data = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
        return json.loads(bounded_decompress(self.key.decrypt(data[:12], data[12:], None), -15))


def bounded_decompress(data, wbits, limit=8 * 1024 * 1024):
    stream = zlib.decompressobj(wbits)
    raw = stream.decompress(data, limit + 1)
    if len(raw) > limit or not stream.eof or stream.unused_data:
        raise ValueError("dati compressi non validi o troppo grandi")
    return raw
