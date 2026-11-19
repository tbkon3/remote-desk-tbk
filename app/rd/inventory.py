"""Inventario locale Windows. Chiamare sul thread che impersona l'utente autorizzato."""
import ctypes as ct
import os
import string
from contextlib import contextmanager

try:
    import winreg
except ImportError:
    winreg = None


MAX_ROWS = 512
MAX_TEXT = 256
MAX_REG_KEYS = 4096
DWORD = ct.c_uint32
PDWORD = ct.POINTER(DWORD)
HANDLE = ct.c_void_p
PHANDLE = ct.POINTER(HANDLE)
WSTRING = ct.c_wchar_p
MORE_DATA = 234


def _dll(name):
    return ct.WinDLL(name, use_last_error=True, winmode=0x800)  # LOAD_LIBRARY_SEARCH_SYSTEM32


def _bind(dll, name, result, *args):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, args
    return function


class _Result:
    def __init__(self):
        self.rows = []
        self.notes = []
        self.partial = False

    def note(self, message, partial=False):
        if message not in self.notes:
            self.notes.append(message)
        self.partial |= partial

    def add(self, **row):
        if len(self.rows) >= MAX_ROWS:
            self.note(f"Mostrati i primi {MAX_ROWS} risultati.", True)
            return False
        clean = {}
        for key, value in row.items():
            value = value or ""
            if len(value) > MAX_TEXT:
                self.note("Alcuni testi sono stati abbreviati.", True)
            # Registro e commenti delle share possono contenere controlli o surrogate isolate.
            value = value[:MAX_TEXT].encode("utf-8", errors="replace").decode("utf-8")
            clean[key] = "".join(c if c.isprintable() else " " for c in value)
        self.rows.append(clean)
        return True

    def finish(self):
        self.rows.sort(key=lambda row: (row.get("name") or row.get("drive") or "").casefold())
        return {"rows": self.rows, "partial": self.partial, "note": " ".join(self.notes)}


class _Share(ct.Structure):
    _fields_ = [("name", WSTRING), ("type", DWORD), ("remark", WSTRING)]


def _shares(result):
    net = _dll("netapi32")
    enum = _bind(net, "NetShareEnum", DWORD, WSTRING, DWORD, PHANDLE, DWORD, PDWORD, PDWORD, PDWORD)
    free = _bind(net, "NetApiBufferFree", DWORD, HANDLE)
    resume = DWORD()
    for _ in range(64):
        buf, count, total = HANDLE(), DWORD(), DWORD()
        status = enum(None, 1, ct.byref(buf), 65536, ct.byref(count), ct.byref(total), ct.byref(resume))
        try:
            if status not in (0, MORE_DATA):
                raise ct.WinError(status)
            entries = ct.cast(buf, ct.POINTER(_Share))
            for idx in range(count.value):
                share = entries[idx]
                if (share.type & 0xFF) != 0:  # solo condivisioni disco, non pipe o stampanti
                    continue
                kind = "Disco (speciale)" if share.type & 0x80000000 else "Disco"
                if not result.add(name=share.name, type=kind, description=share.remark):
                    return
        finally:
            if buf:
                free(buf)
        if status == 0:
            return
    result.note("Limite di enumerazione delle condivisioni raggiunto.", True)


def _drives(result):
    get = _bind(_dll("mpr"), "WNetGetConnectionW", DWORD, WSTRING, WSTRING, PDWORD)
    # Query solo sui nomi di dispositivo locali; nessuna connessione o esplorazione della rete.
    for letter in string.ascii_uppercase:
        drive = letter + ":"
        size = DWORD(1024)
        buf = ct.create_unicode_buffer(size.value)
        status = get(drive, buf, ct.byref(size))
        if status == MORE_DATA and 1024 < size.value <= 32768:
            buf = ct.create_unicode_buffer(size.value)
            status = get(drive, buf, ct.byref(size))
        if status == 0:
            result.add(drive=drive, remote=buf.value)
        elif status == 1201:  # ERROR_CONNECTION_UNAVAIL: mappatura persistente disconnessa
            result.add(drive=drive, remote="Connessione persistente disconnessa")
            result.note("Per le unità disconnesse la destinazione potrebbe non essere disponibile.", True)
        elif status not in (1200, 2250):  # ERROR_BAD_DEVICE, ERROR_NOT_CONNECTED
            result.note("Il provider di rete non ha restituito tutte le mappature.", True)
    result.note("Unità mappate della sessione Windows che effettua la lettura.")


class _ProcessStatus(ct.Structure):
    _fields_ = [(name, DWORD) for name in ("type", "state", "controls", "exit", "specific",
                                            "checkpoint", "wait", "pid", "flags")]


class _Service(ct.Structure):
    _fields_ = [("name", WSTRING), ("display", WSTRING), ("status", _ProcessStatus)]


_STATES = {1: "Fermo", 2: "In avvio", 3: "In arresto", 4: "In esecuzione",
           5: "In ripresa", 6: "In pausa imminente", 7: "In pausa"}
_START = {0: "Boot", 1: "Sistema", 2: "Automatico", 3: "Manuale", 4: "Disabilitato"}


def _service_start(name, result):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services" + "\\" + name,
                            0, winreg.KEY_QUERY_VALUE) as key:
            mode, kind = winreg.QueryValueEx(key, "Start")
        if kind == winreg.REG_DWORD:
            return _START.get(mode, "")
    except OSError:
        pass
    result.note("Tipo di avvio non disponibile per alcuni servizi.", True)
    return ""


def _services(result):
    adv = _dll("advapi32")
    scm_open = _bind(adv, "OpenSCManagerW", HANDLE, WSTRING, WSTRING, DWORD)
    scm_close = _bind(adv, "CloseServiceHandle", ct.c_int, HANDLE)
    enum = _bind(adv, "EnumServicesStatusExW", ct.c_int, HANDLE, DWORD, DWORD, DWORD,
                 HANDLE, DWORD, PDWORD, PDWORD, PDWORD, WSTRING)
    manager = scm_open(None, None, 0x0004)  # SC_MANAGER_ENUMERATE_SERVICE
    if not manager:
        raise ct.WinError(ct.get_last_error())
    try:
        resume = DWORD()
        # SCM può omettere servizi privi del diritto SERVICE_QUERY_STATUS.
        result.note("Sono mostrati i servizi Win32 visibili all'utente della sessione. "
                    "Windows può omettere i servizi con accesso limitato.", True)
        for _ in range(64):
            buf = ct.create_string_buffer(256 * 1024)
            needed, count = DWORD(), DWORD()
            ok = enum(manager, 0, 0x30, 3, buf, len(buf), ct.byref(needed),
                      ct.byref(count), ct.byref(resume), None)
            status = 0 if ok else ct.get_last_error()
            if status not in (0, MORE_DATA):
                raise ct.WinError(status)
            services = ct.cast(buf, ct.POINTER(_Service))
            for idx in range(count.value):
                svc = services[idx]
                if not result.add(name=svc.name, display=svc.display,
                                  status=_STATES.get(svc.status.state, "Sconosciuto"),
                                  start=_service_start(svc.name, result)):
                    return
            if ok:
                return
        result.note("Limite di enumerazione dei servizi raggiunto.", True)
    finally:
        scm_close(manager)


def _user_sid():
    """Risolve solo il SID del token effettivo. Il profilo predefinito non è un fallback valido."""
    adv, kernel = _dll("advapi32"), _dll("kernel32")
    open_thread = _bind(adv, "OpenThreadToken", ct.c_int, HANDLE, DWORD, ct.c_int, PHANDLE)
    open_process = _bind(adv, "OpenProcessToken", ct.c_int, HANDLE, DWORD, PHANDLE)
    info = _bind(adv, "GetTokenInformation", ct.c_int, HANDLE, DWORD, HANDLE, DWORD, PDWORD)
    convert = _bind(adv, "ConvertSidToStringSidW", ct.c_int, HANDLE, PHANDLE)
    close = _bind(kernel, "CloseHandle", ct.c_int, HANDLE)
    free = _bind(kernel, "LocalFree", HANDLE, HANDLE)
    token = HANDLE()
    if not open_thread(HANDLE(-2), 8, True, ct.byref(token)):  # TOKEN_QUERY
        error = ct.get_last_error()
        if error != 1008:  # ERROR_NO_TOKEN
            raise ct.WinError(error)
        if not open_process(HANDLE(-1), 8, ct.byref(token)):
            raise ct.WinError(ct.get_last_error())
    try:
        data, size = ct.create_string_buffer(1024), DWORD()  # TOKEN_USER e SID, max SID 68 byte
        if not info(token, 1, data, len(data), ct.byref(size)):
            raise ct.WinError(ct.get_last_error())
        sid_ptr = ct.cast(data, ct.POINTER(HANDLE))[0]
        text = HANDLE()
        if not convert(sid_ptr, ct.byref(text)):
            raise ct.WinError(ct.get_last_error())
        try:
            return ct.wstring_at(text)
        finally:
            free(text)
    finally:
        close(token)


@contextmanager
def _user_hive():
    sid = _user_sid()
    if sid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
        raise PermissionError("Profilo interattivo non disponibile")
    with winreg.OpenKey(winreg.HKEY_USERS, sid, 0, winreg.KEY_READ) as hive:
        yield hive


def _app_text(key, name, result, get_value):
    # Un valore applicativo anomalo non deve far allocare all'agente una stringa arbitraria.
    buf = ct.create_unicode_buffer(2048)
    size = DWORD(ct.sizeof(buf))
    flags = 0x10000000 | 0x2 | 0x4  # RRF_NOEXPAND | RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ
    status = get_value(int(key), None, name, flags, None, buf, ct.byref(size))
    if status == 0:
        return buf.value.strip()
    if status not in (2, 3):  # valore assente
        result.note("Alcuni metadati applicativi sono illeggibili o troppo lunghi.", True)
    return ""


def _app_entries(hive, scope, seen, result, get_value):
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as root:
                count = winreg.QueryInfoKey(root)[0]
                if count > MAX_REG_KEYS:
                    result.note("Raggiunto il limite di voci di registro per vista.", True)
                for idx in range(min(count, MAX_REG_KEYS)):
                    try:
                        subkey = winreg.EnumKey(root, idx)
                        with winreg.OpenKey(root, subkey, 0, winreg.KEY_QUERY_VALUE | view) as key:
                            name = _app_text(key, "DisplayName", result, get_value)
                            if not name:
                                continue
                            version = _app_text(key, "DisplayVersion", result, get_value)
                            publisher = _app_text(key, "Publisher", result, get_value)
                        identity = (subkey.casefold(), name, version, publisher, scope)
                        if identity not in seen:
                            if not result.add(name=name, version=version, publisher=publisher, scope=scope):
                                return
                            seen.add(identity)
                    except FileNotFoundError:
                        continue  # un'app può essere rimossa durante la lettura
                    except OSError:
                        result.note("Alcune voci applicative non sono leggibili.", True)
        except FileNotFoundError:
            continue
        except OSError:
            result.note(f"Registro applicazioni ({scope}) non interamente accessibile.", True)


def _apps(result):
    result.note("Applicazioni registrate per macchina e utente corrente. "
                "Software portabili e pacchetti MSIX/AppX possono essere assenti.", True)
    get_value = _bind(_dll("advapi32"), "RegGetValueW", ct.c_int32,
                      HANDLE, WSTRING, WSTRING, DWORD, PDWORD, HANDLE, PDWORD)
    seen = set()
    _app_entries(winreg.HKEY_LOCAL_MACHINE, "Macchina", seen, result, get_value)
    try:
        with _user_hive() as hive:
            _app_entries(hive, "Utente", seen, result, get_value)
    except OSError:
        result.note("Profilo dell'utente della sessione non disponibile.", True)


COLLECTORS = {"shares": _shares, "drives": _drives, "services": _services, "apps": _apps}


def read_section(section):
    if not isinstance(section, str) or section not in COLLECTORS:
        raise ValueError("Sezione inventario sconosciuta")
    if os.name != "nt":
        raise RuntimeError("L'inventario è disponibile sui PC Windows")
    result = _Result()
    try:
        COLLECTORS[section](result)
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        result.note(f"Impossibile completare la lettura Windows (errore {code}).", True)
    return result.finish()
