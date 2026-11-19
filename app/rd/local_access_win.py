"""Read-only, logon-scoped secret shared by the interactive SYSTEM worker and its tray."""
import ctypes as ct
import os
import re
import secrets


DWORD = ct.c_uint32
PTR = ct.c_void_p
PPTR = ct.POINTER(PTR)
PDWORD = ct.POINTER(DWORD)
SECRET_SIZE = 32
SYSTEM = "S-1-5-18"
FILE_MAP_READ = 4
READ_CONTROL = 0x20000


class _SecurityAttributes(ct.Structure):
    _fields_ = [("size", DWORD), ("descriptor", PTR), ("inherit", ct.c_int)]


class _SidAndAttributes(ct.Structure):
    _fields_ = [("sid", PTR), ("attributes", DWORD)]


class _TokenLogonSid(ct.Structure):
    _fields_ = [("count", DWORD), ("group", _SidAndAttributes)]


def _fn(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = result, args
    return fn


def _require(value):
    if not value:
        raise ct.WinError(ct.get_last_error())
    return value


class _Windows:
    def __init__(self):
        if os.name != "nt":
            raise OSError("Sessione Windows richiesta")
        def dll(name):
            return ct.WinDLL(name, winmode=0x800, use_last_error=True)
        kernel, adv, wts = dll("kernel32"), dll("advapi32"), dll("wtsapi32")
        self.close = _fn(kernel, "CloseHandle", ct.c_int, PTR)
        self.free = _fn(kernel, "LocalFree", PTR, PTR)
        self.session = _fn(kernel, "ProcessIdToSessionId", ct.c_int, DWORD, PDWORD)
        self.user_token = _fn(wts, "WTSQueryUserToken", ct.c_int, DWORD, PPTR)
        self.process_token = _fn(adv, "OpenProcessToken", ct.c_int, PTR, DWORD, PPTR)
        self.token_info = _fn(adv, "GetTokenInformation", ct.c_int, PTR, DWORD, PTR, DWORD, PDWORD)
        self.sid_string = _fn(adv, "ConvertSidToStringSidW", ct.c_int, PTR, PPTR)
        self.descriptor = _fn(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                              ct.c_int, ct.c_wchar_p, DWORD, PPTR, PDWORD)
        self.create = _fn(kernel, "CreateFileMappingW", PTR, PTR, ct.POINTER(_SecurityAttributes),
                          DWORD, DWORD, DWORD, ct.c_wchar_p)
        self.open = _fn(kernel, "OpenFileMappingW", PTR, DWORD, ct.c_int, ct.c_wchar_p)
        self.map = _fn(kernel, "MapViewOfFile", PTR, PTR, DWORD, DWORD, DWORD, ct.c_size_t)
        self.unmap = _fn(kernel, "UnmapViewOfFile", ct.c_int, PTR)
        self.security = _fn(adv, "GetSecurityInfo", DWORD, PTR, DWORD, DWORD, PPTR, PPTR, PPTR, PPTR, PPTR)

    def sid_text(self, sid):
        text = PTR()
        _require(self.sid_string(sid, ct.byref(text)))
        try:
            return ct.wstring_at(text)
        finally:
            self.free(text)

    def token_data(self, token, kind, minimum):
        size = DWORD()
        self.token_info(token, kind, None, 0, ct.byref(size))
        if not minimum <= size.value <= 65536:
            raise OSError("Identità del processo non disponibile")
        data = ct.create_string_buffer(size.value)
        _require(self.token_info(token, kind, data, len(data), ct.byref(size)))
        return data

    def logon_sid(self):
        # The service launches this worker in the assisted Windows session.
        session = DWORD()
        _require(self.session(os.getpid(), ct.byref(session)))
        if not session.value:
            raise OSError("Nessuna sessione desktop associata al processo")
        token = PTR()
        _require(self.user_token(session, ct.byref(token)))
        try:
            data = self.token_data(token, 28, ct.sizeof(_TokenLogonSid))
            info = _TokenLogonSid.from_buffer(data)
            if info.count != 1 or not info.group.sid:
                raise OSError("SID della sessione non valido")
            sid = self.sid_text(info.group.sid)
            if not re.fullmatch(r"S-1-5-5-[0-9]+-[0-9]+", sid):
                raise OSError("SID di accesso interattivo non valido")
            return sid
        finally:
            self.close(token)

    def verify_owner(self, handle):
        sid, descriptor = PTR(), PTR()
        result = self.security(handle, 6, 1, ct.byref(sid), None, None, None, ct.byref(descriptor))
        if result:
            raise ct.WinError(result)
        try:
            if not sid.value or self.sid_text(sid) != SYSTEM:
                raise PermissionError("Oggetto desktop estraneo al servizio")
        finally:
            self.free(descriptor)


def running_as_system():
    win = _Windows()
    token = PTR()
    _require(win.process_token(PTR(-1), 8, ct.byref(token)))  # GetCurrentProcess(), TOKEN_QUERY
    try:
        data = win.token_data(token, 1, ct.sizeof(_SidAndAttributes))  # TokenUser
        return win.sid_text(_SidAndAttributes.from_buffer(data).sid) == SYSTEM
    finally:
        win.close(token)


def _mapping_name(port, identifier):
    if not re.fullmatch("[a-f0-9]{32}", identifier):
        raise ValueError("Identificativo desktop non valido")
    return r"Local\RemoteDesk-Desktop-%d-%s" % (port, identifier)


class DesktopMapping:
    def __init__(self, port):
        self.port = port
        self.windows = _Windows()
        self.handle = self.sid = self.secret = self.identifier = None

    def close(self):
        if self.handle:
            self.windows.close(self.handle)
        self.handle = self.sid = self.secret = self.identifier = None

    def current(self):
        try:
            sid = self.windows.logon_sid()
        except OSError:
            self.close()
            raise
        if self.sid == sid:
            return self.secret, self.identifier
        self.close()
        key, identifier = secrets.token_bytes(SECRET_SIZE), secrets.token_hex(16)
        # The logon SID is unique per interactive login, including RDP and fast user switching.
        sddl = f"O:SYD:P(A;;GA;;;SY)(A;;0x00020004;;;{sid})"
        win = self.windows
        descriptor = PTR()
        _require(win.descriptor(sddl, 1, ct.byref(descriptor), None))
        try:
            sa = _SecurityAttributes(ct.sizeof(_SecurityAttributes), descriptor, 0)
            ct.set_last_error(0)
            handle = _require(win.create(PTR(-1), ct.byref(sa), 4, 0, SECRET_SIZE,
                                         _mapping_name(self.port, identifier)))
            existing = ct.get_last_error() == 183
        finally:
            win.free(descriptor)
        try:
            if existing:
                raise PermissionError("Nome desktop già assegnato")
            win.verify_owner(handle)
            view = _require(win.map(handle, 2, 0, 0, SECRET_SIZE))
            try:
                ct.memmove(view, key, SECRET_SIZE)
            finally:
                win.unmap(view)
        except BaseException:
            win.close(handle)
            raise
        self.handle, self.sid, self.secret, self.identifier = handle, sid, key, identifier
        return key, identifier


def read_desktop(port, identifier):
    name = _mapping_name(port, identifier)
    win = _Windows()
    handle = _require(win.open(READ_CONTROL | FILE_MAP_READ, 0, name))
    try:
        win.verify_owner(handle)
        view = _require(win.map(handle, FILE_MAP_READ, 0, 0, SECRET_SIZE))
        try:
            return ct.string_at(view, SECRET_SIZE)
        finally:
            win.unmap(view)
    finally:
        win.close(handle)
