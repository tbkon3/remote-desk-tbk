"""Funzioni Windows via ctypes: input, desktop sicuro, Ctrl+Alt+Canc, appunti,
sessioni utente, servizio, avvio automatico, elevazione."""
import ctypes
import ctypes.wintypes as wt
from contextlib import contextmanager
import threading
import time
import logging
import os
import subprocess
import sys
import winreg

log = logging.getLogger("rd.win")

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
try:
    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
except OSError:
    wtsapi32 = userenv = None

ULONG_PTR = ctypes.c_size_t
CREATE_NO_WINDOW = 0x08000000


def set_dpi_aware():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass


# =========================================================================== SendInput
class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wt.LONG), ("dy", wt.LONG), ("mouseData", wt.DWORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ULONG_PTR)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wt.DWORD), ("wParamL", wt.WORD), ("wParamH", wt.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wt.DWORD), ("u", _INPUTUNION)]


user32.SendInput.argtypes = [wt.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
user32.SendInput.restype = wt.UINT
user32.VkKeyScanW.argtypes = [wt.WCHAR]
user32.VkKeyScanW.restype = ctypes.c_short
user32.MapVirtualKeyW.argtypes = [wt.UINT, wt.UINT]
user32.MapVirtualKeyW.restype = wt.UINT

MOUSE_MOVE, MOUSE_ABS, MOUSE_VDESK = 0x1, 0x8000, 0x4000
MOUSE_WHEEL, MOUSE_HWHEEL = 0x0800, 0x1000
MOUSE_BTN = {0: (0x2, 0x4), 1: (0x20, 0x40), 2: (0x8, 0x10), 3: (0x80, 0x100), 4: (0x80, 0x100)}
KEY_EXT, KEY_UP, KEY_UNICODE = 0x1, 0x2, 0x4

EXTENDED_VK = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x5B, 0x5C, 0x5D,
               0xA3, 0xA5, 0x6F, 0x90, 0x2C}

VK_NAMES = {
    "Enter": 0x0D, "Backspace": 0x08, "Tab": 0x09, "Escape": 0x1B, "Delete": 0x2E, "Insert": 0x2D,
    "Home": 0x24, "End": 0x23, "PageUp": 0x21, "PageDown": 0x22, "ArrowLeft": 0x25, "ArrowUp": 0x26,
    "ArrowRight": 0x27, "ArrowDown": 0x28, " ": 0x20, "CapsLock": 0x14, "ContextMenu": 0x5D,
    "PrintScreen": 0x2C, "Pause": 0x13, "ScrollLock": 0x91, "NumLock": 0x90,
    "AudioVolumeMute": 0xAD, "AudioVolumeDown": 0xAE, "AudioVolumeUp": 0xAF,
    # nomi usati dai pulsanti "combo"
    "ctrl": 0xA2, "alt": 0xA4, "shift": 0xA0, "win": 0x5B, "tab": 0x09, "esc": 0x1B, "del": 0x2E,
    "enter": 0x0D, "print_screen": 0x2C, "space": 0x20,
}
for _i in range(1, 25):
    VK_NAMES[f"F{_i}"] = 0x6F + _i
    VK_NAMES[f"f{_i}"] = 0x6F + _i
MOD_VK = {"ctrl": 0xA2, "alt": 0xA4, "shift": 0xA0, "meta": 0x5B}

SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN = 76, 77, 78, 79


_input_state = threading.local()


@contextmanager
def input_guard(allowed):
    _input_state.allowed = allowed
    try:
        yield
    finally:
        del _input_state.allowed


def _send(inputs):
    arr = (INPUT * len(inputs))(*inputs)
    if not getattr(_input_state, "allowed", default_desktop_active)():
        raise PermissionError("Desktop interattivo non disponibile")
    if user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT)) != len(inputs):
        raise OSError("Windows ha rifiutato l'input")


def mouse_event(flags, dx=0, dy=0, data=0):
    i = INPUT(type=0)
    i.mi = MOUSEINPUT(dx, dy, data & 0xFFFFFFFF, flags, 0, 0)
    return i


def key_input(vk=0, scan=0, flags=0):
    i = INPUT(type=1)
    if vk and not flags & KEY_UNICODE:
        scan = user32.MapVirtualKeyW(vk, 0)
        if vk in EXTENDED_VK:
            flags |= KEY_EXT
    i.ki = KEYBDINPUT(vk, scan, flags, 0, 0)
    return i


def mouse_move_abs(x, y):
    vx, vy = user32.GetSystemMetrics(SM_XVIRTUALSCREEN), user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
    vw, vh = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN), user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
    nx = int((x - vx) * 65535 / max(vw - 1, 1))
    ny = int((y - vy) * 65535 / max(vh - 1, 1))
    _send([mouse_event(MOUSE_MOVE | MOUSE_ABS | MOUSE_VDESK, nx, ny)])


def mouse_button(button, down):
    d, u = MOUSE_BTN.get(button, MOUSE_BTN[0])
    _send([mouse_event(d if down else u, data={3: 1, 4: 2}.get(button, 0))])   # XBUTTON1/2: indietro/avanti


def mouse_wheel(dx, dy):
    ev = []
    if dy:
        ev.append(mouse_event(MOUSE_WHEEL, data=int(-dy)))
    if dx:
        ev.append(mouse_event(MOUSE_HWHEEL, data=int(dx)))
    if ev:
        _send(ev)


def key_vk(vk, down):
    _send([key_input(vk, flags=0 if down else KEY_UP)])


def type_text(text):
    text = text.replace("\r\n", "\n")
    for start in range(0, len(text), 32):
        events = []
        for ch in text[start:start + 32]:
            if ch in ("\n", "\t"):
                vk = 0x0D if ch == "\n" else 0x09
                events.extend((key_input(vk), key_input(vk, flags=KEY_UP)))
                continue
            units = ch.encode("utf-16-le")
            for k in range(0, len(units), 2):
                value = int.from_bytes(units[k:k + 2], "little")
                events.extend((key_input(0, value, KEY_UNICODE), key_input(0, value, KEY_UNICODE | KEY_UP)))
        _send(events)


def key_combo(vks):
    if vks:
        _send([key_input(vk) for vk in vks] + [key_input(vk, flags=KEY_UP) for vk in reversed(vks)])


def vk_for_char(ch):
    r = user32.VkKeyScanW(ch)
    if r == -1:
        return None
    return r & 0xFF


# =========================================================================== desktop sicuro
user32.GetThreadDesktop.argtypes = [wt.DWORD]
user32.GetThreadDesktop.restype = wt.HANDLE
user32.GetProcessWindowStation.argtypes = []
user32.GetProcessWindowStation.restype = wt.HANDLE
user32.GetForegroundWindow.argtypes = []
user32.GetForegroundWindow.restype = wt.HWND
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
advapi32.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p]
advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(wt.BYTE)
advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]
advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
user32.GetUserObjectInformationW.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD,
                                             ctypes.POINTER(wt.DWORD)]
MAXIMUM_ALLOWED = 0x02000000


def _desk_name(h):
    buf = ctypes.create_unicode_buffer(256)
    n = wt.DWORD()
    if user32.GetUserObjectInformationW(h, 2, buf, ctypes.sizeof(buf), ctypes.byref(n)):
        return buf.value
    return ""


def _foreground_is_user_level():
    """Also with UAC configured on Default, decline elevated or unidentified foreground windows."""
    hwnd = user32.GetForegroundWindow()
    pid = wt.DWORD()
    if not hwnd or not user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid)):
        return False
    process = kernel32.OpenProcess(0x1000, False, pid.value)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not process:
        return False
    token = wt.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, 8, ctypes.byref(token)):
            return False
        # TOKEN_MANDATORY_LABEL starts with a SID pointer, followed by its attributes and SID.
        buf, used = ctypes.create_string_buffer(256), wt.DWORD()
        if not advapi32.GetTokenInformation(token, 25, buf, len(buf), ctypes.byref(used)):
            return False
        sid = ctypes.c_void_p.from_buffer(buf).value
        if not sid or not advapi32.IsValidSid(sid):
            return False
        count = advapi32.GetSidSubAuthorityCount(sid)
        if not count or not count[0]:
            return False
        integrity = advapi32.GetSidSubAuthority(sid, count[0] - 1)
        return bool(integrity and integrity[0] <= 0x2000 and hwnd == user32.GetForegroundWindow())
    finally:
        if token.value:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def default_desktop_active(service_mode=False):
    """Check the worker's existing desktop. UOI_IO is true only on the input desktop."""
    session = process_session()
    if not session or (service_mode and session != active_console_session()):
        return False
    station = user32.GetProcessWindowStation()
    desk = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    if not station or not desk or _desk_name(station).casefold() != "winsta0" or _desk_name(desk).casefold() != "default":
        return False
    active, size = wt.BOOL(), wt.DWORD()
    if not user32.GetUserObjectInformationW(desk, 6, ctypes.byref(active), ctypes.sizeof(active), ctypes.byref(size)):
        return False
    return bool(active.value and (not service_mode or _foreground_is_user_level()))

# =========================================================================== Ctrl+Alt+Canc
def send_sas():
    if not default_desktop_active(service_mode=True):
        return False
    try:
        sas = ctypes.WinDLL("sas")
        sas.SendSAS.argtypes = [wt.BOOL]
        sas.SendSAS(False)
        return True
    except Exception as e:
        log.warning("SendSAS fallito: %s", e)
        return False


def enable_software_sas():
    """Criterio 'SoftwareSASGeneration' = 3 (servizi e app di accessibilita')."""
    k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0,
                           winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    winreg.SetValueEx(k, "SoftwareSASGeneration", 0, winreg.REG_DWORD, 3)
    winreg.CloseKey(k)


def lock_workstation():
    return bool(user32.LockWorkStation())


def block_input(on):
    if on and not default_desktop_active():
        return False
    return bool(user32.BlockInput(bool(on)))


# =========================================================================== appunti
CF_UNICODETEXT = 13
user32.OpenClipboard.argtypes = [wt.HWND]
user32.GetClipboardData.argtypes = [wt.UINT]
user32.GetClipboardData.restype = wt.HANDLE
user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
user32.SetClipboardData.restype = wt.HANDLE
user32.GetClipboardSequenceNumber.restype = wt.DWORD
kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = wt.HGLOBAL


def _open_clip():
    import time
    for _ in range(10):
        if user32.OpenClipboard(None):
            return True
        time.sleep(0.02)
    return False


def clip_seq():
    return user32.GetClipboardSequenceNumber()


def clip_get():
    if not _open_clip():
        return None
    try:
        h = user32.GetClipboardData(CF_UNICODETEXT)
        if not h:
            return ""
        p = kernel32.GlobalLock(h)
        if not p:
            return ""
        try:
            return ctypes.wstring_at(p)
        finally:
            kernel32.GlobalUnlock(h)
    finally:
        user32.CloseClipboard()


kernel32.GlobalFree.argtypes = [wt.HGLOBAL]
kernel32.GlobalFree.restype = wt.HGLOBAL


def clip_set(text):
    data = text.encode("utf-16-le") + b"\0\0"
    if not _open_clip():
        return False
    try:
        h = kernel32.GlobalAlloc(0x0002, len(data))
        if not h:
            return False
        p = kernel32.GlobalLock(h)
        if not p:
            kernel32.GlobalFree(h)
            return False
        ctypes.memmove(p, data, len(data))
        kernel32.GlobalUnlock(h)
        user32.EmptyClipboard()
        if not user32.SetClipboardData(CF_UNICODETEXT, h):
            kernel32.GlobalFree(h)   # in caso di successo la memoria passa al sistema
            return False
        return True
    finally:
        user32.CloseClipboard()


# =========================================================================== messaggi
def message_box(text, title="RemoteDesk", ask=False, timeout_ms=30000):
    """Mostra un messaggio sul desktop dell'utente. Con ask=True ritorna True se risponde Si'."""
    if ask and not default_desktop_active():
        return False
    deadline = time.monotonic() + timeout_ms / 1000
    flags = 0x40000 | 0x10000 | (0x4 | 0x20 | 0x100 if ask else 0x40)  # MB_DEFBUTTON2 = No
    try:
        f = user32.MessageBoxTimeoutW
        f.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.UINT, wt.WORD, wt.DWORD]
        r = f(None, text, title, flags, 0, timeout_ms)
    except AttributeError:
        if ask:
            return False
        r = user32.MessageBoxW(None, text, title, flags)
    return r == 6 and (not ask or (time.monotonic() < deadline and default_desktop_active()))


# =========================================================================== sessioni / servizio
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
                ("lpTitle", wt.LPWSTR), ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD),
                ("dwYSize", wt.DWORD), ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD),
                ("cbReserved2", wt.WORD), ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD),
                ("dwThreadId", wt.DWORD)]


kernel32.WTSGetActiveConsoleSessionId.restype = wt.DWORD
kernel32.GetCurrentProcess.restype = wt.HANDLE
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
advapi32.DuplicateTokenEx.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                      ctypes.POINTER(wt.HANDLE)]
advapi32.SetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
advapi32.ImpersonateLoggedOnUser.argtypes = [wt.HANDLE]
advapi32.CreateProcessAsUserW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                          wt.BOOL, wt.DWORD, ctypes.c_void_p, wt.LPCWSTR,
                                          ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]


def active_console_session():
    s = kernel32.WTSGetActiveConsoleSessionId()
    return None if s == 0xFFFFFFFF else s


def process_session(pid=None):
    s = wt.DWORD()
    kernel32.ProcessIdToSessionId(pid or os.getpid(), ctypes.byref(s))
    return s.value


def spawn_in_session(session_id, cmdline, cwd):
    """Dal servizio (SYSTEM, sessione 0) lancia un processo SYSTEM nella sessione utente."""
    tok, dup = wt.HANDLE(), wt.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0xF01FF, ctypes.byref(tok)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi32.DuplicateTokenEx(tok, MAXIMUM_ALLOWED, None, 2, 1, ctypes.byref(dup)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = wt.DWORD(session_id)
        if not advapi32.SetTokenInformation(dup, 12, ctypes.byref(sid), 4):  # TokenSessionId
            raise ctypes.WinError(ctypes.get_last_error())
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.lpDesktop = "winsta0\\default"
        pi = PROCESS_INFORMATION()
        buf = ctypes.create_unicode_buffer(cmdline)
        if not advapi32.CreateProcessAsUserW(dup, None, buf, None, None, False,
                                             0x400 | CREATE_NO_WINDOW, None, cwd,
                                             ctypes.byref(si), ctypes.byref(pi)):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(pi.hThread)
        return pi.hProcess, pi.dwProcessId
    finally:
        kernel32.CloseHandle(tok)
        if dup:
            kernel32.CloseHandle(dup)


def process_alive(handle):
    return kernel32.WaitForSingleObject(handle, 0) == 0x102  # WAIT_TIMEOUT


def pid_alive(pid):
    h = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not h:
        return False
    try:
        return process_alive(h)
    finally:
        kernel32.CloseHandle(h)


def terminate(handle):
    kernel32.TerminateProcess(handle, 0)
    kernel32.CloseHandle(handle)


def session_user(session_id):
    if not wtsapi32:
        return ""
    p = ctypes.c_void_p()
    n = wt.DWORD()
    if wtsapi32.WTSQuerySessionInformationW(None, session_id, 5, ctypes.byref(p), ctypes.byref(n)):
        try:
            return ctypes.wstring_at(p.value) if p.value else ""
        finally:
            wtsapi32.WTSFreeMemory(p)
    return ""


def session_profile_dir(session_id):
    if not wtsapi32:
        return None
    tok = wt.HANDLE()
    if not wtsapi32.WTSQueryUserToken(session_id, ctypes.byref(tok)):
        return None
    try:
        buf = ctypes.create_unicode_buffer(520)
        n = wt.DWORD(520)
        if userenv.GetUserProfileDirectoryW(tok, buf, ctypes.byref(n)):
            return buf.value
    finally:
        kernel32.CloseHandle(tok)
    return None


# =========================================================================== mutex istanza singola
kernel32.CreateMutexW.restype = wt.HANDLE


def single_instance(name):
    h = kernel32.CreateMutexW(None, False, name)
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        return None
    return h


# =========================================================================== avvio automatico
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def autostart_get(name="RemoteDesk", hive=winreg.HKEY_CURRENT_USER):
    try:
        k = winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_READ)
        v, _ = winreg.QueryValueEx(k, name)
        winreg.CloseKey(k)
        return v
    except OSError:
        return None


def autostart_set(cmd, name="RemoteDesk", hive=winreg.HKEY_CURRENT_USER):
    k = winreg.CreateKeyEx(hive, RUN_KEY, 0, winreg.KEY_SET_VALUE)
    if cmd:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, cmd)
    else:
        try:
            winreg.DeleteValue(k, name)
        except OSError:
            pass
    winreg.CloseKey(k)


def is_admin():
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_elevated(exe, params, cwd):
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    r = shell32.ShellExecuteW(None, "runas", exe, params, cwd, 0)
    return (r or 0) > 32


def run_hidden(args, check=False):
    return subprocess.run(args, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, check=check)


def find_browser():
    cands = []
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
        if base:
            cands += [os.path.join(base, r"Microsoft\Edge\Application\msedge.exe"),
                      os.path.join(base, r"Google\Chrome\Application\chrome.exe")]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


def work_area():
    r = wt.RECT()
    if user32.SystemParametersInfoW(0x30, 0, ctypes.byref(r), 0):
        return r.left, r.top, r.right, r.bottom
    return 0, 0, user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)


# =========================================================================== impersonazione
class as_session_user:
    """Esegue il blocco con i diritti dell'utente collegato alla sessione (il servizio gira come
    SYSTEM: senza questo il file manager avrebbe accesso a tutto il sistema)."""

    def __init__(self, session_id):
        self.session_id = session_id
        self.tok = wt.HANDLE()

    def __enter__(self):
        if not wtsapi32 or not wtsapi32.WTSQueryUserToken(self.session_id, ctypes.byref(self.tok)):
            raise PermissionError("Nessun utente collegato a Windows: accesso ai file non disponibile")
        if not advapi32.ImpersonateLoggedOnUser(self.tok):
            kernel32.CloseHandle(self.tok)
            raise PermissionError("Impersonazione dell'utente non riuscita")
        return self

    def __exit__(self, *exc):
        advapi32.RevertToSelf()
        kernel32.CloseHandle(self.tok)
        return False


# =========================================================================== forma del cursore
class _POINT(ctypes.Structure):
    _fields_ = [("x", wt.LONG), ("y", wt.LONG)]


class CURSORINFO(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("flags", wt.DWORD), ("hCursor", wt.HANDLE), ("ptScreenPos", _POINT)]


class ICONINFO(ctypes.Structure):
    _fields_ = [("fIcon", wt.BOOL), ("xHotspot", wt.DWORD), ("yHotspot", wt.DWORD),
                ("hbmMask", wt.HANDLE), ("hbmColor", wt.HANDLE)]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG), ("biPlanes", wt.WORD),
                ("biBitCount", wt.WORD), ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG), ("biClrUsed", wt.DWORD),
                ("biClrImportant", wt.DWORD)]


gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
user32.GetCursorInfo.argtypes = [ctypes.POINTER(CURSORINFO)]
user32.LoadCursorW.argtypes = [wt.HINSTANCE, ctypes.c_void_p]
user32.LoadCursorW.restype = wt.HANDLE
user32.GetIconInfo.argtypes = [wt.HANDLE, ctypes.POINTER(ICONINFO)]
user32.DrawIconEx.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, wt.HANDLE, ctypes.c_int, ctypes.c_int, wt.UINT,
                              wt.HANDLE, wt.UINT]
gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
gdi32.CreateCompatibleDC.restype = wt.HDC
gdi32.CreateDIBSection.argtypes = [wt.HDC, ctypes.c_void_p, wt.UINT, ctypes.POINTER(ctypes.c_void_p), wt.HANDLE,
                                   wt.DWORD]
gdi32.CreateDIBSection.restype = wt.HANDLE
gdi32.SelectObject.argtypes = [wt.HDC, wt.HANDLE]
gdi32.SelectObject.restype = wt.HANDLE
gdi32.DeleteObject.argtypes = [wt.HANDLE]
gdi32.DeleteDC.argtypes = [wt.HDC]
gdi32.PatBlt.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.DWORD]
gdi32.GetObjectW.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p]

# cursori standard di Windows -> cursori CSS del browser
_IDC_CSS = {32512: "default", 32513: "text", 32514: "wait", 32515: "crosshair", 32516: "default",
            32642: "nwse-resize", 32643: "nesw-resize", 32644: "ew-resize", 32645: "ns-resize",
            32646: "move", 32648: "not-allowed", 32649: "pointer", 32650: "progress", 32651: "help",
            32671: "pointer", 32672: "pointer"}
_std_cursors = {}


def _standard_cursors():
    if not _std_cursors:
        for idc, css in _IDC_CSS.items():
            h = user32.LoadCursorW(None, ctypes.c_void_p(idc))
            if h:
                _std_cursors[h] = css
    return _std_cursors


def cursor_state():
    """('none'|nome CSS|'custom', handle) del cursore visibile ora, oppure None se non leggibile."""
    if not default_desktop_active():
        return ("none", None)
    ci = CURSORINFO()
    ci.cbSize = ctypes.sizeof(ci)
    if not user32.GetCursorInfo(ctypes.byref(ci)):
        return None
    if not ci.flags & 1:          # CURSOR_SHOWING
        return ("none", None)
    h = ci.hCursor
    css = _standard_cursors().get(h)
    return (css, h) if css else ("custom", h)


def _draw_cursor(h, w, hh, background):
    """Disegna il cursore su un fondo uniforme e ritorna i pixel BGRA."""
    dc = gdi32.CreateCompatibleDC(None)
    bmi = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), w, -hh, 1, 32, 0, 0, 0, 0, 0, 0)
    bits = ctypes.c_void_p()
    bmp = gdi32.CreateDIBSection(dc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
    old = gdi32.SelectObject(dc, bmp)
    try:
        gdi32.PatBlt(dc, 0, 0, w, hh, 0x00FF0062 if background else 0x00000042)  # WHITENESS / BLACKNESS
        user32.DrawIconEx(dc, 0, 0, h, w, hh, 0, None, 0x0003)                   # DI_NORMAL
        return ctypes.string_at(bits, w * hh * 4)
    finally:
        gdi32.SelectObject(dc, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(dc)


def cursor_image(h):
    """Cursore personalizzato -> (pixel RGBA, larghezza, altezza, hotspot x, hotspot y) oppure None.
    La trasparenza si ricava disegnandolo su nero e su bianco (vale anche per i cursori monocromatici)."""
    if not default_desktop_active():
        return None
    ii = ICONINFO()
    if not user32.GetIconInfo(h, ctypes.byref(ii)):
        return None
    try:
        class BITMAP(ctypes.Structure):
            _fields_ = [("bmType", wt.LONG), ("bmWidth", wt.LONG), ("bmHeight", wt.LONG), ("bmWidthBytes", wt.LONG),
                        ("bmPlanes", wt.WORD), ("bmBitsPixel", wt.WORD), ("bmBits", ctypes.c_void_p)]
        bm = BITMAP()
        gdi32.GetObjectW(ii.hbmColor or ii.hbmMask, ctypes.sizeof(bm), ctypes.byref(bm))
        w = bm.bmWidth
        hh = bm.bmHeight if ii.hbmColor else bm.bmHeight // 2   # maschera monocromatica = doppia altezza
        if not (0 < w <= 128 and 0 < hh <= 128):
            return None
        hx, hy = ii.xHotspot, ii.yHotspot
    finally:
        for b in (ii.hbmMask, ii.hbmColor):
            if b:
                gdi32.DeleteObject(b)
    black = _draw_cursor(h, w, hh, False)
    white = _draw_cursor(h, w, hh, True)
    out = bytearray(w * hh * 4)
    for i in range(0, len(out), 4):
        b0, g0, r0 = black[i], black[i + 1], black[i + 2]
        b1, g1, r1 = white[i], white[i + 1], white[i + 2]
        a = 255 - max(0, min(255, ((r1 - r0) + (g1 - g0) + (b1 - b0)) // 3))
        if a:
            out[i] = min(255, r0 * 255 // a)
            out[i + 1] = min(255, g0 * 255 // a)
            out[i + 2] = min(255, b0 * 255 // a)
        out[i + 3] = a
    return (bytes(out), w, hh, hx, hy) if default_desktop_active() else None
