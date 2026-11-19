"""File sharing anchored to one local directory selected by the host."""
import contextlib
import ctypes
import os
import secrets
import stat
import sys
from pathlib import Path

WINDOWS = os.name == "nt"
TEMP_PREFIX = ".rd-transfer-"
DENIED = "Percorso non disponibile nell'area di scambio"


def component(value, *, internal=False):
    if not isinstance(value, str) or not 0 < len(value) <= 255 or value in (".", ".."):
        raise ValueError(DENIED)
    if any(ord(c) < 32 or 0xd800 <= ord(c) <= 0xdfff or c in '\\/:*?"<>|' for c in value) or value.endswith((".", " ")):
        raise ValueError(DENIED)
    prefix = value.partition(".")[0].rstrip(" ").upper()
    if (prefix in ("CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL")
            or (len(prefix) == 4 and prefix[:3] in ("COM", "LPT") and prefix[3] in "0123456789¹²³")
            or not internal and value.casefold().startswith(TEMP_PREFIX)):
        raise ValueError(DENIED)
    return value


def inside(path, root):
    try:
        return os.path.commonpath([os.path.normcase(path), os.path.normcase(root)]) == os.path.normcase(root)
    except ValueError:
        return False


def _plain(st):
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
        raise PermissionError(DENIED)
    if stat.S_ISDIR(st.st_mode):
        return True
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise PermissionError(DENIED)
    return False


if WINDOWS:
    from ctypes import wintypes
    import msvcrt

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                   wintypes.LPVOID, wintypes.DWORD]
    _k32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                                wintypes.DWORD, wintypes.DWORD]
    _k32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]

    def windows_handle(path, *, directory):
        # Pin directories against renaming and reparse-point writes during the operation.
        access = 0x80000000 if directory is False else 0x80  # GENERIC_READ / FILE_READ_ATTRIBUTES
        flags = 0x00200000 | (0x02000000 if directory is not False else 0)  # OPEN_REPARSE_POINT / BACKUP_SEMANTICS
        h = _k32.CreateFileW(path, access, 1, None, 3, flags, None)
        if h == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            attrs = (wintypes.DWORD * 2)()  # FILE_ATTRIBUTE_TAG_INFO
            if not _k32.GetFileInformationByHandleEx(h, 9, attrs, ctypes.sizeof(attrs)):
                raise ctypes.WinError(ctypes.get_last_error())
            if attrs[0] & 0x400 or (directory is not None and bool(attrs[0] & 0x10) != directory):
                raise PermissionError(DENIED)
            buf = ctypes.create_unicode_buffer(32768)
            count = _k32.GetFinalPathNameByHandleW(h, buf, len(buf), 0)
            if not 0 < count < len(buf):
                raise PermissionError(DENIED)
            actual = buf.value.removeprefix("\\\\?\\")
            if os.path.normcase(actual) != os.path.normcase(path):
                # Also rejects DOS aliases for an otherwise protected directory.
                raise PermissionError(DENIED)
            return h
        except BaseException:
            _k32.CloseHandle(h)
            raise


class Scope:
    def __init__(self, root, protected=()):
        if not root or not os.path.isabs(root):
            raise ValueError("Configurare una cartella di scambio locale assoluta")
        self.root = Path(os.path.abspath(root))
        self.protected = [Path(os.path.abspath(p)) for p in protected if p]
        if (self.root == self.root.parent or str(self.root).startswith(("\\\\", "//"))
                or any(inside(self.root, p) for p in self.protected)):
            raise PermissionError(DENIED)

    def check(self, candidate, *, mutating=False):
        if not isinstance(candidate, (str, Path)):
            raise ValueError(DENIED)
        raw = str(candidate)
        if not 0 < len(raw) <= 4096 or raw.startswith(("\\\\", "//")):
            raise ValueError(DENIED)
        p = Path(raw)
        if not p.is_absolute() or ".." in p.parts or not inside(p, self.root):
            raise PermissionError(DENIED)
        relative = p.relative_to(self.root)
        for part in relative.parts:
            component(part)
        p = self.root.joinpath(*relative.parts)
        if (any(inside(p, banned) for banned in self.protected) or
                mutating and (p == self.root or any(inside(banned, p) for banned in self.protected))):
            raise PermissionError(DENIED)
        return p

    @contextlib.contextmanager
    def directory(self, path, *, before_create=None):
        path = self.check(path)
        if WINDOWS and _k32.GetDriveTypeW(self.root.anchor) not in (2, 3, 6):
            raise PermissionError(DENIED)
        with contextlib.ExitStack() as stack:
            current = Path(path.anchor)
            fd = None
            root_device = None
            for index, part in enumerate((None, *path.parts[1:])):
                if index:
                    component(part)
                    current = current / part
                try:
                    if WINDOWS:
                        handle = windows_handle(str(current), directory=True)
                    else:
                        root_or_part = part if index else str(current)
                        child = os.open(root_or_part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    if before_create is None or not inside(current, self.root) or current == self.root:
                        raise
                    before_create()
                    if WINDOWS:
                        try:
                            os.mkdir(current)
                        except FileExistsError:
                            pass
                        handle = windows_handle(str(current), directory=True)
                    else:
                        try:
                            os.mkdir(part, mode=0o700, dir_fd=fd)
                        except FileExistsError:
                            pass
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                if WINDOWS:
                    stack.callback(_k32.CloseHandle, handle)
                else:
                    fd = child
                    stack.callback(os.close, fd)
                    if current == self.root:
                        root_device = os.fstat(fd).st_dev
                    elif root_device is not None and os.fstat(fd).st_dev != root_device:
                        raise PermissionError(DENIED)
            yield Directory(self, path, fd)


class Directory:
    def __init__(self, scope, path, fd):
        self.scope, self.path, self.fd = scope, path, fd

    def arg(self, name):
        return self.path / name if WINDOWS else name

    def stat(self, name, *, internal=False):
        component(name, internal=internal)
        if WINDOWS:
            # Inspect the reparse tag before resolving aliases. Resolving a junction
            # first could contact an unshared UNC target even during a listing.
            path = str(self.path / name)
            handle = windows_handle(path, directory=None)
            try:
                st = os.stat(path, follow_symlinks=False)
            finally:
                _k32.CloseHandle(handle)
        else:
            st = os.stat(self.arg(name), dir_fd=self.fd, follow_symlinks=False)
            if st.st_dev != os.fstat(self.fd).st_dev:
                raise PermissionError(DENIED)
        _plain(st)
        return st

    def scan(self):
        return os.scandir(self.path if WINDOWS else self.fd)

    def reader(self, name):
        self.scope.check(self.path / component(name))
        if WINDOWS:
            handle = windows_handle(str(self.path / name), directory=False)
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                _k32.CloseHandle(handle)
                raise
        else:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            if _plain(os.fstat(fd)):
                raise IsADirectoryError(name)
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def temporary(self):
        name = TEMP_PREFIX + secrets.token_hex(18)
        fd = os.open(self.arg(name), os.O_RDWR | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_BINARY", 0), 0o600, dir_fd=self.fd)
        return name, os.fdopen(fd, "w+b", buffering=0)

    def unlink(self, name):
        os.unlink(self.arg(name), dir_fd=self.fd)

    def remove(self, name):
        if _plain(self.stat(name)):
            # Deliberately refuse removing a populated directory in one remote operation.
            os.rmdir(self.arg(name), dir_fd=self.fd)
        else:
            self.unlink(name)

    def move(self, src, dst, *, overwrite=False):
        """Atomic no-clobber commit. On POSIX use the platform's no-replace operation."""
        if overwrite:
            os.replace(self.arg(src), self.arg(dst), src_dir_fd=self.fd, dst_dir_fd=self.fd)
        elif WINDOWS:
            os.rename(self.arg(src), self.arg(dst))
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
                rc = libc.renameat2(self.fd, os.fsencode(src), self.fd, os.fsencode(dst), 1)
            elif sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
                rc = libc.renameatx_np(self.fd, os.fsencode(src), self.fd, os.fsencode(dst), 4)
            else:
                raise OSError("Rinomina atomica non disponibile su questa piattaforma")
            if rc:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))
