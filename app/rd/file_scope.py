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
    _k32.GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    _k32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]

    def windows_handle(path, *, directory, host_alias=False):
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
            actual = Path(buf.value.removeprefix("\\\\?\\"))
            requested = Path(path)
            if (not actual.is_absolute() or actual.drive.upper() != requested.drive.upper()
                    or actual.parent != requested.parent):
                raise PermissionError(DENIED)
            if actual != requested:
                # The final object and all its parents are already pinned and
                # verified non-reparse. Only accept its genuine DOS alternate name.
                if not host_alias:
                    raise PermissionError(DENIED)
                count = _k32.GetShortPathNameW(str(actual), buf, len(buf))
                if not 0 < count < len(buf) or Path(buf.value).name.lower() != requested.name.lower():
                    raise PermissionError(DENIED)
            return h, actual
        except BaseException:
            _k32.CloseHandle(h)
            raise

    def trusted_directory(path, *, protected=False):
        """Expand host-selected 8.3 components only after pinning their verified parents."""
        if not path.is_absolute() or len(path.drive) != 2 or _k32.GetDriveTypeW(path.anchor) not in (2, 3, 6):
            raise PermissionError(DENIED)
        with contextlib.ExitStack() as stack:
            current = Path(path.anchor)
            for index, part in enumerate((None, *path.parts[1:])):
                target = current if part is None else current / component(part)
                try:
                    handle, actual = windows_handle(str(target), directory=True, host_alias=True)
                except FileNotFoundError:
                    if not protected:
                        raise
                    # No corresponding short name exists for a missing directory.
                    # Reserve its lexical tail, or the parent for a possible future alias.
                    tail = path.parts[index:]
                    return current if any("~" in name for name in tail) else current.joinpath(*tail)
                except OSError:
                    if not protected:
                        raise
                    # An unreadable protected directory cannot be safely normalized.
                    # Reserve the nearest verified ancestor rather than dropping the exclusion.
                    return current
                stack.callback(_k32.CloseHandle, handle)
                current = actual
            return current


class Scope:
    def __init__(self, root, protected=()):
        if not root or not os.path.isabs(root):
            raise ValueError("Configurare una cartella di scambio locale assoluta")
        self.root = Path(os.path.abspath(root))
        self.protected = [Path(os.path.abspath(p)) for p in protected if p]
        self.disk_root = None
        if (self.root == self.root.parent or str(self.root).startswith(("\\\\", "//"))
                or any(inside(self.root, p) for p in self.protected)):
            raise PermissionError(DENIED)

    def bind_windows(self):
        # Called in the file worker under the authenticated interactive user.
        # Keep the configured spelling on the wire and a verified long path for OS calls.
        if self.disk_root is not None:
            return
        physical = trusted_directory(self.root)
        exclusions = list(self.protected)
        for path in self.protected:
            if path.drive.lower() != physical.drive.lower():
                continue
            protected = trusted_directory(path, protected=True)
            if inside(physical, protected):
                raise PermissionError(DENIED)
            if inside(protected, physical):
                exclusions.append(self.root / protected.relative_to(physical))
        self.protected = exclusions
        self.disk_root = physical

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
        if WINDOWS:
            self.bind_windows()
        path = self.check(path)
        disk_root = self.disk_root if WINDOWS else self.root
        disk_path = disk_root / path.relative_to(self.root)
        if WINDOWS and _k32.GetDriveTypeW(disk_root.anchor) not in (2, 3, 6):
            raise PermissionError(DENIED)
        with contextlib.ExitStack() as stack:
            current = Path(disk_path.anchor)
            fd = None
            root_device = None
            for index, part in enumerate((None, *disk_path.parts[1:])):
                if index:
                    component(part)
                    current = current / part
                try:
                    if WINDOWS:
                        handle, _ = windows_handle(str(current), directory=True)
                    else:
                        root_or_part = part if index else str(current)
                        child = os.open(root_or_part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    if before_create is None or not inside(current, disk_root) or current == disk_root:
                        raise
                    before_create()
                    if WINDOWS:
                        try:
                            os.mkdir(current)
                        except FileExistsError:
                            pass
                        handle, _ = windows_handle(str(current), directory=True)
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
            yield Directory(self, path, disk_path, fd)


class Directory:
    def __init__(self, scope, path, disk_path, fd):
        self.scope, self.path, self.disk_path, self.fd = scope, path, disk_path, fd

    def arg(self, name):
        return self.disk_path / name if WINDOWS else name

    def stat(self, name, *, internal=False):
        component(name, internal=internal)
        if WINDOWS:
            # Inspect the reparse tag before resolving aliases. Resolving a junction
            # first could contact an unshared UNC target even during a listing.
            path = str(self.disk_path / name)
            handle, _ = windows_handle(path, directory=None)
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
        return os.scandir(self.disk_path if WINDOWS else self.fd)

    def reader(self, name):
        self.scope.check(self.path / component(name))
        if WINDOWS:
            handle, _ = windows_handle(str(self.disk_path / name), directory=False)
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
