"""Create private portable storage and validate existing data before opening it."""
import ctypes as ct
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import stat

from .file_scope import component
from .local_access_win import (DWORD, PTR, _SecurityAttributes, _SidAndAttributes,
                               _Windows, _fn, _require)


SYSTEM = "S-1-5-18"
ADMINS = "S-1-5-32-544"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
CREATOR_OWNER = "S-1-3-0"
OWNER_RIGHTS = "S-1-3-4"
DENIED = "La cartella dati portabile richiede proprietario, permessi e collegamenti sicuri"
PROFILE_FILES = ("config.json", "config.json.bak", "machine.key", "local.token", "audit.jsonl",
                 "instance.json", "portable.lock", ".portable-update.lock",
                 ".update-pending.json", ".update-ready.json", "service.json")
LOG_FILES = tuple(log + suffix for log in ("portable.log", "user.log", "update.log")
                  for suffix in ("", ".1", ".2"))


def _check_acl(owner, entries, user, *, private, directory):
    trusted = {user, SYSTEM, ADMINS}
    if not private:
        trusted.add(TRUSTED_INSTALLER)
    if owner not in trusted:
        raise PermissionError(f"Proprietario non attendibile: {owner}")
    if entries is None:
        raise PermissionError("DACL assente")
    # With no inheritable trusted ACE, newly created children could receive a
    # process default DACL. Require a grant for both child files and directories.
    inherit = 0
    for kind, flags, mask, sid in entries:
        if kind == 1:  # ACCESS_DENIED_ACE cannot grant access
            continue
        if kind != 0:
            raise PermissionError(f"Tipo ACE non riconosciuto: tipo={kind} flags=0x{flags:02x} mask=0x{mask:08x}")
        # MS-DTYP OWNER RIGHTS denotes this object's current owner. Validate
        # the actual owner above, including independently for each existing file.
        if sid in trusted or sid == OWNER_RIGHTS:
            if mask & 0x1f01ff == 0x1f01ff and not flags & 4:  # no NO_PROPAGATE
                inherit |= flags & 3
            continue
        if flags & 8 and (not private or sid == CREATOR_OWNER):
            continue  # INHERIT_ONLY never applies to this ancestor
        # A parent may allow listing, traversal or adding a different child.
        # It may not allow editing metadata, removing children or changing ACLs.
        # In a private target, even reading its files/listing its names is denied.
        forbidden = 0xffffffff if private else 0x500d0150
        if mask & forbidden:
            raise PermissionError(f"Accesso non privato: SID={sid} flags=0x{flags:02x} "
                                  f"mask=0x{mask:08x} vietati=0x{mask & forbidden:08x}")
    if private and directory and inherit != 3:
        raise PermissionError(f"Permessi ereditabili insufficienti: OI/CI=0x{inherit:x}")


class _Storage(_Windows):
    def __init__(self):
        super().__init__()
        kernel = ct.WinDLL("kernel32", winmode=0x800, use_last_error=True)
        adv = ct.WinDLL("advapi32", winmode=0x800, use_last_error=True)
        self.open_path = _fn(kernel, "CreateFileW", PTR, ct.c_wchar_p, DWORD, DWORD, PTR, DWORD, DWORD, PTR)
        self.info = _fn(kernel, "GetFileInformationByHandle", ct.c_int, PTR, PTR)
        self.mkdir = _fn(kernel, "CreateDirectoryW", ct.c_int, ct.c_wchar_p, ct.POINTER(_SecurityAttributes))
        self.drive_type = _fn(kernel, "GetDriveTypeW", DWORD, ct.c_wchar_p)
        self.get_ace = _fn(adv, "GetAce", ct.c_int, PTR, DWORD, ct.POINTER(PTR))
        token = PTR()
        _require(self.process_token(PTR(-1), 8, ct.byref(token)))
        try:
            sid = self.token_data(token, 1, ct.sizeof(_SidAndAttributes))
            self.user = self.sid_text(_SidAndAttributes.from_buffer(sid).sid)
        finally:
            self.close(token)

    def create_private(self, path):
        descriptor = PTR()
        sddl = f"O:{self.user}D:P(A;OICI;FA;;;{self.user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        _require(self.descriptor(sddl, 1, ct.byref(descriptor), None))
        try:
            access = _SecurityAttributes(ct.sizeof(_SecurityAttributes), descriptor, 0)
            if not self.mkdir(str(path), ct.byref(access)) and ct.get_last_error() != 183:
                raise ct.WinError(ct.get_last_error())
        finally:
            self.free(descriptor)

    def check_security(self, handle, *, private, directory):
        owner, acl, descriptor = PTR(), PTR(), PTR()
        result = self.security(handle, 1, 5, ct.byref(owner), None, ct.byref(acl), None, ct.byref(descriptor))
        if result:
            raise ct.WinError(result)
        try:
            if not owner.value or not acl.value:
                raise PermissionError("Proprietario o DACL assenti")
            entries = []
            # The validated ACL returned by GetSecurityInfo begins with ACL_HEADER.
            ace_count = ct.c_uint16.from_address(acl.value + 4).value
            for index in range(ace_count):
                ace = PTR()
                _require(self.get_ace(acl, index, ct.byref(ace)))
                kind = ct.c_ubyte.from_address(ace.value).value
                flags = ct.c_ubyte.from_address(ace.value + 1).value
                mask = DWORD.from_address(ace.value + 4).value
                sid = self.sid_text(ace.value + 8) if kind == 0 else ""
                entries.append((kind, flags, mask, sid))
            _check_acl(self.sid_text(owner), entries, self.user, private=private, directory=directory)
        finally:
            self.free(descriptor)

    @contextmanager
    def inspect(self, path, *, private, directory):
        # READ_CONTROL + FILE_READ_ATTRIBUTES. Inspect the link itself, and hold
        # each ancestor against rename until validation of its children completes.
        # Existing file writers (including the running agent) remain compatible.
        handle = self.open_path(str(path), 0x20080, 3 if directory else 7, None, 3, 0x02200000, None)
        if handle == PTR(-1).value:
            raise ct.WinError(ct.get_last_error())
        try:
            info = (DWORD * 13)()  # BY_HANDLE_FILE_INFORMATION
            _require(self.info(handle, info))
            if info[0] & 0x400 or bool(info[0] & 0x10) != directory or (not directory and info[10] != 1):
                raise PermissionError(DENIED)
            try:
                self.check_security(handle, private=private, directory=directory)
            except PermissionError as exc:
                role = "oggetto privato" if private else "antenato"
                raise PermissionError(f"{DENIED} ({role} {path!s}; {exc})") from exc
            yield
        finally:
            self.close(handle)


def _children(path, files, profile, inspect):
    def existing(child, directory):
        with ExitStack() as stack:
            try:
                stack.enter_context(inspect(child, private=True, directory=directory))
            except FileNotFoundError:
                return
            if profile and directory and child.name == "logs":
                for name in LOG_FILES:
                    existing(child / name, False)

    for name in set(files) | (set(PROFILE_FILES) if profile else set()):
        existing(path / component(name), False)
    if profile:
        for name in ("logs", "browser", "update"):
            existing(path / name, True)


def private_dir(path, *, profile=False, files=()):
    """Create/verify this directory and existing reserved files without walking unrelated trees."""
    target = Path(path)
    if not target.is_absolute() or target == target.parent or ".." in target.parts:
        raise PermissionError(DENIED)
    if os.name != "nt":
        _posix_dir(target, files, profile)
        return
    win = _Storage()
    if len(target.drive) != 2 or win.drive_type(target.anchor) not in (2, 3):
        raise PermissionError(DENIED)
    with ExitStack() as stack:
        current = Path(target.anchor)
        stack.enter_context(win.inspect(current, private=False, directory=True))
        for part in target.parts[1:]:
            current /= component(part)
            try:
                stack.enter_context(win.inspect(current, private=current == target, directory=True))
            except FileNotFoundError:
                win.create_private(current)
                stack.enter_context(win.inspect(current, private=True, directory=True))
        _children(target, files, profile, win.inspect)


def private_child(pinned_parent, name):
    """Private update directory under a parent and ancestors already pinned by the caller."""
    parent = Path(pinned_parent)
    if not parent.is_absolute() or ".." in parent.parts:
        raise PermissionError(DENIED)
    child = parent / component(name)
    if os.name == "nt":
        win = _Storage()
        if len(parent.drive) != 2 or win.drive_type(parent.anchor) not in (2, 3):
            raise PermissionError(DENIED)
        inspect, create = win.inspect, win.create_private
    else:
        inspect = _posix_inspect
        def create(path):
            path.mkdir(mode=0o700, exist_ok=True)
    with inspect(parent, private=False, directory=True):
        try:
            with inspect(child, private=True, directory=True):
                return child
        except FileNotFoundError:
            create(child)
        with inspect(child, private=True, directory=True):
            return child


@contextmanager
def _posix_inspect(path, *, private, directory):
    info = path.lstat()
    if directory != stat.S_ISDIR(info.st_mode) or (not directory and
            (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
        raise PermissionError(DENIED)
    if private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise PermissionError(DENIED)
    if not private and (info.st_uid not in (0, os.getuid()) or
                        (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
        raise PermissionError(DENIED)
    yield


def _posix_dir(target, files, profile):
    for path in (*reversed(target.parents), target):
        try:
            with _posix_inspect(path, private=path == target, directory=True):
                pass
        except FileNotFoundError:
            path.mkdir(mode=0o700, exist_ok=True)
            with _posix_inspect(path, private=True, directory=True):
                pass
    _children(target, files, profile, _posix_inspect)
