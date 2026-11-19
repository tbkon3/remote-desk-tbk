"""Launch an isolated Windows package. Run: python tests/smoke_release_bundle.py ZIP [--version VERSION]."""
import argparse
import ctypes as ct
import hashlib
import hmac
import http.client
import importlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from ctypes import wintypes as wt


VERSION = "2.4.0"
ASSETS = ("bootstrap.js", "local-api.js", "manage.js", "session_ice.js", "style.css", "icon.png", "icon-active.png")
PAGES = {"/": "console.html", "/chat": "chat.html", "/manage": "manage.html", "/session": "session.html"}
FIXTURE_NAME = "RemoteDesk release smoke"
FIXTURE_ID = "918273645"
LIMIT = 2 * 1024 * 1024


def require(value, message):
    if not value:
        raise RuntimeError(message)


def winfn(dll, name, restype, *argtypes):
    item = getattr(dll, name)
    item.restype, item.argtypes = restype, argtypes
    return item


def checked(value):
    if not value:
        raise ct.WinError(ct.get_last_error())
    return value


def verify_launcher(path):
    # The verified upstream launcher is reused unchanged. Only the agent API identifies this release.
    kernel = ct.WinDLL("kernel32", winmode=0x800, use_last_error=True)
    load = winfn(kernel, "LoadLibraryExW", wt.HANDLE, wt.LPCWSTR, wt.HANDLE, wt.DWORD)
    find = winfn(kernel, "FindResourceW", wt.HANDLE, wt.HANDLE, wt.LPVOID, wt.LPVOID)
    free = winfn(kernel, "FreeLibrary", wt.BOOL, wt.HANDLE)
    handle = checked(load(str(path), None, 0x2 | 0x20))  # inspect resources without running the PE
    try:
        require(find(handle, 1, 14), "RemoteDesk.exe is missing its icon group")
    finally:
        free(handle)


class _BasicLimits(ct.Structure):
    _fields_ = [("times", ct.c_int64 * 2), ("flags", wt.DWORD), ("working_set", ct.c_size_t * 2),
                ("count", wt.DWORD), ("affinity", ct.c_size_t), ("priority", wt.DWORD), ("scheduling", wt.DWORD)]


class _ExtendedLimits(ct.Structure):
    _fields_ = [("basic", _BasicLimits), ("io", ct.c_uint64 * 6), ("memory", ct.c_size_t * 4)]


class _Accounting(ct.Structure):
    _fields_ = [("times", ct.c_int64 * 4), ("faults", wt.DWORD), ("total", wt.DWORD),
                ("active", wt.DWORD), ("terminated", wt.DWORD)]


@contextmanager
def private_launcher(exe, args, env):
    # The C launcher exits as soon as pythonw starts. Assign it to an unnamed job BEFORE
    # resuming its main thread so its child (and only its descendants) is always contained.
    import _winapi
    kernel = ct.WinDLL("kernel32", winmode=0x800, use_last_error=True)
    create = winfn(kernel, "CreateJobObjectW", wt.HANDLE, wt.LPVOID, wt.LPCWSTR)
    configure = winfn(kernel, "SetInformationJobObject", wt.BOOL, wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD)
    assign = winfn(kernel, "AssignProcessToJobObject", wt.BOOL, wt.HANDLE, wt.HANDLE)
    resume = winfn(kernel, "ResumeThread", wt.DWORD, wt.HANDLE)
    query = winfn(kernel, "QueryInformationJobObject", wt.BOOL, wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD, wt.LPVOID)
    terminate = winfn(kernel, "TerminateJobObject", wt.BOOL, wt.HANDLE, wt.UINT)
    close = winfn(kernel, "CloseHandle", wt.BOOL, wt.HANDLE)
    job = checked(create(None, None))

    def active():
        info = _Accounting()
        checked(query(job, 1, ct.byref(info), ct.sizeof(info), None))
        return info.active

    assigned = False
    try:
        limits = _ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        checked(configure(job, 9, ct.byref(limits), ct.sizeof(limits)))
        command = subprocess.list2cmdline([str(exe), *args])
        proc, thread, _, _ = _winapi.CreateProcess(str(exe), command, None, None, False,
                                                   0x4 | subprocess.CREATE_NO_WINDOW, env, str(exe.parent),
                                                   subprocess.STARTUPINFO())
        try:
            checked(assign(job, proc))
            assigned = True
            if resume(thread) == 0xFFFFFFFF:
                raise ct.WinError(ct.get_last_error())
        finally:
            if not assigned:
                _winapi.TerminateProcess(proc, 1)
            _winapi.CloseHandle(thread)
            _winapi.CloseHandle(proc)
        yield active
    finally:
        try:
            if assigned and active():
                checked(terminate(job, 1))
                end = time.monotonic() + 5
                while active() and time.monotonic() < end:
                    time.sleep(0.1)
        finally:
            close(job)


def local_request(port, method, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.request(method, path, headers=headers or {})
        response = conn.getresponse()
        body = response.read(LIMIT + 1)
        require(len(body) <= LIMIT, "Oversized loopback response")
        return response.status, body
    finally:
        conn.close()


def owner_headers(local_access, port, data, method, path):
    # Pin the server to the secret the launched fixture wrote *after* binding the port.
    # This also ensures an occupied port can never cause a POST to an unrelated agent.
    key = (data / "local.token").read_bytes().strip()
    nonce = secrets.token_hex(16)
    code, raw = local_request(port, "GET", "/api/local/challenge?role=owner&nonce=" + nonce)
    require(code == 200, "Owner challenge failed")
    reply = json.loads(raw)

    def signature(purpose, *parts):
        blob = json.dumps(["rd-local-v1", purpose, *parts], separators=(",", ":")).encode("ascii")
        return hmac.new(key, blob, hashlib.sha256).hexdigest()

    require(reply.get("mapping") == "" and hmac.compare_digest(reply.get("proof", ""), signature("server", port, "owner", nonce, "")),
            "Loopback service is not the fixture")
    headers = local_access.native_headers(port, path, method, data_dir=str(data))
    role, stamp, client_nonce, mac = headers[local_access.NATIVE_HEADER].split(".")
    require(role == "owner" and hmac.compare_digest(mac, signature("native", port, role, int(stamp), client_nonce, method, path)),
            "Native request is not signed by the fixture")
    return headers


def probe(root, data, port, version):
    # This branch is invoked by the Python executable INSIDE the candidate ZIP.
    root = root.resolve(strict=True)  # hosted runners can supply an 8.3 alias for %TEMP%
    runtime = (root / "runtime").resolve(strict=True)
    require(Path(sys.executable).resolve() == (runtime / "python.exe").resolve(), "Unexpected probe runtime")
    sys.path.insert(0, str(root / "app"))
    for name in ("aiohttp", "aiortc", "aioice", "av", "cryptography", "mss", "PIL.Image", "pystray", "pyaudiowpatch"):
        module = importlib.import_module(name)
        origin = Path(module.__file__).resolve(strict=True)
        require(origin.is_relative_to(runtime), f"Dependency outside artifact: {name}: {origin} (expected under {runtime})")
    from PIL import Image
    from rd import common, local_access
    require(common.VERSION == version, "Incorrect package version")
    # The probe never reads service credentials from ProgramData, even if the socket disappears.
    common.PROGRAM_DATA = str(data)
    for name in ("icon.png", "icon-active.png"):
        with Image.open(root / "app/web" / name) as picture:
            require(picture.format == "PNG" and min(picture.size) > 0, "Invalid GUI icon: " + name)
            picture.verify()
    headers = owner_headers(local_access, port, data, "GET", "/api/public")
    try:
        require(local_request(port, "GET", "/api/public")[0] == 403, "Unauthenticated state is accessible")
        status, raw = local_request(port, "GET", "/api/public", headers)
        require(status == 200, "Native authenticated GET failed")
        state = json.loads(raw)
        require(state["version"] == version and state["me"]["id"] == FIXTURE_ID and state["me"]["name"] == FIXTURE_NAME,
                "Agent did not load the candidate version and the private fixture")
        require(state["networks"] == [] and state["sessions"] == [] and not state["service"]["active"], "Unexpected active configuration")
        routes = {**PAGES, **{"/web/" + asset: asset for asset in ASSETS}}
        for route, filename in routes.items():
            status, body = local_request(port, "GET", route)
            require(status == 200 and body == (root / "app/web" / filename).read_bytes(), "Incorrect bundled asset: " + route)
    finally:
        quit_headers = owner_headers(local_access, port, data, "POST", "/api/quit")
        require(local_request(port, "POST", "/api/quit", quit_headers)[0] == 200, "Authenticated fixture shutdown failed")


def smoke(archive, version=VERSION):
    require(sys.platform == "win32", "Run this test on Windows")
    # Validate every archive member via checkout code before importing or running anything in the ZIP.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
    from rd.release_package import MAX_PACKAGE, extract_package
    require(0 < archive.stat().st_size <= MAX_PACKAGE, "Invalid archive size")
    with tempfile.TemporaryDirectory(prefix="RemoteDesk smoke ") as directory:
        work = Path(directory)
        root = Path(extract_package(archive, work / "extracted package"))
        require({p.name for p in root.iterdir()} == {"RemoteDesk.exe", "runtime", "app", "LEGGIMI.txt"}, "Unexpected top-level package contents")
        verify_launcher(root / "RemoteDesk.exe")
        profile = work / "isolated profile"
        data = profile / "agent data"
        data.mkdir(parents=True)
        config = {"id": FIXTURE_ID, "name": FIXTURE_NAME, "security_defaults": 1, "update_url": "", "auto_update": False,
                  "network": "", "networks": [], "known": {}, "signal": "", "stun": [], "turn_url": "", "accept_incoming": False}
        (data / "config.json").write_text(json.dumps(config), encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "RD_"))}
        env.update(USERPROFILE=str(profile), LOCALAPPDATA=str(profile), APPDATA=str(profile), HOME=str(profile),
                   LOGNAME="smoke", USER="smoke", USERNAME="smoke", LNAME="smoke", HTTP_PROXY="http://127.0.0.1:1",
                   HTTPS_PROXY="http://127.0.0.1:1", ALL_PROXY="http://127.0.0.1:1", NO_PROXY="127.0.0.1,localhost")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        with private_launcher(root / "RemoteDesk.exe", ["--agent-only", "--data", str(data), "--port", str(port)], env) as active:
            end = time.monotonic() + 30
            while not (data / "local.token").is_file():
                require(active(), "Launcher exited without starting the fixture")
                require(time.monotonic() < end, "Agent did not bind its loopback port within 30 seconds")
                time.sleep(0.1)
            subprocess.run([root / "runtime/python.exe", "-I", "-B", Path(__file__).resolve(), "--probe",
                            str(root), str(data), str(port), version], cwd=work, env=env, check=True, timeout=35)
            end = time.monotonic() + 10
            while active():
                require(time.monotonic() < end, "Fixture did not exit after authenticated shutdown")
                time.sleep(0.1)
    print(f"RemoteDesk {version} Windows bundle smoke passed")


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--probe":
        probe(Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("archive", type=Path)
        parser.add_argument("--version", choices=(VERSION, "2.4.1"), default=VERSION)
        args = parser.parse_args()
        smoke(args.archive.resolve(), args.version)
