"""Offline test for a portable update and console on a disposable github-hosted Windows VM."""
import argparse
import asyncio
import ctypes as ct
from ctypes import wintypes as wt
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit


SCRIPT = Path(__file__).resolve()
sys.path.insert(0, str(SCRIPT.parent))  # also when called by the isolated embedded Python
import smoke_legacy_service as support
from smoke_portable_upgrade import isolated_environment
from smoke_release_bundle import checked, local_request, owner_headers, private_launcher, require, winfn

OLD_HASH = "3e58471929b5e4144c47be617689c2cd5498b6008115e00f6bfb9d8fb803f976"
OLD_SIZE = 53535321
FEED = "https://raw.githubusercontent.com/tbkon3/remote-desk-tbk/main/dist/latest.json"
MANAGED = ("RemoteDesk.exe", "LEGGIMI.txt", "app", "runtime")
CUSTOM_FOLDER = "Assistenza Città Blu"


def host_guard():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "Windows"
            and os.environ.get("GITHUB_REPOSITORY", "").lower() == "tbkon3/remote-desk-tbk"
            and os.environ.get("GITHUB_RUN_ID", "").isdigit(), "Run only on this project's disposable hosted Windows VM")


@contextmanager
def standard_account():
    class UserInfo(ct.Structure):
        _fields_ = [("name", wt.LPWSTR), ("password", wt.LPWSTR), ("age", wt.DWORD), ("priv", wt.DWORD),
                    ("home", wt.LPWSTR), ("comment", wt.LPWSTR), ("flags", wt.DWORD), ("script", wt.LPWSTR)]

    dll = ct.WinDLL("netapi32", winmode=0x800)
    add = winfn(dll, "NetUserAdd", wt.DWORD, wt.LPCWSTR, wt.DWORD, ct.POINTER(UserInfo), wt.LPVOID)
    remove = winfn(dll, "NetUserDel", wt.DWORD, wt.LPCWSTR, wt.LPCWSTR)
    name, password = "rdci" + secrets.token_hex(6), "aA!7" + secrets.token_hex(24)
    info = UserInfo(name, password, 0, 1, None, "Disposable portable CI", 0x201, None)
    result = add(None, 1, ct.byref(info), None)
    require(result == 0, f"Unable to create the private standard account ({result})")
    sid = None
    try:
        identities = support.powershell(r"""
$account=[Security.Principal.NTAccount]::new($env:COMPUTERNAME,$env:RD_SMOKE_ACCOUNT)
$account.Translate([Security.Principal.SecurityIdentifier]).Value
[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
""", dict(os.environ, RD_SMOKE_ACCOUNT=name)).decode("utf8").splitlines()
        sid, group = (value.strip() for value in identities)
        require(sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1].isdigit(), "Unexpected local SID")
        member = wt.LPWSTR(os.environ["COMPUTERNAME"] + "\\" + name)
        join = winfn(dll, "NetLocalGroupAddMembers", wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, wt.LPVOID, wt.DWORD)
        require(join(None, group, 3, ct.byref(member), 1) in (0, 1378), "Cannot grant standard Users membership")
        yield name, password, sid
    finally:
        try:
            if sid:
                remove_private_profile(name, sid)
        finally:
            require(remove(None, name) == 0, "Could not remove disposable local account")


def remove_private_profile(account, sid):
    import winreg
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" + "\\" + sid
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            profile = Path(os.path.expandvars(winreg.QueryValueEx(key, "ProfileImagePath")[0])).resolve()
    except FileNotFoundError:
        return
    require(profile.name.casefold() == account.casefold() and account.startswith("rdci"), "Unexpected disposable profile path")
    api = ct.WinDLL("userenv", winmode=0x800, use_last_error=True)
    delete = winfn(api, "DeleteProfileW", wt.BOOL, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR)
    for attempt in range(20):
        if delete(sid, str(profile), None):
            return
        if attempt < 19:
            time.sleep(.5)
    raise ct.WinError(ct.get_last_error())


@contextmanager
def registered_service():
    # The application discovers its installed service via this exact registry marker.
    # Set it only on a newly created key. Never register or execute a SYSTEM task.
    import winreg
    from rd.local_access_win import _SecurityAttributes, _Windows
    api = ct.WinDLL("advapi32", winmode=0x800)
    create = winfn(api, "RegCreateKeyExW", wt.LONG, wt.HANDLE, wt.LPCWSTR, wt.DWORD, wt.LPWSTR,
                   wt.DWORD, wt.DWORD, wt.LPVOID, ct.POINTER(wt.HANDLE), ct.POINTER(wt.DWORD))
    keypath, marker = r"SOFTWARE\RemoteDesk", secrets.token_hex(24)
    handle, disposition, descriptor = wt.HANDLE(), wt.DWORD(), wt.LPVOID()
    win = _Windows()
    checked(win.descriptor("O:BAG:BAD:P(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KR;;;BU)", 1, ct.byref(descriptor), None))
    try:
        attributes = _SecurityAttributes(ct.sizeof(_SecurityAttributes), descriptor, False)
        code = create(wt.HANDLE(-2147483646), keypath, 0, None, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY,
                      ct.byref(attributes), ct.byref(handle), ct.byref(disposition))
    finally:
        win.free(descriptor)
    require(code == 0, f"Cannot create isolated registry marker ({code})")
    try:
        require(disposition.value == 1, "Refusing to touch an existing service marker")
        winreg.SetValueEx(handle.value, "RD-CI-Owner", 0, winreg.REG_SZ, marker)
        try:
            winreg.SetValueEx(handle.value, "Service", 0, winreg.REG_DWORD, 1)
            yield
            require(winreg.QueryValueEx(handle.value, "Service") == (1, winreg.REG_DWORD), "Service marker changed")
        finally:
            require(winreg.QueryValueEx(handle.value, "RD-CI-Owner") == (marker, winreg.REG_SZ)
                    and winreg.QueryInfoKey(handle.value)[0] == 0, "Registry fixture ownership changed")
            winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, keypath, winreg.KEY_WOW64_64KEY)
    finally:
        winreg.CloseKey(handle.value)


def as_standard_user(account, password, work, version):
    from rd.winapi import STARTUPINFOW, PROCESS_INFORMATION
    kernel = ct.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    adv = ct.WinDLL("advapi32", use_last_error=True, winmode=0x800)
    start = winfn(adv, "CreateProcessWithLogonW", wt.BOOL, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                  wt.LPCWSTR, wt.LPWSTR, wt.DWORD, wt.LPVOID, wt.LPCWSTR,
                  ct.POINTER(STARTUPINFOW), ct.POINTER(PROCESS_INFORMATION))
    wait = winfn(kernel, "WaitForSingleObject", wt.DWORD, wt.HANDLE, wt.DWORD)
    kill = winfn(kernel, "TerminateProcess", wt.BOOL, wt.HANDLE, wt.UINT)
    status = winfn(kernel, "GetExitCodeProcess", wt.BOOL, wt.HANDLE, ct.POINTER(wt.DWORD))
    close = winfn(kernel, "CloseHandle", wt.BOOL, wt.HANDLE)
    exe = work / "reference/RemoteDesk/runtime/python.exe"
    command = ct.create_unicode_buffer(subprocess.list2cmdline([str(exe), "-I", "-B", str(work / "driver" / SCRIPT.name),
                                                               "--worker", str(work), version]))
    # lpEnvironment=NULL inherits the *new* account's profile, not CI flags: pass only the
    # non-secret run identity required by host_guard, on disk alongside the isolated driver.
    startup, process = STARTUPINFOW(), PROCESS_INFORMATION()
    startup.cb = ct.sizeof(startup)
    checked(start(account, ".", password, 1, str(exe), command, subprocess.CREATE_NO_WINDOW, None, str(work),
                  ct.byref(startup), ct.byref(process)))
    try:
        if wait(process.hProcess, 540000) != 0:
            checked(kill(process.hProcess, 1))
            raise TimeoutError("Portable test timed out")
        code = wt.DWORD()
        checked(status(process.hProcess, ct.byref(code)))
        detail = work / "worker-result.txt"
        require(detail.is_file(), f"Worker exited {code.value} before writing its result")
        message = detail.read_text("utf8")
        require(code.value == 0 and message.startswith("OK "), message)
        print(message)
    finally:
        close(process.hThread)
        close(process.hProcess)


def configure(data, name):
    data.mkdir(parents=True, exist_ok=True)
    device = str(100000000 + secrets.randbelow(900000000))
    config = {"id": device, "name": name, "security_defaults": 1, "networks": [], "known": {}, "network": "",
              "signal": "", "stun": [], "turn_url": "", "accept_incoming": False, "update_url": "", "auto_update": False}
    (data / "config.json").write_text(json.dumps(config), "utf8")
    return device


def member_hashes(root):
    result = {}
    for member in MANAGED:
        path = root / member
        files = path.rglob("*") if path.is_dir() else (path,)
        for file in files:
            if file.is_file() and "__pycache__" not in file.relative_to(root).parts:
                result[file.relative_to(root).as_posix()] = support.digest(file)
    return result


def file_id(path):
    info = path.stat()
    require(info.st_ino != 0, "NTFS file identity unavailable")
    return info.st_dev, info.st_ino


def check_previous(target, previous, old_ids, source, installed):
    saved = set(MANAGED)
    if source["RemoteDesk.exe"] == installed["RemoteDesk.exe"]:
        # The updater keeps an identical native launcher in place across the swap.
        require(file_id(target / "RemoteDesk.exe") == old_ids["RemoteDesk.exe"], "Unchanged launcher was replaced")
        saved.remove("RemoteDesk.exe")
    require({p.name for p in previous.iterdir()} == saved, "Unexpected contents in previous package")
    for name in saved:
        require(file_id(previous / name) == old_ids[name] and file_id(target / name) != old_ids[name],
                "Previous or installed file identity is incorrect for " + name)
    expected = {key: value for key, value in source.items() if key.split("/", 1)[0] in saved}
    require(member_hashes(previous) == expected, "Contents of the previous components changed")


def until(active, read, label, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require(active(), "Private process exited while waiting for " + label)
        try:
            result = read()
        except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError):
            result = None
        if result:
            return result
        time.sleep(.2)
    raise TimeoutError(label)


def public(data, port, version, name, device):
    from rd import local_access
    headers = owner_headers(local_access, port, data, "GET", "/api/public")
    code, raw = local_request(port, "GET", "/api/public", headers)
    require(code == 200 and local_request(port, "GET", "/api/public")[0] == 403, "Owner boundary failed")
    state = json.loads(raw)
    require((state["version"], state["me"]["id"], state["me"]["name"]) == (version, device, name)
            and state["networks"] == [] and state["sessions"] == [], "Wrong copy, version or identity in console API")
    return state


def quit_fixture(data, port):
    from rd import local_access
    headers = owner_headers(local_access, port, data, "POST", "/api/quit")
    require(local_request(port, "POST", "/api/quit", headers)[0] == 200, "Fixture quit failed")


def instance(data, target):
    state = json.loads((data / "instance.json").read_text("utf8"))
    require(Path(state["root"]).resolve() == target.resolve() and state["pid"] > 0 and 0 < state["port"] < 65536
            and state["port"] != 47800, "Instance registered the wrong bundle or service port")
    return state["port"]


def safe_page(url):
    parsed = urlsplit(url)
    if parsed.scheme == "about":
        return "about:blank"
    if parsed.scheme not in ("http", "https") or parsed.hostname != "127.0.0.1":
        return parsed.scheme + ":<other>"
    path = parsed.path if parsed.path in ("/", "/local/start", "/chat", "/manage", "/session") else "/<other>"
    return f"{parsed.scheme}://127.0.0.1:{parsed.port}{path}"


def fixture_log_flags(data):
    path = data / "logs/portable.log"
    detail = ""
    if path.is_file():
        with path.open("rb") as inp:
            inp.seek(max(0, path.stat().st_size - 65536))
            detail = inp.read(65536).decode("utf8", errors="ignore").lower()
    return {tag: tag in detail for tag in ("agente pronto", "impossibile verificare", "error", "traceback")}


def prepare_browser_adapter(work):
    # The app discovers and launches this private EXE through its normal Windows
    # browser lookup. Record the exact request atomically inside the private profile.
    binary = work / "browser adapter/Microsoft/Edge/Application/msedge.exe"
    binary.parent.mkdir(parents=True)
    from rd.updater import system_tool
    modules = Path(system_tool(r"WindowsPowerShell\v1.0\powershell.exe")).parent / "Modules"
    support.powershell(r"""
$code=@'
using System;
using System.IO;
using System.Text;
public static class BrowserRequest {
    [STAThread] public static int Main(string[] args) {
        string path = Environment.GetEnvironmentVariable("RD_SMOKE_BROWSER_CAPTURE");
        if (String.IsNullOrEmpty(path)) return 2;
        try {
            File.WriteAllLines(path + ".new", args, new UTF8Encoding(false));
            File.Move(path + ".new", path);
            return 0;
        } catch (IOException) { return 3; }
    }
}
'@
Add-Type -TypeDefinition $code -Language CSharp -OutputAssembly $env:RD_SMOKE_ADAPTER -OutputType WindowsApplication
""", dict(os.environ, RD_SMOKE_ADAPTER=str(binary), PSMODULEPATH=str(modules)))
    require(binary.is_file(), "Could not build private Windows browser adapter")


def requested_console(capture, profile, port):
    args = capture.read_text("utf8").splitlines()
    capture.unlink()
    urls = [v[len("--app="):] for v in args if v.startswith("--app=")]
    profiles = [Path(v[len("--user-data-dir="):]).resolve() for v in args if v.startswith("--user-data-dir=")]
    require(len(urls) == 1 and profiles == [profile / "browser"], "Portable app used an unexpected browser request/profile")
    parsed = urlsplit(urls[0])
    require(safe_page(urls[0]) == f"http://127.0.0.1:{port}/local/start" and not parsed.query and parsed.fragment
            and parsed.username is None and parsed.password is None, "Wrong destination in the app's browser request")
    return urls[0]


async def browser_state(endpoint, url, port, target_root, name, version):
    import aiohttp
    async with aiohttp.ClientSession(trust_env=False) as client:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            async with client.get(f"http://127.0.0.1:{endpoint}/json/list") as response:
                targets = await response.json()
            tab = next((item for item in targets if item["type"] == "page" and item["url"] == "about:blank"), None)
            if tab:
                break
            await asyncio.sleep(.2)
        else:
            raise RuntimeError("Headless browser has no blank target: " + repr([safe_page(t["url"]) for t in targets]))
        async with client.ws_connect(tab["webSocketDebuggerUrl"]) as ws:
            seq = 0
            async def command(method, params):
                nonlocal seq
                seq += 1
                await ws.send_json({"id": seq, "method": method, "params": params})
                while True:
                    result = await ws.receive_json(timeout=8)
                    if result.get("id") == seq:
                        require("error" not in result, "Headless browser rejected " + method)
                        return result["result"]

            opened = await command("Page.navigate", {"url": url})
            require(not opened.get("errorText"), "Browser rejected the app's origin/path: " + safe_page(url))
            # This offline device has no network login. The welcome view renders the
            # owner-only installed version and actual update destination for this copy.
            expression = """([location.port,document.querySelector('#meName')?.textContent,
                document.querySelector('#welcomeUpdateStatus')?.textContent,document.querySelector('#welcomeTarget')?.textContent,
                !!document.querySelector('#welcomeUpdates')?.getClientRects().length])"""
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                result = await command("Runtime.evaluate", {"expression": expression, "returnByValue": True})
                values = result.get("result", {}).get("value", [])
                if len(values) == 5 and values[0:2] == [str(port), name + " - ID di questo PC"] and values[4]:
                    label, sep, path = (values[3] or "").partition(" · ")
                    if (values[2] or "").startswith("Versione installata " + version) and label == "Copia portabile" and sep:
                        require(Path(path).resolve() == target_root, "Console displays the wrong update destination")
                        return
                await asyncio.sleep(.2)
            async with client.get(f"http://127.0.0.1:{endpoint}/json/list") as response:
                targets = await response.json()
            raise RuntimeError("Incorrect rendered portable console. Origin/path: " + repr([safe_page(t["url"]) for t in targets]))


@contextmanager
def console_browser(data, env):
    from rd import agent
    browser = agent.W.find_browser()
    require(browser and Path(browser).is_file(), "Edge or Chrome is required on the hosted runner")
    # Render the URI issued by the unmodified application, using its own browser profile.
    profile = data / "browser"
    args = ["--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + str(profile), "--disable-sync",
            "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
            "--proxy-server=http://127.0.0.1:1", "--proxy-bypass-list=127.0.0.1;localhost",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "about:blank"]
    with private_launcher(Path(browser), args, env) as active:
        endpoint = until(active, lambda: (profile / "DevToolsActivePort").read_text().splitlines(), "Chromium socket")[0]
        yield int(endpoint)


def capture_old(target, staged, data, port, version, original_version):
    # Run the original command builder with its own runtime. Capture only the
    # process launch so the harness can contain its complete tree in a private Job.
    guard_worker(SCRIPT.parents[1])
    require(target == SCRIPT.parents[1] / "Read only parent" / CUSTOM_FOLDER
            and staged.is_relative_to(data / "update"), "Legacy driver escaped its private directories")
    sys.path.insert(0, str(target / "app"))
    from rd import update
    require(update.VERSION == original_version and Path(update.ROOT_DIR).resolve() == target.resolve(), "Wrong historical package")
    args = ["--agent-only", "--data", str(data), "--port", str(port)]
    with patch.object(sys, "argv", ["remotedesk.py", *args]), patch.object(update.subprocess, "Popen") as launch:
        update.Updater(SimpleNamespace(port=port, data_dir=str(data), service_mode=False))._launch_updater(str(staged), version)
    launch.assert_called_once()
    print(json.dumps({"argv": launch.call_args.args[0], "pid": os.getpid()}))


def upgrade(work, target, data, staged, env, version, original_version):
    name = "Custom " + secrets.token_hex(6)
    device = configure(data, name)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    args = ["--agent-only", "--data", str(data), "--port", str(port)]
    if original_version == "2.3.2":
        from smoke_portable_upgrade import assert_legacy_start
        # 2.3.2 has no server proof. Use only public fixture identity and stop its private Job.
        assert_legacy_start(target, data, port, env, name, device)
    else:
        with private_launcher(target / "RemoteDesk.exe", args, env) as active:
            until(active, lambda: public(data, port, original_version, name, device), "old custom instance")
            quit_fixture(data, port)
    key = support.digest(data / "machine.key")
    source = member_hashes(target)
    old_ids = {name: file_id(target / name) for name in MANAGED}
    personal = {target / "customer notes.txt": secrets.token_bytes(40),
                target / "data/client estate.bin": secrets.token_bytes(64)}
    for path, content in personal.items():
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(content)
    before = {path: path.stat().st_ino for path in personal}
    command = subprocess.run([target / "runtime/python.exe", "-I", "-B", SCRIPT, "--capture-old", target, staged, data,
                              str(port), version, original_version], cwd=work, env=env, check=True, capture_output=True, timeout=45)
    captured = json.loads(command.stdout)
    argv = list(captured["argv"])
    index = 1 if original_version == "2.3.2" else 2
    require(Path(argv[0]).resolve() == staged / "runtime/pythonw.exe" and (index == 1 or argv[1] == "-I")
            and Path(argv[index]).resolve() == staged / "app/rd/updater.py", "Old updater escaped the staging bundle")
    opts = dict(zip(argv[index + 1::2], argv[index + 2::2], strict=True))
    require(opts == {"--mode": "user", "--target": str(target), "--source": str(staged), "--port": str(port),
                     "--version": version, "--log": str(data / "logs/update.log"), "--pid": str(captured["pid"]),
                     "--args": json.dumps(args)}, "Old updater did not target this private fixture")
    expected = member_hashes(staged)
    log = data / "logs/update.log"
    def committed():
        text = log.read_text("utf8")
        require("ripristin" not in text.lower() and "errore inatteso" not in text, "Updater rejected fixture: " + text[-800:])
        return "nuova versione attiva: aggiornamento completato" in text

    try:
        with private_launcher(Path(argv[0]), argv[1:], env) as active:
            until(active, committed, "update commit and receipt", timeout=185)
            require(instance(data, target) == port, "Restart did not use the requested private port")
            public(data, port, version, name, device)
            require(support.digest(data / "machine.key") == key, "Device private key changed")
            require(member_hashes(target) == expected, "Active package differs from candidate")
            backups = list((target / ".remotedesk-update").glob("*/previous"))
            require(len(backups) == 1, "Cannot identify the previous package")
            check_previous(target, backups[0], old_ids, source, expected)
            require(all(p.read_bytes() == content and p.stat().st_ino == before[p] for p, content in personal.items()),
                    "Portable update rewrote or lost a personal file")
            require(not any((data / n).exists() for n in (".update-pending.json", ".update-ready.json")),
                    "Unfinished health handshake")
            quit_fixture(data, port)
    except Exception as exc:
        tail = log.read_text("utf8")[-850:] if log.exists() else "(no helper log)"
        raise RuntimeError("Private update did not complete: " + tail) from exc


def guard_worker(work):
    # The parent creates a fresh user profile. The environment block for a logon with
    # profile does not inherit CI environment variables from runneradmin.
    facts = json.loads((work / "host.json").read_text("utf8"))
    os.environ.update(facts["runner"])
    host_guard()
    require(SCRIPT.parent == work / "driver" and work.name.startswith("RD portable ") and
            work.parent == Path(os.environ["PUBLIC"]).resolve(), "Private driver escaped its disposable directory")
    require(not ct.windll.shell32.IsUserAnAdmin(), "Portable processes must run as a standard Windows user")
    return facts


def worker(work, version):
    facts = guard_worker(work)
    reference = work / "reference/RemoteDesk"
    sys.path.insert(0, str(reference / "app"))
    from rd import common, portable, update
    require(common.VERSION == version and common.service_installed(), "Service registration was not visible to the user")
    profile = portable.default_profile()
    require(profile.parent.parent.parent == Path(common.known_folder(0x1c)) and not profile.parent.parent.exists()
            and facts["account"].casefold() == Path(common.known_folder(0x1c)).parents[1].name.casefold(),
            "Not the isolated standard user's fresh LocalAppData")
    manifest = json.loads((work / "feed.json").read_text("utf-8-sig"))
    require(update.verify_manifest(manifest) and update.RELEASE_PUB == support.RELEASE_PUB and update.DEFAULT_URL == FEED,
            "Bundled updater did not verify the publisher feed with its production key")
    if manifest["version"] == version:
        require(manifest["sha256"].lower() == facts["sha256"] and manifest["size"] == facts["size"]
                and manifest["file"] == f"RemoteDesk-{version}.zip", "Publisher manifest does not authenticate this candidate")
    elif facts["signed_required"]:
        raise RuntimeError("Supplied candidate manifest describes a different version")
    env = isolated_environment(Path(common.known_folder(0x1c)).parents[1])
    target = work / "Read only parent" / CUSTOM_FOLDER
    try:
        with (target.parent / "write forbidden.tmp").open("xb"):
            pass
    except PermissionError:
        pass
    else:
        raise RuntimeError("The standard account could write the installation's parent")

    other = work / "other/RemoteDesk"
    # Keep this historical instance alive throughout the custom install and default launch.
    # It is a fully working, authenticated competing agent, bound only to loopback.
    other_data = Path(common.known_folder(0x1c)) / "other fixture data"
    other_name = "Other " + secrets.token_hex(6)
    other_id = configure(other_data, other_name)
    data = Path(common.known_folder(0x1c)) / "custom fixture data"
    staging = data / "update"
    if facts["from_version"] != "2.3.2":
        staging /= "release-" + secrets.token_hex(16)
    staged = staging / "nuovo/RemoteDesk"
    shutil.copytree(reference, staged, ignore=shutil.ignore_patterns("__pycache__"))
    original = member_hashes(other)
    with socket.socket() as test_socket:
        test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        test_socket.bind(("127.0.0.1", 47800))
    with private_launcher(other / "RemoteDesk.exe", ["--agent-only", "--port", "47800", "--data", str(other_data)], env) as active:
        until(active, lambda: public(other_data, 47800, "2.4.0", other_name, other_id), "competing old instance")
        old_keys = tuple(support.digest(other_data / file) for file in ("machine.key", "local.token"))
        upgrade(work, target, data, staged, env, version, facts["from_version"])

        # Suppress only the tray. Observe the real browser request, then render the
        # exact URI in the isolated browser. Headless Chromium ignores forwarded --app.
        from rd.portable_storage import private_dir
        for directory in (profile.parent.parent, profile.parent, profile):
            private_dir(directory)
        name = "Portable " + secrets.token_hex(6)
        device = configure(profile, name)
        prepare_browser_adapter(work)
        capture = profile / "ci-browser-request"
        request_env = dict(env, RD_SMOKE_BROWSER_CAPTURE=str(capture))
        request_env["PROGRAMFILES(X86)"] = str(work / "browser adapter")
        with console_browser(profile, env) as endpoint:
            with private_launcher(target / "RemoteDesk.exe", ["--no-tray"], request_env) as portable_active:
                port = until(portable_active, lambda: instance(profile, target), "default portable instance")
                public(profile, port, version, name, device)
                try:
                    url = until(portable_active, lambda: requested_console(capture, profile, port), "app browser request", timeout=30)
                    asyncio.run(asyncio.wait_for(browser_state(endpoint, url, port, target, name, version), timeout=70))
                except Exception as exc:
                    raise RuntimeError(f"Portable console failed. Private log indicators: {fixture_log_flags(profile)}") from exc
                finally:
                    capture.unlink(missing_ok=True)
                    capture.with_name(capture.name + ".new").unlink(missing_ok=True)
                public(other_data, 47800, "2.4.0", other_name, other_id)
                quit_fixture(profile, port)
        require(member_hashes(other) == original and old_keys == tuple(support.digest(other_data / f)
                for f in ("machine.key", "local.token")), "Competing installation or identity changed")
        require(common.service_installed(), "Portable action changed service registration")
        quit_fixture(other_data, 47800)
    return "OK standard-user console, custom in-place update and unaffected listener. " + (
        "Candidate digest verified against the publisher manifest." if manifest["version"] == version else
        "Offline source-verified candidate. Signed feed identifies " + manifest["version"] + ".")


def main(legacy, candidate, version, manifest, original_version, reference):
    host_guard()
    support.hosted_only()
    sys.path.insert(0, str(support.REPO / "app"))
    from rd.release_package import MAX_PACKAGE, extract_package
    require(reference.stat().st_size == OLD_SIZE and support.digest(reference) == OLD_HASH, "Need exact historical 2.4.0 distribution")
    size, digest = (support.LEGACY_SIZE, support.LEGACY_HASH) if original_version == "2.3.2" else (OLD_SIZE, OLD_HASH)
    require(legacy.stat().st_size == size and support.digest(legacy) == digest, "Wrong original portable distribution")
    require(0 < candidate.stat().st_size <= MAX_PACKAGE and legacy != candidate and version == "2.4.1", "Unexpected candidate")
    support.task_absent()
    public_root = Path(os.environ["PUBLIC"]).resolve(strict=True)
    with standard_account() as (account, password, sid), tempfile.TemporaryDirectory(prefix="RD portable ", dir=public_root) as temp:
        work = Path(temp).resolve()
        acl = "O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + ")"
        # ACL changes are restricted to objects this test just allocated under its random root.
        support.powershell(r"""
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm($env:RD_SMOKE_ACL)
[IO.Directory]::SetAccessControl($env:RD_SMOKE_WORK,$acl)
""", dict(os.environ, RD_SMOKE_WORK=str(work), RD_SMOKE_ACL=acl))
        marker = secrets.token_hex(16)
        locked = work / "Read only parent"
        support.create_owned(locked, acl.replace("FA;;;" + sid, "0x1200a9;;;" + sid), marker)
        target = locked / CUSTOM_FOLDER
        support.create_owned(target, acl, marker)
        other = Path(extract_package(reference, work / "other"))
        old = Path(extract_package(legacy, work / "original")) if original_version == "2.3.2" else other
        new = Path(extract_package(candidate, work / "reference"))
        require(support.hashes(new / "app") == support.tracked_app_hashes()
                and support.hashes(new / "runtime") == support.hashes(other / "runtime")
                and support.digest(new / "RemoteDesk.exe") == support.digest(other / "RemoteDesk.exe"),
                "Candidate differs from the release commit or trusted runtime")
        shutil.copytree(old, target, dirs_exist_ok=True)
        driver = work / "driver"
        driver.mkdir()
        for file in (SCRIPT.name, "smoke_legacy_service.py", "smoke_release_bundle.py", "smoke_portable_upgrade.py"):
            shutil.copy2(SCRIPT.parent / file, driver / file)
        shutil.copyfile(manifest or support.REPO / "dist/latest.json", work / "feed.json")
        facts = {"account": account, "from_version": original_version, "sha256": support.digest(candidate), "size": candidate.stat().st_size,
                 "signed_required": bool(manifest),
                 "runner": {k: os.environ[k] for k in ("GITHUB_ACTIONS", "RUNNER_OS", "RUNNER_ENVIRONMENT",
                                                       "GITHUB_REPOSITORY", "GITHUB_RUN_ID")}}
        (work / "host.json").write_text(json.dumps(facts), "utf8")
        with registered_service():
            as_standard_user(account, password, work, version)
        support.task_absent()


if __name__ == "__main__":
    if len(sys.argv) == 8 and sys.argv[1] == "--capture-old":
        capture_old(*(Path(value).resolve() for value in sys.argv[2:5]), int(sys.argv[5]), sys.argv[6], sys.argv[7])
    elif len(sys.argv) == 4 and sys.argv[1] == "--worker":
        folder = Path(sys.argv[2]).resolve()
        try:
            message = worker(folder, sys.argv[3])
        except Exception:
            (folder / "worker-result.txt").write_text(traceback.format_exc(), "utf8")
            raise
        (folder / "worker-result.txt").write_text(message, "utf8")
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--legacy-zip", type=Path, required=True)
        parser.add_argument("--candidate-zip", type=Path, required=True)
        parser.add_argument("--version", required=True)
        parser.add_argument("--from-version", choices=("2.3.2", "2.4.0"), default="2.4.0")
        parser.add_argument("--reference-zip", type=Path, help="Verified 2.4.0 ZIP, required for migration from 2.3.2")
        parser.add_argument("--candidate-manifest", type=Path, help="Require the exact candidate's publisher signature")
        options = parser.parse_args()
        if options.from_version == "2.3.2" and not options.reference_zip:
            parser.error("--from-version 2.3.2 requires --reference-zip")
        main(options.legacy_zip.resolve(), options.candidate_zip.resolve(), options.version, options.candidate_manifest,
             options.from_version, (options.reference_zip or options.legacy_zip).resolve())
