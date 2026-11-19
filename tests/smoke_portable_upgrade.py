"""Offline 2.3.2 -> 2.4.0 portable upgrade on an ephemeral GitHub-hosted Windows runner.

python tests/smoke_portable_upgrade.py --legacy-zip old.zip --candidate-zip new.zip
Pass --candidate-manifest latest.json to also require the actual signed release manifest.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch


TEST = Path(__file__).resolve()
sys.path.insert(0, str(TEST.parent))  # includes invocations under the bundled interpreter's -I
from smoke_release_bundle import VERSION, local_request, owner_headers, private_launcher, require

LEGACY_VERSION = "2.3.2"
LEGACY_SHA256 = "76e054528ff95a3d7f323fb72963b9645108c919a79c63c90b0d9d67b3f3e1b5"


def hosted_only():
    require(sys.platform == "win32" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Windows" and os.environ.get("GITHUB_ACTIONS") == "true",
            "Use a fresh GitHub-hosted Windows runner for this disposable upgrade test")


def fixture_paths(target, data):
    work = data.resolve().parent.parent
    require(work.parent == Path(tempfile.gettempdir()).resolve() and work.name.startswith("RD upgrade ")
            and data.resolve() == work / "test profile/data" and target.resolve() == work / "installed/RemoteDesk",
            "Refusing to operate outside the private hosted-runner fixture")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def launch_args(data, port):
    return ["--agent-only", "--data", str(data), "--port", str(port)]


def isolated_environment(profile):
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("RD_", "PYTHON"))}
    env.update(USERPROFILE=str(profile), HOME=str(profile), APPDATA=str(profile), LOCALAPPDATA=str(profile),
               LOGNAME="smoke", USERNAME="smoke", USER="smoke", LNAME="smoke",
               HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1",
               ALL_PROXY="http://127.0.0.1:1", NO_PROXY="127.0.0.1,localhost")
    return env


def capture_legacy_command(target, staged, data, port, manifest, candidate):
    """Execute the unmodified 2.3.2 command builder with its original runtime.

    Capture its Popen arguments so the host can create the new helper suspended in a
    private job. The historical launcher requests CREATE_BREAKAWAY_FROM_JOB.
    """
    hosted_only()
    fixture_paths(target, data)
    require(staged.resolve() == data.resolve() / "update/nuovo/RemoteDesk", "Invalid private staging location")
    sys.path.insert(0, str(target / "app"))
    from rd import update
    require(update.VERSION == LEGACY_VERSION and Path(update.ROOT_DIR).resolve() == target.resolve(), "Unexpected legacy runtime")
    if manifest is not None:
        body = json.loads(manifest.read_text(encoding="utf-8"))
        require(update.verify_manifest(body), "Publisher signature failed legacy verification")
        require(body["version"] == VERSION and body["sha256"].lower() == digest(candidate)
                and body["size"] == candidate.stat().st_size and body["file"] == f"RemoteDesk-{VERSION}.zip",
                "Signed candidate manifest does not match the supplied artifact")
    agent = SimpleNamespace(port=port, data_dir=str(data), service_mode=False)
    original = ["remotedesk.py", *launch_args(data, port)]
    with patch.object(sys, "argv", original), patch.object(update.subprocess, "Popen") as capture:
        update.Updater(agent)._launch_updater(str(staged), VERSION)
    require(capture.call_count == 1, "Legacy command builder did not issue one launch request")
    print(json.dumps({"pid": os.getpid(), "argv": capture.call_args.args[0]}))


def assert_legacy_start(target, data, port, env, name, device):
    # 2.3.2 has no server challenge. Send only a public GET, verify an unpredictable fixture
    # identity plus the private job's liveness, and stop by job handle. Never send a legacy token.
    with private_launcher(target / "RemoteDesk.exe", launch_args(data, port), env) as active:
        end = time.monotonic() + 30
        while time.monotonic() < end:
            require(active(), "Legacy private process exited during startup")
            if (data / "local.token").is_file() and (data / "machine.key").is_file():
                try:
                    status, raw = local_request(port, "GET", "/api/public")
                except (OSError, http.client.HTTPException):
                    pass
                else:
                    require(status == 200, "Unexpected listener on legacy fixture port")
                    state = json.loads(raw)
                    require(state["version"] == LEGACY_VERSION and state["me"]["name"] == name and state["me"]["id"] == device
                            and state["networks"] == [] and state["sessions"] == [], "Incorrect legacy fixture state")
                    return
            time.sleep(0.1)
        raise TimeoutError("Legacy fixture failed to start")


def verify_new(target, data, port, name, device):
    hosted_only()
    fixture_paths(target, data)
    sys.path.insert(0, str(target / "app"))
    from rd import common, local_access
    common.PROGRAM_DATA = str(data)  # no access to operator or service credentials
    require(common.VERSION == VERSION, "Incorrect installed application code")
    headers = owner_headers(local_access, port, data, "GET", "/api/public")
    try:
        status, raw = local_request(port, "GET", "/api/public", headers)
        require(status == 200 and local_request(port, "GET", "/api/public")[0] == 403, "Local owner boundary failed")
        state = json.loads(raw)
        require(state["version"] == VERSION and state["me"]["name"] == name and state["me"]["id"] == device
                and state["networks"] == [] and not state["service"]["active"], "Device identity changed after upgrade")
    finally:
        proof = owner_headers(local_access, port, data, "POST", "/api/quit")
        require(local_request(port, "POST", "/api/quit", proof)[0] == 200, "Candidate fixture shutdown failed")


def await_commit(active, target, data, legacy_source_hash, old_owner_hash):
    end = time.monotonic() + 240
    saw_backup = False
    challenge = None
    log = data / "logs/update.log"
    pending, ready = data / ".update-pending.json", data / ".update-ready.json"
    while time.monotonic() < end:
        require(active(), "Private upgrade process exited before it completed")
        for backup in target.parent.glob(target.name + ".precedente-*"):
            if not saw_backup:
                try:
                    saw_backup = digest(backup / "app/rd/common.py") == legacy_source_hash
                except FileNotFoundError:
                    pass
        try:
            payload = json.loads(pending.read_text(encoding="utf-8"))
            require(payload["version"] == VERSION and Path(payload["target"]).resolve() == target.resolve()
                    and len(bytes.fromhex(payload["nonce"])) == 32, "Invalid health challenge")
            challenge = payload
        except FileNotFoundError:
            pass
        if challenge is not None:
            try:
                receipt = json.loads(ready.read_text(encoding="utf-8"))
            except FileNotFoundError:
                pass
            else:
                require(receipt == challenge, "Candidate health acknowledgment did not match")
        text = log.read_text(encoding="utf-8") if log.is_file() else ""
        require("torno alla precedente" not in text and "ripristino incompleto" not in text, "Upgrade rolled back")
        if ("nuova versione attiva: aggiornamento completato" in text and not pending.exists()
                and not ready.exists() and not list(target.parent.glob(target.name + ".precedente-*"))):
            # The helper emits success only after matching the ready receipt against its own challenge.
            require(saw_backup and challenge is not None, "Did not observe the original tree and pending health challenge")
            require(digest(data / "local.token") != old_owner_hash, "Candidate kept the legacy owner token")
            return
        time.sleep(0.1)
    raise TimeoutError("Upgrade did not commit within four minutes")


def run(legacy, candidate, manifest=None):
    hosted_only()
    sys.path.insert(0, str(TEST.parents[1] / "app"))
    from rd.release_package import MAX_PACKAGE, extract_package
    require(0 < legacy.stat().st_size <= MAX_PACKAGE and digest(legacy) == LEGACY_SHA256, "Incorrect original 2.3.2 archive")
    require(0 < candidate.stat().st_size <= MAX_PACKAGE and legacy != candidate, "Invalid candidate archive")
    with tempfile.TemporaryDirectory(prefix="RD upgrade ") as temporary:
        work = Path(temporary).resolve()
        target = Path(extract_package(legacy, work / "installed")).resolve()
        data = work / "test profile/data"
        staging = data / "update"
        staging.mkdir(parents=True)
        staged = Path(extract_package(candidate, staging / "nuovo")).resolve()
        env = isolated_environment(data.parent)
        name, device = "Fixture " + secrets.token_hex(12), str(100000000 + secrets.randbelow(900000000))
        config = {"name": name, "id": device, "networks": [], "known": {}, "network": "", "signal": "",
                  "stun": [], "turn_url": "", "accept_incoming": False, "update_url": "", "auto_update": False}
        (data / "config.json").write_text(json.dumps(config), encoding="utf-8")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        assert_legacy_start(target, data, port, env, name, device)
        old_owner, machine_key = digest(data / "local.token"), digest(data / "machine.key")
        old_source = digest(target / "app/rd/common.py")
        candidate_source = digest(staged / "app/rd/common.py")
        require(old_source != candidate_source, "Candidate still contains the legacy source")
        command = subprocess.run([target / "runtime/python.exe", "-I", "-B", TEST, "--capture", target, staged, data,
                                  str(port), str(manifest) if manifest else "", candidate], cwd=work, env=env,
                                 text=True, capture_output=True, timeout=30)
        require(command.returncode == 0, "Cannot produce authentic legacy launch command: " + command.stderr[-800:])
        captured = json.loads(command.stdout)
        argv = captured["argv"]
        require(type(captured["pid"]) is int and captured["pid"] > 0, "Invalid legacy launcher PID")
        # Check both locations and the restart arguments before handing this private tree to any helper.
        require(Path(argv[0]).resolve() == staged / "runtime/pythonw.exe" and Path(argv[1]).resolve() == staged / "app/rd/updater.py",
                "Legacy command resolved outside staging")
        opts = dict(zip(argv[2::2], argv[3::2], strict=True))
        require(opts == {"--mode": "user", "--target": str(target), "--source": str(staged), "--port": str(port),
                         "--version": VERSION, "--log": str(data / "logs/update.log"), "--pid": str(captured["pid"]),
                         "--args": json.dumps(launch_args(data, port))}, "Unexpected legacy helper arguments")
        with private_launcher(Path(argv[0]), argv[1:], env) as active:
            await_commit(active, target, data, old_source, old_owner)
            require(digest(target / "app/rd/common.py") == candidate_source and digest(data / "machine.key") == machine_key,
                    "Installed code or device key does not match")
            subprocess.run([target / "runtime/python.exe", "-I", "-B", TEST, "--verify", target, data, str(port), name, device],
                           cwd=work, env=env, check=True, timeout=30)
            end = time.monotonic() + 15
            while active():
                require(time.monotonic() < end, "Candidate did not exit after authenticated shutdown")
                time.sleep(0.1)
    print("Portable 2.3.2 -> 2.4.0 upgrade passed" + (" with verified candidate manifest" if manifest else " (artifact-only candidate)"))


if __name__ == "__main__":
    if len(sys.argv) == 8 and sys.argv[1] == "--capture":
        capture_legacy_command(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), int(sys.argv[5]),
                               Path(sys.argv[6]) if sys.argv[6] else None, Path(sys.argv[7]))
    elif len(sys.argv) == 7 and sys.argv[1] == "--verify":
        verify_new(Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--legacy-zip", required=True, type=Path)
        parser.add_argument("--candidate-zip", required=True, type=Path)
        parser.add_argument("--candidate-manifest", type=Path)
        args = parser.parse_args()
        run(args.legacy_zip.resolve(), args.candidate_zip.resolve(), args.candidate_manifest.resolve() if args.candidate_manifest else None)
