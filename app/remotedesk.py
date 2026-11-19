"""RemoteDesk - accesso remoto tra le macchine della tua rete, senza server propri.

Modalita':
  (nessuna)          agente + icona nella barra + console
  --minimized        come sopra ma senza aprire la console (avvio automatico)
  --service          supervisore Windows (attivita' pianificata come SYSTEM)
  --session-agent    agente lanciato dal supervisore nella sessione utente
  --install-service / --uninstall-service   (richiedono amministratore)
"""
import argparse
import asyncio
import json
import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rd.common import WIN  # noqa: E402

if WIN:
    from rd import winapi as W
    W.set_dpi_aware()

from rd.common import DEFAULT_PORT, fmt_id, pick_data_dir, service_installed, setup_logging  # noqa: E402

import logging  # noqa: E402

log = logging.getLogger("rd")


def api(port, path, body=None, timeout=2, data_dir=None, *, owner_only=False):
    from rd.local_access import native_headers
    try:
        data = json.dumps(body).encode() if body is not None else None
        method = "POST" if data is not None else "GET"
        headers = native_headers(port, path, method, data_dir=data_dir, owner_only=owner_only)
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method)
        class LocalOnly(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalOnly())
        with opener.open(req, timeout=timeout) as response:
            raw = response.read(262145)
            return json.loads(raw) if len(raw) <= 262144 else None
    except (OSError, ValueError):
        return None


def agent_alive(port, data_dir=None, *, owner_only=False):
    r = api(port, "/api/ping", timeout=1.5, data_dir=data_dir, owner_only=owner_only)
    return bool(r and r.get("app") == "remotedesk")


# =========================================================================== agente
def load_config(data_dir, portable_instance):
    from rd.common import Config
    new_profile = portable_instance and not any(os.path.lexists(os.path.join(data_dir, name))
                                                for name in ("config.json", "config.json.bak", "machine.key"))
    cfg = Config(data_dir)
    if new_profile and cfg.get("auto_update") is None:
        cfg.update(auto_update=True)
    return cfg


async def run_agent(data_dir, port, service_mode=False, parent=None, stop_flag=None, instance=None):
    from aiohttp import web
    from rd.agent import Agent
    from rd.web import make_app

    cfg = load_config(data_dir, instance is not None)
    agent = Agent(cfg, data_dir, service_mode=service_mode)
    agent.portable = instance is not None
    agent.port = port
    loop = asyncio.get_running_loop()
    app = make_app(agent, port, lambda: agent.stop_event.set())
    runner = web.AppRunner(app, access_log=None, shutdown_timeout=2)   # chiusura rapida anche con richieste aperte
    await runner.setup()
    if instance is not None:
        sock = instance.sock.dup()
        try:
            await web.SockSite(runner, sock).start()
        except BaseException:
            sock.close()
            await runner.cleanup()
            raise
    else:
        for attempt in range(60):
            try:
                await web.TCPSite(runner, "127.0.0.1", port).start()
                break
            except OSError:
                if attempt == 0:
                    log.info("porta %s occupata, attendo...", port)
                await asyncio.sleep(1)
        else:
            log.error("porta %s non disponibile", port)
            await runner.cleanup()
            return
    log.info("agente pronto: ID %s, http://127.0.0.1:%s/ (servizio=%s)", fmt_id(cfg["id"]), port, service_mode)
    from rd.common import write_private
    write_private(os.path.join(data_dir, "local.token"), agent.local_token)
    if instance is not None:
        instance.ready()
    agent.start_networks()
    tasks = [asyncio.ensure_future(agent.housekeeping()),
             asyncio.ensure_future(agent.cursor_watch()), asyncio.ensure_future(agent.updater.loop())]
    if parent:
        tasks.append(asyncio.ensure_future(agent.watch_parent(parent)))
    if stop_flag is not None:
        async def poll_stop():
            while not stop_flag.is_set():
                await asyncio.sleep(0.3)
            agent.stop_event.set()
        tasks.append(asyncio.ensure_future(poll_stop()))
    try:
        await agent.stop_event.wait()
    finally:
        for t in tasks:
            t.cancel()
        await agent.shutdown()
        await runner.cleanup()
        log.info("agente fermato" + (" per aggiornamento" if agent.updating else ""))
    return agent.updating


class AgentThread:
    def __init__(self, data_dir, port, instance=None):
        self.data_dir, self.port = data_dir, port
        self.instance = instance
        self.stop_flag = threading.Event()
        self.updating = False
        self.thread = threading.Thread(target=self._run, daemon=True, name="agent")
        self.thread.start()

    def _run(self):
        try:
            self.updating = bool(asyncio.run(run_agent(self.data_dir, self.port, stop_flag=self.stop_flag,
                                                       instance=self.instance)))
        except Exception:
            log.exception("agente terminato con errore")

    def alive(self):
        return self.thread.is_alive()

    def stop(self, timeout=5):
        self.stop_flag.set()
        self.thread.join(timeout)


# =========================================================================== app utente (tray)
class App:
    def __init__(self, args, data_dir, instance=None):
        self.args, self.data_dir, self.port = args, data_dir, args.port
        self.instance = instance
        self.owner_only = instance is not None
        self.agent = None
        self.icon = None
        self.quit = threading.Event()
        self.last_sessions = set()

    def service_installed(self):
        return not self.owner_only and service_installed(self.data_dir)

    def remove_service(self, *_):
        if self.owner_only:
            return
        from rd import service
        service.elevate("--uninstall-service", user_data=self.data_dir)

    def ensure_agent(self):
        if self.quit.is_set():          # in chiusura: non rilancio nulla
            return
        if self.agent and self.agent.alive():
            return
        if not self.owner_only and agent_alive(self.port, self.data_dir):
            return
        if self.service_installed():
            return  # ci pensa il servizio
        log.info("avvio agente utente")
        self.agent = AgentThread(self.data_dir, self.port, self.instance)

    def open_console(self, *_):
        from rd.agent import open_console
        for _ in range(40):
            if agent_alive(self.port, self.data_dir, owner_only=self.owner_only):
                open_console(self.port, data_dir=self.data_dir, owner_only=self.owner_only)
                return
            time.sleep(0.25)

    def close_all(self, *_):
        api(self.port, "/api/sessions/close", {}, data_dir=self.data_dir, owner_only=self.owner_only)

    def exit(self, *_):
        """Voce "Esci": l'icona sparisce subito, l'agente ha pochi secondi per chiudersi in modo pulito,
        poi il processo termina comunque (nessun thread di lavoro puo' tenerlo in vita)."""
        if self.quit.is_set():
            return
        self.quit.set()
        log.info("chiusura richiesta dall'icona")
        threading.Thread(target=self._parachute, daemon=True).start()
        if self.icon:
            self.icon.stop()            # run() ritorna nel thread principale, che completa la chiusura
        else:
            self.finish()

    def _parachute(self):
        time.sleep(10)
        log.warning("chiusura forzata")
        os._exit(0)

    def finish(self):
        try:
            if self.agent:
                self.agent.stop(timeout=4)
        finally:
            logging.shutdown()
            os._exit(0)

    def watchdog(self):
        while not self.quit.is_set():
            try:
                if self.agent and self.agent.updating:   # il programma di aggiornamento mi sostituira'
                    log.info("aggiornamento in corso: chiudo RemoteDesk")
                    if self.icon:
                        self.icon.stop()
                    os._exit(0)
                self.ensure_agent()
                st = api(self.port, "/api/public", data_dir=self.data_dir, owner_only=self.owner_only)
                if st and self.icon:
                    cur = {s["sid"]: s for s in st["sessions"] if s["connected"]}
                    for sid in set(cur) - self.last_sessions:
                        self.icon.notify(f"{cur[sid]['peer_name']} e' collegato a questo PC", "RemoteDesk")
                    self.last_sessions = set(cur)
                    self.icon.title = (f"RemoteDesk - ID {st['me']['fid']}" +
                                       (f" - {len(cur)} sessioni attive" if cur else ""))
                    self.icon.icon = self.images[1 if cur else 0]
            except Exception as e:
                log.debug("watchdog: %s", e)
            self.quit.wait(3)

    def chat_watch(self):
        """Apre la finestrella di chat quando un tecnico scrive e la finestra non e' aperta."""
        from rd.agent import open_chat_window
        last_open, last_notified = 0, 0
        while not self.quit.is_set():
            st = api(self.port, "/api/chat", timeout=1.5, data_dir=self.data_dir, owner_only=self.owner_only)
            if st and st.get("unread") and not st.get("window"):
                if time.time() - last_open > 20:
                    last_open = time.time()
                    open_chat_window(self.port, data_dir=self.data_dir, owner_only=self.owner_only)
                newest = st.get("latest", 0)
                if self.icon and newest > last_notified:
                    last_notified = newest
                    self.icon.notify("Hai un messaggio nella chat di assistenza", "RemoteDesk")
            self.quit.wait(1)

    def run(self):
        self.ensure_agent()
        threading.Thread(target=self.chat_watch, daemon=True).start()
        if not self.args.minimized and not self.args.no_browser:
            threading.Thread(target=self.open_console, daemon=True).start()
        if self.args.no_tray:
            threading.Thread(target=self.watchdog, daemon=True).start()
            try:
                while not self.quit.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                self.quit.set()
            self.finish()
            return
        import pystray
        from PIL import Image
        self.images = [Image.open(os.path.join(os.path.dirname(__file__), "web", f)) for f in
                       ("icon.png", "icon-active.png")]
        def id_label(_):   # l'ID lo chiedo all'agente: con il servizio i dati non sono leggibili dall'utente
            st = api(self.port, "/api/public", timeout=1, data_dir=self.data_dir, owner_only=self.owner_only)
            return f"ID {st['me']['fid']}" if st else "RemoteDesk"
        menu = pystray.Menu(
            pystray.MenuItem(id_label, None, enabled=False),
            pystray.MenuItem("Apri RemoteDesk", self.open_console, default=True),
            pystray.MenuItem("Disconnetti tutte le sessioni", self.close_all),
            pystray.MenuItem("Rimuovi servizio...", self.remove_service,
                             visible=lambda _: self.service_installed()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(lambda _: "Chiudi icona (il servizio resta attivo)" if self.service_installed()
                             else "Esci da RemoteDesk", self.exit),
        )
        self.icon = pystray.Icon("RemoteDesk", self.images[0], "RemoteDesk", menu)
        threading.Thread(target=self.watchdog, daemon=True).start()
        self.icon.run()
        self.quit.set()                 # icona chiusa (da "Esci" o da Windows): chiudo tutto
        self.finish()


def run_portable(args, root):
    from rd.agent import open_console
    from rd.portable import Instance
    with Instance(root, args.data) as instance:
        data_dir = str(instance.profile)
        if not instance.owner:
            for _ in range(40):
                port = instance.existing_port()
                if port and agent_alive(port, data_dir, owner_only=True):
                    if not (args.minimized or args.agent_only or args.no_browser):
                        open_console(port, data_dir=data_dir, owner_only=True)
                    return
                time.sleep(0.25)
            raise RuntimeError("Il profilo è in uso ma la console della copia portabile non è ancora verificabile.")
        instance.reserve(args.port)
        args.port = instance.port
        setup_logging(data_dir, "portable", args.verbose)
        if args.agent_only:
            asyncio.run(run_agent(data_dir, args.port, instance=instance))
        else:
            App(args, data_dir, instance).run()


def main():
    ap = argparse.ArgumentParser(description="RemoteDesk")
    ap.add_argument("--minimized", action="store_true")
    ap.add_argument("--service", action="store_true")
    ap.add_argument("--session-agent", action="store_true")
    ap.add_argument("--parent", type=int)
    ap.add_argument("--install-service", action="store_true")
    ap.add_argument("--uninstall-service", action="store_true")
    ap.add_argument("--agent-only", action="store_true", help="solo agente, in primo piano")
    ap.add_argument("--no-tray", action="store_true")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--data", help="cartella dati alternativa")
    ap.add_argument("--from-data", help=argparse.SUPPRESS)
    ap.add_argument("--port", type=int)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    privileged = args.service or args.session_agent or args.install_service or args.uninstall_service
    if WIN:
        from rd.common import INSTALL_DIR, ROOT_DIR
        from rd.portable import installed_profile, is_bundle
        canonical = os.path.normcase(os.path.realpath(ROOT_DIR)) == os.path.normcase(os.path.realpath(INSTALL_DIR))
        if privileged and not canonical:
            raise PermissionError("La gestione del servizio richiede la copia nella cartella protetta di installazione.")
        if args.service or args.session_agent:
            from rd.local_access_win import running_as_system
            trusted = os.path.join(INSTALL_DIR, "runtime", "pythonw.exe")
            if (os.path.normcase(os.path.realpath(sys.executable)) != os.path.normcase(os.path.realpath(trusted))
                    or not running_as_system()):
                raise PermissionError("Il servizio richiede il runtime di installazione e l'identità SYSTEM.")
        if not privileged and is_bundle(ROOT_DIR):
            try:
                run_portable(args, ROOT_DIR)
            except (OSError, ValueError, RuntimeError) as exc:
                if args.agent_only or args.no_browser or args.minimized:
                    raise
                W.message_box(str(exc), "RemoteDesk portabile")
                raise SystemExit(1) from exc
            return
        if not privileged and canonical:
            args.data = installed_profile(args.data)
    args.port = args.port if args.port is not None else DEFAULT_PORT
    data_dir = pick_data_dir(args.data, service=privileged)
    mode = ("service" if args.service else "session-agent" if args.session_agent else
            "install" if args.install_service or args.uninstall_service else "app")
    setup_logging(data_dir, mode, args.verbose)

    if args.service:
        from rd.service import run_supervisor
        run_supervisor()
    elif args.install_service or args.uninstall_service:
        from rd import service
        (service.install if args.install_service else service.uninstall)(args.from_data)
    elif args.session_agent or args.agent_only:
        try:
            asyncio.run(run_agent(data_dir, args.port, service_mode=args.session_agent, parent=args.parent))
        except KeyboardInterrupt:
            pass
    else:
        if WIN and not args.no_tray:
            if not W.single_instance("Local\\RemoteDeskTray"):
                # gia' in esecuzione: apro solo la console
                if not args.minimized:
                    from rd.agent import open_console
                    open_console(args.port, data_dir=data_dir)
                return
        App(args, data_dir).run()


if __name__ == "__main__":
    main()
