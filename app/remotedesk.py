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


def api(port, path, body=None, timeout=2):
    try:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST" if data is not None else "GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def agent_alive(port):
    r = api(port, "/api/ping", timeout=1.5)
    return bool(r and r.get("app") == "remotedesk")


# =========================================================================== agente
async def run_agent(data_dir, port, service_mode=False, parent=None, stop_flag=None):
    from aiohttp import web
    from rd.agent import Agent
    from rd.web import make_app

    from rd.common import Config
    cfg = Config(data_dir)
    agent = Agent(cfg, data_dir, service_mode=service_mode)
    loop = asyncio.get_running_loop()
    app = make_app(agent, port, lambda: agent.stop_event.set())
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
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
        return
    log.info("agente pronto: ID %s, http://127.0.0.1:%s/ (servizio=%s)", fmt_id(cfg["id"]), port, service_mode)
    agent.start_networks()
    tasks = [asyncio.ensure_future(agent.clip_watch()), asyncio.ensure_future(agent.housekeeping())]
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
        log.info("agente fermato")


class AgentThread:
    def __init__(self, data_dir, port):
        self.data_dir, self.port = data_dir, port
        self.stop_flag = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="agent")
        self.thread.start()

    def _run(self):
        try:
            asyncio.run(run_agent(self.data_dir, self.port, stop_flag=self.stop_flag))
        except Exception:
            log.exception("agente terminato con errore")

    def alive(self):
        return self.thread.is_alive()

    def stop(self):
        self.stop_flag.set()
        self.thread.join(5)


# =========================================================================== app utente (tray)
class App:
    def __init__(self, args, data_dir):
        self.args, self.data_dir, self.port = args, data_dir, args.port
        self.agent = None
        self.icon = None
        self.quit = threading.Event()
        self.last_sessions = set()

    def service_installed(self):
        return service_installed(self.data_dir)

    def remove_service(self, *_):
        from rd import service
        service.elevate("--uninstall-service", user_data=self.data_dir)

    def ensure_agent(self):
        if self.agent and self.agent.alive():
            return
        if agent_alive(self.port):
            return
        if self.service_installed():
            return  # ci pensa il servizio
        log.info("avvio agente utente")
        self.agent = AgentThread(self.data_dir, self.port)

    def open_console(self, *_):
        from rd.agent import open_console
        for _ in range(40):
            if agent_alive(self.port):
                break
            time.sleep(0.25)
        open_console(self.port)

    def close_all(self, *_):
        api(self.port, "/api/sessions/close", {})

    def exit(self, *_):
        self.quit.set()
        if self.agent:
            self.agent.stop()
        if self.icon:
            self.icon.stop()

    def watchdog(self):
        while not self.quit.is_set():
            try:
                self.ensure_agent()
                st = api(self.port, "/api/public")
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
            st = api(self.port, "/api/chat", timeout=1.5)
            if st and st.get("unread") and not st.get("window"):
                if time.time() - last_open > 20:
                    last_open = time.time()
                    open_chat_window(self.port)
                newest = max((m["id"] for m in st["messages"] if m["who"] == "tech"), default=0)
                if self.icon and newest > last_notified:
                    last_notified = newest
                    try:
                        m = [m for m in st["messages"] if m["id"] == newest][0]
                        self.icon.notify(m["text"][:200], f"Messaggio da {m['name']}")
                    except Exception:
                        pass
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
                self.exit()
            return
        import pystray
        from PIL import Image
        self.images = [Image.open(os.path.join(os.path.dirname(__file__), "web", f)) for f in
                       ("icon.png", "icon-active.png")]
        def id_label(_):   # l'ID lo chiedo all'agente: con il servizio i dati non sono leggibili dall'utente
            st = api(self.port, "/api/public", timeout=1)
            return f"ID {st['me']['fid']}" if st else "RemoteDesk"
        menu = pystray.Menu(
            pystray.MenuItem(id_label, None, enabled=False),
            pystray.MenuItem("Apri RemoteDesk", self.open_console, default=True),
            pystray.MenuItem("Disconnetti tutte le sessioni", self.close_all),
            pystray.MenuItem("Rimuovi servizio...", self.remove_service,
                             visible=lambda _: self.service_installed()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(lambda _: "Nascondi icona" if self.service_installed() else "Esci", self.exit),
        )
        self.icon = pystray.Icon("RemoteDesk", self.images[0], "RemoteDesk", menu)
        threading.Thread(target=self.watchdog, daemon=True).start()
        self.icon.run()


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
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    data_dir = pick_data_dir(args.data, service=args.service or args.session_agent)
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
                    open_console(args.port)
                return
        App(args, data_dir).run()


if __name__ == "__main__":
    main()
