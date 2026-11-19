"""Read-only inventory transport for one explicitly approved Windows session."""
import asyncio
import json
import threading
import time

from .win_identity import interactive_logon, logon_id

SECTIONS = frozenset(("shares", "drives", "services", "apps"))
FRAME_LIMIT = 16 * 1024
TOTAL_LIMIT = 1024 * 1024
ROW_LIMIT = 1500
_workers = threading.BoundedSemaphore(2)


def collect(section, expected_logon, service):
    from .inventory import read_section
    if not _workers.acquire(blocking=False):
        raise RuntimeError("Inventario occupato")
    try:
        if service:
            from . import winapi as W
            sid = W.process_session()
            with W.as_session_user(sid) as user:
                if not sid or (sid, logon_id(user.tok)) != expected_logon:
                    raise PermissionError("La sessione Windows è cambiata")
                return read_section(section)
        return read_section(section)
    finally:
        _workers.release()


def _dump(data):
    return json.dumps(data, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def pages(section, request_id, result):
    partial = bool(result["partial"])
    note = str(result.get("note") or "")[:256]
    base = {"t": "inventory", "section": section, "id": request_id}
    groups, group, size = [], [], 0
    # Reserve space for the envelope, Unicode-escaped note and the truncation notice.
    row_budget = FRAME_LIMIT - 4096
    used, count, truncated = 0, 0, False
    for row in result["rows"]:
        length = len(_dump(row)) + 1
        if length > row_budget:
            truncated = True
            continue
        if count >= ROW_LIMIT or used + length + 4096 > TOTAL_LIMIT:
            truncated = True
            break
        if group and size + length > row_budget:
            groups.append(group)
            group, size = [], 0
        group.append(row)
        size += length
        used += length
        count += 1
    groups.append(group)
    if truncated:
        partial = True
        note = (note + " Limite di trasmissione raggiunto.").strip()
    sent = 0
    for i, rows in enumerate(groups):
        last = i == len(groups) - 1
        payload = _dump(dict(base, more=not last, result={"rows": rows, "partial": partial, "note": note if last else ""}))
        if len(payload) >= FRAME_LIMIT:
            raise ValueError("Pagina inventario troppo grande")
        if sent + len(payload) + (0 if last else 512) > TOTAL_LIMIT:
            yield _dump(dict(base, more=False, result={"rows": [], "partial": True, "note": "Limite di trasmissione raggiunto."}))
            return
        yield payload
        sent += len(payload)


class InventoryChannel:
    def __init__(self, session, channel):
        self.session = session
        self.channel = channel
        self.task = None
        self.last_request = 0
        self.closed = False
        channel.on("message", self.on_message)
        channel.on("close", self.close)

    def permitted(self):
        s = self.session
        return (not self.closed and self.channel.readyState == "open" and s.mode == "manage"
                and s.agent.sessions.get(s.sid) is s and s.lease_active() and s.refresh_authorization())

    def same_logon(self):
        return not self.session.agent.service_mode or interactive_logon() == self.session.windows_logon

    def error(self, request_id, section, text):
        if self.permitted():
            self.channel.send(_dump({"t": "inventory", "id": request_id, "section": section, "error": text}))

    def on_message(self, raw):
        if self.closed or not isinstance(raw, str) or len(raw) > 8192:
            return
        try:
            msg = json.loads(raw)
        except (ValueError, RecursionError):
            return
        if isinstance(msg, dict) and msg.get("t") == "renew":
            self.session.renew(msg)
            return
        if not self.permitted() or len(raw) > 512 or not isinstance(msg, dict) or set(msg) != {"t", "section", "id"} or msg["t"] != "inventory":
            return
        request_id, section = msg["id"], msg["section"]
        if type(request_id) is not int or not 0 <= request_id <= 2**31 - 1:
            return
        if not isinstance(section, str) or section not in SECTIONS:
            self.error(request_id, None, "Sezione non disponibile")
            return
        now = time.monotonic()
        if (self.task and not self.task.done()) or now - self.last_request < 0.25:
            self.error(request_id, section, "Inventario occupato")
            return
        self.last_request = now
        self.task = asyncio.create_task(self.serve(request_id, section))

    async def serve(self, request_id, section):
        s = self.session
        loop = asyncio.get_running_loop()
        try:
            if not self.permitted() or not self.same_logon():
                raise PermissionError
            result = await loop.run_in_executor(None, collect, section, s.windows_logon, s.agent.service_mode)
            for page in pages(section, request_id, result):
                deadline = loop.time() + 5
                while self.channel.bufferedAmount > 64 * 1024:
                    if not self.permitted() or loop.time() >= deadline:
                        raise RuntimeError
                    await asyncio.sleep(0.05)
                if not self.permitted() or not self.same_logon():
                    raise PermissionError
                self.channel.send(page)
                await asyncio.sleep(0)
            s.agent.audit.add("inventory_read", net=s.net.nid, user=s.user, peer=s.peer, section=section)
        except PermissionError:
            self.error(request_id, section, "Identità locale o autorizzazione non valida")
            await s.close(reason="revoked")
        except (OSError, RuntimeError, ValueError, TypeError, KeyError):
            self.error(request_id, section, "Inventario non disponibile")

    def close(self):
        self.closed = True
        if self.task and self.task is not asyncio.current_task() and not self.task.done():
            self.task.cancel()
