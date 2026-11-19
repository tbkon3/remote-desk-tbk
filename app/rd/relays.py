"""Server di segnalazione ("bacheche" pubbliche) usati in parallelo.

Ogni messaggio di una rete viene pubblicato su TUTTI i server configurati e ricevuto dal primo che
lo consegna (i doppioni vengono scartati). I messaggi sono gia' cifrati e firmati: i server vedono solo
dati illeggibili. Tipi supportati:
  https://ntfy.sh             ntfy (HTTP), con storico breve e limiti di messaggi per IP
  mqtts://broker.emqx.io:8883 MQTT 3.1.1 su TLS (client minimo integrato, QoS 0, nessuno storico)
"""
import asyncio
import contextlib
import ipaddress
import json
import logging
import re
import secrets
import ssl
import struct
import time
from urllib.parse import urlparse, urlunparse

from aiohttp import ClientSession, ClientTimeout, TraceConfig, WSMsgType

log = logging.getLogger("rd.relay")
DEFAULT_SIGNAL = "https://ntfy.sh, mqtts://broker.emqx.io:8883, mqtts://broker.hivemq.com:8883"
MAX_BODY = 4 * 1024 * 1024
MAX_EVENT = 64 * 1024
MAX_RELAYS = 8


def _endpoint(value):
    if len(value) > 1024 or any(ord(c) < 33 for c in value) or any(c in value for c in "\\%?#@"):
        raise ValueError("Indirizzo del relay non valido")
    u = urlparse(value)
    if (not u.hostname or u.scheme not in {"https", "wss", "mqtts", "http", "mqtt"}
            or not re.fullmatch(r"[A-Za-z0-9.:\[\]-]+", u.netloc) or u.port == 0
            or u.params or u.netloc.endswith(":") or (u.scheme.startswith("mqtt") and u.path.strip("/"))
            or not re.fullmatch(r"(?:/[a-zA-Z0-9._~-]+)*/?", u.path)
            or any(part in (".", "..") for part in u.path.split("/"))):
        raise ValueError("Indirizzo del relay non valido")
    if u.scheme in {"http", "mqtt"} and not ipaddress.ip_address(u.hostname).is_loopback:
        raise ValueError("Il relay richiede TLS")
    return urlunparse((u.scheme, u.netloc.lower(), u.path.rstrip("/"), "", "", ""))


def parse_signal(text):
    out = []
    if not isinstance(text, str) or len(text) > MAX_RELAYS * 1025:
        return []
    for part in re.split(r"[\s,;]+", text.strip()):
        if not part:
            continue
        try:
            part = _endpoint(part)
        except ValueError:
            return []
        if part not in out:
            out.append(part)
            if len(out) > MAX_RELAYS:
                return []
    return out


def make_relay(url, topic):
    url = _endpoint(url)
    return MqttRelay(url, topic) if url.startswith("mqtt") else NtfyRelay(url, topic)


class RelayError(RuntimeError):
    pass


class Relay:
    def __init__(self, url, topic):
        if not isinstance(topic, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", topic):
            raise ValueError("Topic del relay non valido")
        self.url, self.topic = _endpoint(url), topic
        self.state = "connessione..."
        self.error = ""
        self.ok_since = 0
        self.writers = 0

    async def publish(self, blob):
        if not isinstance(blob, str) or len(blob) > MAX_BODY:
            raise RelayError("messaggio troppo grande")
        if self.writers >= 4:
            raise RelayError("relay occupato")
        data = blob.encode("utf-8")
        if len(data) > MAX_BODY:
            raise RelayError("messaggio troppo grande")
        self.writers += 1
        try:
            return await asyncio.wait_for(self._publish(data), 65)
        finally:
            self.writers -= 1

    @property
    def name(self):
        u = urlparse(self.url)
        kind = "MQTT" if u.scheme.startswith("mqtt") else "ntfy"
        return f"{u.hostname or self.url} ({kind})"

    def status(self):
        return {"name": self.name, "url": self.url, "state": self.state, "error": self.error}

    @property
    def online(self):
        return self.state == "online"


# =========================================================================== ntfy
class NtfyRelay(Relay):
    def __init__(self, url, topic):
        super().__init__(url, topic)
        self.http = "https" + self.url[3:] if self.url.startswith("wss://") else self.url
        self.session = None
        self.quota = None            # {"used", "limit"} se il server lo comunica
        self.quota_until = 0         # quota giornaliera esaurita: non insisto fino a quest'ora
        self.rate_until = 0          # troppe richieste ravvicinate: attendo

    @staticmethod
    async def _read(response, limit):
        if response.content_length is not None and response.content_length > limit:
            raise RelayError("risposta troppo grande")
        data = bytearray()
        async for chunk in response.content.iter_chunked(16 * 1024):
            if len(data) + len(chunk) > limit:
                raise RelayError("risposta troppo grande")
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    async def _redirect(*_):
        raise RelayError("redirect del relay rifiutato")

    async def _events(self, session, since):
        if self.url.startswith("wss://"):
            async with session.ws_connect(f"{self.url}/{self.topic}/ws", params={"since": since},
                                          max_msg_size=MAX_EVENT, heartbeat=45, compress=0) as ws:
                self.state, self.error = "online", ""
                while True:
                    frame = await asyncio.wait_for(ws.receive(), 150)
                    if frame.type != WSMsgType.TEXT:
                        return
                    yield frame.data
        else:
            async with session.get(f"{self.http}/{self.topic}/json", params={"since": since},
                                   allow_redirects=False) as r:
                if r.status == 429:
                    raise RelayError(await self._limit_error(r))
                if r.status != 200:
                    raise RelayError(f"HTTP {r.status}")
                if self.state != "quota":
                    self.state, self.error = "online", ""
                while line := await asyncio.wait_for(r.content.readline(), 150):
                    if len(line) > MAX_EVENT:
                        raise RelayError("evento troppo grande")
                    yield line

    async def run(self, on_msg):
        since = "900s"
        timeout = ClientTimeout(total=None, sock_connect=15, sock_read=150)   # keepalive ntfy ogni 45 s
        trace = TraceConfig()
        trace.on_request_redirect.append(self._redirect)
        # Disable decompression so compressed data cannot expand before the input limits apply.
        async with ClientSession(timeout=timeout, trust_env=False, auto_decompress=False,
                                 headers={"Accept-Encoding": "identity"}, trace_configs=[trace]) as s:
            self.session = s
            quota = asyncio.create_task(self._quota_loop())
            try:
                while True:
                    try:
                        async for line in self._events(s, since):
                            try:
                                ev = json.loads(line)
                            except ValueError:
                                continue
                            if not isinstance(ev, dict) or ev.get("event") != "message":
                                continue
                            identifier = ev.get("id")
                            if isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier):
                                since = identifier
                            body = await self._body(ev)
                            if body:
                                await on_msg(self, body, ev.get("time"))
                        raise RelayError("connessione chiusa")
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        if self.state != "quota":
                            self.state, self.error = "offline", str(e)[:200]
                        log.debug("ntfy %s: %s", self.name, e)
                    await asyncio.sleep(10 if self.state != "quota" else 300)
            finally:
                self.session = None
                quota.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await quota

    async def _body(self, ev):
        att = ev.get("attachment") or {}
        if not isinstance(att, dict):
            return None
        if not att.get("url"):
            message = ev.get("message")
            return message if isinstance(message, str) and len(message) <= MAX_EVENT else None
        url = str(att["url"])   # solo allegati del nostro server e di dimensione ragionevole
        size = att.get("size", 0)
        if (not re.fullmatch(re.escape(self.http + "/file/") + r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?", url)
                or type(size) is not int or not 0 <= size <= MAX_BODY):
            return None
        try:
            async with self.session.get(url, timeout=ClientTimeout(total=30), allow_redirects=False) as r:
                if r.status != 200:
                    return None
                data = await self._read(r, MAX_BODY)
            return data.decode("utf-8")
        except Exception:
            return None

    async def _limit_error(self, r):
        try:
            d = json.loads(await self._read(r, MAX_EVENT))
            code, msg = d.get("code"), d.get("error", "")
            msg = msg[:200] if isinstance(msg, str) else ""
        except Exception:
            code, msg = None, "limite raggiunto"
        if code == 42908:          # quota giornaliera di messaggi
            if self.state != "quota":
                log.warning("ntfy %s: quota giornaliera di messaggi esaurita", self.name)
            self.state, self.error = "quota", "quota giornaliera di messaggi esaurita"
            self.quota_until = time.time() + 3600   # riprovo tra un'ora
        else:                      # 42901 troppe richieste ravvicinate, 42903 troppe sottoscrizioni...
            self.rate_until = time.time() + 30
            self.error = msg or "troppe richieste"
        return msg

    async def _publish(self, data):
        now = time.time()
        if now < self.quota_until:
            raise RelayError("quota giornaliera esaurita")
        if now < self.rate_until:
            await asyncio.sleep(min(self.rate_until - now, 30))
        if not self.session:
            raise RelayError("non connesso")
        async with self.session.post(f"{self.http}/{self.topic}", data=data,
                                     headers={"Content-Type": "text/plain; charset=utf-8"},
                                     timeout=ClientTimeout(total=30), allow_redirects=False) as r:
            if r.status == 429:
                raise RelayError(await self._limit_error(r))
            if r.status >= 300:
                raise RelayError(f"HTTP {r.status}")
            if self.state == "quota":
                self.state, self.error, self.quota_until = "online", "", 0
            try:
                return json.loads(await self._read(r, MAX_EVENT)).get("time")
            except Exception:
                return None

    async def _quota_loop(self):
        while True:
            if self.session and self.state in ("online", "quota"):
                try:
                    async with self.session.get(f"{self.http}/v1/account", timeout=ClientTimeout(total=15),
                                                allow_redirects=False) as r:
                        if r.status == 200:
                            d = json.loads(await self._read(r, MAX_EVENT))
                            lim = (d.get("limits") or {}).get("messages")
                            used = (d.get("stats") or {}).get("messages")
                            if isinstance(lim, int) and isinstance(used, int):
                                self.quota = {"used": used, "limit": lim}
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
                await asyncio.sleep(1800)
            else:
                await asyncio.sleep(15)

    def status(self):
        d = super().status()
        d["quota"] = self.quota
        return d


# =========================================================================== MQTT 3.1.1 minimo
def _varint(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _str(s):
    b = s.encode()
    return struct.pack(">H", len(b)) + b


class MqttRelay(Relay):
    KEEPALIVE = 60

    def __init__(self, url, topic):
        super().__init__(url, topic)
        u = urlparse(url)
        self.host = u.hostname
        self.tls = u.scheme == "mqtts"
        self.port = u.port or (8883 if self.tls else 1883)
        self.mtopic = "rdesk/" + topic
        self.writer = None
        self.lock = asyncio.Lock()

    async def _send(self, ptype, body):
        async with self.lock:
            if not self.writer:
                raise RelayError("non connesso")
            self.writer.write(bytes([ptype]) + _varint(len(body)) + body)
            await asyncio.wait_for(self.writer.drain(), 20)

    @staticmethod
    async def _read_packet(reader):
        head = (await reader.readexactly(1))[0]
        mult, length = 1, 0
        for _ in range(4):
            b = (await reader.readexactly(1))[0]
            length += (b & 0x7F) * mult
            mult *= 128
            if not b & 0x80:
                break
        else:
            raise RelayError("lunghezza MQTT non valida")
        if length > MAX_BODY + 1024:
            raise RelayError("pacchetto troppo grande")
        return head, (await reader.readexactly(length)) if length else b""

    async def run(self, on_msg):
        delay = 5
        while True:
            ping = None
            try:
                ctx = ssl.create_default_context() if self.tls else None
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port, ssl=ctx, server_hostname=self.host if self.tls else None),
                    20)
                self.writer = writer
                cid = "rd" + secrets.token_hex(10)
                await self._send(0x10, _str("MQTT") + bytes([4, 0x02]) + struct.pack(">H", self.KEEPALIVE) + _str(cid))
                head, body = await asyncio.wait_for(self._read_packet(reader), 20)
                if head != 0x20 or body != b"\x00\x00":
                    raise RelayError(f"connessione rifiutata dal broker ({body[1] if len(body) > 1 else '?'})")
                await self._send(0x82, struct.pack(">H", 1) + _str(self.mtopic) + bytes([0]))
                ack_deadline = asyncio.get_running_loop().time() + 20

                async def pinger():
                    while True:
                        await asyncio.sleep(self.KEEPALIVE / 2)
                        await self._send(0xC0, b"")
                ping = asyncio.ensure_future(pinger())
                while True:
                    timeout = self.KEEPALIVE * 2 if ack_deadline is None else ack_deadline - asyncio.get_running_loop().time()
                    head, body = await asyncio.wait_for(self._read_packet(reader), timeout)
                    if head == 0x90:
                        if ack_deadline is None or body != b"\x00\x01\x00":
                            raise RelayError("sottoscrizione MQTT rifiutata")
                        ack_deadline = None
                        self.state, self.error, delay = "online", "", 5
                        continue
                    if head >> 4 != 3:      # interessa solo PUBLISH (SUBACK/PINGRESP ignorati)
                        continue
                    prefix = _str(self.mtopic)
                    if head & 0x06 or not body.startswith(prefix) or len(body) - len(prefix) > MAX_BODY:
                        continue
                    try:
                        await on_msg(self, body[len(prefix):].decode("utf-8"), None)
                    except Exception as e:
                        log.debug("mqtt evento: %s", e)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.state, self.error = "offline", str(e)[:200] or type(e).__name__
                log.debug("mqtt %s: %s", self.name, e)
            finally:
                if ping:
                    ping.cancel()
                    with contextlib.suppress(Exception, asyncio.CancelledError):
                        await ping
                w, self.writer = self.writer, None
                if w:
                    try:
                        w.close()
                        await asyncio.wait_for(w.wait_closed(), 5)
                    except Exception:
                        pass
            await asyncio.sleep(delay)
            delay = min(delay * 2, 120)

    async def _publish(self, data):
        await self._send(0x30, _str(self.mtopic) + data)
        return None
