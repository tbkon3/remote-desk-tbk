"""Server di segnalazione ("bacheche" pubbliche) usati in parallelo.

Ogni messaggio di una rete viene pubblicato su TUTTI i server configurati e ricevuto dal primo che
lo consegna (i doppioni vengono scartati). I messaggi sono gia' cifrati e firmati: i server vedono solo
dati illeggibili. Tipi supportati:
  https://ntfy.sh             ntfy (HTTP), con storico breve e limiti di messaggi per IP
  mqtts://broker.emqx.io:8883 MQTT 3.1.1 su TLS (client minimo integrato, QoS 0, nessuno storico)
"""
import asyncio
import json
import logging
import re
import secrets
import ssl
import struct
import time
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout

log = logging.getLogger("rd.relay")
DEFAULT_SIGNAL = "https://ntfy.sh, mqtts://broker.emqx.io:8883, mqtts://broker.hivemq.com:8883"
MAX_BODY = 4 * 1024 * 1024


def parse_signal(text):
    out = []
    for part in re.split(r"[\s,;]+", str(text or "")):
        part = part.strip().rstrip("/")
        if re.match(r"^(https?|mqtts?)://[^\s/]+", part) and part not in out:
            out.append(part)
    return out


def make_relay(url, topic):
    return MqttRelay(url, topic) if url.startswith("mqtt") else NtfyRelay(url, topic)


class RelayError(RuntimeError):
    pass


class Relay:
    def __init__(self, url, topic):
        self.url, self.topic = url, topic
        self.state = "connessione..."
        self.error = ""
        self.ok_since = 0

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
        self.session = None
        self.quota = None            # {"used", "limit"} se il server lo comunica
        self.quota_until = 0         # quota giornaliera esaurita: non insisto fino a quest'ora
        self.rate_until = 0          # troppe richieste ravvicinate: attendo

    async def run(self, on_msg):
        since = "900s"
        timeout = ClientTimeout(total=None, sock_connect=15, sock_read=150)   # keepalive ntfy ogni 45 s
        async with ClientSession(timeout=timeout, trust_env=True) as s:
            self.session = s
            asyncio.ensure_future(self._quota_loop())
            while True:
                try:
                    async with s.get(f"{self.url}/{self.topic}/json", params={"since": since}) as r:
                        if r.status == 429:
                            raise RelayError(await self._limit_error(r))
                        r.raise_for_status()
                        if self.state not in ("quota",):
                            self.state, self.error = "online", ""
                        async for line in r.content:
                            try:
                                ev = json.loads(line)
                            except ValueError:
                                continue
                            if not isinstance(ev, dict) or ev.get("event") != "message":
                                continue
                            since = ev.get("id", since)
                            body = await self._body(ev)
                            if body:
                                await on_msg(self, body, ev.get("time"))
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    if self.state != "quota":
                        self.state, self.error = "offline", str(e)[:200]
                    log.debug("ntfy %s: %s", self.name, e)
                await asyncio.sleep(10 if self.state != "quota" else 300)

    async def _body(self, ev):
        att = ev.get("attachment") or {}
        if not att.get("url"):
            return ev.get("message", "")
        url = str(att["url"])   # solo allegati del nostro server e di dimensione ragionevole
        if not url.startswith(self.url + "/file/") or int(att.get("size") or 0) > MAX_BODY:
            return None
        try:
            async with self.session.get(url, timeout=ClientTimeout(total=30)) as r:
                data = await r.content.read(MAX_BODY + 1)
            return None if len(data) > MAX_BODY else data.decode("utf-8", "replace")
        except Exception:
            return None

    async def _limit_error(self, r):
        try:
            d = await r.json(content_type=None)
            code, msg = d.get("code"), d.get("error", "")
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

    async def publish(self, blob):
        now = time.time()
        if now < self.quota_until:
            raise RelayError("quota giornaliera esaurita")
        if now < self.rate_until:
            await asyncio.sleep(min(self.rate_until - now, 30))
        if not self.session:
            raise RelayError("non connesso")
        async with self.session.post(f"{self.url}/{self.topic}", data=blob,
                                     timeout=ClientTimeout(total=30)) as r:
            if r.status == 429:
                raise RelayError(await self._limit_error(r))
            if r.status >= 300:
                raise RelayError(f"HTTP {r.status}")
            if self.state == "quota":
                self.state, self.error, self.quota_until = "online", "", 0
            try:
                return (await r.json(content_type=None)).get("time")
            except Exception:
                return None

    async def _quota_loop(self):
        while True:
            if self.session and self.state in ("online", "quota"):
                try:
                    async with self.session.get(f"{self.url}/v1/account", timeout=ClientTimeout(total=15)) as r:
                        if r.status == 200:
                            d = await r.json(content_type=None)
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
            await self.writer.drain()

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
                if head >> 4 != 2 or len(body) < 2 or body[1] != 0:
                    raise RelayError(f"connessione rifiutata dal broker ({body[1] if len(body) > 1 else '?'})")
                await self._send(0x82, struct.pack(">H", 1) + _str(self.mtopic) + bytes([0]))
                self.state, self.error, delay = "online", "", 5

                async def pinger():
                    while True:
                        await asyncio.sleep(self.KEEPALIVE / 2)
                        await self._send(0xC0, b"")
                ping = asyncio.ensure_future(pinger())
                while True:
                    head, body = await asyncio.wait_for(self._read_packet(reader), self.KEEPALIVE * 2)
                    if head >> 4 != 3:      # interessa solo PUBLISH (SUBACK/PINGRESP ignorati)
                        continue
                    qos = (head >> 1) & 3
                    tl = struct.unpack(">H", body[:2])[0]
                    off = 2 + tl + (2 if qos else 0)
                    try:
                        await on_msg(self, body[off:].decode("utf-8", "replace"), None)
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
                w, self.writer = self.writer, None
                if w:
                    try:
                        w.close()
                    except Exception:
                        pass
            await asyncio.sleep(delay)
            delay = min(delay * 2, 120)

    async def publish(self, blob):
        await self._send(0x30, _str(self.mtopic) + blob.encode())
        return None
