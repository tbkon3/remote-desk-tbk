import asyncio
import contextlib
import json
import ssl
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from aiohttp import ClientConnectorError, WSMsgType

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd.relays import (DEFAULT_SIGNAL, MAX_BODY, MAX_RELAYS, MqttRelay, NtfyRelay,
                       RelayError, _str, _varint, make_relay, parse_signal)


class RelaySecurity(unittest.IsolatedAsyncioTestCase):
    def test_endpoint_policy(self):
        for valid in ["https://relay.example/ntfy", "wss://relay.example", "mqtts://relay.example:8883",
                      "mqtt://127.0.0.1:1883", "http://[::1]:8080"]:
            with self.subTest(valid=valid):
                self.assertEqual(parse_signal(valid), [valid])
        for invalid in ["http://relay.example", "mqtt://192.0.2.1", "http://localhost", "https://user@relay",
                        "mqtts://relay:123456", "https://relay/../b", "wss://relay/%2e", "ws://relay",
                        "ftp://relay", "mqtts://relay/path"]:
            with self.subTest(invalid=invalid):
                self.assertEqual(parse_signal("https://valid.example," + invalid), [])
                with self.assertRaises(ValueError):
                    make_relay(invalid, "test")
        self.assertEqual(len(parse_signal(DEFAULT_SIGNAL)), 3)
        self.assertFalse(parse_signal(",".join(f"https://n{i}.example" for i in range(MAX_RELAYS + 1))))
        relay = make_relay("wss://ntfy.example/base", "abc")
        self.assertEqual(relay.http, "https://ntfy.example/base")
        with self.assertRaises(ValueError):
            make_relay("https://relay.example", "../other")

    async def test_chunk_bound_and_attachments(self):
        class Body:
            def __init__(self, chunks):
                self.chunks = chunks

            async def iter_chunked(self, size):
                for chunk in self.chunks:
                    yield chunk

        response = SimpleNamespace(content_length=None, content=Body([b"one", b"two"]))
        self.assertEqual(await NtfyRelay._read(response, 6), b"onetwo")
        with self.assertRaises(RelayError):
            await NtfyRelay._read(response, 5)
        relay = make_relay("wss://ntfy.example", "sample")
        for url in ["http://ntfy.example/file/id", "https://other.example/file/id",
                    "https://ntfy.example/file/../v1", "https://ntfy.example/file/x?q=token"]:
            self.assertIsNone(await relay._body({"attachment": {"url": url, "size": 1}}))
        with self.assertRaises(RelayError):
            await relay._redirect()
        with self.assertRaises(RelayError):
            await relay.publish("x" * (MAX_BODY + 1))

    async def test_mqtt_frame_limits_and_tls(self):
        stream = asyncio.StreamReader()
        stream.feed_data(b"\x30\x80\x80\x80\x80")
        with self.assertRaises(RelayError):
            await MqttRelay._read_packet(stream)
        stream = asyncio.StreamReader()
        stream.feed_data(b"\x30" + _varint(MAX_BODY + 2048))
        with self.assertRaises(RelayError):
            await MqttRelay._read_packet(stream)
        relay = make_relay("mqtts://mqtt.example:8883", "session")
        calls = []
        reader = asyncio.StreamReader()
        for header, payload in [(0x20, b"\x00\x00"), (0x90, b"\x00\x01\x00"),
                                (0x30, _str("rdesk/other") + b"ignored"),
                                (0x30, _str(relay.mtopic) + b"delivered")]:
            reader.feed_data(bytes([header]) + _varint(len(payload)) + payload)
        writer = SimpleNamespace(write=lambda _: None, drain=AsyncMock(), close=lambda: None, wait_closed=AsyncMock())

        async def observed(_, message, when):
            calls.append(message)
            raise asyncio.CancelledError

        with patch("rd.relays.asyncio.open_connection", AsyncMock(return_value=(reader, writer))) as conn:
            with self.assertRaises(asyncio.CancelledError):
                await relay.run(observed)
        kwargs = conn.await_args.kwargs
        self.assertEqual(kwargs["server_hostname"], "mqtt.example")
        self.assertTrue(kwargs["ssl"].check_hostname)
        self.assertEqual(kwargs["ssl"].verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(calls, ["delivered"])

    async def test_wss_endpoint_and_bounded_frames(self):
        relay = make_relay("wss://relay.example/base", "sample")
        settings = {}
        frame = SimpleNamespace(type=WSMsgType.TEXT, data='{"event":"open"}')
        close = SimpleNamespace(type=WSMsgType.CLOSE)
        @contextlib.asynccontextmanager
        async def ws_connect(url, **kwargs):
            settings.update(url=url, **kwargs)
            yield SimpleNamespace(receive=AsyncMock(side_effect=[frame, close]))
        messages = [m async for m in relay._events(SimpleNamespace(ws_connect=ws_connect), "10s")]
        self.assertEqual(messages, [frame.data])
        self.assertEqual(settings["url"], "wss://relay.example/base/sample/ws")
        self.assertGreater(settings["max_msg_size"], 0)
        self.assertEqual(settings["compress"], 0)


class RelayLoopback(unittest.IsolatedAsyncioTestCase):
    async def test_http_stream_publish_and_redirect(self):
        try:
            await asyncio.wait_for(self.exercise_loopback(), timeout=10)
        except ClientConnectorError as exc:
            if sys.platform == "win32" and (isinstance(exc.os_error, PermissionError)
                    or getattr(exc.os_error, "winerror", None) in (5, 10013)):
                self.skipTest("Windows ha negato la connessione al server di test su loopback")
            raise

    async def exercise_loopback(self):
        from aiohttp import ClientSession, web
        from aiohttp.test_utils import TestServer

        relayed = []
        redirects = []
        async def stream(_req):
            return web.Response(body=json.dumps({"event": "message", "message": "example"}).encode() + b"\n")

        async def publish(req):
            relayed.append(await req.text())
            return web.json_response({"time": 10})

        async def redirect(req):
            raise web.HTTPTemporaryRedirect(location="/other")

        async def other(req):
            redirects.append(req.path)
            return web.json_response({})

        app = web.Application()
        app.router.add_get("/sample/json", stream)
        app.router.add_post("/sample", publish)
        app.router.add_post("/redirect", redirect)
        app.router.add_route("*", "/other", other)
        async with TestServer(app, host="127.0.0.1") as host, ClientSession() as session:
            url = str(host.make_url("/")).rstrip("/")
            relay = make_relay(url, "sample")
            relay.session = session
            self.assertEqual(await relay.publish("test"), 10)
            self.assertEqual(relayed, ["test"])
            events = [json.loads(line) async for line in relay._events(session, "10s")]
            self.assertEqual(events[0]["message"], "example")
            moved = make_relay(url, "redirect")
            moved.session = session
            with self.assertRaises(RelayError):
                await moved.publish("test")
            self.assertEqual(redirects, [])


if __name__ == "__main__":
    unittest.main()
