"""Integration tests with ephemeral identities, local ICE and synthetic inventory only."""
import asyncio
import copy
import importlib.util
import json
from pathlib import Path
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rd import auth

HAS_RUNTIME = all(importlib.util.find_spec(name) for name in ("aiohttp", "aiortc", "av", "mss"))
if HAS_RUNTIME:
    from aiohttp.test_utils import make_mocked_request
    from aiortc import RTCConfiguration, RTCPeerConnection, RTCSessionDescription
    from rd import agent as agent_module, inventory, local_access, web
    from rd.agent import Agent
    from rd.common import NetKey
    from rd.network import Network


CALLER, HOST = "111111111", "222222222"
NID = "synthetic"


class MemoryRelay:
    """Carry the actual sealed signaling envelope between two in-memory networks."""

    def __init__(self, recipient):
        self.recipient = recipient
        self.name = "memory"

    async def publish(self, envelope):
        await self.recipient._on_event({"time": time.time(), "message": envelope})


class RegistryAcceptance(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        fields = {"network": "Demo", "users": {
            "first admin": {"pub": auth.pub_of(self.key), "admin": True},
            "second": {"pub": auth.pub_of(self.other), "admin": True}},
            "machines": {HOST: {"pub": auth.pub_of(Ed25519PrivateKey.generate())}}}
        self.genesis = auth.Registry().signed_update("first admin", self.key, lambda d: d.update(fields))

    def test_accepts_historical_minimal_records_and_duplicate_deliveries(self):
        root = auth.Registry.from_cache(self.genesis)
        child = root.signed_update("second", self.other, lambda d: d["machines"][HOST].update(name="PC"))
        joined = auth.trust_chain([child, self.genesis, child, self.genesis], auth.pub_of(self.key))
        self.assertEqual(joined.doc, child)
        self.assertEqual(joined.trusted_history, [self.genesis, child])
        self.assertEqual(root.rights("first admin", HOST), set(auth.LEGACY_RIGHTS))

    def test_rejects_signed_invalid_shapes_and_corrupt_cached_snapshots(self):
        for field, value in (("users", []), ("machines", {HOST: []}), ("v", True), ("prev", "x"),
                             ("users", {"first admin": {"admin": True, "pub": 0}})):
            with self.subTest(field=field, value=value):
                doc = copy.deepcopy(self.genesis)
                doc[field] = value
                doc["sig"] = auth.sign(self.key, auth.Registry.body(doc))
                self.assertIsNone(auth.Registry.from_cache(doc).doc)
                self.assertIsNone(auth.trust_chain([doc], auth.pub_of(self.key)))
        with self.assertRaises(ValueError):
            auth.Registry(self.genesis).signed_update("first admin", self.key, lambda d:
                d["users"]["second"].update(perms={HOST: {"inventory": True}}))

    def test_distinct_signed_siblings_require_resolution(self):
        root = auth.Registry(self.genesis)
        one = root.signed_update("first admin", self.key, lambda d: d["machines"][HOST].update(name="One"))
        two = root.signed_update("second", self.other, lambda d: d["machines"][HOST].update(name="Two"))
        for candidates in ([self.genesis, one, two], [two, self.genesis, one]):
            self.assertIsNone(auth.trust_chain(candidates, auth.pub_of(self.key)))
        renamed = root.signed_update("second", self.other, lambda d: d.update(network="different"))
        self.assertFalse(root.check_new(renamed))

    @unittest.skipUnless(HAS_RUNTIME, "runtime RemoteDesk richiesto")
    def test_live_fork_remains_blocked_when_network_is_reloaded(self):
        fixture = fixture_agent(HOST)
        fixture.registry_changed = Mock()
        fixture.save_networks = Mock()
        entry = {"nid": NID, "name": "Demo", "registry": self.genesis, "history": [self.genesis]}
        network = Network(fixture, entry)
        root = network.reg
        one = root.signed_update("first admin", self.key, lambda d: d["machines"][HOST].update(name="One"))
        two = root.signed_update("second", self.other, lambda d: d["machines"][HOST].update(name="Two"))
        self.assertTrue(network.on_registry(one))
        self.assertFalse(network.on_registry(one))
        self.assertFalse(network.conflict)
        self.assertFalse(network.on_registry(two))
        self.assertTrue(network.conflict)
        self.assertTrue(Network(fixture, copy.deepcopy(entry)).conflict)


class MemoryDatagrams:
    """Local synthetic UDP. aiortc still runs the ICE, DTLS and SCTP protocols."""

    def __init__(self, loop):
        self.loop = loop
        self.bound = {}
        self.port = 30000

    async def endpoint(self, protocol_factory, *, local_addr, **kwargs):
        if local_addr[0] != "127.0.0.1":
            raise AssertionError("non-loopback ICE candidate")
        address = (local_addr[0], self.port)
        self.port += 1
        protocol = protocol_factory()
        self.bound[address] = protocol
        socket_fixture = Mock()

        def sendto(data, remote):
            recipient = self.bound.get(remote)
            if recipient is not None:
                self.loop.call_soon(recipient.datagram_received, bytes(data), address)

        def close():
            if self.bound.pop(address, None) is not None:
                self.loop.call_soon(protocol.connection_lost, None)

        extra = {"socket": socket_fixture, "sockname": address}
        transport = SimpleNamespace(get_extra_info=extra.get, sendto=sendto, close=close)
        protocol.connection_made(transport)
        return transport, protocol


def fixture_agent(mid):
    # Keep real authentication, session and network methods. Bypass desktop startup.
    agent = Agent.__new__(Agent)
    agent.cfg = {"id": mid, "name": mid, "accept_incoming": True, "ask_confirm": False,
                 "allow_inventory": True, "allow_files": False, "allow_control": False,
                 "allow_clipboard": False, "stun": [], "turn_url": ""}
    agent.mkey = Ed25519PrivateKey.generate()
    agent.mpub = auth.pub_of(agent.mkey)
    agent.service_mode = False
    agent.nets = {}
    agent.logins = {}
    agent.leases = {}
    agent.local_token = auth.secrets.token_urlsafe(32)
    agent.sessions = {}
    agent.pending_approvals = {}
    agent._injector = None
    agent.active_prompts = 0
    agent.seen_sids = {}
    agent.block_owner = None
    agent.outgoing = {}
    agent.audit = Mock()
    agent.chat_system = Mock()
    agent.log_event = Mock()
    agent.injector = Mock(side_effect=AssertionError("inventory attempted desktop input"))
    return agent


@unittest.skipUnless(HAS_RUNTIME, "runtime RemoteDesk richiesto")
class ReleaseGate(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.caller, self.host = fixture_agent(CALLER), fixture_agent(HOST)
        self.user_key = Ed25519PrivateKey.generate()
        doc = {"v": 1, "machines": {CALLER: {"pub": self.caller.mpub},
                                    HOST: {"pub": self.host.mpub}},
               "users": {"tech": {"pub": auth.pub_of(self.user_key), "admin": False,
                                  "perms": {HOST: ["inventory"]}}}}
        admin_key = Ed25519PrivateKey.generate()
        doc["users"]["admin"] = {"pub": auth.pub_of(admin_key), "admin": True}
        doc = auth.Registry().signed_update("admin", admin_key, lambda snapshot: snapshot.update(doc))
        key = NetKey("synthetic", auth.new_network_key())
        for agent, other in ((self.caller, HOST), (self.host, CALLER)):
            network = Network(agent, {"nid": NID, "name": "synthetic", "registry": copy.deepcopy(doc)})
            agent.nets[NID] = network
            network.key = key
            network.machines[other] = {"session_protocol": auth.SESSION_PROTOCOL,
                                       "pub": doc["machines"][other]["pub"],
                                       "inventory": True, "last_seen": time.time()}
        self.outgoing = self.caller.nets[NID]
        self.incoming = self.host.nets[NID]
        self.outgoing.relays = [MemoryRelay(self.incoming)]
        self.incoming.relays = [MemoryRelay(self.outgoing)]

    async def post(self, path, params, token=None, native=True, origin="http://127.0.0.1:18080"):
        body = json.dumps(params).encode()
        headers = {"Host": "127.0.0.1:18080", "Origin": "http://127.0.0.1:18080",
                   "Content-Type": "application/json", "Content-Length": str(len(body))}
        headers["Origin"] = origin
        if token:
            headers["X-RD-Login"] = token
        if native:
            proof = local_access._make_proof(self.caller.local_token.encode(), "native",
                                             18080, "owner", "POST", path)
            headers["X-RemoteDesk-Proof"] = local_access._compact(proof)
        payload = Mock(readany=AsyncMock(side_effect=[body, b""]))
        req = make_mocked_request("POST", path, headers=headers, payload=payload)
        return await self.app._handle(req)

    def make_web(self):
        self.app = web.make_app(self.caller, 18080, lambda: None)
        self.app.freeze()

    async def test_http_inventory_ice_requires_current_operator_grant(self):
        self.make_web()
        params = {"nid": NID, "to": HOST, "mode": "manage"}
        path = "/api/session/ice"
        self.assertEqual((await self.post(path, params, native=False)).status, 403)
        self.assertEqual((await self.post(path, params)).status, 401)
        token = self.caller.add_login(None, NID, "tech", self.user_key)
        response = await self.post(path, params, token)
        self.assertEqual(response.status, 200)
        self.assertIn("ice", json.loads(response.body))
        self.outgoing.reg.user("tech").update(perms={}, admin=True)
        self.assertEqual((await self.post(path, params, token)).status, 403)
        self.outgoing.reg.user("tech")["perms"] = {HOST: ["inventory"]}
        self.outgoing.machines[HOST]["session_protocol"] = 1
        self.assertEqual((await self.post(path, params, token)).status, 409)
        self.outgoing.machines[HOST]["session_protocol"] = auth.SESSION_PROTOCOL
        self.outgoing.reg.user("tech")["pub"] = auth.pub_of(Ed25519PrivateKey.generate())
        self.assertEqual((await self.post(path, params, token)).status, 401)

    async def test_inventory_lease_cannot_access_clipboard_or_extend_login(self):
        self.make_web()
        self.caller.clipboard = Mock()
        self.caller.cfg["allow_clipboard"] = True
        token = self.caller.add_login(None, NID, "tech", self.user_key)
        grant = self.caller.get_login(token)[NID]
        before = grant["act"]
        lease = self.caller.issue_lease(self.outgoing, grant, HOST, "manage", "b" * 32)
        params = {"lease": lease}
        for path in ("/api/clip/read", "/api/clip"):
            response = await self.post(path, dict(params, text="sample"), token)
            self.assertEqual(response.status, 403)
        self.assertFalse(self.caller.clipboard.mock_calls)
        renewal = await self.post("/api/session/lease", params, token)
        self.assertEqual(renewal.status, 200)
        self.assertEqual(json.loads(renewal.body)["proof"]["sid"], "b" * 32)
        self.assertEqual(before, grant["act"])
        grant["act"] -= self.caller.IDLE + 1
        self.assertEqual((await self.post("/api/session/lease", params, token)).status, 403)

    async def test_signed_inventory_session_over_memory_datagrams(self):
        loop = asyncio.get_running_loop()
        datagrams = MemoryDatagrams(loop)
        self.enterContext(patch.object(loop, "create_datagram_endpoint", datagrams.endpoint))
        self.enterContext(patch("aioice.ice.get_host_addresses", return_value=["127.0.0.1"]))
        self.enterContext(patch.object(agent_module, "WIN", True))
        consent = Mock(return_value=True)
        self.enterContext(patch.object(agent_module, "W", SimpleNamespace(message_box=consent), create=True))
        self.enterContext(patch.object(inventory, "_dll", side_effect=AssertionError("native inventory")))
        self.enterContext(patch.object(agent_module, "ScreenTrack", side_effect=AssertionError("display")))
        self.enterContext(patch.object(agent_module, "SystemAudioTrack", side_effect=AssertionError("audio")))
        rows = [{"name": "Fixture service", "state": "running"}]
        collector = self.enterContext(patch.object(inventory, "read_section", return_value={
            "rows": rows, "partial": False, "note": ""}))
        controller = RTCPeerConnection(RTCConfiguration(iceServers=[]))
        self.addAsyncCleanup(controller.close)
        channel = controller.createDataChannel("inventory")
        opened = asyncio.Event()
        messages = asyncio.Queue()
        channel.on("open", opened.set)
        channel.on("message", messages.put_nowait)
        await controller.setLocalDescription(await controller.createOffer())
        self.make_web()
        token = self.caller.add_login(None, NID, "tech", self.user_key)
        response = await self.post("/api/connect", {"nid": NID, "to": HOST, "mode": "manage",
                                                   "sdp": controller.localDescription.sdp}, token)
        self.assertEqual(response.status, 200)
        answer = json.loads(response.body)
        self.assertNotIn("error", answer)
        self.assertEqual(len(self.host.sessions), 1)
        consent.assert_called_once()
        session = next(iter(self.host.sessions.values()))
        self.addAsyncCleanup(session.close)
        await controller.setRemoteDescription(RTCSessionDescription(sdp=answer["sdp"], type="answer"))
        await asyncio.wait_for(opened.wait(), 8)
        self.assertEqual(controller.getTransceivers(), [])
        self.assertEqual(session.pc.getTransceivers(), [])
        lease = await self.post("/api/session/lease", {"lease": answer["lease"]}, token)
        self.assertEqual(lease.status, 200)
        proof = json.loads(lease.body)["proof"]
        self.assertEqual(proof["sid"], session.rsid)
        self.assertFalse(session.lease_active())
        channel.send(json.dumps({"t": "inventory", "id": 0, "section": "apps"}))
        channel.send(json.dumps(proof))
        channel.send(json.dumps({"t": "inventory", "id": 1, "section": "services"}))
        response = json.loads(await asyncio.wait_for(messages.get(), 8))
        self.assertEqual(response["id"], 1)
        self.assertEqual(response["result"]["rows"], rows)
        self.assertFalse(response["more"])
        collector.assert_called_once_with("services")
        self.assertEqual(session.lease_issued, proof["iat"])
        deadline = session.lease_deadline
        session.renew(proof)
        self.assertEqual(session.lease_deadline, deadline)
        self.incoming.reg.user("tech")["perms"].clear()
        self.host.registry_changed(self.incoming)
        await asyncio.wait_for(self._wait_closed(channel), 8)
        self.assertFalse(self.host.sessions)

    @staticmethod
    async def _wait_closed(channel):
        if channel.readyState == "closed":
            return
        closed = asyncio.Event()
        channel.on("close", closed.set)
        await closed.wait()
