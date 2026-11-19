"""Authenticated session admission, live revocation and bounded inventory replies."""
import asyncio
import json
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd import agent, auth, inventory_channel as inv, session_policy
from rd.network import Network

HOST, PEER = "123456789", "234567890"
SDP = ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
       "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n"
       "a=mid:0\r\na=sctp-port:5000\r\na=setup:actpass\r\na=fingerprint:sha-256 " + ":".join(["12"] * 32) + "\r\n")


class SessionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.operator, self.peer, self.host = (auth.Ed25519PrivateKey.generate() for _ in range(3))
        self.a = object.__new__(agent.Agent)
        self.a.mpub = auth.pub_of(self.host)
        self.a.cfg = dict(id=HOST, name="test", ask_confirm=False, accept_incoming=True, allow_inventory=True,
                          allow_files=True, allow_control=True, allow_clipboard=True)
        self.a.sessions, self.a.pending_approvals = {}, {}
        self.a.leases = {}
        self.a.block_owner = None
        self.a.active_prompts = 0
        self.a._injector = None
        self.a.audit = Mock()
        self.a.service_mode = False
        self.reg = auth.Registry({"users": {"tech": {"admin": False, "name": "Tech", "pub": auth.pub_of(self.operator),
                                                      "perms": {HOST: ["control", "files", "inventory"]}}},
                                  "machines": {HOST: {"name": "Host", "pub": self.a.mpub},
                                               PEER: {"name": "Caller", "pub": auth.pub_of(self.peer)}}})
        self.net = SimpleNamespace(nid="network", reg=self.reg, conflict=False, pending={})
        self.a.nets = {"network": self.net}

    def offer(self, mode="manage"):
        m = dict(protocol=2, frm=PEER, to=HOST, mode=mode, sid="1" * 32, user="tech", uts=int(time.time()), sdp=SDP)
        body = auth.offer_body(self.net.nid, m)
        return dict(m, msig=auth.sign(self.peer, body), usig=auth.sign(self.operator, body))

    def test_offer_binds_mode_sdp_user_peer_destination_network_age(self):
        msg = self.offer()
        self.assertTrue(self.a.verified_offer(self.net, msg))
        for changes in ({"mode": "control"}, {"sdp": SDP + " "}, {"to": PEER}, {"user": "admin"}, {"usig": ""},
                        {"msig": ""}, {"frm": HOST}, {"protocol": 1}, {"sid": "2"*32}, {"uts": 0}, {"mode": []}):
            with self.subTest(changes=changes):
                self.assertFalse(self.a.verified_offer(self.net, dict(msg, **changes)))
        self.net.nid = "other"
        self.assertFalse(self.a.verified_offer(self.net, msg))

    def test_sdp_requires_fingerprint_and_restricts_media(self):
        session_policy.validate_sdp(SDP, "manage")
        video = "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=setup:actpass\r\na=fingerprint" + SDP.split("a=fingerprint")[1]
        with self.assertRaises(ValueError):
            session_policy.validate_sdp(SDP + video, "manage")
        for sdp in (SDP.replace("sha-256", "sha-1"), SDP.split("a=fingerprint")[0], SDP.replace("12:", "Z:")):
            with self.assertRaises(ValueError):
                session_policy.validate_sdp(sdp, "view")

    def test_per_mode_policy_never_expands_live_grants(self):
        caps = lambda mode: session_policy.capabilities(self.a.cfg, self.reg, "tech", mode, True)
        self.assertEqual(caps("view"), {"view"})
        self.assertEqual(caps("files"), {"files"})
        self.assertEqual(caps("manage"), {"inventory"})
        self.assertEqual(session_policy.permitted_channels("manage"), ("inventory",))
        s = agent.Session(self.a, self.net, self.offer("control"))
        self.reg.user("tech")["perms"][HOST].append("power")
        self.a.cfg["allow_power"] = True
        self.assertTrue(s.refresh_authorization())
        self.assertFalse(s.perms()["power"])
        self.a.cfg["allow_control"] = False
        self.assertFalse(s.refresh_authorization())
        self.a.cfg["allow_control"] = True
        self.assertFalse(s.refresh_authorization())

    async def test_inventory_always_prompts_and_requires_local_opt_in(self):
        with patch.object(agent, "WIN", True), patch.object(agent, "W", create=True) as windows:
            windows.message_box.return_value = False
            with self.assertRaisesRegex(RuntimeError, "rifiutato"):
                await self.a.accept_offer(self.net, self.offer())
            self.assertIn("inventario", windows.message_box.call_args.args[0])
            windows.message_box.reset_mock()
            self.a.cfg["allow_inventory"] = False
            with self.assertRaisesRegex(RuntimeError, "autorizzata"):
                await self.a.accept_offer(self.net, self.offer())
            windows.message_box.assert_not_called()
            self.assertFalse(self.a.sessions or self.a.pending_approvals)

    async def test_key_rotation_during_prompt_or_sdp_rejects(self):
        def revoke_and_restore():
            p = self.reg.machines()[PEER]
            original, p["pub"] = p["pub"], self.a.mpub
            self.a.registry_changed(self.net)
            p["pub"] = original
        loop = asyncio.get_running_loop()
        def prompt(*args):
            loop.call_soon_threadsafe(revoke_and_restore)
            return True
        with patch.object(agent, "WIN", True), patch.object(agent, "W", create=True) as windows:
            windows.message_box.side_effect = prompt
            with self.assertRaisesRegex(RuntimeError, "revocata"):
                await self.a.accept_offer(self.net, self.offer())
            async def negotiate(session, sdp):
                revoke_and_restore()
                return sdp
            with patch.object(agent.Session, "start", negotiate), self.assertRaisesRegex(RuntimeError, "revocata"):
                await self.a.accept_offer(self.net, self.offer("view"))
        self.assertFalse(self.a.sessions or self.a.pending_approvals)

    async def test_outgoing_waiter_invalidated_by_registry_change(self):
        fut = asyncio.get_running_loop().create_future()
        self.net.pending["id"] = (fut, PEER, "view", auth.pub_of(self.peer), "tech", auth.pub_of(self.operator))
        self.reg.user("tech")["perms"][PEER] = ["view"]
        self.reg.machines().pop(PEER)
        self.a.registry_changed(self.net)
        with self.assertRaisesRegex(RuntimeError, "revocata"):
            await fut

    def test_remote_update_requires_auto_opt_in_and_both_signatures(self):
        self.net.cfg, self.net.agent = self.a.cfg, self.a
        self.a.cfg["auto_update"] = True
        self.reg.user("tech")["admin"] = True
        body = dict(frm=PEER, to=HOST, user="tech", ats=int(time.time()), cmd="update", rid="0"*24,
                    net=self.net.nid, protocol=2)
        msg = dict(body, sig=auth.sign(self.operator, body), msig=auth.sign(self.peer, body))
        self.assertTrue(Network._verified_update(self.net, msg))
        for changes in ({"ats": 0}, {"protocol": 1}, {"msig": ""}, {"net": "other"}):
            self.assertFalse(Network._verified_update(self.net, dict(msg, **changes)))
        self.a.cfg["auto_update"] = False
        self.assertFalse(Network._verified_update(self.net, msg))

    def test_network_audit_requires_fresh_double_signature_for_this_network(self):
        self.reg.user("tech")["admin"] = True
        body = dict(type="auditreq", protocol=2, net=self.net.nid, frm=PEER, to="*", user="tech", ats=int(time.time()),
                    rid="a"*24, since=0, until=0, epub=auth.pub_of(self.peer))
        msg = dict(body, msig=auth.sign(self.peer, body), sig=auth.sign(self.operator, body))
        self.assertTrue(self.a.verified_audit_request(self.net, msg))
        for changes in ({"msig": ""}, {"sig": ""}, {"ats": 0}, {"net": "other"}, {"epub": auth.pub_of(self.host)}):
            self.assertFalse(self.a.verified_audit_request(self.net, dict(msg, **changes)))
        self.net.conflict = True
        self.assertFalse(self.a.verified_audit_request(self.net, msg))

    async def test_consent_dialog_runs_only_after_input_barrier(self):
        s = agent.Session(self.a, self.net, self.offer("manage"))
        self.a.pending_approvals[s.sid] = s
        records = []
        self.a._injector = Mock()
        self.a._injector.pause_and_drain.side_effect = lambda: records.append("drain")
        self.a._injector.resume.side_effect = lambda: records.append("resume")
        def consent(*args):
            records.append("prompt")
            self.assertGreater(self.a.active_prompts, 0)
            return True
        with patch.object(agent, "W", create=True) as win:
            win.message_box.side_effect = consent
            self.assertTrue(await self.a.request_consent(s, "permission"))
        self.assertEqual(records, ["drain", "prompt", "resume"])
        self.assertEqual(self.a.active_prompts, 0)

    async def test_live_lease_requires_both_keys_and_expires_even_on_replay(self):
        s = agent.Session(self.a, self.net, self.offer("files"))
        s.set_lease_deadline(time.monotonic() + 60)
        self.a.sessions[s.sid] = s
        self.assertFalse(s.perms()["files"])
        issued = int(time.time())
        body = auth.renewal_body(self.net.nid, PEER, HOST, s.rsid, "files", "tech", issued)
        proof = dict(body, msig=auth.sign(self.peer, body), usig=auth.sign(self.operator, body))
        for changes in ({"usig": ""}, {"msig": ""}, {"sid": "2"*32}, {"iat": issued + 3600}, {"mode": "control"}):
            s.renew(dict(proof, **changes))
            self.assertFalse(s.perms()["files"])
        s.renew(proof)
        self.assertTrue(s.perms()["files"])
        self.assertFalse(s.perms()["files_write"] or s.perms()["files_delete"])
        deadline = s.lease_deadline
        s.renew(proof)
        self.assertEqual(deadline, s.lease_deadline)
        s.set_lease_deadline(time.monotonic())
        s.renew(proof)
        self.assertFalse(s.perms()["files"])
        await s.close(notify=False)

    def test_pages_stay_within_frame_and_total_limits(self):
        result = dict(partial=False, note="", rows=[{"name": "🎬"*200}]*1600)
        frames = list(inv.pages("apps", 1, result))
        self.assertGreater(len(frames), 1)
        self.assertLess(max(map(len, frames)), 16384)
        self.assertLessEqual(sum(map(len, frames)), inv.TOTAL_LIMIT)
        self.assertTrue(all(json.loads(p)["more"] for p in frames[:-1]))
        self.assertFalse(json.loads(frames[-1])["more"])
        self.assertTrue(json.loads(frames[-1])["result"]["partial"])

    async def test_inventory_rechecks_identity_before_delivery(self):
        s = agent.Session(self.a, self.net, self.offer())
        self.a.sessions[s.sid] = s
        self.a.service_mode = True
        s.windows_logon = (2, b"A")
        ch = Mock(readyState="open", bufferedAmount=0)
        with patch.object(agent, "WIN", True):
            s.rights = {"inventory"}
            s.lease_issued = int(time.time())
            s.lease_deadline = time.monotonic() + 50
            ic = inv.InventoryChannel(s, ch)
            with patch("rd.win_identity.effective_logon", return_value=(2, b"A")), \
                    patch.object(inv, "interactive_logon", side_effect=[(2, b"A"), (2, b"B")]), \
                    patch.object(inv, "collect", return_value=dict(rows=[{"name": "secret"}], partial=False, note="")):
                await ic.serve(1, "shares")
            self.assertFalse(any("secret" in call.args[0] for call in ch.send.call_args_list))
            self.assertNotIn(s.sid, self.a.sessions)


if __name__ == "__main__":
    unittest.main()
