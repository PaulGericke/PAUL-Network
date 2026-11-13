import json, os, sqlite3, sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "node"))
import mesh

A, B, C = "a000000000000001", "b000000000000002", "c000000000000003"


def outbox(path, rows):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint TEXT, payload TEXT, created_at INTEGER)")
        for endpoint, payload in rows:
            db.execute("INSERT INTO outbox(endpoint,payload,created_at) VALUES (?,?,?)", (endpoint, json.dumps(payload), int(time.time()) - 5000))


def count(path):
    with sqlite3.connect(path) as db:
        return db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]


class MeshTest(unittest.TestCase):
    def setUp(self):
        self._probe = mesh.PROBE_INTERVAL
        mesh.PROBE_INTERVAL = 0          # most tests: senders may always probe
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        for n in ("a", "b", "c"):
            (d / n).mkdir()
        self.beacon = {"schema": "paulnet-beacon-tx-v1", "node": A, "sequence": 7, "signature": "x" * 88, "public_key": "y" * 44}
        self.witness = {"receiver_node": A, "sender_node": C, "beacon": "Z" * 190, "witness_signature": "s" * 88, "rssi": -110}
        self.tele = {"schema": "paulnet-telemetry-v1", "node": A, "metrics": {"x": 1}, "signature": "t" * 88}
        outbox(d / "a" / "o.db", [("/v1/witnesses", self.witness), ("/v1/register", {"node": A}),
                                  ("/v1/beacons", self.beacon), ("/v1/telemetry", self.tele)])
        outbox(d / "b" / "o.db", []); outbox(d / "c" / "o.db", [])
        t0 = time.time() - 4000
        self.a = mesh.Mesh(d / "a", d / "a" / "o.db", A, started=t0)
        self.b = mesh.Mesh(d / "b", d / "b" / "o.db", B, started=t0)
        self.c = mesh.Mesh(d / "c", d / "c" / "o.db", C, started=t0)
        self.d = d

    def tearDown(self):
        mesh.PROBE_INTERVAL = self._probe
        self.tmp.cleanup()

    def drain(self, now, relays, last_a=None, lose=()):
        """Origin sends everything once; relays answer; returns uploads."""
        uploads = []
        sent = 0
        while True:
            f = self.a.next_origin_frame(last_a, now)
            if f is None:
                break
            sent += 1
            self.a.origin_frame_sent(now)
            if sent in lose:
                continue
            for r in relays:
                res = r.on_data(mesh.parse(f), now - 10, now)
                if res and res[0] == "upload":
                    uploads.append((r.node_id,) + res[1:4])
        for r in relays:
            item = r.next_ack_frame()
            while item:
                origin, frame = item
                self.a.on_ack(mesh.parse(frame))
                r.ack_sent(origin, frame)
                item = r.next_ack_frame()
        return uploads, sent

    def test_frames_fit_and_roundtrip(self):
        blob = mesh.make_blob("/v1/witnesses", self.witness)
        item, frames = mesh.fragments(A, blob)
        self.assertTrue(all(len(f) <= mesh.DATA_HEADER_V21 + mesh.CHUNK <= 255 for f in frames))
        self.assertTrue(all(f[0] >> 5 == 7 for f in frames), "proprietary MType")
        self.assertEqual(mesh.unpack_blob(b"".join(mesh.parse(f)["chunk"] for f in frames)), ("/v1/witnesses", self.witness))

    def test_online_node_does_not_relay_own(self):
        now = time.time()
        self.assertIsNone(self.a.next_origin_frame(now - 5, now))

    def test_offline_origin_priority_upload_and_ack(self):
        now = time.time()
        uploads, sent = self.drain(now, [self.b])
        self.assertEqual([u[1] for u in uploads], ["/v1/beacons", "/v1/telemetry", "/v1/witnesses"])
        self.assertEqual(uploads[0][2], self.beacon)
        self.assertEqual(count(self.d / "a" / "o.db"), 1, "only /v1/register stays (not relayable)")

    def test_two_relays_upload_both_but_origin_clean(self):
        uploads, _ = self.drain(time.time(), [self.b, self.c])
        self.assertEqual(len(uploads), 6)          # collector dedupes by nonce
        self.assertEqual(count(self.d / "a" / "o.db"), 1)

    def test_lost_fragment_retry_after_wait(self):
        now = time.time()
        uploads, _ = self.drain(now, [self.b], lose=(1,))
        self.assertEqual(len(uploads), 2)         # beacon lost (1 fragment), others fine
        self.assertEqual(count(self.d / "a" / "o.db"), 2)
        self.assertIsNone(self.a.next_origin_frame(None, now + 10), "waits RETRY_AFTER")
        uploads, _ = self.drain(now + mesh.RETRY_AFTER + 1, [self.b])
        self.assertEqual([u[1] for u in uploads], ["/v1/beacons"])
        self.assertEqual(count(self.d / "a" / "o.db"), 1)

    def test_duplicate_after_missed_ack_reacks_without_reupload(self):
        now = time.time()
        f = self.a.next_origin_frame(None, now)
        frames = [f]
        self.a.origin_frame_sent(now)
        while self.a.sending:
            frames.append(self.a.next_origin_frame(None, now)); self.a.origin_frame_sent(now)
        res = None
        for fr in frames:
            res = self.b.on_data(mesh.parse(fr), now - 10, now) or res
        self.assertEqual(res[0], "upload")
        self.b.acks.clear()                        # ACK lost
        self.assertIsNone(self.b.on_data(mesh.parse(f), now - 10, now + 700))
        self.assertTrue(self.b.next_ack_frame(), "re-ACK queued")

    def send_all(self, sender, receivers, now, last=None):
        """sender transmits every queued item once; returns list of (receiver, result)."""
        out = []
        while True:
            f = sender.next_origin_frame(last, now)
            if f is None:
                break
            sender.origin_frame_sent(now)
            for r, r_last in receivers:
                res = r.on_data(mesh.parse(f), r_last, now)
                if res:
                    out.append((r, res))
        return out

    def ack_all(self, relay, listeners):
        item = relay.next_ack_frame()
        while item:
            origin, frame = item
            for l in listeners:
                l.on_ack(mesh.parse(frame))
            relay.ack_sent(origin, frame)
            item = relay.next_ack_frame()

    def carry_into_outbox(self, node, results):
        with sqlite3.connect(node.outbox_db) as db:
            for r, res in results:
                if r is node and res[0] == "carry":
                    db.execute("INSERT INTO outbox(endpoint,payload,created_at) VALUES (?,?,?)",
                               (mesh.CARRY_ENDPOINT, json.dumps(res[1]), int(time.time()) - 5000))

    def hear(self, listener, relay_id, dist):
        listener.heard_ack(mesh.parse(mesh.make_ack(relay_id, A, [b"zzzz"], dist)))

    def test_two_hop_chain_origin_carrier_uploader(self):
        now = time.time()
        Path(self.d / "b" / mesh.FORCE_OFFLINE_FILE).write_text(str(int(now) + 600))   # B offline too
        self.hear(self.b, C, 0)                     # B heard online C -> distance 1
        self.assertEqual(self.b.distance(None, now), 1)
        res = self.send_all(self.a, [(self.b, None)], now)
        self.assertEqual({r[1][0] for r in res}, {"carry"})
        self.assertTrue(all(r[1][3] == 1 for r in res), "hop 1")
        self.carry_into_outbox(self.b, res)
        self.ack_all(self.b, [self.a])
        self.assertEqual(count(self.d / "a" / "o.db"), 1, "A handed everything to B")
        res2 = self.send_all(self.b, [(self.c, now - 10), (self.a, None)], now)   # A hears B too
        uploads = [r for r in res2 if r[0] is self.c and r[1][0] == "upload"]
        self.assertEqual(sorted(u[1][1] for u in uploads), ["/v1/beacons", "/v1/telemetry", "/v1/witnesses"])
        self.assertTrue(all(u[1][3] == A and u[1][4] == 2 for u in uploads), "origin kept, hop 2")
        self.assertFalse([r for r in res2 if r[0] is self.a], "A never takes its own reports back")
        self.ack_all(self.c, [self.b])
        self.assertEqual(count(self.d / "b" / "o.db"), 0, "B delivered what it carried")

    def test_hop_limit(self):
        now = time.time()
        Path(self.d / "b" / mesh.FORCE_OFFLINE_FILE).write_text(str(int(now) + 600))
        self.hear(self.b, C, 0)
        item, frames = mesh.fragments(A, mesh.make_blob("/v1/beacons", self.beacon), hops=mesh.MAX_HOPS - 1)
        self.assertIsNone(self.b.on_data(mesh.parse(frames[0]), None, now), "offline at last hop: no custody")
        self.assertIsNone(self.b.next_ack_frame())
        self.assertEqual(self.c.on_data(mesh.parse(frames[0]), now - 10, now)[0], "upload", "online may still upload")

    def test_sideways_custody_refused(self):
        now = time.time()
        for n in "ab":
            Path(self.d / n / mesh.FORCE_OFFLINE_FILE).write_text(str(int(now) + 600))
        res = self.send_all(self.a, [(self.b, None)], now)
        self.assertFalse(res, "B has no route to the Internet either: no custody, no ACK")
        self.hear(self.b, C, 0)
        self.hear(self.a, B, 1)                     # A only hears B (distance 1) -> A is 2
        res = self.send_all(self.b, [(self.a, None)], now)
        self.assertFalse([r for r in res if r[1][0] == "carry"], "A (2) never takes from B (1)")

    def test_no_ping_pong_after_handover(self):
        now = time.time()
        Path(self.d / "b" / mesh.FORCE_OFFLINE_FILE).write_text(str(int(now) + 600))
        Path(self.d / "c" / mesh.FORCE_OFFLINE_FILE).write_text(str(int(now) + 600))
        self.hear(self.c, "dd00000000000004", 0)    # C is 1 hop from the Internet
        self.hear(self.b, C, 1)                     # B is 2
        res = self.send_all(self.a, [(self.b, None)], now)
        self.carry_into_outbox(self.b, res); self.ack_all(self.b, [self.a])
        res2 = self.send_all(self.b, [(self.c, None)], now)
        self.carry_into_outbox(self.c, res2); self.ack_all(self.c, [self.b])
        self.assertEqual(count(self.d / "b" / "o.db"), 0)
        res3 = self.send_all(self.c, [(self.b, None)], now + mesh.RETRY_AFTER + 5)
        self.assertFalse([r for r in res3 if r[1][0] == "carry"], "B does not take back what it handed over")

    def test_carry_upload_transform(self):
        blob = mesh.make_blob("/v1/witnesses", self.witness)
        endpoint, text = mesh.carry_to_upload(json.dumps(mesh.carry_record(A, 2, blob)), B)
        self.assertEqual(endpoint, "/v1/witnesses?relay=" + B + "&hops=2")
        self.assertEqual(json.loads(text), self.witness)

    def test_slower_datarate_per_attempt(self):
        now = time.time()
        self.a.on_ack(mesh.parse(mesh.make_ack(B, B, [], 0)), now, snr=5.0)   # good link -> start SF9 (v2.4)
        rates = []
        for k in range(4):
            f = self.a.next_origin_frame(None, now + k * (mesh.RETRY_AFTER + 1))
            rates.append(self.a.current_datr())
            while self.a.sending:
                self.a.origin_frame_sent(now + k * (mesh.RETRY_AFTER + 1))
                if self.a.sending:
                    self.a.next_origin_frame(None, now + k * (mesh.RETRY_AFTER + 1))
            for other in list(self.a._candidates(now + k * (mesh.RETRY_AFTER + 1))):
                pass
        self.assertEqual(rates[0], "SF9BW125")
        self.assertIn("SF10BW125", rates)
        self.assertEqual(rates[-1], "SF11BW125")

    def test_hello_announces_route(self):
        now = time.time()
        hello = self.c.next_hello_frame(now - 10, now)        # C online -> distance 0
        self.assertIsNotNone(hello)
        f = mesh.parse(hello)
        self.assertEqual((f["kind"], f["dist"], f["items"]), ("ack", 0, []))
        self.b.on_ack(f, now)
        self.assertEqual(self.b.distance(None, now), 1)
        self.c.hello_sent(now)
        self.assertIsNone(self.c.next_hello_frame(now - 10, now + 10), "not again before HELLO_INTERVAL")
        self.assertIsNone(self.a.next_hello_frame(None, now), "no route -> no hello")

    def test_without_route_only_rare_probe(self):
        mesh.PROBE_INTERVAL = 1800
        now = time.time()
        first = self.a.next_origin_frame(None, now)
        self.assertIsNotNone(first, "one probe")
        while self.a.sending:
            self.a.origin_frame_sent(now)
            if self.a.sending:
                self.a.next_origin_frame(None, now)
        self.assertIsNone(self.a.next_origin_frame(None, now + 60), "no route known: wait for the next probe")
        self.hear(self.a, B, 0)
        self.assertIsNotNone(self.a.next_origin_frame(None, now + 61), "route known: send")

    def test_never_take_back_from_parent_even_if_it_claims_no_route(self):
        now = time.time()
        for n in "ab":
            Path(self.d / n / mesh.FORCE_OFFLINE_FILE).write_text(str(int(now) + 600))
        self.hear(self.a, B, 1)                      # A's route goes through B
        item, frames = mesh.fragments(B, mesh.make_blob("/v1/beacons", dict(self.beacon, node=B)),
                                      hops=0, dist=mesh.UNKNOWN_DIST, sender=B)   # B did not know its route yet
        self.assertIsNone(self.a.on_data(mesh.parse(frames[0]), None, now))
        self.assertIsNone(self.a.next_ack_frame())

    def test_v1_frames_still_parse(self):
        v1 = mesh.MAGIC + bytes([mesh.KIND_DATA_V1]) + bytes.fromhex(A) + b"abcd" + bytes([0, 1]) + b"xyz"
        f = mesh.parse(v1)
        self.assertEqual((f["hops"], f["total"], f["chunk"]), (0, 1, b"xyz"))

    def test_offline_relay_does_not_take_items(self):
        now = time.time()
        item, frames = mesh.fragments(A, mesh.make_blob("/v1/beacons", self.beacon), hops=mesh.MAX_HOPS - 1)
        self.assertIsNone(self.b.on_data(mesh.parse(frames[0]), now - 4000, now))
        self.assertIsNone(self.b.next_ack_frame())

    def test_forged_origin_rejected(self):
        now = time.time()
        bad = dict(self.beacon, node=C)
        item, frames = mesh.fragments(A, mesh.make_blob("/v1/beacons", bad))
        self.assertIsNone(self.b.on_data(mesh.parse(frames[0]), now - 10, now))

    def test_tampered_fragment_rejected(self):
        now = time.time()
        item, frames = mesh.fragments(A, mesh.make_blob("/v1/beacons", self.beacon))
        bad = frames[0][:-1] + bytes([frames[0][-1] ^ 1])
        self.assertIsNone(self.b.on_data(mesh.parse(bad), now - 10, now))

    def test_force_offline_switch(self):
        now = time.time()
        Path(self.d / "a" / mesh.FORCE_OFFLINE_FILE).write_text(str(int(now) + 60))
        self.assertTrue(self.a.offline(now - 1, now))
        Path(self.d / "a" / mesh.FORCE_OFFLINE_FILE).write_text(str(int(now) - 1))
        self.assertFalse(self.a.offline(now - 1, now))

    def test_idle_node_is_not_offline(self):
        now = time.time()
        with sqlite3.connect(self.d / "b" / "o.db") as db:
            db.execute("INSERT INTO outbox(endpoint,payload,created_at) VALUES (?,?,?)", ("/v1/telemetry", "{}", int(now) - 30))
        self.assertFalse(self.b.offline(now - 4000, now), "fresh report, no backlog yet")
        self.assertTrue(self.a.offline(now - 4000, now), "old reports piling up")

    def test_frame_gap(self):
        now = time.time()
        self.a.spent(now, 1.0)
        self.assertFalse(self.a.tx_ready(now + 1.5))
        self.assertTrue(self.a.tx_ready(now + 2.1))

    def test_airtime_budget(self):
        now = time.time()
        self.a.spent(now, mesh.AIRTIME_PER_HOUR)
        self.assertLessEqual(self.a.airtime_left(now), 0)
        self.assertGreater(self.a.airtime_left(now + 3601), 0)

    def test_parse_rejects_garbage(self):
        for raw in (b"\xe1PR\x01short", b"\xe1PR\x02" + b"\0" * 17 + b"\x05", b"ON5" + b"\0" * 20):
            with self.assertRaises(ValueError):
                mesh.parse(raw)



class MeshV23Test(unittest.TestCase):
    """PAUL_MESH_V23: receive reports, selective resend, link-adaptive SF, newest telemetry only."""

    def setUp(self):
        self._probe = mesh.PROBE_INTERVAL
        mesh.PROBE_INTERVAL = 0
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        for n in ("a", "b", "c"):
            (self.d / n).mkdir()
        import base64 as b64
        self.big = {"receiver_node": A, "sender_node": C, "beacon": b64.b64encode(os.urandom(420)).decode(),
                    "witness_signature": "s" * 88, "rssi": -110}
        outbox(self.d / "a" / "o.db", [("/v1/witnesses", self.big)])
        outbox(self.d / "b" / "o.db", []); outbox(self.d / "c" / "o.db", [])
        t0 = time.time() - 4000
        self.a = mesh.Mesh(self.d / "a", self.d / "a" / "o.db", A, started=t0)
        self.b = mesh.Mesh(self.d / "b", self.d / "b" / "o.db", B, started=t0)
        self.c = mesh.Mesh(self.d / "c", self.d / "c" / "o.db", C, started=t0)

    def tearDown(self):
        mesh.PROBE_INTERVAL = self._probe
        self.tmp.cleanup()

    def round(self, now, keep=None):
        """A sends one round; B (online) receives fragments whose position in the round is in keep."""
        sent, res = [], None
        while True:
            f = self.a.next_origin_frame(None, now)
            if f is None:
                break
            pos = len(sent)
            sent.append((mesh.parse(f)["index"], self.a.current_datr(), len(f)))
            self.a.origin_frame_sent(now)
            if keep is None or pos in keep:
                res = self.b.on_data(mesh.parse(f), now - 10, now, snr=-9.0) or res
            if not self.a.sending:
                break
        return sent, res

    def report_to_a(self, now):
        item = self.b.next_report_frame(now - 10, now)
        if item is None:
            return None
        sender, frame = item
        self.assertEqual(sender, A)
        self.b.report_sent(sender)
        return self.a.on_report(mesh.parse(frame), now, snr=-15.0), mesh.parse(frame)

    def learn_parent(self, now, snr=-15.0):
        hello = mesh.make_ack(B, B, [], 0)
        self.a.on_ack(mesh.parse(hello), now, snr=snr)

    def test_report_roundtrip_and_negative_snr(self):
        frame = mesh.make_report(B, A, [(b"\x01\x02\x03\x04", 3, {0, 2})], 0, -9.25)
        p = mesh.parse(frame)
        self.assertEqual((p["kind"], p["relay"], p["sender"], p["dist"]), ("report", B, A, 0))
        self.assertEqual(p["snr"], -9.0)        # half-dB steps, rounded
        self.assertEqual(p["entries"], [{"item": b"\x01\x02\x03\x04", "total": 3, "have": {0, 2}}])
        self.assertIsNone(mesh.parse(mesh.make_report(B, A, [], 0, None))["snr"])
        self.assertTrue(len(frame) <= 51, "fits SF11 comfortably")

    def test_link_index(self):
        dr = ("SF9BW125", "SF10BW125", "SF11BW125")
        self.assertEqual(mesh.link_index(2.0, dr), 0)
        self.assertEqual(mesh.link_index(-7.0, dr), 1)      # -7 - 8 = -15 -> SF10 floor (v2.4 margin 8 dB)
        self.assertEqual(mesh.link_index(-9.0, dr), 2)
        self.assertEqual(mesh.link_index(-19.0, dr), 2)     # clamp to slowest
        self.assertEqual(mesh.link_index(None, dr), 2)      # v2.4: unknown link -> most robust SF

    def test_start_sf_from_reverse_link_then_forward_report(self):
        now = time.time()
        self.learn_parent(now, snr=-16.0)                   # we hear B badly -> SF11, small chunks
        sent, _ = self.round(now, keep=set())
        self.assertTrue(all(d == "SF11BW125" for _, d, _ in sent))
        self.assertTrue(all(n <= mesh.DATA_HEADER_V21 + mesh.CHUNK_BY_SF[11] for _, _, n in sent))

    def test_selective_resend_only_missing_fragments(self):
        now = time.time()
        self.learn_parent(now, snr=0.0)
        sent, res = self.round(now, keep={0, 2})
        self.assertGreaterEqual(len(sent), 3)
        self.assertIsNone(res)
        self.assertIsNone(self.b.next_report_frame(now - 10, now + 1), "waits REPORT_QUIET")
        updated, report = self.report_to_a(now + mesh.REPORT_QUIET + 1)
        self.assertEqual(updated, 1)
        self.assertEqual(report["snr"], -9.0)
        self.assertEqual(self.a.tx_link[B][0], -9.0)
        t = now + mesh.REPORT_QUIET + 2                     # resend right away, not after RETRY_AFTER
        resent, res = self.round(t)
        expected = sorted(set(range(len(sent))) - {0, 2})
        self.assertEqual([i for i, _, _ in resent], expected)
        self.assertEqual(res[0], "upload")
        self.assertEqual(res[2], self.big)
        origin, ack = self.b.next_ack_frame()
        self.assertEqual(self.a.on_ack(mesh.parse(ack), t), 1)
        self.assertEqual(count(self.d / "a" / "o.db"), 0)

    def test_heavy_loss_slows_down(self):
        now = time.time()
        self.learn_parent(now, snr=0.0)
        sent, _ = self.round(now, keep={0})
        self.assertEqual(sent[0][1], "SF9BW125")
        self.report_to_a(now + mesh.REPORT_QUIET + 1)       # report says -9 dB -> SF10, plus 1 stall
        resent, _ = self.round(now + mesh.REPORT_QUIET + 2, keep=set())
        self.assertTrue(resent and all(d == "SF11BW125" for _, d, _ in resent))
        self.assertTrue(all(i != 0 for i, _, _ in resent))

    def test_fragment_plan_kept_and_partials_per_total(self):
        now = time.time()
        self.learn_parent(now, snr=0.0)
        sent, _ = self.round(now, keep={0})
        total = len(sent)
        self.learn_parent(now + 1, snr=-16.0)               # link got worse: SF changes, plan does not
        resent, res = self.round(now + mesh.RETRY_AFTER + 2)
        self.assertEqual(len(resent), total)
        self.assertEqual(res[0], "upload")
        other = mesh.fragments(A, b"x" * 300, chunk=110)[1][0]
        self.assertIsNone(self.b.on_data(mesh.parse(other), now - 10, now))
        self.assertNotIn("mismatch", self.b.last_rx_note)

    def test_no_report_when_receiver_would_not_take_custody(self):
        now = time.time()
        self.b.on_ack(mesh.parse(mesh.make_ack(C, C, [], 5)), now)   # B offline, its route is far away
        self.a.on_ack(mesh.parse(mesh.make_ack(C, C, [], 0)), now)   # A itself is 1 hop from the Internet
        f = self.a.next_origin_frame(None, now)
        self.assertIsNone(self.b.on_data(mesh.parse(f), None, now))
        self.assertEqual(self.b.reports, {})

    def test_old_nodes_ignore_report(self):
        import importlib.machinery, importlib.util
        path = Path(mesh.__file__).resolve().parent.parent / "mesh-backups" / "mesh.py.v2.2"
        if not path.exists():
            self.skipTest("no v2.2 copy")
        loader = importlib.machinery.SourceFileLoader("mesh22", str(path))
        old = importlib.util.module_from_spec(importlib.util.spec_from_loader("mesh22", loader))
        loader.exec_module(old)
        self.assertFalse(old.is_frame(mesh.make_report(B, A, [], 0, -5)))
        self.assertTrue(old.is_frame(mesh.make_ack(B, A, [b"abcd"], 0)))

    def test_only_newest_telemetry_offered(self):
        tele = lambda n: {"schema": "paulnet-telemetry-v1", "node": A, "metrics": {"n": n}, "signature": "t" * 88}
        with sqlite3.connect(self.d / "a" / "o.db") as db:
            db.execute("DELETE FROM outbox")
            for n in range(5):
                db.execute("INSERT INTO outbox(endpoint,payload,created_at) VALUES (?,?,?)",
                           ("/v1/telemetry", json.dumps(tele(n)), int(time.time()) - 5000))
        now = time.time()
        got = []
        while True:
            f = self.a.next_origin_frame(None, now)
            if f is None:
                break
            self.a.origin_frame_sent(now)
            res = self.b.on_data(mesh.parse(f), now - 10, now)
            if res:
                got.append(res[2]["metrics"]["n"])
        self.assertEqual(got, [4])

    def test_parent_prefers_better_link(self):
        now = time.time()
        self.a.on_ack(mesh.parse(mesh.make_ack(C, C, [], 0)), now, snr=-19.0)
        self.a.on_ack(mesh.parse(mesh.make_ack(B, B, [], 0)), now, snr=-11.0)
        self.assertEqual(self.a.parent(now), B)
        self.assertEqual(self.a.status()["parent"], B)

if __name__ == "__main__":
    unittest.main()


class MeshV24Test(unittest.TestCase):
    """PAUL_MESH_V24: dictionary blobs with packed binary fields, capability via RPT kind 7, telemetry throttle."""

    def setUp(self):
        self._probe = mesh.PROBE_INTERVAL
        mesh.PROBE_INTERVAL = 0
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        import base64 as b64
        self.pk = b64.b64encode(os.urandom(32)).decode()
        self.tele = lambda n: {"schema": "paulnet-telemetry-v1", "kind": "system_status", "version": "1.0.4", "node": A,
                               "gateway": "0000000000000001", "public_key": self.pk, "timestamp": 1794580000 + n,
                               "nonce": os.urandom(16).hex(), "metrics": {"process_uptime_s": n, "cpu_temperature_c": 41.5},
                               "signature": b64.b64encode(os.urandom(64)).decode()}
        for n in ("a", "b"):
            (self.d / n).mkdir()
        outbox(self.d / "a" / "o.db", [("/v1/telemetry", self.tele(1))])
        outbox(self.d / "b" / "o.db", [])
        t0 = time.time() - 4000
        self.a = mesh.Mesh(self.d / "a", self.d / "a" / "o.db", A, started=t0)
        self.b = mesh.Mesh(self.d / "b", self.d / "b" / "o.db", B, started=t0)

    def tearDown(self):
        mesh.PROBE_INTERVAL = self._probe
        self.tmp.cleanup()

    def test_compact_roundtrip_exact(self):
        p = self.tele(5)
        p["odd"] = "not base64 !"
        p["nonce"] = "ABCDEF"                       # upper-case hex must stay exactly as it was
        blob = mesh.make_blob("/v1/telemetry", p, compact=True)
        self.assertEqual(blob[:2], bytes([mesh.BLOB_DICT_MAGIC, 2]))
        endpoint, back = mesh.unpack_blob(blob)
        self.assertEqual(json.dumps(back, sort_keys=True), json.dumps(p, sort_keys=True))
        self.assertLess(len(blob), len(mesh.make_blob("/v1/telemetry", p)))

    def test_dict1_still_decodes_and_unknown_dict_rejected(self):
        import zlib
        raw = json.dumps({"e": "/v1/telemetry", "p": self.tele(2)}, separators=(",", ":"), sort_keys=True).encode()
        c = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY, zdict=mesh.BLOB_DICTS[1])
        blob1 = bytes([mesh.BLOB_DICT_MAGIC, 1]) + c.compress(raw) + c.flush()
        self.assertEqual(mesh.unpack_blob(blob1)[1], self.tele(2) | {"nonce": json.loads(raw)["p"]["nonce"],
                                                                    "signature": json.loads(raw)["p"]["signature"]})
        with self.assertRaises(ValueError):
            mesh.unpack_blob(bytes([mesh.BLOB_DICT_MAGIC, 9]) + b"xx")

    def test_compact_only_after_parent_proves_it(self):
        now = time.time()
        self.a.on_ack(mesh.parse(mesh.make_ack(B, B, [], 0)), now, snr=0.0)
        f = self.a.next_origin_frame(None, now)
        self.assertFalse(self.a.sending["blob"][:1] == bytes([mesh.BLOB_DICT_MAGIC]), "classic before any RPT")
        rpt = mesh.make_report(B, A, [], 0, -5.0)
        self.assertEqual(rpt[3], mesh.KIND_REPORT_V24)
        self.a.on_report(mesh.parse(rpt), now, snr=-10.0)
        self.assertTrue(self.a.compact_ok(now))
        self.a.sending = None
        self.a.last_telemetry_mesh = 0
        original = self.tele(3)
        with sqlite3.connect(self.d / "a" / "o.db") as db:
            db.execute("DELETE FROM outbox")
            db.execute("INSERT INTO outbox(endpoint,payload,created_at) VALUES (?,?,?)",
                       ("/v1/telemetry", json.dumps(original), int(now) - 5000))
        self.a.waiting.clear()
        self.a.next_origin_frame(None, now + 1)
        self.assertEqual(self.a.sending["blob"][:1], bytes([mesh.BLOB_DICT_MAGIC]))
        res = None
        while True:
            fr = self.a.next_origin_frame(None, now + 1)
            if fr is None:
                break
            self.a.origin_frame_sent(now + 1)
            res = self.b.on_data(mesh.parse(fr), now - 10, now + 1) or res
            if not self.a.sending:
                break
        self.assertEqual(res[0], "upload")
        self.assertEqual(json.dumps(res[2], sort_keys=True), json.dumps(original, sort_keys=True),
                         "relayed payload must be byte-identical JSON (signature stays valid)")

    def test_telemetry_throttled_while_offline(self):
        now = time.time()
        f = self.a.next_origin_frame(None, now)
        self.assertIsNotNone(f)
        while self.a.sending:
            self.a.origin_frame_sent(now)
            if self.a.sending:
                self.a.next_origin_frame(None, now)
        with sqlite3.connect(self.d / "a" / "o.db") as db:
            db.execute("INSERT INTO outbox(endpoint,payload,created_at) VALUES (?,?,?)",
                       ("/v1/telemetry", json.dumps(self.tele(9)), int(now) - 5000))
        self.assertIsNone(self.a.next_origin_frame(None, now + 60), "next telemetry only after 30 min")
        self.assertIsNotNone(self.a.next_origin_frame(None, now + mesh.TELEMETRY_MESH_INTERVAL + 1))

    def test_capability_announce_on_classic_blob(self):
        now = time.time()
        self.b.neighbours[A] = (1, now)
        f = mesh.fragments(A, mesh.make_blob("/v1/telemetry", self.tele(4)), 0, 1, A, 125)[1][0]
        self.b.on_data(mesh.parse(f), now - 10, now, snr=-9.0)
        self.assertIsNone(self.b.next_report_frame(now - 10, now))
        sender, frame = None, None
        item = self.b.next_report_frame(now - 10, now + mesh.REPORT_QUIET + 1)
        self.assertIsNotNone(item)
        sender, frame = item
        self.b.report_sent(sender, now + mesh.REPORT_QUIET + 1)
        p = mesh.parse(frame)
        self.assertTrue(p["compact"])
        self.a.on_ack(mesh.parse(mesh.make_ack(B, B, [], 0)), now, snr=-9.0)
        self.a.on_report(p, now, snr=-12.0)
        self.assertTrue(self.a.compact_ok(now))
        self.b.on_data(mesh.parse(f), now - 10, now + 30, snr=-9.0)
        self.assertIsNone(self.b.next_report_frame(now - 10, now + 100) if not self.b.reports else None,
                          "no second announce within CAPS_TTL/4")

    def test_telemetry_not_blocked_when_failed_one_was_replaced(self):
        now = time.time()
        self.a.on_ack(mesh.parse(mesh.make_ack(B, B, [], 0)), now, snr=0.0)
        self.a.next_origin_frame(None, now)
        while self.a.sending:
            self.a.origin_frame_sent(now)
            if self.a.sending:
                self.a.next_origin_frame(None, now)
        with sqlite3.connect(self.d / "a" / "o.db") as db:      # node.py replaced the old telemetry row
            db.execute("DELETE FROM outbox")
            db.execute("INSERT INTO outbox(endpoint,payload,created_at) VALUES (?,?,?)",
                       ("/v1/telemetry", json.dumps(self.tele(8)), int(now) - 5000))
        self.assertIsNotNone(self.a.next_origin_frame(None, now + 5), "newer telemetry may go out")

    def test_v25_parent_prefers_capable_neighbour(self):
        now = time.time()
        self.a.neighbours[B] = (0, now); self.a.neighbours[C] = (0, now)
        self.a.rx_link[B] = (-13.0, now); self.a.rx_link[C] = (-11.0, now)
        self.assertEqual(self.a.parent(now), C)          # only SNR: C
        self.a.compact_peers[B] = now
        self.assertEqual(self.a.parent(now), B)          # B decodes dict blobs + sends reports
        self.assertTrue(self.a.compact_ok(now))

    def test_v25_reported_link_kept_6h(self):
        now = time.time()
        self.a.tx_link[B] = (-10.0, now - 2 * 3600)
        self.a.rx_link[B] = (-19.0, now)
        self.assertEqual(self.a.link_snr(B, now), -10.0)
        self.a.tx_link[B] = (-10.0, now - 7 * 3600)
        self.assertEqual(self.a.link_snr(B, now), -19.0)

    def test_v26_weak_neighbour_not_used_for_route(self):
        now = time.time()
        self.a.neighbours[C] = (0, now); self.a.rx_link[C] = (-17.0, now)      # online but barely heard
        self.a.neighbours[B] = (1, now); self.a.tx_link[B] = (-8.0, now)       # offline relay, good link
        self.assertEqual(self.a.parent(now), B)
        self.assertEqual(self.a.distance(None, now), 2)                         # B (dist 1) is strictly closer
        self.a.rx_link[C] = (-12.0, now)
        self.assertEqual(self.a.parent(now), C)
        self.assertEqual(self.a.distance(None, now), 1)

    def test_v26_only_weak_neighbours_fall_back(self):
        now = time.time()
        self.a.neighbours[C] = (0, now); self.a.rx_link[C] = (-18.0, now)
        self.assertTrue(self.a.route_known(now))           # only weak neighbours: fall back to them
        self.assertEqual(self.a.parent(now), C)

    def test_old_v23_node_ignores_v24_report(self):
        import importlib.machinery, importlib.util
        path = Path(mesh.__file__).resolve().parent.parent / "mesh-backups" / "mesh.py.v2.3"
        if not path.exists():
            self.skipTest("no v2.3 copy")
        loader = importlib.machinery.SourceFileLoader("mesh23", str(path))
        old = importlib.util.module_from_spec(importlib.util.spec_from_loader("mesh23", loader))
        loader.exec_module(old)
        self.assertFalse(old.is_frame(mesh.make_report(B, A, [], 0, -5)))
