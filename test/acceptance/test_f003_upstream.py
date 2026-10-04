"""F-003 上游查询与对冲 — 6 用例 (S-STD, U1/U2 双上游).

断言语义真源: .trellis/spec/prd/requirements.md F-003 节.
出向计数全部来自假上游请求记录 (上游用户视角); hedge 参数化走 extra env
(UPSTREAM_HEDGE_MS=100). 每用例独立 qname 编程双上游, 应答地址区分赢家.
bad content-type 与错事务 ID 经 fakestack 失败注入以原样字节应答
(状态 200 但内容/类型不合校验链), 复用批 1 基建, 不改共享语义.
"""

import shutil
import struct
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST

HEDGE_MS = 100  # 实例级对冲间隔 (UPSTREAM_HEDGE_MS)


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class F003UpstreamTest(unittest.TestCase):
    """F-003: 快返不启第二, hedge 并发, 错误即回退, 校验链拒绝, 单飞合并."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f003-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            u2 = fakestack.FakeStack(harness.STACK_PORTS["u2"], "doh",
                                     name="f003-u2").start()
            cls.stacks.append(u2)
            cls.u2 = u2
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f003-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            # 每用例独立 qname; 双上游各自编程, 地址区分赢家.
            # fastfirst: U1 50ms 应答 (hedge 100ms 内) → U2 零出向.
            u1.add_doh("fastfirst.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "fastfirst.example.org",
                                          ["93.184.216.21"]), delay=0.05)
            u2.add_doh("fastfirst.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "fastfirst.example.org",
                                          ["93.184.216.22"]))
            # hedge: U1 慢 500ms, U2 50ms → U2 胜出, 双上游均有出向.
            u1.add_doh("hedge.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "hedge.example.org",
                                          ["93.184.216.31"]), delay=0.5)
            u2.add_doh("hedge.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "hedge.example.org",
                                          ["93.184.216.32"]), delay=0.05)
            # failover: U1 永久 500 → 立即回退 U2.
            u1.add_doh("failover.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "failover.example.org",
                                          ["93.184.216.41"]),
                       fail={"status": 500})
            u2.add_doh("failover.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "failover.example.org",
                                          ["93.184.216.42"]))
            # badctype: U1 200 但 text/plain → 校验链拒绝, U2 胜出.
            u1.add_doh("badctype.example.org", dnscodec.TYPE_A,
                       a_records_response(0x5151, "badctype.example.org",
                                          ["93.184.216.51"]),
                       fail={"status": 200,
                             "content": a_records_response(
                                 0x5151, "badctype.example.org",
                                 ["93.184.216.51"]),
                             "content_type": "text/plain; charset=utf-8"})
            u2.add_doh("badctype.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "badctype.example.org",
                                          ["93.184.216.52"]))
            # wrongid: U1 应答事务 ID 恒错 (0x0BB8, 原样不回填) → 拒绝, U2 胜出.
            u1.add_doh("wrongid.example.org", dnscodec.TYPE_A,
                       a_records_response(0x0BB8, "wrongid.example.org",
                                          ["93.184.216.61"]),
                       fail={"status": 200,
                             "content": a_records_response(
                                 0x0BB8, "wrongid.example.org",
                                 ["93.184.216.61"]),
                             "content_type": "application/dns-message"})
            u2.add_doh("wrongid.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "wrongid.example.org",
                                          ["93.184.216.62"]))
            # singleflight: U1 50ms 应答, 50 并发同键合并为一次外发.
            u1.add_doh("singleflight.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "singleflight.example.org",
                                          ["93.184.216.71"]), delay=0.05)
            u2.add_doh("singleflight.example.org", dnscodec.TYPE_A,
                       a_records_response(0, "singleflight.example.org",
                                          ["93.184.216.72"]), delay=0.05)

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f003"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std",
                upstreams="%s/dns-query,%s/dns-query"
                          % (u1.base_url, u2.base_url),
                workdir=workdir,
                extra={"UPSTREAM_HEDGE_MS": str(HEDGE_MS)})
            cls.inst = harness.Instance("f003-s-std", env,
                                        workdir).start()
            cls.instances.append(cls.inst)
        except Exception:
            cls._teardown_all()
            raise

    @classmethod
    def _teardown_all(cls):
        for inst in getattr(cls, "instances", []):
            if inst.proc is not None and not inst._stopped:
                inst.kill()
        for stack in getattr(cls, "stacks", []):
            stack.stop()

    @classmethod
    def tearDownClass(cls):
        cls._teardown_all()

    def _query(self, qid, qname):
        query = dnscodec.build_query(qid, qname, dnscodec.TYPE_A, edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        return dnscodec.parse_packet(body)

    def test_f003_fast_first_no_second(self):
        """F-003 AC: 首上游 50ms 应答 → 不启动第二上游 (U2 出向计数 0)."""
        packet = self._query(0x3001, "fastfirst.example.org")
        self.assertEqual(packet["rcode"], 0)
        self.assertEqual(dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                         ["93.184.216.21"], "应答须来自快返的 U1")
        self.assertEqual(len(self.u1.doh_queries("fastfirst.example.org")), 1)
        self.assertEqual(len(self.u2.doh_queries("fastfirst.example.org")), 0,
                         "hedge 间隔内拿到结果不得启动第二上游")

    def test_f003_hedge_parallel(self):
        """F-003 AC: 首上游超 hedge 间隔无响应 → 并发启动后续, 首个合法应答胜出."""
        packet = self._query(0x3002, "hedge.example.org")
        self.assertEqual(packet["rcode"], 0)
        self.assertEqual(dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                         ["93.184.216.32"],
                         "U1 延迟 500ms 时应答须来自 50ms 的 U2")
        self.assertGreaterEqual(
            len(self.u1.doh_queries("hedge.example.org")), 1,
            "U1 确已被发出 (对冲并发)")
        self.assertGreaterEqual(
            len(self.u2.doh_queries("hedge.example.org")), 1,
            "U2 须被并发启动")

    def test_f003_failover_on_error(self):
        """F-003 AC: 单上游失败 → 立即启动下一个, 应答来自 U2."""
        packet = self._query(0x3003, "failover.example.org")
        self.assertEqual(packet["rcode"], 0)
        self.assertEqual(dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                         ["93.184.216.42"], "U1 返回 500 后应答须来自 U2")
        self.assertEqual(len(self.u1.doh_queries("failover.example.org")), 1)
        self.assertEqual(len(self.u2.doh_queries("failover.example.org")), 1,
                         "U1 失败后 U2 须被启动且仅一次")

    def test_f003_bad_content_skipped(self):
        """F-003: U1 应答 Content-Type 非 dns-message → 校验链拒绝, U2 胜出."""
        packet = self._query(0x3004, "badctype.example.org")
        self.assertEqual(packet["rcode"], 0)
        self.assertEqual(dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                         ["93.184.216.52"], "text/plain 应答须被拒, U2 胜出")
        self.assertGreaterEqual(
            len(self.u1.doh_queries("badctype.example.org")), 1,
            "U1 确已被询问过 (其应答被校验链拒绝)")
        self.assertEqual(len(self.u2.doh_queries("badctype.example.org")), 1)

    def test_f003_wrong_id_rejected(self):
        """F-003: U1 应答事务 ID 与查询不一致 → 拒绝, U2 胜出且 ID 回填正确."""
        qid = 0x4213  # 与 U1 固定应答 ID 0x0BB8 不同
        packet = self._query(qid, "wrongid.example.org")
        self.assertEqual(packet["rcode"], 0)
        self.assertEqual(packet["id"], qid, "胜出应答须回填请求 ID")
        self.assertEqual(dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                         ["93.184.216.62"], "错 ID 应答须被拒, U2 胜出")
        self.assertGreaterEqual(
            len(self.u1.doh_queries("wrongid.example.org")), 1)
        self.assertEqual(len(self.u2.doh_queries("wrongid.example.org")), 1)

    def test_f003_singleflight(self):
        """F-003 AC: 同键 50 并发未命中查询 → 上游侧外发计数为 1.

        U1 50ms 应答落在 hedge 100ms 内, 全部并发合并在同一在飞交换上;
        事务 ID 不同不影响合并 (外发键按 ID 归一化).
        """
        qname = "singleflight.example.org"
        count = 50
        barrier = threading.Barrier(count)
        results = [None] * count
        errors = []

        def worker(idx):
            try:
                barrier.wait(timeout=10)
                qid = 0x7100 + idx
                query = dnscodec.build_query(qid, qname, dnscodec.TYPE_A,
                                             edns=False)
                status, _, body = self.inst.doh_get(query, timeout=15)
                results[idx] = (status, qid, body)
            except Exception as exc:  # noqa: BLE001 — 线程内收集后统一断言
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertFalse(errors, "并发线程异常: %r" % errors[:3])
        for status, qid, body in results:
            self.assertIsNotNone(body)
            self.assertEqual(status, 200)
            packet = dnscodec.parse_packet(body)
            self.assertEqual(packet["rcode"], 0)
            self.assertEqual(packet["id"], qid, "每个请求须回填自身 ID")
            self.assertEqual(
                dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                ["93.184.216.71"])
        self.assertEqual(len(self.u1.doh_queries(qname)), 1,
                         "50 并发同键查询必须合并为一次上游外发")


if __name__ == "__main__":
    unittest.main()
