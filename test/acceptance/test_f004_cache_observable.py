"""F-004 应答缓存 — 用户可观察面 5 用例 (S-STD, 单受控上游 U1).

断言语义真源: .trellis/spec/prd/requirements.md F-004 节.
出向计数全部来自假上游请求记录 (上游用户视角).
"""

import shutil
import struct
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST

# 受控运营商表: 电信与联通各一个 /24 (requirements F-006 "<运营商> <CIDR>" 格式)
ISP_TABLE = "chinanet 1.2.4.0/24\nunicom 1.2.8.0/24\n"


def a_records_response(qid, qname, addresses, ttl, qtype=dnscodec.TYPE_A):
    """构造应答: question 回显 + 未压缩名字的 N 条记录 (A 记录或空应答)."""
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", qtype, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", qtype, dnscodec.CLASS_IN,
                                ttl, len(rdata)) + rdata
    return out


def https_response(qid, qname, ttl, hint4):
    """构造 HTTPS 应答: SvcPriority=1 + target "." + ipv4hint
    (RFC 9460 RDATA = SvcPriority(2) + TargetName + SvcParams)."""
    qn = dnscodec.encode_name(qname)
    rdata = (struct.pack(">H", 1) + b"\x00"
             + struct.pack(">HH", dnscodec.SVC_IPV4HINT, 4)
             + bytes(int(x) for x in hint4.split(".")))
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN) \
        + qn + struct.pack(">HHIH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN,
                           ttl, len(rdata)) + rdata


class F004CacheObservableTest(unittest.TestCase):
    """F-004: TTL 内不出向, scope 隔离, stale 兜底, SERVFAIL 不缓存,
    HTTPS 过期立即返回."""

    @classmethod
    def setUpClass(cls):
        cls.query = (FIXTURES / "query_a_www_example_com.bin").read_bytes()
        cls.response = (FIXTURES
                        / "response_a_www_example_com.bin").read_bytes()
        cls.u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f004-u1").start()
        cls.u1.add_doh("www.example.com", dnscodec.TYPE_A, cls.response)
        cls.u1.add_doh("ttl.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "ttl.example.org",
                                          ["93.184.216.37"], 300))
        cls.u1.add_doh("stale.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "stale.example.org",
                                          ["93.184.216.34"], 30))
        cls.u1.add_doh("servfail.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "servfail.example.org",
                                          ["93.184.216.35"], 300))
        cls.u1.add_doh("https.example.org", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "https.example.org", 30,
                                      "93.184.216.36"))
        cls.cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f004-cfrange").start()
        cls.cfrange.add_path("/ips-v4", CF_V4_LIST)
        cls.cfrange.add_path("/ips-v6", CF_V6_LIST)
        cls.isp = fakestack.FakeStack(harness.STACK_PORTS["isp"], "files",
                                      name="f004-isp").start()
        cls.isp.add_path("/isp.txt", ISP_TABLE)
        cls.workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f004"
        if cls.workdir.exists():
            shutil.rmtree(cls.workdir)
        env = harness.family_env(
            "s_std",
            upstreams="%s/dns-query" % cls.u1.base_url,
            workdir=cls.workdir,
            isp_url="%s/isp.txt" % cls.isp.base_url)
        cls.inst = harness.Instance("f004-s-std", env, cls.workdir).start()

    @classmethod
    def tearDownClass(cls):
        inst = getattr(cls, "inst", None)
        if inst is not None and inst.proc is not None and not inst._stopped:
            inst.kill()
        for stack in (getattr(cls, "u1", None),
                      getattr(cls, "cfrange", None),
                      getattr(cls, "isp", None)):
            if stack is not None:
                stack.stop()

    def _outbound(self, qname, qtype=dnscodec.TYPE_A):
        return len(self.u1.doh_queries(qname, qtype))

    def _upload_isp_pool(self, scope, ipv4, source):
        status, _, _ = self.inst.admin_json(
            "POST", "/admin/preferred",
            payload={"ipv4": ipv4, "ipv6": [], "ttl": 600,
                     "source": source, "scope": scope})
        self.assertTrue(200 <= status < 300,
                        "%s 池上报失败: %s" % (scope, status))

    def test_f004_https_expired_immediate(self):
        """F-004: HTTPS 过期缓存立即返回且后台刷新.

        等待成因: 应答 TTL=30 (CACHE_MIN_TTL 下限, 无法更短), 需 31s 让
        条目过期, 验证 "HTTPS 有缓存 (含过期) 立即返回 + 后台刷新" 语义.
        """
        query = dnscodec.build_query(0x3101, "https.example.org",
                                     dnscodec.TYPE_HTTPS, edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        self.assertEqual(self._outbound("https.example.org",
                                        dnscodec.TYPE_HTTPS), 1)
        time.sleep(31)
        start = time.monotonic()
        status, _, body = self.inst.doh_get(query)
        elapsed = time.monotonic() - start
        self.assertEqual(status, 200)
        self.assertLess(elapsed, 1.0, "过期 HTTPS 缓存必须立即返回")
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["rcode"], 0)
        # 后台刷新: 稍后上游对该 HTTPS 查询的出向计数 +1
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if self._outbound("https.example.org", dnscodec.TYPE_HTTPS) >= 2:
                break
            time.sleep(0.2)
        self.assertEqual(
            self._outbound("https.example.org", dnscodec.TYPE_HTTPS), 2,
            "立即返回后应触发后台刷新 (重新出向)")

    def test_f004_scope_isolation(self):
        """F-004: 运营商 A/B 各配 isp 池 → 同域名两次出向, 应答各归各池."""
        self._upload_isp_pool("isp:chinanet",
                              ["104.16.10.1", "104.16.10.2"], "probe-a")
        self._upload_isp_pool("isp:unicom",
                              ["104.24.10.1", "104.24.10.2"], "probe-b")
        query = dnscodec.build_query(0x3201, "www.example.com",
                                     dnscodec.TYPE_A, edns=False)
        status, _, body = self.inst.doh_get(
            query, extra_headers={"X-Real-IP": "1.2.4.10"})
        self.assertEqual(status, 200)
        got = set(dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A))
        self.assertEqual(got, {"104.16.10.1", "104.16.10.2"},
                         "电信客户端应答须来自 chinanet 池: %r" % got)
        status, _, body = self.inst.doh_get(
            query, extra_headers={"X-Real-IP": "1.2.8.10"})
        self.assertEqual(status, 200)
        got = set(dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A))
        self.assertEqual(got, {"104.24.10.1", "104.24.10.2"},
                         "联通客户端应答须来自 unicom 池: %r" % got)
        self.assertEqual(
            self._outbound("www.example.com"), 2,
            "不同池 scope 的缓存键不同, 同域名必须各自出向一次")

    def test_f004_servfail_no_cache(self):
        """F-004: 上游全挂且无缓存 → SERVFAIL 保真; 恢复后同键重新出向."""
        qname = "servfail.example.org"
        query = dnscodec.build_query(0x3301, qname, dnscodec.TYPE_A,
                                     edns=False)
        query = bytearray(query)
        query[2:4] = struct.pack(">H", 0x0110)  # RD | CD
        query = bytes(query)
        self.u1.set_doh_fail(qname, dnscodec.TYPE_A, {"status": 500})
        try:
            status, _, body = self.inst.doh_get(query)
            self.assertEqual(status, 200)
            packet = dnscodec.parse_packet(body)
            self.assertEqual(packet["rcode"], 2, "上游全挂且无缓存须 SERVFAIL")
            self.assertTrue(packet["qr"], "SERVFAIL 须置 QR")
            self.assertTrue(packet["ra"], "SERVFAIL 须置 RA")
            self.assertEqual(packet["opcode"], 0, "opcode 须保真")
            self.assertTrue(packet["rd"], "RD 须保真")
            self.assertTrue(packet["cd"], "CD 须保真")
            self.assertEqual(self._outbound(qname), 1)
        finally:
            self.u1.set_doh_fail(qname, dnscodec.TYPE_A, None)  # 恢复上游
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["rcode"], 0,
                         "SERVFAIL 不得被缓存, 恢复后须重新出向")
        self.assertEqual(self._outbound(qname), 2,
                         "同键在恢复后重新出向, 证明失败应答未入缓存")

    def test_f004_stale_serving(self):
        """F-004: 上游应答 TTL=30 → 过期后上游 500 → 服务过期应答 (TTL 写 30).

        等待成因: 应答 TTL=30 (CACHE_MIN_TTL 下限), 需 31s 进入过期窗口且
        仍在 CACHE_STALE_TTL (默认 86400) 内, 才能触发 stale 兜底路径.
        """
        qname = "stale.example.org"
        query = dnscodec.build_query(0x3401, qname, dnscodec.TYPE_A,
                                     edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        self.assertEqual(dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A), ["93.184.216.34"])
        self.u1.set_doh_fail(qname, dnscodec.TYPE_A, {"status": 500})
        time.sleep(31)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["rcode"], 0,
                         "上游全挂但过期缓存可服务时不得 SERVFAIL")
        self.assertEqual(dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                         ["93.184.216.34"], "过期应答地址须与原应答一致")
        self.assertEqual([rec["ttl"] for rec in packet["answers"]], [30],
                         "过期应答的记录 TTL 必须写为 30")
        self.assertGreaterEqual(
            self._outbound(qname), 2, "上游确已被重新尝试且失败 (500)")

    def test_f004_ttl_no_second_upstream(self):
        """F-004: TTL 内同键二次查询 → 假上游出向计数恒为 1."""
        q1 = dnscodec.build_query(0x3501, "ttl.example.org",
                                  dnscodec.TYPE_A, edns=False)
        q2 = dnscodec.build_query(0x3502, "ttl.example.org",
                                  dnscodec.TYPE_A, edns=False)
        status, _, body = self.inst.doh_get(q1)
        self.assertEqual(status, 200)
        status, _, body = self.inst.doh_get(q2)
        self.assertEqual(status, 200)
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["id"], 0x3502, "缓存命中仍须回填请求 ID")
        self.assertEqual(self._outbound("ttl.example.org"), 1,
                         "TTL 内同键二次查询不得再次出向")


if __name__ == "__main__":
    unittest.main()
