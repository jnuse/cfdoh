"""F-005 客户端识别 — 4 用例 (S-STD + 受控 ISP 表).

断言语义真源: .trellis/spec/prd/requirements.md F-005 节.
取值顺序: X-Real-IP → CF-Connecting-IP → X-Forwarded-For 首值;
反代模式缺失时以 TCP 对端地址补齐.
"""

import json
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

ISP_TABLE = "chinanet 1.2.4.0/24\n"
CHINANET_CLIENT = "1.2.4.10"
CHINANET_POOL = {"104.16.10.1", "104.16.10.2"}
# 每个身份用例用独立域名: 用例语义是 "该识别头生效";
# 不允许用例间缓存交互干扰判定 (同域名同键重复查询的改写一致性
# 属 F-009 批 3 语义, 已另行上报实现缺陷).
IDENTITY_DOMAINS = {
    "xrealip": "idn-xrealip.example.com",
    "cfcip": "idn-cfcip.example.com",
}


def a_records_response(qid, qname, addresses, ttl):
    """构造 A 应答: question 回显 + 未压缩名字的 N 条 A 记录."""
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class F005ClientIdentityTest(unittest.TestCase):
    """F-005: 识别头优先级与反代 TCP 对端补齐, 池按客户端 IP 选择."""

    @classmethod
    def setUpClass(cls):
        cls.query = (FIXTURES / "query_a_www_example_com.bin").read_bytes()
        cls.response = (FIXTURES
                        / "response_a_www_example_com.bin").read_bytes()
        cls.u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f005-u1").start()
        cls.u1.add_doh("www.example.com", dnscodec.TYPE_A, cls.response)
        for domain in (list(IDENTITY_DOMAINS.values())
                       + ["warm.example.com"]):
            cls.u1.add_doh(domain, dnscodec.TYPE_A,
                           a_records_response(0x1234, domain,
                                              ["104.16.132.229"], 300))
        cls.cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f005-cfrange").start()
        cls.cfrange.add_path("/ips-v4", CF_V4_LIST)
        cls.cfrange.add_path("/ips-v6", CF_V6_LIST)
        cls.isp = fakestack.FakeStack(harness.STACK_PORTS["isp"], "files",
                                      name="f005-isp").start()
        cls.isp.add_path("/isp.txt", ISP_TABLE)
        cls.workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f005"
        if cls.workdir.exists():
            shutil.rmtree(cls.workdir)
        env = harness.family_env(
            "s_std",
            upstreams="%s/dns-query" % cls.u1.base_url,
            workdir=cls.workdir,
            isp_url="%s/isp.txt" % cls.isp.base_url)
        cls.inst = harness.Instance("f005-s-std", env, cls.workdir).start()
        # 预置 isp:chinanet 池, 供池选择断言 (上报通道语义归 F-008 批 3)
        status, _, _ = cls.inst.admin_json(
            "POST", "/admin/preferred",
            payload={"ipv4": sorted(CHINANET_POOL), "ipv6": [],
                     "ttl": 600, "source": "probe-x",
                     "scope": "isp:chinanet"})
        if not (200 <= status < 300):
            raise AssertionError("setUpClass chinanet 池上报失败: %s"
                                 % status)
        # 预热: ISP 表为查询驱动的惰性加载, 首查可能回落全国层
        # (F-006 允许 "查不到即回落"); 本文件断言的是识别头语义,
        # 轮询至 chinanet 池可观察到后再进用例, 剔除冷启动变量.
        warm_query = dnscodec.build_query(0x2f01, "warm.example.com",
                                          dnscodec.TYPE_A, edns=False)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            status, _, body = cls.inst.doh_get(
                warm_query, extra_headers={"X-Real-IP": CHINANET_CLIENT})
            if (status == 200
                    and set(dnscodec.answer_addresses(
                        dnscodec.parse_packet(body),
                        dnscodec.TYPE_A)) == CHINANET_POOL):
                break
            time.sleep(0.3)
        else:
            raise AssertionError(
                "setUpClass 预热失败: chinanet 池 10s 内未生效 "
                "(ISP 表惰性加载或池上报异常)")

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

    def _explain_client_ip(self, name, headers=None):
        status, _, body = self.inst.request(
            "GET", "/explain?name=%s&type=A" % name, headers=headers or {})
        self.assertEqual(status, 200, "explain 应答: %r" % body[:200])
        data = json.loads(body)
        return data.get("client_ip")

    def test_f005_xrealip_preferred(self):
        """F-005: X-Real-IP=电信网段 IP → explain 显示且应答走 chinanet 池."""
        domain = IDENTITY_DOMAINS["xrealip"]
        query = dnscodec.build_query(0x5001, domain, dnscodec.TYPE_A,
                                     edns=False)
        status, _, body = self.inst.doh_get(
            query, extra_headers={"X-Real-IP": CHINANET_CLIENT})
        self.assertEqual(status, 200)
        got = set(dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A))
        self.assertEqual(got, CHINANET_POOL,
                         "电信客户端应答须来自 isp:chinanet 池: %r" % got)
        self.assertEqual(
            self._explain_client_ip(domain,
                                    {"X-Real-IP": CHINANET_CLIENT}),
            CHINANET_CLIENT, "explain 须显示 X-Real-IP 识别出的客户端 IP")

    def test_f005_cf_connecting_ip_fallback(self):
        """F-005: 无 X-Real-IP 时 CF-Connecting-IP 生效 (同上语义)."""
        domain = IDENTITY_DOMAINS["cfcip"]
        query = dnscodec.build_query(0x5002, domain, dnscodec.TYPE_A,
                                     edns=False)
        status, _, body = self.inst.doh_get(
            query, extra_headers={"CF-Connecting-IP": CHINANET_CLIENT})
        self.assertEqual(status, 200)
        got = set(dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A))
        self.assertEqual(got, CHINANET_POOL,
                         "CF-Connecting-IP 识别的电信客户端须用 chinanet 池")
        self.assertEqual(
            self._explain_client_ip(
                domain, {"CF-Connecting-IP": CHINANET_CLIENT}),
            CHINANET_CLIENT, "explain 须显示 CF-Connecting-IP 识别的 IP")

    def test_f005_xff_first_fallback(self):
        """F-005: 仅 X-Forwarded-For 时取首值."""
        client_ip = self._explain_client_ip(
            "www.example.com",
            {"X-Forwarded-For": "203.0.113.77, 198.51.100.9"})
        self.assertEqual(client_ip, "203.0.113.77",
                         "XFF 须取首值, 实际: %r" % client_ip)

    def test_f005_direct_tcp_peer(self):
        """F-005: 直连无识别头 → 反代模式以 TCP 对端地址补齐 (127.0.0.1)."""
        client_ip = self._explain_client_ip("www.example.com")
        self.assertEqual(client_ip, "127.0.0.1",
                         "无识别头时须用 TCP 对端地址, 实际: %r" % client_ip)


if __name__ == "__main__":
    unittest.main()
