"""F-017 请求参数 — 5 用例 (S-STD).

断言语义真源: .trellis/spec/prd/requirements.md F-017 节.
全部参数折入缓存 variant, 不同参数的应答互不污染.
"""

import shutil
import struct
import sys
import unittest
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST


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


def dns_url(query, **params):
    """带额外请求参数 (?ip4/?cf/?rules 等) 的 GET URL."""
    url = "/dns-query?dns=%s" % dnscodec.b64url_encode(query)
    for key, value in params.items():
        url += "&%s=%s" % (key, quote(value, safe=""))
    return url


class F017RequestParamsTest(unittest.TestCase):
    """F-017: ?ip4/?cf/?rules 的生效, 非法 400, 参数折入缓存键."""

    @classmethod
    def setUpClass(cls):
        cls.query = (FIXTURES / "query_a_www_example_com.bin").read_bytes()
        cls.u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f017-u1").start()
        cls.u1.add_doh("www.example.com", dnscodec.TYPE_A,
                       (FIXTURES
                        / "response_a_www_example_com.bin").read_bytes())
        for name in ("override.example.com", "variant.example.com"):
            cls.u1.add_doh(name, dnscodec.TYPE_A,
                           a_records_response(0x1234, name,
                                              ["104.16.132.229"], 300))
        # ?cf 受控优选域名: A → 203.0.113.20, AAAA → 空应答 (无 v6 池)
        cls.u1.add_doh("cfsrc.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "cfsrc.example.org",
                                          ["203.0.113.20"], 300))
        cls.u1.add_doh("cfsrc.example.org", dnscodec.TYPE_AAAA,
                       a_records_response(0x1234, "cfsrc.example.org",
                                          [], 300, dnscodec.TYPE_AAAA))
        cls.cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f017-cfrange").start()
        cls.cfrange.add_path("/ips-v4", CF_V4_LIST)
        cls.cfrange.add_path("/ips-v6", CF_V6_LIST)
        cls.workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f017"
        if cls.workdir.exists():
            shutil.rmtree(cls.workdir)
        env = harness.family_env(
            "s_std",
            upstreams="%s/dns-query" % cls.u1.base_url,
            workdir=cls.workdir)
        cls.inst = harness.Instance("f017-s-std", env, cls.workdir).start()

    @classmethod
    def tearDownClass(cls):
        inst = getattr(cls, "inst", None)
        if inst is not None and inst.proc is not None and not inst._stopped:
            inst.kill()
        for stack in (getattr(cls, "u1", None),
                      getattr(cls, "cfrange", None)):
            if stack is not None:
                stack.stop()

    def _doh_get_url(self, url):
        status, _, body = self.inst.request(
            "GET", url, headers={"Accept": "application/dns-message"})
        return status, body

    def test_f017_ip4_override(self):
        """F-017: ?ip4 两地址 + CF 站点 → A 记录恰为指定地址."""
        query = dnscodec.build_query(0x5101, "override.example.com",
                                     dnscodec.TYPE_A, edns=False)
        status, body = self._doh_get_url(
            dns_url(query, ip4="203.0.113.10,203.0.113.11"))
        self.assertEqual(status, 200)
        got = sorted(dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A))
        self.assertEqual(got, ["203.0.113.10", "203.0.113.11"],
                         "A 记录须恰为 ?ip4 指定的两地址: %r" % got)

    def test_f017_ip4_invalid_400(self):
        """F-017: ?ip4 含非法地址 → 400."""
        status, body = self._doh_get_url(dns_url(self.query,
                                                  ip4="999.1.1.1"))
        self.assertEqual(status, 400)

    def test_f017_rules_offwhitelist_400(self):
        """F-017: ?rules 指向白名单外主机 → 400."""
        status, body = self._doh_get_url(
            dns_url(self.query, rules="https://evil.example/x.json"))
        self.assertEqual(status, 400)

    def test_f017_cf_domain_pool(self):
        """F-017: ?cf=<受控域名> (解析出 203.0.113.20) → A 记录=该地址."""
        query = dnscodec.build_query(0x5104, "www.example.com",
                                     dnscodec.TYPE_A, edns=False)
        status, body = self._doh_get_url(dns_url(query, cf="cfsrc.example.org"))
        self.assertEqual(status, 200)
        got = dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A)
        self.assertEqual(got, ["203.0.113.20"],
                         "A 记录须来自 ?cf 域名解析出的地址: %r" % got)

    def test_f017_variant_cache_keys(self):
        """F-017: 同域名 ?ip4 两个不同值 → 出向 2 次, 应答各自正确."""
        query = dnscodec.build_query(0x5105, "variant.example.com",
                                     dnscodec.TYPE_A, edns=False)
        status, body = self._doh_get_url(dns_url(query, ip4="203.0.113.30"))
        self.assertEqual(status, 200)
        got = dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A)
        self.assertEqual(got, ["203.0.113.30"])
        status, body = self._doh_get_url(dns_url(query, ip4="203.0.113.31"))
        self.assertEqual(status, 200)
        got = dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A)
        self.assertEqual(got, ["203.0.113.31"],
                         "不同参数须命中不同缓存键, 互不污染")
        self.assertEqual(
            len(self.u1.doh_queries("variant.example.com", dnscodec.TYPE_A)),
            2, "两个参数变体各须出向一次")


if __name__ == "__main__":
    unittest.main()
