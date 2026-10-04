"""F-009 Cloudflare 判定与地址改写 — 5 用例 (S-STD + S-DROP).

断言语义真源: .trellis/spec/prd/requirements.md F-009 节.
CF 站点 A/AAAA 替换为优选池 (每族 ≤6), 多次应答轮转, 非 CF 原样,
HTTPS 地址提示同步替换, CF_DROP_AAAA 去 AAAA.
"""

import base64
import shutil
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST

# 8 地址池: 验证每族服务上限 6
BIG_POOL = ["104.16.10.%d" % i for i in range(1, 9)]


def a_records_response(qid, qname, addresses, ttl=300,
                       qtype=dnscodec.TYPE_A):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", qtype, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", qtype, dnscodec.CLASS_IN,
                                ttl, len(rdata)) + rdata
    return out


def aaaa_records_response(qid, qname, addresses, ttl=300):
    import ipaddress
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_AAAA, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = ipaddress.IPv6Address(addr).packed
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_AAAA,
                                dnscodec.CLASS_IN, ttl, 16) + rdata
    return out


def https_response(qid, qname, ttl=300, alpn=None, hint4=None):
    qn = dnscodec.encode_name(qname)
    params = b""
    if alpn:
        val = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        params += struct.pack(">HH", dnscodec.SVC_ALPN, len(val)) + val
    if hint4:
        val = b"".join(bytes(int(x) for x in h.split("."))
                       for h in hint4)
        params += struct.pack(">HH", dnscodec.SVC_IPV4HINT, len(val)) + val
    rdata = struct.pack(">H", 1) + b"\x00" + params
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN) \
        + qn + struct.pack(">HHIH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN,
                           ttl, len(rdata)) + rdata


class F009CfRewriteTest(unittest.TestCase):
    """F-009: 池内改写与上限, 非 CF 原样, 轮转, hint 同步, drop AAAA."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f009-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f009-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            u1.add_doh("cf9a.example.com", dnscodec.TYPE_A,
                       a_records_response(0x1234, "cf9a.example.com",
                                          ["104.16.132.229",
                                           "104.16.132.230"]))
            u1.add_doh("cf9r.example.com", dnscodec.TYPE_A,
                       a_records_response(0x1234, "cf9r.example.com",
                                          ["104.16.132.229"]))
            u1.add_doh("cf9h.example.com", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "cf9h.example.com",
                                      alpn=["h2"],
                                      hint4=["104.16.132.229",
                                             "104.16.132.230"]))
            u1.add_doh("plain9.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "plain9.example.org",
                                          ["93.184.216.34",
                                           "93.184.216.35"], ttl=217))
            u1.add_doh("cf9d.example.com", dnscodec.TYPE_AAAA,
                       aaaa_records_response(0x1234, "cf9d.example.com",
                                             ["2606:4700:10:10::5"]))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f009"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std",
                extra={"CF_REWRITE_ENABLED": "true"})
            cls.i1 = harness.Instance("f009-s-std", env,
                                      workdir / "std").start()
            cls.instances.append(cls.i1)
            status, _, _ = cls.i1.admin_json(
                "POST", "/admin/preferred",
                payload={"ipv4": BIG_POOL, "ipv6": [], "ttl": 600,
                         "source": "probe-a", "scope": "default"})
            if not (200 <= status < 300):
                raise AssertionError("f009 池上报失败: %s" % status)

            env2 = harness.family_env(
                "s_drop", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "drop", drop_aaaa=True,
                extra={"CF_REWRITE_ENABLED": "true"})
            cls.i2 = harness.Instance("f009-s-drop", env2,
                                      workdir / "drop").start()
            cls.instances.append(cls.i2)
            status, _, _ = cls.i2.admin_json(
                "POST", "/admin/preferred",
                payload={"ipv4": BIG_POOL, "ipv6": [], "ttl": 600,
                         "source": "probe-a", "scope": "default"})
            if not (200 <= status < 300):
                raise AssertionError("f009 drop 池上报失败: %s" % status)
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

    def _query(self, inst, name, qtype, qid):
        query = dnscodec.build_query(qid, name, qtype, edns=False)
        status, _, body = inst.doh_get(query)
        self.assertEqual(status, 200)
        return dnscodec.parse_packet(body)

    def test_f009_rewrite_all_from_pool(self):
        """F-009 AC: CF 站点 A 记录全来自池且 ≤6 条."""
        packet = self._query(self.i1, "cf9a.example.com",
                             dnscodec.TYPE_A, 0x9101)
        self.assertEqual(packet["rcode"], 0)
        got = dnscodec.answer_addresses(packet, dnscodec.TYPE_A)
        self.assertTrue(got, "CF 站点应答须含 A 记录")
        self.assertTrue(set(got) <= set(BIG_POOL),
                        "A 记录须全部来自池: %r" % got)
        self.assertLessEqual(len(got), 6, "每族服务上限 6: %r" % got)

    def test_f009_non_cf_passthrough(self):
        """F-009 AC: 非 CF 站点应答与上游语义一致."""
        packet = self._query(self.i1, "plain9.example.org",
                             dnscodec.TYPE_A, 0x9102)
        self.assertEqual(packet["rcode"], 0)
        rows = [(r["name"], r["address"], r["ttl"])
                for r in packet["answers"] if r["type"] == dnscodec.TYPE_A]
        self.assertEqual(
            rows, [("plain9.example.org", "93.184.216.34", 217),
                   ("plain9.example.org", "93.184.216.35", 217)],
            "非 CF 站点须原样返回 (地址与 TTL 不变): %r" % rows)

    def test_f009_rotation_spread(self):
        """F-009/F-001: 多次查询首条 A 轮转 (≥2 种取值)."""
        firsts = set()
        for i in range(6):
            packet = self._query(self.i1, "cf9r.example.com",
                                 dnscodec.TYPE_A, 0x9110 + i)
            firsts.add(dnscodec.answer_addresses(packet,
                                                 dnscodec.TYPE_A)[0])
        self.assertGreaterEqual(
            len(firsts), 2,
            "6 次查询首条须轮转出 ≥2 种池地址: %r" % firsts)

    def test_f009_https_hints_sync(self):
        """F-009 AC: HTTPS 应答的 ipv4hint 与 A 记录同步替换为池."""
        packet = self._query(self.i1, "cf9h.example.com",
                             dnscodec.TYPE_HTTPS, 0x9103)
        self.assertEqual(packet["rcode"], 0)
        for rec in packet["answers"]:
            if rec["type"] != dnscodec.TYPE_HTTPS:
                continue
            hints = rec["params"].get(dnscodec.SVC_IPV4HINT)
            self.assertTrue(
                hints and set(hints) <= set(BIG_POOL)
                and len(hints) <= 6,
                "ipv4hint 须与 A/AAAA 同步替换为池地址: %r" % hints)

    def test_f009_drop_aaaa(self):
        """F-009 AC: CF_DROP_AAAA 开启时 CF 站点 AAAA 查询无记录返回."""
        packet = self._query(self.i2, "cf9d.example.com",
                             dnscodec.TYPE_AAAA, 0x9104)
        self.assertEqual(packet["rcode"], 0)
        aaaa = [r for r in packet["answers"]
                if r["type"] == dnscodec.TYPE_AAAA]
        self.assertEqual(aaaa, [], "drop 开启时 CF 站点不得返回 AAAA: %r"
                         % aaaa)


if __name__ == "__main__":
    unittest.main()
