"""F-012 CNAME 展平 — 2 用例 (S-STD, ECH_DOMAINS 门控).

断言语义真源: .trellis/spec/prd/requirements.md F-012 节.
ECH 主机 (CF / Meta / ECH_DOMAINS) 的应答把 CNAME 链上记录移到查询名下,
/explain 判定 Chromium 可用 ECH; 非 ECH 主机保持链形.
"""

import base64
import json
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

ECH_BASE = (FIXTURES / "echconfig.b64").read_text().strip()


def ech_config(tag):
    raw = bytearray(base64.b64decode(ECH_BASE))
    raw[42] = tag
    return base64.b64encode(bytes(raw)).decode()


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
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


def cname_a_response(qid, alias, target, addr, ttl=300):
    """应答: CNAME alias→target + A target→addr (未压缩名字)."""
    an = dnscodec.encode_name(alias)
    tn = dnscodec.encode_name(target)
    return (struct.pack(">HHHHHH", qid, 0x8180, 1, 2, 0, 0)
            + an + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
            + an + struct.pack(">HHIH", dnscodec.TYPE_CNAME,
                               dnscodec.CLASS_IN, ttl, len(tn)) + tn
            + tn + struct.pack(">HHIH", dnscodec.TYPE_A,
                               dnscodec.CLASS_IN, ttl, 4)
            + bytes(int(x) for x in addr.split(".")))


def https_response(qid, qname, alpn, ttl=300):
    qn = dnscodec.encode_name(qname)
    val = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    params = struct.pack(">HH", dnscodec.SVC_ALPN, len(val)) + val
    rdata = struct.pack(">H", 1) + b"\x00" + params
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN) \
        + qn + struct.pack(">HHIH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN,
                           ttl, len(rdata)) + rdata


class F012FlattenTest(unittest.TestCase):
    """F-012: ECH 主机 CNAME 链记录挂查询名; 非主机保持链形."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f012-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f012-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            # ECH 主机走 ECH_DOMAINS 门控: 别名经 CNAME 链到 CF 边缘地址
            u1.add_doh("cfa12.example.com", dnscodec.TYPE_A,
                       cname_a_response(0x1234, "cfa12.example.com",
                                        "edge12.example.net",
                                        "104.16.132.229"))
            u1.add_doh("cfa12.example.com", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "cfa12.example.com",
                                      ["h3", "h2"]))
            u1.add_doh("cfa12.example.com", dnscodec.TYPE_AAAA,
                       aaaa_records_response(0x1234, "cfa12.example.com",
                                             ["2606:4700:10:10::4"]))
            # 非 ECH 主机: CNAME 链指向非 CF 地址
            u1.add_doh("plain12.example.org", dnscodec.TYPE_A,
                       cname_a_response(0x1234, "plain12.example.org",
                                        "tgt12.example.org",
                                        "93.184.216.34"))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f012"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std",
                ech_config_b64=ech_config(ord("B")),
                extra={"CF_REWRITE_ENABLED": "true", "ECH_ENABLED": "true",
                       "ECH_SOURCE_DOMAIN": "ech-dead12.example",
                       "ECH_DOMAINS": "cfa12.example.com"})
            cls.inst = harness.Instance("f012-s-std", env,
                                        workdir / "std").start()
            cls.instances.append(cls.inst)
            status, _, _ = cls.inst.admin_json(
                "POST", "/admin/preferred",
                payload={"ipv4": ["104.16.10.1", "104.16.10.2"],
                         "ipv6": [], "ttl": 600, "source": "probe-a",
                         "scope": "default"})
            if not (200 <= status < 300):
                raise AssertionError("f012 池上报失败: %s" % status)
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

    def test_f012_flatten_to_qname(self):
        """F-012 AC: CNAME 链记录挂查询名, explain 判定 Chromium 可用."""
        query = dnscodec.build_query(0xc001, "cfa12.example.com",
                                     dnscodec.TYPE_A, edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["rcode"], 0)
        owners = {r["name"].rstrip(".").lower() for r in packet["answers"]}
        self.assertEqual(owners, {"cfa12.example.com"},
                         "全部记录 owner 须为查询名: %r" % owners)
        addrs = dnscodec.answer_addresses(packet, dnscodec.TYPE_A)
        self.assertTrue(addrs, "展平后须含 A 记录")
        self.assertTrue(set(addrs) <= {"104.16.10.1", "104.16.10.2"},
                        "A 记录须被池改写: %r" % addrs)
        # HTTPS 记录先入缓存 (explain 只读不写, 逐类型现查)
        qh = dnscodec.build_query(0xc002, "cfa12.example.com",
                                  dnscodec.TYPE_HTTPS, edns=False)
        status, _, _ = self.inst.doh_get(qh)
        self.assertEqual(status, 200)
        status, _, body = self.inst.request(
            "GET", "/explain?name=cfa12.example.com")
        self.assertEqual(status, 200)
        verdict = json.loads(body).get("chromium_ech") or {}
        self.assertTrue(verdict.get("usable"),
                        "explain 须判定 Chromium 可用 ECH: %r" % verdict)

    def test_f012_non_cf_no_flatten(self):
        """F-012: 非 ECH 主机 CNAME 链保持链形不展平."""
        query = dnscodec.build_query(0xc003, "plain12.example.org",
                                     dnscodec.TYPE_A, edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["rcode"], 0)
        cnames = [r for r in packet["answers"]
                  if r["type"] == dnscodec.TYPE_CNAME]
        self.assertTrue(cnames, "非 ECH 主机须保留 CNAME 记录")
        a_recs = [r for r in packet["answers"]
                  if r["type"] == dnscodec.TYPE_A]
        self.assertTrue(a_recs, "链上须有 A 记录")
        self.assertEqual(a_recs[0]["name"].rstrip(".").lower(),
                         "tgt12.example.org",
                         "非 ECH 主机的 A 记录须保持链上 owner, 不展平")


if __name__ == "__main__":
    unittest.main()
