"""F-011 h3 门控 — 4 用例 (S-STD, 每用例独立域名避开应答缓存).

断言语义真源: .trellis/spec/prd/requirements.md F-011 节.
verdict 合并语义: 全部 source ok 才允许 h3, 任一 fail 即否决;
翻转经 generation 折入缓存键, 即刻生效; 无数据保留上游 ALPN.
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


def https_response(qid, qname, alpn, ttl=300):
    qn = dnscodec.encode_name(qname)
    val = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    params = struct.pack(">HH", dnscodec.SVC_ALPN, len(val)) + val
    rdata = struct.pack(">H", 1) + b"\x00" + params
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN) \
        + qn + struct.pack(">HHIH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN,
                           ttl, len(rdata)) + rdata


class F011H3GateTest(unittest.TestCase):
    """F-011: 全 ok 放行, 一 fail 否决, 翻转即刻, 无数据保留."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f011-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f011-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            # 上游 HTTPS 记录一律携带 [h3, h2]: 门控语义 = verdict 决定 h3 去留
            for n in ("gate-ok11.example.com", "gate-veto11.example.com",
                      "gate-flip11.example.com", "gate-plain11.example.com"):
                u1.add_doh(n, dnscodec.TYPE_A,
                           a_records_response(0x1234, n, ["104.16.132.229"]))
                u1.add_doh(n, dnscodec.TYPE_HTTPS,
                           https_response(0x1234, n, ["h3", "h2"]))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f011"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std",
                ech_config_b64=ech_config(ord("B")),
                extra={"CF_REWRITE_ENABLED": "true", "ECH_ENABLED": "true",
                       "ECH_SOURCE_DOMAIN": "ech-dead11.example"})
            cls.inst = harness.Instance("f011-s-std", env,
                                        workdir / "std").start()
            cls.instances.append(cls.inst)
            status, _, _ = cls.inst.admin_json(
                "POST", "/admin/preferred",
                payload={"ipv4": ["104.16.10.1", "104.16.10.2"],
                         "ipv6": [], "ttl": 600, "source": "probe-a",
                         "scope": "default"})
            if not (200 <= status < 300):
                raise AssertionError("f011 池上报失败: %s" % status)
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

    def _report(self, source, verdicts, ttl=600):
        status, _, _ = self.inst.admin_json(
            "POST", "/admin/h3",
            payload={"source": source, "ttl": ttl, "verdicts": verdicts})
        self.assertTrue(200 <= status < 300,
                        "h3 verdict 上报失败: %s" % status)

    def _alpn_of(self, name, qid):
        query = dnscodec.build_query(qid, name, dnscodec.TYPE_HTTPS,
                                     edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["rcode"], 0)
        for rec in packet["answers"]:
            if rec["type"] == dnscodec.TYPE_HTTPS:
                return rec["params"].get(dnscodec.SVC_ALPN)
        self.fail("HTTPS 应答缺少 HTTPS 记录")

    def test_f011_all_ok_enables_h3(self):
        """F-011: 单 source 全 ok → ALPN 含 h3."""
        self._report("probe-ok", {"gate-ok11.example.com": True})
        self.assertIn("h3", self._alpn_of("gate-ok11.example.com", 0xb001),
                      "全部 source ok 时 ALPN 须含 h3")

    def test_f011_one_fail_vetoes(self):
        """F-011 AC: 两 source 一 ok 一 fail → ALPN 不含 h3."""
        self._report("probe-a", {"gate-veto11.example.com": True})
        self._report("probe-b", {"gate-veto11.example.com": False})
        alpn = self._alpn_of("gate-veto11.example.com", 0xb002)
        self.assertNotIn("h3", alpn,
                         "任一 source fail 即否决 h3: %r" % alpn)

    def test_f011_flip_immediate(self):
        """F-011 AC: verdict 翻转后新应答立即反映 (不等缓存 TTL)."""
        self._report("probe-f", {"gate-flip11.example.com": False})
        self.assertNotIn(
            "h3", self._alpn_of("gate-flip11.example.com", 0xb003),
            "fail verdict 后首查不得含 h3")
        # 同 source 整份覆盖为 ok; 两次查询间零延迟, 依赖 generation 换代
        self._report("probe-f", {"gate-flip11.example.com": True})
        self.assertIn(
            "h3", self._alpn_of("gate-flip11.example.com", 0xb004),
            "翻转 ok 后立即查询须即刻含 h3 (generation 折入缓存键)")

    def test_f011_no_data_keep_alpn(self):
        """F-011: 无 verdict 数据 → 保留上游 ALPN 原样."""
        alpn = self._alpn_of("gate-plain11.example.com", 0xb005)
        self.assertEqual(alpn, ["h3", "h2"],
                         "无 verdict 时须保留上游 ALPN: %r" % alpn)


if __name__ == "__main__":
    unittest.main()
