"""F-014 特殊站点处理 — 4 用例 (S-STD: GitHub / X / 站点池).

断言语义真源: .trellis/spec/prd/requirements.md F-014 节.
GitHub 域名钉住独立测速池, 不返回 AAAA, 不注入 ECH; X 域名仅当判定由
Cloudflare 服务时改写; 站点池钉住 A/AAAA (去 v6), HTTPS 提示同步,
ECH 保留; 空上报即刻撤销.
"""

import base64
import ipaddress
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


GH_POOL = ["104.17.10.9"]
SITE_POOL = ["104.17.30.9"]
DEFAULT_POOL = ["104.16.10.1", "104.16.10.2"]


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
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_AAAA, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = ipaddress.IPv6Address(addr).packed
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_AAAA,
                                dnscodec.CLASS_IN, ttl, 16) + rdata
    return out


def https_response(qid, qname, ttl=300, alpn=None, hint4=None, ech=None):
    qn = dnscodec.encode_name(qname)
    params = b""
    if alpn:
        val = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        params += struct.pack(">HH", dnscodec.SVC_ALPN, len(val)) + val
    if hint4:
        val = b"".join(bytes(int(x) for x in h.split("."))
                       for h in hint4)
        params += struct.pack(">HH", dnscodec.SVC_IPV4HINT, len(val)) + val
    if ech:
        raw = base64.b64decode(ech)
        params += struct.pack(">HH", dnscodec.SVC_ECH, len(raw)) + raw
    rdata = struct.pack(">H", 1) + b"\x00" + params
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN) \
        + qn + struct.pack(">HHIH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN,
                           ttl, len(rdata)) + rdata


class F014SpecialSitesTest(unittest.TestCase):
    """F-014: GitHub 钉住, X 判定, 站点池钉住与撤销."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f014-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f014-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            # GitHub 域名: 上游 A 在 CF 网段, HTTPS 不带 ech (F-014 语义)
            u1.add_doh("gh14.example.com", dnscodec.TYPE_A,
                       a_records_response(0x1234, "gh14.example.com",
                                          ["104.16.132.229"]))
            u1.add_doh("gh14.example.com", dnscodec.TYPE_AAAA,
                       aaaa_records_response(0x1234, "gh14.example.com",
                                             ["2606:4700:10:10::2"]))
            u1.add_doh("gh14.example.com", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "gh14.example.com",
                                      alpn=["h2"],
                                      hint4=["104.16.132.229"]))
            # X 域名: 上游应答非 CF 地址; <域名>.cdn.cloudflare.net 未编程
            # (解析失败) → 判定不由 Cloudflare 服务
            u1.add_doh("x14.example.com", dnscodec.TYPE_A,
                       a_records_response(0x1234, "x14.example.com",
                                          ["93.184.216.34"]))
            # 站点池域名: 上游 HTTPS 自带 ech=X, 验证钉住时 ECH 保留
            u1.add_doh("site14.example.com", dnscodec.TYPE_A,
                       a_records_response(0x1234, "site14.example.com",
                                          ["104.16.132.229"]))
            u1.add_doh("site14.example.com", dnscodec.TYPE_AAAA,
                       aaaa_records_response(0x1234, "site14.example.com",
                                             ["2606:4700:10:10::3"]))
            u1.add_doh("site14.example.com", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "site14.example.com",
                                      alpn=["h2"],
                                      hint4=["104.16.132.229"],
                                      ech=ech_config(ord("X"))))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f014"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std",
                ech_config_b64=ech_config(ord("B")),
                extra={"CF_REWRITE_ENABLED": "true", "ECH_ENABLED": "true",
                       "ECH_SOURCE_DOMAIN": "ech-dead14.example",
                       "GITHUB_DOMAINS": "gh14.example.com",
                       "X_DOMAINS": "x14.example.com"})
            cls.inst = harness.Instance("f014-s-std", env,
                                        workdir / "std").start()
            cls.instances.append(cls.inst)
            status, _, _ = cls.inst.admin_json(
                "POST", "/admin/preferred",
                payload={"ipv4": DEFAULT_POOL, "ipv6": [], "ttl": 600,
                         "source": "probe-a", "scope": "default"})
            if not (200 <= status < 300):
                raise AssertionError("f014 默认池上报失败: %s" % status)
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

    def _query(self, name, qtype, qid):
        query = dnscodec.build_query(qid, name, qtype, edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        return dnscodec.parse_packet(body)

    def test_f014_github_pinned(self):
        """F-014 AC: GitHub 池存在 → A 仅池内 IPv4, 无 AAAA, 无 ech."""
        status, _, _ = self.inst.admin_json(
            "POST", "/admin/github",
            payload={"source": "gh-probe", "ttl": 600,
                     "hosts": {"gh14.example.com": GH_POOL}})
        self.assertTrue(200 <= status < 300, "github 池上报失败: %s" % status)
        packet = self._query("gh14.example.com", dnscodec.TYPE_A, 0xe001)
        self.assertEqual(packet["rcode"], 0)
        addrs = dnscodec.answer_addresses(packet, dnscodec.TYPE_A)
        self.assertEqual(addrs, GH_POOL,
                         "GitHub A 记录须仅池内 IPv4: %r" % addrs)
        packet = self._query("gh14.example.com", dnscodec.TYPE_AAAA, 0xe002)
        aaaa = [r for r in packet["answers"]
                if r["type"] == dnscodec.TYPE_AAAA]
        self.assertEqual(aaaa, [], "GitHub 域名不返回 AAAA: %r" % aaaa)
        packet = self._query("gh14.example.com", dnscodec.TYPE_HTTPS, 0xe003)
        for rec in packet["answers"]:
            if rec["type"] != dnscodec.TYPE_HTTPS:
                continue
            self.assertNotIn(
                dnscodec.SVC_ECH, rec["params"],
                "GitHub 域名不得注入 ECH: %r" % rec["param_keys"])
            self.assertEqual(rec["params"].get(dnscodec.SVC_IPV4HINT),
                             GH_POOL, "HTTPS 提示须同步钉住池")

    def test_f014_x_not_cf_passthrough(self):
        """F-014 AC: X 域名当前不由 Cloudflare 服务 → 应答原样."""
        packet = self._query("x14.example.com", dnscodec.TYPE_A, 0xe004)
        self.assertEqual(packet["rcode"], 0)
        addrs = dnscodec.answer_addresses(packet, dnscodec.TYPE_A)
        self.assertEqual(addrs, ["93.184.216.34"],
                         "非 CF 服务的 X 域名须原样返回: %r" % addrs)

    def test_f014_site_pool_pinned(self):
        """F-014: 站点池钉住 A, 去 v6, HTTPS 提示同步且 ECH 保留."""
        status, _, _ = self.inst.admin_json(
            "POST", "/admin/site",
            payload={"source": "site-probe", "ttl": 600,
                     "hosts": {"site14.example.com": SITE_POOL}})
        self.assertTrue(200 <= status < 300, "site 池上报失败: %s" % status)
        packet = self._query("site14.example.com", dnscodec.TYPE_A, 0xe005)
        addrs = dnscodec.answer_addresses(packet, dnscodec.TYPE_A)
        self.assertEqual(addrs, SITE_POOL, "站点 A 须钉住池: %r" % addrs)
        packet = self._query("site14.example.com", dnscodec.TYPE_AAAA, 0xe006)
        aaaa = [r for r in packet["answers"]
                if r["type"] == dnscodec.TYPE_AAAA]
        self.assertEqual(aaaa, [], "站点池去 v6, 不得返回 AAAA: %r" % aaaa)
        packet = self._query("site14.example.com", dnscodec.TYPE_HTTPS,
                             0xe007)
        for rec in packet["answers"]:
            if rec["type"] != dnscodec.TYPE_HTTPS:
                continue
            self.assertEqual(rec["params"].get(dnscodec.SVC_IPV4HINT),
                             SITE_POOL, "HTTPS 提示须同步站点池")
            self.assertEqual(rec["params"].get(dnscodec.SVC_ECH),
                             ech_config(ord("X")),
                             "钉住时上游 ECH 配置须保留")

    def test_f014_site_revoke_by_empty(self):
        """F-014: site 上报空 hosts 覆盖 → 钉住即刻撤销, 回普通优选池."""
        status, _, _ = self.inst.admin_json(
            "POST", "/admin/site",
            payload={"source": "site-probe", "ttl": 600, "hosts": {}})
        self.assertTrue(200 <= status < 300, "空 hosts 撤销失败: %s" % status)
        packet = self._query("site14.example.com", dnscodec.TYPE_A, 0xe008)
        addrs = set(dnscodec.answer_addresses(packet, dnscodec.TYPE_A))
        self.assertEqual(addrs, set(DEFAULT_POOL),
                         "撤销后须回普通优选池 (无需等 TTL): %r" % addrs)


if __name__ == "__main__":
    unittest.main()
