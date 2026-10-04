"""F-010 ECH 注入 — 6 用例 (S-STD 主实例 + 两台变体实例).

断言语义真源: .trellis/spec/prd/requirements.md F-010 节.
CF 站点 HTTPS 注入 ECHConfigList (字节 = ECH_CONFIG_BASE64); 非 CF 不注入;
源域名不可达不阻塞; ?ech= 指定域名优先; 无 HTTPS 记录补造; ECH_ENABLED 关.
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

# 冻结的真实 ECHConfigList (公开 DNS 数据, 见 fixtures/echconfig.b64);
# 运行时把公钥末字节 (偏移 42) 换成 tag 字节, 结构保持合法且互异可断言.
ECH_BASE = (FIXTURES / "echconfig.b64").read_text().strip()


def ech_config(tag):
    raw = bytearray(base64.b64decode(ECH_BASE))
    raw[42] = tag
    return base64.b64encode(bytes(raw)).decode()


ECH_CFG_B = ech_config(ord("B"))    # ECH_CONFIG_BASE64 配置
ECH_CFG_S = ech_config(ord("S"))    # 源域名 echsrc10 发布的配置
ECH_CFG_S2 = ech_config(ord("T"))   # ?ech= 指定域名 ech2-10 发布的配置


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


def https_response(qid, qname, ttl=300, alpn=None, hint4=None, ech=None,
                   count=1):
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
    return struct.pack(">HHHHHH", qid, 0x8180, 1, count, 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN) \
        + qn + struct.pack(">HHIH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN,
                           ttl, len(rdata)) + rdata


class F010EchInjectTest(unittest.TestCase):
    """F-010: 注入开关, 优先级, 不可达容忍, 补造记录."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f010-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f010-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            for n in ("cfa10.example.com", "synth10.example.com"):
                u1.add_doh(n, dnscodec.TYPE_A,
                           a_records_response(0x1234, n, ["104.16.132.229"]))
            u1.add_doh("plain10.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "plain10.example.org",
                                          ["93.184.216.34"]))
            u1.add_doh("cfa10.example.com", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "cfa10.example.com",
                                      alpn=["h3", "h2"],
                                      hint4=["104.16.132.229"]))
            u1.add_doh("plain10.example.org", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "plain10.example.org",
                                      alpn=["h2"],
                                      hint4=["93.184.216.34"]))
            u1.add_doh("synth10.example.com", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "synth10.example.com",
                                      count=0))
            u1.add_doh("echsrc10.example.org", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "echsrc10.example.org",
                                      ech=ECH_CFG_S))
            u1.add_doh("echsrc10.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "echsrc10.example.org",
                                          ["104.16.132.230"]))
            u1.add_doh("ech2-10.example.org", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "ech2-10.example.org",
                                      ech=ECH_CFG_S2))
            u1.add_doh("ech2-10.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "ech2-10.example.org",
                                          ["104.16.132.231"]))
            # 死源域名: 不编程任何记录 (u1 对未编程查询 404)

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f010"
            if workdir.exists():
                shutil.rmtree(workdir)
            common = {"CF_REWRITE_ENABLED": "true"}
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std", ech_config_b64=ECH_CFG_B,
                extra=dict(common, ECH_ENABLED="true",
                           ECH_SOURCE_DOMAIN="echsrc10.example.org"))
            cls.i1 = harness.Instance("f010-s-std", env,
                                      workdir / "std").start()
            cls.instances.append(cls.i1)
            status, _, _ = cls.i1.admin_json(
                "POST", "/admin/preferred",
                payload={"ipv4": ["104.16.10.1", "104.16.10.2"],
                         "ipv6": [], "ttl": 600, "source": "probe-a",
                         "scope": "default"})
            if not (200 <= status < 300):
                raise AssertionError("f010 池上报失败: %s" % status)

            env2 = harness.family_env(
                "s_drop", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "nosrc",
                extra=dict(common, ECH_ENABLED="true",
                           ECH_SOURCE_DOMAIN="ech-dead10.example"))
            cls.i2 = harness.Instance("f010-nosrc", env2,
                                      workdir / "nosrc").start()
            cls.instances.append(cls.i2)

            env3 = harness.family_env(
                "s_host", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "echoff", ech_config_b64=ECH_CFG_B,
                extra=dict(common))  # 不设 ECH_ENABLED (产品默认关)
            cls.i3 = harness.Instance("f010-echoff", env3,
                                      workdir / "echoff").start()
            cls.instances.append(cls.i3)
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

    def _https_query(self, inst, name, qid, url_extra=""):
        query = dnscodec.build_query(qid, name, dnscodec.TYPE_HTTPS,
                                     edns=False)
        path = "/dns-query?dns=%s%s" % (dnscodec.b64url_encode(query),
                                        url_extra)
        status, _, body = inst.request(
            "GET", path, headers={"Accept": "application/dns-message"})
        self.assertEqual(status, 200)
        return dnscodec.parse_packet(body)

    @staticmethod
    def _ech_params(packet):
        out = []
        for rec in packet["answers"]:
            if rec["type"] == dnscodec.TYPE_HTTPS:
                out.append(rec["params"].get(dnscodec.SVC_ECH))
        return out

    def test_f010_cf_site_ech(self):
        """F-010 AC: CF 站点 HTTPS 注入 ech, 字节=ECH_CONFIG_BASE64."""
        packet = self._https_query(self.i1, "cfa10.example.com", 0xa001)
        self.assertEqual(packet["rcode"], 0)
        echs = [e for e in self._ech_params(packet) if e]
        self.assertTrue(
            echs, "CF 站点 HTTPS 须含 ech 参数 (期望字节 = ECH_CONFIG_BASE64)")
        self.assertEqual(
            echs[0], ECH_CFG_B,
            "ech 字节须等于 ECH_CONFIG_BASE64 配置 (归一化 base64 比较)")

    def test_f010_non_cf_no_inject(self):
        """F-010 AC: 非 CF 站点 HTTPS 不注入."""
        packet = self._https_query(self.i1, "plain10.example.org", 0xa002)
        self.assertEqual(packet["rcode"], 0)
        self.assertEqual(self._ech_params(packet), [None],
                         "非 CF 站点不得注入 ech")

    def test_f010_source_unreachable(self):
        """F-010 AC: ECH 源域名不可达 → 应答正常返回, 不报错."""
        packet = self._https_query(self.i2, "cfa10.example.com", 0xa003)
        self.assertEqual(packet["rcode"], 0,
                         "源不可达不得阻塞解析 (无 ech 可接受)")

    def test_f010_ech_param_priority(self):
        """F-010: ?ech=<域名> 的配置优先于 ECH_CONFIG_BASE64."""
        packet = self._https_query(self.i1, "cfa10.example.com", 0xa004,
                                   url_extra="&ech=ech2-10.example.org")
        self.assertEqual(packet["rcode"], 0)
        echs = [e for e in self._ech_params(packet) if e]
        self.assertTrue(echs, "?ech= 须注入配置")
        self.assertEqual(echs[0], ECH_CFG_S2,
                         "注入字节须取 ?ech 指定域名发布的配置")

    def test_f010_synthesized_record(self):
        """F-010: 上游无 HTTPS 记录的 CF 站点 → 补造含 ech 与 alpn 的记录."""
        packet = self._https_query(self.i1, "synth10.example.com", 0xa005)
        self.assertEqual(packet["rcode"], 0, "补造失败不得返回 SERVFAIL")
        https = [r for r in packet["answers"]
                 if r["type"] == dnscodec.TYPE_HTTPS]
        self.assertTrue(https, "上游无记录时须补造 HTTPS 记录")
        rec = https[0]
        self.assertIn(dnscodec.SVC_ECH, rec["params"],
                      "补造记录须含 ech 参数")
        self.assertIn(dnscodec.SVC_ALPN, rec["params"],
                      "补造记录须含 alpn 参数 (按 h3 门控)")

    def test_f010_disabled_switch(self):
        """F-010: ECH_ENABLED 未开启的实例 → CF 站点 HTTPS 无注入."""
        packet = self._https_query(self.i3, "cfa10.example.com", 0xa006)
        self.assertEqual(packet["rcode"], 0)
        self.assertEqual(self._ech_params(packet), [None],
                         "ECH_ENABLED 关闭时不得注入 ech")


if __name__ == "__main__":
    unittest.main()
