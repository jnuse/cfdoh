"""F-018 explain 端点 — 3 用例 (S-STD, ECH_DOMAINS 建立 ECH 面).

断言语义真源: .trellis/spec/prd/requirements.md F-018 节.
输出: 客户端 IP, 各类型应答 (缓存态, 逐步判定链), Chromium ECH 可用性;
name 语法校验 400; 只读不写缓存.
"""

import base64
import ipaddress
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


class F018ExplainTest(unittest.TestCase):
    """F-018: 决策链逐步可见, 非法 name 400, 只读."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f018-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f018-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            for n in ("cf18.example.com", "ro18.example.com"):
                u1.add_doh(n, dnscodec.TYPE_A,
                           a_records_response(0x1234, n, ["104.16.132.229"]))
                u1.add_doh(n, dnscodec.TYPE_AAAA,
                           aaaa_records_response(0x1234, n,
                                                 ["2606:4700:10:10::7"]))
                u1.add_doh(n, dnscodec.TYPE_HTTPS,
                           https_response(0x1234, n, alpn=["h3", "h2"],
                                          hint4=["104.16.132.229"]))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f018"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std",
                ech_config_b64=ech_config(ord("B")),
                extra={"CF_REWRITE_ENABLED": "true", "ECH_ENABLED": "true",
                       "ECH_SOURCE_DOMAIN": "ech-dead18.example",
                       "ECH_DOMAINS": "cf18.example.com"})
            cls.inst = harness.Instance("f018-s-std", env,
                                        workdir / "std").start()
            cls.instances.append(cls.inst)
            status, _, _ = cls.inst.admin_json(
                "POST", "/admin/preferred",
                payload={"ipv4": ["104.16.10.1", "104.16.10.2"],
                         "ipv6": [], "ttl": 600, "source": "probe-a",
                         "scope": "default"})
            if not (200 <= status < 300):
                raise AssertionError("f018 池上报失败: %s" % status)
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

    def test_f018_full_chain(self):
        """F-018 AC: CF 站点三类型 → chromium 可用, 判定链含池/改写/ECH 注入."""
        status, _, body = self.inst.request(
            "GET", "/explain?name=cf18.example.com")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("client_ip", data, "explain 须含 client_ip")
        answers = data.get("answers") or {}
        for qtype in ("A", "AAAA", "HTTPS"):
            entry = answers.get(qtype)
            self.assertTrue(entry, "explain 须含 %s 类型应答" % qtype)
            self.assertIn("cache", entry, "%s 应答须含缓存态" % qtype)
        # 判定链: 池选择, Cloudflare 改写, ECH 注入 三步在 HTTPS 应答 notes 中
        notes = (answers.get("HTTPS") or {}).get("notes") or []
        joined = " | ".join(notes)
        self.assertIn("pool:", joined, "判定链须含池选择步: %r" % notes)
        self.assertIn("cloudflare:", joined,
                      "判定链须含 Cloudflare 判定步: %r" % notes)
        self.assertIn("ech:", joined, "判定链须含 ECH 注入步: %r" % notes)
        pool_idx = joined.find("pool:")
        cf_idx = joined.find("cloudflare:")
        ech_idx = joined.find("ech:")
        self.assertLess(ech_idx, len(joined))
        self.assertGreater(ech_idx, max(pool_idx, cf_idx),
                           "ECH 注入步须在池选择与 Cloudflare 判定之后")
        verdict = data.get("chromium_ech") or {}
        self.assertTrue(verdict.get("usable"),
                        "CF 站点三类型齐备且含 ech 时 Chromium 判定须可用: %r"
                        % verdict)

    def test_f018_invalid_name_400(self):
        """F-018 AC: 非法 name → 400."""
        status, _, _ = self.inst.request(
            "GET", "/explain?name=..bad..")
        self.assertEqual(status, 400, "非法 name 须 400")

    def test_f018_pool_scope_default_and_scoped(self):
        """F-018: pool scope 无窄层时显示 default; 前缀池贡献后显示前缀串."""
        status, _, body = self.inst.request(
            "GET", "/explain?name=cf18.example.com&type=A")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual((data.get("pool") or {}).get("scope"), "default",
                         "无窄层池贡献时 explain 须显示 default: %r"
                         % data.get("pool"))
        # 上报本机前缀 scoped 池后再查, scope 应显示前缀串
        status, _, _ = self.inst.admin_json(
            "POST", "/admin/preferred",
            payload={"ipv4": ["104.16.11.1"], "ipv6": [],
                     "ttl": 600, "source": "probe-scope",
                     "scope": "client"})
        self.assertTrue(200 <= status < 300,
                        "scoped 池上报失败: %s" % status)
        status, _, body = self.inst.request(
            "GET", "/explain?name=cf18.example.com&type=A")
        self.assertEqual(status, 200)
        data = json.loads(body)
        scope = (data.get("pool") or {}).get("scope")
        self.assertTrue(scope and scope != "default",
                        "scoped 池贡献后须显示前缀 scope: %r" % scope)

    def test_f018_readonly(self):
        """F-018: explain 只读 — 之后同键 DoH 查询仍真实出向 (未写缓存)."""
        status, _, _ = self.inst.request(
            "GET", "/explain?name=ro18.example.com&type=A")
        self.assertEqual(status, 200)
        after_explain = len(self.u1.doh_queries("ro18.example.com",
                                               dnscodec.TYPE_A))
        self.assertEqual(after_explain, 1,
                         "explain 自身现查应出向一次 (且不写缓存)")
        query = dnscodec.build_query(0x1801, "ro18.example.com",
                                     dnscodec.TYPE_A, edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        self.assertEqual(
            len(self.u1.doh_queries("ro18.example.com", dnscodec.TYPE_A)), 2,
            "explain 不得写缓存: 同键 DoH 查询须再次真实出向")


if __name__ == "__main__":
    unittest.main()
