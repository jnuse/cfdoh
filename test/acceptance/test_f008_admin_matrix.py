"""F-008 池上报接口鉴权与校验矩阵 — 6 用例 (S-STD + S-NOADMIN).

断言语义真源: .trellis/spec/prd/requirements.md F-008 节.
双令牌矩阵 (HUB_TOKEN 仅 isp:*), 常数时间比较, 未配置 ADMIN_TOKEN 时
/admin/* 全 404; 地址逐个强校验, 每族 ≤64, ttl 钳 60-86400,
isp 池逐 IP 校验 CF 网段, 任一在外整批 400.
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

CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class F008AdminMatrixTest(unittest.TestCase):
    """F-008: 鉴权 401/403/404, isp 越界整批 400, 每族上限, ttl 钳制."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f008-u1").start()
            u1.add_doh("m8.example.com", dnscodec.TYPE_A,
                       a_records_response(0x1234, "m8.example.com",
                                          ["104.16.132.229"]))
            cls.stacks.append(u1)
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f008-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f008"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std",
                extra={"CF_REWRITE_ENABLED": "true"})
            cls.i1 = harness.Instance("f008-s-std", env,
                                      workdir / "std").start()
            cls.instances.append(cls.i1)
            env2 = harness.family_env(
                "s_noadmin", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "noadmin",
                extra={"CF_REWRITE_ENABLED": "true"})
            cls.i2 = harness.Instance("f008-s-noadmin", env2,
                                      workdir / "noadmin").start()
            cls.instances.append(cls.i2)
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

    def _post_preferred(self, inst, payload, token=harness.ADMIN_TOKEN):
        return inst.admin_json("POST", "/admin/preferred", token=token,
                               payload=payload)

    def test_f008_hub_scope_default_403(self):
        """F-008 AC: HUB_TOKEN 写 scope=default → 403 (仅允许 isp:*)."""
        status, _, _ = self._post_preferred(
            self.i1, {"ipv4": ["104.16.30.1"], "ipv6": [], "ttl": 600,
                      "source": "hub", "scope": "default"},
            token=harness.HUB_TOKEN)
        self.assertEqual(status, 403)

    def test_f008_isp_offrange_400(self):
        """F-008 AC: isp 池含非 CF 网段地址 → 400 整批拒绝."""
        status, _, _ = self._post_preferred(
            self.i1, {"ipv4": ["104.16.31.1", "203.0.113.50"], "ipv6": [],
                      "ttl": 600, "source": "hub", "scope": "isp:chinanet"})
        self.assertEqual(status, 400, "任一地址在 CF 网段外须整批 400")
        # 整批拒绝: 即使池内含合法地址也不得部分入池
        status, data, _ = self.i1.admin_json("GET", "/admin/preferred")
        self.assertEqual(status, 200)
        isp_scopes = [p.get("Scope") for p in (data or {}).get("isp") or []]
        self.assertNotIn("isp:chinanet", isp_scopes,
                         "整批拒绝后不得残留部分地址入池: %r" % isp_scopes)

    def test_f008_wrong_token_401(self):
        """F-008 AC: 错误令牌 → 401 (含无 Authorization 头)."""
        status, _, _ = self._post_preferred(
            self.i1, {"ipv4": ["104.16.32.1"], "ipv6": [], "ttl": 600,
                      "source": "p", "scope": "default"}, token="wrong-token")
        self.assertEqual(status, 401)
        status, _, _ = self.i1.admin_json("GET", "/admin/preferred",
                                          token=None)
        self.assertEqual(status, 401, "缺失 Bearer 头须 401")

    def test_f008_no_admin_token_404(self):
        """F-008 AC: 未配置 ADMIN_TOKEN 时全部 /admin/* → 404."""
        paths = ["/admin/preferred", "/admin/site", "/admin/github",
                 "/admin/h3", "/admin/health", "/admin/selfcheck"]
        for path in paths:
            for method in ("GET", "POST"):
                status, _, _ = self.i2.admin_json(method, path, token=None)
                self.assertEqual(
                    status, 404,
                    "无 ADMIN_TOKEN 时 %s %s 须 404, 实际 %s"
                    % (method, path, status))
        # HUB_TOKEN 已配置也不得打开 admin 面 (ADMIN_TOKEN 缺失即全关)
        status, _, _ = self.i2.admin_json("GET", "/admin/preferred",
                                          token=harness.HUB_TOKEN)
        self.assertEqual(status, 404)

    def test_f008_family_limit_400(self):
        """F-008: 每族上报 >64 地址 → 400."""
        addrs = ["104.17.%d.%d" % (1 + i // 254, 1 + i % 254)
                 for i in range(65)]
        self.assertEqual(len(set(addrs)), 65)
        status, _, _ = self._post_preferred(
            self.i1, {"ipv4": addrs, "ipv6": [], "ttl": 600,
                      "source": "p", "scope": "default"})
        self.assertEqual(status, 400, "每族 65 条须超限 400")

    def test_f008_ttl_clamped(self):
        """F-008: ttl=10 上报成功但钳至 60 (GET /admin/preferred 回读)."""
        status, _, _ = self._post_preferred(
            self.i1, {"ipv4": ["104.16.33.1"], "ipv6": [], "ttl": 10,
                      "source": "ttl-probe", "scope": "default"})
        self.assertTrue(200 <= status < 300, "ttl=10 须被钳制接受: %s" % status)
        status, data, _ = self.i1.admin_json("GET", "/admin/preferred")
        self.assertEqual(status, 200)
        learned = (data or {}).get("learned") or {}
        entries = (learned.get("Sources") or []) + [learned]
        seen = [e.get("ExpiresAt") for e in entries
                if e.get("ExpiresAt") and "ttl-probe" in (e.get("Source"), "")]
        self.assertTrue(seen, "回读未见 ttl-probe 池: %r" % learned)
        now_ms = time.time() * 1000
        delta = (seen[0] - now_ms) / 1000.0
        self.assertTrue(50 <= delta <= 75,
                        "ttl=10 须钳至 60 (剩余 %.1fs)" % delta)


if __name__ == "__main__":
    unittest.main()
