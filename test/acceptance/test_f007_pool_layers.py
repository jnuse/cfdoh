"""F-007 优选池分层 — 6 用例 (S-STD 三实例: 池拉取层 / 无远程层 / TTL 过期专用).

断言语义真源: .trellis/spec/prd/requirements.md F-007 节.
优先级: 显式参数 > 客户端 /24 专属池 > isp:<name> > isp:national > 自学习池
> 优选域名池; 窄层不足从宽层补足; 层 TTL 过期自动回落.
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

# 受控 ISP 表: 电信 /24, 联通 /24 (F-006 "<运营商> <CIDR>" 文本)
ISP_TABLE = "chinanet 1.2.4.0/24\nunicom 1.2.8.0/24\n"
CHINANET_CLIENT = "1.2.4.10"

# 池地址全部落在受控 CF 网段内 (104.16.0.0/13, 104.19/104.20 亦在其中)
CLIENT_POOL = ["104.20.1.1", "104.20.1.2"]
NATIONAL_POOL = ["104.19.1.1", "104.19.1.2", "104.19.1.3", "104.19.1.4"]
CHINANET_POOL = ["104.18.40.1", "104.18.40.2"]


def a_records_response(qid, qname, addresses, ttl=300):
    """构造 A 应答: question 回显 + 未压缩名字的 N 条 A 记录."""
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


def feed_pools_body(pools):
    return json.dumps({"pools": pools})


class F007PoolLayersTest(unittest.TestCase):
    """F-007: 分层取用, 窄层补足, 无共识交错, TTL 回落, 显式参数跳层."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f007-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f007-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)
            isp = fakestack.FakeStack(harness.STACK_PORTS["isp"], "files",
                                      name="f007-isp").start()
            isp.add_path("/isp.txt", ISP_TABLE)
            cls.stacks.append(isp)
            cfhub = fakestack.FakeStack(harness.STACK_PORTS["cfhub"],
                                        "files", name="f007-cfhub").start()
            cfhub.add_path("/pools", feed_pools_body([
                {"isp": "national", "name": "全国", "family": 4,
                 "ips": [{"ip": a} for a in NATIONAL_POOL],
                 "published": True}]))
            cls.stacks.append(cfhub)

            for n in ("lay7c.example.com", "lay7i.example.com",
                      "lay7n.example.com", "lay7e.example.com",
                      "lay7no1.example.com", "lay7no2.example.com",
                      "lay7t1.example.com", "lay7t2.example.com"):
                u1.add_doh(n, dnscodec.TYPE_A,
                           a_records_response(0x1234, n, ["104.16.132.229"]))
            # 优选域名池受控解析: 地址须与普通站点原址互异且在 CF 网段内
            # (104.21.9.9 ∈ 104.16.0.0/13)
            u1.add_doh("pref7.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "pref7.example.org",
                                          ["104.21.9.9"]))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f007"
            if workdir.exists():
                shutil.rmtree(workdir)

            # i1: isp 表 + 池拉取 national 层 — client/isp/补足用例
            env1 = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "i1",
                isp_url="%s/isp.txt" % isp.base_url,
                pool_feed_url="%s/pools" % cfhub.base_url,
                extra={"CF_REWRITE_ENABLED": "true",
                       "POOL_FEED_INTERVAL_SEC": "60"})
            cls.i1 = harness.Instance("f007-i1", env1,
                                      workdir / "i1").start()
            cls.instances.append(cls.i1)

            # i2: 无远程层, 优选域名池受控解析 — 共识/显式参数用例
            # (s_host 位: s_noadmin 位无 ADMIN_TOKEN, 上报面 404 不可用)
            env2 = harness.family_env(
                "s_host", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "i2",
                preferred_domains="pref7.example.org",
                extra={"CF_REWRITE_ENABLED": "true"})
            cls.i2 = harness.Instance("f007-i2", env2,
                                      workdir / "i2").start()
            cls.instances.append(cls.i2)

            # i3: TTL 过期专用 (只上报 ttl=60 的自学习池, 无其他层干扰)
            env3 = harness.family_env(
                "s_config", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "i3",
                preferred_domains="pref7.example.org",
                extra={"CF_REWRITE_ENABLED": "true"})
            cls.i3 = harness.Instance("f007-i3", env3,
                                      workdir / "i3").start()
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

    # ------------------------------------------------ helpers

    def _upload(self, inst, scope, ipv4, source, ttl=600, xreal=None):
        headers = {"Authorization": "Bearer " + harness.ADMIN_TOKEN,
                   "Content-Type": "application/json"}
        if xreal:
            headers["X-Real-IP"] = xreal
        status, _, _ = inst.request(
            "POST", "/admin/preferred", headers=headers,
            body=json.dumps({"ipv4": ipv4, "ipv6": [], "ttl": ttl,
                             "source": source, "scope": scope}).encode())
        self.assertTrue(200 <= status < 300,
                        "%s 池上报失败: %s" % (scope, status))

    def _query_a(self, inst, name, qid, xreal=None):
        query = dnscodec.build_query(qid, name, dnscodec.TYPE_A, edns=False)
        status, _, body = inst.doh_get(query, extra_headers=(
            {"X-Real-IP": xreal} if xreal else None))
        self.assertEqual(status, 200)
        return dnscodec.answer_addresses(dnscodec.parse_packet(body),
                                         dnscodec.TYPE_A)

    def _poll_until(self, fn, timeout=12.0, what=""):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = fn()
            if last:
                return last
            time.sleep(0.3)
        self.fail("等待超时: %s (最后: %r)" % (what, last))

    # ------------------------------------------------ 用例

    def test_f007_client_scope_pool(self):
        """F-007 AC1: 探针 /24 上报专属池, 同 /24 浏览器优先用该池."""
        self._upload(self.i1, "client", CLIENT_POOL, "probe-c",
                     xreal="198.51.100.10")

        def observed():
            got = set(self._query_a(self.i1, "lay7c.example.com", 0x7001,
                                    xreal="198.51.100.99"))
            # 优先语义: 专属池地址全部入选; 不足 6 条时允许宽层补足
            if (set(CLIENT_POOL) <= got
                    and got <= set(CLIENT_POOL) | set(NATIONAL_POOL)):
                return got
            return None

        got = self._poll_until(observed, what="client 专属池生效")
        self.assertTrue(got, "同 /24 客户端应答须优先用专属池: %r" % got)

    def test_f007_isp_layer(self):
        """F-007 AC: 电信 IP 用 isp:chinanet 池; 非电信 IP 不用该池."""
        self._upload(self.i1, "isp:chinanet", CHINANET_POOL, "probe-isp")

        def isp_serving():
            got = set(self._query_a(self.i1, "lay7i.example.com", 0x7002,
                                    xreal=CHINANET_CLIENT))
            # isp 层优先: 池内地址全部入选, 不足时允许 national 补足
            if (set(CHINANET_POOL) <= got
                    and got <= set(CHINANET_POOL) | set(NATIONAL_POOL)):
                return got
            return None

        got = self._poll_until(isp_serving, what="isp:chinanet 池生效")
        # 换非电信 / 非专属前缀 IP → 不得命中 chinanet 池
        got2 = set(self._query_a(self.i1, "lay7i.example.com", 0x7003,
                                 xreal="198.51.101.9"))
        self.assertEqual(got2, set(NATIONAL_POOL),
                         "非电信且无专属池的客户端应落 national 层: %r" % got2)

    def test_f007_narrow_fills_from_wide(self):
        """F-007: 专属池仅 2 地址 → 应答含 2 专属 + 补自 national 层."""
        self._upload(self.i1, "client", CLIENT_POOL, "probe-c2",
                     xreal="198.51.100.10")

        def filled():
            got = set(self._query_a(self.i1, "lay7n.example.com", 0x7004,
                                    xreal="198.51.100.99"))
            if (set(CLIENT_POOL) <= got
                    and got & set(NATIONAL_POOL)
                    and got <= set(CLIENT_POOL) | set(NATIONAL_POOL)
                    and len(got) <= 6):
                return got
            return None

        got = self._poll_until(filled, what="专属池 + national 补足")
        self.assertTrue(got, "应答须为 2 专属地址 + national 补足: %r" % got)

    def test_f007_no_consensus_interleave(self):
        """F-007: 3 source 不相交列表无多数共识 → 交错合并覆盖 ≥2 source."""
        groups = [["104.16.201.1", "104.16.201.2"],
                  ["104.16.202.1", "104.16.202.2"],
                  ["104.16.203.1", "104.16.203.2"]]
        for i, addrs in enumerate(groups):
            self._upload(self.i2, "default", addrs, "probe-%d" % i)

        def covered():
            got = set(self._query_a(self.i2, "lay7no1.example.com", 0x7005))
            hits = sum(1 for g in groups if got & set(g))
            return got if hits >= 2 else None

        got = self._poll_until(covered, what="无共识交错合并 (≥2 source)")
        self.assertTrue(got, "应答须覆盖 ≥2 个 source 的贡献: %r" % got)

    def test_f007_ttl_expiry_fallback(self):
        """F-007 AC: 探针池 ttl=60, 停止上报到期 → 回落优选域名池.

        等待成因: 池上报 ttl 钳制下限为 60 (F-008), 无法更短; 需 61s 让
        自学习池过期, 才能观察到逐层回落. 第二查询用新域名, 避开首查询
        已写入的 300s 应答缓存.
        """
        self._upload(self.i3, "default", ["104.16.210.1", "104.16.210.2"],
                     "probe-ttl", ttl=60)
        first = set(self._query_a(self.i3, "lay7t1.example.com", 0x7006))
        self.assertEqual(first, {"104.16.210.1", "104.16.210.2"},
                         "过期前应答须来自探针池: %r" % first)
        time.sleep(61)

        def fell_back():
            got = set(self._query_a(self.i3, "lay7t2.example.com", 0x7007))
            return got if got == {"104.21.9.9"} else None

        # 优选域名 pref7.example.org 受控解析为 104.21.9.9, 与普通站点原址
        # 104.16.132.229 互异, 回落可区分.
        got = self._poll_until(fell_back, timeout=15.0,
                               what="探针池过期后回落优选域名池")
        self.assertTrue(got, "探针池过期后应回落优选域名池: %r" % got)

    def test_f007_explicit_skips_learned(self):
        """F-007: 已有 default 池时 ?ip4= 显式参数跳过学习池."""
        self._upload(self.i2, "default", ["104.16.220.1", "104.16.220.2"],
                     "probe-e")
        query = dnscodec.build_query(0x7008, "lay7e.example.com",
                                     dnscodec.TYPE_A, edns=False)
        status, _, body = self.i2.request(
            "GET", "/dns-query?dns=%s&ip4=203.0.113.77"
            % dnscodec.b64url_encode(query),
            headers={"Accept": "application/dns-message"})
        self.assertEqual(status, 200)
        got = dnscodec.answer_addresses(dnscodec.parse_packet(body),
                                        dnscodec.TYPE_A)
        self.assertEqual(got, ["203.0.113.77"],
                         "显式 ?ip4 须跳过学习池直接生效: %r" % got)


if __name__ == "__main__":
    unittest.main()
