"""F-028 公开池拉取 — 5 用例 (S-STD, 受控 cfhub 角色).

断言语义真源: .trellis/spec/prd/requirements.md F-028 节 与
.trellis/spec/arch/hubfeed.md.
cfhub 为 fakestack files 角色 (18105), 应答按用例编程; 拉取周期取钳制下限
60s (POOL_FEED_INTERVAL_SEC). 等待用例 1 个 (~65s): 周期刷新须真实失败一次
后断言旧池沿用, 语义才非空.
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

ISP_TABLE = "chinanet 1.2.4.0/24\nunicom 1.2.8.0/24\n"
CHINANET_CLIENT = "1.2.4.10"
UPSTREAM_ORIGIN = "104.16.132.229"


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


def feed_doc(pools):
    """构造 cfhub 公开池 API 应答: [(isp, published, [ip...])] → JSON."""
    return json.dumps({"pools": [
        {"isp": isp, "name": isp, "family": 4,
         "ips": [{"ip": ip} for ip in ips], "published": published}
        for isp, published, ips in pools]})


class F028CfhubFeedTest(unittest.TestCase):
    """F-028: 拉取入池, 污染池整池拒绝, 未发布跳过, 每族上限 6, 失败沿用旧池."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f028-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            for n in ("feed1.example.com", "cap1.example.com",
                      "old1.example.com", "old2.example.com"):
                u1.add_doh(n, dnscodec.TYPE_A,
                           a_records_response(0, n, [UPSTREAM_ORIGIN]))
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f028-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)
            isp = fakestack.FakeStack(harness.STACK_PORTS["isp"], "files",
                                      name="f028-isp").start()
            isp.add_path("/isp.txt", ISP_TABLE)
            cls.stacks.append(isp)
            cls.isp = isp
            cfhub = fakestack.FakeStack(harness.STACK_PORTS["cfhub"],
                                        "files", name="f028-cfhub").start()
            cfhub.add_path("/pools", "{}", "application/json")
            cls.stacks.append(cfhub)
            cls.cfhub = cfhub
            cls.base = harness.REPO_ROOT / ".cache" / "acceptance" / "f028"
            if cls.base.exists():
                shutil.rmtree(cls.base)
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

    # ------------------------------------------------------------ 辅助

    def _set_feed(self, doc):
        self.cfhub.set_path_content("/pools", doc, "application/json")

    def _start_case(self, name, subdir):
        env = harness.family_env(
            "s_std", upstreams="%s/dns-query" % self.u1.base_url,
            workdir=self.base / subdir,
            isp_url="%s/isp.txt" % self.isp.base_url,
            pool_feed_url="%s/pools" % self.cfhub.base_url,
            extra={"CF_REWRITE_ENABLED": "true",
                   "POOL_FEED_INTERVAL_SEC": "60"})
        inst = harness.Instance(name, env, self.base / subdir).start()
        self.instances.append(inst)
        return inst

    def _isp_pools(self, inst):
        status, data, _ = inst.admin_json("GET", "/admin/preferred")
        if status != 200:
            return None
        return (data or {}).get("isp") or []

    def _pool_of(self, pools, scope):
        for p in pools:
            if p.get("Scope") == scope:
                return p
        return None

    def _poll_until(self, fn, timeout=15.0, what=""):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = fn()
            if last:
                return last
            time.sleep(0.3)
        self.fail("等待超时: %s (最后: %r)" % (what, last))

    def _query_a(self, inst, qid, qname):
        query = dnscodec.build_query(qid, qname, dnscodec.TYPE_A, edns=False)
        status, _, body = inst.doh_get(
            query, extra_headers={"X-Real-IP": CHINANET_CLIENT})
        self.assertEqual(status, 200)
        return set(dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A))

    def _wait_ingested(self, inst, ips, scope="isp:chinanet"):
        def ingested():
            pool = self._pool_of(self._isp_pools(inst) or [], scope)
            if pool and pool.get("IPv4") == ips:
                return pool
            return None

        return self._poll_until(ingested, timeout=20.0,
                                what="公开池拉取入池 %s" % scope)

    # ------------------------------------------------------------ 用例

    def test_f028_isp_pool_ingested(self):
        """F-028 AC: API 含已发布电信池 → isp:chinanet 生效, 查询应答池内."""
        ips = ["104.18.52.1", "104.18.52.2", "104.18.52.3"]
        self._set_feed(feed_doc([("chinanet", True, ips)]))
        inst = self._start_case("f028-ingest", "ingest")
        try:
            pool = self._wait_ingested(inst, ips)
            self.assertEqual(pool.get("IPv4"), ips, "入池顺序须保持 API 顺序")
            # 浏览器 (电信客户端) 观察到该池 (ISP 表惰性加载 → 轮询至翻转)
            def serving():
                got = self._query_a(inst, 0x2801, "feed1.example.com")
                return got if got == set(ips) else None

            got = self._poll_until(serving, what="浏览器观察到拉取池生效")
            self.assertEqual(got, set(ips))
        finally:
            inst.kill()

    def test_f028_polluted_pool_rejected(self):
        """F-028 AC: 污染池 (含非 CF 网段地址) 整池拒绝, 干净池照常写入."""
        clean = ["104.18.50.1", "104.18.50.2"]
        self._set_feed(feed_doc([
            ("chinanet", True, clean),
            ("unicom", True, ["203.0.113.9", "104.18.50.3"])]))
        inst = self._start_case("f028-polluted", "polluted")
        try:
            self._wait_ingested(inst, clean)  # 同一响应里的干净池作锚点
            pools = self._isp_pools(inst)
            self.assertIsNone(self._pool_of(pools, "isp:unicom"),
                              "污染池须整池拒绝: %r" % pools)
        finally:
            inst.kill()

    def test_f028_unpublished_skipped(self):
        """F-028: published=false 池 → 不采用."""
        clean = ["104.18.51.1", "104.18.51.2"]
        self._set_feed(feed_doc([
            ("chinanet", True, clean),
            ("unicom", False, ["104.18.51.9", "104.18.51.10"])]))
        inst = self._start_case("f028-unpub", "unpub")
        try:
            self._wait_ingested(inst, clean)  # 同一响应里的已发布池作锚点
            pools = self._isp_pools(inst)
            self.assertIsNone(self._pool_of(pools, "isp:unicom"),
                              "未发布池不得采用: %r" % pools)
        finally:
            inst.kill()

    def test_f028_family_cap_six(self):
        """F-028: 池给 10 地址 → 每族至多 6 条, 顺序 = API 顺序."""
        ips = ["104.18.60.%d" % i for i in range(1, 11)]
        self._set_feed(feed_doc([("chinanet", True, ips)]))
        inst = self._start_case("f028-cap", "cap")
        try:
            pool = self._wait_ingested(inst, ips[:6])
            self.assertEqual(pool.get("IPv4"), ips[:6],
                             "入池须截取前 6 条且保持 API 顺序")

            def serving():
                got = self._query_a(inst, 0x2802, "cap1.example.com")
                return got if got == set(ips[:6]) else None

            got = self._poll_until(serving, what="浏览器观察到截断后的池")
            self.assertEqual(got, set(ips[:6]), "服务应答至多 6 条")
            self.assertNotIn("104.18.60.7", got, "第 7 条及以后不得服务")
        finally:
            inst.kill()

    def test_f028_failure_keeps_old(self):
        """F-028 AC: 首拉成功 → API 改 500 → 拉取失败沿用旧池.

        等待成因: 拉取周期取钳制下限 60s, 须等周期刷新真实失败一次 (~65s)
        后断言旧池仍在有效期内 (POOL_FEED_TTL_SEC 默认 1800) 持续服务,
        否则 "失败沿用旧池" 语义未被检验.
        """
        old = ["104.18.55.1", "104.18.55.2", "104.18.55.3"]
        self._set_feed(feed_doc([("chinanet", True, old)]))
        inst = self._start_case("f028-keepold", "keepold")
        try:
            self._wait_ingested(inst, old)

            def serving_old1():
                got = self._query_a(inst, 0x2803, "old1.example.com")
                return got if got == set(old) else None

            got = self._poll_until(serving_old1, what="首拉成功后池生效")
            self.assertEqual(got, set(old))

            self.cfhub.set_path_content("/pools", "internal error",
                                        "text/plain; charset=utf-8", 500)
            time.sleep(65)  # 60s 周期刷新须真实失败一次

            pool = self._pool_of(self._isp_pools(inst) or [], "isp:chinanet")
            self.assertIsNotNone(pool, "拉取失败后旧池不得被清空")
            self.assertEqual(pool.get("IPv4"), old)
            # 全新 qname (绕开缓存) 仍旧池内应答
            got = self._query_a(inst, 0x2804, "old2.example.com")
            self.assertEqual(got, set(old),
                             "拉取失败期间解析须继续用旧池应答: %r" % got)
        finally:
            inst.kill()


if __name__ == "__main__":
    unittest.main()
