"""跨用户流 — 2 用例 (S-STD 双实例: 探针上报流 / 公开池拉取流).

断言语义真源: .trellis/spec/prd/requirements.md F-006/F-007/F-028 与
本任务 testplan.md 跨用户流节.
探针上报 → 浏览器观察到池生效; 受控 cfhub 污染池整池拒绝,
干净池照常服务, 浏览器应答不受污染影响.
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
UPSTREAM_ORIGIN = {"104.16.132.229"}
PROBE_POOL = {"104.18.60.1", "104.18.60.2"}
FEED_CLEAN = ["104.18.50.1", "104.18.50.2"]


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class FlowCrossUserTest(unittest.TestCase):
    """跨用户流: 探针 → 浏览器; 污染 hubfeed → 浏览器隔离."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="flow-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="flow-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)
            isp = fakestack.FakeStack(harness.STACK_PORTS["isp"], "files",
                                      name="flow-isp").start()
            isp.add_path("/isp.txt", ISP_TABLE)
            cls.stacks.append(isp)
            cfhub = fakestack.FakeStack(harness.STACK_PORTS["cfhub"],
                                        "files", name="flow-cfhub").start()
            # 干净 chinanet 池 + 污染 unicom 池 (混入非 CF 网段地址,
            # 整池不得采用, F-028 语义在跨用户流上的观察面)
            cfhub.add_path("/pools", json.dumps({"pools": [
                {"isp": "chinanet", "name": "电信", "family": 4,
                 "ips": [{"ip": a} for a in FEED_CLEAN], "published": True},
                {"isp": "unicom", "name": "联通", "family": 4,
                 "ips": [{"ip": "203.0.113.9"}, {"ip": "104.18.50.3"}],
                 "published": True}]}))
            cls.stacks.append(cfhub)

            for n in ("flowprobe.example.com", "flowfeed.example.com",
                      "flowwarm.example.com"):
                u1.add_doh(n, dnscodec.TYPE_A,
                           a_records_response(0x1234, n, ["104.16.132.229"]))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "flow"
            if workdir.exists():
                shutil.rmtree(workdir)
            env1 = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "probe",
                isp_url="%s/isp.txt" % isp.base_url,
                extra={"CF_REWRITE_ENABLED": "true"})
            cls.i_probe = harness.Instance("flow-probe", env1,
                                           workdir / "probe").start()
            cls.instances.append(cls.i_probe)

            env2 = harness.family_env(
                "s_drop", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "feed",
                isp_url="%s/isp.txt" % isp.base_url,
                pool_feed_url="%s/pools" % cfhub.base_url,
                extra={"CF_REWRITE_ENABLED": "true",
                       "POOL_FEED_INTERVAL_SEC": "60"})
            cls.i_feed = harness.Instance("flow-feed", env2,
                                          workdir / "feed").start()
            cls.instances.append(cls.i_feed)
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

    def _query_a(self, inst, name, qid, xreal):
        query = dnscodec.build_query(qid, name, dnscodec.TYPE_A, edns=False)
        status, _, body = inst.doh_get(
            query, extra_headers={"X-Real-IP": xreal})
        self.assertEqual(status, 200)
        return set(dnscodec.answer_addresses(
            dnscodec.parse_packet(body), dnscodec.TYPE_A))

    def _poll_until(self, fn, timeout=15.0, what=""):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = fn()
            if last:
                return last
            time.sleep(0.3)
        self.fail("等待超时: %s (最后: %r)" % (what, last))

    def test_flow_probe_to_browser(self):
        """跨用户流 1: 探针上报 isp 池 → 浏览器同网段观察到翻转."""
        # 上报前: 浏览器拿到上游原址
        before = self._query_a(self.i_probe, "flowprobe.example.com",
                               0x1001, CHINANET_CLIENT)
        self.assertEqual(before, UPSTREAM_ORIGIN,
                         "上报前应答须为上游原址: %r" % before)
        # 探针上报 (电信 IP 身份)
        status, _, _ = self.i_probe.admin_json(
            "POST", "/admin/preferred",
            payload={"ipv4": sorted(PROBE_POOL), "ipv6": [], "ttl": 600,
                     "source": "probe-1", "scope": "isp:chinanet"})
        self.assertTrue(200 <= status < 300, "探针上报失败: %s" % status)
        # ISP 表为查询驱动惰性加载: 预热轮询至池对浏览器可观察
        def flipped():
            got = self._query_a(self.i_probe, "flowprobe.example.com",
                                0x1002, CHINANET_CLIENT)
            return got if got == PROBE_POOL else None

        got = self._poll_until(flipped, what="探针上报后浏览器观察到池翻转")
        self.assertEqual(got, PROBE_POOL,
                         "上报后浏览器应答须翻转到探针池: %r" % got)

    def test_flow_hubfeed_pollution_isolated(self):
        """跨用户流 2: 污染池整池不入, 干净池生效, 浏览器应答正常."""
        def fed():
            status, data, _ = self.i_feed.admin_json("GET",
                                                     "/admin/preferred")
            if status != 200:
                return None
            pools = (data or {}).get("isp") or []
            scopes = {p.get("Scope") for p in pools}
            if "isp:chinanet" in scopes:
                return pools
            return None

        pools = self._poll_until(fed, timeout=20.0, what="公开池拉取入池")
        scopes = {p.get("Scope") for p in pools}
        self.assertNotIn(
            "isp:unicom", scopes,
            "含非 CF 网段地址的污染池须整池拒绝: %r" % scopes)
        chinanet = [p for p in pools if p.get("Scope") == "isp:chinanet"]
        self.assertEqual(chinanet[0].get("IPv4"), FEED_CLEAN,
                         "干净池须照常入池且顺序保持: %r" % chinanet)
        # 浏览器 (电信客户端) 应答来自干净池, 不受污染影响
        def clean_serving():
            got = self._query_a(self.i_feed, "flowfeed.example.com",
                                0x1003, CHINANET_CLIENT)
            return got if got == set(FEED_CLEAN) else None

        got = self._poll_until(clean_serving, what="浏览器观察到干净池")
        self.assertEqual(got, set(FEED_CLEAN),
                         "浏览器应答须来自干净池: %r" % got)


if __name__ == "__main__":
    unittest.main()
