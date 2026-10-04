"""批 1 基础设施冒烟: 单实例起停 + /health + 一次经受控假上游的 DoH 查询.

覆盖: build_bin / family_env / Instance 生命周期 (start → ready → SIGTERM →
退出码 0 与快照四件套) / FakeStack 双角色 / dnscodec 编解码 / preflight.
"""

import json
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# 受控 CF 网段表内容 (含冻结应答地址 104.16.132.229 所在的 104.16.0.0/13)
CF_V4_LIST = "\n".join([
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "",
])
CF_V6_LIST = "\n".join([
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/32", "",
])


class SmokeBatch1Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.query = (FIXTURES / "query_a_www_example_com.bin").read_bytes()
        cls.response = (FIXTURES / "response_a_www_example_com.bin").read_bytes()
        cls.u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="smoke-u1").start()
        cls.u1.add_doh("www.example.com", dnscodec.TYPE_A, cls.response)
        cls.cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="smoke-cfrange").start()
        cls.cfrange.add_path("/ips-v4", CF_V4_LIST)
        cls.cfrange.add_path("/ips-v6", CF_V6_LIST)
        cls.workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "smoke"
        if cls.workdir.exists():
            shutil.rmtree(cls.workdir)
        env = harness.family_env(
            "s_std",
            upstreams="%s/dns-query" % cls.u1.base_url,
            workdir=cls.workdir)
        cls.inst = harness.Instance("smoke-s-std", env,
                                    cls.workdir).start()

    @classmethod
    def tearDownClass(cls):
        inst = getattr(cls, "inst", None)
        if inst is not None and inst.proc is not None and not inst._stopped:
            inst.kill()  # 清理路径, 不做断言
        for stack in (getattr(cls, "u1", None),
                      getattr(cls, "cfrange", None)):
            if stack is not None:
                stack.stop()

    def test_10_health_ok(self):
        status, _, body = self.inst.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

    def test_20_doh_a_query_via_controlled_upstream(self):
        status, headers, body = self.inst.doh_get(self.query)
        self.assertEqual(status, 200)
        self.assertEqual(harness.header(headers, "Content-Type"),
                         "application/dns-message")
        packet = dnscodec.parse_packet(body)
        query_packet = dnscodec.parse_packet(self.query)
        self.assertEqual(packet["id"], query_packet["id"],
                         "事务 ID 必须回填请求 ID")
        self.assertEqual(packet["rcode"], 0)
        self.assertEqual(dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                         ["104.16.132.229"])
        # 受控上游恰好一次出向, 域名与类型匹配 (上游用户视角记录)
        outbound = self.u1.doh_queries()
        self.assertEqual(len(outbound), 1)
        self.assertEqual(outbound[0]["qname"], "www.example.com")
        self.assertEqual(outbound[0]["qtype"], dnscodec.TYPE_A)

    def test_30_graceful_shutdown_and_snapshots(self):
        code = self.inst.stop()  # SIGTERM, 断言退出码 0
        self.assertEqual(code, 0)
        snaps = harness.snapshot_paths(self.inst.env["CACHE_PERSIST_PATH"])
        for label, path in snaps.items():
            self.assertTrue(path.is_file(),
                            "快照缺失: %s (%s)" % (path, label))
        self.assertGreater(snaps["cache"].stat().st_size, 0,
                           "执行过查询后缓存快照不应为空")


if __name__ == "__main__":
    unittest.main()
