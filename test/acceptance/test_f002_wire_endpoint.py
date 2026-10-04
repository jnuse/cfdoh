"""F-002 DNS wire 编解码 — 端点可观察面 3 用例 (S-STD).

完整 wire 语义由 Go 单测负责; 此处仅断言攻击包打 DoH 端点得到 400
(解析拒绝而非死循环). 攻击包字节为 fixtures 冻结 fixture.
"""

import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST


class F002WireEndpointTest(unittest.TestCase):
    """F-002: 攻击包打端点 → 400, 不死循环 (超时即红)."""

    @classmethod
    def setUpClass(cls):
        cls.pointer_loop = (FIXTURES / "attack_pointer_loop.bin").read_bytes()
        cls.high_label = (FIXTURES / "attack_high_label.bin").read_bytes()
        cls.oversized = (FIXTURES
                         / "attack_oversized_qdcount.bin").read_bytes()
        cls.u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f002-u1").start()
        cls.cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f002-cfrange").start()
        cls.cfrange.add_path("/ips-v4", CF_V4_LIST)
        cls.cfrange.add_path("/ips-v6", CF_V6_LIST)
        cls.workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f002"
        if cls.workdir.exists():
            shutil.rmtree(cls.workdir)
        env = harness.family_env(
            "s_std",
            upstreams="%s/dns-query" % cls.u1.base_url,
            workdir=cls.workdir)
        cls.inst = harness.Instance("f002-s-std", env, cls.workdir).start()

    @classmethod
    def tearDownClass(cls):
        inst = getattr(cls, "inst", None)
        if inst is not None and inst.proc is not None and not inst._stopped:
            inst.kill()
        for stack in (getattr(cls, "u1", None),
                      getattr(cls, "cfrange", None)):
            if stack is not None:
                stack.stop()

    def test_f002_pointer_loop_400(self):
        """F-002: 压缩指针成环 fixture → 400 (防环, 不死循环)."""
        status, _, _ = self.inst.doh_get(self.pointer_loop, timeout=15.0)
        self.assertEqual(status, 400)

    def test_f002_high_label_400(self):
        """F-002: 0x40 高位 label fixture → 400."""
        status, _, _ = self.inst.doh_get(self.high_label, timeout=15.0)
        self.assertEqual(status, 400)

    def test_f002_oversized_counts_400(self):
        """F-002: qdcount=33 (>32) fixture → 400."""
        status, _, _ = self.inst.doh_get(self.oversized, timeout=15.0)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
