"""F-019 健康与探针端点 — 4 用例 (S-STD).

断言语义真源: .trellis/spec/prd/requirements.md F-019 节.
/health 方法矩阵 (GET 200 ok, 其他 405); /probe 回显客户端 IP 与部署信息.
"""

import json
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import fakestack, harness  # noqa: E402

CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST


class F019HealthProbeTest(unittest.TestCase):
    """F-019: /health 存活检查与 /probe 请求环境回显的方法矩阵."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f019-u1").start()
            cls.stacks.append(u1)
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f019-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)
            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f019"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env("s_std",
                                     upstreams="%s/dns-query" % u1.base_url,
                                     workdir=workdir)
            cls.inst = harness.Instance("f019-s-std", env,
                                        workdir).start()
            cls.instances.append(cls.inst)
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

    def test_f019_health_ok(self):
        """F-019 AC: GET /health → 200 且 ok 为 true."""
        status, _, body = self.inst.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body).get("ok"), True)

    def test_f019_health_405(self):
        """F-019 AC: /health 其他方法 → 405."""
        status, _, _ = self.inst.request("POST", "/health")
        self.assertEqual(status, 405)
        status, _, _ = self.inst.request("DELETE", "/health")
        self.assertEqual(status, 405)

    def test_f019_probe_echo(self):
        """F-019 AC: GET /probe → 200 含 client_ip 与版本字段 (TCP 对端回显)."""
        status, _, body = self.inst.request("GET", "/probe")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get("client_ip"), "127.0.0.1",
                         "无识别头时须回显 TCP 对端地址: %r" % data)
        self.assertTrue(isinstance(data.get("version"), str)
                        and data["version"] != "",
                         "version 字段须为非空字符串: %r" % data)

    def test_f019_probe_405(self):
        """F-019 AC: /probe 其他方法 → 405."""
        status, _, _ = self.inst.request("POST", "/probe")
        self.assertEqual(status, 405)
        status, _, _ = self.inst.request("PUT", "/probe")
        self.assertEqual(status, 405)


if __name__ == "__main__":
    unittest.main()
