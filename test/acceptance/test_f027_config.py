"""F-027 客户端配置 — 3 用例 (cfhost 进程级, C1 族).

断言语义真源: .trellis/spec/prd/requirements.md F-027 节 与
.trellis/spec/arch/cfhost.md (配置项, 必填项, 环境变量优先).

沙箱边界说明: CFHOST_HOSTS_PATH / CFHOST_STATE_PATH / CFHOST_CONFIG 在全部
用例中指向 .cache/acceptance 沙箱 — 这是测试隔离必需, 不属于被验收的
可调参数; 最小配置用例除两项必填外不设任何可调参数 (测速/并发/周期全取
产品默认值).
"""

import json
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import harness  # noqa: E402

HOSTS_SENTINEL = b"203.0.113.200 untouched-manual-entry.example\n"


class F027ConfigTest(unittest.TestCase):
    """F-027: 最小配置运行, 空域名报错退出, 环境变量优先于配置文件."""

    @classmethod
    def setUpClass(cls):
        cls.base = harness.REPO_ROOT / ".cache" / "acceptance" / "f027"
        if cls.base.exists():
            shutil.rmtree(cls.base)

    def _write_config(self, wd, doc):
        wd.mkdir(parents=True, exist_ok=True)
        path = wd / "cfhost.json"
        path.write_text(json.dumps(doc))
        return path

    def test_f027_minimal_config(self):
        """F-027 AC: 仅域名与源 → run-once 其余参数取默认值正常运行.

        默认测速参数 (timeout 2000ms × 3 轮) 保持不动 — 单候选最坏 ~6s.
        """
        wd = self.base / "minimal"
        config = self._write_config(
            wd, {"managed_domains": ["minimal.example.org"],
                 "sources": ["list:203.0.113.60"]})
        env = harness.cfhost_env(wd, config=config)

        proc = harness.CfhostProc("f027-minimal", env, wd,
                                  args=("run-once",)).run(timeout=60)
        self.assertEqual(proc.returncode, 0,
                         "最小配置 run-once 须以默认参数正常运行: %s"
                         % proc.stderr.strip())
        state = harness.cfhost_state(env)
        self.assertEqual(state["candidates"], ["203.0.113.60"])
        self.assertEqual(state["last_summary"], "tested=1 ok=0 best_v4=none 0ms",
                         "默认测速参数完整执行一轮 (1 候选全淘汰)")

    def test_f027_empty_domains_abort(self):
        """F-027 AC: 域名列表空 → 非 0 退出且 hosts 未被修改."""
        wd = self.base / "emptydom"
        config = self._write_config(wd, {"sources": ["list:203.0.113.61"]})
        env = harness.cfhost_env(wd, config=config)
        hosts = Path(env["CFHOST_HOSTS_PATH"])
        hosts.write_bytes(HOSTS_SENTINEL)

        proc = harness.CfhostProc("f027-emptydom", env, wd,
                                  args=("run-once",)).run()
        self.assertNotEqual(proc.returncode, 0, "空域名列表须报错退出")
        self.assertIn("managed_domains", proc.stderr,
                      "报错须指向必填项缺失: %s" % proc.stderr.strip())
        self.assertEqual(hosts.read_bytes(), HOSTS_SENTINEL,
                         "报错退出路径不得修改 hosts")

    def test_f027_env_overrides_file(self):
        """F-027 AC: 配置文件与环境变量同键 → 环境变量生效.

        文件指定状态文件 A, 环境变量指定状态文件 B; run-once 后状态落 B
        且 A 不存在 — 路径抉择完全可观察.
        """
        wd = self.base / "envover"
        config = self._write_config(
            wd, {"managed_domains": ["ovr.example.org"],
                 "sources": ["list:203.0.113.62"],
                 "state_path": str(wd / "state-a.json")})
        state_b = wd / "state-b" / "cfhost-state.json"
        env = harness.cfhost_env(
            wd, config=config,
            extra={"CFHOST_STATE_PATH": str(state_b),
                   "CFHOST_TIMEOUT_MS": "250", "CFHOST_ROUNDS": "1"})

        proc = harness.CfhostProc("f027-envover", env, wd,
                                  args=("run-once",)).run()
        self.assertEqual(proc.returncode, 0,
                         "run-once 须正常退出: %s" % proc.stderr.strip())
        self.assertTrue(state_b.is_file(),
                        "状态文件须落在环境变量指定的 B 路径")
        self.assertEqual(json.loads(state_b.read_text())["candidates"],
                         ["203.0.113.62"])
        self.assertFalse((wd / "state-a.json").exists(),
                         "配置文件指定的 A 路径不得被使用")


if __name__ == "__main__":
    unittest.main()
