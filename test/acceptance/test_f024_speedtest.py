"""F-024 本地测速与选优 — 1 用例 (cfhost 进程级, C1 族).

断言语义真源: .trellis/spec/prd/requirements.md F-024 节.
已知取舍 #4: 滞回/强制重选由 Go 表驱动单测覆盖, 验收层只测用户可观察的
"测速全败保现状": 候选全为不可达公网地址 (203.0.113.x TEST-NET) →
run-once 退出 0, hosts 区块内容不变, 状态含淘汰标记.
淘汰标记的用户可观察面: last_summary 的 best_v4=none / ok=0 + fail_streak ≥ 1.
"""

import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import harness  # noqa: E402

# 预置 hosts: 区块外用户条目 + 带标记区块内的旧地址 (须逐字节保持)
HOSTS_BEFORE = (b"127.0.0.1 localhost.localdomain\n"
                b"203.0.113.200 my-own-entry.example\n"
                b"# BEGIN cfhost\n"
                b"203.0.113.9 keep.example.org\n"
                b"# END cfhost\n")


class F024SpeedtestTest(unittest.TestCase):
    """F-024: 候选全部测速失败 → hosts 保持现状, 状态记淘汰."""

    @classmethod
    def setUpClass(cls):
        cls.base = harness.REPO_ROOT / ".cache" / "acceptance" / "f024"
        if cls.base.exists():
            shutil.rmtree(cls.base)

    def test_f024_all_fail_keep_hosts(self):
        """F-024 AC: 候选全不可达 → run-once 退出 0, hosts 区块不变, 状态含淘汰标记."""
        wd = self.base / "allfail"
        env = harness.cfhost_env(
            wd, sources=["list:203.0.113.1"],
            managed_domains="keep.example.org",
            extra={"CFHOST_TIMEOUT_MS": "250", "CFHOST_ROUNDS": "1"})
        hosts = Path(env["CFHOST_HOSTS_PATH"])
        hosts.write_bytes(HOSTS_BEFORE)

        proc = harness.CfhostProc("f024-allfail", env, wd,
                                  args=("run-once",)).run()
        self.assertEqual(proc.returncode, 0,
                         "测速全败须保现状正常退出, 不得报错: %s"
                         % proc.stderr.strip())

        self.assertEqual(hosts.read_bytes(), HOSTS_BEFORE,
                         "测速全败时 hosts 整个文件 (含区块) 逐字节不变")

        state = harness.cfhost_state(env)
        self.assertIn("best_v4=none", state["last_summary"],
                      "状态摘要须含淘汰标记 best_v4=none: %r"
                      % state["last_summary"])
        self.assertIn("ok=0", state["last_summary"],
                      "全部候选淘汰后 ok 计数须为 0")
        self.assertGreaterEqual(state["fail_streak"], 1,
                                "连续失败计数须开始累积")
        self.assertEqual(state["candidates"], ["203.0.113.1"],
                          "上轮候选如实记录, 供下轮兜底")


if __name__ == "__main__":
    unittest.main()
