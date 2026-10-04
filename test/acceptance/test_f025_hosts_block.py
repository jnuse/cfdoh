"""F-025 hosts 管理 — 1 用例 (cfhost 进程级, C1 族).

断言语义真源: .trellis/spec/prd/requirements.md F-025 节.

测速结果注入通道排查结论 (取舍 #5 判定, 2026-10 批 5 实查):
- internal/cfhost/config.go 的 env 全集 (CFHOST_CONFIG/MANAGED_DOMAINS/
  SOURCES/CONCURRENCY/TIMEOUT_MS/ROUNDS/HYSTERESIS/FAILOVER_ROUNDS/
  INTERVAL_MIN/HOSTS_PATH/STATE_PATH/CANDIDATE_LIMIT/HTTP_VERIFY) 与
  cmd/cfhost/main.go 的 flag 集均无测速结果注入项;
- probe 的可替换 seam (newProbeTLSConfig) 是 Go 包内变量, 仅 Go 单测可换,
  进程外不可达.
→ 无注入通道, 按取舍 #5 以 "测速全失败不重写" 为等价面: 静态源单地址 +
probe 全败 → hosts 区块外逐字节保留 (整个文件逐字节不变, 强于区块外).
区块两行写入格式由 Go 单测 (hosts_test.go) 覆盖, 验收层不重复.
"""

import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import harness  # noqa: E402

# 区块外内容刻意带: 注释行, 用户手动条目, 空行, 无尾换行的末行 —
# 逐字节保留断言对全部形态生效.
HOSTS_BEFORE = (b"# my custom hosts\n"
                b"203.0.113.201 manual.example\n"
                b"\n"
                b"# BEGIN cfhost\n"
                b"203.0.113.8 keep.example.org\n"
                b"# END cfhost\n"
                b"# trailing comment without newline")


class F025HostsBlockTest(unittest.TestCase):
    """F-025: 测速全败 → hosts 区块外逐字节保留 (取舍 #5 等价面)."""

    @classmethod
    def setUpClass(cls):
        cls.base = harness.REPO_ROOT / ".cache" / "acceptance" / "f025"
        if cls.base.exists():
            shutil.rmtree(cls.base)

    def test_f025_block_written(self):
        """F-025 AC (等价面): 静态源单地址 + 测速全败 → hosts 逐字节不变."""
        wd = self.base / "keepblock"
        env = harness.cfhost_env(
            wd, sources=["list:203.0.113.2"],
            managed_domains="keep.example.org",
            extra={"CFHOST_TIMEOUT_MS": "250", "CFHOST_ROUNDS": "1"})
        hosts = Path(env["CFHOST_HOSTS_PATH"])
        hosts.write_bytes(HOSTS_BEFORE)

        proc = harness.CfhostProc("f025-keepblock", env, wd,
                                  args=("run-once",)).run()
        self.assertEqual(proc.returncode, 0,
                         "全败路径 run-once 须正常退出: %s" % proc.stderr.strip())

        self.assertEqual(hosts.read_bytes(), HOSTS_BEFORE,
                         "hosts 区块外内容 (含无尾换行末行) 须逐字节保留")
        state = harness.cfhost_state(env)
        self.assertEqual(state["current_v4"], "",
                          "测速全败不得采纳任何地址为在用地址")


if __name__ == "__main__":
    unittest.main()
