"""F-023 候选拉取与校验 — 3 用例 (cfhost 进程级, C1 族).

断言语义真源: .trellis/spec/prd/requirements.md F-023 节.
候选 API 源为 fakestack files 角色 (cfhub 端口 18105), 受控 https;
run-once 后从状态文件 candidates 字段断言上轮候选 (用户可观察面).
已知取舍 #3: domain: 源依赖系统 DNS 不可控, 不入验收.
测速提速: 候选全为不可达 TEST-NET 地址, TIMEOUT_MS=250/ROUNDS=1 快速淘汰.
"""

import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import fakestack, harness  # noqa: E402

FAST_PROBE = {"CFHOST_TIMEOUT_MS": "250", "CFHOST_ROUNDS": "1"}


class F023MultiSourceTest(unittest.TestCase):
    """F-023: 多源合并去重, 单源失败容忍, 私网过滤."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        try:
            src = fakestack.FakeStack(harness.STACK_PORTS["cfhub"], "files",
                                      name="f023-candsrc").start()
            cls.stacks.append(src)
            cls.src = src
            cls.base = harness.REPO_ROOT / ".cache" / "acceptance" / "f023"
            if cls.base.exists():
                shutil.rmtree(cls.base)
        except Exception:
            for stack in cls.stacks:
                stack.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        for stack in cls.stacks:
            stack.stop()

    def _run_once(self, wd_name, sources):
        wd = self.base / wd_name
        env = harness.cfhost_env(wd, sources=sources,
                                 managed_domains="probe.example.org",
                                 extra=FAST_PROBE)
        proc = harness.CfhostProc("f023-" + wd_name, env, wd,
                                  args=("run-once",)).run()
        return env, proc

    def test_f023_multi_source_union(self):
        """F-023 AC: API 源 + list 静态源 → 上轮候选为两源并集去重."""
        self.src.add_path("/union", "203.0.113.10\n203.0.113.11\n")
        env, proc = self._run_once(
            "union",
            ["%s/union" % self.src.base_url, "list:203.0.113.10,203.0.113.12"])
        self.assertEqual(proc.returncode, 0,
                         "run-once 须正常退出: %s" % proc.stderr.strip())
        self.assertGreaterEqual(self.src.request_count("/union"), 1,
                                "API 源须被真实拉取")
        state = harness.cfhost_state(env)
        self.assertEqual(state["candidates"],
                         ["203.0.113.10", "203.0.113.11", "203.0.113.12"],
                         "候选须为两源并集, 首见序去重 (跨源重复项只留一次)")

    def test_f023_single_source_failure(self):
        """F-023 AC: API 源 500 + list 源正常 → 候选仍含 list 项, 退出 0."""
        self.src.add_path("/fail500", "203.0.113.20\n",
                          fail={"status": 500, "times": None})
        env, proc = self._run_once(
            "fail500",
            ["%s/fail500" % self.src.base_url, "list:203.0.113.30,203.0.113.31"])
        self.assertEqual(proc.returncode, 0,
                         "单源失败须容忍, run-once 正常退出: %s"
                         % proc.stderr.strip())
        state = harness.cfhost_state(env)
        self.assertEqual(state["candidates"],
                         ["203.0.113.30", "203.0.113.31"],
                         "失败源的其余源结果照常进入候选, 失败源无任何混入")

    def test_f023_private_filtered(self):
        """F-023 AC: API 返回含 192.168.1.1 → 候选无它, 不进入测速."""
        self.src.add_path("/mixed", "203.0.113.40\n192.168.1.1\n")
        env, proc = self._run_once("mixed",
                                   ["%s/mixed" % self.src.base_url])
        self.assertEqual(proc.returncode, 0)
        state = harness.cfhost_state(env)
        self.assertEqual(state["candidates"], ["203.0.113.40"],
                         "私网地址须被过滤, 仅公网单播进入候选")


if __name__ == "__main__":
    unittest.main()
