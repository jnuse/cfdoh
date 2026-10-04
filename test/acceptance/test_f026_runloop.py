"""F-026 客户端常驻服务与安装 — 3 用例 (cfhost 进程级, C1 族).

断言语义真源: .trellis/spec/prd/requirements.md F-026 节 与
.trellis/spec/arch/client-entry.md (子命令集与退出语义).
Windows 服务化 (install/start/stop) 不在 Linux 验收层, 由手动清单 C1 覆盖.

已知取舍 #7 (test_f026_runloop_periodic): 产品配置面唯一周期通道
CFHOST_INTERVAL_MIN 为分钟整数, 且实现将其钳至下限 1 分钟
(internal/cfhost/config.go minInterval), spec (cfhost.md) 未定义钳制区间.
2026-10-04 裁决: 采用最小可表达周期 (CFHOST_INTERVAL_MIN=1 分钟),
~130s 观测窗口内拉取计数 ≥2; 产品钳制保持, 钳制区间补 spec 属后续任务.
"""

import datetime
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import fakestack, harness  # noqa: E402

FAST_PROBE = {"CFHOST_TIMEOUT_MS": "250", "CFHOST_ROUNDS": "1"}

# 预置状态: 上一轮已有在用地址 (本轮全败须保留, status 才有真实地址可报)
SEEDED_STATE = {
    "current_v4": "203.0.113.7",
    "current_v6": "",
    "last_summary": "seeded",
    "next_run": 0,
    "fail_streak": 0,
    "candidates": [],
}


class F026RunloopTest(unittest.TestCase):
    """F-026: run-once→status 输出, 单实例锁, RunLoop 自动周期轮询."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.daemons = []
        try:
            src = fakestack.FakeStack(harness.STACK_PORTS["cfhub"], "files",
                                      name="f026-pollsrc").start()
            cls.stacks.append(src)
            cls.src = src
            cls.src.add_path("/poll", "203.0.113.50\n")
            cls.base = harness.REPO_ROOT / ".cache" / "acceptance" / "f026"
            if cls.base.exists():
                shutil.rmtree(cls.base)
        except Exception:
            for d in cls.daemons:
                d.kill()
            for stack in cls.stacks:
                stack.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        for d in cls.daemons:
            d.kill()
        for stack in cls.stacks:
            stack.stop()

    def _poll_until(self, fn, timeout, what):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = fn()
            if last:
                return last
            time.sleep(0.2)
        self.fail("等待超时: %s (最后: %r)" % (what, last))

    def test_f026_run_once_status(self):
        """F-026 AC: run-once → status 输出在用地址/上轮摘要/下次刷新, 退出 0."""
        wd = self.base / "status"
        env = harness.cfhost_env(wd, sources=["list:203.0.113.5"],
                                 managed_domains="probe.example.org",
                                 extra=FAST_PROBE)
        state_path = Path(env["CFHOST_STATE_PATH"])
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(SEEDED_STATE))

        proc = harness.CfhostProc("f026-ronce", env, wd,
                                  args=("run-once",)).run()
        self.assertEqual(proc.returncode, 0,
                         "run-once 须正常退出: %s" % proc.stderr.strip())

        st = harness.CfhostProc("f026-status", env, wd, args=("status",)).run()
        self.assertEqual(st.returncode, 0, "status 须退出 0")
        out = st.stdout
        self.assertIn("current v4: 203.0.113.7", out,
                      "status 须输出在用地址 (全败轮保留上轮地址):\n%s" % out)
        self.assertIn("last summary: tested=1 ok=0 best_v4=none", out,
                      "status 须输出上轮测速摘要:\n%s" % out)
        # 下次刷新: RFC3339 时刻, 须在未来 (默认周期 10 分钟)
        next_line = [ln for ln in out.splitlines() if ln.startswith("next run:")]
        self.assertEqual(len(next_line), 1, "status 须含 next run 行:\n%s" % out)
        ts = next_line[0].split(":", 1)[1].strip()
        nxt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.datetime.now(datetime.timezone.utc)
        self.assertGreater(nxt, now, "下次刷新时刻须在未来: %s" % ts)
        state = harness.cfhost_state(env)
        self.assertGreater(state["next_run"], 0, "状态文件 next_run 须被写入")

    def test_f026_runloop_periodic(self):
        """F-026 AC: RunLoop 常驻 → ~130s 窗口内自动轮询 ≥2 轮且 next_run 推进.

        周期通道为分钟粒度, 按取舍 #7 裁决取最小可表达周期
        (CFHOST_INTERVAL_MIN=1, 即 1 分钟); 窗口 130s 覆盖两次调度轮次,
        期间不触发任何手动命令, 证明自动周期轮询存在.
        """
        wd = self.base / "periodic"
        env = harness.cfhost_env(
            wd, sources=["%s/poll" % self.src.base_url],
            managed_domains="probe.example.org",
            extra={**FAST_PROBE, "CFHOST_INTERVAL_MIN": "1"})
        inst = harness.CfhostProc("f026-runloop", env, wd).start()
        self.daemons.append(inst)
        try:
            # 首轮: 受控源被拉取一次, 状态文件落盘
            self._poll_until(
                lambda: self.src.request_count("/poll") >= 1
                and harness.cfhost_state(env) is not None,
                timeout=20, what="RunLoop 首轮拉取与状态落盘")
            first_run = harness.cfhost_state(env)["next_run"]
            baseline = self.src.request_count("/poll")

            # 观测窗口 130s (覆盖 1 分钟周期的两次调度): 期间不触发任何
            # 手动命令, 只看自动周期轮询
            window_deadline = time.monotonic() + 130.0
            final_count = baseline
            while time.monotonic() < window_deadline:
                final_count = max(final_count,
                                  self.src.request_count("/poll"))
                time.sleep(0.5)
            final_state = harness.cfhost_state(env)

            self.assertGreaterEqual(
                final_count - baseline, 2,
                "130s 窗口内受控源新增拉取 %d < 2 (自动周期轮询缺失)"
                % (final_count - baseline))
            self.assertGreater(final_state["next_run"], first_run,
                               "窗口内状态文件 next_run 须随轮次推进: "
                               "first=%d final=%d"
                               % (first_run, final_state["next_run"]))
        finally:
            inst.stop(expect_exit=0)
            if inst in self.daemons:
                self.daemons.remove(inst)

    def test_f026_second_instance_lock(self):
        """F-026 AC: 常驻实例持锁 → 第二实例非 0 退出, 首实例存活."""
        wd = self.base / "lock"
        env = harness.cfhost_env(wd, sources=["list:203.0.113.3"],
                                 managed_domains="probe.example.org",
                                 extra=FAST_PROBE)
        lock = harness.cfhost_lock_path(env)
        inst1 = harness.CfhostProc("f026-lock1", env, wd).start()
        self.daemons.append(inst1)
        try:
            self._poll_until(
                lambda: lock.is_file() and self._lock_alive(lock),
                timeout=20, what="首实例锁文件出现且 PID 存活")
            with lock.open() as fh:
                self.assertEqual(int(fh.read().strip()), inst1.proc.pid,
                                 "锁文件须登记首实例自身 PID")

            try:
                second = harness.CfhostProc("f026-lock2", env, wd).run(
                    timeout=30)
            except subprocess.TimeoutExpired:
                self.fail("第二实例 30s 内未自行退出 (未检测到锁)")
            self.assertNotEqual(second.returncode, 0,
                                "撞锁的第二实例须非 0 退出")
            self.assertIn("another cfhost instance is running",
                          second.stderr,
                          "撞锁退出须携带明确成因: %s" % second.stderr.strip())
            self.assertIsNone(inst1.proc.poll(), "首实例须继续存活")
        finally:
            inst1.stop(expect_exit=0)
            if inst1 in self.daemons:
                self.daemons.remove(inst1)
        self.assertFalse(lock.exists(), "首实例退出后锁文件须释放")

    @staticmethod
    def _lock_alive(lock):
        try:
            pid = int(lock.read_text().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False


if __name__ == "__main__":
    unittest.main()
