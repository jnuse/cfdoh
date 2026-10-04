"""F-029 Docker 镜像与 Compose 部署 — 静态验收 2 例.

断言语义真源: .trellis/spec/prd/requirements.md F-029 节 与
.trellis/spec/arch/build-release.md (交付物清单).
断言只做文本包含级 (标准库无 YAML; 深度语法由 CI 自身闭环);
docker build 与 compose up 由 CI / 手动清单闭环, 本地不执行.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import harness  # noqa: E402

REPO = harness.REPO_ROOT


def read(rel):
    return (REPO / rel).read_text(encoding="utf-8")


class F029DeliveryTest(unittest.TestCase):
    """F-029: 交付文件存在与 compose 形状 (healthcheck / 非 root / 快照卷)."""

    def test_f029_delivery_files(self):
        """交付资产清单齐全: Dockerfile, deploy 五件, workflows 两件."""
        required = [
            "Dockerfile",
            "deploy/compose.yml",
            "deploy/env.example",
            "deploy/cfdoh.service",
            "deploy/cfhost.service",
            "deploy/nginx.sample.conf",
            ".github/workflows/ci.yml",
            ".github/workflows/release.yml",
        ]
        missing = [rel for rel in required if not (REPO / rel).is_file()]
        self.assertEqual(
            missing, [],
            "交付资产缺失: %s (对照 .trellis/spec/arch/build-release.md "
            "对外接口文件清单)" % missing)

    def test_f029_compose_shape(self):
        """compose 含 healthcheck, 非 root (user: 指令), 快照卷挂载."""
        text = read("deploy/compose.yml")
        problems = []
        if "healthcheck:" not in text:
            problems.append("compose 缺 healthcheck (F-029: /health 可作容器健康检查)")
        if not re.search(r"(?m)^\s*user:\s*\S+", text):
            problems.append("compose 缺 user: 指令 (F-029: 非 root 用户运行)")
        if "cfdoh-state:/var/lib/cfdoh" not in text:
            problems.append("compose 缺快照卷挂载 cfdoh-state:/var/lib/cfdoh "
                            "(F-029: 快照目录挂载为卷)")
        self.assertEqual(problems, [], "compose 形状不符:\n  - " + "\n  - ".join(problems))


if __name__ == "__main__":
    unittest.main()
