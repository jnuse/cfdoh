"""F-030 发布流水线 — 静态验收 2 例.

断言语义真源: .trellis/spec/prd/requirements.md F-030 节 与
.trellis/spec/arch/build-release.md (产物命名与平台矩阵).
断言只做文本包含级; workflow 语法与实际执行由 CI 自身闭环.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import harness  # noqa: E402

REPO = harness.REPO_ROOT


class F030PipelineTest(unittest.TestCase):
    """F-030: release 双组件多平台 matrix + sha256 + GHCR; ci 含 go 三连与 acceptance."""

    def test_f030_release_shape(self):
        """release.yml: cfdoh linux/amd64+arm64, cfhost windows/amd64+linux/amd64, sha256, GHCR push."""
        text = (REPO / ".github/workflows/release.yml").read_text(encoding="utf-8")
        problems = []
        if text.count("component: cfdoh") < 2:
            problems.append("release matrix 缺 cfdoh 双平台条目 (linux/amd64 + linux/arm64)")
        if text.count("component: cfhost") < 2:
            problems.append("release matrix 缺 cfhost 双平台条目 (windows/amd64 + linux/amd64)")
        if "goarch: arm64" not in text:
            problems.append("release 缺 goarch: arm64 (cfdoh linux/arm64)")
        if "goos: windows" not in text:
            problems.append("release 缺 goos: windows (cfhost windows/amd64)")
        if "sha256sum" not in text or "SHA256SUMS" not in text:
            problems.append("release 缺 sha256 校验和步 (sha256sum → SHA256SUMS)")
        if "ghcr.io" not in text or "push: true" not in text:
            problems.append("release 缺 GHCR 推送步 (ghcr.io + push: true)")
        self.assertEqual(problems, [], "release 形状不符:\n  - " + "\n  - ".join(problems))

    def test_f030_ci_shape(self):
        """ci.yml: go 三连 + acceptance 步 (含低端口前置, f016 远程规则源绑 443)."""
        text = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        problems = []
        for token in ("go vet ./...", "go test", "go build ./..."):
            if token not in text:
                problems.append("ci 缺 go 三连之一: %r" % token)
        if "python3 -m unittest discover -s test/acceptance" not in text:
            problems.append("ci 缺 acceptance 步 (python3 -m unittest discover -s test/acceptance)")
        if "net.ipv4.ip_unprivileged_port_start=80" not in text:
            problems.append("ci 缺低端口前置 sysctl "
                            "(f016 受控远程规则源需绑 443; CI 非 root)")
        self.assertEqual(problems, [], "ci 形状不符:\n  - " + "\n  - ".join(problems))


if __name__ == "__main__":
    unittest.main()
