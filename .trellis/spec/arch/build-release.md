# 构建与发布

业务逻辑:
- 多阶段 Dockerfile: 构建阶段静态编译 (CGO 关闭), 运行阶段最小镜像, 含系统 CA 证书, 非 root 用户运行.
- 镜像发布到 GHCR; 版本 tag 与 latest 同步推送; 镜像内二进制与同提交的 release 产物同源.
- compose 样例: 端口映射, 环境变量注入, 快照目录挂载为卷, /health 健康检查.
- CI 在 push 与 PR 时跑测试与构建检查, 全绿才可合并.
- Release 由 vX.Y.Z tag 触发: cfdoh (linux/amd64, linux/arm64), cfhost (windows/amd64, linux/amd64), 全部产物的 sha256 校验和, GHCR 镜像.
- 版本号与提交哈希经构建参数注入, --version 可查.

对外接口:

- 命令行: `docker compose -f deploy/compose.yml up -d`
- 产物: release 资产 (`cfdoh_<ver>_<os>_<arch>.tar.gz`, `cfhost_<ver>_<os>_<arch>.zip|tar.gz`, `SHA256SUMS`), 镜像 `ghcr.io/<owner>/cfdoh`
- 文件: `Dockerfile`, `deploy/compose.yml`, `deploy/env.example`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`

数据所有权: 产物命名规则与目标平台矩阵.

扩展规则:
- 新目标平台只加构建矩阵条目, 产物命名规则不变.
- 版本注入路径唯一 (构建参数), 不引入手工版本文件.
- 流水线不产生运行时配置, 运行时默认值全部在 config 模块.

事件目录: 无.
