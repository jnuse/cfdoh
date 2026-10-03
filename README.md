# cfdoh

Self-hosted DoH resolver with Cloudflare IP optimization and ECH injection,
plus a Windows client daemon that pins your domains to the fastest verified
address. Go 复刻 [edge-smart-doh](refer/edge-smart-doh) 的行为基线, 单静态二进制, 无外部运行时依赖.

- **cfdoh** (服务端): RFC 8484 DoH 端点, 应答缓存与预取, Cloudflare 优选池改写, ECH 注入, h3 门控, 运营商/专属/自学习多层池, 规则引擎, admin API.
- **cfhost** (客户端): 拉取候选 → 本机 TLS 握手测速 → 滞回选优 → 维护 hosts 标记区块; Windows 原生服务.

## 快速开始 (compose 部署)

```bash
cp deploy/env.example deploy/.env
# 编辑 deploy/.env: 按需开启 CF_REWRITE_ENABLED / ADMIN_TOKEN / ECH_ENABLED ...
docker compose -f deploy/compose.yml up -d
curl http://127.0.0.1:8787/health        # {"ok":true}
```

浏览器/系统 DoH 指向 `https://<你的域名>/dns-query` (前置 nginx/caddy 终止 TLS, 样例见 `deploy/nginx.sample.conf`; 直连 TLS 模式配 `TLS_CERT_FILE`/`TLS_KEY_FILE`).

冒烟自测脚本 (起服务 + `/health`, `/dns-query` GET/POST, `/explain`, 快照与重启恢复):

```bash
./scripts/e2e.sh   # 外网经代理时: E2E_HTTPS_PROXY=http://host:port ./scripts/e2e.sh
```

## 快速开始 (cfhost 安装, Windows)

1. 下载 `cfhost_<ver>_windows_amd64.zip`, 解压后以管理员运行:

```powershell
cfhost install      # 安装原生服务 (自启)
cfhost start
cfhost status       # 当前在用地址 / 上轮测速摘要 / 下次刷新
```

2. 配置文件 `%APPDATA%\cfdoh\cfhost.json` (或 `CFHOST_CONFIG` 指定):

```json
{
  "managed_domains": ["doh.example.com"],
  "sources": ["pool:https://cfhub.1molchuan.top/api/v1/pools#national", "domain:cf.090227.xyz"]
}
```

- 只维护 hosts 内 `# BEGIN cfhost` .. `# END cfhost` 区块, 区块外内容逐字节保留; 地址未变化不重写.
- 安全软件若拦截 hosts 修改需放行 cfhost; 本机代理客户端若分流 DoH 域名需与 hosts 钉住共存, 注意关闭代理对该域名的远程解析.
- 手动跑一轮: `cfhost run-once`.

Linux 客户端用 `deploy/cfhost.service`.

## 服务端运维

- 全部行为经环境变量调节, 参考 `deploy/env.example` 与启动日志的脱敏摘要; 零配置即可运行 (默认 cloudflare/google/quad9 上游).
- `GET /health` 存活检查; `GET /probe` 回显客户端 IP 与版本; `GET /explain?name=<域名>` 输出池选择/改写/ECH 注入逐步决策链.
- admin: `POST/GET /admin/preferred|site|github|h3|selfcheck|health`, Bearer `ADMIN_TOKEN` 全权 / `HUB_TOKEN` 仅运营商池 (未配置 `ADMIN_TOKEN` 时整组 404).
- 重启不丢状态: 配置 `CACHE_PERSIST_PATH` 后, 缓存与 pool/h3/ech 探针态定期与退出时快照, 启动回读.
- systemd 单元: `deploy/cfdoh.service`.

## 构建

```bash
go build ./... && go vet ./... && go test ./...
go build -trimpath -ldflags "-s -w -X github.com/jnuse/cfdoh/internal/httpapi.Version=$(git describe --tags)" -o cfdoh ./cmd/cfdoh
GOOS=windows go build -ldflags "-X main.version=$(git describe --tags)" -o cfhost.exe ./cmd/cfhost
docker build -t cfdoh:dev .
```

发布: 推送 `vX.Y.Z` tag 触发 release workflow — 服务端 linux/amd64+arm64, 客户端 windows/amd64+linux/amd64, SHA256SUMS 与 GHCR 镜像.

## 仓库布局

- `internal/wire` DNS 编解码 (防御性解析), `internal/cache|ecs|rules|upstream` 解析基础
- `internal/pool|cfrange|isp|h3|ech|hubfeed` 优选与 ECH 能力层
- `internal/rewrite|resolver|httpapi` 改写链与服务端汇合; `cmd/cfdoh` 入口
- `internal/cfhost`, `cmd/cfhost` 客户端
- 行为契约与模块划分见 `.trellis/spec/`

## 许可证

参考实现为 AGPL-3.0; 本项目作为网络服务提供时保持源码公开, 许可证与之兼容.
