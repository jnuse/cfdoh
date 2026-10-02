# Implement

执行批次: 每批末尾跑 `go build ./... && go vet ./... && go test ./...`, 全绿才进下一批. 模块接口签名以 .trellis/spec/arch/<模块>.md 为准.

## 批 1: 基础层 (wire, config)

- [ ] go.mod 初始化 (module github.com/jnuse/cfdoh, Go 1.23, 依赖 x/sync)
- [ ] internal/wire: 类型 (Packet/Record/RData sealed), Parse/Encode, name 编解码 (压缩指针 + 防环), CanonicalName/MatchDomain, ParseIPv4/ParseIPv6, MakeServfail/PatchID/ResponseTTL/RotateAddresses, SvcParam 读写 (DescribeHTTPS/UpsertSvcParam)
- [ ] internal/wire 测试: refer packet 用例移植 + 攻击包 + 全类型往返
- [ ] internal/config: 环境变量 + 文件合并, 钳制, SanitizedSummary; 测试覆盖钳制边界与优先级

## 批 2: 能力层 A (ecs, rules, upstream, cache)

- [ ] internal/ecs: Make/ShouldUse/Add/Remove; OPT 合成语义测试
- [ ] internal/rules: 三形态解析, Load (远程防御链), ShouldBlock/EcsOverride/Apply, ValidateDynamicURL; 表驱动测试
- [ ] internal/upstream: 对冲 Query (TTL 250-15000, hedge 0-5000), ResolveAddresses, singleflight 合并; httptest 假上游测试 (延迟/失败/非法应答)
- [ ] internal/cache: IdentityOf (身份+变体), 分片 LRU, Put 内 TTL 钳制 (负缓存 SOA 语义), 快照读写; 状态判定 (fresh/refresh/stale) 测试

## 批 3: 能力层 B (pool, cfrange, isp, h3, ech, hubfeed)

- [ ] internal/pool: 三张学习池表 + SetLearned/Preferred (池层优先序, 每族补足), CombineRankings (严格多数/限段/交错), HostPools (站点/GitHub), SitePoolTag, 状态查询; 投票合并全分支测试
- [ ] internal/cfrange: 官方列表拉取解析, Contains; 用本地 httptest 假列表测试
- [ ] internal/isp: 表解析 (嵌套最长前缀, 单调栈 parent), ScopeOf 刷新退避; 表驱动测试
- [ ] internal/h3: SetVerdicts/Verdict (后缀最长匹配)/AlpnFor/CacheTag 代数; 全票制测试
- [ ] internal/ech: ConfigFor (发布域名解析缓存), Validated, Meta 三态 + MetaCacheTag; 状态机测试
- [ ] internal/hubfeed: 公开池 API 拉取解析 (cfhub JSON), 整池 CF 校验拒绝, RefreshOnce/Start; httptest 假 API 测试 (含污染池)

## 批 4: 服务端汇合 (rewrite, resolver, httpapi, cmd/cfdoh)

- [ ] internal/rewrite: OnCloudflare/UsesCloudflare/RewriteAddresses/RewriteX/PinAddresses/PinHTTPSHints/InjectECH/InjectConfigured/Flatten; 改写链表驱动测试 (A/AAAA/HTTPS hint 同步, 展平, 兜底)
- [ ] internal/resolver: Resolve (缓存策略编排: fresh/refresh/stale/HTTPS 即返/SERVFAIL), ResolveFresh (改写链 + notes), ChromiumECHVerdict; 假上游集成测试
- [ ] internal/httpapi: 路由 (dns-query+别名/explain/admin×6/health/probe), DoH 请求校验 (406/415/413/400/405), admin 双令牌鉴权矩阵 + 上报校验, 直连/反代监听, 优雅退出
- [ ] cmd/cfdoh: 信号处理, 快照恢复, 启动日志
- [ ] 端到端自测脚本: 起服务 + curl /health, /dns-query (GET/POST), /explain

## 批 5: 客户端 (internal/cfhost, cmd/cfhost)

- [ ] internal/cfhost: 配置, 候选拉取 (公开池 API/优选域名/静态), 本地测速 (TLS 握手计时, 多轮中位), 滞回, hosts 区块管理 (原子写/无变化不写/区块外保真/flushdns), 单实例锁, RunOnce/RunLoop
- [ ] cmd/cfhost: 子命令分发 (install/uninstall/start/stop/run-once/status), --version
- [ ] 测试: hosts 区块保真, 滞回判定表驱动, 候选过滤; Windows 服务接口抽象

## 批 6: 交付 (构建与发布)

- [ ] 版本注入 (--version), ldflags 构建参数
- [ ] Dockerfile (多阶段, 非 root, CA 证书), deploy/compose.yml + env.example
- [ ] .github/workflows/ci.yml (测试+构建检查), release.yml (tag 触发, 双组件四平台产物 + SHA256SUMS + GHCR)
- [ ] 本地 docker build 验证; workflow YAML 语法校验
- [ ] README 快速开始 (compose 部署 + cfhost 安装)

## 验证命令

```bash
go build ./... && go vet ./... && go test ./...
docker build -t cfdoh:dev .
```

## 回滚点

每批一次 commit; 批内失败回退到批首 commit.
