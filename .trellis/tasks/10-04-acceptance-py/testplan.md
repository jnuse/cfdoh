# Test Plan — 逐用例清单 (用例真源)

本文是全部测试用例的完整清单, 实现按此逐条物化, 不得增删语义. 命名规则: 测试函数 `test_f<编号>_<slug>`, 审计命令 `grep -rho 'f0[0-9][0-9]' test/ | sort -u` 应覆盖 001-030.

## 实例族 (被测进程配置组)

| 族 | 配置要点 | 服务于 |
|---|---|---|
| S-STD | 反代模式; UPSTREAMS/ECS_UPSTREAMS=受控 U1/U2; ADMIN_TOKEN/HUB_TOKEN; ISP_TABLE_URL/CF_RANGE_URL(或等价)/PREFERRED_DOMAINS/ECH_CONFIG_BASE64 全受控; CACHE_PERSIST_PATH=临时 | 大多数用例 |
| S-NOADMIN | 同 S-STD 但无 ADMIN_TOKEN | F-008 AC4 |
| S-DROP | S-STD + CF_DROP_AAAA=1 | F-009 |
| S-HOST | S-STD + PUBLIC_HOSTNAMES=doh.test | F-021 AC3 |
| S-TLS | 直连模式, 证书=fixtures 对 | F-021 AC2 |
| S-CONFIG | CFDOH_CONFIG 文件 + 环境变量冲突 (勘误: 原记 CONFIG_PATH, 实名 CFDOH_CONFIG) | F-022 AC3 |
| C1 | cfhost: HOSTS_PATH=临时文件, 源=受控 API/list | F-023 至 F-027 |

## 环境哨兵 (preflight, _shared/preflight.py)

已知情况全部固化, 失败时输出成因与对策, 不留 "网络不通查半天":

- [ ] PF1 go 工具链可用 (`go version`); python ≥ 3.9
- [ ] PF2 端口预检: 实例族端口与假栈端口逐个探测; 被占则 fail 并附占用进程 PID/命令行, 提示 "已知成因: 上次失败残留 cfdoh; 对策: kill 该 PID" (2026-10-04 实际发生过: 残留进程占 18080, 新进程 bind 失败, /health 由旧进程应答, 现象为 SERVFAIL)
- [ ] PF3 fixtures 证书存在且未过期 (读 notAfter); 过期则提示 "重跑 fixtures/make-certs.sh"
- [ ] PF4 起进程后校验启动日志无 "address already in use" 且进程仍存活 (残留进程第二道保险)
- [ ] PF5 (仅 live) 代理探测: E2E_HTTPS_PROXY 已设则用之; 未设则取 `ip route show default` 网关 IP (WSL 网关每次重启会变, 禁止写死) 探测 10808 端口 — 已知: 该口为 mixed (http/socks5 双协议); 不通则 fail, 输出 "宿主 <ip>:10808 不通 — 代理客户端未开或未开局域网连接; 开启后重试或设 E2E_HTTPS_PROXY=<url>"
- [ ] PF6 (仅 live) 经代理预检一次真实 DoH (1.1.1.1, 3s 超时); 失败输出排查清单 (代理开否/局域网允许否/规则模式覆盖否)
- [ ] 客户端直连 127.0.0.1 永不走代理 (http.client 显式连接, 天然不读环境代理; 已知 e2e.sh 曾需 NO_PROXY 处理同类问题)

## 批 2 对应用例

### F-001 DoH 端点 [S-STD] (14)

- `test_f001_ok_get` — Given 合法 GET 查询 → GET /dns-query?dns= → 200; ID 回填, rcode 0, 应答头三件套 (Content-Type / Cache-Control: no-store / X-Content-Type-Options: nosniff)
- `test_f001_ok_post` — 同上 POST 通道, Content-Type 校验通过
- `test_f001_qr_set_400` — QR 置位的请求包 → 400
- `test_f001_accept_406` — Accept: text/html → 406
- `test_f001_alias_path` — 配置别名 (如 /linuxdo) → 行为与 /dns-query 逐项一致 (200/400/406 全矩阵)
- `test_f001_post_content_type_415` — POST Content-Type: text/plain → 415
- `test_f001_get_missing_dns_400` — GET 无 dns 参数 → 400
- `test_f001_get_bad_b64_400` — dns 含非法 base64url 字符 → 400
- `test_f001_oversize_413` — 请求体超 MAX_DNS_PACKET_SIZE → 413 (Content-Length 预检路径; 实际读取双检由 chunked 无长度体覆盖)
- `test_f001_method_405` — DELETE → 405 (Allow 头含 GET, POST)
- `test_f001_multi_question_400` — qdcount=2 的包 → 400
- `test_f001_opcode_nonzero_400` — opcode=1 的包 → 400
- `test_f001_trailing_garbage_400` — 合法包后接尾随字节 → 400
- `test_f001_rotation` — 同键连续查询 ≥6 次 → 首条 A 记录出现 ≥2 种取值 (缓存命中轮转也生效)

### F-002 wire 端点面 [S-STD] (3)

(完整 wire 语义由 Go 单测负责; 此处仅端点可观察面)

- `test_f002_pointer_loop_400` — 压缩指针成环 fixture 打端点 → 400 (不死循环, 有超时上限)
- `test_f002_high_label_400` — 0x40/0x80 高位 label fixture → 400
- `test_f002_oversized_counts_400` — qdcount>32 fixture → 400

### F-004 缓存用户可观察面 [S-STD] (5)

- `test_f004_ttl_no_second_upstream` — TTL 内同键二次查询 → 假上游出向计数恒为 1
- `test_f004_scope_isolation` — X-Real-IP 分属运营商 A/B, 各配 isp 池 → 同域名两次出向 (键不同), 应答各归各池
- `test_f004_stale_serving` — 上游应答 TTL=30 → 等 31s → 上游改 500 → 返回过期应答且记录 TTL 写 30, 非 SERVFAIL [耗时 ~35s]
- `test_f004_servfail_no_cache` — 上游全挂且无缓存 → SERVFAIL (QR|RA 置位, opcode/RD/CD 保真); 恢复上游后同键重新出向 (证明未缓存)
- `test_f004_https_expired_immediate` — HTTPS 查询入缓 → 等 TTL 过 → 再查 → 立即返回 (耗时 <1s) 且稍后上游出向计数 +1 (后台刷新) [耗时 ~35s]

### F-005 客户端识别 [S-STD] (4)

- `test_f005_xrealip_preferred` — X-Real-IP=电信网段 IP → /explain 显示该 IP 且应答走 isp:chinanet 池
- `test_f005_cf_connecting_ip_fallback` — 无 X-Real-IP, CF-Connecting-IP=网段 IP → 同上生效
- `test_f005_xff_first_fallback` — 仅 X-Forwarded-For: a, b → 取首值 a
- `test_f005_direct_tcp_peer` — 直连无任何头 → explain client_ip=127.0.0.1 (TCP 对端)

### F-017 请求参数 [S-STD] (5)

- `test_f017_ip4_override` — ?ip4=203.0.113.10,203.0.113.11 + CF 站点 → A 记录恰为指定两地址
- `test_f017_ip4_invalid_400` — ?ip4=999.1.1.1 → 400
- `test_f017_rules_offwhitelist_400` — ?rules=https://evil.example/x.json (白名单外) → 400
- `test_f017_cf_domain_pool` — ?cf=<受控域名> (受控解析出 203.0.113.20) → A 记录=203.0.113.20
- `test_f017_variant_cache_keys` — 同域名 ?ip4 两个不同值 → 上游出向 2 次, 应答各自正确 (互不污染)

## 批 3 对应用例

### F-007 池分层 [S-STD] (6)

- `test_f007_client_scope_pool` — 探针 X-Real-IP=198.51.100.10 POST scope=client → 浏览器 X-Real-IP=198.51.100.99 (同 /24) 查询 → A 记录来自专属池
- `test_f007_isp_layer` — isp:chinanet 池 + 电信 IP → 池内地址; 换非电信 IP → 不用该池
- `test_f007_narrow_fills_from_wide` — 专属池仅 2 地址 → 应答含 2 专属 + 补自 national 层
- `test_f007_no_consensus_interleave` — 3 source 各报不相交列表 (无多数共识) → 应答 A 记录覆盖 ≥2 个 source 的贡献
- `test_f007_ttl_expiry_fallback` — 探针池 ttl=60 → 停止上报等 61s → 应答回落 PREFERRED_DOMAINS 池 (受控解析) [耗时 ~65s]
- `test_f007_explicit_skips_learned` — 已有 default 池 → ?ip4= 指定 → 应答为指定地址非池

### F-008 admin 鉴权与校验矩阵 [S-STD + S-NOADMIN] (6)

- `test_f008_hub_scope_default_403` — HUB_TOKEN + scope=default → 403
- `test_f008_isp_offrange_400` — ADMIN_TOKEN + scope=isp:chinanet 含 203.0.113.x (非 CF 网段) → 400 整批拒绝
- `test_f008_wrong_token_401` — Bearer 错误令牌 → 401
- `test_f008_no_admin_token_404` — [S-NOADMIN] 全部 /admin/* → 404
- `test_f008_family_limit_400` — 每族 >64 地址 → 400
- `test_f008_ttl_clamped` — ttl=10 上报成功 (ADMIN_TOKEN) → GET /admin/preferred 显示钳后 60

### F-009 Cloudflare 改写 [S-STD + S-DROP] (5)

- `test_f009_rewrite_all_from_pool` — CF 站点 (上游应答 104.16.x) + default 池 → A 记录全来自池, ≤6 条
- `test_f009_non_cf_passthrough` — 非 CF 站点 (上游应答 93.184.x) → 应答记录与上游语义一致
- `test_f009_rotation_spread` — 多次查询首条轮转 (归 F-001 语义, 此处对池内地址断言)
- `test_f009_https_hints_sync` — 上游 HTTPS 含 ipv4hint → 改写后 hint 与 A 同步替换
- `test_f009_drop_aaaa` — [S-DROP] CF 站点 AAAA 查询 → 无 AAAA 记录返回 (或空应答 rcode 0)

### F-010 ECH [S-STD] (6)

- `test_f010_cf_site_ech` — CF 站点 HTTPS → SvcParam 含 ech, 字节=ECH_CONFIG_BASE64 配置
- `test_f010_non_cf_no_inject` — 非 CF 站点 HTTPS → 无 ech 参数
- `test_f010_source_unreachable` — ECH_SOURCE_DOMAIN 指向死地址 (不设 BASE64) → 应答正常 rcode 0 (无 ech 可接受), 不报错
- `test_f010_ech_param_priority` — ?ech=<受控域名> (其 HTTPS 含不同 ech) → 注入取该域名配置 (优先于 BASE64)
- `test_f010_synthesized_record` — 上游无 HTTPS 记录的 CF 站点 → 补造 HTTPS 记录含 ech + alpn
- `test_f010_disabled_switch` — ECH_ENABLED=0 实例 → CF 站点 HTTPS 无注入 [需独立小实例, 归入 S-DROP 族复用机制另配]

### F-011 h3 门控 [S-STD] (4)

- `test_f011_all_ok_enables_h3` — 1 source 全 ok → ALPN 含 h3
- `test_f011_one_fail_vetoes` — 两 source 一 ok 一 fail → ALPN 无 h3
- `test_f011_flip_immediate` — fail 上报 → 无 h3; 改 ok 整份覆盖 → 立即有 h3 (无 TTL 等待, 两次查询间零延迟)
- `test_f011_no_data_keep_alpn` — 无 verdict → 保留上游 ALPN 原样

### F-012 CNAME 展平 [S-STD] (2)

- `test_f012_flatten_to_qname` — 上游应答 CNAME 链 (别名 → 边缘节点 A) → 应答全部 owner=查询名; /explain chromium 判定可用
- `test_f012_non_cf_no_flatten` — 非 CF 主机 CNAME 链 → 保持链形不展平

### F-013 ECS 出向断言 [S-STD] (4)

- `test_f013_cn_ecs_sent` — 查询 example.cn + X-Real-IP → 假上游收到的出向包 OPT 含 code 8, 地址截断 /24
- `test_f013_com_no_ecs` — example.com 同条件 → 出向包无 ECS option
- `test_f013_inbound_stripped` — 请求自带 ECS (fixture 注入) → 出向至多一个 ECS option (剥离或幂等替换)
- `test_f013_ecs_upstream_routing` — 带 ECS 出向走 ECS_UPSTREAMS 实例, 普通上游零收包

### F-014 特殊站点 [S-STD] (4)

- `test_f014_github_pinned` — POST /admin/github 池 → github.com A 仅池内 IPv4, 无 AAAA, 无 ech
- `test_f014_x_not_cf_passthrough` — X 域名上游应答非 CF 地址 → 原样
- `test_f014_site_pool_pinned` — POST /admin/site 池 → 该站点 A/AAAA 钉住池 (去 v6), HTTPS hint 同步, ECH 保留
- `test_f014_site_revoke_by_empty` — site 上报空 hosts 覆盖 → 钉住即刻撤销, 回普通池

### F-015 Meta ECH [S-STD] (4)

- `test_f015_rotated_injected` — selfcheck 探针报 rotated+合法配置 → Meta 域名 HTTPS 注入学习钥字节, 且后续查询即刻换代 (不等 TTL)
- `test_f015_broken_suspended` — 报 broken → 不注入任何配置, 应答为未污染上游包
- `test_f015_ok_back_to_seed` — 报 ok → 清除覆盖回种子配置
- `test_f015_invalid_b64_rejected` — rotated 附非法 base64 → 拒绝, 维持原态

### F-016 规则引擎 [S-STD] (5)

- `test_f016_block_refused` — RULES_JSON block 规则命中 → rcode 3 空应答, 假上游出向计数 0
- `test_f016_replace_a_ttl_inherited` — replace-a 规则 → 地址替换, TTL=原应答非 OPT 最小值
- `test_f016_remote_invalid_fallback` — RULES_URL 返回非法 JSON → 内嵌规则继续生效 (block 仍 REFUSED)
- `test_f016_hostmap_shorthand` — host-map 简写规则 → 等价展开生效
- `test_f016_per_domain_ecs_override` — enable-ecs/disable-ecs 逐域名覆盖模式 → 出向断言分别有/无 ECS

### F-018 explain [S-STD] (3)

- `test_f018_full_chain` — CF 站点三类型 → chromium 可用; steps 依次含池选择, Cloudflare 改写, ECH 注入; 含 client_ip 与各类型缓存态
- `test_f018_invalid_name_400` — name=..bad.. → 400
- `test_f018_readonly` — explain 后立即 /dns-query 同键 → 仍出向一次 (explain 未写缓存)

### F-020 管理状态 [S-STD] (3)

- `test_f020_full_state` — ADMIN_TOKEN GET /admin/preferred → JSON 含自学习/专属/isp/github/site/meta/selfcheck/h3 键
- `test_f020_hub_get_403` — HUB_TOKEN GET → 403
- `test_f020_selfcheck_report` — POST /admin/selfcheck {source, ok, problems(60 条)} → GET 状态见 50 条截断

### 跨用户流 [S-STD] (2)

- `test_flow_probe_to_browser` — 探针上报 isp 池 (X-Real-IP=电信 IP) → 浏览器同网段查询 → 应答池内地址 (上报前查询为上游原址, 上报后翻转)
- `test_flow_hubfeed_pollution_isolated` — 受控 cfhub 返回污染池 (含非 CF 地址) + 干净池 → 干净池生效, 污染池整池不入; 浏览器应答正常

## 批 4 对应用例

### F-003 上游对冲 [S-STD, U1/U2 双上游] (6)

- `test_f003_fast_first_no_second` — U1 50ms 应答 → U2 出向计数 0
- `test_f003_hedge_parallel` — U1 延迟 500ms, U2 50ms (hedge=100ms) → 应答来自 U2, 两上游均有出向
- `test_f003_failover_on_error` — U1 返回 500 → 立即启动 U2, 应答来自 U2
- `test_f003_bad_content_skipped` — U1 返回 Content-Type: text/plain → 校验链拒绝, U2 胜出
- `test_f003_wrong_id_rejected` — U1 应答事务 ID 错误 → 拒绝, U2 胜出
- `test_f003_singleflight` — 50 线程并发同键未命中查询 → U1 出向计数=1

### F-019 健康探针 [S-STD] (4)

- `test_f019_health_ok` — GET /health → 200 {"ok":true}
- `test_f019_health_405` — POST /health → 405
- `test_f019_probe_echo` — GET /probe → 200 含 client_ip 与版本字段
- `test_f019_probe_405` — POST /probe → 405

### F-021 生命周期与形态 [S-STD + S-HOST + S-TLS] (6)

- `test_f021_snapshot_and_restore` — 探针上报池 → SIGTERM (断言退出码 0) → 4 份快照文件存在 (cache + pool/h3/ech) → 重启 → 首次查询即池内地址 (无需再上报)
- `test_f021_sigint_equivalent` — SIGINT 同 SIGTERM (退出码 0, 快照存在)
- `test_f021_host_mismatch_421` — [S-HOST] Host: other.test → 421; Host: doh.test 与 localhost → 正常
- `test_f021_direct_tls_mode` — [S-TLS] https 直连查询 (fixtures CA 校验) → 正常应答
- `test_f021_corrupt_snapshot_boot` — 快照文件写垃圾字节 → 重启正常 (不阻塞), 日志含警告
- `test_f021_pprof_default_off` — 默认配置 pprof 端口无监听 (连接拒绝)

### F-022 配置体系 [S-CONFIG] (3)

- `test_f022_min_config_works` — 仅 UPSTREAMS 受控, 其余默认 → 应答正常且无池不改写 (与上游应答一致)
- `test_f022_clamped_logged` — UPSTREAM_TIMEOUT_MS=99999 → 启动日志含钳制提示且值=15000 (从脱敏摘要断言)
- `test_f022_env_overrides_file` — CFDOH_CONFIG 文件 PORT=A (勘误: 原记 CONFIG_PATH) + 环境变量 PORT=B → 实际监听 B

### F-028 公开池拉取 [S-STD] (5)

- `test_f028_isp_pool_ingested` — 受控 API 含 published 电信池 → isp:chinanet 生效 (查询池内)
- `test_f028_polluted_pool_rejected` — API 混入污染池与干净池 → 仅干净池入池
- `test_f028_unpublished_skipped` — published=false 池 → 不采用
- `test_f028_family_cap_six` — 池给 10 地址 → 至多 6 条服务, 顺序=API 顺序
- `test_f028_failure_keeps_old` — 首拉成功 → API 改 500 → 查询仍旧池内应答

## 批 5 对应用例 (C1 族, cfhost 进程级)

- `test_f023_multi_source_union` — API 源 (受控 https) + list: 静态源 → run-once 后状态文件上轮候选=并集去重 (域名源依赖系统 DNS 不可控, 不入验收, 已知取舍)
- `test_f023_single_source_failure` — API 源 500 + list 源正常 → 候选仍含 list 项
- `test_f023_private_filtered` — API 返回含 192.168.1.1 → 候选无它
- `test_f024_all_fail_keep_hosts` — 候选全为不可达公网地址 (203.0.113.x) → run-once 退出 0, hosts 区块内容不变, 状态含淘汰标记 (滞回/强制重选细节由 Go 表驱动单测负责, 验收层不重复)
- `test_f025_block_written` — 静态源单地址 + 注入测速结果 (若 run-once 无注入通道则以全失败路径代替) → hosts 区块外逐字节保留 (区块内容由 Go 单测覆盖写入格式; 若注入通道可用则加断言区块两行)
- `test_f026_run_once_status` — run-once → status 子命令输出在用地址/上轮摘要/下次刷新, 退出 0
- `test_f026_second_instance_lock` — 常驻实例持有锁 → 第二实例启动 → 非 0 退出, 首实例进程存活
- `test_f026_runloop_periodic` — RunLoop 常驻 (非 run-once), INTERVAL=3s, 候选源=受控 API → 12s 窗口内源拉取计数 ≥3 且状态文件 next_run 时刻推进 (不触发任何手动命令, 证明自动周期轮询存在)
- `test_f027_minimal_config` — 仅域名+源 → run-once 正常
- `test_f027_empty_domains_abort` — 域名列表空 → 非 0 退出且 hosts 未被修改
- `test_f027_env_overrides_file` — 文件与环境变量同键 → 环境变量生效

## 批 6 对应用例

### F-029/F-030 静态验收 (4)

- `test_f029_delivery_files` — Dockerfile, deploy/{compose.yml, env.example, cfdoh.service, cfhost.service, nginx.sample.conf} 存在
- `test_f029_compose_shape` — compose 文本含: healthcheck, 非 root (user: 指令), 快照卷挂载
- `test_f030_release_shape` — release.yml 文本含: cfdoh linux/amd64+arm64, cfhost windows/amd64+linux/amd64, sha256, GHCR push
- `test_f030_ci_shape` — ci.yml 含 go 三连与 acceptance 步

### live 层 [吸收 scripts/e2e.sh 全场景] (7)

- `test_live_preflight_proxy` — PF5/PF6 哨兵 (失败信息含已知成因清单)
- `test_live_zero_config` — 零配置默认三上游 → A/AAAA/HTTPS 三类型 rcode 0 + ID 回填 (代理经 E2E_HTTPS_PROXY)
- `test_live_explain` — /explain 骨架 (client_ip, answers 三类型, chromium_ech)
- `test_live_probe_health` — /health ok + /probe 回显
- `test_live_admin_matrix` — 401/200 鉴权矩阵
- `test_live_snapshot_reboot` — SIGTERM 快照 4 件套 + 重启恢复应答
- `test_live_no_rewrite_without_pool` — 无池场景应答与默认上游语义一致 (地址非池改写)

## 用例统计

批 2: 31; 批 3: 54; 批 4: 23; 批 5: 11; 批 6: 11; 合计 130 (+ 哨兵 6).

## 手动清单 (test/live/MANUAL.md, 发布前人工执行, 不进 CI)

S 系列 (cfdoh, 浏览器用户):
- S0 前置: 真实部署, 上游可达, 池已上报
- S1 配置生效: 浏览器安全 DNS 指向端点; net-internals 显示 active; 服务端可见查询
- S2 无差别可用性: CF 与非 CF 站点全部正常打开
- S3 优选生效: DNS 缓存 A 记录=池内地址; Remote Address 打到池地址; 多次查询首条轮转
- S4 ECH 生效: DevTools Security 加密 ClientHello; CF 检测页 ech 生效
- S5 h3 门控: Protocol 列按 verdict 显 h3/h2
- S6 失败不劫持: 上游故障时 stale 兜底或原样应答, 最坏回到普通解析

C 系列 (cfhost, 客户端用户):
- C0 前置: 发布产物解压, 域名与源已配
- C1 安装服务化: install 后服务自启; 重启系统后完成一轮 (Windows 实测; F-026 AC1)
- C2 一轮生效: hosts 区块内管辖域名指向最优地址; 区块外手动条目逐字节保留
- C3 实际访问: 访问管辖域名, Remote Address=钉住地址, 站点正常
- C4 自动选优不抖动: 长期观察 status, 地址随线路切换但滞回不频繁跳; status 含在用地址/上轮摘要/下次刷新
- C5 常驻行为: 崩溃/重启自动恢复; 第二实例不并发; 日志轮转不撑盘
- C6 卸载干净: uninstall 后服务移除, hosts 区块清除, 系统复原
- C7 已知冲突: 杀毒软件放行 hosts 修改; 代理客户端分流场景下站点仍正常 (F-026 安装文档两项要求的实测面)
- C8 隐私: 默认零外联 (防火墙可见仅配置源); 状态文件仅本机

## 已知取舍 (过目点)

1. F-008 "scope client 无法确定上报者地址 400" 不可制造: 入口恒以 TCP 对端补齐, 验收层剔除, 语义由 Go 单测保留.
2. F-022 零配置默认上游 = 真实三上游, 属 live 层; acceptance 用 "最小受控配置" 等价面.
3. F-023 域名源依赖系统 DNS 不可控, 不入验收.
4. F-024 滞回/强制重选由 Go 表驱动单测覆盖; 验收层只测用户可观察的 "全败保现状".
5. F-025 "最优不变不重写" 的 mtime 断言在 Go 单测; 验收层以 "测速全败不重写" 为可观察等价面; 若 cfhost 存在测速注入通道则升级为强断言 (实现时确认).
6. 等待类用例 3 个 (~35s ×2, ~65s ×1), 全套件预计 4-6 分钟.
7. 客户端配置钳制区间 spec 未定义 (cfhost.md 无钳制规则, 与服务端 config.md 不对称); test_f026_runloop_periodic 若因 Interval 被实现钳至更大值而红, 即为 spec 与实现分歧暴露, 交产品裁决; 钳制补 spec 属后续任务, 不在本任务内改产品.
