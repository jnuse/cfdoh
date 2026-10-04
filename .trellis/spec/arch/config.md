# config

业务逻辑:
- 环境变量与配置文件合并, 环境变量优先.
- 数值项全部钳制到区间, 超界值钳到边界并记日志.
- 令牌类缺失即标记对应功能关闭; 上游仅接受 https.
- 启动输出脱敏摘要 (令牌打码).

对外接口:

```go
type Config struct { /* 字段与下方环境变量对照表一一对应 */ }
func Load() (*Config, error)
func (c *Config) SanitizedSummary() string
func (c *Config) TLSEnabled() bool
```

## 环境变量对照表 (唯一真源)

本表是环境变量的规范出处; 测试, 文档与部署样例以本表为准, 不从 config.go 抄名.
语义列中的回退/停用行为属于合同的一部分.

| 变量 | 语义 | 默认 | 钳制/校验 |
|---|---|---|---|
| CFDOH_CONFIG | KEY=VALUE 配置文件路径, 环境变量优先于文件 | (无) | 文件不存在报错; 畸形行忽略并告警 |
| UPSTREAMS | 逗号分隔 DoH 上游 | cloudflare,google,quad9 | 仅保留 https 前缀 |
| ECS_UPSTREAMS | ECS 查询走的上游 | 同 UPSTREAMS | 同上 |
| UPSTREAM_TIMEOUT_MS | 单次上游尝试超时 | 2500 | 250–15000 |
| UPSTREAM_HEDGE_MS | 对冲间隔 (0 关闭) | 100 | 0–5000 |
| CACHE_MIN_TTL / CACHE_MAX_TTL | 应答 TTL 钳制区间 | 30 / 3600 | 0–3600 / 1–86400 |
| NEGATIVE_CACHE_MAX_TTL | 负应答 TTL 上限 | 300 | 0–3600 |
| CACHE_STALE_TTL | 过期可服务窗口 | 86400 | 0–604800 |
| CACHE_PREFETCH_PERCENT | 预取阈值比例 | 10 | 0–90 |
| CACHE_MAX_ENTRIES | LRU 容量 | 4096 | 128–65536 |
| CACHE_PERSIST_PATH | 缓存快照路径 (空关闭) | (空) | — |
| ECS_MODE | off / always / rules | rules | 非法值回退 rules 并告警 |
| ECS_DOMAINS | ECS 规则模式域名后缀 | .cn | — |
| ECS_IPV4_PREFIX / ECS_IPV6_PREFIX | ECS 子网前缀长 | 24 / 48 | 0–32 / 0–128 |
| CF_REWRITE_ENABLED / CF_DROP_AAAA | 改写与 AAAA 丢弃开关 | false | 仅 true (大小写不敏感) 为真 |
| CF_PREFERRED_DOMAIN | 优选域名池 (越过后四层) | (空) | 规范化去尾点 |
| CF_PREFERRED_IPV4 / CF_PREFERRED_IPV6 | 静态优选地址 | (空) | — |
| ADMIN_TOKEN / HUB_TOKEN / DOH_ORIGIN_TOKEN | 令牌 (空即关闭对应端点/功能) | (空) | — |
| ISP_TABLE_URL | 运营商 CIDR 表 | (空=关闭) | — |
| CF_IPV4_URL / CF_IPV6_URL | CF 网段列表源 | cloudflare.com/ips-v4(v6) | — |
| RULES_JSON / RULES_URL | 内嵌与远程规则 | [] / (空) | — |
| ECH_ENABLED | ECH 注入总开关 | false | 同 bool 规则 |
| ECH_CONFIG_BASE64 | ECH 配置直供 | (空) | — |
| ECH_DOMAINS | 无条件注入域名 | (空) | — |
| ECH_SOURCE_DOMAIN | ECH 配置源域名 | cloudflare-ech.com | — |
| META_ECH_CONFIG_BASE64 | Meta ECH 种子 | (空) | — |
| META_DOMAINS | Meta 系域名 | facebook,instagram,whatsapp,fbcdn,messenger,threads 六域 | — |
| X_DOMAINS / GITHUB_DOMAINS | X 与 GitHub 域名 | x.com,twitter.com,twimg.com,t.co / (空) | — |
| DYNAMIC_RULE_HOSTS | 动态规则源主机白名单 | paste.rs,raw.githubusercontent.com,gist.githubusercontent.com | — |
| DYNAMIC_RULES_MAX_BYTES | 动态规则大小上限 | 262144 | 1024–1048576 |
| MAX_DNS_PACKET_SIZE | DNS 包大小上限 | 4096 | 512–65535 |
| POOL_FEED_URL | 公开池 API | cfhub 公开端点 | 显式置空停用; 非 https 停用并告警 |
| POOL_FEED_INTERVAL_SEC / POOL_FEED_TTL_SEC | 拉取周期 / 池有效期 | 300 / 1800 | 60–3600 / 300–86400 |
| HOST / PORT | 监听地址 | 127.0.0.1 / 8787 | PORT 1–65535 |
| PUBLIC_HOSTNAMES | Host 白名单 (空不校验) | (空) | — |
| TLS_CERT_FILE / TLS_KEY_FILE | 直连模式证书对 (双填生效) | (空) | — |
| PATH_ALIASES | /dns-query 路径别名 | (空) | — |
| DEBUG / LOG_QUERIES | 调试与查询日志开关 | false | 同 bool 规则 |
| PPROF_ADDR | pprof 独立监听地址 (空关闭) | (空) | — |

非数值的数值项回退默认并告警; 钳制动作记 "clamped to minimum/maximum" 日志.

数据所有权: 全局默认值表与钳制区间表.

扩展规则:
- 新配置项同变更登记本表与本结构, 钳制集中在 Load.
- 字段命名与本表环境变量名保持一一对应, 不引入中间别名.
- 客户端配置不入本模块 (住 internal/cfhost).

事件目录: 无.
