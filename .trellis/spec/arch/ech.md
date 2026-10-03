# ech

业务逻辑:
- 配置来源优先级: 请求指定域名 > 静态 base64 > 发布域名 (默认 cloudflare-ech.com) 的 HTTPS 记录解析 (缓存).
- base64 输入校验为合法 ECHConfigList 字节串, 非法拒绝.
- Meta 三态: 种子 (静态配置生效), 学习 (探针回收的新钥), 暂停 (不注入, 返回未污染应答); 探针报 ok 且字节一致时学习钥续期.
- Meta 配置字节或过期变化递增代数; 代数折入 Meta 域名 HTTPS 应答缓存键.
- 发布域名解析走 upstream 辅助解析, 结果带缓存, 失败不阻塞应答 (由 rewrite 兜底).

对外接口:

```go
func ConfigFor(ctx context.Context, sourceDomain string, cfg *config.Config) ([]byte, error)
func Validated(base64 string) ([]byte, error)
type MetaState int
type StatusReport struct { Mode string; Bytes int; Until int64; Source, Reason string; Active bool }
func SetMeta(cfgList []byte, ttl int, source, reason string)
func SetMetaSuspended(ttl int, source, reason string)
func ClearMeta()
func MetaOverride() (cfgList []byte, state MetaState)
func MetaCacheTag() string
func MetaConfirm(verified []byte, ttl int, source string)
func Status() *StatusReport
```

数据所有权: 发布域名配置缓存与时刻; Meta 状态 (配置字节, 过期, 来源, 原因) 与代数.

扩展规则:
- 新配置来源插入优先级链, 不改注入动作 (注入住 rewrite).
- Meta 三态状态机转移固定, 新状态须经 PRD 变更.

事件目录:
- meta_ech_seed_ok — 探针确认种子有效, 覆盖清除; detail: source.
- meta_ech_rotated — 学习新钥生效; detail: source, 字节数, ttl.
- meta_ech_suspended — 注入暂停; detail: source, 原因摘要, ttl.
