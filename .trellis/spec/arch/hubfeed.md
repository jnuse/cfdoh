# hubfeed

业务逻辑:
- 定时拉取公开池 API (URL 可配, 默认 cfhub 端点, 置空停用), 周期可配 (默认 5 分钟).
- 仅采用 published 为真的池; 池内地址顺序即质量顺序, 每地址族取至多 6 条.
- 按 isp 字段写入运营商池 (scope isp:<name>), national 写入全国池; 写入走 pool 的 SetLearned.
- 逐池校验: 任一地址不在 Cloudflare 公布网段内则整池不采用, 其余池不受影响.
- 拉取成功后池有效期可配 (默认 30 分钟); 失败沿用旧池, 由 pool 惰性过期回落.
- 拉取在后台执行, 不阻塞查询路径.

对外接口:

```go
func Start(ctx context.Context, cfg *config.Config) error
func RefreshOnce(ctx context.Context, cfg *config.Config) error
```

数据所有权: 上次拉取时刻与各池摘要.

扩展规则:
- 新公开池源格式扩展解析函数, 不改校验与入池流程.
- 整池拒绝的防御语义不可放松为逐地址丢弃.
- 本模块只拉取与入池, 不参与应答改写路径.

事件目录:
- pool_feed_refresh — 拉取完成; detail: 各池地址数, 耗时, 是否成功.
- pool_feed_rejected — 整池拒绝; detail: 池名, 原因.
