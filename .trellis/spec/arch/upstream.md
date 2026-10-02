# upstream

业务逻辑:
- 顺序启动加对冲: 对冲间隔内无结果即启动下一个上游, 首个合法应答胜出, 中止其余在飞请求.
- 单上游失败立即启动下一个; 全部失败报错.
- 应答校验链: HTTP 2xx, Content-Type, 字节数上限, QR 位置位, 事务 ID 一致.
- 携带 ECS 的查询路由到 ECS 上游列表, 其余走普通列表.
- 同键并发未命中查询合并为一次外发.
- 辅助解析 ResolveAddresses 直接对冲查询 A/AAAA, 不走应答缓存; 供 pool (优选域名), rewrite (判定探测), ech (发布域名) 消费.

对外接口:

```go
type Result struct { Packet []byte; Upstream string }
func Query(ctx context.Context, query []byte, cfg *config.Config, withECS bool) (*Result, error)
func ResolveAddresses(ctx context.Context, name string, cfg *config.Config) (v4, v6 []string, err error)
```

数据所有权: 并发合并组表.

扩展规则:
- 新应答校验追加校验链, 不改对冲主流程.
- 新上游传输协议 (如明文 UDP DNS) 须经 arch 变更后另立实现, 不混入本模块.
- 超时与对冲参数只从 config 读入, 不引入模块内默认值.

事件目录:
- upstream_failure — 全部上游失败或末次尝试失败; detail: 错误链摘要.
