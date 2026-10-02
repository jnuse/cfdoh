# ecs

业务逻辑:
- 决策次序: 规则覆盖 > 模式 off > 模式 always > 模式 rules (域名后缀命中 ECS_DOMAINS).
- 子网取客户端 v4 /24, v6 /48; 无客户端 IP 不带 ECS.
- 注入幂等: 替换已有 ECS option; 剥离删除全部 ECS option, 均不破坏 OPT 其余字段; 无 OPT 时合成 (class 1232, ttl 0).
- 身份串为截断子网的规范化文本, 折入缓存身份隔离应答.

对外接口:

```go
type Value struct { Family uint16; Prefix uint8; Addr []byte; Identity string }
func Make(clientIP string, v4Prefix, v6Prefix int) *Value
func ShouldUse(q *wire.Packet, cfg *config.Config, override, present bool) bool
func Add(q *wire.Packet, v *Value) *wire.Packet
func Remove(q *wire.Packet) *wire.Packet
```

数据所有权: — .

扩展规则:
- 模式集合固定三值, 新模式须经 PRD 变更.
- wire 操作全部经由 wire 模块, 不直接改报文字节.

事件目录: 无.
