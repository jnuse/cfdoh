# config

业务逻辑:
- 环境变量与配置文件合并, 环境变量优先.
- 数值项全部钳制到区间, 超界值钳到边界并记日志.
- 令牌类缺失即标记对应功能关闭; 上游仅接受 https.
- 启动输出脱敏摘要 (令牌打码).

对外接口:

```go
type Config struct { /* 字段与 requirements F-022 对照表一一对应 */ }
func Load() (*Config, error)
func (c *Config) SanitizedSummary() string
```

数据所有权: 全局默认值表与钳制区间表.

扩展规则:
- 新配置项同变更登记 requirements F-022 对照表与本结构, 钳制集中在 Load.
- 字段命名与 PRD 环境变量名保持一一对应, 不引入中间别名.
- 客户端配置不入本模块 (住 internal/cfhost).

事件目录: 无.
