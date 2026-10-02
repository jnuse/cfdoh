# cfhost

业务逻辑:
- 主循环一轮: 拉取候选 (多源合并去重, 仅公网单播; 源含公开池 API, 优选域名, 静态列表) → 本地测速 (对 443 端口 TCP+TLS 握手计时, SNI 用管辖域名之一, 多轮取中位, 失败淘汰, 可选 HTTP 端到端验证) → 滞回判定 → hosts 区块更新.
- 测速全部失败时保留 hosts 现状不动.
- hosts 区块带标记 (# BEGIN cfhost 至 # END cfhost), 区块外逐字节保留; 原子更新; 最优地址未变化不重写; 更新后刷新系统 DNS 缓存.
- 单实例锁, 重复启动退出.
- Windows 服务化 (install/uninstall/start/stop) 与状态查询 (status); run-once 单轮执行.
- 状态文件记录在用地址与上轮测速摘要; 日志带轮转.

对外接口:

```go
type Config struct { ManagedDomains, Sources []string; Concurrency, Timeout, Rounds int; Hysteresis float64; FailoverRounds int; Interval time.Duration; HostsPath string }
func LoadConfig() (*Config, error)
func RunOnce(ctx context.Context, cfg *Config) error
func RunLoop(ctx context.Context, cfg *Config) error
func Install() error
func Uninstall() error
func Status() string
```

数据所有权: 状态文件 (在用地址, 上轮摘要, 下次刷新时刻); hosts 区块内容.

扩展规则:
- 新候选源扩展 Source 类型, 拉取与过滤主流程不动.
- 写入 hosts 的域名只来自管辖域名列表; hosts 写入路径唯一.
- 测速结论不向任何外部方上报; 可选上报功能默认关闭, 开启后仅将测速得到的地址列表发给自己配置的服务端.

事件目录:
- hosts_updated — hosts 区块地址变化; detail: 域名数, 在用地址.
- hosts_kept — 测速完成但滞回保留原地址; detail: 原地址, 新地址, 差距比例.
