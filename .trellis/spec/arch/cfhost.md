# cfhost

业务逻辑:
- 主循环一轮: 拉取候选 (多源合并去重, 仅公网单播; 源含公开池 API, 优选域名, 静态列表) → 本地测速 (对 443 端口 TCP+TLS 握手计时, SNI 用管辖域名之一, 多轮取中位, 失败淘汰, 默认开启可关闭的 HTTP 端到端验证) → 滞回判定 → hosts 区块更新. next_run 缺失或过期 (如状态落盘失败) 时按配置周期兜底休眠, 轮询不坍缩为连续重试.
- 候选源四形态语法: `pool:<url>[#<isp>]` (公开池 API, cfhub 形 JSON 对象 `{"pools":[{isp,family,ips:[{ip}],published}]}`, 地址在 ips[].ip 嵌套, 只取 published 且 isp 匹配, 缺省 national, 地址族按地址本身逐个判定), `domain:<域名>` (系统 DNS 解析 A), `list:<ip,...>` (静态), 其余 `https://...` (通用远程 API, 每行一个 IP 的文本或 JSON 字符串数组). 远程源仅接受 https 且走系统证书校验; 重定向仅限 https 目标 (含 10 跳上限), 降级跳转拒绝跟随.
- 状态文件默认路径 os.UserConfigDir()/cfdoh/cfhost-state.json, 领域含在用 v4/v6, 上轮摘要, 下次刷新时刻, 连续失败计数与上轮候选; 单实例锁文件 cfhost.lock (含 PID, O_EXCL 原子创建, 并发启动仅一实例持锁; 活实例拒绝, 死实例覆盖) 同目录, 仅常驻模式持有.
- 测速全部失败时保留 hosts 现状不动.
- hosts 区块带标记 (# BEGIN cfhost 至 # END cfhost), 区块外逐字节保留; 原子更新; 最优地址未变化不重写; 更新后刷新系统 DNS 缓存. 临时文件优先写系统 TEMP 目录 (System32\drivers\etc 是杀软重点布防目录, 在其中创建文件的扫描概率远高于 TEMP), TEMP 与 hosts 不同卷或不可用时回退 hosts 同目录以保持 rename 原子性; rename 遇 Access denied / sharing violation (杀软扫描句柄) 以 200ms 间隔至多重试 5 次, 耗尽按本轮跳过. hosts 读取与写入的瞬时错误 (如安全软件短暂锁定) 记告警并按本轮跳过: 不写 hosts, 在用地址与失败计数保持不变, 下周期重试, 守护不退出.
- 单实例锁, 重复启动退出.
- Windows 服务化 (install/uninstall/start/stop) 与状态查询 (status); run-once 单轮执行. status 在配置加载失败时仍按 CFHOST_STATE_PATH 或默认路径渲染状态, 不因配置缺失整体失败.
- 状态文件记录在用地址与上轮测速摘要; 日志带轮转 (超 1MiB 切至 .1 单代, 启动时与每次写入时检查, 长驻进程不重启也轮转).

对外接口:

```go
type Config struct { ManagedDomains, Sources []string; Concurrency, Timeout, Rounds int; Hysteresis float64; FailoverRounds int; Interval time.Duration; HostsPath, StatePath string; CandidateLimit int; HTTPVerify bool }
func LoadConfig() (*Config, error)
func RunOnce(ctx context.Context, cfg *Config) error
func RunLoop(ctx context.Context, cfg *Config) error
func Install() error
func Uninstall() error
func Status() string
```

数值默认与钳制区间以上方对照表为准; 新配置项同变更登记本表与 normalize 钳制, 键名与环境变量一一对应.

数据所有权: 状态文件 (在用地址, 上轮摘要, 下次刷新时刻); hosts 区块内容.

扩展规则:
- 新候选源扩展 Source 类型, 拉取与过滤主流程不动.
- 写入 hosts 的域名只来自管辖域名列表; hosts 写入路径唯一.
- 测速结论不向任何外部方上报; 可选上报功能默认关闭, 开启后仅将测速得到的地址列表发给自己配置的服务端.

## 环境变量与钳制区间 (唯一真源)

加载序: 默认值 → JSON 配置文件 → CFHOST_* 环境变量 (优先). 文件路径取
CFHOST_CONFIG, 未设时默认为可执行文件同目录的 cfhost.json (可携式布局;
exe 路径不可得时回退 UserConfigDir/cfdoh/cfhost.json). 状态文件, 单实例锁
与 cfhost.log 跟随配置文件所在目录 (CFHOST_STATE_PATH 可单独覆盖状态, 锁
与日志随状态). 文件为 snake_case 键, 零值表示未设 (hysteresis 与
http_verify 除外, 0 与 false 是合法显式值).

| 环境变量 | 文件键 | 语义 | 默认 | 钳制/备注 |
|---|---|---|---|---|
| CFHOST_MANAGED_DOMAINS | managed_domains | 管辖域名 (必填 ≥ 1) | (空即报错退出) | 逗号分隔; 每项去首尾空白与尾点后按规范形存储 |
| CFHOST_SOURCES | sources | 候选源 (必填 ≥ 1) | (空即报错退出) | 分号或换行分隔; 源四形态见上 |
| CFHOST_CONCURRENCY | concurrency | 测速并发 | 8 | 1–64 |
| CFHOST_TIMEOUT_MS | timeout_ms | 单地址每轮超时 | 2000 | 250–10000 |
| CFHOST_ROUNDS | rounds | 采样轮数 | 3 | 1–10 |
| CFHOST_HYSTERESIS | hysteresis | 滞回比例 | 0.2 | 0.0–0.9 |
| CFHOST_FAILOVER_ROUNDS | failover_rounds | 在用地址连续失效强制重选轮数 | 3 | 1–100 |
| CFHOST_INTERVAL_MIN | interval_min | 轮询周期 (分钟整数) | 60min | 钳 1min–24h; 唯一周期通道, 无亚分钟表达 |
| CFHOST_HOSTS_PATH | hosts_path | hosts 路径 | 系统标准路径 (Windows: System32/drivers/etc/hosts; 其余: /etc/hosts) | — |
| CFHOST_STATE_PATH | state_path | 状态文件路径 | 配置文件所在目录 cfhost-state.json | 锁与日志随状态目录 |
| CFHOST_CANDIDATE_LIMIT | candidate_limit | 候选数量上限 | 256 | ≤ 0 回默认; 无上限钳 |
| CFHOST_HTTP_VERIFY | http_verify | 测速 HTTP 端到端验证 (/cdn-cgi/trace) | true | 指针字段, 文件或环境变量显式 false 关闭 |

钳制动作记 "clamped" 日志; 非法数值环境变量直接报错退出 (与服务端回退默认不同). 重启生效, 不做热重载.

事件目录:
- hosts_updated — hosts 区块地址变化; detail: 域名数, 在用地址.
- hosts_kept — 测速完成但滞回保留原地址; detail: 原地址, 新地址, 差距比例.
