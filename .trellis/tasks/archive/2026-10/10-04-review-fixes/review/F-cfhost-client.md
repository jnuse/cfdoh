# F-cfhost-client 审查报告 (cfhost 客户端与客户端入口)

## 头部

- 组名: F-cfhost-client (internal/cfhost 全部非测试文件 + cmd/cfhost/main.go)
- 审查文件清单 (逐文件全读):
  - internal/cfhost/cfhost.go (115 行)
  - internal/cfhost/config.go (364 行)
  - internal/cfhost/hosts.go (148 行)
  - internal/cfhost/loop.go (252 行)
  - internal/cfhost/probe.go (150 行)
  - internal/cfhost/service_other.go (38 行)
  - internal/cfhost/service_windows.go (184 行)
  - internal/cfhost/sources.go (257 行)
  - internal/cfhost/state.go (119 行)
  - cmd/cfhost/main.go (82 行)
  - 测试文件通读用于确认已钉住的行为: config_test.go, hosts_test.go, loop_test.go, probe_test.go, service_test.go, sources_test.go, state_test.go
- 依据 spec: .trellis/spec/arch/cfhost.md (含环境变量与钳制区间表), .trellis/spec/arch/client-entry.md, .trellis/spec/prd/requirements.md F-023 至 F-027, 决策 note 2026-10-04-cfhost-轮询周期钳制下限保持-1-分钟
- 运行过的命令与结果:
  - `go vet ./internal/cfhost/ ./cmd/cfhost/` → 通过 (exit 0, 无输出)
  - `go test -race ./internal/cfhost/` → ok github.com/jnuse/cfdoh/internal/cfhost 5.395s (全部通过, 无数据竞争)
  - 另: 核对 golang.org/x/sys@v0.29.0 svc/mgr.CreateService 源码确认其对 exepath 调用 syscall.EscapeArg 自动加引号 (排除安装路径含空格疑点)

## Findings (按严重度排序)

### 1. [high] service_windows.go:44-48 — Windows 服务安装参数传 "run", 但入口没有 "run" 子命令, 服务启动即失败

- 代码: `internal/cfhost/service_windows.go:44-48`
  ```go
  s, err = m.CreateService(serviceName, exe, mgr.Config{
      ...
  }, "run")
  ```
  与 `cmd/cfhost/main.go:45-48`:
  ```go
  default:
      fmt.Fprintf(os.Stderr, "cfhost: unknown subcommand %q\n\n", args[0])
      usage()
      os.Exit(2)
  ```
- 违反 spec: client-entry.md "子命令分发: install, uninstall, start, stop, run-once, status; 无参数时进入服务模式 (RunLoop)"; PRD F-026 验收 "Given Windows 安装服务后系统重启, When 服务自启, Then 完成一轮拉取测速与 hosts 刷新".
- 失败模式: 在 Windows 上执行 `cfhost install` + `cfhost start` (或系统重启自启), SCM 以 binPath `"<exe>" run` 拉起进程; main.go 的 switch 没有 `case "run"`, 落入 default 分支打印 unknown subcommand 后 exit 2, 服务永远无法完成任何一轮拉取测速, F-026 的 P0 主路径在 Windows 上整体失效. 服务安装注释 "binpath = current executable + ' run'" 与 usage 文本 "(no args) run the daemon loop (also used by the Windows service)" 自相矛盾, 证实是遗漏而非有意分歧.
- 最小修复: CreateService 不传 "run" 参数 (无参数即进入服务模式), 与入口和 spec 目录一致.

### 2. [medium] config.go:234-238 — 域名校验用 trim 后副本, 存储却保留原始串, 带空白域名可静默使整个客户端失效

- 代码: `internal/cfhost/config.go:234-238`
  ```go
  for _, d := range cfg.ManagedDomains {
      d = strings.TrimSpace(d)
      if !validDomain(d) {
  ```
- 违反 spec: PRD F-027 "域名逐个语法校验"; cfhost.md 表 CFHOST_MANAGED_DOMAINS 语义为管辖域名 (测速 SNI 与 hosts 写入直接消费该列表).
- 失败模式: JSON 配置文件写 `"managed_domains": [" a.example.com"]` (前后空白; 环境变量路径经 splitCSV 已 trim, 仅文件路径触发). 校验对 trim 副本通过, 但 cfg.ManagedDomains 仍存原始串; probeOptions 取 `ManagedDomains[0]` 作 SNI (loop.go), TLS 握手以 " a.example.com" 做证书校验必然失败, 全部候选被淘汰, 每轮 v4top==nil, hosts 永不更新, 进程不报错只记录 best_v4=none 摘要 — 守护进程静默完全失效. 尾部点形式 ("example.com.") 属同类: validDomain 校验前 TrimSuffix 掉点, 存储仍带点.
- 最小修复: normalize 循环内将 trim (与去尾点) 后的值写回 cfg.ManagedDomains.

### 3. [low] state.go:86-102 — 单实例锁为 check-then-write, 无 O_EXCL, 并发启动窗口内两实例可同时持锁

- 代码: `internal/cfhost/state.go:91-99`
  ```go
  if data, err := os.ReadFile(lockPath); err == nil {
      ...pidAlive(pid)...
  }
  ...
  if err := os.WriteFile(lockPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
  ```
- 违反 spec: cfhost.md "单实例锁文件 cfhost.lock (含 PID, 活实例拒绝, 死实例覆盖) ... 仅常驻模式持有", "单实例锁, 重复启动退出"; PRD F-026 验收 "Given 重复启动第二实例, When 启动, Then 检测到锁后退出且不影响首实例".
- 失败模式: 两进程同时启动 (如服务自启瞬间用户又手动运行), 都读到 "锁不存在/死 PID", 都 WriteFile 成功, 双实例并行跑 RunOnce, 对 hosts 与状态文件并发写 (各自 temp+rename, 不会损坏文件但互相覆盖, hosts 在两套选优间抖动, 且先退出实例的 release 会删掉含对方 PID 的锁文件, 使存活实例失去保护). 单测只钉住串行场景 (TestLockRejectsLivePID / TestLockOverwritesDeadAndCorrupt), 未覆盖并发窗口.
- 最小修复: 用 os.OpenFile(O_CREATE|O_EXCL) 原子创建, 冲突时再读 PID 判死活后重试覆盖.

### 4. [low] cfhost.go:46-48 — Status() 在配置加载失败时丢弃 CFHOST_STATE_PATH, 输出错误的 "no state"

- 代码: `internal/cfhost/cfhost.go:46-48`
  ```go
  if cfg, err := LoadConfig(); err == nil && cfg.StatePath != "" {
      statePath = cfg.StatePath
  }
  ```
- 违反 spec: cfhost.md 环境变量表 "CFHOST_STATE_PATH | state_path | 状态文件路径"; PRD F-026 "status 子命令输出当前在用地址, 上轮测速摘要, 下次刷新时间".
- 失败模式: 用户设置了 CFHOST_STATE_PATH 但必填项 managed_domains 缺失 (或配置文件解析失败) 时, LoadConfig 返回 err, statePath 回退默认路径; 若实际状态文件在自定义路径上已存在, `cfhost status` 报 "no state", 与真实运行状态不符. status 是只读查询, 却被无关的必填校验连坐.
- 最小修复: LoadConfig 失败分支单独读 CFHOST_STATE_PATH 环境变量, 未设再用默认路径.

### 5. [low] cfhost.go:88-116 — 日志轮转只在进程启动时执行一次, 常驻期间不再轮转

- 代码: `internal/cfhost/cfhost.go:88-91, 104-111`
  ```go
  loggingOnce.Do(func() { ... })
  ...
  const rotateSize = 1 << 20
  if st, err := os.Stat(path); err == nil && st.Size() > rotateSize {
  ```
- 违反 spec: cfhost.md "日志带轮转."; PRD F-026 "日志带轮转".
- 失败模式: 轮转检查仅在 initLogging (进程启动, sync.Once) 时发生. 常驻服务连续运行数月不重启, cfhost.log 越过 1MiB 后持续增长, 永不切到 .1 — "带轮转" 的承诺只对每次重启生效, 长运行场景退化为无轮转, 磁盘占用无界.
- 最小修复: 包装 Writer 在写入路径按当前文件大小触发同样的 rotate 逻辑.

### 6. [low] loop.go:130-133 — 状态落盘失败时轮询间隔退化为连续重试, 违反定时周期

- 代码: `internal/cfhost/loop.go:130-133`
  ```go
  delay := time.Until(time.Unix(st.NextRun, 0))
  if delay <= 0 {
      continue
  }
  ```
- 违反 spec: PRD F-026 "定时轮询 (默认 10 分钟, 可配)"; cfhost.md 表 CFHOST_INTERVAL_MIN 语义.
- 失败模式: saveState 持续失败 (状态目录权限被收回, 磁盘满) 时, RunOnce 仍返回 nil (loop.go 仅 Warn), 磁盘上的 NextRun 停留在 0 或过期值, loadState 读回后 delay 恒 <= 0, 循环不休眠立即开始下一轮 — 轮询周期坍缩为 "单轮耗时", 以远高于配置周期的频率反复拉取远程源 (水源礼貌性问题, 正是 1 分钟下限决策要避免的), 且刷屏 Warn 日志.
- 最小修复: delay <= 0 时兜底休眠 cfg.Interval (或至少 minInterval).

### 7. [low] hosts.go:98-101 — hosts 读取的瞬时错误直接终止守护进程, 与无人值守目标冲突

- 代码: `internal/cfhost/hosts.go:99-102`
  ```go
  data, err := os.ReadFile(path)
  if err != nil && !errors.Is(err, fs.ErrNotExist) {
      return false, fmt.Errorf("read hosts: %w", err)
  }
  ```
- 违反 spec: PRD F-026 用户故事 "一次安装后客户端长期自动运行, 无需手工干预"; 同节 "安装文档说明安全软件对 hosts 修改的放行要求" 表明安全软件与 hosts 的交互是已预期场景.
- 失败模式: Windows 上安全软件短暂独占锁定 hosts (PRD 明示的邻接场景) 或其他瞬时读错误发生时, RunOnce 报错 → loopWithLock 返回 → RunLoop 退出; 服务安装未配置失败恢复动作 (service_windows.go CreateService 未设 Recovery), SCM 不会拉起, 客户端就此永久停摆, hosts 停留在旧地址直至人工干预.
- 最小修复: hosts 读失败按可重试错误处理 (记录日志, 本轮跳过, 下一周期再试), 而非向 RunLoop 传播致命错误.

### 8. [info] sources.go:39-42, 226 — 远程源客户端默认跟随重定向, https→http 降级重定向不被拒绝

- 代码: `internal/cfhost/sources.go:39-42` (defaultFetcher 无 CheckRedirect 约束), `sources.go:226` (`resp, err := client.Do(req)`)
- 涉及 spec: PRD F-023 "远程源仅接受 https 且走系统证书校验"; cfhost.md "远程源仅 https 系统证书".
- 不确定点: requireHTTPS 只校验首跳 URL; Go http.Client 默认跟随最多 10 次重定向且允许 https→http 跨 scheme 降级, 后续跳与正文传输脱离 TLS. 实际可利用性受限: 篡改的候选地址仍须通过 probe.go 的 SNI+系统证书 TLS 握手才能进入 hosts, 端到端攻击代价高; 且无法确证任何真实池源会发降级重定向. 若要闭合, 设置 CheckRedirect 拒绝非 https 目标即可.
- 结论: 登记为 info, 供 spec 侧决定是否显式登记该边界.

## 已核对无问题 (高风险不变量逐条)

- 源四形态语法 (pool:<url>[#<isp>] / domain: / list: / 其余 https://) 与 spec 一致, http://, ftp://, 空 pool, 非法 domain 拒绝 (sources.go:57-88, TestParseSource 钉住) → 一致
- pool 源只取 published 且 isp 匹配, 缺省 national; v4+v6 合并 (sources.go:135-162, TestFetchFromPool 钉住) → 一致
- domain 源走系统 DNS (net.DefaultResolver) 且仅 A 记录 (LookupNetIP "ip4"), 不依赖 daemon 自身 → 一致
- 仅公网单播: Unmap 后剔除回环/私网/链路本地单播, 另剔除多播与未指定 (严于 spec 但方向安全), v4-mapped 私网经 Unmap 后正确剔除 (sources.go:113-117) → 一致
- 多源合并去重保首见序, 超上限截断保首见序, CandidateLimit <= 0 回默认 256, 无上限钳 → 一致
- 单源失败容忍跳过; 全部源失败沿用上轮候选; 无候选且无历史时报错退出且不动 hosts (loop.go:41-49, TestRunOnceNoCandidatesNoHistory / TestFetchCandidatesAllFailed 钉住) → 一致
- 远程源响应 2MiB 读取上限, 非 2xx 视为失败, 无未限内存读 → 一致
- 测速: 443 端口, TCP 连接+TLS 握手整体计时, SNI 用首个管辖域名, 每轮独立超时预算, 多轮取中位 (偶数取下中位, 已钉住), 全轮失败淘汰, sem 限并发, 结果保输入序 (probe.go) → 一致
- 生产 TLS 走系统证书校验, InsecureSkipVerify 仅存在于测试注入缝 (newProbeTLSConfig) → 一致
- 可选 /cdn-cgi/trace 验证: 手动拨号钉死候选 IP, Host/SNI 用管辖域名, 判 http=crypto 或 2xx 非空体 (probe.go:112-150) → 一致
- 滞回: 无在用直接取最优; 在用存活时 newMedian < curMedian×(1-hysteresis) 才切换; 在用失效 streak 累加, 达 FailoverRounds 强制切换并清零; "仅快 5% 不切换 / 快 25% 切换 / 连续 3 轮失效强制切换" 三条 PRD 验收全部被单测钉住 (loop_test.go TestDecideHysteresis) → 一致
- v4 测速全败: hosts 现状保留, FailStreak 递增, 状态与 NextRun 仍落盘, 不报错 (loop.go:56-66, TestRunOnceProbeFailureKeepsHosts 钉住) → 一致
- v6: 全败或增益不足保留旧条目, 无可用 v6 时不写 v6 行; 渲染顺序 v4 全部域名后 v6 全部域名 (TestRenderBlockOrder / TestDecideV6 钉住) → 一致
- hosts 区块: 标记行匹配容忍 \r; 无 BEGIN 则文件末尾补换行后追加; 有 BEGIN 无 END 重建区块; 区块外字节逐字节保留 (前缀/后缀钉住); 渲染内容未变不重写 (mtime 断言钉住); temp 文件 + 保留原权限 + rename 原子替换; 更新成功后才 flushdns (仅 Windows, 失败仅告警) → 一致
- 状态文件: 损坏 JSON 视为空态不阻断启动; 原子写 (temp+rename); 领域字段覆盖在用 v4/v6, 上轮摘要, next_run, fail_streak, 上轮候选 → 一致
- 锁生命周期: 仅常驻 (RunLoop/loopWithLock) 持有, run-once 与 status 不持有; 活实例拒绝, 死实例与损坏锁覆盖; 释放删除锁文件 (串行语义钉住, 并发窗口见 finding 3) → 一致
- 配置加载序 默认 → JSON (CFHOST_CONFIG 显式路径读失败报错, 默认路径不存在忽略, 解析失败报错) → CFHOST_* 环境变量优先 (TestLoadConfigFileAndEnvPrecedence 钉住) → 一致
- 钳制区间逐项对照 spec 表: concurrency 8 / 1-64; timeout_ms 2000 / 250-10000; rounds 3 / 1-10; hysteresis 0.2 / 0.0-0.9 (文件侧指针支持显式 0); failover_rounds 3 / 1-100; interval 10min / 钳 1min-24h 且 CFHOST_INTERVAL_MIN 分钟整数为唯一周期通道 (与 2026-10-04 决策 note 一致, 0 钳到 1min 有测试钉住); candidate_limit 256 / <=0 回默认无上限钳; http_verify 默认 false; clamped 动作记日志; 非法数值环境变量报错退出 (与服务端回退默认不同) → 全部一致
- 重启生效, 无任何热重载路径 → 一致
- 入口薄壳: install/uninstall/start/stop/run-once/status 六个子命令齐全分发, 额外仅有 --version/help; 无参数进入 RunLoop; 不承载业务逻辑 → 一致 (Windows 服务参数缺陷见 finding 1)
- 并发与资源: probe 的 sem+WaitGroup 无 goroutine 泄漏; 定时器正确 Stop; ctx 取消后 fetch/probe 快速失败, 服务 Stop 走优雅退出路径; go test -race 通过 → 无发现
- 事件目录: hosts_updated (detail: 域名数, v4/v6 在用地址) 与 hosts_kept (detail: 原地址, 候选地址, 差距比例) 的名称与字段构成 → 一致

## 结尾计数

- high: 1
- medium: 1
- low: 5
- info: 1
