# Design

修复技术方案. 逐条细节 (代码位置, 失败模式, 证据) 以 review/ 报告为准, 本文只定修法方向与 spec 落点.

## 修法方向

### High

**H1 /admin/health nil panic**: pool 层修契约 — GithubStatus()/SiteStatus() 无活跃池时返回非 nil 空对象 (`&HostPoolStatus{}`), 调用点 (httpapi 两处) 不动. 层内修契约优于逐调用点判 nil: 接口多个消费点, 空态是合法状态而非错误. 同步 pool.md 对外接口注释 (返回值永非 nil). 回归: 单跑 TestAdminHealth 绿 + 新增空态断言.

**H2 Windows 服务 "run"**: cmd/cfhost/main.go 子命令表增加 "run" (与无参数同, 进入服务模式 RunLoop). 兼容已发布的 v1.0.0/v1.1.0 安装参数; service_windows.go 安装参数保持 "run" 不变 (显式优于隐式). client-entry.md 登记子命令.

### Medium

**M1 ContentTag 抖动**: appendLearnedLocked 序列化前对表键排序 (sort.Strings), 使哈希与 map 迭代序/写入序无关. 表键序无行为语义 (读时按排名输出), 排序零副作用; 不改 set 的 order 语义 (容量淘汰仍按插入序). 回归: 多 scope 相同内容周期重写, 标签不变.

**M2 ech publish 无界**: publish 表加容量上限 (插入序, 超限淘汰最早; 上限 256, 常量集中). 不选白名单方案: ?ech= 任意域是 PRD F-017 明文能力, 保留能力, 只封内存. 登记上限到 ech.md.

**M3 ech Status TOCTOU**: 取 mu 后复查 meta == nil 返回 nil. 单行防御, 与 refer 判空语义一致.

**M4 交错限段 (裁决 1)**: 交错循环复用共识路径的 perBlock 计数 (达到 maxPerBlock 跳过该地址). pool.md 扩展规则补登记: "交错路径同受每 /24 ≤2 约束, 强于 refer (refer 交错无此限), 有意强化: 防单探针垄断单 /24". Go 单测: 三列表无共识 + 某 /24 六地址, 断言输出 ≤2.

**M5 isp mapped CIDR**: Unmap 后校验 prefix.IsValid() (bits ≤ addr.BitLen()), 无效 continue. 单测: `foo ::ffff:1.2.3.0/120` 被跳过, v6 查询回落全国层.

**M6 ECS 回退**: cfg.EcsUpstreams 默认取解析后的 cfg.Upstreams (UPSTREAMS 未设时同为内置三元组, 行为不变; 仅自配 UPSTREAMS 时回退跟随). 与 config.md 表 "同 UPSTREAMS" 对齐, 无需改 spec.

**M7 X probe**: resolver X 分支改用 classify() 结果门控 RewriteX (classify 含 cdn.cloudflare.net 探测); RewriteX 内部 UsesCloudflare 复判移除 (判定唯一来源在 resolver, 避免 dual-source 漂移). rewrite.md 判定句已是正确语义, 无需改; resolver.md 无需改 (调用细节). Go 单测: CNAME setup 形态 X 域名 (地址不在网段 + probe 域名可解析) 被改写.

**M8 PinAddresses CNAME**: 无 qname-owned A 时, 回退用应答中首条 A 记录 (任意 owner) 作 TTL/类型模板钉住; 应答无任何 A 记录时在 qname 下补造 (refer 语义). 既有钉住现状的 Go 用例 ("no query-name a record untouched") 改判. 展平步骤在其后归名, 顺序不变.

**M9 逐记录替换**: replaceFamily 改为逐条过滤 — 仅替换地址落在 CF 网段内的 A/AAAA; DropAAAA 仅删网段内 AAAA 与对应 hint. 复用 cfrange.Contains. rewrite.md 补一句 "混合应答仅替换网段内记录 (对齐 refer)". Go 单测: 混合 CF/非 CF 应答, 非 CF 记录原样.

**M10 ParseRelaxed (裁决 2)**: wire.md 防御性检查清单补登记: "上游应答解析 (upstream 校验链, resolver 刷新, ech 源域) 使用 ParseRelaxed 允许尾随字节, 对齐真实上游互操作容错; 入站查询与缓存存取保持严格 Parse." 不改码.

**M11 cfhost trim**: normalize 循环写回 trim (与去尾点) 后的值到 cfg.ManagedDomains. 单测: 带空白/尾点域名经 LoadConfig 后存储为规范形.

### Low / Info (修法摘要)

- L1: SaveSnapshot 全程持模块级互斥锁 (同一 Cache 实例内定时/退出互斥).
- L2: decodeName 累计 wire 长度 > 255 或 label 数 > 128 报错.
- L3: ResponseTTL 负应答无 SOA 分支返回 0 (不缓存), 对齐 refer.
- L4: PRD F-004 补 "TTL 0 的记录视为不可缓存" (登记偏差, 行为保留).
- L5: LearnedStatus Sources 只列 expiresAt > now 的表项.
- L6: store 分支 Put 拒存与 Encode 失败两点补发 cache_write_error (slog DEBUG 门控, 同 prefetch_error 款式).
- L7: RewriteAddresses 的 CFDropAAAA 分支同步 removeSvcParam(ParamIPv6Hint).
- L8: Accept 校验改逗号分割逐项 trim + startsWith("application/dns-message"), `*/*` 项精确等于才放行.
- L9: 别名注册前查重 (内置路由集合 + 已注册集合), 冲突 slog Warn 跳过.
- L10: readFileConfig scanner.Buffer(64KiB, 4MiB).
- L11: 锁创建改 O_CREATE|O_EXCL; 冲突时读 PID 判死活, 死则删除后重试一次.
- L12: Status() LoadConfig 失败分支: 读 CFHOST_STATE_PATH env, 未设用 defaultStatePath(resolved config path).
- L13: 自定义 Writer 包装, 每次 Write 检查文件大小超 1MiB 触发轮转 (同款 rename 逻辑).
- L14: delay <= 0 时兜底 time.Sleep(cfg.Interval).
- L15: hosts 读错误 (非 ErrNotExist) 记 Warn 返回 "本轮跳过" 信号, RunOnce 容忍不向 RunLoop 传播致命错误.
- I1: qtypeList 解析失败返回哨兵使该条件永不匹配 (规则整体不命中), 对齐 refer; 单测钉.
- I2/I3/I5/I8: rules.md / h3.md / httpapi.md 各补一句登记 (字典序展开, 无前缀主机路由, 字典序截断, ttl 0 当缺省).
- I4: pool.md 登记零地址优选域名计失败边界.
- I6: resolver.md 登记判定采样时机 "规则后改写前".
- I7: rewrite.md 补 Flatten 边界描述 (保 CNAME, 不封顶 TTL, 首记录 CNAME 假设, 尾部记录归名) + v6 hint 保留行为.
- I9: cfhost fetcher 设 CheckRedirect: 目标非 https 返回错误.

## 测试策略

- 每条修复 Go 单测钉住 (新用例或改判既有用例); H1 额外要求 TestAdminHealth 脱离测试顺序独立绿.
- acceptance 套件跑全量: 修复不破坏 127 例; 与修复冲突的用例修判并在 implement.md 登记. 允许为 H1 (admin/health 默认态) 与 M9 (混合应答) 补 acceptance 断言, 其余以 Go 单测为钉.
- race 全程绿 (M1/M3/L1 涉及并发).

## 回滚

每批一 commit; 批内失败回退批首. 批次顺序: A (high) → B (服务端稳态/安全) → C (改写链) → D (cfhost 侧) → E (剩余 low + spec 登记).
