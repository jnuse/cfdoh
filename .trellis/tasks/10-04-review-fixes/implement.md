# Implement

逐条清单与修法见 prd.md / design.md; 细节真源 = 本目录 review/ 六份报告.
每批末: `go build ./... && go vet ./... && go test -race ./...` + 受影响 acceptance 模块; 批 5 末全量.

## 批 1: High (H1, H2)

- [ ] H1: pool.GithubStatus/SiteStatus 返回非 nil 空对象 + TestAdminHealth 独立绿 + 空态断言
- [ ] H2: main.go 增加 "run" 子命令进服务模式 + client-entry.md 登记 + 单测
- [ ] 批末验证: go 三连 -race + acceptance f020/f019/f021 模块

## 批 2: 服务端稳态与安全 (M1, M2, M3, M5, M6)

- [ ] M1: appendLearnedLocked 键排序; 多 scope 同内容重写标签不变单测
- [ ] M2: publish 表容量上限 256 插入序淘汰; ech.md 登记上限
- [ ] M3: Status 取锁后复查 meta nil
- [ ] M5: isp mapped CIDR IsValid 校验跳过; 污染行单测
- [ ] M6: EcsUpstreams 默认回退 Upstreams; 自配上游不泄露单测
- [ ] 批末验证: go 三连 -race + acceptance f013 (ECS 出向)/f028 模块

## 批 3: 改写链 (M7, M8, M9, L7)

- [ ] M7: X 分支用 classify() 门控, RewriteX 去内部复判; CNAME setup X 单测
- [ ] M8: PinAddresses 无 qname-A 回退首条 A 模板 + 无 A 补造; 改判 "no query-name a record untouched"
- [ ] M9: replaceFamily/DropAAAA 逐记录网段过滤; 混合应答单测; rewrite.md 补登记
- [ ] L7: DropAAAA 同步移除 ipv6hint
- [ ] 批末验证: go 三连 -race + acceptance f009/f014/f010 模块

## 批 4: cfhost 侧 (M11, L11-L15, I9)

- [ ] M11: 域名 trim/去尾点写回存储
- [ ] L11: 锁 O_EXCL 原子创建
- [ ] L12: status 配置失败单独读 CFHOST_STATE_PATH
- [ ] L13: 日志轮转写入路径触发
- [ ] L14: delay<=0 兜底休眠 Interval
- [ ] L15: hosts 读瞬时错误本轮跳过不终止
- [ ] I9: fetcher 拒绝降级重定向
- [ ] 批末验证: go 三连 -race + acceptance f023-f027 模块

## 批 5: 剩余 low + 裁决与登记 (M4, M10, L1-L6, L8-L10, I1-I8)

- [ ] M4: 交错合并 perBlock 限段 (裁决 1) + pool.md 登记强于 refer
- [ ] M10: wire.md 收编 ParseRelaxed 豁免 (裁决 2)
- [ ] L1: SaveSnapshot 互斥
- [ ] L2: decodeName 255/128 上限
- [ ] L3: 无 SOA 负应答返回 0
- [ ] L4: PRD F-004 登记 TTL 0 不可缓存
- [ ] L5: LearnedStatus 过滤过期 source
- [ ] L6: cache_write_error 补发射点
- [ ] L8: Accept 逐项判定对齐 refer
- [ ] L9: PATH_ALIASES 查重跳过
- [ ] L10: 配置文件行上限 4MiB
- [ ] I1: qtype 错型永不匹配 (修齐 refer)
- [ ] I2/I3/I4/I5/I6/I7/I8: 各 spec 登记落位
- [ ] 批末全量: go 三连 -race + acceptance 127 例全绿 + 与修复冲突用例登记齐

## 验证命令

```bash
go build ./... && go vet ./... && go test -race ./...
python3 -m unittest discover -s test/acceptance
go test -run TestAdminHealth ./internal/httpapi/   # 独立绿
```

## 回滚点

每批一次 commit; 批内失败回退到批首 commit.
