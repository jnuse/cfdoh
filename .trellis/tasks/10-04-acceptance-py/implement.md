# Implement

用例真源: 同目录 testplan.md (116 用例 + 6 哨兵, 含已知取舍六条). 实现逐条物化, 不得增删语义; 断言语义以 .trellis/spec/prd/requirements.md 对应 F 节验收标准为准.

执行批次: 每批末尾跑 `python3 -m unittest discover -s test/acceptance` 与 `go build ./... && go vet ./... && go test ./...`, 新增部分全绿才进下一批.

## 批 1: 基础设施

- [x] test/_shared/dnscodec.py: 编码 (header/question/OPT+ECS), 解码 (flags/question/A/AAAA/CNAME/HTTPS SvcParam/OPT ECS), 压缩指针跟随
- [x] test/_shared/fakestack.py: 受控 https 工厂 (应答表/延迟/失败注入/出向记录, 多角色复用)
- [x] test/_shared/harness.py: build/spawn/就绪/SIGTERM/退出码与快照断言/DoH 与 admin 客户端封装/端口登记
- [x] test/_shared/preflight.py: PF1-PF4 (版本/端口占用含 PID/证书有效期/启动日志扫描); live 哨兵 PF5-PF6 骨架
- [x] fixtures: 证书与密钥预生成提交, make-certs.sh; 冻结请求字节与假上游应答字节
- [x] 冒烟: 单实例起停 + /health + 一次 DoH 查询走通

## 批 2: DoH 端点合同 (F-001, F-002 端点面, F-004 用户可观察, F-005, F-017)

- [x] F-001: 200/400 (QR, 非法 b64, 缺 dns)/406/415/413/405, ID 回填, 应答头三件套, 路径别名
- [x] F-002 端点面: 攻击包 fixture (环指针/尾随字节) 打端点得 400 (完整 wire 语义由 Go 单测负责)
- [x] F-004: TTL 内二次查询不出向 (上游记录数=1), 上游全挂 + 过期缓存 → TTL 30 应答, 无缓存 → SERVFAIL 位保真
- [x] F-005: X-Real-IP → explain 显示并影响池选择, XFF 首值回退
- [x] F-017: ?ip4/?ip6/?cf/?ech/?rules 合法生效与非法 400, 参数折入缓存键互不污染

## 批 3: 池与改写 (F-007 至 F-016, F-018, F-020)

- [x] F-007 分层: 显式参数 > client /24 池 > isp > national; 层 TTL 过期回落
- [x] F-008 admin 鉴权矩阵: 401/403 (hub 写 default)/400 (非 CF 网段整批拒)/404 (未配 ADMIN_TOKEN 需独立实例)
- [x] F-009 池改写: A 记录全来自池, 轮转 (多次查询首条分布 ≥2), 非 CF 原样, AAAA drop 开关
- [x] F-010 ECH: CF 站点 HTTPS 含 ech, 非 CF 无注入, 源不可达不阻塞
- [x] F-011 h3: verdict 上报后 ALPN 门控, 翻转即刻生效
- [x] F-012 展平: CNAME 链记录挂查询名, explain chromium 判定可用
- [x] F-013 出向断言: .cn 域名上游收到 ECS /24, 非 .cn 无 ECS, 自带 ECS 至多一个
- [x] F-014 GitHub/X/站点池钉住与撤销回落
- [x] F-015 Meta 三态 (种子/学习/暂停) 与换代
- [x] F-016 规则: block → REFUSED 无外发, replace-a 继承 TTL, 远程规则失败回退
- [x] F-018 explain: 决策链逐步, 非法 name 400, 只读
- [x] F-020 admin 状态查询与自检上报
- [x] 跨用户流: 探针上报 → 浏览器观察到; hubfeed 污染池 → 浏览器不受影响 (F-028 的池校验面)

## 批 4: 上游行为与生命周期 (F-003, F-019, F-021, F-022, F-028)

- [x] F-003: 首上游快返不启第二 (出向计数), hedge 超时并发, 全失败兜底链
- [x] F-019: /health 405 矩阵, /probe 回显
- [x] F-021: SIGTERM 快照 4 件套, 重启即恢复 (上报池免再报), PUBLIC_HOSTNAMES 421, 直连模式 TLS 证书 (fixtures 复用)
- [x] F-022: 零配置默认应答, 数值钳制启动日志, 环境变量优先于配置文件
- [x] F-028: 受控 cfhub 拉取入池, 污染池整池拒绝, 失败沿用旧池

## 批 5: 客户端 (F-023 至 F-027)

- [ ] F-023: 多源合并去重, 私网过滤, 单源失败容忍 (受控 API 源)
- [ ] F-024: run-once 轮后状态文件含耗时或淘汰标记; 滞回与强制重选用注入测速结果断言
- [ ] F-025: hosts 区块两行, 区块外逐字节, 最优不变不重写 (mtime)
- [ ] F-026: run-once/status 子命令, 第二实例撞锁退出, RunLoop 周期轮询 (受控源计数 ≥2 轮)
- [ ] F-027: 最小配置运行, 空域名报错退出, 环境变量优先

## 批 6: 交付静态验收 + live 层 + CI (F-029, F-030)

- [ ] F-029/F-030 静态断言: 文件清单, compose healthcheck/非 root/卷, release matrix/sha256/GHCR
- [ ] test/live/: 吸收 e2e.sh 全场景 (三类型查询, explain, probe, admin 矩阵, 快照, 重启), E2E_HTTPS_PROXY 注入
- [ ] 删除 scripts/e2e.sh
- [ ] test/live/MANUAL.md: S 系列 (cfdoh 浏览器用户) + C 系列 (cfhost 客户端用户) 手动清单
- [ ] ci.yml 追加 acceptance 步
- [ ] 全量验证: discover acceptance 全绿 + go 三连全绿 + live 手动跑通

## 验证命令

```bash
python3 -m unittest discover -s test/acceptance -v
python3 -m unittest discover -s test/live -v   # 需代理: E2E_HTTPS_PROXY=...
go build ./... && go vet ./... && go test ./...
grep -rho "F-0[0-9][0-9]" test/ | sort -u       # 映射审计: 应覆盖 001-030
```

## 回滚点

每批一次 commit; 批内失败回退到批首 commit.
