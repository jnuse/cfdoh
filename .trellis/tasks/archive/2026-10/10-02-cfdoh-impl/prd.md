# 实现 cfdoh 双组件 (服务端 + 客户端)

## Goal

按已冻结的三层 spec (prd 30 项功能 / cdd 52 条术语 / arch 19 模块) 实现 Go 项目 cfdoh: 服务端 (DoH 解析与应答改写) 与客户端 (本机测速与 hosts 维护), 含测试与发布流水线. refer/edge-smart-doh 为行为对照基线, 不作为代码依赖.

## Requirements

- 全部实现归 .trellis/spec/arch/modules.md 划分的 20 个模块, 路径与依赖列一致.
- 服务端行为满足 F-001 至 F-022, F-028; 客户端满足 F-023 至 F-027; 交付满足 F-029, F-030.
- wire 层防御性检查 (计数上限, 尾随字节, label 类型, SVCB 参数递增, 深拷贝) 不降级.
- 缓存键两段构成 (身份 + 变体) 与池翻转即刻穿透语义保真.
- 第三方依赖限于 golang.org/x/sync (并发合并); 其余标准库实现.
- 单元测试覆盖: wire 全类型往返与攻击包, pool 投票合并, cache 键与 TTL 语义, rules 匹配与动作, rewrite 改写链, cfhost 滞回与 hosts 区块.

## Acceptance Criteria

- [ ] go build ./... 与 go vet ./... 全绿
- [ ] go test ./... 全绿, 覆盖上列重点模块
- [ ] refer 测试用例集的 packet 用例移植通过 (F-002 验收)
- [ ] 服务端本地起动后 /health ok, /dns-query 对 A/AAAA/HTTPS 正常应答 (自测)
- [ ] /explain 输出池选择, 改写, ECH 注入决策链 (自测)
- [ ] cfhost run-once 在测试环境完成一轮并正确维护 hosts 区块
- [ ] Dockerfile 与 compose 样例可构建 (本地 build 验证)
- [ ] CI/release workflow 文件就位 (语法校验)

## Notes

- 行为基线 refer/, 验收对照其 /explain 语义.
- 实现批次与顺序住 implement.md; 模块接口签名住 .trellis/spec/arch/*.md.
