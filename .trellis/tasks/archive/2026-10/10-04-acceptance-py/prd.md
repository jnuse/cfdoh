# Python 标准库验收测试套件

## Goal

为已全部实现的 cfdoh 构建用户视角验收套件: `test/acceptance/` 回归层 (受控真实上游, 覆盖 F-001 至 F-030 全量), `test/live/` 真实环境层 (默认不跑), 验收通过后挂入 CI. 全部代码仅用 Python 标准库.

## Requirements

- 零第三方依赖: test/ 下所有 import 为标准库, 可机械审计.
- test/ 为纯 Python 目录, 永不放 .go 文件; go build/vet/test 不受影响.
- 30 条 F 全量物化, 无 skip, 无中间态: 红即未达成或回归.
- 独立 oracle: mini DNS codec 独立实现, 与 Go 实现双实现交叉验证; 请求输入用冻结 fixture 字节.
- 上游层为受控真实上游: 真 TLS, 真 HTTP, 真 DNS wire, 数据按剧本可编程; 假上游同时记录出向报文供断言 (上游用户视角).
- 全部远程依赖受控: DoH 上游, cfrange 列表, ISP 表, cfhub API, ECH 源域名的 HTTPS 记录.
- 证书预生成为 fixture 提交, 经 SSL_CERT_FILE 注入被测子进程; 产品代码零测试钩子.
- 五类用户视角覆盖: 浏览器 (入向强断言), 上游 (出向 wire 断言), 探针/hub (admin 上报流), 运维 (进程生命周期与配置), cfhost 用户 (hosts 与退出码).
- 跨用户流为一等公民: 探针上报 → 浏览器观察到池生效; hub 污染 → 浏览器不受影响.
- F-029/F-030 做轻量静态验收 (文件存在性与关键字段); docker build 与 workflow 语法由 CI 闭环, 本地不跑.
- scripts/e2e.sh 职责并入 test/live/ 后删除; scripts/fake-upstream 不动.
- live 层读 E2E_HTTPS_PROXY 环境变量路由上游出网 (宿主 mixed 端口), 断言限弱断言.

## Acceptance Criteria

- [x] `python3 -m unittest discover -s test/acceptance` 全绿 (127 例, ~375s)
- [x] 覆盖映射可审计: F-001 至 F-030 每条至少一个测试, 测试文件名或 docstring 标注 F 编号
- [x] test/ 下无非标准库 import; 无 .go 文件
- [x] `go build ./... && go vet ./... && go test ./...` 不受影响
- [x] ci.yml 含 acceptance 步; live 层不进 CI
- [x] test/live/ 在代理可用时手动跑通 (吸收原 e2e.sh 全部场景, 7 例绿)
- [x] scripts/e2e.sh 已删除

## Notes

- 行为基线 refer/edge-smart-doh 不变; 断言语义以 .trellis/spec/prd/requirements.md 各节验收标准为准.
- 本套件为终局考卷: 全绿是 30 条 F 达成的证据, 与 implement.md 批次解耦.
