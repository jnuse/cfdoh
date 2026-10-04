# Design

讨论已拍板, 本文固化实现决策. Go 侧测试约束 (spec design "测试仅标准 testing + httptest") 管辖 Go 模块测试, 本套件为其外部的第三层, 不违反.

## 分层定位

三层金字塔: Go 单测 (函数边界, 全类型往返与攻击包) → Go httptest (HTTP 边界合同) → Python acceptance (用户边界, 独立 oracle, 进程级). race 检测由 Go 层负责, 验收层不承担.

## 目录结构

```
test/
  _shared/                  # 前导下划线: unittest discover 不收集
    __init__.py
    dnscodec.py             # mini DNS wire codec (独立 oracle)
    fakestack.py            # 受控 https 服务工厂 (上游/cfrange/isp/cfhub/ech 复用)
    harness.py              # build/spawn/就绪等待/停止/客户端封装
    preflight.py            # 环境哨兵: 已知情况固化, 失败即报成因与对策
  acceptance/
    fixtures/               # 冻结请求字节, 假上游应答, 证书与密钥, 再生成脚本
    test_f001_doh_endpoint.py
    ...                     # 按 F 组织, 一个文件一至多条 F
    test_f030_delivery.py
  live/
    test_live_upstreams.py  # 真实三上游冒烟 (吸收 scripts/e2e.sh 场景)
```

## dnscodec.py 范围

- 编码: header, question, OPT (含 ECS option 合成), 常见查询构造 helper.
- 解码: header flags, question, A/AAAA/CNAME/HTTPS (SvcParam: alpn, ipv4hint, ipv6hint, ech), OPT (ECS option 读出), 压缩指针跟随含跳数上限.
- 只覆盖断言所需子集, 不追求全类型; 自身无测试, 依赖双实现交叉验证.

## fakestack.py

- ThreadingHTTPServer + ssl.SSLContext(PROTOCOL_TLS_SERVER).wrap_socket, 载入 fixtures 证书.
- 可编程: 按 (qname, qtype) 应答表; 每路径延迟; 按次数/永久失败注入; 收到的请求字节全量记录 (出向断言的来源).
- 一个工厂实例化多个角色: DoH 上游, cfrange 列表, ISP 表, cfhub API, ECH 源域名的 HTTPS 应答.

## harness.py

- 复用 e2e.sh 已验证的编排: go build 一次 → subprocess.Popen 注入环境 (SSL_CERT_FILE, UPSTREAMS, ECS_UPSTREAMS, ADMIN_TOKEN, HUB_TOKEN, CACHE_PERSIST_PATH, 各远程源 URL) → 轮询 /health 就绪 → 场景 → SIGTERM → 断言退出码 0 与快照文件.
- setUpClass 起实例, 多用例复用; 每文件按需独立实例 (环境变量组不同则分实例).
- 客户端封装: DoH GET/POST, admin JSON POST, 原始头控制 (Accept/Content-Type/超长 body).

## 环境哨兵 (preflight.py)

已知情况全部写死在代码里, 排查信息先于故障出现:

- acceptance: go/python 版本; 实例端口与假栈端口逐个空闲检测, 被占时附占用进程 PID 与命令行并给出已知成因 (残留 cfdoh) 与对策; fixtures 证书 notAfter 检查; 启动后日志扫描 "address already in use".
- live: 代理哨兵 — E2E_HTTPS_PROXY 优先; 未设时动态取 `ip route show default` 网关 (WSL 网关 IP 每次重启会变, 禁止写死 172.26.0.1), 探测宿主 10808 mixed 端口 (http/socks5 双协议, 已知事实); 再经代理预检 1.1.1.1 DoH (3s 超时). 任何一步失败输出成因清单: 代理未开 / 未允许局域网 / 规则模式未覆盖.
- 客户端对 127.0.0.1 一律 http.client 显式连接, 不读环境代理 (已知 e2e.sh 曾需 NO_PROXY 处理同类问题, 此处结构性规避).

## 端口与实例管理

- 实例族与假栈端口在 harness 内静态登记 (18101 起连续分配), 全套件复用; 起实例前 preflight 已确保空闲.
- 假栈 (fakestack) 端口同样登记检测.
- 等待类用例 (TTL 过期) 的等待时长与成因在用例内注释标注.

## 证书 fixture

- openssl 预生成自签 CA + 服务端证书对 (SAN 覆盖 127.0.0.1 与测试主机名), 有效期 10 年, 提交 fixtures/.
- 再生成脚本 fixtures/make-certs.sh 随附, 手动执行, 不进任何自动流程.

## live 层

- 环境变量 E2E_HTTPS_PROXY 传给被测进程 (宿主 mixed 端口 10808, http:// 或 socks5:// scheme 均可).
- 断言限于: 三默认上游任一应答合法, 事务 ID 回填, 非 SERVFAIL, 耗时上限, /explain 骨架, 优雅退出与重启恢复 (原 e2e.sh 全场景).

## F-029/F-030 静态验收

- 文件存在: Dockerfile, deploy/compose.yml, deploy/env.example, deploy/*.service, nginx 样例, .github/workflows/{ci,release}.yml.
- 结构断言: compose 含 healthcheck, 非 root 用户, 快照卷挂载; release workflow 含双组件多平台 matrix, sha256, GHCR 推送步.
- 不执行 docker build, 不做 YAML 深度语法校验 (标准库无 YAML; CI 自身闭环).

## CI 挂载

- ci.yml 追加一步: `python3 -m unittest discover -s test/acceptance` (放在 go test 之后).
- live 层不挂 CI.

## 用例真源

- testplan.md 为逐用例清单 (116 用例 + 6 哨兵), 实现不得增删语义; 已知取舍六条列于其末尾, 过目确认后生效.

## 与现有资产关系

- scripts/e2e.sh 删除, 场景并入 test/live/.
- scripts/fake-upstream (Go) 保留不动, 超出本任务范围.
