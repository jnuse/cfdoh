# Design

技术设计的划分与依赖住 .trellis/spec/arch/modules.md, 术语与代码命名住 .trellis/spec/cdd/terms.md; 本文只补 spec 未拍板的实现决策.

## 工具链与依赖

- Go 单模块, go.mod module 名 `github.com/jnuse/cfdoh` (仓库名落定后同变更全局替换).
- Go 版本 1.23+; CGO_ENABLED=0 静态编译.
- 第三方依赖仅 golang.org/x/sync/singleflight; TLS/HTTP/JSON/压缩全标准库. 不引入 wire 编解码库 (自研, 保防御性检查).
- 测试仅标准 testing + net/http/httptest; 不引入断言库.

## 并发模型

- pool, h3, ech, hubfeed 的状态表用 sync.RWMutex 保护 (读多写少); 单写整表覆盖, 读时合并.
- cache 用分片 LRU (按身份哈希分 16 片, 各片独立锁), 避免全局锁竞争.
- resolver 每查询无共享可变状态; Options 值传递.
- 后台任务 (hubfeed 拉取, cfrange/isp 刷新, 缓存快照) 由 cmd/cfdoh 的 ctx 统一调度, 各自 time.Ticker.

## HTTP 服务

- 反代模式: net/http 标准服务器, 127.0.0.1:8787.
- 直连模式: tls.Listen + http2 标准库 (http.Server TLSConfig NextProtos h2/http1.1), 证书文件路径配置.
- /dns-query GET/POST 与 admin JSON 端点共用一个 mux; 路径别名映射表在 config.
- 优雅退出: ctx cancel → server.Shutdown (10s 上限) → 快照 → exit.

## wire 层实现要点 (refer 移植坑, 由分析结论钉死)

- 解码 RDATA 一律 copy 出独立 []byte; 不引用输入缓冲.
- 压缩指针: visited map[int]bool + 32 跳上限; 指针目标允许包内任意偏移.
- IPv6 渲染 8 组完整 hex; ParseIPv6 拒绝 IPv4-mapped 文本; ParseIPv4 容忍前导零 (与上游一致).
- OPT: class=payload size, ttl=ext-rcode/version/DO; MakeServfail flags 掩码 0x7910 逐位照抄.
- ECS 掩码: 末字节仅 prefix%8 非 0 时按位掩.

## cfhost 实现要点

- Windows 服务: golang.org/x/sys/windows/svc — x/sys 归入允许依赖 (标准库延伸).
- hosts 区块: 读全文 → 定位标记区块 → 替换区块内容 → 临时文件 + os.Rename → 保留权限 (先 stat 原 mode).
- 测速: net.Dialer + crypto/tls (SNI 配置域名, InsecureSkipVerify=false 校验 CF 证书链), 计时到手shake完成; HTTP 验证 GET /cdn-cgi/trace 校验 http=crypto 语义.
- 状态文件 JSON: {current: {domain: ip}, last_summary, next_run}.

## 测试策略

- wire: 参照 refer test/packet.test.ts 用例集移植 + 攻击包 (环指针, 超长 label, 尾随字节, 越界 RDATA).
- 各能力模块: 表驱动单测; pool/cache 语义逐条对 F-004/F-007 验收.
- httpapi: httptest 端到端 (DoH GET/POST, admin 鉴权矩阵, explain 骨架).
- cfhost: hosts 区块保真 (区块外逐字节), 滞回判定表驱动; Windows 服务部分用接口抽象跳过 CI.
- 集成自测: 起服务端 + 假上游 (httptest DoH), 验证改写链与缓存.
