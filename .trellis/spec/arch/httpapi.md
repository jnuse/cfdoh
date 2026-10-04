# httpapi

业务逻辑:
- 两种监听: 直连模式 (内嵌 TLS, HTTP/1.1 与 HTTP/2) 与反代模式 (回环明文, TLS 由前置终止); Host 校验不在集合内返回 421.
- 路由: /dns-query 与配置的路径别名, /explain, /health, /probe, /admin/*; 其余 404. pprof 调试端点经 PPROF_ADDR 独立门控 (默认关闭, 监听独立地址, 不挂主路由).
- DoH 端点: Accept 与 Content-Type 校验 (406, 415), GET 与 POST 双通道, 包大小双检 (413), 非法请求包 400, 非 GET/POST 405.
- 请求参数解析 (?ip4, ?ip6, ?cf, ?ech, ?rules): 语法与上限强校验, 全部折入缓存变体.
- admin 鉴权: 双令牌 (管理令牌全权, 推送令牌仅运营商池), Bearer 常数时间比较; 未配置管理令牌时全部 admin 返回 404.
- admin 上报强校验: 地址逐个解析, 主机名语法白名单, source 与 ttl 钳制; 运营商池逐地址校验在 Cloudflare 网段内, 任一在外整批拒绝; site/github 上报 ttl 缺省 3600 钳 60-86400, h3 缺省 5400 钳 300-86400, github 空 hosts 报 400 (site 空列表为合法撤销).
- 自检报告存储与展示, 载荷可选 metaEch {state, echConfig, ttl, verified} 驱动 Meta ECH 三态 (F-015): rotated 学习新钥 (echConfig 须合法 ECHConfigList), ok 清除覆盖 (verified 与学习钥字节一致时续期), broken 暂停注入; ttl 缺省 86400 钳 300-604800, broken 再钳上限 86400; rotated 附非法 echConfig 时 400 并清除覆盖回种子 (有意分歧于 refer 的保持原态, 验收套件钉死); metaEch 与 problems/hosts 共存一次上报; explain 输出汇总各能力模块状态.
- 客户端识别头取值顺序 X-Real-IP → CF-Connecting-IP → X-Forwarded-For 首值; 自定义信任头 X-DoH-Client-IP 经 DOH_ORIGIN_TOKEN 门控 (请求携带常数时间匹配的 X-DoH-Origin-Token 时优先取该头首值); 反代模式下缺失时以 TCP 对端地址补齐.

对外接口:

```go
func New(cfg *config.Config) *Server
func (s *Server) Run(ctx context.Context) error
```

数据所有权: 自检报告表 (至多 8 来源).

扩展规则:
- 新端点登记路由表; 鉴权与输入校验前置不变.
- 解析逻辑不入驻本模块 (全部委托 resolver).
- 事件由属主模块发射, 本模块只做 HTTP 编解码与转发.

事件目录:
- listening — 监听启动; detail: 模式, 地址.
- selfcheck_failed — 自检上报失败结论; detail: source, 问题列表.
- meta_ech_report_rejected — metaEch rotated 上报携带非法 echConfig, 拒绝并清除覆盖; detail: source, 错误.
