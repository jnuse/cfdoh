# httpapi

业务逻辑:
- 两种监听: 直连模式 (内嵌 TLS, HTTP/1.1 与 HTTP/2) 与反代模式 (回环明文, TLS 由前置终止); Host 校验不在集合内返回 421.
- 路由: /dns-query 与配置的路径别名, /explain, /health, /probe, /admin/*; 其余 404.
- DoH 端点: Accept 与 Content-Type 校验 (406, 415), GET 与 POST 双通道, 包大小双检 (413), 非法请求包 400, 非 GET/POST 405.
- 请求参数解析 (?ip4, ?ip6, ?cf, ?ech, ?rules): 语法与上限强校验, 全部折入缓存变体.
- admin 鉴权: 双令牌 (管理令牌全权, 推送令牌仅运营商池), Bearer 常数时间比较; 未配置管理令牌时全部 admin 返回 404.
- admin 上报强校验: 地址逐个解析, 主机名语法白名单, source 与 ttl 钳制; 运营商池逐地址校验在 Cloudflare 网段内, 任一在外整批拒绝.
- 自检报告存储与展示; explain 输出汇总各能力模块状态.
- 客户端识别头取值顺序 X-Real-IP → CF-Connecting-IP → X-Forwarded-For 首值.

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
