# Module Map

cfdoh 的模块划分: 模块, 代码落点, 依赖. 各模块的定义见其模块文档 (一模块一文件). 服务端与客户端无共享内部包; 域名匹配与规范化服务由 wire 提供, 供 rules, ecs, h3 复用.

| 模块 | 路径 | 依赖 |
|---|---|---|
| wire | internal/wire/ | — |
| config | internal/config/ | — |
| rules | internal/rules/ | wire |
| ecs | internal/ecs/ | wire |
| upstream | internal/upstream/ | config, wire |
| cache | internal/cache/ | config, wire |
| pool | internal/pool/ | upstream, wire |
| cfrange | internal/cfrange/ | config |
| isp | internal/isp/ | config |
| h3 | internal/h3/ | wire |
| hubfeed | internal/hubfeed/ | config, cfrange, pool |
| ech | internal/ech/ | config, upstream, wire |
| rewrite | internal/rewrite/ | config, wire, cfrange, upstream, pool, ech, h3 |
| resolver | internal/resolver/ | config, ecs, rules, cache, upstream, pool, rewrite, isp |
| httpapi | internal/httpapi/ | config, resolver, pool, h3, ech, cfrange |
| 服务端入口 | cmd/cfdoh/ | httpapi, config |
| cfhost | internal/cfhost/ | — |
| 客户端入口 | cmd/cfhost/ | cfhost |
| 构建与发布 | Dockerfile, deploy/, .github/workflows/ | — |

## 分层说明

- 基础层: wire, config — 零内部依赖; wire 承担报文编解码与域名规范化匹配, 是所有解析侧模块的地基.
- 能力层: rules, ecs, upstream, cache, pool, cfrange, isp, h3, ech, hubfeed — 各管一个 PRD 功能域, 互不依赖 (pool 与 ech 对 upstream 是解析服务消费).
- 改写层: rewrite — 消费能力层产出改写应答; 唯一同时依赖 pool, ech, h3, cfrange 的模块.
- 编排层: resolver — 一次查询的完整管线: 计划 (ECS 决策与缓存身份), 缓存读写策略, 过期服务, 改写链编排; 不感知 HTTP.
- 接入层: httpapi — TLS 监听, Host 校验, 路由, 请求参数解析, admin 鉴权与上报校验; 不含解析逻辑.
- 客户端: cfhost — 候选拉取, 本地测速, hosts 区块, 服务化安装, 配置, 主循环; 单包多文件, 独立于服务端全部模块.
- 交付: 构建与发布 — 容器镜像, compose 样例, CI 与 release 流水线; 不合入运行时代码路径.
