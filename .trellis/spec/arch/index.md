# Architecture Documents

项目结构的唯一现在时真源. 划分住本文的模块图谱 (全局唯一); 定义住各模块文档 (一模块一文件). schema 真源在代码与配置文件, 本层只装语义并链接真源.

## 文档清单

- modules.md — 模块划分: 模块, 路径, 依赖, 分层说明.
- wire.md — wire 的定义.
- config.md — config 的定义.
- rules.md — rules 的定义.
- ecs.md — ecs 的定义.
- upstream.md — upstream 的定义.
- cache.md — cache 的定义.
- pool.md — pool 的定义.
- cfrange.md — cfrange 的定义.
- isp.md — isp 的定义.
- h3.md — h3 的定义.
- hubfeed.md — hubfeed 的定义.
- ech.md — ech 的定义.
- rewrite.md — rewrite 的定义.
- resolver.md — resolver 的定义.
- httpapi.md — httpapi 的定义.
- server-entry.md — 服务端入口的定义.
- cfhost.md — cfhost 的定义.
- client-entry.md — 客户端入口的定义.
- build-release.md — 构建与发布的定义.

## 文档格式

- 划分: 住 modules.md, 全层唯一一张图谱; 写法参照同目录 modules.md.template.
- 定义: 一模块一文件, 写法参照同目录 module.md.template; 首行标题建议用图谱模块名, 保持可对照.
- 写作律:
  - 文档是设计蓝图: 对外接口写到签名级, 机制参数写作时拍板.
  - 代码与旧文档只供完整性参考, 不是设计真源; 偏差落到目标接口.
  - 目标接口不含历史形态兼容: 迁移要么集中单一模块, 要么不做, 不散落各处; 命名不为连续性沿用旧名.
  - 并列内容一条一行.
- 通用: 具体形式不做硬要求; 两时态词表必过; 平铺文件, 不建子目录. 与上游模板的本地分歧声明在本节, 上游模板保持原样以零冲突同步.

## Pre-Development Checklist

- 跨模块改动前: 核对 modules.md 的依赖列, 确认影响面.
- 模块或契约变更: 与代码同变更更新对应模块文档, 跑 `python3 .trellis/scripts/verify_spec.py`.
