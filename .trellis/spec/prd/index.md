# Product Requirement Documents

项目级产品需求的唯一现在时真源: 系统为什么做, 现在做什么, 每项可验收. 为整个项目服务; 任务级 prd 住 `.trellis/tasks/`, 为单次编码服务, 随任务归档.

## 文档清单

- background.md — 项目背景与目标, 功能行为的推导源头.
- requirements.md — 行为级功能需求全集 (F-001 至 F-030, 服务端 + 客户端 + 交付).

## 文档格式

本体文档登记于文档清单; 写作参照同目录模板 (background.md.template, requirements.md.template, feature.md.template), 具体形式不做硬要求; 两时态词表必过 (无过去时碎片, 无元话语). 平铺文件, 不建子目录. 与上游模板的本地分歧声明在本节, 上游模板保持原样以零冲突同步.

## Pre-Development Checklist

- 实现功能前: 从 background.md 的目标核对该功能的行为与验收标准.
- 需求变更: 同变更更新本层文档, 跑 `python3 .trellis/scripts/verify_spec.py`.
