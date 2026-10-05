# PRD: cfhost hosts 写入韧性与 TEMP 优先临时文件

## Goal

消除 Windows 上 cfhost 写 hosts 的两类故障: 杀软扫描句柄与 rename 的竞态 (2026-10-05 实测: 管理员 run-once rename 稳定 Access denied, 服务 11:17 轮询因此死亡), 与写失败导致守护退出 (当日服务被杀两次, SCM 无恢复动作, 客户端永久停摆).

## 裁决 (菜包 2026-10-05 拍板)

tmp 文件**优先写系统 TEMP 目录**, 少过 System32\drivers\etc 的杀软过滤闸 (etc 是杀软重点布防目录, 在其中创建文件的扫描概率远高于 TEMP); 知知仅补工程配套: 跨卷回退同目录保原子性, rename 退避重试, 耗尽跳过本轮.

## Requirements

1. **TEMP 优先**: 临时文件优先创建于 os.TempDir(); 仅当 TEMP 与 hosts 目标不同卷 (rename 会退化为 copy+delete, 丢失原子性) 时回退到目标同目录. 两条路径都保持 "写完整内容 + 原子 rename 替换 + 保留原权限" 语义.
2. **rename 退避重试**: rename 遇 Access denied / sharing violation 类失败时退避重试 (200ms 间隔, 至多 5 次), 吸收杀软扫描窗口 (通常数百毫秒内释放).
3. **写失败不终止守护**: 重试耗尽仍失败时按本轮跳过处理 (与既有 hosts 读失败跳过同款语义): 不写 hosts, 在用地址与失败计数保持不变, NextRun 照常落盘, RunLoop 继续活到下周期. 常驻服务不得因 hosts 写失败退出.
4. **失败可观测**: 跳过与重试耗尽记 Warn 日志 (含错误与重试次数).
5. **spec 同步**: cfhost.md 登记临时文件策略与写失败跳过语义; PRD F-025 原子更新句补 "临时文件优先 TEMP, 跨卷回退同目录" 与写失败跳过.

## Acceptance Criteria

- [x] 单测: TEMP 优先路径 (tmp 落在注入的 TEMP 目录); 跨卷/不可用 TEMP 回退同目录; rename 注入失败序列验证重试次数与最终成功; 重试耗尽走跳过分支 (RunOnce 返回 nil, 在用地址不变, 状态落盘).
- [x] 单测: 服务路径 (RunLoop) 在 hosts 写持续失败时不退出.
- [x] go build ./... && go vet ./... && go test -race ./... 全绿. (check 补: GOOS=windows 交叉构建也验, 修复 syscall.ERROR_SHARING_VIOLATION 不存在改用 x/sys/windows)
- [x] acceptance f025/f026 模块全绿.
- [x] cfhost.md 与 PRD F-025 措辞同步.

## Constraints

- 不改服务端; 不改 hosts 区块格式与渲染逻辑.
- 测试用注入缝 (函数变量/接口) 模拟 Windows 竞态, 不依赖真实杀软; 遵循 newProbeTLSConfig 先例.
- 发版 v1.2.2 由菜包拍板.
