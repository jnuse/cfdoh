# 客户端入口

业务逻辑:
- 子命令分发: install, uninstall, start, stop, run-once, status; 无参数或 "run" (Windows 服务安装参数, 与无参数同路径) 时进入服务模式 (RunLoop).
- 子命令语义全部委托 internal/cfhost.

对外接口: 命令行 `cfhost <subcommand>`.

数据所有权: — .

扩展规则:
- 入口保持薄壳, 不承载业务逻辑.
- 新子命令登记到 cfhost 模块后此处仅分发.

事件目录: 无.
