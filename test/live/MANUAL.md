# 手动验收清单 (发布前人工执行, 不进 CI)

断言语义真源: `.trellis/spec/prd/requirements.md` 各 F 节验收标准.
逐条执行并勾选; 任一条不符合即阻塞发布.

## S 系列 — cfdoh 浏览器用户

前置 S0: 真实部署 (compose 或 systemd + 反代 TLS), 三默认上游可达,
浏览器与部署机同网络; 已有探针或 hub 向服务端上报过优选池
(ADMIN_TOKEN 通道, 池在有效期内).

- [ ] S1 配置生效 (F-001)
  步骤: 浏览器安全 DNS 设为 `https://<域名>/dns-query`; 打开
  `chrome://net-internals/#dns` 确认 Secure DNS 已启用并指向该端点;
  访问任一新域名后查看服务端日志 (LOG_QUERIES 开启时) 或 /explain.
  预期: net-internals 显示 DoH 生效; 服务端可见查询来源.
- [ ] S2 无差别可用性 (F-009)
  步骤: 依次打开若干 Cloudflare 站点与非 Cloudflare 站点 (各 ≥ 3 个).
  预期: 全部正常打开; 非 Cloudflare 站点应答未被改写 (地址与直连解析一致).
- [ ] S3 优选生效 (F-007/F-009)
  步骤: 清 DNS 缓存后多次 (≥ 4 次) 解析同一 Cloudflare 域名
  (`dig @<端点> <域名>` 或 net-internals 刷新); DevTools Network 面板
  看任一 CF 站点请求的 Remote Address.
  预期: A 记录全部来自上报池; Remote Address 打到池内地址;
  多次解析首条记录轮转 (分组循环左移).
- [ ] S4 ECH 生效 (F-010/F-012)
  步骤: DevTools Security 面板查看 Cloudflare 站点连接详情;
  打开 Cloudflare 的 ECH 检测页 (浏览器内搜索 "ech" 检测页).
  预期: Security 面板显示加密 ClientHello (ECH); 检测页报告 ECH 生效.
- [ ] S5 h3 门控 (F-011)
  步骤: 探针对同一站点上报 ok 与 fail 两种 verdict, 各刷新站点一次;
  DevTools Network 的 Protocol 列对比.
  预期: 全 source ok 的站点显示 h3; 任一 fail 的站点即刻降为 h2
  (verdict 翻转不等缓存 TTL).
- [ ] S6 失败不劫持 (F-004/F-003)
  步骤: 将 UPSTREAMS 指向不可达地址后重启, 访问此前解析过的域名
  (缓存已过期但在 stale 窗口内) 与全新域名.
  预期: 过期缓存域名拿到 TTL 30 的 stale 应答; 无缓存域名拿到 SERVFAIL
  而非挂死; 恢复上游后解析自动恢复.

## C 系列 — cfhost 客户端用户

前置 C0: 从 release 产物解压 cfhost (Windows 为 `cfhost_<ver>_windows_amd64.zip`),
配置文件 `cfhost.json` 放在可执行文件同目录 (默认布局; 状态/锁/日志同目录),
已填管辖域名 (Cloudflare 代理域名, 含 DoH 域名) 与候选源 (≥ 1),
代理客户端 (如有) 已放行候选源域名.

- [ ] C1 安装服务化 (F-026 AC1)
  步骤: 管理员运行 `cfhost install && cfhost start`; 重启系统.
  预期: 服务自启并完成一轮拉取-测速-hosts 刷新
  (事件查看器/服务列表可见运行状态, hosts 区块已有条目).
- [ ] C2 hosts 区块 (F-025)
  步骤: 打开 hosts 文件, 确认 `# BEGIN cfhost` 至 `# END cfhost` 区块
  内每域名一行指向当前最优地址; 区块外预置的手动条目保持原样.
  预期: 区块内域名齐全且地址一致; 区块外内容逐字节未变.
- [ ] C3 实际访问 (F-023/F-024)
  步骤: 浏览器访问任一管辖域名, DevTools Network 查看 Remote Address.
  预期: Remote Address 为 hosts 钉住的地址; 站点正常打开 (证书有效).
- [ ] C4 自动选优不抖动 (F-024)
  步骤: 长期观察 (≥ 数小时) `cfhost status` 输出.
  预期: 地址随线路质量切换但滞回抑制频繁跳变; status 含当前在用地址,
  上轮测速摘要, 下次刷新时间.
- [ ] C5 常驻行为 (F-026)
  步骤: 结束 cfhost 进程后观察服务自动恢复; 运行期间再启动第二实例;
  长期观察日志目录.
  预期: 崩溃/重启后自动恢复; 第二实例检测到锁后退出, 不并发写 hosts;
  日志按轮转策略滚动, 不撑满磁盘.
- [ ] C6 卸载干净 (F-026)
  步骤: 管理员运行 `cfhost stop && cfhost uninstall`; 检查服务列表与 hosts.
  预期: 服务条目移除; hosts 的 cfhost 区块清除; 系统解析恢复原状.
- [ ] C7 已知冲突 (F-026 安装文档两项要求)
  步骤: 在装有杀毒软件的机器上完成 C1-C3; 在代理客户端开启分流
  (管辖域名走代理) 的场景下访问管辖域名.
  预期: 杀毒软件放行 hosts 修改 (或已按文档加白); 分流场景下站点仍正常
  (hosts 钉住的直连地址可被代理规则兼容).
- [ ] C8 隐私 (F-023/F-024)
  步骤: 防火墙出站监控 cfhost 进程; 打开状态文件查看内容.
  预期: 默认仅连接配置的候选源 (可选上报关闭时无其他外联);
  状态文件只含本机测速结论, 不含其他数据.
