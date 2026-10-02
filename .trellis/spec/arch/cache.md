# cache

业务逻辑:
- 键由身份与变体两段构成: 身份 = 规范化查询名, 类型, 类, DO, CD, ECS 身份串; 变体 = 请求参数, 池 scope, 站点池标签, h3 与 Meta 代数.
- SERVFAIL 不入缓存; 应答 TTL 取 answers 非 OPT 最小值, 负应答按 SOA 语义, 最终钳制.
- 状态判定: fresh 直返; refresh (剩余 TTL 低于预取比例) 由调用方先答后刷; stale (过期仍在服务窗口) 由调用方在上游全败时使用; 判定所需的预取比例与过期窗口于读时经 cfg 传入.
- LRU 淘汰, 容量钳制 128 至 65536.
- 快照定时与退出时写 (临时文件加原子改名), 启动回读未过期条目; 快照不含客户端 IP.

对外接口:

```go
type Identity struct { Key, Text string }
func IdentityOf(q *wire.Packet, ecsID, variant string) (*Identity, error)
type Hit struct { Packet []byte; State State; OrigTTL int }
func New(maxEntries int) *Cache
func (c *Cache) Get(id *Identity, cfg *config.Config) *Hit
func (c *Cache) Put(id *Identity, packet []byte, cfg *config.Config) (ttl int, stored bool)
func (c *Cache) LoadSnapshot(path string) error
func (c *Cache) SaveSnapshot(path string) error
```

数据所有权: LRU 条目 (应答字节, 过期时刻, 原 TTL); 快照文件格式 (键, 头, 过期时刻, base64 体).

扩展规则:
- 键两段构成不可局部修改; 新影响因素进变体段并登记 CDD 缓存变体条目.
- 淘汰与容量策略可换, 键与状态语义不动.
- 快照格式变更须带版本号并能读既有版本的文件.

事件目录: 无 (读写异常由 resolver 记).
