"""被测进程编排与客户端封装.

复用 scripts/e2e.sh 已验证的编排事实:
- 构建: go build ./cmd/cfdoh (整套件构建一次, 缓存到 .cache)
- 快照四件套: CACHE_PERSIST_PATH 本体 + 同目录 pool/h3/ech-state.json
- 就绪: 轮询 GET /health 直至 200 {"ok":true}
- 优雅退出: SIGTERM → 退出码 0

端口静态登记 18101 起连续分配, preflight 起实例前逐个确保空闲.
客户端一律 http.client 显式连 127.0.0.1 — 天然不读环境代理变量
(已知 e2e.sh 曾需 NO_PROXY 处理的同类问题, 此处结构性规避).
"""

import http.client
import json
import os
import signal
import ssl
import subprocess
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "test" / "acceptance" / "fixtures"
BUILD_DIR = REPO_ROOT / ".cache" / "acceptance"

ADMIN_TOKEN = "acc-admin-token"
HUB_TOKEN = "acc-hub-token"

# ---------------------------------------------------------------- 端口登记

# 假栈角色端口 (受控远程源)
STACK_PORTS = {
    "u1": 18101,        # DoH 上游 1
    "u2": 18102,        # DoH 上游 2 (对冲)
    "cfrange": 18103,   # CF IPv4/IPv6 网段列表
    "isp": 18104,       # 运营商 CIDR 表
    "cfhub": 18105,     # 公开池 API
    "echsrc": 18106,    # ECH 源域名应答
    "extra1": 18107,
    "extra2": 18108,
}

# 被测实例族端口
INSTANCE_PORTS = {
    "s_std": 18111,
    "s_noadmin": 18112,
    "s_drop": 18113,
    "s_host": 18114,
    "s_tls": 18115,
    "s_config": 18116,
    "c1": 18121,
}


def all_registered_ports():
    return sorted(list(STACK_PORTS.values()) + list(INSTANCE_PORTS.values()))


# 受控 CF 网段表 (假栈 cfrange 角色应答的冻结内容; 含全部官方 v4/v6 网段,
# 覆盖 fixtures 冻结应答地址 104.16.132.229 所在的 104.16.0.0/13).
CF_V4_LIST = "\n".join([
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "",
])
CF_V6_LIST = "\n".join([
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/32", "",
])


# ---------------------------------------------------------------- 构建

_build_lock = threading.Lock()
_built = {}


def build_bin(binary="cfdoh"):
    """go build 一次, 进程内缓存. binary ∈ {cfdoh, cfhost}."""
    with _build_lock:
        if binary in _built:
            return _built[binary]
        from . import preflight
        preflight.check_toolchain()
        BUILD_DIR.mkdir(parents=True, exist_ok=True)
        target = BUILD_DIR / binary
        proc = subprocess.run(
            ["go", "build", "-o", str(target),
             str(REPO_ROOT / "cmd" / binary)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise AssertionError("go build %s 失败:\n%s"
                                 % (binary, proc.stderr.strip()))
        _built[binary] = target
        return target


# ---------------------------------------------------------------- 环境组装

_PROXY_VARS = {"http_proxy", "https_proxy", "all_proxy", "no_proxy",
               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}


def child_env(overrides):
    """被测子进程环境: 剥离代理变量 (acceptance 全部远程源为受控本机),
    再应用 overrides; SSL_CERT_FILE 默认注入 fixtures CA (受控上游信任根),
    显式 override 优先 (live 层需要系统根时自行覆盖)."""
    env = {k: v for k, v in os.environ.items() if k not in _PROXY_VARS}
    env.update(overrides)
    env.setdefault("SSL_CERT_FILE", str(FIXTURES / "ca.pem"))
    return env


def family_env(family, *, upstreams, workdir, ecs_upstreams=None,
               admin_token=ADMIN_TOKEN, hub_token=HUB_TOKEN,
               isp_url="", cf_ipv4_url="", cf_ipv6_url="", pool_feed_url="",
               ech_config_b64="", ech_domains="", preferred_domains="",
               path_aliases="", public_hostnames="", drop_aaaa=False,
               max_packet_size=4096, extra=None):
    """实例族环境模板 (testplan 实例族表).

    全部远程 URL 默认受控或停用: ISP 空即关闭, POOL_FEED_URL 空即停用,
    CF 网段 URL 未给时指向假栈 cfrange 端口 (调用方须已启动该栈).
    """
    if family not in INSTANCE_PORTS:
        raise ValueError("unknown family %r" % family)
    port = INSTANCE_PORTS[family]
    persist = str(Path(workdir) / "cache.json")
    env = {
        "HOST": "127.0.0.1",
        "PORT": str(port),
        "UPSTREAMS": upstreams,
        "ECS_UPSTREAMS": ecs_upstreams if ecs_upstreams is not None
        else upstreams,
        "ADMIN_TOKEN": admin_token,
        "HUB_TOKEN": hub_token,
        "CACHE_PERSIST_PATH": persist,
        "ISP_TABLE_URL": isp_url,
        "CF_IPV4_URL": cf_ipv4_url
        or "https://127.0.0.1:%d/ips-v4" % STACK_PORTS["cfrange"],
        "CF_IPV6_URL": cf_ipv6_url
        or "https://127.0.0.1:%d/ips-v6" % STACK_PORTS["cfrange"],
        "POOL_FEED_URL": pool_feed_url,
        "ECH_CONFIG_BASE64": ech_config_b64,
        "ECH_DOMAINS": ech_domains,
        "CF_PREFERRED_DOMAIN": preferred_domains,
        "PATH_ALIASES": path_aliases,
        "PUBLIC_HOSTNAMES": public_hostnames,
        "MAX_DNS_PACKET_SIZE": str(max_packet_size),
    }
    if drop_aaaa:
        env["CF_DROP_AAAA"] = "true"
    if family == "s_noadmin":
        env.pop("ADMIN_TOKEN", None)
    if extra:
        env.update(extra)
    return env


def header(headers, name):
    """大小写无关取响应头 (http.client 返回原始大小写)."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def snapshot_paths(persist_path):
    """SIGTERM 后应存在的快照四件套 (e2e.sh 验证过的文件名与派生规则)."""
    base = Path(persist_path)
    return {
        "cache": base,
        "pool": base.with_name("pool-state.json"),
        "h3": base.with_name("h3-state.json"),
        "ech": base.with_name("ech-state.json"),
    }


# ---------------------------------------------------------------- 实例

class Instance:
    """一个被测 cfdoh 进程的生命周期与客户端访问."""

    def __init__(self, name, env, workdir, binary="cfdoh"):
        self.name = name
        self.env = env
        self.port = int(env["PORT"])
        self.workdir = Path(workdir)
        self.binary = binary
        self.proc = None
        self.log_path = self.workdir / ("%s.log" % name)
        self._stopped = False

    # -- 生命周期

    def start(self, ready_timeout=15.0):
        ensure_readiness()
        self.workdir.mkdir(parents=True, exist_ok=True)
        bin_path = build_bin(self.binary)
        log_fd = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(
                [str(bin_path)], cwd=str(self.workdir), env=child_env(self.env),
                stdout=log_fd, stderr=subprocess.STDOUT,
                start_new_session=True)
        finally:
            log_fd.close()
        try:
            self.wait_ready(ready_timeout)
        except Exception:
            self.kill()
            raise
        return self

    def wait_ready(self, timeout=15.0):
        deadline = time.monotonic() + timeout
        last_err = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                status, _, body = self.request("GET", "/health")
                if status == 200 and json.loads(body).get("ok") is True:
                    self._pf4()
                    return
                last_err = "health 状态 %d" % status
            except (OSError, ValueError) as exc:
                last_err = repr(exc)
            time.sleep(0.2)
        raise AssertionError(
            "[%s] %ds 内未就绪 (最后错误: %s). 启动日志:\n%s"
            % (self.name, timeout, last_err, self.log_tail()))

    def _pf4(self):
        from . import preflight
        time.sleep(0.3)  # 给潜在 bind 失败留出日志落盘时间
        preflight.check_alive_after_start(self.proc, self.name,
                                          self.log_text())

    def stop(self, sig=signal.SIGTERM, expect_exit=0, timeout=15.0):
        """优雅停止并断言退出码; 已停止则直接返回 (幂等)."""
        if self._stopped or self.proc is None:
            return 0
        self.proc.send_signal(sig)
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            raise AssertionError(
                "[%s] 收到 %s 后 %ds 未退出. 日志尾部:\n%s"
                % (self.name, sig.name, timeout, self.log_tail()))
        self._stopped = True
        code = self.proc.returncode
        if expect_exit is not None and code != expect_exit:
            raise AssertionError(
                "[%s] 退出码 %s != %s. 日志尾部:\n%s"
                % (self.name, code, expect_exit, self.log_tail()))
        return code

    def kill(self):
        """PF2 已知成因路径的清理手段: 直接击杀, 不做断言."""
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)
        self._stopped = True

    # -- 日志

    def log_text(self):
        try:
            return self.log_path.read_text(errors="replace")
        except OSError:
            return ""

    def log_tail(self, lines=20):
        return "\n".join(self.log_text().splitlines()[-lines:])

    # -- HTTP 客户端 (显式连 127.0.0.1, 不读环境代理)

    def request(self, method, path, headers=None, body=None, timeout=10.0):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def request_tls(self, method, path, headers=None, body=None, timeout=10.0):
        """S-TLS 族直连模式客户端: 用 fixtures CA 校验服务端证书.

        注: Python 3.14 起 create_default_context 默认开启 VERIFY_X509_STRICT,
        测试自签 CA 无 keyUsage 扩展会误拒; 此处仅关掉该 pedantic 位,
        证书链与主机名校验保持完整.
        """
        ctx = ssl.create_default_context(cafile=str(FIXTURES / "ca.pem"))
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        conn = http.client.HTTPSConnection("127.0.0.1", self.port,
                                           timeout=timeout, context=ctx)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def doh_get(self, query_bytes, path="/dns-query", accept=True,
                extra_headers=None, timeout=10.0):
        from . import dnscodec
        headers = {}
        if accept:
            headers["Accept"] = "application/dns-message"
        if extra_headers:
            headers.update(extra_headers)
        return self.request("GET", "%s?dns=%s" % (path,
                                                  dnscodec.b64url_encode(query_bytes)),
                            headers=headers, timeout=timeout)

    def doh_post(self, query_bytes, path="/dns-query", content_type=True,
                 accept=True, extra_headers=None, timeout=10.0):
        headers = {}
        if accept:
            headers["Accept"] = "application/dns-message"
        if content_type:
            headers["Content-Type"] = "application/dns-message"
        if extra_headers:
            headers.update(extra_headers)
        return self.request("POST", path, headers=headers, body=query_bytes,
                            timeout=timeout)

    def admin_json(self, method, path, token=ADMIN_TOKEN, payload=None,
                   timeout=10.0):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, resp_headers, data = self.request(method, path, headers=headers,
                                                  body=body, timeout=timeout)
        parsed = None
        if data:
            try:
                parsed = json.loads(data)
            except ValueError:
                parsed = None
        return status, parsed, data


# ---------------------------------------------------------------- cfhost

def cfhost_env(workdir, sources=None, managed_domains=None, config=None,
               extra=None):
    """cfhost 子进程环境模板 (批 5, F-023 至 F-027).

    - config 为 None 时写一份 "{}" 到 workdir/cfhost.json 并指向它: 隔离
      宿主默认配置路径 (UserConfigDir/cfdoh/cfhost.json), 且空对象不覆盖
      任何 env 值 (fileConfig 零值即 "未设置");
    - hosts 与状态文件固定落在 workdir 沙箱 (state 子目录同时承载
      cfhost.lock 与 cfhost.log);
    - sources / managed_domains 为 None 时不注入对应 env (留给配置文件通道);
    - 测速提速项 (TIMEOUT_MS/ROUNDS) 不在此默认注入: F-027 最小配置用例
      语义上要求默认值, 由需要的用例经 extra 传入.
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    if config is None:
        config = workdir / "cfhost.json"
        config.write_text("{}\n")
    env = {
        "CFHOST_CONFIG": str(config),
        "CFHOST_HOSTS_PATH": str(workdir / "hosts"),
        "CFHOST_STATE_PATH": str(workdir / "state" / "cfhost-state.json"),
    }
    if sources is not None:
        env["CFHOST_SOURCES"] = ";".join(sources)
    if managed_domains is not None:
        domains = managed_domains if isinstance(managed_domains,
                                                (list, tuple)) \
            else [managed_domains]
        env["CFHOST_MANAGED_DOMAINS"] = ",".join(domains)
    if extra:
        env.update(extra)
    return env


def cfhost_state(env):
    """读取 cfhost 状态文件; 不存在返回 None, 损坏抛 ValueError."""
    path = Path(env["CFHOST_STATE_PATH"])
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def cfhost_lock_path(env):
    """单实例锁文件路径 (状态文件同目录 cfhost.lock)."""
    return Path(env["CFHOST_STATE_PATH"]).with_name("cfhost.lock")


class CfhostProc:
    """一个被测 cfhost 进程: 一次性子命令 run() 或常驻模式 start()/stop().

    进程级编排范本同 Instance: 构建走 build_bin("cfhost"), 环境走
    child_env (剥代理 + SSL_CERT_FILE 注入 fixtures CA, cfhost 拉取受控
    https 源与 probe TLS 校验复用同一信任根).
    """

    def __init__(self, name, env, workdir, args=()):
        self.name = name
        self.env = env
        self.workdir = Path(workdir)
        self.args = tuple(args)
        self.proc = None
        self.log_path = self.workdir / ("%s.log" % name)
        self._stopped = False

    def run(self, timeout=90.0):
        """一次性子命令: 阻塞运行至退出, 捕获 stdout/stderr."""
        bin_path = build_bin("cfhost")
        return subprocess.run(
            [str(bin_path)] + list(self.args), cwd=str(self.workdir),
            env=child_env(self.env), capture_output=True, text=True,
            timeout=timeout)

    def start(self):
        """常驻模式: 后台启动 (start_new_session), 日志落文件."""
        ensure_readiness()
        self.workdir.mkdir(parents=True, exist_ok=True)
        bin_path = build_bin("cfhost")
        log_fd = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(
                [str(bin_path)] + list(self.args), cwd=str(self.workdir),
                env=child_env(self.env), stdout=log_fd,
                stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            log_fd.close()
        return self

    def stop(self, sig=signal.SIGTERM, expect_exit=0, timeout=20.0):
        """优雅停止并断言退出码; 已停止则直接返回 (幂等)."""
        if self._stopped or self.proc is None:
            return 0
        self.proc.send_signal(sig)
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            raise AssertionError(
                "[%s] 收到 %s 后 %ds 未退出. 日志尾部:\n%s"
                % (self.name, sig.name, timeout, self.log_tail()))
        self._stopped = True
        code = self.proc.returncode
        if expect_exit is not None and code != expect_exit:
            raise AssertionError(
                "[%s] 退出码 %s != %s. 日志尾部:\n%s"
                % (self.name, code, expect_exit, self.log_tail()))
        return code

    def kill(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)
        self._stopped = True

    def log_text(self):
        try:
            return self.log_path.read_text(errors="replace")
        except OSError:
            return ""

    def log_tail(self, lines=20):
        return "\n".join(self.log_text().splitlines()[-lines:])


_readiness_flag = {"done": False}
_readiness_lock = threading.Lock()


def ensure_readiness():
    """PF1+PF2+PF3 执行一次: 首个监听者 (假栈或被测实例) 启动前."""
    with _readiness_lock:
        if _readiness_flag["done"]:
            return
        from . import preflight
        preflight.check_toolchain()
        preflight.check_ports_free(all_registered_ports())
        preflight.check_certs()
        _readiness_flag["done"] = True
