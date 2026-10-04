"""环境哨兵: 已知情况固化在代码里, 排查信息先于故障出现.

- PF1 工具链: go 可用, python >= 3.9
- PF2 端口: 实例族与假栈端口逐个空闲检测; 被占时附占用进程 PID 与命令行
  及已知成因 (残留 cfdoh) 与对策
- PF3 fixtures 证书存在且未过期 (notAfter); 过期提示重跑 make-certs.sh
- PF4 启动后: 日志无 "address already in use" 且进程存活
- PF5/PF6 (仅 live 层, 批 6 接线): 代理探测骨架
"""

import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone

FIXTURES_DIR = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.pardir, "acceptance", "fixtures"))

CERT_MIN_REMAIN_DAYS = 7


class PreflightError(AssertionError):
    """哨兵失败, 消息含成因与对策."""


def _fail(problems):
    raise PreflightError("preflight 失败:\n  - " + "\n  - ".join(problems))


# ---------------------------------------------------------------- PF1

def check_toolchain():
    problems = []
    try:
        out = subprocess.run(["go", "version"], capture_output=True,
                             text=True, timeout=30)
        if out.returncode != 0:
            problems.append("go version 退出码 %d: %s"
                            % (out.returncode, out.stderr.strip()))
    except FileNotFoundError:
        problems.append("go 不在 PATH — 已知成因: WSL 内未装/未加载 fnm; "
                        "对策: 检查 fnm 与默认 node/go 环境")
    except subprocess.TimeoutExpired:
        problems.append("go version 超时")
    if sys.version_info < (3, 9):
        problems.append("python %s < 3.9" % sys.version.split()[0])
    if problems:
        _fail(problems)


# ---------------------------------------------------------------- PF2

def port_owner(port):
    """返回占用 127.0.0.1:port 的监听进程 (pid, cmdline) 或 None.

    优先 ss -tlnp; 不可用或无 pid 信息时回退 /proc 扫描 (inode 关联).
    """
    try:
        out = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True,
                             timeout=10)
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                fields = line.split()
                if len(fields) < 4:
                    continue
                if fields[0] != "LISTEN" and "LISTEN" not in fields[0]:
                    continue
                local = fields[3] if len(fields) > 3 else fields[-1]
                if not local.endswith(":%d" % port):
                    continue
                m = re.search(r"pid=(\d+)", line)
                if m:
                    pid = int(m.group(1))
                    return pid, _cmdline(pid)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return _port_owner_procfs(port)


def _port_owner_procfs(port):
    """解析 /proc/net/tcp (与 tcp6) 找监听 socket inode, 再扫 /proc/*/fd."""
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table) as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    local, state, inode = parts[1], parts[3], parts[9]
                    if state != "0A":  # LISTEN
                        continue
                    ip, _, p = local.rpartition(":")
                    if int(p, 16) != port:
                        continue
                    # 只关心 127.0.0.1 与 0.0.0.0/:: 绑定
                    if ip.lower() in ("0100007f", "00000000", "00000000000000000000000000000000"):
                        inodes.add(inode)
        except OSError:
            continue
    if not inodes:
        return None
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        fd_dir = "/proc/%s/fd" % entry
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if target.startswith("socket:[") and target[8:-1] in inodes:
                    return int(entry), _cmdline(int(entry))
        except OSError:
            continue
    return None


def _cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            return fh.read().replace(b"\x00", b" ").decode(
                "utf-8", "replace").strip()
    except OSError:
        return "<unreadable>"


def check_ports_free(ports):
    """逐端口探测. 与被测实例的 bind 语义一致 (Go listener 默认
    SO_REUSEADDR): 仅活动监听者算占用, TIME_WAIT 不误报."""
    problems = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
        except OSError:
            owner = port_owner(port)
            if owner:
                pid, cmd = owner
                problems.append(
                    "端口 %d 被占用: PID %d (%s). 已知成因: 上次失败残留 "
                    "cfdoh; 对策: kill 该 PID 后重跑" % (port, pid, cmd))
            else:
                problems.append(
                    "端口 %d 被占用 (属主未知, 可能非本用户进程). "
                    "对策: 确认无残留 cfdoh 后重跑" % port)
        finally:
            sock.close()
    if problems:
        _fail(problems)


# ---------------------------------------------------------------- PF3

def check_certs():
    problems = []
    for name in ("ca.pem", "server.pem", "server.key"):
        path = os.path.join(FIXTURES_DIR, name)
        if not os.path.isfile(path):
            problems.append("fixtures 缺 %s — 对策: 手动执行 "
                            "fixtures/make-certs.sh 重新生成" % name)
    if problems:
        _fail(problems)
    now = datetime.now(timezone.utc)
    for name in ("ca.pem", "server.pem"):
        path = os.path.join(FIXTURES_DIR, name)
        try:
            out = subprocess.run(
                ["openssl", "x509", "-in", path, "-noout", "-enddate"],
                capture_output=True, text=True, timeout=15)
            if out.returncode != 0:
                problems.append("%s 无法解析: %s" % (name, out.stderr.strip()))
                continue
            # notAfter=Jun  8 03:04:05 2036 GMT
            raw = out.stdout.strip().split("=", 1)[1]
            expiry = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            remain = (expiry - now).total_seconds() / 86400
            if remain < CERT_MIN_REMAIN_DAYS:
                problems.append(
                    "%s 将于 %s 过期 (剩 %.1f 天) — 对策: 手动执行 "
                    "fixtures/make-certs.sh 重新生成" % (name, raw, remain))
        except FileNotFoundError:
            problems.append("openssl 不可用, 无法校验 %s 有效期" % name)
        except (subprocess.TimeoutExpired, ValueError) as exc:
            problems.append("校验 %s 失败: %r" % (name, exc))
    if problems:
        _fail(problems)


# ---------------------------------------------------------------- PF4

def scan_startup_log(log_text, name):
    """启动日志扫描: address already in use 与致命错误提示."""
    problems = []
    for line in log_text.splitlines():
        if "address already in use" in line:
            problems.append(
                "[%s] 启动日志含 address already in use — 已知成因: 端口被 "
                "残留进程抢占 (PF2 漏检或竞态); 对策: kill 残留 cfdoh 后重跑"
                % name)
    return problems


def check_alive_after_start(proc, name, log_text):
    """PF4: 进程仍存活且日志无端口冲突."""
    problems = scan_startup_log(log_text, name)
    if proc.poll() is not None:
        problems.append("[%s] 进程启动后立即退出 (code=%s). 日志尾部:\n%s"
                        % (name, proc.returncode,
                           "\n".join(log_text.splitlines()[-15:])))
    if problems:
        _fail(problems)


# ---------------------------------------------------------------- PF5/PF6 (live 骨架)

def default_proxy_url(timeout=2.0):
    """live 哨兵辅助: E2E_HTTPS_PROXY 优先; 未设时取默认路由网关的 10808.

    已知事实: WSL 网关 IP 每次重启会变, 禁止写死; 宿主 10808 为 mixed 端口.
    返回 "http://<gateway>:10808" 或 None.
    """
    env = os.environ.get("E2E_HTTPS_PROXY")
    if env:
        return env
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5)
        m = re.search(r"via (\d+\.\d+\.\d+\.\d+)", out.stdout)
        if not m:
            return None
        return "http://%s:10808" % m.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def probe_live_proxy():
    """PF5: 探测代理可用性; 失败时输出成因清单. (live 层批 6 接线)"""
    url = default_proxy_url()
    if not url:
        _fail(["无法确定代理地址: E2E_HTTPS_PROXY 未设且取不到默认路由网关. "
               "对策: 设 E2E_HTTPS_PROXY=<url> 或开启宿主代理客户端"])
    problems = []
    from urllib.parse import urlsplit
    host = urlsplit(url).hostname
    port = urlsplit(url).port or 10808
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
    except OSError:
        problems.append(
            "宿主 %s:%d 不通 — 已知成因: 代理客户端未开或未开局域网连接; "
            "对策: 开启后重试或设 E2E_HTTPS_PROXY=<url>" % (host, port))
    if problems:
        _fail(problems)
    return url


def probe_live_doh(proxy_url, timeout=3.0):
    """PF6 骨架: 经代理预检一次真实 DoH (cloudflare 1.1.1.1).

    支持 http:// 代理 (CONNECT 隧道); socks5:// 接线属于批 6 live 层.
    失败时输出排查清单: 代理开否 / 局域网允许否 / 规则模式覆盖否.
    """
    from urllib.parse import urlsplit
    parsed = urlsplit(proxy_url)
    if parsed.scheme == "socks5":
        _fail(["socks5 代理预检未接线 (批 6); 当前请用 http:// scheme 或"
               "设 E2E_HTTPS_PROXY=http://<host>:10808"])
    host, port = parsed.hostname, parsed.port or 80
    problems = []
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.sendall(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n"
                    b"Host: 1.1.1.1:443\r\n\r\n")
        status_line = raw.recv(1024).split(b"\r\n", 1)[0]
        if b" 200 " not in status_line:
            problems.append("代理拒绝 CONNECT 1.1.1.1:443 (%r) — 已知成因: "
                            "规则模式未覆盖或未开局域网连接" % status_line)
        raw.close()
    except OSError as exc:
        problems.append("经代理连 1.1.1.1 失败 (%r). 排查清单: 代理客户端"
                        "开否 / 允许局域网连接否 / 规则模式覆盖否" % exc)
    if problems:
        _fail(problems)


def check_acceptance_readiness():
    """acceptance 层统一入口: PF1 + PF2 + PF3."""
    from . import harness
    check_toolchain()
    check_ports_free(harness.all_registered_ports())
    check_certs()


if __name__ == "__main__":
    check_acceptance_readiness()
    print("acceptance preflight OK")
