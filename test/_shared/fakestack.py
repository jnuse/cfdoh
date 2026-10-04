"""受控 https 服务工厂.

ThreadingHTTPServer + ssl 包装, 载入 fixtures 证书. 一个工厂实例化多个角色:
- role="doh": DoH 上游 — 按 (qname, qtype) 应答表服务 GET/POST 查询, 应答字节
  中的事务 ID 自动回填为入向查询 ID (真实上游行为); 记录全部出向查询.
- role="files": 文本/JSON 静态文件 — 按路径应答表 (cfrange 列表, ISP 表,
  cfhub API, 任意远程源).

共同能力: 每条目延迟 (锁外 sleep, 慢上游不阻塞快上游), 按次数/永久失败注入,
收到的请求全量记录. fail 形如 {"status": 500, "times": 2} — times 缺省为永久.
"""

import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import dnscodec

_FIXTURES = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.pardir, "acceptance", "fixtures"))


class FakeStack:
    """单个受控 https 端点. 线程安全: 应答表与请求记录均加锁."""

    def __init__(self, port, role, name=None):
        if role not in ("doh", "files"):
            raise ValueError("role must be 'doh' or 'files'")
        self.port = port
        self.role = role
        self.name = name or "%s-%d" % (role, port)
        self.base_url = "https://127.0.0.1:%d" % port
        self._lock = threading.Lock()
        self._doh_table = {}       # (qname_lower, qtype) -> entry
        self._doh_default = None   # 未命中时的兜底 entry
        self._path_table = {}      # path -> entry
        self.requests = []         # 全量请求记录 (上游用户视角)
        self._server = None
        self._thread = None
        self._started = False

    # ------------------------------------------------ 应答表编程

    def add_doh(self, qname, qtype, response_bytes, delay=0.0, fail=None):
        """登记 (qname, qtype) 的应答字节; fail 为失败注入配置."""
        with self._lock:
            self._doh_table[(qname.rstrip(".").lower(), qtype)] = {
                "response": response_bytes, "delay": delay, "fail": fail,
                "fail_used": 0,
            }

    def set_doh_default(self, response_bytes, delay=0.0, fail=None):
        with self._lock:
            self._doh_default = {
                "response": response_bytes, "delay": delay, "fail": fail,
                "fail_used": 0,
            }

    def set_doh_fail(self, qname, qtype, fail):
        """对已登记的 DoH 条目追加/更新失败注入."""
        with self._lock:
            entry = self._doh_table[(qname.rstrip(".").lower(), qtype)]
            entry["fail"] = fail
            entry["fail_used"] = 0

    def add_path(self, path, content, content_type="text/plain; charset=utf-8",
                 status=200, delay=0.0, fail=None):
        if isinstance(content, str):
            content = content.encode("utf-8")
        with self._lock:
            self._path_table[path] = {
                "content": content, "content_type": content_type,
                "status": status, "delay": delay, "fail": fail,
                "fail_used": 0,
            }

    def set_path_fail(self, path, fail):
        with self._lock:
            entry = self._path_table[path]
            entry["fail"] = fail
            entry["fail_used"] = 0

    def set_path_content(self, path, content,
                         content_type="text/plain; charset=utf-8", status=200):
        """替换已登记路径的应答内容 (如首拉成功后改 500 或换数据)."""
        if isinstance(content, str):
            content = content.encode("utf-8")
        with self._lock:
            entry = self._path_table[path]
            entry.update({"content": content, "content_type": content_type,
                          "status": status})

    # ------------------------------------------------ 请求记录查询

    def request_count(self, path=None):
        """收到的请求数; path 给定时仅计该路径."""
        with self._lock:
            if path is None:
                return len(self.requests)
            return sum(1 for r in self.requests if r["path"] == path)

    def doh_queries(self, qname=None, qtype=None):
        """收到的 DoH 查询记录 (上游视角的出向报文)."""
        with self._lock:
            rows = [r for r in self.requests if r.get("kind") == "doh"]
        if qname is not None:
            rows = [r for r in rows if r["qname"] == qname.rstrip(".").lower()]
        if qtype is not None:
            rows = [r for r in rows if r["qtype"] == qtype]
        return rows

    # ------------------------------------------------ 生命周期

    def start(self):
        if self._started:
            return self
        from . import harness
        harness.ensure_readiness()
        stack = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def _run(self):
                try:
                    stack._handle(self)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            do_GET = _run
            do_POST = _run
            do_PUT = _run
            do_DELETE = _run

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(_FIXTURES, "server.pem"),
                            os.path.join(_FIXTURES, "server.key"))
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._server.daemon_threads = True
        self._server.socket = ctx.wrap_socket(self._server.socket,
                                              server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="fakestack-" + self.name,
                                        daemon=True)
        self._thread.start()
        self._started = True
        return self

    def stop(self):
        if not self._started:
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        self._started = False

    # ------------------------------------------------ 请求处理

    def _handle(self, handler):
        parsed = urlsplit(handler.path)
        path = parsed.path
        body = b""
        length = int(handler.headers.get("Content-Length") or 0)
        if length:
            body = handler.rfile.read(length)
        record = {
            "time": time.time(),
            "method": handler.command,
            "path": path,
            "headers": dict(handler.headers.items()),
            "body": body,
        }

        if self.role == "doh":
            self._handle_doh(handler, parsed, body, record)
        else:
            self._handle_files(handler, path, record)

    def _handle_doh(self, handler, parsed, body, record):
        query_bytes = self._extract_dns(handler, parsed, body)
        if query_bytes is None:
            self._reply(handler, 400, b"bad dns request",
                        "text/plain; charset=utf-8")
            return
        try:
            packet = dnscodec.parse_packet(query_bytes)
            question = packet["questions"][0]
            qname = question["name"].rstrip(".").lower()
            qtype = question["type"]
        except (dnscodec.DNSCodecError, IndexError):
            self._reply(handler, 400, b"unparsable dns query",
                        "text/plain; charset=utf-8")
            return
        record.update({"kind": "doh", "query_bytes": query_bytes,
                       "qname": qname, "qtype": qtype, "qid": packet["id"]})
        with self._lock:
            self.requests.append(record)
            entry = self._doh_table.get((qname, qtype)) or self._doh_default
        if entry is None:
            self._reply(handler, 404, b"no upstream answer programmed",
                        "text/plain; charset=utf-8")
            return
        if not self._serve_entry(handler, entry,
                                 response_id=packet["id"]):
            return

    def _handle_files(self, handler, path, record):
        with self._lock:
            self.requests.append(record)
            entry = self._path_table.get(path)
        if entry is None:
            self._reply(handler, 404, b"not programmed",
                        "text/plain; charset=utf-8")
            return
        status = entry["status"]
        self._serve_entry(handler, entry, status=status)

    def _serve_entry(self, handler, entry, response_id=None, status=200,
                     content_type="application/dns-message"):
        """延迟 → 失败注入 → 应答. 返回 False 表示已回失败包."""
        if entry["delay"]:
            time.sleep(entry["delay"])  # 锁外: 慢上游不阻塞其他请求线程
        with self._lock:
            failure = self._consume_fail(entry)
        if failure is not None:
            self._reply(handler, failure[0], failure[1], failure[2])
            return False
        if response_id is not None:
            content = dnscodec.patch_id(entry["response"], response_id)
            self._reply(handler, status, content, content_type)
        else:
            self._reply(handler, status, entry["content"],
                        entry["content_type"])
        return True

    @staticmethod
    def _consume_fail(entry):
        """消费一次失败注入; 返回 (status, content, ctype) 或 None."""
        fail = entry["fail"]
        if fail is None:
            return None
        times = fail.get("times")
        if times is None or entry["fail_used"] < times:
            entry["fail_used"] += 1
            return (fail.get("status", 500),
                    fail.get("content", b"programmed failure"),
                    fail.get("content_type", "text/plain; charset=utf-8"))
        return None

    @staticmethod
    def _extract_dns(handler, parsed, body):
        if handler.command == "POST":
            return body or None
        if handler.command == "GET":
            values = parse_qs(parsed.query).get("dns")
            if not values:
                return None
            try:
                return dnscodec.b64url_decode(values[0])
            except dnscodec.DNSCodecError:
                return None
        return None

    @staticmethod
    def _reply(handler, status, content, content_type):
        if isinstance(content, str):
            content = content.encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(content)))
        handler.end_headers()
        handler.wfile.write(content)
