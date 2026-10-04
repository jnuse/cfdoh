"""F-021 服务端部署与运行形态 — 6 用例 (S-STD + S-HOST + S-TLS).

断言语义真源: .trellis/spec/prd/requirements.md F-021 节 与
.trellis/spec/arch/server-entry.md (退出次序: 停收 → 快照 → 退).
快照四件套 = CACHE_PERSIST_PATH 本体 + 同目录 pool/h3/ech-state.json;
S-HOST 族 PUBLIC_HOSTNAMES=doh.test; S-TLS 族用 fixtures 证书对直连.
pprof 端口取已登记未占用的 extra1 (18107).
"""

import http.client
import json
import shutil
import signal
import socket
import struct
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST

SNAP_POOL = ["104.18.61.1", "104.18.61.2"]  # 上报的 default 池 (CF 网段内)
PPROF_PORT = harness.STACK_PORTS["extra1"]  # 18107, pprof 门控监听用


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class HostHeaderInstance(harness.Instance):
    """S-HOST 族: PUBLIC_HOSTNAMES 校验下用白名单 Host 完成就绪等待."""

    ready_host = "doh.test"

    def wait_ready(self, timeout=15.0):
        deadline = time.monotonic() + timeout
        last_err = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                status, _, body = self.request("GET", "/health",
                                               headers={"Host": self.ready_host})
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


class TLSModeInstance(harness.Instance):
    """S-TLS 族直连模式: 就绪等待与请求均走 TLS (fixtures CA 校验)."""

    def wait_ready(self, timeout=15.0):
        deadline = time.monotonic() + timeout
        last_err = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                status, _, body = self.request_tls("GET", "/health")
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


class F021LifecycleTest(unittest.TestCase):
    """F-021: 快照与恢复, SIGINT 等价, Host 校验, 直连 TLS, 损坏快照, pprof 门控."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f021-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            for n, addr in (("snap1.example.org", "104.16.132.229"),
                            ("snap2.example.org", "104.16.132.229"),
                            ("int1.example.org", "93.184.216.80"),
                            ("corrupt1.example.org", "93.184.216.95"),
                            ("tls1.example.org", "93.184.216.90"),
                            ("host1.example.org", "93.184.216.85")):
                u1.add_doh(n, dnscodec.TYPE_A,
                           a_records_response(0, n, [addr]))
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f021-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)
            cls.base = harness.REPO_ROOT / ".cache" / "acceptance" / "f021"
            if cls.base.exists():
                shutil.rmtree(cls.base)
        except Exception:
            cls._teardown_all()
            raise

    @classmethod
    def _teardown_all(cls):
        for inst in getattr(cls, "instances", []):
            if inst.proc is not None and not inst._stopped:
                inst.kill()
        for stack in getattr(cls, "stacks", []):
            stack.stop()

    @classmethod
    def tearDownClass(cls):
        cls._teardown_all()

    # ------------------------------------------------------------ 辅助

    def _start_std(self, name, subdir, extra=None, cls=harness.Instance):
        env = harness.family_env(
            "s_std", upstreams="%s/dns-query" % self.u1.base_url,
            workdir=self.base / subdir,
            extra={"CF_REWRITE_ENABLED": "true", **(extra or {})})
        inst = cls(name, env, self.base / subdir).start()
        self.instances.append(inst)
        return inst

    def _query_a(self, inst, qid, qname):
        query = dnscodec.build_query(qid, qname, dnscodec.TYPE_A, edns=False)
        status, _, body = inst.doh_get(query)
        self.assertEqual(status, 200)
        return dnscodec.parse_packet(body)

    def _assert_snapshots_exist(self, persist_path):
        paths = harness.snapshot_paths(persist_path)
        for label, path in sorted(paths.items()):
            self.assertTrue(path.is_file(), "快照 %s 缺失: %s" % (label, path))
            self.assertGreater(path.stat().st_size, 0,
                               "快照 %s 为空文件: %s" % (label, path))
        return paths

    # ------------------------------------------------------------ 用例

    def test_f021_corrupt_snapshot_boot(self):
        """F-021: 快照损坏只警告, 不阻塞启动, 解析照常."""
        wd = self.base / "corrupt"
        wd.mkdir(parents=True)
        (wd / "cache.json").write_bytes(b"\x00\x01 not json at all")
        (wd / "pool-state.json").write_bytes(b"\xff garbage {")
        inst = self._start_std("f021-corrupt", "corrupt")
        try:
            packet = self._query_a(inst, 0x2105, "corrupt1.example.org")
            self.assertEqual(packet["rcode"], 0, "损坏快照不得影响解析")
            log = inst.log_text()
            self.assertIn("cache snapshot not restored", log,
                          "损坏缓存快照须记警告")
            self.assertIn("snapshot unreadable", log,
                          "损坏池快照须记警告 (不阻塞, 保持空态)")
        finally:
            inst.stop()

    def test_f021_direct_tls_mode(self):
        """F-021 AC: 直连模式配置证书 → 经 TLS (fixtures CA 校验) 正常应答."""
        env = harness.family_env(
            "s_tls", upstreams="%s/dns-query" % self.u1.base_url,
            workdir=self.base / "tls",
            extra={"TLS_CERT_FILE": str(harness.FIXTURES / "server.pem"),
                   "TLS_KEY_FILE": str(harness.FIXTURES / "server.key")})
        inst = TLSModeInstance("f021-tls", env, self.base / "tls").start()
        self.instances.append(inst)
        try:
            query = dnscodec.build_query(0x2115, "tls1.example.org",
                                         dnscodec.TYPE_A, edns=False)
            status, _, body = inst.request_tls(
                "GET", "/dns-query?dns=%s" % dnscodec.b64url_encode(query),
                headers={"Accept": "application/dns-message"})
            self.assertEqual(status, 200)
            packet = dnscodec.parse_packet(body)
            self.assertEqual(packet["rcode"], 0)
            self.assertEqual(packet["id"], 0x2115)
            self.assertEqual(dnscodec.answer_addresses(packet,
                                                       dnscodec.TYPE_A),
                             ["93.184.216.90"])
        finally:
            inst.stop()  # 直连模式同样须优雅退出 (退出码 0)

    def test_f021_host_mismatch_421(self):
        """F-021 AC: PUBLIC_HOSTNAMES 配置后其他 Host → 421, 白名单与 localhost 正常."""
        env = harness.family_env(
            "s_host", upstreams="%s/dns-query" % self.u1.base_url,
            workdir=self.base / "host",
            public_hostnames="doh.test")
        inst = HostHeaderInstance("f021-host", env, self.base / "host").start()
        self.instances.append(inst)
        try:
            status, _, _ = inst.request("GET", "/health",
                                        headers={"Host": "doh.test"})
            self.assertEqual(status, 200, "白名单 Host 须正常服务")
            status, _, _ = inst.request("GET", "/health",
                                        headers={"Host": "localhost"})
            self.assertEqual(status, 200, "localhost 须豁免")
            status, _, _ = inst.request("GET", "/health",
                                        headers={"Host": "other.test"})
            self.assertEqual(status, 421, "集合外 Host 须 421")
            # 正常路径也走一次 DoH (带端口形态的 Host 同样通过)
            query = dnscodec.build_query(0x2116, "host1.example.org",
                                         dnscodec.TYPE_A, edns=False)
            status, _, body = inst.doh_get(
                query, extra_headers={"Host": "doh.test:%d" % inst.port})
            self.assertEqual(status, 200)
            self.assertEqual(dnscodec.parse_packet(body)["rcode"], 0)
        finally:
            inst.stop()

    def test_f021_pprof_default_off(self):
        """F-021: pprof 独立开关门控 — 默认不监听 (连接拒绝)."""
        # 阶段 1: 显式配置 PPROF_ADDR → 独立端口可访问 (证明机制存在)
        inst = self._start_std(
            "f021-pprof-on", "pprof-on",
            extra={"PPROF_ADDR": "127.0.0.1:%d" % PPROF_PORT})
        try:
            conn = http.client.HTTPConnection("127.0.0.1", PPROF_PORT,
                                              timeout=5)
            try:
                conn.request("GET", "/debug/pprof/")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200,
                                 "显式 PPROF_ADDR 须暴露调试端点")
                resp.read()
            finally:
                conn.close()
        finally:
            inst.stop()
        self._assert_port_refused(PPROF_PORT, "pprof 实例退出后")
        # 阶段 2: 默认配置 (PPROF_ADDR 未设) → 无 pprof 监听
        inst2 = self._start_std("f021-pprof-off", "pprof-off")
        try:
            self._assert_port_refused(PPROF_PORT, "默认配置下")
        finally:
            inst2.stop()

    def _assert_port_refused(self, port, when):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                pass
        except OSError:
            return
        self.fail("%s 端口 %d 不得有监听 (pprof 默认关闭)" % (when, port))

    def test_f021_sigint_equivalent(self):
        """F-021: SIGINT 与 SIGTERM 等价 (退出码 0, 快照四件套存在)."""
        inst = self._start_std("f021-int", "int")
        packet = self._query_a(inst, 0x2121, "int1.example.org")
        self.assertEqual(packet["rcode"], 0)
        inst.stop(sig=signal.SIGINT, expect_exit=0)
        self._assert_snapshots_exist(inst.env["CACHE_PERSIST_PATH"])

    def test_f021_snapshot_and_restore(self):
        """F-021 AC: 探针上报池 → SIGTERM 快照 → 重启后池即刻可用 (免再上报)."""
        wd = self.base / "snap"
        inst = self._start_std("f021-snap", "snap")
        try:
            status, _, _ = inst.admin_json(
                "POST", "/admin/preferred",
                payload={"ipv4": SNAP_POOL, "ipv6": [], "ttl": 600,
                         "source": "probe-snap", "scope": "default"})
            self.assertTrue(200 <= status < 300, "池上报失败: %s" % status)
            # 上报后即生效 (在内存态可见)
            def serving():
                packet = self._query_a(inst, 0x2111, "snap1.example.org")
                got = set(dnscodec.answer_addresses(packet, dnscodec.TYPE_A))
                return got if got == set(SNAP_POOL) else None

            got = self._poll_until(serving, what="上报后浏览器观察到池")
            self.assertEqual(got, set(SNAP_POOL))
        finally:
            inst.stop(expect_exit=0)  # SIGTERM 快照落盘, 退出码 0
        self._assert_snapshots_exist(inst.env["CACHE_PERSIST_PATH"])
        # 重启: 同一 CACHE_PERSIST_PATH, 无任何再上报
        inst2 = self._start_std("f021-snap-r2", "snap")
        try:
            start = time.monotonic()
            packet = self._query_a(inst2, 0x2112, "snap2.example.org")
            elapsed = time.monotonic() - start
            got = set(dnscodec.answer_addresses(packet, dnscodec.TYPE_A))
            self.assertEqual(got, set(SNAP_POOL),
                             "重启后首次查询即须命中快照恢复的池: %r" % got)
            self.assertLess(elapsed, 5.0, "恢复的池即刻可用, 无需等待")
        finally:
            inst2.stop(expect_exit=0)

    def _poll_until(self, fn, timeout=15.0, what=""):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = fn()
            if last:
                return last
            time.sleep(0.3)
        self.fail("等待超时: %s (最后: %r)" % (what, last))


if __name__ == "__main__":
    unittest.main()
