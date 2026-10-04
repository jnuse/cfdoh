"""live 层: 真实三上游冒烟 — 7 用例, 吸收 scripts/e2e.sh 全部场景.

场景映射 (e2e.sh → 本模块):
  boot/health          → test_live_probe_health
  POST A / GET AAAA/HTTPS (rcode 0 + ID 回填) → test_live_zero_config
  /explain 骨架        → test_live_explain
  /probe 回显          → test_live_probe_health
  admin 401/200 矩阵   → test_live_admin_matrix
  SIGTERM 快照 4 件套 + 重启恢复 → test_live_snapshot_reboot
  (testplan 新增)      → test_live_preflight_proxy, test_live_no_rewrite_without_pool

断言限弱断言 (.trellis/tasks/10-04-acceptance-py/design.md live 层节):
三默认上游任一应答合法, 事务 ID 回填, 非 SERVFAIL, 耗时上限 (客户端超时),
/explain 骨架, 优雅退出与重启恢复. 不因真实上游波动引入时序脆弱性.

出网路由: 被测子进程经 HTTPS_PROXY=<E2E_HTTPS_PROXY 或网关 10808> 访问
真实上游; POOL_FEED_URL 显式置空停用真实 cfhub 拉取 (不可控远程依赖,
不影响默认上游语义, 且 test_live_no_rewrite_without_pool 要求无池环境).
本机客户端 http.client 显式连 127.0.0.1, 不读环境代理变量.
"""

import json
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, harness, preflight  # noqa: E402

LIVE_PORT = 18080  # e2e.sh 沿用端口
ADMIN_TOKEN = "live-admin-token"
QNAME = "www.cloudflare.com"
WORKDIR = harness.REPO_ROOT / ".cache" / "acceptance" / "live"

SYSTEM_CERT_FILES = [
    "/etc/ssl/certs/ca-certificates.crt",       # Arch / Debian 系
    "/etc/pki/tls/certs/ca-bundle.crt",         # Fedora / RHEL
    "/etc/ssl/cert.pem",                        # macOS / OpenBSD
]


def system_ca_bundle():
    for path in SYSTEM_CERT_FILES:
        if Path(path).is_file():
            return path
    raise preflight.PreflightError(
        "preflight 失败:\n  - 系统 CA bundle 未找到 (找过 %s). 已知成因: "
        "WSL Arch 未装 ca-certificates; 对策: pacman -S ca-certificates "
        "或设 E2E_HTTPS_PROXY 前先补齐系统根" % ", ".join(SYSTEM_CERT_FILES))


class LiveUpstreamsTest(unittest.TestCase):
    """真实三上游: 哨兵, 零配置三类型, explain, 探针, admin, 快照重启, 无池不改写."""

    @classmethod
    def setUpClass(cls):
        cls.proxy = preflight.probe_live_proxy()   # PF5
        preflight.probe_live_doh(cls.proxy)        # PF6
        preflight.check_ports_free([LIVE_PORT])
        cls.ca_bundle = system_ca_bundle()
        harness.build_bin("cfdoh")
        if WORKDIR.exists():
            shutil.rmtree(WORKDIR)
        WORKDIR.mkdir(parents=True, exist_ok=True)
        cls.instances = []
        try:
            cls.inst = cls._start("live-1")
        except Exception:
            cls._teardown_all()
            raise

    @classmethod
    def _live_env(cls):
        """零配置上游 (UPSTREAMS 未设 → 默认 cloudflare/google/quad9, 同 e2e.sh);
        出网经代理; 系统根校验真实上游证书."""
        return {
            "HOST": "127.0.0.1",
            "PORT": str(LIVE_PORT),
            "ADMIN_TOKEN": ADMIN_TOKEN,
            "CACHE_PERSIST_PATH": str(WORKDIR / "cache.json"),
            "POOL_FEED_URL": "",
            "HTTPS_PROXY": cls.proxy,
            "https_proxy": cls.proxy,
            "SSL_CERT_FILE": cls.ca_bundle,
        }

    @classmethod
    def _start(cls, name):
        inst = harness.Instance(name, cls._live_env(), WORKDIR).start()
        cls.instances.append(inst)
        return inst

    @classmethod
    def _teardown_all(cls):
        for inst in getattr(cls, "instances", []):
            if inst.proc is not None and not inst._stopped:
                inst.kill()

    @classmethod
    def tearDownClass(cls):
        cls._teardown_all()

    # ------------------------------------------------------------ 辅助

    def _query(self, inst, qid, qname, qtype, method="GET",
               assert_content_type=False, timeout=15.0):
        """一次 DoH 查询: 200 + rcode 0 + ID 回填 + 应答非空 (e2e check_answer 等价)."""
        query = dnscodec.build_query(qid, qname, qtype)
        if method == "GET":
            status, headers, body = inst.doh_get(query, timeout=timeout)
        else:
            status, headers, body = inst.doh_post(query, timeout=timeout)
        self.assertEqual(status, 200, "DoH %s %s 应答 %d" % (method, qname, status))
        if assert_content_type:
            self.assertEqual(harness.header(headers, "Content-Type"),
                             "application/dns-message")
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["id"], qid,
                         "事务 ID 未回填: %#x != %#x" % (packet["id"], qid))
        self.assertEqual(packet["rcode"], 0,
                         "非 NOERROR (SERVFAIL 等): rcode=%d" % packet["rcode"])
        self.assertGreaterEqual(len(packet["answers"]), 1, "answer 节为空")
        return packet

    # ------------------------------------------------------------ 用例

    def test_live_preflight_proxy(self):
        """PF5/PF6 哨兵: 代理可确定, 端口可达, 经代理可连 1.1.1.1 DoH."""
        url = preflight.probe_live_proxy()
        self.assertTrue(url, "PF5 未返回代理地址")
        preflight.probe_live_doh(url)  # 失败即抛 PreflightError (含成因清单)

    def test_live_zero_config(self):
        """零配置默认三上游: A(POST) / AAAA(GET) / HTTPS(GET) rcode 0 + ID 回填."""
        self._query(self.inst, 0x1234, QNAME, dnscodec.TYPE_A,
                    method="POST", assert_content_type=True)
        self._query(self.inst, 0x2234, QNAME, dnscodec.TYPE_AAAA)
        self._query(self.inst, 0x3234, QNAME, dnscodec.TYPE_HTTPS)

    def test_live_explain(self):
        """/explain 骨架: client_ip, answers 三类型, chromium_ech (e2e 同面)."""
        status, _, body = self.inst.request(
            "GET", "/explain?name=%s" % QNAME, timeout=30.0)
        self.assertEqual(status, 200, "explain 应答 %d" % status)
        doc = json.loads(body)
        self.assertTrue(doc.get("client_ip"), "explain 缺 client_ip")
        for key in ("A", "AAAA", "HTTPS"):
            self.assertIn(key, doc.get("answers", {}), "explain 缺 answers.%s" % key)
        self.assertIn("chromium_ech", doc, "explain 缺 chromium_ech")

    def test_live_probe_health(self):
        """/health ok + /probe 回显客户端 IP (e2e 同面)."""
        status, _, body = self.inst.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body).get("ok") is True, "health 非 ok")
        status, _, body = self.inst.request("GET", "/probe")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body).get("client_ip"), "probe 缺 client_ip")

    def test_live_admin_matrix(self):
        """admin 鉴权矩阵: 无令牌 401, 正确令牌 200 (e2e 同面)."""
        status, _, _ = self.inst.admin_json("GET", "/admin/preferred", token=None)
        self.assertEqual(status, 401, "无令牌应 401, 实际 %d" % status)
        status, _, _ = self.inst.admin_json("GET", "/admin/preferred",
                                            token=ADMIN_TOKEN)
        self.assertEqual(status, 200, "管理令牌应 200, 实际 %d" % status)

    def test_live_snapshot_reboot(self):
        """SIGTERM 快照 4 件套 + 重启恢复应答 (e2e 同面)."""
        inst = self.inst
        inst.stop(sig=15, expect_exit=0)
        snaps = harness.snapshot_paths(inst.env["CACHE_PERSIST_PATH"])
        for label, path in snaps.items():
            self.assertTrue(Path(path).is_file(),
                            "快照缺失: %s (%s)" % (label, path))
        self.inst = self._start("live-2")
        self._query(self.inst, 0x4234, QNAME, dnscodec.TYPE_A)

    def test_live_no_rewrite_without_pool(self):
        """无池场景: 应答为默认上游语义 (地址非池改写), explain pool 为空."""
        packet = self._query(self.inst, 0x5234, QNAME, dnscodec.TYPE_A)
        self.assertGreaterEqual(
            len(dnscodec.answer_addresses(packet, dnscodec.TYPE_A)), 1,
            "A 记录缺失")
        status, _, body = self.inst.request(
            "GET", "/explain?name=%s&type=A" % QNAME, timeout=30.0)
        self.assertEqual(status, 200)
        doc = json.loads(body)
        pool = doc.get("pool") or {}
        self.assertFalse(pool.get("ipv4") or pool.get("ipv6"),
                         "零上报/无优选域名场景不应有可用池地址: %r" % pool)


if __name__ == "__main__":
    unittest.main()
