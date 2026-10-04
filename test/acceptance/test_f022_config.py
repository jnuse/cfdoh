"""F-022 服务端配置体系 — 3 用例 (S-CONFIG, 最小受控配置等价面).

断言语义真源: .trellis/spec/prd/requirements.md F-022 节.
已知取舍 #2: 零配置默认上游为真实三上游, 属 live 层; acceptance 用
"最小受控配置" 等价面 — 仅 UPSTREAMS 与 CF 网段源受控, 其余默认/关闭.
配置文件机制真名为 CFDOH_CONFIG (KEY=VALUE 文件), 环境变量优先.
数值钳制断言从脱敏摘要读值 (timeout=15000ms), 钳制提示来自启动日志.
decoy 端口取已登记未占用的 extra2 (18108).
"""

import shutil
import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST

DECOY_PORT = harness.STACK_PORTS["extra2"]  # 18108, 仅出现在配置文件里


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class F022ConfigTest(unittest.TestCase):
    """F-022: 最小配置默认应答, 数值钳制入日志, 环境变量优先于配置文件."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f022-u1").start()
            u1.add_doh("www.example.com", dnscodec.TYPE_A,
                       a_records_response(0, "www.example.com",
                                          ["104.16.132.229"]))
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f022-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)
            cls.base = harness.REPO_ROOT / ".cache" / "acceptance" / "f022"
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

    def _start(self, name, subdir, extra=None, **kw):
        env = harness.family_env(
            "s_config", upstreams="%s/dns-query" % self.u1.base_url,
            workdir=self.base / subdir, extra=extra, **kw)
        inst = harness.Instance(name, env, self.base / subdir).start()
        self.instances.append(inst)
        return inst

    def test_f022_min_config_works(self):
        """F-022 AC: 仅 UPSTREAMS 受控 (其余默认) → 应答正常且无池不改写."""
        inst = self._start("f022-min", "min", admin_token="", hub_token="")
        try:
            query = dnscodec.build_query(0x2201, "www.example.com",
                                         dnscodec.TYPE_A, edns=False)
            status, _, body = inst.doh_get(query)
            self.assertEqual(status, 200)
            packet = dnscodec.parse_packet(body)
            self.assertEqual(packet["rcode"], 0)
            self.assertEqual(packet["id"], 0x2201)
            self.assertEqual(
                dnscodec.answer_addresses(packet, dnscodec.TYPE_A),
                ["104.16.132.229"],
                "无池时不得改写, 应答须与上游一致")
        finally:
            inst.stop()

    def test_f022_clamped_logged(self):
        """F-022 AC: 数值超区间 → 钳到边界且启动日志可见 (值从脱敏摘要断言)."""
        inst = self._start("f022-clamp", "clamp",
                           extra={"UPSTREAM_TIMEOUT_MS": "99999"})
        try:
            log = inst.log_text()
            self.assertIn("clamped to maximum", log, "须输出钳制提示")
            self.assertIn("UPSTREAM_TIMEOUT_MS", log, "提示须含键名")
            self.assertIn("timeout=15000ms", log,
                          "脱敏摘要须显示钳后值 15000")
            status, _, _ = inst.request("GET", "/health")
            self.assertEqual(status, 200)
        finally:
            inst.stop()

    def test_f022_env_overrides_file(self):
        """F-022 AC: 配置文件 PORT=decoy + 环境变量 PORT → 实际监听环境变量值."""
        wd = self.base / "prec"
        wd.mkdir(parents=True, exist_ok=True)
        cfg_file = wd / "cfdoh.conf"
        cfg_file.write_text("# KEY=VALUE 配置文件\nPORT=%d\n" % DECOY_PORT)
        inst = self._start("f022-prec", "prec",
                           extra={"CFDOH_CONFIG": str(cfg_file)})
        try:
            # 环境变量 PORT (s_config 族端口) 胜出: 就绪等待本身就证明监听在 B
            status, _, _ = inst.request("GET", "/health")
            self.assertEqual(status, 200)
            # 配置文件里的 decoy 端口不得被监听
            try:
                with socket.create_connection(("127.0.0.1", DECOY_PORT),
                                               timeout=1.0):
                    pass
                self.fail("配置文件 PORT 不得生效 (环境变量优先)")
            except OSError:
                pass
        finally:
            inst.stop()


if __name__ == "__main__":
    unittest.main()
