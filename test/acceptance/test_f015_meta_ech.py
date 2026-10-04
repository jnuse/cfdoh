"""F-015 Meta ECH 三态 — 4 用例 (S-STD).

断言语义真源: .trellis/spec/prd/requirements.md F-015 节.
三态: 探针报 ok (清除覆盖回种子) / rotated + echConfig (学习新钥) /
broken (暂停注入); 学习钥校验合法 base64; 换代即刻生效.
上报通道: POST /admin/selfcheck 的 metaEch 语义 (F-015 业务规则字段:
rotated + echConfig / broken / ok).
"""

import base64
import shutil
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST

ECH_BASE = (FIXTURES / "echconfig.b64").read_text().strip()


def ech_config(tag):
    raw = bytearray(base64.b64decode(ECH_BASE))
    raw[42] = tag
    return base64.b64encode(bytes(raw)).decode()


ECH_SEED = ech_config(ord("E"))
ECH_ROTATED = ech_config(ord("R"))


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


def https_response(qid, qname, alpn, ttl=300):
    qn = dnscodec.encode_name(qname)
    val = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    params = struct.pack(">HH", dnscodec.SVC_ALPN, len(val)) + val
    rdata = struct.pack(">H", 1) + b"\x00" + params
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN) \
        + qn + struct.pack(">HHIH", dnscodec.TYPE_HTTPS, dnscodec.CLASS_IN,
                           ttl, len(rdata)) + rdata


class F015MetaEchTest(unittest.TestCase):
    """F-015: rotated 注入换代, broken 暂停, ok 回种子, 非法 base64 拒绝."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f015-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f015-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            # Meta 域名上游: A 为 Meta 网段地址; HTTPS 无 ech
            # (Meta 不在 DNS 发布 ECH, F-015 业务规则)
            u1.add_doh("meta15.example.com", dnscodec.TYPE_A,
                       a_records_response(0x1234, "meta15.example.com",
                                          ["157.240.1.35"]))
            u1.add_doh("meta15.example.com", dnscodec.TYPE_HTTPS,
                       https_response(0x1234, "meta15.example.com", ["h2"]))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f015"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std",
                extra={"CF_REWRITE_ENABLED": "true", "ECH_ENABLED": "true",
                       "ECH_SOURCE_DOMAIN": "ech-dead15.example",
                       "META_ECH_CONFIG_BASE64": ECH_SEED,
                       "META_DOMAINS": "meta15.example.com"})
            cls.inst = harness.Instance("f015-s-std", env,
                                        workdir / "std").start()
            cls.instances.append(cls.inst)
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

    def _report(self, meta):
        status, _, _ = self.inst.admin_json(
            "POST", "/admin/selfcheck",
            payload={"source": "meta-probe", "ok": True, "metaEch": meta})
        return status

    def _ech_of(self, qid):
        query = dnscodec.build_query(qid, "meta15.example.com",
                                     dnscodec.TYPE_HTTPS, edns=False)
        status, _, body = self.inst.doh_get(query)
        self.assertEqual(status, 200)
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["rcode"], 0)
        for rec in packet["answers"]:
            if rec["type"] == dnscodec.TYPE_HTTPS:
                return rec["params"].get(dnscodec.SVC_ECH)
        return None

    def test_f015_rotated_injected(self):
        """F-015 AC: 报 rotated + 合法配置 → 注入学习钥且即刻换代."""
        status = self._report({"state": "rotated", "echConfig": ECH_ROTATED})
        self.assertTrue(200 <= status < 500, "上报处理异常: %s" % status)
        self.assertEqual(
            self._ech_of(0xf001), ECH_ROTATED,
            "rotated 后 Meta HTTPS 须注入学习钥字节 (即刻换代, 不等 TTL)")

    def test_f015_broken_suspended(self):
        """F-015 AC: 报 broken → 不注入任何配置 (未污染上游应答)."""
        self._report({"state": "rotated", "echConfig": ECH_ROTATED})
        status = self._report({"state": "broken"})
        self.assertTrue(200 <= status < 500, "上报处理异常: %s" % status)
        self.assertIsNone(
            self._ech_of(0xf002),
            "broken 后不得注入任何 ECH 配置 (返回未污染上游应答)")

    def test_f015_ok_back_to_seed(self):
        """F-015 AC: 报 ok → 清除覆盖回到种子配置."""
        self._report({"state": "rotated", "echConfig": ECH_ROTATED})
        status = self._report({"state": "ok"})
        self.assertTrue(200 <= status < 500, "上报处理异常: %s" % status)
        self.assertEqual(self._ech_of(0xf003), ECH_SEED,
                         "ok 后须清除学习覆盖, 回到种子配置")

    def test_f015_invalid_b64_rejected(self):
        """F-015: rotated 附非法 base64 → 400, 保持原态 (学习覆盖不动).

        区分性场景 (2026-10-04 裁决对齐 refer): 先合法 rotated 建立学习
        覆盖, 再发坏 rotated; 坏上报只应被拒绝, 不得触发状态迁移
        (旧实现的清除回种子行为已翻案).
        """
        status = self._report({"state": "rotated", "echConfig": ECH_ROTATED})
        self.assertTrue(200 <= status < 500, "上报处理异常: %s" % status)
        self.assertEqual(self._ech_of(0xf004), ECH_ROTATED,
                         "前置: 合法 rotated 后注入学习钥")
        status = self._report({"state": "rotated",
                               "echConfig": "!!not-base64!!"})
        self.assertEqual(status, 400, "非法 base64 的 rotated 须 400 拒绝")
        self.assertEqual(
            self._ech_of(0xf005), ECH_ROTATED,
            "坏上报不得迁移状态, 学习覆盖须原样保持 (对齐 refer)")


if __name__ == "__main__":
    unittest.main()
