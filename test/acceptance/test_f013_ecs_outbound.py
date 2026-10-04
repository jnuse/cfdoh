"""F-013 ECS 子网出向断言 — 4 用例 (S-STD, UPSTREAMS 与 ECS_UPSTREAMS 分离).

断言语义真源: .trellis/spec/prd/requirements.md F-013 节.
rules 模式 (默认 .cn) 命中时出向携带客户端 /24 ECS; 非命中不带;
入向自带 ECS 被剥离或幂等替换; 带 ECS 出向走 ECS_UPSTREAMS.
全部断言来自假上游对出向报文的记录 (上游用户视角).
"""

import shutil
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST

CLIENT_IP = "198.51.100.77"   # X-Real-IP 识别的客户端
CLIENT_SUBNET = "198.51.100.0"  # v4 /24 截断后的 ECS 地址


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class F013EcsOutboundTest(unittest.TestCase):
    """F-013: .cn 带 /24 ECS, .com 不带, 入向剥离, ECS 上游路由."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f013-u1").start()
            u2 = fakestack.FakeStack(harness.STACK_PORTS["u2"], "doh",
                                     name="f013-u2").start()
            cls.stacks.extend([u1, u2])
            cls.u1, cls.u2 = u1, u2
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f013-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            for stack in (u1, u2):
                for n in ("cn13.example.cn", "com13.example.com",
                          "strip13.example.cn"):
                    stack.add_doh(n, dnscodec.TYPE_A,
                                  a_records_response(0x1234, n,
                                                     ["104.16.132.229"]))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f013"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                ecs_upstreams="%s/dns-query" % u2.base_url,
                workdir=workdir / "std")
            cls.inst = harness.Instance("f013-s-std", env,
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

    def _query(self, name, qid, ecs=None):
        """发起一次 A 查询; ecs 三元组时请求自带 ECS option."""
        ecs_tuple = None
        if ecs:
            family, prefix, addr = ecs
            ecs_tuple = (family, prefix, addr)
        query = dnscodec.build_query(qid, name, dnscodec.TYPE_A,
                                     edns=ecs_tuple is not None,
                                     ecs=ecs_tuple)
        status, _, body = self.inst.doh_get(
            query, extra_headers={"X-Real-IP": CLIENT_IP})
        self.assertEqual(status, 200)
        return dnscodec.parse_packet(body)

    @staticmethod
    def _outbound_ecs(stack, qname):
        rows = stack.doh_queries(qname, dnscodec.TYPE_A)
        options = []
        for row in rows:
            packet = dnscodec.parse_packet(row["query_bytes"])
            found = [o for rec in packet["additionals"]
                     if rec["type"] == dnscodec.TYPE_OPT
                     for o in rec.get("options", [])
                     if o["code"] == dnscodec.OPT_ECS]
            options.extend(found)
        return rows, options

    def test_f013_cn_ecs_sent(self):
        """F-013 AC: example.cn 查询出向 OPT 含 code 8, 地址截断 /24."""
        self._query("cn13.example.cn", 0xd001)
        rows, options = self._outbound_ecs(self.u2, "cn13.example.cn")
        self.assertTrue(rows, "ECS 查询须到达 ECS_UPSTREAMS (u2)")
        self.assertEqual(len(options), 1, "出向须恰一个 ECS option")
        ecs = options[0]
        self.assertEqual(ecs["family"], 1)
        self.assertEqual(ecs["source_prefix"], 24, "v4 子网须截断为 /24")
        self.assertEqual(ecs["address"], CLIENT_SUBNET,
                         "ECS 地址须为客户端 /24 网络地址: %r" % ecs)

    def test_f013_com_no_ecs(self):
        """F-013 AC: example.com 同条件出向无 ECS option."""
        self._query("com13.example.com", 0xd002)
        rows, options = self._outbound_ecs(self.u1, "com13.example.com")
        self.assertTrue(rows, "普通查询须到达 UPSTREAMS (u1)")
        self.assertEqual(options, [], "非 .cn 域名不得携带 ECS")

    def test_f013_inbound_stripped(self):
        """F-013 AC: 请求自带 ECS → 出向至多一个 (幂等替换为客户端 /24)."""
        # 入向 ECS: 203.0.113.0/24 (与客户端网段不同, 可区分替换语义)
        self._query("strip13.example.cn", 0xd003,
                    ecs=(1, 24, bytes([203, 0, 113])))
        rows, options = self._outbound_ecs(self.u2, "strip13.example.cn")
        self.assertTrue(rows)
        self.assertLessEqual(len(options), 1, "出向至多一个 ECS option")
        if options:
            self.assertEqual(options[0]["address"], CLIENT_SUBNET,
                             "保留的 ECS 须为客户端 /24 (幂等替换): %r"
                             % options[0])

    def test_f013_ecs_upstream_routing(self):
        """F-013 AC: 带 ECS 出向走 ECS_UPSTREAMS, 普通上游零收包."""
        self._query("cn13.example.cn", 0xd004)
        u2_rows, _ = self._outbound_ecs(self.u2, "cn13.example.cn")
        u1_rows, _ = self._outbound_ecs(self.u1, "cn13.example.cn")
        self.assertGreaterEqual(len(u2_rows), 1, "ECS 查询须外发到 u2")
        self.assertEqual(u1_rows, [], "ECS 查询不得外发到普通上游 u1")


if __name__ == "__main__":
    unittest.main()
