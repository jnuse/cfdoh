"""F-016 规则引擎 — 5 用例 (四台规则实例 + 443 端口受控远程规则源).

断言语义真源: .trellis/spec/prd/requirements.md F-016 节.
block → REFUSED 空应答不外发; replace-a 继承原最小 TTL; 远程规则失败回退
内嵌; host-map 简写等价展开; enable-ecs/disable-ecs 逐域名覆盖模式.

实例分置成因: 单一 RULES_JSON 互扰 (block 与其余动作的行为隔离) —
每类规则独立实例, 远程规则源走仅允许的 443 端口 https.
"""

import json
import shutil
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _shared import dnscodec, fakestack, harness  # noqa: E402

CF_V4_LIST = harness.CF_V4_LIST
CF_V6_LIST = harness.CF_V6_LIST

REMOTE_RULES_PORT = 443  # 动态/远程规则仅允许 https + 443 端口 (F-016)

RULES_BLOCK = [{"domain_suffix": "block16.example.com", "action": "block"}]
RULES_REPLACE = [{"domain_suffix": "plain16.example.org",
                  "action": "replace-a", "ipv4": ["203.0.113.60"]}]
RULES_HOSTMAP = {"app16.hm.example.org": {"ipv4": ["203.0.113.61"]}}
RULES_ECS = [
    {"domain_suffix": "forced16.example.com", "action": "enable-ecs"},
    {"domain_suffix": "noecs16.example.cn", "action": "disable-ecs"},
]


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


def a_response_ttls(qid, qname, rows):
    """两条不同 TTL 的 A 记录 (TTL 继承断言用)."""
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(rows), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr, ttl in rows:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class F016RulesTest(unittest.TestCase):
    """F-016: block, replace-a, 远程回退, host-map 简写, ECS 覆盖."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f016-u1").start()
            cls.stacks.append(u1)
            cls.u1 = u1
            u2 = fakestack.FakeStack(harness.STACK_PORTS["u2"], "doh",
                                     name="f016-u2").start()
            cls.stacks.append(u2)
            cls.u2 = u2
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f016-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)
            remote = fakestack.FakeStack(REMOTE_RULES_PORT, "files",
                                         name="f016-remote").start()
            remote.add_path("/bad-rules", "{not valid json",
                            "application/json")
            cls.stacks.append(remote)
            cls.remote = remote

            for stack in (u1, u2):
                for n in ("block16.example.com", "plain16b.example.org",
                          "forced16.example.com", "noecs16.example.cn"):
                    stack.add_doh(n, dnscodec.TYPE_A,
                                  a_records_response(0x1234, n,
                                                     ["104.16.132.229"]))
            u1.add_doh("plain16.example.org", dnscodec.TYPE_A,
                       a_response_ttls(0x1234, "plain16.example.org",
                                       [("93.184.216.34", 111),
                                        ("93.184.216.35", 222)]))
            u1.add_doh("app16.hm.example.org", dnscodec.TYPE_A,
                       a_records_response(0x1234, "app16.hm.example.org",
                                          ["93.184.216.36"]))

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f016"
            if workdir.exists():
                shutil.rmtree(workdir)

            def start(family, sub, extra, ecs_upstreams=None):
                env = harness.family_env(
                    family, upstreams="%s/dns-query" % u1.base_url,
                    ecs_upstreams=(ecs_upstreams or "%s/dns-query"
                                   % u1.base_url),
                    workdir=workdir / sub, extra=extra)
                inst = harness.Instance("f016-" + sub, env,
                                        workdir / sub).start()
                cls.instances.append(inst)
                return inst

            # i1: 内嵌 block + 远程非法 JSON (回退断言)
            cls.i_block = start(
                "s_std", "block",
                {"RULES_JSON": json.dumps(RULES_BLOCK),
                 "RULES_URL": "https://127.0.0.1/bad-rules",
                 "DYNAMIC_RULE_HOSTS": "127.0.0.1",
                 "CF_REWRITE_ENABLED": "true"})
            # i2: replace-a (非 CF 站点, 可观察面不被池改写遮蔽)
            cls.i_replace = start(
                "s_drop", "replace",
                {"RULES_JSON": json.dumps(RULES_REPLACE),
                 "CF_REWRITE_ENABLED": "true"})
            # i3: host-map 简写
            cls.i_hostmap = start(
                "s_host", "hostmap",
                {"RULES_JSON": json.dumps(RULES_HOSTMAP),
                 "CF_REWRITE_ENABLED": "true"})
            # i4: ECS 逐域名覆盖 (ECS 上游分离观察)
            cls.i_ecs = start(
                "s_config", "ecs",
                {"RULES_JSON": json.dumps(RULES_ECS),
                 "CF_REWRITE_ENABLED": "true"},
                ecs_upstreams="%s/dns-query" % u2.base_url)
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

    def _query(self, inst, name, qid, xreal=None):
        query = dnscodec.build_query(qid, name, dnscodec.TYPE_A, edns=False)
        status, _, body = inst.doh_get(query, extra_headers=(
            {"X-Real-IP": xreal} if xreal else None))
        self.assertEqual(status, 200)
        return dnscodec.parse_packet(body)

    def test_f016_block_refused(self):
        """F-016 AC: block 规则命中 → rcode 3 空应答, 上游零外发."""
        packet = self._query(self.i_block, "block16.example.com", 0x1601)
        self.assertEqual(packet["rcode"], 3, "block 须返回 REFUSED")
        self.assertEqual(packet["answers"], [], "block 应答须为空")
        outbound = self.u1.doh_queries("block16.example.com",
                                       dnscodec.TYPE_A)
        self.assertEqual(outbound, [], "block 命中不得外发上游")

    def test_f016_replace_a_ttl_inherited(self):
        """F-016 AC: replace-a → 地址替换且 TTL 取原应答最小值 (111)."""
        packet = self._query(self.i_replace, "plain16.example.org", 0x1602)
        self.assertEqual(packet["rcode"], 0)
        rows = [(r["address"], r["ttl"]) for r in packet["answers"]
                if r["type"] == dnscodec.TYPE_A]
        self.assertEqual(rows, [("203.0.113.60", 111)],
                         "replace-a 须替换地址并继承原最小 TTL: %r" % rows)

    def test_f016_remote_invalid_fallback(self):
        """F-016 AC: 远程规则源非法 JSON → 内嵌规则继续生效 (block 仍 REFUSED)."""
        self.assertGreaterEqual(
            self.remote.request_count("/bad-rules"), 1,
            "远程规则源须被实际拉取过")
        packet = self._query(self.i_block, "block16.example.com", 0x1603)
        self.assertEqual(packet["rcode"], 3,
                         "远程失败后内嵌 block 须继续生效")

    def test_f016_hostmap_shorthand(self):
        """F-016: host-map 简写 → 等价展开为 replace-a 生效."""
        packet = self._query(self.i_hostmap, "app16.hm.example.org", 0x1604)
        self.assertEqual(packet["rcode"], 0)
        addrs = dnscodec.answer_addresses(packet, dnscodec.TYPE_A)
        self.assertEqual(addrs, ["203.0.113.61"],
                         "host-map 简写须展开为地址替换: %r" % addrs)

    def test_f016_per_domain_ecs_override(self):
        """F-016: enable-ecs/disable-ecs 逐域名覆盖 rules 模式."""
        xreal = "198.51.100.66"
        # .com 域名被 enable-ecs 覆盖 → 出向带 ECS (走 ECS 上游)
        self._query(self.i_ecs, "forced16.example.com", 0x1605, xreal=xreal)
        rows = self.u2.doh_queries("forced16.example.com",
                                   dnscodec.TYPE_A)
        self.assertTrue(rows, "enable-ecs 域名须外发到 ECS 上游")
        ecs = dnscodec.find_ecs(dnscodec.parse_packet(rows[-1]["query_bytes"]))
        self.assertTrue(ecs and ecs["address"] == "198.51.100.0",
                        "enable-ecs 覆盖须携带 ECS /24: %r" % ecs)
        # .cn 域名被 disable-ecs 覆盖 → 出向无 ECS
        self._query(self.i_ecs, "noecs16.example.cn", 0x1606, xreal=xreal)
        rows_u1 = self.u1.doh_queries("noecs16.example.cn",
                                      dnscodec.TYPE_A)
        rows_u2 = self.u2.doh_queries("noecs16.example.cn",
                                      dnscodec.TYPE_A)
        carriers = [r for r in rows_u1 + rows_u2
                    if dnscodec.find_ecs(dnscodec.parse_packet(
                        r["query_bytes"]))]
        self.assertEqual(carriers, [],
                         "disable-ecs 覆盖后出向不得携带 ECS")


if __name__ == "__main__":
    unittest.main()
