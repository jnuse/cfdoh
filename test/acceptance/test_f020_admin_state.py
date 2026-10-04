"""F-020 管理状态查询与自检上报 — 3 用例 (S-STD).

断言语义真源: .trellis/spec/prd/requirements.md F-020 节.
GET /admin/preferred 返回全部池与探针状态; hub 令牌只读面 403;
自检上报 problems 截 50 条.
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

# GET /admin/preferred 顶层键 (F-020: 自学习/专属/运营商/GitHub/站点/
# Meta ECH/自检/h3 全量状态)
STATE_KEYS = {"learned", "scoped", "isp", "github", "site", "ech", "h3",
              "selfcheck"}


def a_records_response(qid, qname, addresses, ttl=300):
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class F020AdminStateTest(unittest.TestCase):
    """F-020: 全量状态 JSON, hub GET 403, 自检上报截断."""

    @classmethod
    def setUpClass(cls):
        cls.stacks = []
        cls.instances = []
        try:
            u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f020-u1").start()
            u1.add_doh("m20.example.com", dnscodec.TYPE_A,
                       a_records_response(0x1234, "m20.example.com",
                                          ["104.16.132.229"]))
            cls.stacks.append(u1)
            cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f020-cfrange").start()
            cfrange.add_path("/ips-v4", CF_V4_LIST)
            cfrange.add_path("/ips-v6", CF_V6_LIST)
            cls.stacks.append(cfrange)

            workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f020"
            if workdir.exists():
                shutil.rmtree(workdir)
            env = harness.family_env(
                "s_std", upstreams="%s/dns-query" % u1.base_url,
                workdir=workdir / "std")
            cls.inst = harness.Instance("f020-s-std", env,
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

    def test_f020_full_state(self):
        """F-020 AC: ADMIN_TOKEN GET /admin/preferred → 全量状态键."""
        status, data, _ = self.inst.admin_json("GET", "/admin/preferred")
        self.assertEqual(status, 200)
        self.assertIsInstance(data, dict)
        missing = STATE_KEYS - set(data)
        self.assertEqual(missing, set(),
                         "状态 JSON 须含全部池与探针键, 缺: %r" % missing)

    def test_f020_hub_get_403(self):
        """F-020 AC: hub 令牌 GET → 403 (仅允许写 isp 池)."""
        status, _, _ = self.inst.admin_json("GET", "/admin/preferred",
                                            token=harness.HUB_TOKEN)
        self.assertEqual(status, 403)

    def test_f020_selfcheck_report(self):
        """F-020: 自检上报 60 条 problems → 状态只保留 50 条截断."""
        status, _, _ = self.inst.admin_json(
            "POST", "/admin/selfcheck",
            payload={"source": "sc-probe", "ok": False,
                     "problems": ["problem-%02d" % i for i in range(60)]})
        self.assertTrue(200 <= status < 300, "自检上报失败: %s" % status)
        status, data, _ = self.inst.admin_json("GET", "/admin/selfcheck")
        self.assertEqual(status, 200)
        rows = [r for r in (data or []) if r.get("source") == "sc-probe"]
        self.assertEqual(len(rows), 1, "同 source 覆盖: %r" % rows)
        problems = rows[0].get("problems") or []
        self.assertEqual(len(problems), 50,
                         "60 条 problems 须截断为 50: %d" % len(problems))


if __name__ == "__main__":
    unittest.main()
