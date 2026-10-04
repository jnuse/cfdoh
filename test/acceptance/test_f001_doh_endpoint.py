"""F-001 DoH 查询端点 — 端点合同 14 用例 (S-STD + 别名路径).

断言语义真源: .trellis/spec/prd/requirements.md F-001 节.
用例清单真源: 本任务 testplan.md 批 2 F-001 节, 逐条物化.
"""

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

ALIAS = "/linuxdo"

DNS_MSG = "application/dns-message"


def a_records_response(qid, qname, addresses, ttl):
    """构造 A 应答: question 回显 + 未压缩名字的 N 条 A 记录."""
    qn = dnscodec.encode_name(qname)
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(addresses), 0, 0) \
        + qn + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    for addr in addresses:
        rdata = bytes(int(x) for x in addr.split("."))
        out += qn + struct.pack(">HHIH", dnscodec.TYPE_A,
                                dnscodec.CLASS_IN, ttl, len(rdata)) + rdata
    return out


class F001DohEndpointTest(unittest.TestCase):
    """F-001: RFC 8484 校验矩阵, 应答头, 事务 ID, 路径别名, 轮转."""

    @classmethod
    def setUpClass(cls):
        cls.query = (FIXTURES / "query_a_www_example_com.bin").read_bytes()
        cls.response = (FIXTURES
                        / "response_a_www_example_com.bin").read_bytes()
        cls.u1 = fakestack.FakeStack(harness.STACK_PORTS["u1"], "doh",
                                     name="f001-u1").start()
        cls.u1.add_doh("www.example.com", dnscodec.TYPE_A, cls.response)
        cls.u1.add_doh(
            "rotate.example.org", dnscodec.TYPE_A,
            a_records_response(0x1234, "rotate.example.org",
                               ["93.184.216.34", "93.184.216.35",
                                "93.184.216.36"], 300))
        cls.cfrange = fakestack.FakeStack(harness.STACK_PORTS["cfrange"],
                                          "files", name="f001-cfrange").start()
        cls.cfrange.add_path("/ips-v4", CF_V4_LIST)
        cls.cfrange.add_path("/ips-v6", CF_V6_LIST)
        cls.workdir = harness.REPO_ROOT / ".cache" / "acceptance" / "f001"
        if cls.workdir.exists():
            shutil.rmtree(cls.workdir)
        env = harness.family_env(
            "s_std",
            upstreams="%s/dns-query" % cls.u1.base_url,
            workdir=cls.workdir,
            path_aliases=ALIAS)
        cls.inst = harness.Instance("f001-s-std", env, cls.workdir).start()

    @classmethod
    def tearDownClass(cls):
        inst = getattr(cls, "inst", None)
        if inst is not None and inst.proc is not None and not inst._stopped:
            inst.kill()  # 清理路径, 不做断言
        for stack in (getattr(cls, "u1", None),
                      getattr(cls, "cfrange", None)):
            if stack is not None:
                stack.stop()

    # ------------------------------------------------ 200 通道与应答头

    def test_f001_ok_get(self):
        """F-001: 合法 GET → 200, ID 回填, rcode 0, 应答头三件套."""
        status, headers, body = self.inst.doh_get(self.query)
        self.assertEqual(status, 200)
        self.assertEqual(harness.header(headers, "Content-Type"), DNS_MSG)
        self.assertEqual(harness.header(headers, "Cache-Control"), "no-store")
        self.assertEqual(harness.header(headers, "X-Content-Type-Options"),
                         "nosniff")
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["id"], 0x1234, "事务 ID 必须回填请求 ID")
        self.assertEqual(packet["rcode"], 0)

    def test_f001_ok_post(self):
        """F-001: 合法 POST 通道 → 与 GET 同语义."""
        status, headers, body = self.inst.doh_post(self.query)
        self.assertEqual(status, 200)
        self.assertEqual(harness.header(headers, "Content-Type"), DNS_MSG)
        self.assertEqual(harness.header(headers, "Cache-Control"), "no-store")
        self.assertEqual(harness.header(headers, "X-Content-Type-Options"),
                         "nosniff")
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["id"], 0x1234, "事务 ID 必须回填请求 ID")
        self.assertEqual(packet["rcode"], 0)

    # ------------------------------------------------ 请求校验矩阵

    def test_f001_qr_set_400(self):
        """F-001: QR 置位的请求包 → 400."""
        qr_query = bytearray(self.query)
        qr_query[2] |= 0x80
        status, _, _ = self.inst.doh_get(bytes(qr_query))
        self.assertEqual(status, 400)

    def test_f001_accept_406(self):
        """F-001: Accept: text/html → 406."""
        status, _, _ = self.inst.doh_get(
            self.query, accept=False, extra_headers={"Accept": "text/html"})
        self.assertEqual(status, 406)

    def test_f001_alias_path(self):
        """F-001: 别名路径与 /dns-query 行为逐项一致 (200/400/406 矩阵)."""
        status, _, body = self.inst.doh_get(self.query, path=ALIAS)
        self.assertEqual(status, 200)
        packet = dnscodec.parse_packet(body)
        self.assertEqual(packet["id"], 0x1234)
        self.assertEqual(packet["rcode"], 0)
        status, _, _ = self.inst.request(
            "GET", ALIAS, headers={"Accept": DNS_MSG})
        self.assertEqual(status, 400, "别名路径缺 dns 参数须与主路径一致")
        status, _, _ = self.inst.doh_get(
            self.query, path=ALIAS, accept=False,
            extra_headers={"Accept": "text/html"})
        self.assertEqual(status, 406, "别名路径 Accept 校验须与主路径一致")

    def test_f001_post_content_type_415(self):
        """F-001: POST Content-Type: text/plain → 415."""
        status, _, _ = self.inst.request(
            "POST", "/dns-query",
            headers={"Accept": DNS_MSG, "Content-Type": "text/plain"},
            body=self.query)
        self.assertEqual(status, 415)

    def test_f001_get_missing_dns_400(self):
        """F-001: GET 无 dns 参数 → 400."""
        status, _, _ = self.inst.request("GET", "/dns-query",
                                         headers={"Accept": DNS_MSG})
        self.assertEqual(status, 400)

    def test_f001_get_bad_b64_400(self):
        """F-001: dns 含非法 base64url 字符 → 400."""
        status, _, _ = self.inst.request(
            "GET", "/dns-query?dns=ab!cd", headers={"Accept": DNS_MSG})
        self.assertEqual(status, 400)

    def test_f001_oversize_413(self):
        """F-001: 请求体超 MAX_DNS_PACKET_SIZE (4096) → 413.

        Content-Length 预检路径: 显式携带超限长度, 服务端须在读体前拒绝.
        """
        big = self.query + b"\x00" * 8192
        status, _, _ = self.inst.request(
            "POST", "/dns-query",
            headers={"Accept": DNS_MSG, "Content-Type": DNS_MSG}, body=big)
        self.assertEqual(status, 413)

    def test_f001_method_405(self):
        """F-001: DELETE → 405, Allow 头含 GET 与 POST."""
        status, headers, _ = self.inst.request("DELETE", "/dns-query",
                                               headers={"Accept": DNS_MSG})
        self.assertEqual(status, 405)
        allow = (harness.header(headers, "Allow") or "").upper()
        self.assertIn("GET", allow, "Allow 须含 GET: %r" % allow)
        self.assertIn("POST", allow, "Allow 须含 POST: %r" % allow)

    def test_f001_multi_question_400(self):
        """F-001: qdcount=2 的包 → 400 (查询必须恰好 1 个 question)."""
        question = (dnscodec.encode_name("a.example.com")
                    + struct.pack(">HH", dnscodec.TYPE_A,
                                  dnscodec.CLASS_IN))
        packet = (struct.pack(">HHHHHH", 0x4242, 0x0100, 2, 0, 0, 0)
                  + question
                  + dnscodec.encode_name("b.example.com")
                  + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN))
        status, _, _ = self.inst.doh_get(packet)
        self.assertEqual(status, 400)

    def test_f001_opcode_nonzero_400(self):
        """F-001: opcode=1 的包 → 400 (opcode 必须为 0)."""
        query = dnscodec.build_query(0x4243, "opcode.example.com",
                                     dnscodec.TYPE_A, edns=False)
        query = bytearray(query)
        query[2:4] = struct.pack(">H", 0x0900)  # opcode=1 | RD
        status, _, _ = self.inst.doh_get(bytes(query))
        self.assertEqual(status, 400)

    def test_f001_trailing_garbage_400(self):
        """F-001: 合法包后接尾随字节 → 400."""
        trailing = (FIXTURES / "attack_trailing.bin").read_bytes()
        status, _, _ = self.inst.doh_get(trailing)
        self.assertEqual(status, 400)

    # ------------------------------------------------ 轮转

    def test_f001_rotation(self):
        """F-001: 同键连续查询 ≥6 次 → 首条 A 记录出现 ≥2 种取值.

        上游应答含 3 条 A 记录; 应答前按 type 分组循环左移, 缓存命中轮转
        也生效, 用以分散只连首个地址的客户端.
        """
        query = dnscodec.build_query(0x2101, "rotate.example.org",
                                     dnscodec.TYPE_A, edns=False)
        firsts = []
        for _ in range(6):
            status, _, body = self.inst.doh_get(query)
            self.assertEqual(status, 200)
            addresses = dnscodec.answer_addresses(
                dnscodec.parse_packet(body), dnscodec.TYPE_A)
            self.assertEqual(len(addresses), 3)
            firsts.append(addresses[0])
        self.assertGreaterEqual(
            len(set(firsts)), 2,
            "首条 A 记录应随查询轮转 (实际序列: %r)" % firsts)


if __name__ == "__main__":
    unittest.main()
