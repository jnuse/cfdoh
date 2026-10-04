#!/usr/bin/env python3
"""生成冻结 fixture 字节 (手动执行, 产物提交).

- query_a_www_example_com.bin: 合法 A 查询 (ID 0x1234, RD)
- response_a_www_example_com.bin: 假上游应答 — question 回显 + 压缩指针
  answer (www.example.com A 300 104.16.132.229), 专用于锻炼 oracle 的
  指针跟随解码; 假上游回填事务 ID 后原样服务
- attack_*.bin: F-002 端点面攻击包 (指针成环 / 高位 label / qdcount 超限 /
  尾随字节)
- echconfig.b64: cloudflare-ech.com HTTPS 记录的 ech SvcParam 字节
  (2026-10 经 1.1.1.1 DoH 抓取的公开 DNS 数据, 结构合法的 ECHConfigList);
  测试用例在运行时把公钥末字节替换为 tag 字节派生互异配置
  (见各 test_f010/f012/f018 文件内 ech_config helper), 本脚本不重生它

生成后不要手改; 需要新 fixture 时改本脚本再跑.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from _shared import dnscodec  # noqa: E402

OUT = Path(__file__).resolve().parent
QID = 0x1234


def header(qid, flags, qd, an, ns, ar):
    return struct.pack(">HHHHHH", qid, flags, qd, an, ns, ar)


def label(text):
    return bytes([len(text)]) + text.encode()


def main():
    # 合法查询: www.example.com A, RD=1, 无 EDNS
    qname = label("www") + label("example") + label("com") + b"\x00"
    query = header(QID, 0x0100, 1, 0, 0, 0) + qname \
        + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    (OUT / "query_a_www_example_com.bin").write_bytes(query)

    # 应答: question 回显 + answer 名字用压缩指针 0xc00c (指向 offset 12)
    # flags: QR|RD|RA = 0x8180
    answer = b"\xc0\x0c" + struct.pack(
        ">HHIH", dnscodec.TYPE_A, dnscodec.CLASS_IN, 300,
        4, ) + bytes([104, 16, 132, 229])
    response = header(QID, 0x8180, 1, 1, 0, 0) + qname \
        + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN) + answer
    (OUT / "response_a_www_example_com.bin").write_bytes(response)

    # 攻击包 1: 压缩指针自环 — offset 12 起 label "a", offset 14 的指针
    # 指向 offset 14 自身
    loop_name = label("a") + b"\xc0\x0e"
    loop = header(QID, 0x0100, 1, 0, 0, 0) + loop_name \
        + struct.pack(">HH", 255, dnscodec.CLASS_IN)
    (OUT / "attack_pointer_loop.bin").write_bytes(loop)

    # 攻击包 2: 高位 label (0x40 长度字节 = extended label type, 非法)
    high = header(QID, 0x0100, 1, 0, 0, 0) + b"\x40" + b"b" * 64 + b"\x00" \
        + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    (OUT / "attack_high_label.bin").write_bytes(high)

    # 攻击包 3: qdcount=33 (上限 32)
    body = b""
    for i in range(33):
        body += label("q%d" % i) + label("test") + b"\x00" \
            + struct.pack(">HH", dnscodec.TYPE_A, dnscodec.CLASS_IN)
    oversized = header(QID, 0x0100, 33, 0, 0, 0) + body
    (OUT / "attack_oversized_qdcount.bin").write_bytes(oversized)

    # 攻击包 4: 合法查询 + 尾随字节
    (OUT / "attack_trailing.bin").write_bytes(query + b"DEAD")

    # 自检: 正常 query/response 可被 oracle 解析, 攻击包按预期被拒
    parsed_q = dnscodec.parse_packet(query)
    assert parsed_q["id"] == QID and parsed_q["rd"]
    assert parsed_q["questions"][0]["name"] == "www.example.com"
    parsed_r = dnscodec.parse_packet(response)
    assert parsed_r["rcode"] == 0 and parsed_r["ra"]
    assert parsed_r["answers"][0]["name"] == "www.example.com"
    assert parsed_r["answers"][0]["address"] == "104.16.132.229"
    for name in ("attack_pointer_loop", "attack_high_label", "attack_trailing"):
        try:
            dnscodec.parse_packet((OUT / (name + ".bin")).read_bytes())
        except dnscodec.DNSCodecError:
            pass
        else:
            raise SystemExit("self-check failed: %s not rejected" % name)
    # qdcount 超限包: 拒绝语义属产品 (F-002), oracle 不含该规则,
    # 仅结构性校验 fixture 确实携带 33 个 question (越过上限 32)
    oversized_packet = dnscodec.parse_packet(
        (OUT / "attack_oversized_qdcount.bin").read_bytes())
    assert len(oversized_packet["questions"]) == 33, "qdcount fixture broken"
    print("fixtures written to", OUT)


if __name__ == "__main__":
    main()
