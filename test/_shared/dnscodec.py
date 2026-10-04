"""Mini DNS wire codec — 独立 oracle.

与 Go 实现 (internal/wire) 完全独立的双实现, 用于交叉验证. 只覆盖验收断言
所需子集: 查询构造 (header/question/OPT 含 ECS 合成), 应答解析 (flags,
question, A/AAAA/CNAME, HTTPS SvcParam: alpn/ipv4hint/ipv6hint/ech, OPT 的
ECS option 读出), 压缩指针跟随含跳数上限. 不追求全类型覆盖.
"""

import base64
import struct

TYPE_A = 1
TYPE_CNAME = 5
TYPE_AAAA = 28
TYPE_OPT = 41
TYPE_HTTPS = 65

CLASS_IN = 1

# RFC 9460 SvcParamKey
SVC_ALPN = 1
SVC_IPV4HINT = 4
SVC_ECH = 5
SVC_IPV6HINT = 6

# EDNS option code
OPT_ECS = 8

MAX_NAME_BYTES = 255
MAX_POINTER_JUMPS = 32


class DNSCodecError(ValueError):
    """报文不合法 (含压缩指针成环, 高位 label, 截断, 尾随字节)."""


# ---------------------------------------------------------------- 编码

def encode_name(name):
    """域名的未压缩编码. label 1..63 字节, 全名含长度前缀与终止符 ≤ 255."""
    out = b""
    total = 1
    for label in name.rstrip(".").split("."):
        if label == "":
            raise DNSCodecError("empty label in %r" % name)
        try:
            b = label.encode("ascii")
        except UnicodeEncodeError:
            raise DNSCodecError("non-ascii label %r" % label)
        if len(b) > 63:
            raise DNSCodecError("label too long: %r" % label)
        out += bytes([len(b)]) + b
        total += 1 + len(b)
    if total > MAX_NAME_BYTES:
        raise DNSCodecError("name exceeds 255 bytes: %r" % name)
    return out + b"\x00"


def encode_ecs_option(family, source_prefix, address_bytes):
    """合成 ECS (EDNS Client Subnet, option code 8) 的 value.

    address_bytes 必须已截断为 ceil(source_prefix/8) 字节.
    """
    if family not in (1, 2):
        raise DNSCodecError("bad ECS family %d" % family)
    nbytes = (source_prefix + 7) // 8
    if len(address_bytes) != nbytes:
        raise DNSCodecError("ECS address bytes %d != prefix /%d needs %d"
                            % (len(address_bytes), source_prefix, nbytes))
    value = struct.pack(">HBB", family, source_prefix, 0) + address_bytes
    return struct.pack(">HH", OPT_ECS, len(value)) + value


def build_query(qid, qname, qtype, rd=True, edns=True, ecs=None,
                qclass=CLASS_IN, ecs_source_prefix=None):
    """构造一个 question 的查询包.

    edns: 是否附加 OPT (class 1232, DO=0).
    ecs: (family, prefix, address_bytes) 三元组时在 OPT 中合成 ECS option.
    """
    flags = 0
    if rd:
        flags |= 0x0100
    body = encode_name(qname) + struct.pack(">HH", qtype, qclass)
    extra = b""
    arcount = 0
    if edns:
        opt_rdata = b""
        if ecs is not None:
            family, prefix, addr = ecs
            if ecs_source_prefix is not None:
                prefix = ecs_source_prefix
            opt_rdata = encode_ecs_option(family, prefix, addr)
        extra = (b"\x00" + struct.pack(">HHIH", TYPE_OPT, 1232, 0, len(opt_rdata))
                 + opt_rdata)
        arcount = 1
    return struct.pack(">HHHHHH", qid, flags, 1, 0, 0, arcount) + body + extra


def patch_id(packet, qid):
    """把报文前两字节的事务 ID 替换为 qid (假上游应答回填用)."""
    b = bytearray(packet)
    b[0:2] = struct.pack(">H", qid)
    return bytes(b)


# ---------------------------------------------------------------- 解码

def _decode_name(data, offset):
    """从 offset 解码域名, 跟随压缩指针.

    返回 (name_text, next_offset). next_offset 是名字在原 section 中的
    结束位置 (指针只推进 2 字节). 防环: 已访问指针目标集合 + 32 跳上限.
    """
    labels = []
    visited = set()
    jumps = 0
    pos = offset
    end = None
    while True:
        if pos >= len(data):
            raise DNSCodecError("name truncated at %d" % pos)
        length = data[pos]
        if length == 0:
            if end is None:
                end = pos + 1
            break
        top = length & 0xC0
        if top == 0xC0:
            if pos + 1 >= len(data):
                raise DNSCodecError("compression pointer truncated")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if end is None:
                end = pos + 2
            if target in visited or jumps >= MAX_POINTER_JUMPS:
                raise DNSCodecError("compression pointer loop (target=%d)" % target)
            visited.add(target)
            jumps += 1
            pos = target
            continue
        if top != 0:
            raise DNSCodecError("high label bits 0x%02x at %d" % (length, pos))
        if pos + 1 + length > len(data):
            raise DNSCodecError("label truncated at %d" % pos)
        labels.append(bytes(data[pos + 1:pos + 1 + length]).decode("ascii"))
        pos += 1 + length
    return ".".join(labels), end


def _parse_question(data, offset):
    qname, offset = _decode_name(data, offset)
    if offset + 4 > len(data):
        raise DNSCodecError("question truncated")
    qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
    return {"name": qname, "type": qtype, "class": qclass}, offset + 4


def _render_ipv6(units):
    """8 组完整 hex, 不用 :: 缩写 (保证身份串稳定, 与 F-002 一致)."""
    return ":".join("%x" % u for u in units)


def _parse_a(rdata):
    if len(rdata) != 4:
        raise DNSCodecError("bad A rdata length %d" % len(rdata))
    return ".".join(str(b) for b in rdata)


def _parse_aaaa(rdata):
    if len(rdata) != 16:
        raise DNSCodecError("bad AAAA rdata length %d" % len(rdata))
    return _render_ipv6(struct.unpack(">8H", rdata))


def _parse_svcb_params(rdata, offset):
    """解析 SvcParam 序列; key 必须严格递增 (RFC 9460)."""
    params = []
    while offset < len(rdata):
        if offset + 4 > len(rdata):
            raise DNSCodecError("svcb param header truncated")
        key, plen = struct.unpack(">HH", rdata[offset:offset + 4])
        value = rdata[offset + 4:offset + 4 + plen]
        if len(value) != plen:
            raise DNSCodecError("svcb param value truncated (key=%d)" % key)
        if params and key <= params[-1][0]:
            raise DNSCodecError("svcb param key not increasing (%d after %d)"
                                % (key, params[-1][0]))
        params.append((key, value))
        offset += 4 + plen
    return params


def _parse_svcb_value(key, value):
    if key == SVC_ALPN:
        protos = []
        i = 0
        while i < len(value):
            n = value[i]
            if i + 1 + n > len(value):
                raise DNSCodecError("alpn length overflow")
            protos.append(value[i + 1:i + 1 + n].decode("ascii"))
            i += 1 + n
        return protos
    if key == SVC_IPV4HINT:
        if len(value) % 4 != 0:
            raise DNSCodecError("ipv4hint length %d not multiple of 4" % len(value))
        return [_parse_a(value[i:i + 4]) for i in range(0, len(value), 4)]
    if key == SVC_IPV6HINT:
        if len(value) % 16 != 0:
            raise DNSCodecError("ipv6hint length %d not multiple of 16" % len(value))
        return [_parse_aaaa(value[i:i + 16]) for i in range(0, len(value), 16)]
    if key == SVC_ECH:
        return base64.b64encode(value).decode("ascii")
    return value.hex()


def _parse_record(data, offset):
    """解析一条记录; 返回 (record_dict, next_offset)."""
    name, offset = _decode_name(data, offset)
    if offset + 10 > len(data):
        raise DNSCodecError("record fixed fields truncated")
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
    rstart = offset + 10
    rend = rstart + rdlen
    if rend > len(data):
        raise DNSCodecError("rdata truncated (type=%d)" % rtype)
    rdata = bytes(data[rstart:rend])
    rec = {"name": name, "type": rtype, "class": rclass, "ttl": ttl}
    if rtype == TYPE_A:
        rec["address"] = _parse_a(rdata)
    elif rtype == TYPE_AAAA:
        rec["address"] = _parse_aaaa(rdata)
    elif rtype == TYPE_CNAME:
        rec["target"], _ = _decode_name(data, rstart)
    elif rtype == TYPE_HTTPS:
        # RFC 9460: RDATA = SvcPriority(2) + TargetName + SvcParams
        if len(rdata) < 3:
            raise DNSCodecError("https rdata too short (%d)" % len(rdata))
        rec["svc_priority"] = struct.unpack(">H", rdata[:2])[0]
        target, pstart = _decode_name(data, rstart + 2)
        rec["target"] = target
        params = _parse_svcb_params(rdata, pstart - rstart)
        rec["params"] = {key: _parse_svcb_value(key, value)
                          for key, value in params}
        rec["param_keys"] = [key for key, _ in params]
    elif rtype == TYPE_OPT:
        rec["udp_payload"] = rclass
        rec["ext_rcode"] = (ttl >> 24) & 0xFF
        rec["version"] = (ttl >> 16) & 0xFF
        rec["do"] = bool(ttl & 0x8000)
        rec["options"] = _parse_opt_options(rdata)
    else:
        rec["rdata_hex"] = rdata.hex()
    return rec, rend


def _parse_opt_options(rdata):
    """解析 OPT rdata 的 option 序列, 读出 ECS (code 8)."""
    options = []
    i = 0
    while i < len(rdata):
        if i + 4 > len(rdata):
            raise DNSCodecError("opt option header truncated")
        code, olen = struct.unpack(">HH", rdata[i:i + 4])
        value = rdata[i + 4:i + 4 + olen]
        if len(value) != olen:
            raise DNSCodecError("opt option value truncated (code=%d)" % code)
        opt = {"code": code}
        if code == OPT_ECS:
            if olen < 4:
                raise DNSCodecError("ecs option too short")
            family, src_prefix, scope_prefix = struct.unpack(">HBB", value[:4])
            addr = value[4:]
            nbytes = (src_prefix + 7) // 8
            if len(addr) != nbytes:
                raise DNSCodecError("ecs address bytes %d != /%d needs %d"
                                    % (len(addr), src_prefix, nbytes))
            padded = addr + b"\x00" * ((4 if family == 1 else 16) - len(addr))
            if family == 1:
                opt["address"] = _parse_a(padded)
            elif family == 2:
                opt["address"] = _parse_aaaa(padded)
            else:
                opt["address"] = addr.hex()
            opt["family"] = family
            opt["source_prefix"] = src_prefix
            opt["scope_prefix"] = scope_prefix
        options.append(opt)
        i += 4 + olen
    return options


def parse_packet(data):
    """解析完整报文为 dict. 拒绝尾随字节与 section 计数异常."""
    data = bytes(data)
    if len(data) < 12:
        raise DNSCodecError("packet shorter than header")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", data[:12])
    packet = {
        "id": qid,
        "qr": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0xF,
        "aa": bool(flags & 0x0400),
        "tc": bool(flags & 0x0200),
        "rd": bool(flags & 0x0100),
        "ra": bool(flags & 0x0080),
        "ad": bool(flags & 0x0020),
        "cd": bool(flags & 0x0010),
        "rcode": flags & 0x000F,
        "questions": [],
        "answers": [],
        "authorities": [],
        "additionals": [],
    }
    offset = 12
    for _ in range(qdcount):
        q, offset = _parse_question(data, offset)
        packet["questions"].append(q)
    counts = (ancount, nscount, arcount)
    for section, count in zip(("answers", "authorities", "additionals"), counts):
        for _ in range(count):
            rec, offset = _parse_record(data, offset)
            packet[section].append(rec)
    if offset != len(data):
        raise DNSCodecError("trailing bytes: %d consumed of %d"
                            % (offset, len(data)))
    return packet


def find_ecs(packet):
    """返回 additionals 中 OPT 的第一个 ECS option, 无则 None."""
    for rec in packet["additionals"]:
        if rec["type"] == TYPE_OPT:
            for opt in rec.get("options", []):
                if opt["code"] == OPT_ECS:
                    return opt
    return None


def answer_addresses(packet, rtype):
    """按记录顺序返回 answers 中指定类型的字段列表 (A/AAAA → address)."""
    return [rec["address"] for rec in packet["answers"] if rec["type"] == rtype]


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text):
    if "=" in text:
        raise DNSCodecError("base64url must be unpadded")
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))
