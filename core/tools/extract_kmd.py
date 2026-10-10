#!/usr/bin/env python3

"""从 `.kmd` 产品数据文件生成 `src/kmsdata_gen.rs`。

`.kmd` 是二进制产品数据文件，布局（全部小端、紧凑）：

```text
0x00  Magic[4] = "KMD\\0"
0x04  VERSION_INFO (MinorVer u16, MajorVer u16)      MajorVer 必须为 2
0x08  CsvlkCount  u8
0x09  Flags       u8
0x0a  Reserved    u8[2]
0x0c  Counts[5]   i32 x5   AppItemCount / KmsItemCount / SkuItemCount / HostBuildCount / _
0x20  Offsets[5]  u64 x5   App / Kms / Sku / HostBuild / Reserved2
0x48  CsvlkData[CsvlkCount]   每项 32 字节
        +0  EPidOffset   u64（指向字符串池里的 ePID 模板串）
        +8  ReleaseDate  i64（Unix 秒）
        +16 GroupId      u32
        +20 MinKeyId     u32
        +24 MaxKeyId     u32
        +28 MinActiveClients u8 + Reserved[3]
      之后紧跟各种 32 字节条目：
        DataEntry: Guid[16] NameOffset u64 AppIndex KmsIndex ProtocolVersion
                    NCountPolicy IsRetail IsPreview EPidIndex reserved
        HostBuild:  DisplayNameOffset u64 ReleaseDate i64 BuildNumber i32
                    PlatformId i32 Flags u32 reserved[4]
```

用法：

    python tools/extract_kmd.py <product.kmd> [-o src/kmsdata_gen.rs]

脚本只依赖标准库；生成的表由 `src/kmsdata.rs` 用 `include!` 引入。
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

HEADER_FIXED = 0x48
CSVLK_SIZE = 32
ITEM_SIZE = 32
HOSTBUILD_SIZE = 32

MAGIC = b"KMD\0"
SUPPORTED_MAJOR = 2

def u8(b: bytes, o: int) -> int:
    return b[o]

def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]

def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]

def i32(b: bytes, o: int) -> int:
    return struct.unpack_from("<i", b, o)[0]

def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]

def i64(b: bytes, o: int) -> int:
    return struct.unpack_from("<q", b, o)[0]

def cstr(data: bytes, offset: int, what: str) -> str:
    """读字符串池里的 C 字符串。"""
    if offset == 0:
        return ""
    if not (0 < offset < len(data)):
        raise ValueError(f"{what}: 字符串偏移 {offset} 越界（文件 {len(data)} 字节）")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError(f"{what}: 偏移 {offset} 起没有字符串终止符")
    return data[offset:end].decode("utf-8", errors="replace")

def guid(data: bytes, offset: int) -> list[int]:
    return list(data[offset : offset + 16])

def parse(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < HEADER_FIXED:
        raise ValueError("文件太短，连 header 都不够")
    if data[:4] != MAGIC:
        raise ValueError(f"magic 不是 KMD\\0，而是 {data[:4]!r}")
    if data[-1] != 0:
        raise ValueError("文件末尾不是 0，按 loadKmsData() 的检查应视为格式错误")

    major = u16(data, 6)
    if major != SUPPORTED_MAJOR:
        raise ValueError(f"不支持的 KMD 主版本 {major}（只支持 {SUPPORTED_MAJOR}）")

    header = {
        "minor": u16(data, 4),
        "major": major,
        "csvlk_count": u8(data, 8),
        "flags": u8(data, 9),
        "app_count": u32(data, 0x0C),
        "kms_count": u32(data, 0x10),
        "sku_count": u32(data, 0x14),
        "host_count": u32(data, 0x18),
        "app_off": u64(data, 0x20),
        "kms_off": u64(data, 0x28),
        "sku_off": u64(data, 0x30),
        "host_off": u64(data, 0x38),
        "reserved2_off": u64(data, 0x40),
    }

    csvlk = []
    for i in range(header["csvlk_count"]):
        o = HEADER_FIXED + i * CSVLK_SIZE
        if o + CSVLK_SIZE > len(data):
            raise ValueError(f"CSVLK #{i} 越界")
        csvlk.append(
            {
                "epid": cstr(data, u64(data, o), f"CSVLK #{i} 的 ePID"),
                "release_date": i64(data, o + 8),
                "group_id": u32(data, o + 16),
                "min_key_id": u32(data, o + 20),
                "max_key_id": u32(data, o + 24),
                "min_active_clients": u8(data, o + 28),
            }
        )

    def read_item(off: int, what: str) -> dict:
        if off + ITEM_SIZE > len(data):
            raise ValueError(f"{what} 越界（偏移 {off}）")
        return {
            "guid": guid(data, off),
            "name": cstr(data, u64(data, off + 16), f"{what} 的名字"),
            "app_index": u8(data, off + 24),
            "kms_index": u8(data, off + 25),
            "protocol_version": u8(data, off + 26),
            "n_count_policy": u8(data, off + 27),
            "is_retail": u8(data, off + 28),
            "is_preview": u8(data, off + 29),
            "epid_index": u8(data, off + 30),
        }

    apps = [
        read_item(header["app_off"] + i * ITEM_SIZE, f"App #{i}")
        for i in range(header["app_count"])
    ]
    kms_items = [
        read_item(header["kms_off"] + i * ITEM_SIZE, f"Kms #{i}")
        for i in range(header["kms_count"])
    ]
    sku_items = [
        read_item(header["sku_off"] + i * ITEM_SIZE, f"Sku #{i}")
        for i in range(header["sku_count"])
    ]

    hostbuilds = []
    for i in range(header["host_count"]):
        o = header["host_off"] + i * HOSTBUILD_SIZE
        if o + HOSTBUILD_SIZE > len(data):
            raise ValueError(f"HostBuild #{i} 越界")
        hostbuilds.append(
            {
                "name": cstr(data, u64(data, o), f"HostBuild #{i} 的显示名"),
                "release_date": i64(data, o + 8),
                "build_number": i32(data, o + 16),
                "platform_id": i32(data, o + 20),
                "flags": u32(data, o + 24),
            }
        )

    if csvlk and sum(CSVLK_SIZE for _ in csvlk) + HEADER_FIXED != header["app_off"]:
        raise ValueError(
            f"CSVLK 数组结尾 {HEADER_FIXED + len(csvlk) * CSVLK_SIZE} 与 AppItemOffset "
            f"{header['app_off']} 不吻合"
        )
    total = header["app_count"] + header["kms_count"] + header["sku_count"]
    if total and header["app_off"] + total * ITEM_SIZE != header["host_off"]:
        raise ValueError("条目数组结尾与 HostBuildOffset 不吻合")
    if header["host_count"] and header["host_off"] + header["host_count"] * HOSTBUILD_SIZE > len(data):
        raise ValueError("HostBuild 数组超出文件")

    for i, item in enumerate(kms_items):
        if item["epid_index"] >= len(csvlk):
            raise ValueError(f"Kms #{i} 的 EPidIndex {item['epid_index']} 超出 CSVLK 数量")
        if item["app_index"] >= len(apps):
            raise ValueError(f"Kms #{i} 的 AppIndex {item['app_index']} 超出 App 数量")

    return {
        "header": header,
        "csvlk": csvlk,
        "apps": apps,
        "kms_items": kms_items,
        "sku_items": sku_items,
        "hostbuilds": hostbuilds,
        "size": len(data),
    }

def rust_bytes(values: list[int]) -> str:
    return "[" + ", ".join(f"0x{v:02X}" for v in values) + "]"

def rust_str(s: str) -> str:
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'

def emit(parsed: dict, kmd_name: str) -> str:
    out = []
    w = out.append

    w("// 由 tools/extract_kmd.py 生成，请勿手工编辑。")
    w(f"// 数据来源：{kmd_name}（{parsed['size']} 字节）")
    w("// CSVLK {} 条 / 产品(KmsItem) {} 条 / App {} 条 / SKU {} 条 / HostBuild {} 条"
      .format(
          len(parsed["csvlk"]),
          len(parsed["kms_items"]),
          len(parsed["apps"]),
          len(parsed["sku_items"]),
          len(parsed["hostbuilds"]),
      ))
    w("")

    w("/// CSVLK 表，索引即 KMD 里 `CsvlkData[]` 的下标。")
    w("pub const CSVLK: &[Csvlk] = &[")
    for c in parsed["csvlk"]:
        w("    Csvlk {")
        w(f"        epid: {rust_str(c['epid'])},")
        w(f"        group_id: {c['group_id']},")
        w(f"        min_key_id: 0x{c['min_key_id']:08X},")
        w(f"        max_key_id: 0x{c['max_key_id']:08X},")
        w(f"        min_active_clients: {c['min_active_clients']},")
        w(f"        release_date: {c['release_date']},")
        w("    },")
    w("];")
    w("")

    w("/// 产品表（KMD 的 `KmsItemList`）：客户端请求里的 `KMSID` 在这张表里匹配。")
    w("pub const PRODUCTS: &[Product] = &[")
    for item in parsed["kms_items"]:
        app = parsed["apps"][item["app_index"]] if parsed["apps"] else None
        app_guid = app["guid"] if app else [0] * 16
        w("    Product {")
        w(f"        name: {rust_str(item['name'])},")
        w(f"        kms_id: {rust_bytes(item['guid'])},")
        w(f"        app_id: {rust_bytes(app_guid)},")
        w(f"        csvlk_index: {item['epid_index']},")
        w(f"        protocol_version: {item['protocol_version']},")
        w(f"        n_count_policy: {item['n_count_policy']},")
        w(f"        is_retail: {'true' if item['is_retail'] else 'false'},")
        w(f"        is_preview: {'true' if item['is_preview'] else 'false'},")
        w("    },")
    w("];")
    w("")

    return "\n".join(out)

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="从 .kmd 生成 Rust 常量表")
    ap.add_argument("kmd", type=Path, help=".kmd 产品数据文件")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("src/kmsdata_gen.rs"),
        help="输出文件（默认 src/kmsdata_gen.rs）",
    )
    args = ap.parse_args(argv)

    parsed = parse(args.kmd)
    text = emit(parsed, args.kmd.name)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")

    h = parsed["header"]
    print(
        f"KMD {h['major']}.{h['minor']}：CSVLK {h['csvlk_count']} / App {h['app_count']} / "
        f"Kms {h['kms_count']} / Sku {h['sku_count']} / HostBuild {h['host_count']}",
        file=sys.stderr,
    )
    print(f"已写入 {args.output}（{len(text)} 字节）", file=sys.stderr)
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"解析失败：{exc}", file=sys.stderr)
        raise SystemExit(1)
