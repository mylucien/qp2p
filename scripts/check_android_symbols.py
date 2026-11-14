#!/usr/bin/env python3
"""校验 Android 的 .so 没有引用高于 minSdk 的 libc 符号。

为什么需要这个：Rust 交叉编译到 Android 时，NDK 的 stub libc 里**所有** API 级别的
符号都在，链接期不会报错；一旦真机上缺这个符号，`dlopen` 直接失败，整个库加载
不起来，Kotlin 只能拿到一个 `UnsatisfiedLinkError`（没有任何线索）。

真实事故：`if_addrs` 落到 `getifaddrs`，该符号 API 24（Android 7.0）才引入，
在 Android 6.0（API 23）的电视盒子上连接按钮一点就报 `UnsatisfiedLinkError`。

规则：
1. 未定义的**强**符号（弱引用缺了不致命，跳过）不得出现在
   `scripts/data/android-libc-api-levels.txt` 中「引入版本 > minSdk」的集合里。
2. NEEDED 只能是我们认识的系统库；出现 `libc++_shared.so` 这类说明打包缺东西。

用法：
    python3 scripts/check_android_symbols.py android/app/src/main/jniLibs/*/libqp2p_android.so
"""

from __future__ import annotations

import os
import struct
import sys

MIN_API = 23
# Android 系统库里本来就有的，不需要随包分发
ALLOWED_NEEDED = {
    "libc.so",
    "libdl.so",
    "liblog.so",
    "libm.so",
    "libstdc++.so",
    "libandroid.so",
    "libz.so",
}

TABLE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "android-libc-api-levels.txt"
)

BIND_WEAK = 2


def load_table() -> dict[str, int]:
    table: dict[str, int] = {}
    with open(TABLE, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, api = line.partition("\t")
            if name and api:
                table[name] = int(api)
    return table


def read_elf(path: str) -> tuple[list[str], list[tuple[str, int]]]:
    """返回 (NEEDED 列表, [(未定义符号, 绑定类型)])。"""
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF":
        raise SystemExit(f"{path}: 不是 ELF 文件")
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"

    if is64:
        e_shoff, = struct.unpack_from(endian + "Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
    else:
        e_shoff, = struct.unpack_from(endian + "I", data, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)

    def section(i: int) -> dict:
        off = e_shoff + i * e_shentsize
        if is64:
            name, _typ, _flags, _addr, offset, size, link, _info, _align, _ent = struct.unpack_from(
                endian + "IIQQQQIIQQ", data, off
            )
        else:
            name, _typ, _flags, _addr, offset, size, link, _info, _align, _ent = struct.unpack_from(
                endian + "IIIIIIIIII", data, off
            )
        return {"name": name, "off": offset, "size": size, "link": link}

    sections = [section(i) for i in range(e_shnum)]
    shstr = sections[e_shstrndx]
    strtab = data[shstr["off"]: shstr["off"] + shstr["size"]]
    for sec in sections:
        start = sec["name"]
        sec["sname"] = strtab[start: strtab.find(b"\0", start)].decode()

    dynstr = next(s for s in sections if s["sname"] == ".dynstr")
    strings = data[dynstr["off"]: dynstr["off"] + dynstr["size"]]

    def text(at: int) -> str:
        return strings[at: strings.find(b"\0", at)].decode()

    needed: list[str] = []
    dynamic = next((s for s in sections if s["sname"] == ".dynamic"), None)
    if dynamic:
        step = 16 if is64 else 8
        fmt = endian + ("qQ" if is64 else "iI")
        pos = dynamic["off"]
        while pos < dynamic["off"] + dynamic["size"]:
            tag, value = struct.unpack_from(fmt, data, pos)
            pos += step
            if tag == 0:
                break
            if tag == 1:  # DT_NEEDED
                needed.append(text(value))

    undefined: list[tuple[str, int]] = []
    dynsym = next((s for s in sections if s["sname"] == ".dynsym"), None)
    if dynsym:
        entry = 24 if is64 else 16
        for i in range(dynsym["size"] // entry):
            pos = dynsym["off"] + i * entry
            if is64:
                name, info, _other, shndx, _value, _size = struct.unpack_from(
                    endian + "IBBHQQ", data, pos
                )
            else:
                name, _value, _size, info, _other, shndx = struct.unpack_from(
                    endian + "IIIBBH", data, pos
                )
            if shndx == 0 and name:  # SHN_UNDEF
                undefined.append((text(name), info >> 4))

    return needed, undefined


def check(path: str, table: dict[str, int]) -> list[str]:
    needed, undefined = read_elf(path)
    problems: list[str] = []

    for lib in needed:
        if lib not in ALLOWED_NEEDED:
            problems.append(f"依赖了不该有的库：{lib}（要随包分发吗？）")

    for name, bind in undefined:
        if bind == BIND_WEAK:
            continue  # 弱引用：运行时找不到就走降级分支，不会让 dlopen 失败
        api = table.get(name)
        if api is not None and api > MIN_API:
            problems.append(f"{name} 需要 API {api}，minSdk 是 {MIN_API}")

    api_max = max((table[n] for n, b in undefined if b != BIND_WEAK and n in table), default=0)
    print(
        f"  {os.path.basename(os.path.dirname(path))}/{os.path.basename(path)}: "
        f"{len(undefined)} 个未定义符号，最高要求的 libc API = {api_max}"
    )
    return problems


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    table = load_table()
    print(f"校验 {len(argv) - 1} 个 .so（minSdk = {MIN_API}）")
    failed = False
    for path in argv[1:]:
        problems = check(path, table)
        for item in problems:
            print(f"  ✗ {item}")
        if problems:
            failed = True
    if failed:
        print("失败：so 里有高于 minSdk 的符号，旧设备会 UnsatisfiedLinkError", file=sys.stderr)
        return 1
    print("通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
