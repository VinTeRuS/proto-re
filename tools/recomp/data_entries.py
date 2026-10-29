#!/usr/bin/env python3
"""Function entries Ghidra missed: code addresses referenced only from data (CRT initializer tables, vtables,
callbacks) or from instruction immediates (`push offset callback`). Writes re/extra_functions.txt, read by recomp.py.

A candidate is a 4-byte value anywhere in the image that points into .text, outside every known function body,
and looks like a function start (16-byte aligned, preceded by int3/ret/nop padding, or a `jmp rel32` thunk of the
incremental-linking table, whose target is added too). False positives only cost some dead recompiled code: nothing
calls them."""
import bisect
import os
import sys

import pefile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recomp  # noqa: E402  (config loading: tools/recomp/game.py or RECOMP_CONFIG)


def main():
    recomp.load_config(recomp.default_config())
    pe = pefile.PE(recomp.IMAGE, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = pe.sections[0]
    lo = base + text.VirtualAddress
    hi = lo + text.Misc_VirtualSize
    code = text.get_data()
    starts, ends = [], {}
    with open(recomp.FUNCTIONS_CSV) as f:
        next(f)
        for row in f:
            p = row.split(",")
            va = int(p[0], 16)
            starts.append(va)
            ends[va] = va + int(p[1])
    starts.sort()

    def inside(v):
        i = bisect.bisect_right(starts, v) - 1
        return i >= 0 and v < ends[starts[i]]

    def jmp_target(v):
        off = v - lo
        if code[off] != 0xE9:
            return None
        t = (v + 5 + int.from_bytes(code[off + 1:off + 5], "little", signed=True)) & 0xFFFFFFFF
        return t if lo <= t < hi else None

    def looks_like_start(v):
        off = v - lo
        if code[off] in (0xCC, 0x00):
            return False
        if jmp_target(v):  # incremental-linking thunk table: back-to-back `jmp rel32`
            return True
        return v % 16 == 0 or code[off - 1] in (0xCC, 0xC3, 0x90) or code[off - 3] == 0xC2

    found = set()
    for s in pe.sections:
        data = s.get_data()
        step = 1 if s is text else 4  # immediates in code are unaligned
        for o in range(0, len(data) - 3, step):
            v = int.from_bytes(data[o:o + 4], "little")
            if lo <= v < hi and v not in ends and not inside(v) and looks_like_start(v):
                found.add(v)
    # Functions Ghidra merged into the body of the previous one: MSVC pads between functions with int3 and starts the
    # next one 16-byte aligned; int3 never occurs inside a function body.
    merged = 0
    for off in range(16, len(code) - 1, 16):
        if code[off] == 0xCC or code[off - 1] != 0xCC:
            continue
        v = lo + off
        if v not in ends and inside(v):
            found.add(v)
            merged += 1
    print(f"{merged} starts inside Ghidra function bodies (merged functions)")

    # Thunk targets: the real function, often never referenced by anything else.
    for v in list(found) + starts:
        t = jmp_target(v)
        if t and t not in ends and not inside(t):
            found.add(t)
    out = recomp.EXTRA_FUNCTIONS
    with open(out, "w") as f:
        f.write("# Function entries missing from functions.csv (tools/recomp/data_entries.py)\n")
        for v in sorted(found):
            f.write(f"{v:08x}\n")
    print(f"{len(found)} extra entries -> {out}")


if __name__ == "__main__":
    sys.exit(main())
