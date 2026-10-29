#!/usr/bin/env python3
"""Static recompiler: x86-32 functions of a PE image (tools/recomp/game.py) -> C (see src/recomp/runtime.h).

Each function becomes `void f_<va>(Ctx* c)`. Control flow inside the function maps to labels and goto; jumps
leaving the function are tail calls through RecompDispatch; calls push the real guest return address and go
through RecompDispatch; `ret n` pops the return address into c->ret_target and returns. Flags are computed
exactly for every instruction that defines them (no liveness elimination yet). Unsupported instructions are
emitted as RecompUnimplemented() calls and counted in the summary, never silently dropped.

Usage:
  recomp.py [--config game.py] --functions <rva list file | all> --out <file.c>
"""
import argparse
import collections
import os
import sys

import capstone
from capstone import x86_const as X
import pefile
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# Per-game settings (image path, addresses of special calls and helpers) live in a config module: tools/recomp/
# game.py by default, --config or RECOMP_CONFIG for another one. load_config() fills the globals below.
IMAGE = None  # PE image (exe or dll) being recompiled
IMAGE_NAME = None  # its file name, for the generated headers
FUNCTIONS_CSV = None  # Ghidra export (tools/ghidra/ExportFunctions.java)
EXTRA_FUNCTIONS = None  # entries Ghidra missed (tools/recomp/data_entries.py)
BASE = None  # load address of the generated code; --base rebases everything (rebase())
ORIG_BASE = None  # the image's preferred base (PE header)
LOCALIZE = True  # general registers in C locals (--no-localize to compare)
DIRTY_TRACKING = True  # spill only changed state (--no-dirty to compare)
NATIVE = False  # use NATIVE_OVERRIDES (native host builds: --base other than the image's)

REG32 = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"}
REG16 = {"ax": "eax", "cx": "ecx", "dx": "edx", "bx": "ebx", "sp": "esp", "bp": "ebp", "si": "esi", "di": "edi"}
REG8L = {"al": "eax", "cl": "ecx", "dl": "edx", "bl": "ebx"}
REG8H = {"ah": "eax", "ch": "ecx", "dh": "edx", "bh": "ebx"}
# User-mode selectors of 32-bit Windows; only ever read by the engine (stack/segment probes).
# Calls with a special implementation in recompiled code (CRT setjmp/longjmp: thunk and IAT slot addresses).
SETJMP_TARGETS = set()
# Engine functions replaced by native implementations in the native host: f_<addr> just forwards to
# Native_<original addr>.
NATIVE_OVERRIDES = set()
# Statically linked MSVC helpers emitted inline at their call sites (no call, no register spill): float->int64
# truncation, stack probes (alloca/large frames) and 64-bit integer helpers.
INLINE_HELPERS = {}
SETJMP_IAT = set()
LONGJMP_IAT = set()


def load_config(path):
    """Reads a game config module (see tools/recomp/game.py) into the globals above."""
    global IMAGE, IMAGE_NAME, FUNCTIONS_CSV, EXTRA_FUNCTIONS, BASE, ORIG_BASE
    global SETJMP_TARGETS, NATIVE_OVERRIDES, INLINE_HELPERS, SETJMP_IAT, LONGJMP_IAT
    cfg = {"__file__": path}
    with open(path) as f:
        exec(compile(f.read(), path, "exec"), cfg)
    IMAGE = os.path.expanduser(cfg["IMAGE"])
    IMAGE_NAME = os.path.basename(IMAGE)
    FUNCTIONS_CSV = cfg.get("FUNCTIONS_CSV", os.path.join(ROOT, "re", "functions.csv"))
    EXTRA_FUNCTIONS = cfg.get("EXTRA_FUNCTIONS", os.path.join(ROOT, "re", "extra_functions.txt"))
    ORIG_BASE = BASE = pefile.PE(IMAGE, fast_load=True).OPTIONAL_HEADER.ImageBase
    SETJMP_TARGETS = set(cfg.get("SETJMP_TARGETS", ()))
    NATIVE_OVERRIDES = set(cfg.get("NATIVE_OVERRIDES", ()))
    INLINE_HELPERS = dict(cfg.get("INLINE_HELPERS", {}))
    SETJMP_IAT = set(cfg.get("SETJMP_IAT", ()))
    LONGJMP_IAT = set(cfg.get("LONGJMP_IAT", ()))


def default_config():
    return os.environ.get("RECOMP_CONFIG", os.path.join(ROOT, "tools", "recomp", "game.py"))


SEGMENT_SELECTORS = {"cs": 0x1b, "ds": 0x23, "es": 0x23, "ss": 0x23, "fs": 0x3b, "gs": 0x0}

COND = {
    "o": "c->of", "no": "!c->of",
    "b": "c->cf", "ae": "!c->cf",
    "e": "c->zf", "ne": "!c->zf",
    "be": "(c->cf || c->zf)", "a": "(!c->cf && !c->zf)",
    "s": "c->sf", "ns": "!c->sf",
    "p": "c->pf", "np": "!c->pf",
    "l": "(c->sf != c->of)", "ge": "(c->sf == c->of)",
    "le": "(c->zf || c->sf != c->of)", "g": "(!c->zf && c->sf == c->of)",
}


SSE_MNEMONICS = {"cvttss2si", "cvtss2si", "cvttsd2si", "cvtsd2si"}


FLAG_NAMES = ("CF", "ZF", "SF", "OF", "PF", "AF", "DF")
ALL_FLAGS = (1 << len(FLAG_NAMES)) - 1


def _mask(kinds):
    m = {}
    for bit, name in enumerate(FLAG_NAMES):
        v = 0
        for kind in kinds:
            v |= getattr(X, f"X86_EFLAGS_{kind}_{name}", 0)
        m[bit] = v
    return m


_DEF_BITS = _mask(("MODIFY", "RESET", "SET", "UNDEFINED"))
_USE_BITS = _mask(("TEST", "PRIOR"))
STATUS = 0b111111  # CF ZF SF OF PF AF

# Instructions whose capstone flag metadata is missing or incomplete.
MANUAL_DEFS = {"fcomi": STATUS, "fcomip": STATUS, "fucomi": STATUS, "fucomip": STATUS, "fcompi": STATUS,
               "fucompi": STATUS, "comiss": STATUS, "ucomiss": STATUS, "comisd": STATUS, "ucomisd": STATUS,
               "sahf": STATUS, "popfd": ALL_FLAGS, "cmpxchg8b": 0b10}
MANUAL_USES = {"lahf": STATUS, "pushfd": ALL_FLAGS}

# Architectural flag effects of the integer ALU, OR-ed into capstone's: capstone 5.0.7 reports no flags at all for
# some encodings (e.g. `test byte ptr [mem], r8`), which made liveness drop flags a following jcc reads.
_CF, _ZF, _SF, _OF, _PF, _AF = (1 << k for k in range(6))
for _m in ("add", "sub", "adc", "sbb", "cmp", "and", "or", "xor", "test", "neg", "cmpxchg", "xadd"):
    MANUAL_DEFS.setdefault(_m, STATUS)
for _m in ("inc", "dec"):
    MANUAL_DEFS.setdefault(_m, STATUS & ~_CF)
for _m in ("adc", "sbb", "rcl", "rcr", "cmc"):
    MANUAL_USES.setdefault(_m, _CF)
# Condition codes read by jcc/setcc/cmovcc, by suffix.
_COND_USES = {"o": _OF, "no": _OF, "b": _CF, "ae": _CF, "e": _ZF, "ne": _ZF, "be": _CF | _ZF, "a": _CF | _ZF,
              "s": _SF, "ns": _SF, "p": _PF, "np": _PF, "l": _SF | _OF, "ge": _SF | _OF,
              "le": _ZF | _SF | _OF, "g": _ZF | _SF | _OF}
for _cc, _u in _COND_USES.items():
    for _prefix in ("j", "set", "cmov"):
        MANUAL_USES.setdefault(_prefix + _cc, _u)


def flag_sets(ins):
    """(defs, uses) as bit sets over FLAG_NAMES."""
    base = ins.mnemonic.split()[-1]
    e = ins.eflags
    defs = sum(1 << b for b, m in _DEF_BITS.items() if e & m)
    uses = sum(1 << b for b, m in _USE_BITS.items() if e & m)
    defs |= MANUAL_DEFS.get(base, 0)
    uses |= MANUAL_USES.get(base, 0)
    return defs, uses


EXTRA_ENTRIES = set()  # filled by load_functions
THUNKS = set()  # thunk entries (functions.csv), filled by load_functions


def rebase(new_base):
    """Generates code for the engine loaded at `new_base` instead of its preferred base (the native host on Android,
    where ART owns 0x10000000): every address taken from the analysis moves by the same delta, and the image bytes
    get the DLL's base relocations applied (relocate_pe), exactly as the loader does at run time."""
    global BASE, SETJMP_TARGETS, SETJMP_IAT, LONGJMP_IAT, INLINE_HELPERS
    delta = new_base - ORIG_BASE
    BASE = new_base
    INLINE_HELPERS = {a + delta: k for a, k in INLINE_HELPERS.items()}
    SETJMP_TARGETS = {a + delta for a in SETJMP_TARGETS}
    SETJMP_IAT = {a + delta for a in SETJMP_IAT}
    LONGJMP_IAT = {a + delta for a in LONGJMP_IAT}


def relocate_pe(pe):
    if BASE != ORIG_BASE:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
        pe.relocate_image(BASE)


def load_all_starts():
    """Every entry in functions.csv, thunks included."""
    with open(FUNCTIONS_CSV) as f:
        next(f)
        return [int(row.split(",", 1)[0], 16) - ORIG_BASE + BASE for row in f]


class Unsupported(Exception):
    pass


def load_functions():
    """Non-thunk function entries -> decoding extent. Ghidra's size counts the addresses of the body, which can
    be smaller than its extent (e.g. a loop tail after the counted range), so a function may be decoded up to the
    next function entry (thunks included); decoding only follows control flow, so data in between is never read."""
    sizes = {}
    starts = []
    with open(FUNCTIONS_CSV) as f:
        next(f)
        for row in f:
            p = row.split(",")
            va = int(p[0], 16) - ORIG_BASE + BASE
            starts.append(va)
            sizes[va] = int(p[1])
            if p[2] != "false":
                # Ghidra's "thunks" include this-adjusting stubs (mov ecx, [..]; add ecx, n; jmp f): compiled like
                # any function, but left native by the in-process bridge (EXTRA_ENTRIES are not patched).
                THUNKS.add(va)
                EXTRA_ENTRIES.add(va)
    # Entries Ghidra missed (tools/recomp/data_entries.py): decoded up to the next entry like the others.
    extra_path = EXTRA_FUNCTIONS
    if os.path.exists(extra_path):
        known = set(starts)
        with open(extra_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    va = int(line, 16) - ORIG_BASE + BASE
                    if va not in known:
                        starts.append(va)
                        sizes[va] = 1
                        EXTRA_ENTRIES.add(va)
    starts.sort()
    import bisect
    ghidra_starts = sorted(set(load_all_starts()))
    extents = {}
    for va, size in sizes.items():
        # Missed entries are bounded by Ghidra's entries only: a false positive must not cut a real function.
        bound = ghidra_starts
        i = bisect.bisect_right(bound, va)
        nxt = bound[i] if i < len(bound) else va + size
        extents[va] = max(size, nxt - va)
    return extents



def inline_helper(kind, nxt):
    """C for an inlined MSVC helper, written as if the call had run (registers, stack pointer, x87 stack)."""
    probe = ("{ uint32_t n = c->eax, e = c->esp; uint32_t top = (e - 4u >= n) ? e - 4u - n : 0u; "
             f"c->esp = top + 4u; c->eax = 0x{nxt:08x}u; }}")
    if kind == "ftol2":
        return ("{ double v = X87(c, 0); X87Pop(c); int64_t r = (v != v || v >= 9223372036854775808.0 || "
                "v < -9223372036854775808.0) ? INT64_MIN : (int64_t)v; "
                "c->eax = (uint32_t)r; c->edx = (uint32_t)((uint64_t)r >> 32); }")
    if kind == "chkstk":
        return probe
    if kind in ("chkstk16", "chkstk8"):
        mask = 15 if kind == "chkstk16" else 7
        return (f"{{ uint32_t n0 = c->eax, m = (c->esp - n0) & {mask}u, n1 = n0 + m; c->eax = n1 < n0 ? 0xffffffffu : n1; "
                f"}} {probe}")
    if kind == "allmul":
        return ("{ uint32_t e = c->esp; uint64_t a = R32(e) | ((uint64_t)R32(e + 4u) << 32), "
                "b = R32(e + 8u) | ((uint64_t)R32(e + 12u) << 32), r = a * b; "
                "c->eax = (uint32_t)r; c->edx = (uint32_t)(r >> 32); c->ecx = R32(e + 8u); c->esp = e + 16u; }")
    if kind in ("allshl", "aullshr"):
        op = "<<" if kind == "allshl" else ">>"
        return ("{ uint32_t s = c->ecx & 0xffu; uint64_t v = ((uint64_t)c->edx << 32) | c->eax; "
                f"if (s >= 64u) v = 0; else {{ v {op}= s; if (s >= 32u) c->ecx = (c->ecx & ~0xffu) | (s & 0x1fu); }} "
                "c->eax = (uint32_t)v; c->edx = (uint32_t)(v >> 32); }")
    raise ValueError(kind)


# ---- spill only what changed (see apply_spills) ----
_GPRS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
_GPR_WRITE_RE = re.compile(r"\br_(eax|ecx|edx|ebx|esp|ebp|esi|edi)\s*(?:=(?!=)|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|\+\+|--)"
                           r"|&r_(eax|ecx|edx|ebx|esp|ebp|esi|edi)\b")
_XMM_WRITE_RE = re.compile(r"&r_xmm(\d)|\br_xmm(\d)(?:\.\w+(?:\[[^\]]*\])?)?\s*(?:=(?!=)|\+=|-=|\*=|/=|&=|\|=|\^=)")
_X87_WRITE_RE = re.compile(r"X87PushL|X87PopL|\br_top\s*=(?!=)|&r_top|\br_st\[[^\]]*\]\s*=(?!=)|X87L\([^)]*\)\s*=(?!=)")


def _writes(text, xmms, x87):
    w = set()
    for m in _GPR_WRITE_RE.finditer(text):
        w.add(m.group(1) or m.group(2))
    for m in _XMM_WRITE_RE.finditer(text):
        n = m.group(1) or m.group(2)
        if n in xmms:
            w.add("xmm" + n)
    if x87 and _X87_WRITE_RE.search(text):
        w.add("x87")
    return w


def _spill_expr(dirty, xmms, x87):
    parts = [f"c->{r} = r_{r}" for r in _GPRS if r in dirty]
    parts += [f"c->xmm[{n}] = r_xmm{n}" for n in xmms if "xmm" + n in dirty]
    if x87 and "x87" in dirty:
        parts += ["memcpy(c->st, r_st, sizeof r_st)", "c->st_top = r_top"]
    return "(" + ", ".join(parts) + ")" if parts else "((void)0)"


def _reload_expr(xmms, x87):
    # Everything: loads the function never uses again are dead and dropped by the C compiler. Flags are not
    # reloaded: they are undefined after a call.
    parts = [f"r_{r} = c->{r}" for r in _GPRS]
    parts += [f"r_xmm{n} = c->xmm[{n}]" for n in xmms]
    if x87:
        parts += ["memcpy(r_st, c->st, sizeof r_st)", "r_top = c->st_top", "r_cw = c->fpu_cw"]
    return "(" + ", ".join(parts) + ")"


def apply_spills(lines, xmms, x87, dirty_tracking=True):
    """Replaces RSPILL/RRELOAD in a localized body. With dirty tracking, a spill stores only the state changed
    since the last point where locals and context agreed (function entry, after a reload). The dirty set at a label
    is the union over every path reaching it (gotos and fall-through), iterated to a fixed point for loops. Flags
    are never spilled: x86 code does not keep them across calls or returns, and inside the function they live in rf."""
    everything = set(_GPRS) | {"xmm" + n for n in xmms} | ({"x87"} if x87 else set())
    if not dirty_tracking:
        return [_rewrite(l, xmms, x87, lambda pos: everything) if ("RSPILL" in l or "RRELOAD" in l) else l
                for l in lines]
    label_in = {}
    for _ in range(12):
        changed = False
        result = []
        dirty = set()
        for line in lines:
            if line.startswith("L_"):
                name = line[:line.index(":")]
                dirty = dirty | label_in.get(name, set())
                result.append(line)
                continue
            start = set(dirty)
            # gotos leaving this line: the state at the goto
            for m in re.finditer(r"goto (L_[0-9a-f]+);", line):
                d = start | _writes(line[:m.start()], xmms, x87)
                last = line.rfind("RRELOAD", 0, m.start())
                if last >= 0 and _unconditional(line[:m.start()]):
                    d = _writes(line[last:m.start()], xmms, x87)
                old = label_in.get(m.group(1), set())
                if not d <= old:
                    label_in[m.group(1)] = old | d
                    changed = True
            if "RSPILL" in line or "RRELOAD" in line:
                result.append(_rewrite(line, xmms, x87, lambda pos, l=line, st=start: st | _writes(l[:pos], xmms, x87)))
                last = line.rfind("RRELOAD")
                dirty = _writes(line[last:], xmms, x87) if last >= 0 and _unconditional(line) else \
                    start | _writes(line, xmms, x87)
            else:
                result.append(line)
                dirty = start | _writes(line, xmms, x87)
            # nothing falls through an unconditional exit
            tail = line.split("/*")[0].rstrip()
            if tail.endswith("return; }") and not tail.lstrip().startswith("if ") or \
                    re.match(r"^\s*goto L_[0-9a-f]+;\s*$", tail):
                dirty = set()
        if not changed:
            return result
    return [_rewrite(l, xmms, x87, lambda pos: everything) if ("RSPILL" in l or "RRELOAD" in l) else l
            for l in lines]


def _unconditional(text):
    """True when every path through `text` passes its last reload: a plain call statement, or the direct/dispatch
    call pair (both branches reload). Conditional exits and setjmp keep the state of paths that did not reload."""
    stripped = text.lstrip()
    if "setjmp" in text or stripped.startswith("if ("):
        return False
    if "else" not in text:
        return True
    return "if (RecompDirect(" in text and text.count("RRELOAD") == 2


def _rewrite(line, xmms, x87, dirty_at):
    pieces, pos = [], 0
    for m in re.finditer(r"RSPILL|RRELOAD", line):
        pieces.append(line[pos:m.start()])
        pieces.append(_spill_expr(dirty_at(m.start()), xmms, x87) if m.group(0) == "RSPILL"
                      else _reload_expr(xmms, x87))
        pos = m.end()
    pieces.append(line[pos:])
    return "".join(pieces)

# ---- register localization (see RLOCALS in runtime.h) ----
_REG_RE = re.compile(r"c->(eax|ecx|edx|ebx|esp|ebp|esi|edi)\b")
_FLAG_RE = re.compile(r"c->(cf|zf|sf|of|pf|df|af)\b")
# Flag helpers with a variant on the local RFlags copy.
_FLAG_CALLS = [("SubFlags(c, ", "SubFlagsL(&rf, "), ("AddFlags(c, ", "AddFlagsL(&rf, "),
               ("RECOMP_FLAGS_LOGIC(c, ", "RECOMP_FLAGS_LOGIC(&rf, "), ("RecompLahf(c)", "RecompLahfL(&rf)"),
               ("RecompSahf(c, ", "RecompSahfL(&rf, "), ("RecompEflags(c)", "RecompEflagsL(&rf)"),
               ("RecompSetEflags(c, ", "RecompSetEflagsL(&rf, "), ("X87CompareFlags(c, ", "X87CompareFlagsL(&rf, ")]
# Callees that read or write the general registers through the context: spill before, reload after.
_SPILL_CALL_RE = re.compile(r"\b(f_[0-9a-f]{8}|RecompDispatch|RecompUnimplemented|RecompCpuid|RecompLongjmp)\(c\b")


def _wrap_calls(line):
    out, pos = [], 0
    for m in _SPILL_CALL_RE.finditer(line):
        if m.start() < pos:
            continue
        depth, i = 0, m.end() - 2  # the opening parenthesis
        while i < len(line):
            if line[i] == "(":
                depth += 1
            elif line[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append(line[pos:m.start()])
        out.append(f"(RSPILL, {line[m.start():i + 1]}, RRELOAD)")
        pos = i + 1
    out.append(line[pos:])
    return "".join(out)


_XMM_RE = re.compile(r"c->xmm\[(\d)\]")
_STACK_ACCESS_RE = re.compile(r"\b(R8|R16|R32|R64|RF32|RF64|W8|W16|W32|W64|WF32|WF64)\(\(uint32_t\)\(r_esp(?: \+ 0x[0-9a-f]+u)?\)")
_X87_CALLS = [("X87Precision(c, ", "X87PrecisionCW(r_cw, "), ("c->fpu_cw = ", "r_cw = c->fpu_cw = "),
              ("X87(c, ", "X87L("), ("X87Push(c, ", "X87PushL(r_st, &r_top, "), ("X87Pop(c)", "X87PopL(&r_top)"),
              ("X87StatusWord(c)", "X87StatusWordL(c, r_top)"), ("c->st_top", "r_top"), ("c->st[", "r_st[")]


def vector_state(body):
    """XMM registers and x87 use of a function body: they get local copies too, spilled and reloaded with the
    general registers. Returns (declarations, spill expressions, reload expressions)."""
    xmms = sorted(set(_XMM_RE.findall(body)))
    x87 = any(k in body for k in ("X87(c, ", "X87Push(c, ", "X87Pop(c)", "X87StatusWord(c)", "c->st_top", "c->st[",
                                  "X87Precision(c, ", "c->fpu_cw = "))
    decl = [f"XmmValue r_xmm{n} = c->xmm[{n}];" for n in xmms]
    spill = [f"c->xmm[{n}] = r_xmm{n}" for n in xmms]
    reload = [f"r_xmm{n} = c->xmm[{n}]" for n in xmms]
    if x87:
        decl.append("double r_st[8]; memcpy(r_st, c->st, sizeof r_st); uint32_t r_top = c->st_top; "
                    "uint16_t r_cw = c->fpu_cw;")
        spill += ["memcpy(c->st, r_st, sizeof r_st)", "c->st_top = r_top"]  # r_cw is written through
        reload += ["memcpy(r_st, c->st, sizeof r_st)", "r_top = c->st_top", "r_cw = c->fpu_cw"]
    return decl, spill, reload, x87


def localize(line, x87=False):
    if "setjmp(" in line:
        # setjmp: the context must be current when the jmp_buf is prepared; after a longjmp the locals are stale and
        # RecompSetjmpResume has restored the context, so reload from it.
        line = line.replace("{ uint32_t jb = R32(c->esp); if", "{ uint32_t jb = R32(r_esp); RSPILL; if")
        line = line.replace("{ c->eax = 0; }", "{ r_eax = 0; }")  # setjmp's flags: spilled/reloaded with the rest
        line = line.replace("RecompSetjmpResume(c, R32(c->esp)); }", "RecompSetjmpResume(c, R32(c->esp)); RRELOAD; }")
        return line
    line = _REG_RE.sub(r"r_\1", line)
    line = _FLAG_RE.sub(r"rf.\1", line)
    line = _XMM_RE.sub(r"r_xmm\1", line)
    if x87:
        for old, new in _X87_CALLS:
            line = line.replace(old, new)
    for old, new in _FLAG_CALLS:
        line = line.replace(old, new)
    line = line.replace("Push32(c, ", "LPush32(&r_esp, ").replace("Pop32(c)", "LPop32(&r_esp)")
    # esp-relative memory is the thread's own stack: no TSO ordering needed.
    line = _STACK_ACCESS_RE.sub(lambda m: "S" + m.group(0), line)
    line = _wrap_calls(line)
    return re.sub(r"\breturn;", "{ RSPILL; return; }", line)


class FunctionCompiler:
    def __init__(self, md, pe, va, size, known_entries):
        self.md = md
        self.va = va
        self.size = size
        self.known = known_entries
        self.pe = pe
        self.code = pe.get_data(va - BASE, size)
        self.out = []
        self.unsupported = collections.Counter()
        self.table_targets = {}  # address of a computed jmp -> list of its table targets
        self.direct_calls = set()  # recompiled functions called directly (need a prototype in the output)
        self.unknown_targets = set()  # direct call/jump targets that are no known function entry
        self.ins = self.decode()

    # ---- operands ----
    def reg_get(self, name):
        if name in REG32:
            return f"c->{name}"
        if name in REG16:
            return f"(c->{REG16[name]} & 0xffffu)"
        if name in REG8L:
            return f"(c->{REG8L[name]} & 0xffu)"
        if name in REG8H:
            return f"((c->{REG8H[name]} >> 8) & 0xffu)"
        if name in SEGMENT_SELECTORS:
            return f"0x{SEGMENT_SELECTORS[name]:x}u"
        raise Unsupported(f"register {name}")

    def reg_set(self, name, value):
        if name in REG32:
            return f"c->{name} = (uint32_t)({value});"
        if name in REG16:
            r = REG16[name]
            return f"c->{r} = (c->{r} & 0xffff0000u) | ((uint32_t)({value}) & 0xffffu);"
        if name in REG8L:
            r = REG8L[name]
            return f"c->{r} = (c->{r} & 0xffffff00u) | ((uint32_t)({value}) & 0xffu);"
        if name in REG8H:
            r = REG8H[name]
            return f"c->{r} = (c->{r} & 0xffff00ffu) | (((uint32_t)({value}) & 0xffu) << 8);"
        raise Unsupported(f"register {name}")

    def address(self, ins, op):
        m = op.mem
        parts = []
        if m.segment == X.X86_REG_FS:
            parts.append("c->fs_base")
        elif m.segment not in (0, X.X86_REG_DS, X.X86_REG_SS, X.X86_REG_ES, X.X86_REG_CS):
            raise Unsupported(f"segment {ins.reg_name(m.segment)}")
        if m.base != 0:
            parts.append(self.reg_get(ins.reg_name(m.base)))
        if m.index != 0:
            parts.append(f"{self.reg_get(ins.reg_name(m.index))} * {m.scale}u")
        if m.disp or not parts:
            parts.append(f"0x{m.disp & 0xffffffff:x}u")
        return "(uint32_t)(" + " + ".join(parts) + ")"

    def read(self, ins, op, bits=None):
        bits = bits or op.size * 8
        if op.type == X.X86_OP_REG:
            return self.reg_get(ins.reg_name(op.reg))
        if op.type == X.X86_OP_IMM:
            return f"0x{op.imm & Mask(bits):x}u"
        if op.type == X.X86_OP_MEM:
            fn = {8: "R8", 16: "R16", 32: "R32"}.get(bits)
            if not fn:
                raise Unsupported(f"{bits}-bit memory read")
            return f"{fn}({self.address(ins, op)})"
        raise Unsupported("operand type")

    def write(self, ins, op, value, bits=None):
        bits = bits or op.size * 8
        if op.type == X.X86_OP_REG:
            return self.reg_set(ins.reg_name(op.reg), value)
        if op.type == X.X86_OP_MEM:
            fn = {8: "W8", 16: "W16", 32: "W32"}.get(bits)
            if not fn:
                raise Unsupported(f"{bits}-bit memory write")
            cast = {8: "uint8_t", 16: "uint16_t", 32: "uint32_t"}[bits]
            return f"{fn}({self.address(ins, op)}, ({cast})({value}));"
        raise Unsupported("write to non-lvalue")

    # ---- decoding (recursive descent from the entry point) ----
    def decode_one(self, addr):
        off = addr - self.va
        if off < 0 or off >= self.size:
            return None
        # An instruction starting inside the extent is decoded whole even if it ends past it (Ghidra's sizes can cut
        # through the last instruction).
        for i in self.md.disasm(self.pe.get_data(addr - BASE, 16), addr, count=1):
            return i
        return None

    def follow_jmp_thunks(self, t):
        """Final target of a chain of `jmp rel32` thunks (incremental-linking table)."""
        for _ in range(4):
            try:
                b = self.pe.get_data(t - BASE, 5)
            except Exception:
                return t
            if len(b) < 5 or b[0] != 0xE9:
                return t
            t = (t + 5 + int.from_bytes(b[1:5], "little", signed=True)) & 0xffffffff
        return t

    def jump_table(self, ins, recent=()):
        """Targets of `jmp dword ptr [reg*4 + table]`.

        With the switch's bound in view (`cmp reg, N` + `ja` before the jump) exactly N+1 entries are read, and
        MSVC's two-level form (`movzx reg, byte ptr [reg + index]` right before the jump) reads the byte index table
        first. Targets past the function's extent grow it: Ghidra sometimes splits a function at a case label.
        Without a bound, entries are read while they stay inside the function."""
        op = ins.operands[0]
        if op.type != X.X86_OP_MEM or op.mem.base != 0 or op.mem.index == 0 or op.mem.scale != 4:
            return None
        table = op.mem.disp & 0xffffffff
        reg = ins.reg_name(op.mem.index)
        bound = None
        byte_index = None
        for prev in reversed(recent[-8:]):
            ops = prev.operands
            if (prev.mnemonic == "movzx" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and
                    ins.reg_name(ops[0].reg) == reg and ops[1].type == X.X86_OP_MEM and ops[1].size == 1 and
                    ops[1].mem.index == 0 and ops[1].mem.base != 0):
                byte_index = (ops[1].mem.disp & 0xffffffff, ins.reg_name(ops[1].mem.base))
                reg = byte_index[1]
            elif (prev.mnemonic == "cmp" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and
                  ins.reg_name(ops[0].reg) == reg and ops[1].type == X.X86_OP_IMM):
                bound = (ops[1].imm & 0xffffffff) + 1
                break
        if bound is not None and bound <= 4096:
            if byte_index is not None:
                idx = self.pe.get_data(byte_index[0] - BASE, bound)
                count = max(idx) + 1
            else:
                count = bound
            targets = [int.from_bytes(self.pe.get_data(table - BASE + 4 * k, 4), "little") for k in range(count)]
            if all(self.text_lo <= t < self.text_hi for t in targets):
                end = max(targets) + 16
                if end > self.va + self.size:
                    self.size = end - self.va
                    self.code = self.pe.get_data(self.va - BASE, self.size)
                return targets
        targets = []
        for k in range(1024):
            try:
                entry = int.from_bytes(self.pe.get_data(table - BASE + 4 * k, 4), "little")
            except Exception:
                break
            if not self.inside(entry):
                break
            targets.append(entry)
        return targets or None

    def decode(self):
        decoded = {}
        work = [self.va]
        text = self.pe.sections[0]
        self.text_lo = BASE + text.VirtualAddress
        self.text_hi = self.text_lo + text.Misc_VirtualSize
        self.traps = set()  # addresses where decoding failed or hit int3: reaching them is a trap
        while work:
            addr = work.pop()
            recent = []  # the straight-line run leading here (switch bound detection)
            while addr not in decoded and addr not in self.traps:
                i = self.decode_one(addr)
                if i is None or i.mnemonic == "int3":
                    self.traps.add(addr)
                    break
                decoded[addr] = i
                recent.append(i)
                nxt = addr + i.size
                m = i.mnemonic
                if i.group(capstone.CS_GRP_JUMP):
                    op = i.operands[0] if i.operands else None
                    if op is not None and op.type == X.X86_OP_IMM:
                        if self.inside(op.imm):
                            work.append(op.imm)
                    elif m == "jmp":
                        table = self.jump_table(i, recent)
                        if table:
                            self.table_targets[addr] = table
                            work.extend(table)
                    if m == "jmp":
                        break
                    addr = nxt
                    continue
                if i.group(capstone.CS_GRP_RET) or m in ("ret", "hlt", "ud2"):
                    break
                addr = nxt
        return [decoded[a] for a in sorted(decoded)]

    # ---- control flow ----
    def targets(self):
        t = set()
        for i in self.ins:
            if i.group(capstone.CS_GRP_JUMP) and i.operands and i.operands[0].type == X.X86_OP_IMM:
                d = i.operands[0].imm
                if self.inside(d):
                    t.add(d)
        for table in self.table_targets.values():
            t.update(table)
        return t

    def inside(self, d):
        return self.va <= d < self.va + self.size

    def jump_to(self, d):
        if self.inside(d):
            return f"goto L_{d:08x};"
        if d in self.known:
            self.direct_calls.add(d)
            return f"if (RecompDirect(0x{d:08x}u)) f_{d:08x}(c); else RecompDispatch(c, 0x{d:08x}u); return;"
        self.unknown_targets.add(d)
        return f"RecompDispatch(c, 0x{d:08x}u); return;"

    # ---- instructions ----
    def emit(self, ins):
        m = ins.mnemonic
        ops = ins.operands
        nxt = ins.address + ins.size
        rep = X.X86_PREFIX_REP in ins.prefix or X.X86_PREFIX_REPE in ins.prefix
        repne = X.X86_PREFIX_REPNE in ins.prefix
        base = m.split()[-1]
        bits = ops[0].size * 8 if ops else 32
        if X.X86_PREFIX_LOCK in ins.prefix and base not in ("cmpxchg", "cmpxchg8b"):
            return self.locked_or_plain(ins, base)

        if base in ("nop", "int3", "prefetcht0", "prefetchnta", "wait", "emms"):
            # Hints and FPU/MMX state syncs have no effect on the emulated state; only int3 traps.
            return "/* " + m + " */" if base != "int3" else f'RecompUnimplemented(c, 0x{ins.address:08x}u, "int3"); return;'
        if base == "mov" or base == "movabs":
            return self.write(ins, ops[0], self.read(ins, ops[1], bits))
        if base in ("movzx", "movsx"):
            sb = ops[1].size * 8
            v = self.read(ins, ops[1], sb)
            if base == "movsx":
                v = f"(uint32_t)(int32_t)(int{sb}_t)({v})"
            return self.write(ins, ops[0], v)
        if base == "lea":
            return self.write(ins, ops[0], self.address(ins, ops[1]))
        if base == "push":
            if ops[0].type == X.X86_OP_IMM:
                return f"Push32(c, 0x{ops[0].imm & 0xffffffff:x}u);"
            return f"{{ uint32_t v = {self.read(ins, ops[0])}; Push32(c, v); }}"
        if base == "pop":
            return "{ uint32_t v = Pop32(c); " + self.write(ins, ops[0], "v") + " }"
        if base in ("add", "sub", "adc", "sbb", "cmp"):
            a = self.read(ins, ops[0], bits)
            b = self.read(ins, ops[1], bits)
            if ops[1].type == X.X86_OP_IMM:
                b = f"0x{ops[1].imm & Mask(bits):x}u"
            carry = "c->cf" if base in ("adc", "sbb") else "0"
            if self.flags_dead(ins):
                if base == "cmp":
                    return "/* cmp: flags dead */"
                sign = "+" if base in ("add", "adc") else "-"
                return self.write(ins, ops[0], f"({a} {sign} {b} {sign} {carry})")
            fn = "AddFlags" if base in ("add", "adc") else "SubFlags"
            expr = f"{fn}(c, {a}, {b}, {carry}, {bits})"
            if base == "cmp":
                return f"(void){expr};"
            return "{ uint32_t r = " + expr + "; " + self.write(ins, ops[0], "r") + " }"
        if base in ("and", "or", "xor", "test"):
            op = {"and": "&", "or": "|", "xor": "^", "test": "&"}[base]
            a = self.read(ins, ops[0], bits)
            b = self.read(ins, ops[1], bits)
            if ops[1].type == X.X86_OP_IMM:
                b = f"0x{ops[1].imm & Mask(bits):x}u"
            if self.flags_dead(ins):
                if base == "test":
                    return "/* test: flags dead */"
                return self.write(ins, ops[0], f"({a} {op} {b})")
            s = f"{{ uint32_t r = ({a} {op} {b}) & 0x{Mask(bits):x}u; RECOMP_FLAGS_LOGIC(c, r, {bits});"
            if base != "test":
                s += " " + self.write(ins, ops[0], "r")
            return s + " }"
        if base in ("inc", "dec") and self.flags_dead(ins):
            sign = "+" if base == "inc" else "-"
            return self.write(ins, ops[0], f"({self.read(ins, ops[0], bits)} {sign} 1u)")
        if base == "neg" and self.flags_dead(ins):
            return self.write(ins, ops[0], f"(0u - {self.read(ins, ops[0], bits)})")
        if base in ("inc", "dec"):
            a = self.read(ins, ops[0], bits)
            fn = "AddFlags" if base == "inc" else "SubFlags"
            return ("{ uint8_t cf = c->cf; uint32_t r = " + f"{fn}(c, {a}, 1u, 0, {bits}); c->cf = cf; "
                    + self.write(ins, ops[0], "r") + " }")
        if base == "neg":
            a = self.read(ins, ops[0], bits)
            return ("{ uint32_t r = " + f"SubFlags(c, 0u, {a}, 0, {bits}); " + self.write(ins, ops[0], "r") + " }")
        if base == "not":
            return self.write(ins, ops[0], f"~{self.read(ins, ops[0], bits)}")
        if base in ("shl", "sal", "shr", "sar") and self.flags_dead(ins):
            a = self.read(ins, ops[0], bits)
            n = self.read(ins, ops[1], 8) if len(ops) > 1 else "1u"
            if base in ("shl", "sal"):
                expr = f"(uint32_t)((uint64_t)a << n)"
            elif base == "shr":
                expr = "a >> n"
            else:
                expr = (f"(uint32_t)(n >= {bits} ? ((int32_t)(a << {32 - bits}) >> 31) : "
                        f"(((int32_t)(a << {32 - bits}) >> {32 - bits}) >> n))")
            return ("{ uint32_t n = (" + n + f") & 31u; uint32_t a = {a} & 0x{Mask(bits):x}u; if (n) {{ "
                    + self.write(ins, ops[0], expr) + " } }")
        if base in ("shl", "sal", "shr", "sar"):
            a = self.read(ins, ops[0], bits)
            n = self.read(ins, ops[1], 8) if len(ops) > 1 else "1u"
            sign = 1 << (bits - 1)
            body = f"uint32_t n = ({n}) & 31u; uint32_t a = {a} & 0x{Mask(bits):x}u; if (n) {{ uint32_t r; "
            if base in ("shl", "sal"):
                body += (f"r = (uint32_t)((uint64_t)a << n) & 0x{Mask(bits):x}u; c->cf = (uint32_t)(((uint64_t)a << n) "
                         f">> {bits}) & 1u; c->of = ((r >> {bits - 1}) & 1u) ^ c->cf; ")
            elif base == "shr":
                body += f"r = a >> n; c->cf = (a >> (n - 1)) & 1u; c->of = (a >> {bits - 1}) & 1u; "
            else:
                body += (f"int32_t sa = (int32_t)(a << {32 - bits}) >> {32 - bits}; r = (uint32_t)(n >= {bits} ? (sa >> "
                         f"{bits - 1}) : (sa >> n)) & 0x{Mask(bits):x}u; c->cf = (uint32_t)(sa >> (n > {bits} ? {bits - 1} : n - 1)) & 1u; c->of = 0; ")
            body += (f"c->zf = r == 0; c->sf = (r & 0x{sign:x}u) != 0; c->pf = Parity(r); "
                     + self.write(ins, ops[0], "r") + " }")
            return "{ " + body + " }"
        if base in ("rol", "ror"):
            a = self.read(ins, ops[0], bits)
            n = self.read(ins, ops[1], 8) if len(ops) > 1 else "1u"
            if base == "rol":
                expr = f"((a << n) | (a >> (({bits} - n) % {bits}))) & 0x{Mask(bits):x}u"
                cf = "r & 1u"
            else:
                expr = f"((a >> n) | (a << (({bits} - n) % {bits}))) & 0x{Mask(bits):x}u"
                cf = f"(r >> {bits - 1}) & 1u"
            return ("{ uint32_t n = (" + n + f") & 31u % {bits}; uint32_t a = {a} & 0x{Mask(bits):x}u; "
                    f"if (n) {{ uint32_t r = {expr}; c->cf = {cf}; " + self.write(ins, ops[0], "r") + " } }")
        if base == "imul":
            if len(ops) == 1:
                if bits == 8:
                    v = self.read(ins, ops[0])
                    return ("{ int32_t p = (int32_t)(int8_t)c->eax * (int8_t)" + v + "; "
                            "c->eax = (c->eax & 0xffff0000u) | ((uint32_t)p & 0xffffu); c->cf = c->of = p != (int8_t)p; }")
                if bits == 16:
                    v = self.read(ins, ops[0])
                    return ("{ int32_t p = (int32_t)(int16_t)c->eax * (int16_t)" + v + "; "
                            "c->eax = (c->eax & 0xffff0000u) | ((uint32_t)p & 0xffffu); "
                            "c->edx = (c->edx & 0xffff0000u) | (((uint32_t)p >> 16) & 0xffffu); c->cf = c->of = p != (int16_t)p; }")
                v = self.read(ins, ops[0])
                return ("{ int64_t p = (int64_t)(int32_t)c->eax * (int32_t)" + v + "; c->eax = (uint32_t)p; "
                        "c->edx = (uint32_t)((uint64_t)p >> 32); c->cf = c->of = p != (int64_t)(int32_t)p; }")
            a = self.read(ins, ops[1 if len(ops) == 3 else 0])
            b = f"0x{ops[2].imm & 0xffffffff:x}u" if len(ops) == 3 else self.read(ins, ops[1])
            if bits == 16:
                return ("{ int32_t p = (int32_t)(int16_t)" + a + " * (int16_t)" + b + "; uint32_t r = (uint32_t)p & 0xffffu; "
                        "c->cf = c->of = p != (int16_t)p; " + self.write(ins, ops[0], "r") + " }")
            return ("{ int64_t p = (int64_t)(int32_t)" + a + " * (int32_t)" + b + "; uint32_t r = (uint32_t)p; "
                    "c->cf = c->of = p != (int64_t)(int32_t)r; " + self.write(ins, ops[0], "r") + " }")
        if base == "mul":
            if bits != 32:
                raise Unsupported("mul r/m8/16")
            v = self.read(ins, ops[0])
            return ("{ uint64_t p = (uint64_t)c->eax * " + v + "; c->eax = (uint32_t)p; c->edx = (uint32_t)(p >> 32); "
                    "c->cf = c->of = c->edx != 0; }")
        if base in ("div", "idiv"):
            if bits != 32:
                raise Unsupported(f"{base} r/m8/16")
            v = self.read(ins, ops[0])
            if base == "div":
                return ("{ uint64_t n = ((uint64_t)c->edx << 32) | c->eax; uint32_t d = " + v + "; "
                        "c->eax = (uint32_t)(n / d); c->edx = (uint32_t)(n % d); }")
            return ("{ int64_t n = (int64_t)(((uint64_t)c->edx << 32) | c->eax); int32_t d = (int32_t)" + v + "; "
                    "c->eax = (uint32_t)(int32_t)(n / d); c->edx = (uint32_t)(int32_t)(n % d); }")
        if base == "cdq":
            return "c->edx = (c->eax & 0x80000000u) ? 0xffffffffu : 0u;"
        if base == "xchg":
            a, b = self.read(ins, ops[0]), self.read(ins, ops[1])
            return "{ uint32_t a = " + a + ", b = " + b + "; " + self.write(ins, ops[0], "b") + " " + self.write(ins, ops[1], "a") + " }"
        if base.startswith("set") and base[3:] in COND:
            return self.write(ins, ops[0], f"({COND[base[3:]]}) ? 1u : 0u", 8)
        if base.startswith("cmov") and base[4:] in COND:
            return f"if ({COND[base[4:]]}) {{ " + self.write(ins, ops[0], self.read(ins, ops[1])) + " }"
        if base.startswith("j") and base != "jmp" and base[1:] in COND:
            return f"if ({COND[base[1:]]}) {{ {self.jump_to(ops[0].imm)} }}"
        if base in ("jecxz",):
            return f"if (c->ecx == 0) {{ {self.jump_to(ops[0].imm)} }}"
        if base == "jmp":
            if ops[0].type == X.X86_OP_IMM:
                return self.jump_to(ops[0].imm)
            target = self.read(ins, ops[0])
            table = self.table_targets.get(ins.address)
            if table:
                cases = " ".join(f"case 0x{d:08x}u: goto L_{d:08x};" for d in sorted(set(table)))
                return f"{{ uint32_t t = {target}; switch (t) {{ {cases} default: RecompDispatch(c, t); return; }} }}"
            # Computed jump without a recognised table: a tail call through the pointer.
            return f"{{ uint32_t t = {target}; RecompDispatch(c, t); return; }}"
        if base == "call":
            op = ops[0]
            is_iat = op.type == X.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0
            if (op.type == X.X86_OP_IMM and op.imm in SETJMP_TARGETS) or (is_iat and (op.mem.disp & 0xffffffff) in SETJMP_IAT):
                return ("{ uint32_t jb = R32(c->esp); if (setjmp(*RecompSetjmpPrepare(c, jb)) == 0) { c->eax = 0; } "
                        "else { RecompSetjmpResume(c, R32(c->esp)); } }")
            if is_iat and (op.mem.disp & 0xffffffff) in LONGJMP_IAT:
                return "RecompLongjmp(c, R32(c->esp), R32(c->esp + 4u));"
            if ops[0].type == X.X86_OP_IMM:
                t = ops[0].imm & 0xffffffff
                final = self.follow_jmp_thunks(t)
                if final in INLINE_HELPERS:
                    return inline_helper(INLINE_HELPERS[final], nxt)
                if t in self.known:
                    self.direct_calls.add(t)
                    return (f"Push32(c, 0x{nxt:08x}u); if (RecompDirect(0x{t:08x}u)) f_{t:08x}(c); "
                            f"else RecompDispatch(c, 0x{t:08x}u);")
                self.unknown_targets.add(t)
                return f"Push32(c, 0x{nxt:08x}u); RecompDispatch(c, 0x{t:08x}u);"
            return f"{{ uint32_t t = {self.read(ins, ops[0])}; Push32(c, 0x{nxt:08x}u); RecompDispatch(c, t); }}"
        if base == "ret":
            n = ops[0].imm if ops else 0
            return f"c->ret_target = Pop32(c); c->esp += {n}u; return;"
        if base == "leave":
            return "c->esp = c->ebp; c->ebp = Pop32(c);"
        if base in ("movsd", "movsb", "movsw", "stosd", "stosb", "stosw") and not ops_are_xmm(ins):
            width = {"d": 4, "b": 1, "w": 2}[base[-1]]
            rd, wr = {4: ("R32", "W32"), 1: ("R8", "W8"), 2: ("R16", "W16")}[width]
            step = f"(c->df ? -{width} : {width})"
            if base.startswith("movs"):
                one = f"{wr}(c->edi, {rd}(c->esi)); c->esi += {step}; c->edi += {step};"
            else:
                val = {4: "c->eax", 1: "(uint8_t)c->eax", 2: "(uint16_t)c->eax"}[width]
                one = f"{wr}(c->edi, {val}); c->edi += {step};"
            if rep:
                return f"while (c->ecx) {{ {one} c->ecx--; }}"
            return one
        if base in ("cmpsb", "cmpsd", "cmpsw", "scasb", "scasd"):
            width = {"b": 1, "d": 4, "w": 2}[base[-1]]
            rd = {4: "R32", 1: "R8", 2: "R16"}[width]
            step = f"(c->df ? -{width} : {width})"
            if base.startswith("cmps"):
                one = f"(void)SubFlags(c, {rd}(c->esi), {rd}(c->edi), 0, {width * 8}); c->esi += {step}; c->edi += {step};"
            else:
                one = f"(void)SubFlags(c, c->eax, {rd}(c->edi), 0, {width * 8}); c->edi += {step};"
            if rep:
                return f"while (c->ecx) {{ {one} c->ecx--; if (!c->zf) break; }}"
            if repne:
                return f"while (c->ecx) {{ {one} c->ecx--; if (c->zf) break; }}"
            return one
        if base == "cmpxchg":
            if bits != 32:
                raise Unsupported("cmpxchg 8/16")
            if ops[0].type == X.X86_OP_MEM:
                addr = self.address(ins, ops[0])
                src = self.read(ins, ops[1])
                return ("{ uint32_t expected = c->eax; uint32_t* p = (uint32_t*)G(" + addr + "); "
                        "uint32_t old = __sync_val_compare_and_swap(p, expected, " + src + "); "
                        "(void)SubFlags(c, expected, old, 0, 32); if (!c->zf) c->eax = old; }")
            raise Unsupported("cmpxchg reg")
        if base == "cld":
            return "c->df = 0;"
        if base == "std":
            return "c->df = 1;"
        # ---- SSE ----
        if ops_are_xmm(ins) or base in SSE_MNEMONICS:
            return self.sse(ins, base)
        # ---- x87 ----
        if base.startswith("f") or base in ("lahf", "sahf"):
            return self.x87(ins, base)
        # ---- remaining integer instructions ----
        if base in ("shld", "shrd"):
            a = self.read(ins, ops[0])
            b = self.read(ins, ops[1])
            n = self.read(ins, ops[2], 8)
            if base == "shld":
                expr = "(uint32_t)((((uint64_t)a << 32) | b) << n >> 32)"
                cf = "(a >> (32 - n)) & 1u"
            else:
                expr = "(uint32_t)((((uint64_t)b << 32) | a) >> n)"
                cf = "(a >> (n - 1)) & 1u"
            return ("{ uint32_t a = " + a + ", b = " + b + ", n = (" + n + ") & 31u; if (n) { uint32_t r = " + expr
                    + "; c->cf = " + cf + "; c->zf = r == 0; c->sf = r >> 31; c->pf = Parity(r); "
                    + self.write(ins, ops[0], "r") + " } }")
        if base in ("rcr", "rcl"):
            a = self.read(ins, ops[0], bits)
            n = self.read(ins, ops[1], 8) if len(ops) > 1 else "1u"
            step = ("{ uint32_t out = v & 1u; v = (v >> 1) | ((uint32_t)c->cf << " + str(bits - 1) + "); c->cf = out; }"
                    if base == "rcr" else
                    "{ uint32_t out = (v >> " + str(bits - 1) + ") & 1u; v = ((v << 1) | c->cf) & 0x" + f"{Mask(bits):x}" + "u; c->cf = out; }")
            return ("{ uint32_t v = " + a + " & 0x" + f"{Mask(bits):x}" + "u; uint32_t n = (" + n + ") & 31u; "
                    "while (n--) " + step + " " + self.write(ins, ops[0], "v") + " }")
        if base in ("bsr", "bsf"):
            v = self.read(ins, ops[1])
            fn = "31u - (uint32_t)__builtin_clz(v)" if base == "bsr" else "(uint32_t)__builtin_ctz(v)"
            return "{ uint32_t v = " + v + "; c->zf = v == 0; if (v) { " + self.write(ins, ops[0], fn) + " } }"
        if base in ("bt", "bts", "btr", "btc"):
            if ops[0].type == X.X86_OP_MEM and ops[1].type == X.X86_OP_REG:
                raise Unsupported(f"{base} memory with register offset")
            v = self.read(ins, ops[0], bits)
            n = self.read(ins, ops[1], bits)
            s = "{ uint32_t v = " + v + "; uint32_t n = (" + n + ") & " + str(bits - 1) + "u; c->cf = (v >> n) & 1u; "
            if base != "bt":
                op = {"bts": "v | (1u << n)", "btr": "v & ~(1u << n)", "btc": "v ^ (1u << n)"}[base]
                s += self.write(ins, ops[0], op) + " "
            return s + "}"
        if base == "xadd":
            return self.locked_or_plain(ins, "xadd")
        if base == "cmpxchg8b":
            a = self.address(ins, ops[0])
            return ("{ uint64_t expected = ((uint64_t)c->edx << 32) | c->eax; uint64_t desired = ((uint64_t)c->ecx << 32) | c->ebx; "
                    "uint64_t old = __sync_val_compare_and_swap((uint64_t*)G(" + a + "), expected, desired); "
                    "c->zf = old == expected; if (!c->zf) { c->eax = (uint32_t)old; c->edx = (uint32_t)(old >> 32); } }")
        if base == "pushfd":
            return "Push32(c, RecompEflags(c));"
        if base == "popfd":
            return "RecompSetEflags(c, Pop32(c));"
        if base == "cpuid":
            return "RecompCpuid(c);"
        if base == "in":
            return f'RecompUnimplemented(c, 0x{ins.address:08x}u, "port input"); return;'
        if base == "cwde":
            return "c->eax = (uint32_t)(int32_t)(int16_t)c->eax;"
        if base == "cbw":
            return "c->eax = (c->eax & 0xffff0000u) | (uint16_t)(int16_t)(int8_t)c->eax;"
        if base == "cwd":
            return "c->edx = (c->edx & 0xffff0000u) | ((c->eax & 0x8000u) ? 0xffffu : 0u);"
        if base == "sahf":
            return self.x87(ins, base)
        if base == "bswap":
            return self.write(ins, ops[0], f"__builtin_bswap32({self.read(ins, ops[0])})")
        raise Unsupported(m)

    def locked_or_plain(self, ins, base):
        """Read-modify-write with a lock prefix (atomic on the host) or without it."""
        ops = ins.operands
        bits = ops[0].size * 8
        if bits != 32 or ops[0].type != X.X86_OP_MEM:
            if base == "xadd" and ops[0].type == X.X86_OP_REG:
                a, b = self.read(ins, ops[0]), self.read(ins, ops[1])
                return ("{ uint32_t a = " + a + ", b = " + b + "; uint32_t r = AddFlags(c, a, b, 0, 32); "
                        + self.write(ins, ops[1], "a") + " " + self.write(ins, ops[0], "r") + " }")
            raise Unsupported(f"lock {base} {bits}-bit")
        p = f"(uint32_t*)G({self.address(ins, ops[0])})"
        if base == "xadd":
            src = self.read(ins, ops[1])
            return ("{ uint32_t b = " + src + "; uint32_t old = __sync_fetch_and_add(" + p + ", b); "
                    "(void)AddFlags(c, old, b, 0, 32); " + self.write(ins, ops[1], "old") + " }")
        if base in ("inc", "dec"):
            fn = "__sync_fetch_and_add" if base == "inc" else "__sync_fetch_and_sub"
            flags = "AddFlags" if base == "inc" else "SubFlags"
            return ("{ uint8_t cf = c->cf; uint32_t old = " + fn + "(" + p + ", 1u); (void)" + flags
                    + "(c, old, 1u, 0, 32); c->cf = cf; }")
        if base in ("add", "sub"):
            v = self.read(ins, ops[1], 32)
            fn = "__sync_fetch_and_add" if base == "add" else "__sync_fetch_and_sub"
            flags = "AddFlags" if base == "add" else "SubFlags"
            return "{ uint32_t b = " + v + "; uint32_t old = " + fn + "(" + p + ", b); (void)" + flags + "(c, old, b, 0, 32); }"
        if base in ("or", "and", "xor"):
            v = self.read(ins, ops[1], 32)
            fn = {"or": "__sync_fetch_and_or", "and": "__sync_fetch_and_and", "xor": "__sync_fetch_and_xor"}[base]
            op = {"or": "|", "and": "&", "xor": "^"}[base]
            return ("{ uint32_t b = " + v + "; uint32_t old = " + fn + "(" + p + ", b); uint32_t r = old " + op
                    + " b; RECOMP_FLAGS_LOGIC(c, r, 32); }")
        if base == "xchg":
            v = self.read(ins, ops[1], 32)
            return "{ uint32_t old = __sync_lock_test_and_set(" + p + ", " + v + "); " + self.write(ins, ops[1], "old") + " }"
        raise Unsupported(f"lock {base}")

    # ---- SSE ----
    def xmm(self, ins, op):
        name = ins.reg_name(op.reg)
        if not name.startswith("xmm"):
            raise Unsupported(f"register {name}")
        return f"c->xmm[{int(name[3:])}]"

    def is_xmm(self, ins, op):
        return op.type == X.X86_OP_REG and ins.reg_name(op.reg).startswith("xmm")

    def v128(self, ins, op):
        """128-bit source as an XmmValue expression."""
        if self.is_xmm(ins, op):
            return self.xmm(ins, op)
        if op.type == X.X86_OP_MEM:
            return f"RecompLoad128({self.address(ins, op)})"
        raise Unsupported("128-bit source")

    def f32(self, ins, op):
        if op.type == X.X86_OP_MEM:
            return f"RF32({self.address(ins, op)})"
        return f"{self.xmm(ins, op)}.f[0]"

    def f64(self, ins, op):
        if op.type == X.X86_OP_MEM:
            return f"RF64({self.address(ins, op)})"
        return f"{self.xmm(ins, op)}.d[0]"

    def sse(self, ins, base):
        ops = ins.operands
        d = ops[0]
        s = ops[1] if len(ops) > 1 else None
        # ---- moves ----
        if base in ("movaps", "movups", "movdqa", "movdqu", "movapd", "movupd"):
            if d.type == X.X86_OP_MEM:
                return f"RecompStore128({self.address(ins, d)}, {self.xmm(ins, s)});"
            return f"{self.xmm(ins, d)} = {self.v128(ins, s)};"
        if base == "movss":
            if self.is_xmm(ins, d) and s.type == X.X86_OP_MEM:
                return f"{{ XmmValue* x = &{self.xmm(ins, d)}; x->f[0] = RF32({self.address(ins, s)}); x->u32[1] = x->u32[2] = x->u32[3] = 0; }}"
            if d.type == X.X86_OP_MEM:
                return f"WF32({self.address(ins, d)}, {self.xmm(ins, s)}.f[0]);"
            return f"{self.xmm(ins, d)}.f[0] = {self.xmm(ins, s)}.f[0];"
        if base == "movsd":  # SSE2 scalar double (the string form never has xmm operands)
            if self.is_xmm(ins, d) and s.type == X.X86_OP_MEM:
                return f"{{ XmmValue* x = &{self.xmm(ins, d)}; x->d[0] = RF64({self.address(ins, s)}); x->u64[1] = 0; }}"
            if d.type == X.X86_OP_MEM:
                return f"WF64({self.address(ins, d)}, {self.xmm(ins, s)}.d[0]);"
            return f"{self.xmm(ins, d)}.d[0] = {self.xmm(ins, s)}.d[0];"
        if base in ("movd", "movq"):
            if self.is_xmm(ins, d):
                if s.type == X.X86_OP_MEM:
                    v = f"R64({self.address(ins, s)})" if base == "movq" else f"R32({self.address(ins, s)})"
                elif self.is_xmm(ins, s):
                    v = f"{self.xmm(ins, s)}.u64[0]"
                else:
                    v = self.read(ins, s, 32)
                return f"{{ XmmValue* x = &{self.xmm(ins, d)}; x->u64[0] = {v}; x->u64[1] = 0; }}"
            if d.type == X.X86_OP_MEM:
                if base == "movq":
                    return f"W64({self.address(ins, d)}, {self.xmm(ins, s)}.u64[0]);"
                return f"W32({self.address(ins, d)}, {self.xmm(ins, s)}.u32[0]);"
            return self.write(ins, d, f"{self.xmm(ins, s)}.u32[0]", 32)
        if base in ("movlps", "movhps", "movlpd", "movhpd"):
            lane = 0 if base in ("movlps", "movlpd") else 1
            if d.type == X.X86_OP_MEM:
                return f"W64({self.address(ins, d)}, {self.xmm(ins, s)}.u64[{lane}]);"
            return f"{self.xmm(ins, d)}.u64[{lane}] = R64({self.address(ins, s)});"
        if base == "movhlps":
            return f"{self.xmm(ins, d)}.u64[0] = {self.xmm(ins, s)}.u64[1];"
        if base == "movlhps":
            return f"{self.xmm(ins, d)}.u64[1] = {self.xmm(ins, s)}.u64[0];"
        if base == "movmskps":
            x = self.xmm(ins, s)
            return self.write(ins, d, f"(({x}.u32[0] >> 31) | (({x}.u32[1] >> 31) << 1) | (({x}.u32[2] >> 31) << 2) | (({x}.u32[3] >> 31) << 3))", 32)
        # ---- packed float arithmetic ----
        packed = {"addps": "+", "subps": "-", "mulps": "*", "divps": "/"}
        if base in packed:
            return (f"{{ XmmValue b = {self.v128(ins, s)}; XmmValue* a = &{self.xmm(ins, d)}; for (int k = 0; k < 4; ++k) "
                    f"a->f[k] = a->f[k] {packed[base]} b.f[k]; }}")
        if base in ("minps", "maxps"):
            cmp = "<" if base == "minps" else ">"
            return (f"{{ XmmValue b = {self.v128(ins, s)}; XmmValue* a = &{self.xmm(ins, d)}; for (int k = 0; k < 4; ++k) "
                    f"a->f[k] = (a->f[k] {cmp} b.f[k]) ? a->f[k] : b.f[k]; }}")
        if base == "sqrtps":
            return (f"{{ XmmValue b = {self.v128(ins, s)}; XmmValue* a = &{self.xmm(ins, d)}; for (int k = 0; k < 4; ++k) "
                    f"a->f[k] = sqrtf(b.f[k]); }}")
        scalar = {"addss": "+", "subss": "-", "mulss": "*", "divss": "/"}
        if base in scalar:
            dst = f"{self.xmm(ins, d)}.f[0]"
            return f"{dst} = {dst} {scalar[base]} {self.f32(ins, s)};"
        scalar_d = {"addsd": "+", "subsd": "-", "mulsd": "*", "divsd": "/"}
        if base in scalar_d:
            dst = f"{self.xmm(ins, d)}.d[0]"
            return f"{dst} = {dst} {scalar_d[base]} {self.f64(ins, s)};"
        if base in ("minss", "maxss"):
            dst = f"{self.xmm(ins, d)}.f[0]"
            cmp = "<" if base == "minss" else ">"
            return f"{{ float b = {self.f32(ins, s)}; {dst} = ({dst} {cmp} b) ? {dst} : b; }}"
        if base == "sqrtss":
            return f"{self.xmm(ins, d)}.f[0] = sqrtf({self.f32(ins, s)});"
        if base == "sqrtsd":
            return f"{self.xmm(ins, d)}.d[0] = sqrt({self.f64(ins, s)});"
        # ---- bitwise ----
        bitwise = {"andps": "a & b", "andpd": "a & b", "pand": "a & b", "orps": "a | b", "orpd": "a | b", "por": "a | b",
                   "xorps": "a ^ b", "xorpd": "a ^ b", "pxor": "a ^ b", "andnps": "~a & b", "andnpd": "~a & b",
                   "pandn": "~a & b"}
        if base in bitwise:
            expr = bitwise[base]
            return (f"{{ XmmValue bv = {self.v128(ins, s)}; XmmValue* av = &{self.xmm(ins, d)}; for (int k = 0; k < 2; ++k) "
                    f"{{ uint64_t a = av->u64[k], b = bv.u64[k]; av->u64[k] = {expr}; }} }}")
        # ---- compares ----
        preds = {"eq": "a == b", "lt": "a < b", "le": "a <= b", "unord": "a != a || b != b", "neq": "!(a == b)",
                 "nlt": "!(a < b)", "nle": "!(a <= b)", "ord": "a == a && b == b"}
        if base.startswith("cmp") and base.endswith("ps") and base[3:-2] in preds:
            expr = preds[base[3:-2]]
            return (f"{{ XmmValue bv = {self.v128(ins, s)}; XmmValue* av = &{self.xmm(ins, d)}; for (int k = 0; k < 4; ++k) "
                    f"{{ float a = av->f[k], b = bv.f[k]; av->u32[k] = ({expr}) ? 0xffffffffu : 0u; }} }}")
        if base.startswith("cmp") and base.endswith("ss") and base[3:-2] in preds:
            expr = preds[base[3:-2]]
            return (f"{{ float a = {self.xmm(ins, d)}.f[0], b = {self.f32(ins, s)}; "
                    f"{self.xmm(ins, d)}.u32[0] = ({expr}) ? 0xffffffffu : 0u; }}")
        if base in ("comiss", "ucomiss", "comisd", "ucomisd"):
            if base.endswith("ss"):
                a, b, t = f"{self.xmm(ins, d)}.f[0]", self.f32(ins, s), "float"
            else:
                a, b, t = f"{self.xmm(ins, d)}.d[0]", self.f64(ins, s), "double"
            return (f"{{ {t} a = {a}, b = {b}; int un = a != a || b != b; c->zf = un || a == b; c->pf = un; "
                    f"c->cf = un || a < b; c->of = c->sf = 0; }}")
        # ---- shuffles ----
        if base == "shufps":
            imm = ops[2].imm & 0xff
            src = self.v128(ins, s)
            return (f"{{ XmmValue a = {self.xmm(ins, d)}, b = {src}; XmmValue* r = &{self.xmm(ins, d)}; "
                    f"r->f[0] = a.f[{imm & 3}]; r->f[1] = a.f[{(imm >> 2) & 3}]; r->f[2] = b.f[{(imm >> 4) & 3}]; "
                    f"r->f[3] = b.f[{(imm >> 6) & 3}]; }}")
        if base in ("unpcklps", "unpckhps"):
            lo = 0 if base == "unpcklps" else 2
            return (f"{{ XmmValue a = {self.xmm(ins, d)}, b = {self.v128(ins, s)}; XmmValue* r = &{self.xmm(ins, d)}; "
                    f"r->f[0] = a.f[{lo}]; r->f[1] = b.f[{lo}]; r->f[2] = a.f[{lo + 1}]; r->f[3] = b.f[{lo + 1}]; }}")
        if base == "pshufd":
            imm = ops[2].imm & 0xff
            return (f"{{ XmmValue a = {self.v128(ins, s)}; XmmValue* r = &{self.xmm(ins, d)}; "
                    f"r->u32[0] = a.u32[{imm & 3}]; r->u32[1] = a.u32[{(imm >> 2) & 3}]; r->u32[2] = a.u32[{(imm >> 4) & 3}]; "
                    f"r->u32[3] = a.u32[{(imm >> 6) & 3}]; }}")
        # ---- conversions ----
        if base == "cvtsi2ss":
            return f"{self.xmm(ins, d)}.f[0] = (float)(int32_t){self.read(ins, s, 32)};"
        if base == "cvtsi2sd":
            return f"{self.xmm(ins, d)}.d[0] = (double)(int32_t){self.read(ins, s, 32)};"
        if base == "cvttss2si":
            return self.write(ins, d, f"(uint32_t)RecompTruncF32({self.f32(ins, s)})")
        if base == "cvtss2si":
            return self.write(ins, d, f"(uint32_t)RecompRoundToInt((double){self.f32(ins, s)})")
        if base == "cvttsd2si":
            return self.write(ins, d, f"(uint32_t)RecompTruncF64({self.f64(ins, s)})")
        if base == "cvtss2sd":
            return f"{self.xmm(ins, d)}.d[0] = (double){self.f32(ins, s)};"
        if base == "cvtsd2ss":
            return f"{self.xmm(ins, d)}.f[0] = (float){self.f64(ins, s)};"
        if base == "cvttps2dq":
            return (f"{{ XmmValue a = {self.v128(ins, s)}; XmmValue* r = &{self.xmm(ins, d)}; for (int k = 0; k < 4; ++k) "
                    f"r->u32[k] = (uint32_t)RecompTruncF32(a.f[k]); }}")
        if base == "cvtdq2ps":
            return (f"{{ XmmValue a = {self.v128(ins, s)}; XmmValue* r = &{self.xmm(ins, d)}; for (int k = 0; k < 4; ++k) "
                    f"r->f[k] = (float)(int32_t)a.u32[k]; }}")
        raise Unsupported(base)

    # ---- x87 (double-precision model with control/status words) ----
    def sti(self, ins, op):
        name = ins.reg_name(op.reg)
        if name in ("st(0)", "st0"):
            return 0
        if name.startswith("st(") and name.endswith(")"):
            return int(name[3:-1])
        if name.startswith("st") and name[2:].isdigit():
            return int(name[2:])
        raise Unsupported(f"x87 register {name}")

    def x87(self, ins, base):
        ops = ins.operands
        st = lambda i: f"X87(c, {i})"
        if base == "lahf":
            return "c->eax = (c->eax & 0xffff00ffu) | ((uint32_t)RecompLahf(c) << 8);"
        if base == "sahf":
            return "RecompSahf(c, (uint8_t)(c->eax >> 8));"
        if base in ("fnstsw", "fstsw"):
            if ops and ops[0].type == X.X86_OP_MEM:
                return f"W16({self.address(ins, ops[0])}, X87StatusWord(c));"
            return "c->eax = (c->eax & 0xffff0000u) | X87StatusWord(c);"
        if base in ("fnstcw", "fstcw"):
            return f"W16({self.address(ins, ops[0])}, c->fpu_cw);"
        if base == "fldcw":
            return f"c->fpu_cw = R16({self.address(ins, ops[0])});"
        if base in ("fninit", "finit"):
            return "X87Init(c);"
        if base in ("fnclex", "fclex"):
            return "c->fpu_sw &= 0x7f00u;"
        consts = {"fldz": "0.0", "fld1": "1.0", "fldpi": "3.14159265358979323846", "fldl2e": "1.44269504088896340736",
                  "fldl2t": "3.32192809488736234787", "fldlg2": "0.30102999566398119521", "fldln2": "0.69314718055994530942"}
        if base in consts:
            return f"X87Push(c, {consts[base]});"
        if base in ("fld", "fild"):
            op = ops[0]
            if op.type == X.X86_OP_REG:
                return f"X87Push(c, {st(self.sti(ins, op))});"
            a = self.address(ins, op)
            if base == "fild":
                v = {2: f"(double)(int16_t)R16({a})", 4: f"(double)(int32_t)R32({a})", 8: f"(double)(int64_t)R64({a})"}[op.size]
            else:
                v = {4: f"(double)RF32({a})", 8: f"RF64({a})", 10: f"RecompLoadF80({a})"}.get(op.size)
            return f"X87Push(c, {v});"
        if base in ("fst", "fstp", "fist", "fistp"):
            op = ops[0]
            pop = " X87Pop(c);" if base.endswith("p") else ""
            if op.type == X.X86_OP_REG:
                return f"{st(self.sti(ins, op))} = {st(0)};{pop}"
            a = self.address(ins, op)
            if base.startswith("fist"):
                w = {2: f"W16({a}, (uint16_t)X87ToInt16(c, {st(0)}))", 4: f"W32({a}, (uint32_t)X87ToInt32(c, {st(0)}))",
                     8: f"W64({a}, (uint64_t)X87ToInt64(c, {st(0)}))"}[op.size]
            else:
                w = {4: f"WF32({a}, (float){st(0)})", 8: f"WF64({a}, {st(0)})", 10: f"RecompStoreF80({a}, {st(0)})"}[op.size]
            return f"{w};{pop}"
        if base == "fxch":
            i = self.sti(ins, ops[0]) if ops else 1
            if ops and len(ops) == 2:
                i = self.sti(ins, ops[1]) if self.sti(ins, ops[0]) == 0 else self.sti(ins, ops[0])
            return f"{{ double t = {st(0)}; {st(0)} = {st(i)}; {st(i)} = t; }}"
        unary = {"fchs": "-v", "fabs": "fabs(v)", "fsqrt": "sqrt(v)", "fsin": "sin(v)", "fcos": "cos(v)",
                 "f2xm1": "exp2(v) - 1.0", "frndint": "X87RoundRC(c, v)"}
        if base in unary:
            return f"{{ double v = {st(0)}; {st(0)} = X87Precision(c, {unary[base]}); }}"
        if base == "fsincos":
            return f"{{ double v = {st(0)}; {st(0)} = X87Precision(c, sin(v)); X87Push(c, X87Precision(c, cos(v))); }}"
        if base == "fptan":
            return f"{{ {st(0)} = X87Precision(c, tan({st(0)})); X87Push(c, 1.0); }}"
        if base == "fpatan":
            return f"{{ {st(1)} = X87Precision(c, atan2({st(1)}, {st(0)})); X87Pop(c); }}"
        if base == "fyl2x":
            return f"{{ {st(1)} = X87Precision(c, {st(1)} * log2({st(0)})); X87Pop(c); }}"
        if base == "fscale":
            return f"{{ {st(0)} = X87Precision(c, ldexp({st(0)}, (int)trunc({st(1)}))); }}"
        # ---- comparisons ----
        if base in ("fcomi", "fcomip", "fucomi", "fucomip", "fcompi", "fucompi"):
            i = self.sti(ins, ops[-1]) if ops else 1
            pop = " X87Pop(c);" if base.endswith("p") or base.endswith("pi") else ""
            return f"X87CompareFlags(c, {st(0)}, {st(i)});{pop}"
        if base in ("fcom", "fcomp", "fucom", "fucomp", "ficom", "ficomp"):
            pops = " X87Pop(c);" if base.endswith("p") else ""
            if not ops:
                v = st(1)
            elif ops[0].type == X.X86_OP_REG:
                v = st(self.sti(ins, ops[-1]))
            else:
                a = self.address(ins, ops[0])
                if base.startswith("fi"):
                    v = {2: f"(double)(int16_t)R16({a})", 4: f"(double)(int32_t)R32({a})"}[ops[0].size]
                else:
                    v = {4: f"(double)RF32({a})", 8: f"RF64({a})"}[ops[0].size]
            return f"X87CompareStatus(c, {st(0)}, {v});{pops}"
        if base in ("fcompp", "fucompp"):
            return f"X87CompareStatus(c, {st(0)}, {st(1)}); X87Pop(c); X87Pop(c);"
        if base == "ftst":
            return f"X87CompareStatus(c, {st(0)}, 0.0);"
        # ---- binary arithmetic ----
        ops_map = {"add": "a + b", "mul": "a * b", "sub": "a - b", "subr": "b - a", "div": "a / b", "divr": "b / a"}
        stem = base[1:]
        integer = False
        if stem.startswith("i"):
            integer = True
            stem = stem[1:]
        popping = stem.endswith("p") and stem[:-1] in ops_map
        if popping:
            stem = stem[:-1]
        if stem in ops_map:
            expr = ops_map[stem]
            if not ops:  # faddp etc. without operands: st(1) = st(1) op st(0), pop
                return f"{{ double a = {st(1)}, b = {st(0)}; {st(1)} = X87Precision(c, {expr}); X87Pop(c); }}"
            if len(ops) == 1 and ops[0].type == X.X86_OP_MEM:
                a_ = self.address(ins, ops[0])
                if integer:
                    v = {2: f"(double)(int16_t)R16({a_})", 4: f"(double)(int32_t)R32({a_})"}[ops[0].size]
                else:
                    v = {4: f"(double)RF32({a_})", 8: f"RF64({a_})"}[ops[0].size]
                return f"{{ double a = {st(0)}, b = {v}; {st(0)} = X87Precision(c, {expr}); }}"
            if len(ops) == 2:
                dst, src = self.sti(ins, ops[0]), self.sti(ins, ops[1])
                pop = " X87Pop(c);" if popping else ""
                return f"{{ double a = {st(dst)}, b = {st(src)}; {st(dst)} = X87Precision(c, {expr});{pop} }}"
            if len(ops) == 1 and ops[0].type == X.X86_OP_REG:
                i = self.sti(ins, ops[0])
                if popping:
                    return f"{{ double a = {st(i)}, b = {st(0)}; {st(i)} = X87Precision(c, {expr}); X87Pop(c); }}"
                return f"{{ double a = {st(0)}, b = {st(i)}; {st(0)} = X87Precision(c, {expr}); }}"
        if base in ("ffree", "fincstp", "fdecstp", "fnop"):
            return {"ffree": "/* ffree */", "fincstp": "c->st_top = (c->st_top + 1) & 7;",
                    "fdecstp": "c->st_top = (c->st_top - 1) & 7;", "fnop": "/* fnop */"}[base]
        raise Unsupported(base)

    def falls_through(self, i):
        m = i.mnemonic
        if m == "jmp" or i.group(capstone.CS_GRP_RET) or m in ("ret", "hlt", "ud2"):
            return False
        return True

    def successors(self, i, decoded):
        m = i.mnemonic
        succ = []
        if i.group(capstone.CS_GRP_JUMP):
            op = i.operands[0] if i.operands else None
            if op is not None and op.type == X.X86_OP_IMM and op.imm in decoded:
                succ.append(op.imm)
            succ.extend(d for d in self.table_targets.get(i.address, ()) if d in decoded)
        if self.falls_through(i):
            nxt = i.address + i.size
            if nxt in decoded:
                succ.append(nxt)
        return succ

    def liveness(self, decoded):
        """Flags live after each instruction. Calls clobber the flags (MSVC never reads flags across a call);
        nothing is live after leaving the function."""
        info = {}
        for i in self.ins:
            defs, uses = flag_sets(i)
            if i.group(capstone.CS_GRP_CALL):
                defs, uses = ALL_FLAGS, 0
            info[i.address] = (defs, uses, self.successors(i, decoded))
        live_in = {a: 0 for a in info}
        live_out = {a: 0 for a in info}
        changed = True
        order = [i.address for i in reversed(self.ins)]
        while changed:
            changed = False
            for a in order:
                defs, uses, succ = info[a]
                out = 0
                for t in succ:
                    out |= live_in[t]
                inn = uses | (out & ~defs)
                if out != live_out[a] or inn != live_in[a]:
                    live_out[a], live_in[a] = out, inn
                    changed = True
        self.live_out = live_out
        self.flag_defs = {a: info[a][0] for a in info}

    def flags_dead(self, ins):
        return (self.flag_defs.get(ins.address, ALL_FLAGS) & self.live_out.get(ins.address, ALL_FLAGS)) == 0

    def compile(self):
        labels = self.targets()
        decoded = {i.address for i in self.ins}
        self.liveness(decoded)
        body = []
        for i in self.ins:
            line = ""
            try:
                line = self.emit(i)
            except Unsupported as e:
                self.unsupported[str(e)] += 1
                line = f'RecompUnimplemented(c, 0x{i.address:08x}u, "{i.mnemonic} {i.op_str}"); return;'
            body.append((i, line))
        out = [f"void f_{self.va:08x}(Ctx* c) {{"]
        if LOCALIZE:
            out.append("    RLOCALS;")
        trap_labels = set()
        # Fall-through into an instruction that is not next in the output (overlapping decodes) needs its label.
        for n, (i, _) in enumerate(body):
            if self.falls_through(i):
                nxt = i.address + i.size
                following = body[n + 1][0].address if n + 1 < len(body) else None
                if following != nxt and nxt in decoded:
                    labels.add(nxt)
        for n, (i, line) in enumerate(body):
            if i.address in labels:
                out.append(f"L_{i.address:08x}:;")
            out.append(f"    {line}  /* {i.address:08x}: {i.mnemonic} {i.op_str} */")
            if self.falls_through(i):
                nxt = i.address + i.size
                following = body[n + 1][0].address if n + 1 < len(body) else None
                if following != nxt:
                    if nxt in decoded:
                        out.append(f"    goto L_{nxt:08x};")
                    elif not self.inside(nxt):
                        # Falls off its extent into the next entry: Ghidra split one body in two (or more), the
                        # code simply continues there.
                        out.append(f"    {self.jump_to(nxt)}")
                    else:
                        out.append(f'    RecompUnimplemented(c, 0x{nxt:08x}u, "fell into undecoded bytes"); return;')
        # Branch targets that were never decoded (int3 or undecodable): traps.
        for t in sorted(labels - decoded):
            out.append(f"L_{t:08x}:;")
            out.append(f'    RecompUnimplemented(c, 0x{t:08x}u, "branch into undecoded bytes"); return;')
        if not self.ins:
            out.append(f'    RecompUnimplemented(c, 0x{self.va:08x}u, "no decodable instruction"); return;')
        if LOCALIZE:
            decl, spill, reload, x87 = vector_state("\n".join(out[2:]))
            out = out[:2] + ["    " + d for d in decl] + \
                [localize(l, x87) if not l.startswith("L_") else l for l in out[2:]]
            xmms = sorted(set(_XMM_RE.findall("\n".join(out))))  # (already renamed: read the declarations)
            xmms = [d.split("r_xmm")[1].split(" ")[0] for d in decl if d.startswith("XmmValue r_xmm")]
            out = out[:1] + apply_spills(out[1:], xmms, x87, DIRTY_TRACKING)
        out.append("}")
        # Prototypes last: tail jumps added while assembling the body are direct calls too.
        protos = [f"void f_{t:08x}(Ctx* c);" for t in sorted(self.direct_calls - {self.va})]
        return "\n".join(protos + out)


def ops_are_xmm(ins):
    return any(o.type == X.X86_OP_REG and ins.reg_name(o.reg).startswith("xmm") for o in ins.operands)


def Mask(bits):
    return (1 << bits) - 1


def entry_patch(fc):
    """Hook metadata for entering the recompiled function from native code: whole instructions covering >= 5
    bytes, at most one CALL/JMP rel32 among them, no other relative branch; may extend into int3 padding only."""
    stolen = b""
    rel32_at = -1
    addr = fc.va
    while len(stolen) < 5:
        off = addr - fc.va
        if off >= fc.size:
            raw = fc.pe.get_data(addr - BASE, 1)
            if raw != b"\xcc":
                return None
            stolen += raw
            addr += 1
            continue
        i = fc.decode_one(addr)
        if i is None:
            return None
        raw = bytes(i.bytes)
        if raw[0] in (0xE8, 0xE9) and len(raw) == 5:
            if rel32_at >= 0:
                return None
            rel32_at = len(stolen)
        elif i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_RET) and len(stolen) + len(raw) < 5:
            if not (i.group(capstone.CS_GRP_RET) and off + len(raw) <= fc.size):
                return None
        stolen += raw
        addr += len(raw)
    if len(stolen) > 15:
        return None
    return stolen, rel32_at


class WriteIfChanged:
    """File writer that leaves an unchanged file untouched, so make rebuilds only the parts that changed."""

    def __init__(self, path):
        self.path, self.parts = path, []

    def write(self, text):
        self.parts.append(text)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        text = "".join(self.parts)
        try:
            with open(self.path) as f:
                if f.read() == text:
                    return
        except OSError:
            pass
        with open(self.path, "w") as f:
            f.write(text)


def write_split(out_dir, funcs, patches, per_file):
    os.makedirs(out_dir, exist_ok=True)
    head = f'/* Generated by tools/recomp/recomp.py from {IMAGE_NAME}; do not edit. */\n' \
           '#include <math.h>\n#include "runtime.h"\n#include "runtime_fp.h"\n\n'
    # Functions go to files by address (64 KiB of code per file), so adding or changing a function rewrites only
    # its own file and make rebuilds just that part.
    buckets = collections.defaultdict(list)
    for va, text in funcs:
        buckets[(va - BASE) >> 16].append(text)
    for name in os.listdir(out_dir):
        if name.startswith("part_") and int(name[5:9], 16) not in buckets:
            os.remove(os.path.join(out_dir, name))
    for b, texts in buckets.items():
        with WriteIfChanged(os.path.join(out_dir, f"part_{b:04x}.c")) as f:
            f.write(head)
            for text in texts:
                f.write(text + "\n\n")
    parts = len(buckets)
    with WriteIfChanged(os.path.join(out_dir, "table.c")) as f:
        f.write(head)
        for va, _ in funcs:
            f.write(f"void f_{va:08x}(Ctx* c);\n")
        f.write("\nconst struct { uint32_t va; RecompFn fn; } g_recomp_table[] = {\n")
        for va, _ in funcs:
            f.write(f"    {{0x{va:08x}u, f_{va:08x}}},\n")
        f.write("};\nconst uint32_t g_recomp_count = sizeof(g_recomp_table) / sizeof(g_recomp_table[0]);\n\n")
        f.write("/* Entry patches: va, stolen length, rel32 offset (-1 none), expected bytes. */\n")
        f.write("const struct { uint32_t va; uint8_t len; int8_t rel32_at; uint8_t bytes[15]; } g_recomp_entries[] = {\n")
        for va, patch in patches:
            stolen, rel = patch
            b = ", ".join(f"0x{x:02x}" for x in stolen)
            f.write(f"    {{0x{va:08x}u, {len(stolen)}, {rel}, {{{b}}}}},\n")
        f.write("};\nconst uint32_t g_recomp_entry_count = sizeof(g_recomp_entries) / sizeof(g_recomp_entries[0]);\n")
    return parts


def main():
    load_config(next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--config=")), None)
                or (sys.argv[sys.argv.index("--config") + 1] if "--config" in sys.argv else default_config()))
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", help="game config module (default tools/recomp/game.py or RECOMP_CONFIG)")
    ap.add_argument("--functions", required=True)
    ap.add_argument("--out", required=True, help="output .c file, or a directory with --split")
    ap.add_argument("--split", type=int, default=0, help="functions per file (writes part_NNNN.c + table.c)")
    ap.add_argument("--base", type=lambda v: int(v, 0), default=ORIG_BASE,
                    help="engine load address (native host: 0x7c000000, guest.h kEngineBase)")
    ap.add_argument("--no-localize", action="store_true", help="keep general registers in the context")
    ap.add_argument("--no-dirty", action="store_true", help="spill all localized state at every call")
    ap.add_argument("--no-native", action="store_true", help="recompile NATIVE_OVERRIDES too (difftests)")
    args = ap.parse_args()
    global LOCALIZE, DIRTY_TRACKING
    LOCALIZE = not args.no_localize
    DIRTY_TRACKING = not args.no_dirty
    global NATIVE
    NATIVE = args.base != ORIG_BASE and not args.no_native  # the Wine host has no Native_* implementations
    rebase(args.base)
    sizes = load_functions()
    if args.functions == "all":
        vas = sorted(sizes)
    else:
        vas = sorted((int(l.strip(), 16) if int(l.strip(), 16) >= ORIG_BASE else int(l.strip(), 16) + ORIG_BASE)
                     - ORIG_BASE + BASE for l in open(args.functions) if l.strip())
    pe = pefile.PE(IMAGE, fast_load=True)
    relocate_pe(pe)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    unsupported = collections.Counter()
    funcs = []
    patches = []
    compiled = {va for va in vas if va in sizes}
    # Direct call/jump targets that are no known entry (Ghidra missed them) are added and compiled as well, until no
    # new ones appear; thunks (jmp [iat], jmp rel32) are followed by the dispatcher instead.
    text = pe.sections[0]
    text_lo, text_hi = BASE + text.VirtualAddress, BASE + text.VirtualAddress + text.Misc_VirtualSize
    starts = sorted(set(load_all_starts()))
    work = list(vas)
    discovered = 0
    while work:
        va = work.pop(0)
        if va not in sizes:
            print(f"skip {va:#x}: not a function start", file=sys.stderr)
            continue
        orig = va - BASE + ORIG_BASE
        if NATIVE and orig in NATIVE_OVERRIDES:
            funcs.append((va, f"void Native_{orig:08x}(Ctx* c);\nvoid f_{va:08x}(Ctx* c) {{ Native_{orig:08x}(c); }}"))
            continue
        fc = FunctionCompiler(md, pe, va, sizes[va], compiled)
        funcs.append((va, fc.compile()))
        for t in sorted(fc.unknown_targets):
            if text_lo <= t < text_hi and t not in compiled:
                import bisect
                i = bisect.bisect_right(starts, t)
                sizes[t] = (starts[i] if i < len(starts) else t + 16) - t
                compiled.add(t)
                EXTRA_ENTRIES.add(t)
                work.append(t)
                discovered += 1
        unsupported.update(fc.unsupported)
        # Missed entries are only reachable through computed calls; the in-process bridge leaves them native.
        patch = entry_patch(fc) if va not in EXTRA_ENTRIES else None
        if patch:
            patches.append((va, patch))
    funcs.sort()
    patches.sort()
    print(f"{discovered} entries discovered as direct call/jump targets", file=sys.stderr)
    if args.split:
        parts = write_split(args.out, funcs, patches, args.split)
        print(f"{len(funcs)} functions in {parts} files; {len(patches)} enterable from native code; "
              f"{sum(unsupported.values())} unsupported instructions")
        for k, v in unsupported.most_common(30):
            print(f"  {v:6d}  {k}")
        return
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write(f"/* Generated by tools/recomp/recomp.py from {IMAGE_NAME}; do not edit. */\n")
        f.write('#include <math.h>\n#include "runtime.h"\n#include "runtime_fp.h"\n\n')
        for va, _ in funcs:
            f.write(f"void f_{va:08x}(Ctx* c);\n")
        f.write("\n")
        for _, text in funcs:
            f.write(text + "\n\n")
        f.write("const struct { uint32_t va; RecompFn fn; } g_recomp_table[] = {\n")
        for va, _ in funcs:
            f.write(f"    {{0x{va:08x}u, f_{va:08x}}},\n")
        f.write("};\nconst uint32_t g_recomp_count = sizeof(g_recomp_table) / sizeof(g_recomp_table[0]);\n")
    total = sum(unsupported.values())
    print(f"{len(funcs)} functions recompiled; {total} unsupported instructions")
    for k, v in unsupported.most_common(30):
        print(f"  {v:6d}  {k}")


if __name__ == "__main__":
    main()
