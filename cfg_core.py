"""
cfg_core.py - standalone x86-32 control-flow / def-use / data-dependency engine.

Merges the two former IDA Pro plugins:
  * Lab 3: per-instruction D (defs) / U (uses) sets + control-flow edges
  * Lab 4: stack-pointer tracking (stk_N slots), reaching-definitions data
           dependencies (DD), callee stack purge, function discovery

IDA is replaced by Capstone. IDA's type library is replaced by heuristics
for call arguments (see Analyzer.callee_signature).
"""
from __future__ import annotations

import json

from capstone import (CS_ARCH_X86, CS_AC_READ, CS_AC_WRITE, CS_GRP_CALL,
                      CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, CS_OP_IMM,
                      CS_OP_MEM, CS_OP_REG, Cs)
from capstone.x86_const import X86_PREFIX_REP, X86_PREFIX_REPNE

START = "START"

# ----------------------------------------------------------------- registers
_FAMILIES = {
    "eax": ("eax", "ax", "al", "ah"),
    "ebx": ("ebx", "bx", "bl", "bh"),
    "ecx": ("ecx", "cx", "cl", "ch"),
    "edx": ("edx", "dx", "dl", "dh"),
    "esi": ("esi", "si"),
    "edi": ("edi", "di"),
    "ebp": ("ebp", "bp"),
    "esp": ("esp", "sp"),
}
REG32 = {alias: full for full, aliases in _FAMILIES.items() for alias in aliases}
_IGNORED = {"eip", "ip", "cs", "ds", "es", "fs", "gs", "ss", "fpsw", "fpcw"}


def norm_reg(name):
    """Map any sub-register to its 32-bit parent; None for registers we ignore."""
    if not name or name in _IGNORED:
        return None
    return REG32.get(name, name)


def s32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


def add_unique(group, item):
    if item is not None and item not in group:
        group.append(item)


# --------------------------------------------------------------------- image
class Image:
    """Flat memory image made of (base, bytes, executable) segments."""

    def __init__(self):
        self.segments = []
        self.imports = {}  # IAT slot address -> "dll!function"

    def add(self, base, data, executable=True):
        self.segments.append((base, bytes(data), executable))

    def read(self, addr, n=16):
        for base, data, _ in self.segments:
            if base <= addr < base + len(data):
                return data[addr - base:addr - base + n]
        return b""

    @classmethod
    def from_bytes(cls, data, base=0x401000):
        """Raw bytes, or a 32-bit PE if the data starts with MZ and pefile is installed.
        Returns (image, default_entry_points)."""
        if data[:2] == b"MZ":
            try:
                import pefile
                pe = pefile.PE(data=data)
                if pe.FILE_HEADER.Machine != 0x14C:
                    raise ValueError("Only 32-bit x86 PE files are supported")
                img = cls()
                ib = pe.OPTIONAL_HEADER.ImageBase
                for s in pe.sections:
                    sdata = s.get_data()
                    if 0 < s.Misc_VirtualSize < len(sdata):
                        sdata = sdata[:s.Misc_VirtualSize]  # drop file-alignment padding
                    img.add(ib + s.VirtualAddress, sdata,
                            bool(s.Characteristics & 0x20000000))
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                    dll = entry.dll.decode(errors="replace").lower()
                    if dll.endswith(".dll"):
                        dll = dll[:-4]
                    for imp in entry.imports:
                        fn = imp.name.decode(errors="replace") if imp.name else "ord%d" % imp.ordinal
                        img.imports[imp.address] = "%s!%s" % (dll, fn)
                return img, [ib + pe.OPTIONAL_HEADER.AddressOfEntryPoint]
            except ImportError:
                raise ValueError("Input looks like a PE file (MZ header) but pefile is not "
                                 "installed: pip install pefile")
        img = cls()
        img.add(base, data, True)
        return img, [base]


# ------------------------------------------------------------------ analyzer
class Analyzer:
    def __init__(self, image):
        self.img = image
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self._insn = {}
        self._items = {}
        self._purge = {}
        self._sig = {}
        self._code = set()      # every instruction address reached by collect()
        self._leaders = set()   # function starts, branch targets, and fall-throughs after branches
        self._api_purge = {}    # "dll!func" -> bytes popped, learned from balanced functions
        self._call_fix = {}     # call address -> bytes popped, corrected by stack balancing

    # ---- decoding -------------------------------------------------------
    def insn(self, ea):
        if ea in self._insn:
            return self._insn[ea]
        result = None
        raw = self.img.read(ea, 16)
        if raw:
            for i in self.cs.disasm(raw, ea, 1):
                result = i
                break
        self._insn[ea] = result
        return result

    def rname(self, reg_id):
        return norm_reg(self.cs.reg_name(reg_id)) if reg_id else None

    @staticmethod
    def asm(i):
        return (i.mnemonic + " " + i.op_str).strip()

    def direct_target(self, i):
        """Target of a direct jmp/jcc/call, else None."""
        if i.operands and i.operands[0].type == CS_OP_IMM:
            return i.operands[0].imm & 0xFFFFFFFF
        return None

    def is_reg(self, i, idx, name):
        return (len(i.operands) > idx and i.operands[idx].type == CS_OP_REG
                and self.rname(i.operands[idx].reg) == name)

    # ---- control flow ---------------------------------------------------
    def successors(self, ea):
        i = self.insn(ea)
        if i is None or i.group(CS_GRP_RET) or i.mnemonic in ("hlt", "ud2", "int3"):
            return []
        nxt = ea + i.size
        out = []
        if i.group(CS_GRP_JUMP):
            t = self.direct_target(i)
            if t is not None:
                out.append(t)
            if i.mnemonic not in ("jmp", "ljmp"):
                out.append(nxt)
        else:
            out.append(nxt)  # includes call fall-through
        return [s for s in dict.fromkeys(out) if self.insn(s) is not None]

    def dests(self, itemset, ea):
        return [s for s in self.successors(ea) if s in itemset]

    def collect(self, start):
        """All instructions reachable from start without following calls (like FuncItems)."""
        if start in self._items:
            return self._items[start]
        seen, work = set(), [start]
        while work:
            a = work.pop()
            if a in seen or self.insn(a) is None:
                continue
            seen.add(a)
            succ = self.successors(a)
            nxt = a + self.insn(a).size
            if succ != [nxt]:
                self._leaders.update(succ)
                self._leaders.add(nxt)
            work.extend(succ)
        self._code |= seen
        self._leaders.add(start)
        self._items[start] = sorted(seen)
        return self._items[start]

    def discover(self, entries, sweep=False):
        """Recursive descent over call targets; optional linear sweep for orphan code
        (equivalent of define_undefined_funcs)."""
        starts, covered, work = set(), set(), list(entries)

        def drain():
            while work:
                f = work.pop()
                if f in starts or self.insn(f) is None:
                    continue
                starts.add(f)
                for a in self.collect(f):
                    covered.add(a)
                    i = self.insn(a)
                    if i.group(CS_GRP_CALL):
                        t = self.direct_target(i)
                        if t is not None and self.insn(t) is not None:
                            work.append(t)

        drain()
        if sweep:
            for base, data, executable in self.img.segments:
                if not executable:
                    continue
                a, end = base, base + len(data)
                while a < end:
                    i = self.insn(a)
                    if i is None:
                        a += 1
                        continue
                    if a not in covered and i.mnemonic not in ("int3", "nop"):
                        work.append(a)
                        drain()
                    a += i.size
        return sorted(starts)

    # ---- stack tracking (Lab 4 monitor_stack / change_stack) -------------
    def callee_purge(self, t):
        if t in self._purge:
            return self._purge[t]
        val = 0
        for a in self.collect(t):
            i = self.insn(a)
            if i.mnemonic.startswith("ret") and i.operands and i.operands[0].type == CS_OP_IMM:
                val = i.operands[0].imm
                break
        self._purge[t] = val
        return val

    # ---- calls we can't analyze (imports, call reg, call [mem]) ------------
    def _prev(self, ea):
        """Address of the instruction that falls through to ea, if known."""
        for k in range(1, 16):
            p = ea - k
            if p in self._code and self.insn(p).size == k:
                return p
        return None

    def _iat_slot(self, op):
        if op.type == CS_OP_MEM and not op.mem.base and not op.mem.index:
            a = op.mem.disp & 0xFFFFFFFF
            if a in self.img.imports:
                return a
        return None

    def _regs_written(self, i):
        try:
            return [norm_reg(self.cs.reg_name(r)) for r in i.regs_access()[1]]
        except Exception:
            return []

    def _touches_esp(self, i):
        try:
            read, written = i.regs_access()
        except Exception:
            return False
        return any(norm_reg(self.cs.reg_name(r)) == "esp" for r in list(read) + list(written))

    def call_name(self, ea):
        """'dll!func' for a call through the IAT: call [IAT], mov reg,[IAT] + call reg,
        or a call to a `jmp [IAT]` thunk. None otherwise."""
        i = self.insn(ea)
        if not i.operands:
            return None
        op = i.operands[0]
        slot = self._iat_slot(op)
        if slot is not None:
            return self.img.imports[slot]
        if op.type == CS_OP_IMM:
            t = self.insn(op.imm & 0xFFFFFFFF)
            if t is not None and t.mnemonic == "jmp" and t.operands:
                slot = self._iat_slot(t.operands[0])
                if slot is not None:
                    return self.img.imports[slot]
            return None
        if op.type == CS_OP_REG:
            reg, a = self.rname(op.reg), ea
            for _ in range(40):
                a = self._prev(a)
                if a is None:
                    break
                j = self.insn(a)
                if reg in self._regs_written(j):
                    if j.mnemonic == "mov" and len(j.operands) == 2:
                        slot = self._iat_slot(j.operands[1])
                        if slot is not None:
                            return self.img.imports[slot]
                    break
        return None

    def guess_call(self, ea):
        """(bytes popped by callee, number of stack args, caller_cleans) for an opaque call.
        `add esp, N` right after the call means the caller cleans up (cdecl); otherwise
        assume stdcall and count the pushes right before the call in the same block."""
        i = self.insn(ea)
        nxt = self.insn(ea + i.size)
        if (nxt is not None and nxt.mnemonic == "add" and self.is_reg(nxt, 0, "esp")
                and len(nxt.operands) > 1 and nxt.operands[1].type == CS_OP_IMM):
            return 0, max(0, s32(nxt.operands[1].imm)) // 4, True
        n, a = 0, ea
        while n < 16 and a not in self._leaders:
            p = self._prev(a)
            if p is None:
                break
            j = self.insn(p)
            if j.mnemonic == "push":
                n += 1
            elif (j.group(CS_GRP_CALL) or j.group(CS_GRP_JUMP) or j.group(CS_GRP_RET)
                  or self._touches_esp(j)):
                break
            a = p
        return 4 * n, n, False

    def is_opaque_call(self, ea):
        """True for calls whose callee we can't analyze (imports, thunks, indirect)."""
        i = self.insn(ea)
        if not i.group(CS_GRP_CALL):
            return False
        t = self.direct_target(i)
        return self.call_name(ea) is not None or t is None or self.insn(t) is None

    def call_effect(self, ea, overrides=None):
        """(bytes popped, number of stack args, register args) for the call at ea."""
        i = self.insn(ea)
        if not self.is_opaque_call(ea):
            t = self.direct_target(i)
            regs, n = self.callee_signature(t)
            return self.callee_purge(t), n, regs
        purge, n, caller_cleans = self.guess_call(ea)
        if not caller_cleans:
            name = self.call_name(ea)
            if overrides and ea in overrides:
                purge = overrides[ea]
            elif ea in self._call_fix:
                purge = self._call_fix[ea]
            elif name in self._api_purge:
                purge = self._api_purge[name]
            n = purge // 4
        return purge, n, []

    def change_stack(self, ea, esp, ebp, overrides=None):
        i = self.insn(ea)
        m = i.mnemonic
        if m == "leave":
            return ((ebp + 4) if ebp is not None else esp), None
        if m == "pop":
            return esp + 4, (None if self.is_reg(i, 0, "ebp") else ebp)
        if m == "push":
            return esp - 4, ebp
        if m == "call":
            return esp + self.call_effect(ea, overrides)[0], ebp
        if m == "mov" and self.is_reg(i, 0, "ebp") and self.is_reg(i, 1, "esp"):
            return esp, esp
        if (m in ("add", "sub") and self.is_reg(i, 0, "esp")
                and len(i.operands) > 1 and i.operands[1].type == CS_OP_IMM):
            imm = s32(i.operands[1].imm)
            return (esp + imm if m == "add" else esp - imm), ebp
        return esp, ebp

    def _stack_pass(self, start, items, overrides):
        """One stack-height propagation. Returns (state, problems); a problem is
        (kind, ea, esp_a, esp_b): 'merge' = paths disagree, 'ret' = esp != 0 at ret."""
        itemset, state, work, problems = set(items), {}, [(start, 0, None)], []
        while work:
            ea, esp, ebp = work.pop()
            if ea in state:
                if esp is not None and state[ea][0] is not None and state[ea][0] != esp:
                    problems.append(("merge", ea, state[ea][0], esp))
                continue
            state[ea] = (esp, ebp)
            nesp, nebp = self.change_stack(ea, esp, ebp, overrides)
            for d in self.dests(itemset, ea):
                work.append((d, nesp, nebp))
        for ea in items:
            if self.insn(ea).group(CS_GRP_RET) and ea in state and state[ea][0] not in (0, None):
                problems.append(("ret", ea, state[ea][0], 0))
        return state, problems

    def stack_states(self, start, items):
        """Stack heights per instruction, plus warnings. If the heights don't balance,
        try correcting the pop count of one opaque call (see guess_call) until they do."""
        state, problems = self._stack_pass(start, items, {})
        if problems:
            deltas = []
            for kind, _, a, b in problems:
                deltas += [b - a] if kind == "ret" else [a - b, b - a]
            deltas = [d for d in dict.fromkeys(deltas) if d]
            opaque = [ea for ea in items if self.is_opaque_call(ea)]
            for c in opaque:
                base = self.call_effect(c)[0]
                for d in deltas:
                    trial = {c: base + d}
                    if trial[c] < 0 or trial[c] > 64:
                        continue
                    st, pr = self._stack_pass(start, items, trial)
                    if not pr:
                        self._call_fix[c] = trial[c]
                        name = self.call_name(c)
                        if name:  # reuse at every other call site of this API
                            self._api_purge[name] = trial[c]
                        return st, ["note: assumed call at 0x%x pops %d bytes (balances the "
                                    "function)" % (c, trial[c])]
        warnings = []
        for kind, ea, a, b in problems:
            if kind == "merge":
                warnings.append("WARNING: stack height differs where paths meet at 0x%x (%d vs %d); "
                                "stk_N names from here on may be wrong" % (ea, a, b))
            else:
                warnings.append("WARNING: stack not balanced at ret 0x%x (esp = %d, expected 0); "
                                "stk_N names may be wrong" % (ea, a))
        return state, warnings

    # ---- memory operand naming (Lab 3 memoryGetName + Lab 4 mem_address) --
    def mem_name(self, op, esp, ebp):
        m = op.mem
        base, index = self.rname(m.base), self.rname(m.index)
        regs = [r for r in (base, index) if r]
        disp = s32(m.disp)
        seg = self.cs.reg_name(m.segment) if m.segment else None
        prefix = seg + ":" if seg in ("fs", "gs") else ""
        if not regs:
            return "%smem_0x%x" % (prefix, disp & 0xFFFFFFFF), regs
        if base in ("esp", "ebp") and not index:
            baseval = esp if base == "esp" else ebp
            if baseval is not None:
                return "stk_%d" % (baseval + disp), regs
        parts = []
        if base:
            parts.append(base)
        if index:
            parts.append(index if m.scale == 1 else "%s*%d" % (index, m.scale))
        t = " + ".join(parts)
        if disp < 0:
            t += " - 0x%x" % -disp
        elif disp:
            t += " + 0x%x" % disp
        return prefix + "[%s]" % t, regs

    # ---- def / use (Lab 3 du + Lab 4 du) ---------------------------------
    def du(self, ea, esp, ebp):
        i = self.insn(ea)
        if i is None:
            return [], []
        m = i.mnemonic
        base_m = m.split()[-1]  # "rep stosd" -> "stosd"

        if base_m == "nop":  # multi-byte nops have a memory operand but touch nothing
            return [], []
        if base_m in ("stosd", "stosw", "stosb"):  # edge case from the plugins
            d, u = ["[edi]", "edi"], ["eax", "edi"]
            if m.startswith("rep") or X86_PREFIX_REP in i.prefix or X86_PREFIX_REPNE in i.prefix:
                d.append("ecx")
                u.append("ecx")
            return d, u

        d, u = [], []
        for op in i.operands:
            if op.type == CS_OP_MEM:
                name, regs = self.mem_name(op, esp, ebp)
                if base_m != "lea" and op.access & CS_AC_READ:
                    add_unique(u, name)
                for r in regs:
                    add_unique(u, r)
                if op.access & CS_AC_WRITE:
                    add_unique(d, name)
            elif op.type == CS_OP_REG:
                n = self.rname(op.reg)
                if op.access & CS_AC_READ:
                    add_unique(u, n)
                if op.access & CS_AC_WRITE:
                    add_unique(d, n)

        # implicit register effects (stack pointer, eflags, ecx for rep, edx for mul/cdq ...)
        try:
            read, written = i.regs_access()
        except Exception:
            read, written = [], []
        for r in read:
            add_unique(u, norm_reg(self.cs.reg_name(r)))
        for r in written:
            add_unique(d, norm_reg(self.cs.reg_name(r)))

        # implicit stack-slot effects
        if base_m == "pop":
            add_unique(d, "esp")
            add_unique(u, "esp")
            if esp is not None:
                add_unique(u, "stk_%d" % esp)
        elif base_m == "push":
            add_unique(d, "esp")
            add_unique(u, "esp")
            if esp is not None:
                add_unique(d, "stk_%d" % (esp - 4))
        elif i.group(CS_GRP_RET):
            add_unique(d, "esp")
            add_unique(u, "esp")
        elif base_m.startswith("leave"):
            add_unique(d, "ebp")
            add_unique(u, "ebp")
            add_unique(d, "esp")
            if ebp is not None:
                add_unique(u, "stk_%d" % ebp)
        elif i.group(CS_GRP_CALL):
            add_unique(d, "esp")
            add_unique(u, "esp")
            add_unique(d, "eax")
            _, nstack, regs = self.call_effect(ea)
            for r in regs:
                add_unique(u, r)
            if esp is not None:
                for k in range(nstack):
                    add_unique(u, "stk_%d" % (esp + 4 * k))
        return d, u

    def callee_signature(self, t):
        """Heuristic stand-in for IDA's prototype lookup.
        Returns (register args, number of stack args).
          * ecx/edx are register args if the callee reads them before writing them
            (thiscall / fastcall), scanning straight-line code until control flow.
          * stack args = `ret N` / 4, else highest [ebp+8+4k] slot touched (cap 16).
        """
        if t in self._sig:
            return self._sig[t]
        regs, defined, a = [], set(), t
        for _ in range(200):
            i = self.insn(a)
            if i is None or i.group(CS_GRP_CALL) or i.group(CS_GRP_JUMP) or i.group(CS_GRP_RET):
                break
            d, u = self.du(a, None, None)
            zero_idiom = (i.mnemonic in ("xor", "sub") and len(i.operands) == 2
                          and i.operands[0].type == CS_OP_REG and i.operands[1].type == CS_OP_REG
                          and i.operands[0].reg == i.operands[1].reg)
            for r in ("ecx", "edx"):
                if r in defined:
                    continue
                if r in u and not zero_idiom:
                    regs.append(r)
                    defined.add(r)
                elif r in d or zero_idiom:
                    defined.add(r)
            a += i.size
        nstack = self.callee_purge(t) // 4
        if nstack == 0:
            for x in self.collect(t):
                for op in self.insn(x).operands:
                    if (op.type == CS_OP_MEM and self.rname(op.mem.base) == "ebp"
                            and not op.mem.index and s32(op.mem.disp) >= 8):
                        nstack = max(nstack, (s32(op.mem.disp) - 8) // 4 + 1)
        self._sig[t] = (regs, min(nstack, 16))
        return self._sig[t]

    # ---- reaching definitions (Lab 4 data_dependencies) -------------------
    def data_dependencies(self, start, items, duvals):
        itemset = set(items)
        succ = {ea: self.dests(itemset, ea) for ea in items}
        IN = {ea: None for ea in items}  # None = not reached yet
        IN[start] = {}
        work = [start]
        S = frozenset([START])
        while work:
            ea = work.pop()
            d, _ = duvals[ea]
            out = dict(IN[ea])
            for loc in d:
                out[loc] = frozenset([ea])
            for s in succ[ea]:
                if IN[s] is None:
                    IN[s] = dict(out)
                    work.append(s)
                    continue
                cur, changed = IN[s], False
                for loc in set(out) | set(cur):
                    new = out.get(loc, S) | cur.get(loc, S)
                    if new != cur.get(loc, S):
                        cur[loc] = new
                        changed = True
                if changed:
                    work.append(s)
        deps = {}
        for ea in items:
            _, u = duvals[ea]
            state = IN[ea] or {}
            ds = set()
            for loc in u:
                ds |= state.get(loc, S)
            deps[ea] = ds
        return deps

    # ---- basic blocks -------------------------------------------------------
    def basic_blocks(self, start, items, succ):
        itemset = set(items)
        leaders = {start}
        for ea in items:
            i = self.insn(ea)
            nxt = ea + i.size
            if succ[ea] != [nxt]:
                leaders.update(succ[ea])
                if nxt in itemset:
                    leaders.add(nxt)
        blocks = []
        for L in sorted(leaders):
            ea, members = L, []
            while True:
                members.append(ea)
                s = succ[ea]
                nxt = ea + self.insn(ea).size
                if len(s) == 1 and s[0] == nxt and nxt not in leaders:
                    ea = nxt
                else:
                    break
            blocks.append({"start": L, "instructions": members, "successors": succ[members[-1]]})
        return blocks

    # ---- top level ----------------------------------------------------------
    def analyze_function(self, start):
        items = self.collect(start)
        itemset = set(items)
        stack, warnings = self.stack_states(start, items)
        duvals = {ea: self.du(ea, *stack.get(ea, (None, None))) for ea in items}
        deps = self.data_dependencies(start, items, duvals)
        succ = {ea: self.dests(itemset, ea) for ea in items}

        def asm(ea):
            i = self.insn(ea)
            name = self.call_name(ea) if i.group(CS_GRP_CALL) or i.group(CS_GRP_JUMP) else None
            return self.asm(i) + (" <%s>" % name if name else "")

        return {
            "entry": start,
            "warnings": warnings,
            "instructions": [{
                "ea": ea, "asm": asm(ea),
                "defs": duvals[ea][0], "uses": duvals[ea][1],
                "deps": sorted(deps[ea], key=lambda x: (x != START, x if x != START else 0)),
                "succ": succ[ea], "esp": stack.get(ea, (None, None))[0],
            } for ea in items],
            "blocks": self.basic_blocks(start, items, succ),
        }

    def analyze(self, entries, sweep=False):
        return [self.analyze_function(s) for s in self.discover(entries, sweep)]


# ------------------------------------------------------------------ renderers
def _du_str(ins, empty=""):
    d = ", ".join(ins["defs"]) or empty
    u = ", ".join(ins["uses"]) or empty
    return ("D: %s U: %s" % (d, u)).replace("  ", " ").strip()


def _dd_labels(ins):
    return [START if d == START else "0x%x" % d for d in ins["deps"]]


def to_dot(funcs, mode="both"):
    """mode: cfg  -> Lab 3 format (D/U labels + control-flow edges)
             ddg  -> Lab 4 format (DD labels + dependency edges, n0 = START)
             both -> asm + D/U + DD labels, solid control edges, dashed blue data edges"""
    out = []
    for fn in funcs:
        ins_list = fn["instructions"]
        node = {ins["ea"]: "n%d" % (k + 1) for k, ins in enumerate(ins_list)}
        out.append('digraph "0x%x" {' % fn["entry"])
        if mode in ("ddg", "both"):
            out.append('n0 [label = "START"];')
        for ins in ins_list:
            if mode == "cfg":
                label = "0x%x; %s" % (ins["ea"], _du_str(ins))
            elif mode == "ddg":
                label = "0x%x; DD: %s" % (ins["ea"], ", ".join(_dd_labels(ins)))
            else:
                label = "0x%x; %s; %s DD: %s" % (ins["ea"], ins["asm"].replace('"', "'"),
                                                _du_str(ins), ", ".join(_dd_labels(ins)))
            out.append('%s [label = "%s"];' % (node[ins["ea"]], label))
        out.append("")
        if mode in ("cfg", "both"):
            for ins in ins_list:
                for s in ins["succ"]:
                    out.append("%s -> %s;" % (node[ins["ea"]], node[s]))
        if mode in ("ddg", "both"):
            style = ' [style=dashed, color=blue]' if mode == "both" else ""
            for ins in ins_list:
                for d in ins["deps"]:
                    tgt = "n0" if d == START else node[d]
                    out.append("%s -> %s%s;" % (node[ins["ea"]], tgt, style))
        out.append("}")
    return "\n".join(out) + "\n"


def to_json(funcs):
    data = []
    for fn in funcs:
        h = lambda x: x if x == START else "0x%x" % x
        data.append({
            "function": "0x%x" % fn["entry"],
            "warnings": fn.get("warnings", []),
            "blocks": [{
                "start": "0x%x" % b["start"],
                "successors": ["0x%x" % s for s in b["successors"]],
                "instructions": [ins["ea"] for ins in fn["instructions"] if ins["ea"] in set(b["instructions"])],
            } for b in fn["blocks"]],
            "instructions": [{
                "addr": "0x%x" % ins["ea"], "asm": ins["asm"],
                "defs": ins["defs"], "uses": ins["uses"],
                "data_deps": [h(d) for d in ins["deps"]],
                "successors": ["0x%x" % s for s in ins["succ"]],
            } for ins in fn["instructions"]],
        })
    for fd in data:
        for b in fd["blocks"]:
            b["instructions"] = ["0x%x" % a for a in b["instructions"]]
    return json.dumps(data, indent=2)


TEXT_LEGEND = ("Legend: D = locations written, U = locations read, DD = addresses of the "
               "instructions whose values this one reads (START = value on function entry), "
               "stk_N = stack slot at offset N from esp on entry (stk_4 = 1st stack arg), "
               "Bk = basic block, '-' = none.")


def to_text(funcs, max_instructions=None, legend=False):
    """Compact, LLM-friendly listing. Stops after max_instructions (total) and says so."""
    lines = [TEXT_LEGEND, ""] if legend else []
    total = sum(len(fn["instructions"]) for fn in funcs)
    shown = 0
    for fn in funcs:
        if max_instructions is not None and shown >= max_instructions:
            break
        by_ea = {ins["ea"]: ins for ins in fn["instructions"]}
        names = {b["start"]: "B%d" % k for k, b in enumerate(fn["blocks"])}
        lines.append("function 0x%x  (%d instructions, %d blocks)" %
                     (fn["entry"], len(by_ea), len(fn["blocks"])))
        for w in fn.get("warnings", []):
            lines.append("  " + w)
        for b in fn["blocks"]:
            if max_instructions is not None and shown >= max_instructions:
                break
            succ = ", ".join("%s(0x%x)" % (names[s], s) for s in b["successors"]) or "none (exit)"
            lines.append("  %s @0x%x -> %s" % (names[b["start"]], b["start"], succ))
            for ea in b["instructions"]:
                if max_instructions is not None and shown >= max_instructions:
                    break
                ins = by_ea[ea]
                lines.append("    0x%x  %-28s %s  DD: %s" %
                             (ea, ins["asm"], _du_str(ins, "-" if legend else ""),
                              ", ".join(_dd_labels(ins)) or "-"))
                shown += 1
        lines.append("")
    if shown < total:
        lines.append("... TRUNCATED: %d more instructions not shown "
                     "(raise max_instructions, or request a single function)." % (total - shown))
    return "\n".join(lines)


def render(funcs, fmt="text", mode="both"):
    if fmt == "dot":
        return to_dot(funcs, mode)
    if fmt == "json":
        return to_json(funcs)
    if fmt == "text":
        return to_text(funcs)
    raise ValueError("format must be dot, json or text")


# -------------------------------------------------------------------- helpers
def parse_hex(s):
    """Accept '55 8b ec', '558bec', '\\x55\\x8b', '0x55,0x8b' ..."""
    t = s.replace("\\x", "").replace("0x", "").replace(",", "")
    t = "".join(t.split())
    if len(t) % 2 or any(c not in "0123456789abcdefABCDEF" for c in t):
        raise ValueError("code must be hex bytes, e.g. '55 8b ec c3'")
    return bytes.fromhex(t)


def parse_addr(v):
    return v if isinstance(v, int) else int(str(v), 0)


def run(data, base=0x401000, entries=None, fmt="text", mode="both", sweep=False):
    img, default_entries = Image.from_bytes(data, base)
    if data[:2] != b"MZ" or default_entries == [base]:
        default_entries = [base]
    entries = [parse_addr(e) for e in entries] if entries else default_entries
    funcs = Analyzer(img).analyze(entries, sweep)
    if not funcs:
        raise ValueError("No decodable code at the entry point(s) %s" % [hex(e) for e in entries])
    return render(funcs, fmt, mode)
