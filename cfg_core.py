"""
cfg_core.py - standalone x86 (16/32/64-bit) control-flow / def-use / data-dependency engine.

Merges the two former IDA Pro plugins:
  * Lab 3: per-instruction D (defs) / U (uses) sets + control-flow edges
  * Lab 4: stack-pointer tracking (stk_N slots), reaching-definitions data
           dependencies (DD), callee stack purge, function discovery

IDA is replaced by Capstone. IDA's type library is replaced by heuristics
for call arguments (see Analyzer.callee_signature).

Supported inputs:
  * 32-bit PE (machine 0x14c) and 64-bit PE32+ (machine 0x8664)
  * 16-bit DOS MZ executables (real mode; addresses are linear: segment*16 + offset,
    with segment 0 = start of the load module, as in the file before relocation)
  * raw code in any of the three modes (bits=16/32/64; .COM files: bits=16, base 0x100)
"""
from __future__ import annotations

import json
import struct

from capstone import (CS_ARCH_X86, CS_AC_READ, CS_AC_WRITE, CS_GRP_CALL,
                      CS_GRP_JUMP, CS_GRP_RET, CS_MODE_16, CS_MODE_32, CS_MODE_64,
                      CS_OP_IMM, CS_OP_MEM, CS_OP_REG, Cs)
from capstone.x86_const import X86_PREFIX_REP, X86_PREFIX_REPNE

START = "START"
ANALYSIS_VERSION = "2026-11-20"  # bump when analysis results change (written to the warning log)
BITS = (16, 32, 64)

# Imported functions that never return to their caller (matched on the name after "dll!",
# case-insensitive). Code after a call to one of these is not part of the call's path.
_NORETURN_APIS = {
    "exitprocess", "exitthread", "freelibraryandexitthread", "rtlexituserprocess",
    "rtlexituserthread", "fatalexit", "fatalappexita", "fatalappexitw", "rtlraisestatus",
    "exit", "_exit", "_exit_", "quick_exit", "abort", "_amsg_exit", "terminate",
    "__std_terminate", "_invalid_parameter_noinfo_noreturn", "_cxxthrowexception",
    "longjmp", "_longjmp", "__report_gsfailure", "__report_rangecheckfailure",
}


_COMPLEX = object()  # marker: stack effect depends on state (see Analyzer._fixed_effect)


def _api_noreturn(name):
    return bool(name) and name.split("!")[-1].lower() in _NORETURN_APIS
_CS_MODE = {16: CS_MODE_16, 32: CS_MODE_32, 64: CS_MODE_64}

# ----------------------------------------------------------------- registers
# Each family lists its names from widest to narrowest; registers are reported by the
# name that matches the code's width (ax in 16-bit, eax in 32-bit, rax in 64-bit).
_LEGACY = [
    ("rax", "eax", "ax", "al", "ah"),
    ("rbx", "ebx", "bx", "bl", "bh"),
    ("rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "edx", "dx", "dl", "dh"),
    ("rsi", "esi", "si", "sil"),
    ("rdi", "edi", "di", "dil"),
    ("rbp", "ebp", "bp", "bpl"),
    ("rsp", "esp", "sp", "spl"),
]
_EXTENDED = [("r%d" % n, "r%dd" % n, "r%dw" % n, "r%db" % n) for n in range(8, 16)]
_FLAGS = {16: "flags", 32: "eflags", 64: "rflags"}
_IGNORED = {"rip", "eip", "ip", "cs", "ds", "es", "fs", "gs", "ss", "fpsw", "fpcw"}
_SEGMENT = {"cs", "ds", "es", "fs", "gs", "ss"}


def _reg_table(bits):
    pick = {16: 2, 32: 1, 64: 0}[bits]
    table = {}
    for fam in _LEGACY:
        for alias in fam:
            table[alias] = fam[pick]
    for fam in _EXTENDED:
        for alias in fam:
            table[alias] = fam[0]
    for f in _FLAGS.values():
        table[f] = _FLAGS[bits]
    return table


_REGS = {b: _reg_table(b) for b in BITS}
REG32 = _REGS[32]  # kept for older imports


def norm_reg(name, bits=32):
    """Map any sub-register to its full-width parent for this mode; None for registers we ignore."""
    if not name or name in _IGNORED:
        return None
    return _REGS[bits].get(name, name)


def sx(v, bits):
    """Sign-extend the low `bits` of v."""
    mask = (1 << bits) - 1
    v &= mask
    return v - (1 << bits) if v >> (bits - 1) else v


def s32(v):
    return sx(v, 32)


def add_unique(group, item):
    if item is not None and item not in group:
        group.append(item)


class Mode:
    """Everything that depends on the code width."""

    def __init__(self, bits):
        if bits not in BITS:
            raise ValueError("bits must be 16, 32 or 64")
        self.bits = bits
        self.word = bits // 8                      # stack slot / return address size
        self.mask = (1 << max(bits, 32)) - 1       # 16-bit uses linear 20-bit addresses
        n = norm_reg
        self.sp, self.bp = n("esp", bits), n("ebp", bits)
        self.ax, self.cx, self.di = n("eax", bits), n("ecx", bits), n("edi", bits)
        # registers that may carry arguments into a callee
        self.arg_regs = {16: [], 32: ["ecx", "edx"], 64: ["rcx", "rdx", "r8", "r9"]}[bits]
        # first stack argument, relative to esp at the call (x64: after the 32-byte shadow space)
        self.arg_area = 0x20 if bits == 64 else 0
        # callee pops its own arguments (stdcall / pascal); never in x64
        self.callee_pops = bits != 64

    def legend(self):
        first = {16: "stk_2 = 1st stack arg of a near function",
                 32: "stk_4 = 1st stack arg",
                 64: "args 1-4 are in rcx, rdx, r8, r9; stk_40 = 5th arg"}[self.bits]
        return ("Legend: %d-bit code. D = locations written, U = locations read, DD = addresses "
                "of the instructions whose values this one reads (START = value on function "
                "entry), stk_N = stack slot at offset N from %s on entry (%s), "
                "stk_?(%s+N) = stack slot whose offset is unknown because stack tracking was "
                "lost there, Bk = basic block, '-' = none. 'about' summarizes each function. "
                "WARNING/note lines report limits of this static analysis (often caused by "
                "obfuscation, packers or hand-written stack tricks), not mistakes by you, and "
                "another model would get the same lines; control flow, register D/U/DD and the "
                "stk_N names that are shown remain usable."
                % (self.bits, self.sp, first, self.sp))


# --------------------------------------------------------------------- image
class Image:
    """Flat memory image made of (base, bytes, executable) segments."""

    def __init__(self, bits=32):
        self.segments = []
        self.imports = {}  # IAT slot address -> "dll!function"
        self.bits = bits
        self.kind = "raw"  # raw, PE, PE32+, DOS MZ

    def add(self, base, data, executable=True):
        self.segments.append((base, bytes(data), executable))

    def read(self, addr, n=16):
        for base, data, _ in self.segments:
            if base <= addr < base + len(data):
                return data[addr - base:addr - base + n]
        return b""

    def describe(self):
        return "%d-bit %s" % (self.bits, self.kind)

    @classmethod
    def from_bytes(cls, data, base=0x401000, bits=None):
        """Raw bytes, a PE/PE32+ (needs pefile), or a 16-bit DOS MZ executable.
        `bits` sets the mode for raw bytes (default 32); executables set their own.
        Returns (image, default_entry_points)."""
        if data[:2] == b"MZ":
            kind = _mz_kind(data)
            if kind == "PE":
                return cls._from_pe(data)
            if kind == "DOS":
                return cls._from_dos(data)
            raise ValueError("%s executables (16-bit Windows/OS2) are not supported; "
                             "extract the code and analyze it as raw bytes with bits=16" % kind)
        img = cls(bits or 32)
        img.add(base, data, True)
        return img, [base]

    @classmethod
    def _from_pe(cls, data):
        try:
            import pefile
        except ImportError:
            raise ValueError("Input looks like a PE file (MZ header) but pefile is not "
                             "installed: pip install pefile")
        pe = pefile.PE(data=data)
        machine = pe.FILE_HEADER.Machine
        if machine == 0x14C:
            img = cls(32)
            img.kind = "PE"
        elif machine == 0x8664:
            img = cls(64)
            img.kind = "PE32+"
        else:
            arch = {0xAA64: "ARM64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2", 0x200: "Itanium"}
            raise ValueError("Only x86 PE files are supported (32-bit or 64-bit); this one is "
                             "for %s (machine type 0x%x)" % (arch.get(machine, "another CPU"), machine))
        ib = pe.OPTIONAL_HEADER.ImageBase
        for s in pe.sections:
            sdata = s.get_data()
            if 0 < s.Misc_VirtualSize < len(sdata):
                sdata = sdata[:s.Misc_VirtualSize]  # drop file-alignment padding
            img.add(ib + s.VirtualAddress, sdata, bool(s.Characteristics & 0x20000000))
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode(errors="replace").lower()
            if dll.endswith(".dll"):
                dll = dll[:-4]
            for imp in entry.imports:
                fn = imp.name.decode(errors="replace") if imp.name else "ord%d" % imp.ordinal
                img.imports[imp.address] = "%s!%s" % (dll, fn)
        return img, [ib + pe.OPTIONAL_HEADER.AddressOfEntryPoint]

    @classmethod
    def _from_dos(cls, data):
        if len(data) < 0x1C:
            raise ValueError("DOS MZ header is truncated")
        last, pages, _, hdr_paras = struct.unpack_from("<4H", data, 2)
        ip, cs = struct.unpack_from("<2H", data, 0x14)
        end = pages * 512 - ((512 - last) if last else 0)
        if not 0 < end <= len(data):
            end = len(data)
        start = hdr_paras * 16
        if start >= end:
            raise ValueError("DOS MZ file has no code after its header")
        img = cls(16)
        img.kind = "DOS MZ"
        img.add(0, data[start:end], True)  # load module at linear 0, segment values as in the file
        return img, [(cs * 16 + ip) & 0xFFFFF]


def _mz_kind(data):
    """'PE', 'NE', 'LE', 'LX' or 'DOS' for a file starting with MZ."""
    if len(data) >= 0x40:
        reloc_off = struct.unpack_from("<H", data, 0x18)[0]
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        sig = data[lfanew:lfanew + 4] if lfanew + 4 <= len(data) else b""
        if sig == b"PE\0\0":
            return "PE"
        if reloc_off >= 0x40 and sig[:2] in (b"NE", b"LE", b"LX"):
            return sig[:2].decode()
    return "DOS"


# ------------------------------------------------------------------ analyzer
class Analyzer:
    def __init__(self, image, bits=None):
        self.img = image
        self.m = Mode(bits or getattr(image, "bits", 32))
        self.bits = self.m.bits
        self.cs = Cs(CS_ARCH_X86, _CS_MODE[self.bits])
        self.cs.detail = True
        self._insn = {}
        self._items = {}
        self._purge = {}
        self._sig = {}
        self._code = set()      # every instruction address reached by collect()
        self._leaders = set()   # function starts, branch targets, and fall-throughs after branches
        self._api_purge = {}    # "dll!func" -> bytes popped, learned from balanced functions
        self._call_fix = {}     # call address -> bytes popped, corrected by stack balancing
        self._succ = {}         # successors() cache, so every pass sees the same graph
        self._visited = set()   # every address collect() has walked so far
        self._returns = {}      # function start -> False if it can never return
        self._busy = set()      # functions whose "returns?" question is being answered
        self._sp_eff = {}       # function start -> net stack change at its rets (None = unknown)
        self._sp_busy = set()
        self._fx = {}           # instruction -> constant esp change (ebp untouched), or _COMPLEX
        self._exit = {}         # instruction -> is a ret that leaves the function

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

    def norm(self, name):
        return norm_reg(name, self.bits)

    def rname(self, reg_id):
        return self.norm(self.cs.reg_name(reg_id)) if reg_id else None

    @staticmethod
    def asm(i):
        return (i.mnemonic + " " + i.op_str).strip()

    def direct_target(self, i):
        """Target of a direct jmp/jcc/call, else None. 16-bit far jumps/calls (seg:off)
        resolve to the linear address seg*16 + off."""
        ops = i.operands
        if not ops or ops[0].type != CS_OP_IMM:
            return None
        if i.mnemonic in ("lcall", "ljmp"):
            if self.bits == 16 and len(ops) == 2 and ops[1].type == CS_OP_IMM:
                return ((ops[0].imm & 0xFFFF) * 16 + (ops[1].imm & 0xFFFF)) & 0xFFFFF
            return None
        return ops[0].imm & self.m.mask

    def is_reg(self, i, idx, name):
        return (len(i.operands) > idx and i.operands[idx].type == CS_OP_REG
                and self.rname(i.operands[idx].reg) == name)

    def mem_addr(self, i, op):
        """Absolute address of a memory operand with no registers (or rip-relative), else None."""
        m = op.mem
        if m.index:
            return None
        if m.base:
            if self.cs.reg_name(m.base) != "rip":
                return None
            return (i.address + i.size + m.disp) & self.m.mask
        return m.disp & self.m.mask

    # ---- control flow ---------------------------------------------------
    def successors(self, ea):
        if ea in self._succ:
            return self._succ[ea]
        i = self.insn(ea)
        out = []
        if i is None or i.mnemonic in ("hlt", "ud2", "int3") or self._terminates(i):
            pass
        elif i.group(CS_GRP_RET):
            t = self.push_ret_target(ea)  # push addr; ret = jump to addr
            if t is not None:
                out.append(t)
        elif i.group(CS_GRP_JUMP):
            t = self.direct_target(i)
            if t is not None:
                out.append(t)
            if i.mnemonic not in ("jmp", "ljmp"):
                out.append(ea + i.size)
        elif i.group(CS_GRP_CALL):
            t = self.getpc_target(ea)
            if t is not None:  # call $+5 / call L; L: pop = push of its own address + jump
                out.append(t)
            elif self.call_returns(ea):
                out.append(ea + i.size)
        else:
            out.append(ea + i.size)
        out = [s for s in dict.fromkeys(out) if self.insn(s) is not None]
        if i is not None:
            self._succ[ea] = out
        return out

    def dests(self, itemset, ea):
        return [s for s in self.successors(ea) if s in itemset]

    def _terminates(self, i):
        """int 29h (__fastfail) in 32/64-bit; int 20h and int 21h with AH=4Ch in DOS code."""
        if i.mnemonic != "int" or not i.operands or i.operands[0].type != CS_OP_IMM:
            return False
        n, a = i.operands[0].imm & 0xFF, i.address
        if self.bits != 16:
            return n == 0x29
        if n == 0x20:
            return True
        if n == 0x21:
            if (a - 2) in self._visited and self.img.read(a - 2, 2) == b"\xb4\x4c":  # mov ah, 4Ch
                return True
            r = self.img.read(a - 3, 3)  # mov ax, 4Cxxh
            return (a - 3) in self._visited and len(r) == 3 and r[0] == 0xB8 and r[2] == 0x4C
        return False

    def push_ret_target(self, ea):
        """Target of `push imm; ret` (a jump disguised as a return), else None."""
        i = self.insn(ea)
        if i is None or i.mnemonic != "ret" or i.operands or self.bits == 16:
            return None
        p = ea - 5
        if p not in self._visited:
            return None
        j = self.insn(p)
        if (j is None or j.mnemonic != "push" or j.size != 5 or not j.operands
                or j.operands[0].type != CS_OP_IMM):
            return None
        t = j.operands[0].imm & self.m.mask
        return t if self.insn(t) is not None else None

    def getpc_target(self, ea):
        """For a call that pushes its own return address as data instead of calling a function
        (`call $+5`, or `call L` where L starts with `pop`): the call target. Else None."""
        i = self.insn(ea)
        if i is None or not i.group(CS_GRP_CALL) or i.mnemonic == "lcall":
            return None
        t = self.direct_target(i)
        if t is None:
            return None
        ti = self.insn(t)
        if ti is None:
            return None
        return t if t == ea + i.size or ti.mnemonic == "pop" else None

    def call_returns(self, ea):
        """False for a call that never comes back (ExitProcess, abort, an internal function
        with no way to return)."""
        name = self.call_name(ea)
        if name:
            return not _api_noreturn(name)
        t = self.direct_target(self.insn(ea))
        if t is None or self.insn(t) is None:
            return True
        return self.func_returns(t)

    def func_returns(self, t):
        """False if no path through the function at t can return: every exit is a call that
        never returns, hlt/ud2/int 29h, or an endless loop. Unknown cases count as returning."""
        if t in self._returns:
            return self._returns[t]
        if t in self._busy or len(self._busy) > 40:  # recursion / very deep call chains
            return True
        self._busy.add(t)
        try:
            res = False
            for a in self.collect(t):
                if self.successors(a):
                    continue
                i = self.insn(a)
                if i.mnemonic in ("hlt", "ud2") or self._terminates(i):
                    continue
                if (i.group(CS_GRP_CALL) or i.group(CS_GRP_JUMP)) and _api_noreturn(self.call_name(a)):
                    continue
                if i.group(CS_GRP_CALL) and not self.call_returns(a):
                    continue
                res = True  # ret, indirect jump, int3, or code we can't decode
                break
        finally:
            self._busy.discard(t)
        self._returns[t] = res
        return res

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
            self._visited.add(a)
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
                    if i.group(CS_GRP_CALL) and self.getpc_target(a) is None:
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

    def _iat_slot(self, i, op):
        if op.type == CS_OP_MEM:
            a = self.mem_addr(i, op)
            if a is not None and a in self.img.imports:
                return a
        return None

    def _regs_written(self, i):
        try:
            return [self.norm(self.cs.reg_name(r)) for r in i.regs_access()[1]]
        except Exception:
            return []

    def _touches_sp(self, i):
        try:
            read, written = i.regs_access()
        except Exception:
            return False
        return any(self.norm(self.cs.reg_name(r)) == self.m.sp for r in list(read) + list(written))

    def call_name(self, ea):
        """'dll!func' for a call through the IAT: call [IAT], mov reg,[IAT] + call reg,
        or a call to a `jmp [IAT]` thunk. None otherwise."""
        i = self.insn(ea)
        if not i.operands:
            return None
        op = i.operands[0]
        slot = self._iat_slot(i, op)
        if slot is not None:
            return self.img.imports[slot]
        if op.type == CS_OP_IMM:
            tea = self.direct_target(i)
            t = self.insn(tea) if tea is not None else None
            if t is not None and t.mnemonic == "jmp" and t.operands:
                slot = self._iat_slot(t, t.operands[0])
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
                        slot = self._iat_slot(j, j.operands[1])
                        if slot is not None:
                            return self.img.imports[slot]
                    break
        return None

    def _block_before(self, ea, limit=40):
        """Instructions before ea in the same basic block, nearest first, stopping at
        control flow."""
        out, a = [], ea
        while len(out) < limit and a not in self._leaders:
            p = self._prev(a)
            if p is None:
                break
            j = self.insn(p)
            if j.group(CS_GRP_CALL) or j.group(CS_GRP_JUMP) or j.group(CS_GRP_RET):
                break
            out.append(j)
            a = p
        return out

    def _guess_call_x64(self, ea):
        """x64 opaque call: caller cleans up. Register args = highest of rcx, rdx, r8, r9
        written in the block before the call (and all lower ones); stack args = stores to
        [rsp + 0x20 + 8k] in the same block."""
        regs = self.m.arg_regs
        highest, slots = -1, set()
        for j in self._block_before(ea):
            if self.m.sp in self._regs_written(j):
                break  # rsp moved: earlier stores are not relative to the call's rsp
            for r in self._regs_written(j):
                if r in regs:
                    highest = max(highest, regs.index(r))
            if j.mnemonic.startswith("mov") and j.operands and j.operands[0].type == CS_OP_MEM:
                mm = j.operands[0].mem
                if self.rname(mm.base) == "rsp" and not mm.index and mm.disp >= self.m.arg_area:
                    slots.add((mm.disp - self.m.arg_area) // 8)
        nstack = 0
        while nstack in slots and nstack < 16:  # only a run of slots starting at [rsp+0x20]
            nstack += 1
        return regs[:highest + 1], nstack

    def guess_call(self, ea):
        """(bytes popped by callee, number of stack args, caller_cleans) for an opaque call.
        `add esp, N` right after the call means the caller cleans up (cdecl); otherwise
        assume stdcall and count the pushes right before the call in the same block."""
        w = self.m.word
        if not self.m.callee_pops:
            return 0, self._guess_call_x64(ea)[1], True
        i = self.insn(ea)
        a = ea + i.size
        for _ in range(6):  # the cleanup may come a few instructions later: call f; mov edi, eax; add esp, 4
            nxt = self.insn(a)
            if nxt is None:
                break
            if (nxt.mnemonic == "add" and self.is_reg(nxt, 0, self.m.sp)
                    and len(nxt.operands) > 1 and nxt.operands[1].type == CS_OP_IMM):
                return 0, max(0, sx(nxt.operands[1].imm, self.bits)) // w, True
            if (nxt.group(CS_GRP_CALL) or nxt.group(CS_GRP_JUMP) or nxt.group(CS_GRP_RET)
                    or nxt.mnemonic in ("int3", "hlt") or self._touches_sp(nxt)):
                break
            a += nxt.size
        n, a = 0, ea
        while n < 16 and a not in self._leaders:
            p = self._prev(a)
            if p is None:
                break
            j = self.insn(p)
            if j.mnemonic == "push":
                n += 1
            elif (j.group(CS_GRP_CALL) or j.group(CS_GRP_JUMP) or j.group(CS_GRP_RET)
                  or self._touches_sp(j)):
                break
            a = p
        return w * n, n, False

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
        if self.getpc_target(ea) is not None:
            return 0, 0, []
        if not self.is_opaque_call(ea):
            t = self.direct_target(i)
            regs, n = self.callee_signature(t)
            if self.bits == 64:  # wrappers pass registers through: also trust the caller's setup
                cregs, cn = self._guess_call_x64(ea)
                regs, n = max(regs, cregs, key=len), max(n, cn)
            return (self.callee_purge(t) if self.m.callee_pops else 0), n, regs
        if not self.m.callee_pops:
            regs, n = self._guess_call_x64(ea)
            return 0, n, regs
        purge, n, caller_cleans = self.guess_call(ea)
        if not caller_cleans:
            name = self.call_name(ea)
            if overrides and ea in overrides:
                purge = overrides[ea]
            elif ea in self._call_fix:
                purge = self._call_fix[ea]
            elif name in self._api_purge:
                purge = self._api_purge[name]
            n = purge // self.m.word
        return purge, n, []

    def _push_size(self, i):
        """Bytes pushed/popped by push/pop (a 16-bit `push ax` in 32-bit code moves 2)."""
        if i.operands:
            op = i.operands[0]
            if op.type == CS_OP_REG and self.cs.reg_name(op.reg) in _SEGMENT:
                return self.m.word
            if op.size in (2, 4, 8):
                return op.size
        return self.m.word

    def _frame_value(self, op, esp, ebp):
        """Value of [sp/bp + disp] as a stack offset, for a lea source operand."""
        if op.type != CS_OP_MEM or op.mem.index:
            return None
        b = self.rname(op.mem.base)
        bv = esp if b == self.m.sp else ebp if b == self.m.bp else None
        return None if bv is None else bv + sx(op.mem.disp, 32)

    def _sp_value(self, ea, i, esp, ebp):
        """New stack offset for `mov esp, ebp`, `lea esp, [ebp - N]`, or
        `lea r11, [rsp + N]` ... `mov rsp, r11` in the same block. None if unknown."""
        if len(i.operands) < 2:
            return None
        src = i.operands[1]
        if i.mnemonic == "lea":
            return self._frame_value(src, esp, ebp)
        if src.type != CS_OP_REG:
            return None
        reg = self.rname(src.reg)
        if reg == self.m.bp:
            return ebp
        for j in self._block_before(ea):
            if reg in self._regs_written(j):
                if j.mnemonic == "lea" and len(j.operands) == 2:
                    return self._frame_value(j.operands[1], esp, ebp)
                return None
            if self.m.sp in self._regs_written(j):
                return None
        return None

    def change_stack(self, ea, esp, ebp, overrides=None):
        """(esp, ebp) after the instruction at ea. None = unknown: any write to esp/ebp
        that isn't modelled makes it unknown instead of silently keeping the old value.
        A known ebp can bring esp back (mov esp, ebp / leave)."""
        if overrides and ea in overrides:  # trial pop count for an opaque call (_balance)
            return (None if esp is None else esp + overrides[ea]), ebp
        fx = self._fx.get(ea)
        if fx is None:
            fx = self._fx[ea] = self._fixed_effect(ea)
        if fx is not _COMPLEX:
            return (None if esp is None else esp + fx), ebp
        return self._change_stack(ea, esp, ebp, overrides)

    def _fixed_effect(self, ea):
        """The esp change of an instruction whose effect doesn't depend on the current
        esp/ebp and leaves ebp alone (push, pop, add esp, N, most calls, ordinary
        instructions); _COMPLEX otherwise. Cached: stack passes run many times."""
        i = self.insn(ea)
        m, sp, bp = i.mnemonic, self.m.sp, self.m.bp
        if m in ("push", "pop") and not (self.is_reg(i, 0, sp) or self.is_reg(i, 0, bp)):
            return self._push_size(i) * (1 if m == "pop" else -1)
        if i.group(CS_GRP_CALL) and self._alloca_size(ea) is None:
            if self.getpc_target(ea) is not None:
                return -self.m.word
            return self.call_effect(ea)[0] if self.m.callee_pops else 0
        if m == "leave" or m == "enter" or m in ("push", "pop") or i.group(CS_GRP_CALL):
            return _COMPLEX
        if m.startswith(("pusha", "popa", "pushf", "popf")) or i.group(CS_GRP_RET):
            return _COMPLEX if m.startswith("popa") else self._change_stack(ea, 0, 0)[0]
        written = self._regs_written(i)
        if sp in written or bp in written:
            return _COMPLEX
        return 0

    def _change_stack(self, ea, esp, ebp, overrides=None):
        i = self.insn(ea)
        m, w, sp, bp = i.mnemonic, self.m.word, self.m.sp, self.m.bp

        def add(x, d):
            return None if x is None or d is None else x + d

        if m == "leave":
            return add(ebp, w), None
        if m == "enter":
            size = i.operands[0].imm & 0xFFFF if i.operands else 0
            level = i.operands[1].imm & 0x1F if len(i.operands) > 1 else 0
            nbp = add(esp, -w)
            return add(nbp, -(w * level + size)), nbp
        if m == "pop":
            if self.is_reg(i, 0, sp):  # pop esp
                return None, ebp
            return add(esp, self._push_size(i)), (None if self.is_reg(i, 0, bp) else ebp)
        if m == "push":
            return add(esp, -self._push_size(i)), ebp
        if m.startswith("pusha"):
            return add(esp, -8 * w), ebp
        if m.startswith("popa"):
            return add(esp, 8 * w), None  # popa reloads ebp
        if m.startswith("pushf"):
            return add(esp, -w), ebp
        if m.startswith("popf"):
            return add(esp, w), ebp
        if i.group(CS_GRP_RET):  # only matters for push/ret jumps
            return add(esp, w), ebp
        if i.group(CS_GRP_CALL):
            if self.getpc_target(ea) is not None:
                return add(esp, -w), ebp
            if not self.m.callee_pops:  # x64: callee never pops arguments
                return esp, ebp
            probe = self._alloca_size(ea)
            if probe is not None:
                return add(esp, -probe), ebp
            return add(esp, self.call_effect(ea, overrides)[0]), ebp
        if m == "mov" and self.is_reg(i, 0, bp) and self.is_reg(i, 1, sp):
            return esp, esp
        if m == "lea" and self.is_reg(i, 0, bp) and len(i.operands) == 2:  # lea ebp, [esp + N]
            return esp, self._frame_value(i.operands[1], esp, ebp)
        if m in ("mov", "lea") and self.is_reg(i, 0, sp):  # esp restored: mov esp, ebp / lea esp, [..]
            return self._sp_value(ea, i, esp, ebp), ebp
        if (m in ("add", "sub") and self.is_reg(i, 0, sp)
                and len(i.operands) > 1 and i.operands[1].type == CS_OP_IMM):
            imm = sx(i.operands[1].imm, 8 * i.operands[0].size)
            return add(esp, imm if m == "add" else -imm), ebp
        if (m in ("add", "sub") and self.is_reg(i, 0, sp)
                and len(i.operands) > 1 and i.operands[1].type == CS_OP_REG):
            imm = self._reg_const(ea, self.rname(i.operands[1].reg))
            return add(esp, None if imm is None else imm if m == "add" else -imm), ebp
        written = self._regs_written(i)
        return (None if sp in written else esp), (None if bp in written else ebp)

    def _alloca_size(self, ea):
        """Bytes a 32/16-bit stack-probe call (`mov eax, N; call __chkstk`) moves esp down:
        the callee itself lowers esp by eax, so its own stack doesn't balance. None otherwise."""
        if self.bits == 64 or self.is_opaque_call(ea):
            return None
        i = self.insn(ea)
        nxt = self.insn(ea + i.size)
        if nxt is not None and nxt.mnemonic == "sub" and self.is_reg(nxt, 0, self.m.sp):
            return None  # caller moves esp itself (mingw ___chkstk_ms)
        v = self._reg_const(ea, self.m.ax)
        if v is None or not 0x1000 <= v <= 0x1000000:
            return None
        if self._sp_effect(self.direct_target(i)) is not None:
            return None
        return v

    def _sp_effect(self, t):
        """Net stack change of the function at t when it reaches a ret: 0 if every ret is
        balanced, None if unknown or unbalanced."""
        if t in self._sp_eff:
            return self._sp_eff[t]
        if t in self._sp_busy:
            return 0
        self._sp_busy.add(t)
        try:
            items = self.collect(t)
            state, _ = self._stack_pass(t, items, {}, join=True)
            vals = {state[a][0] for a in items if a in state and self._is_exit_ret(a)}
            res = 0 if vals == {0} else None
        finally:
            self._sp_busy.discard(t)
        self._sp_eff[t] = res
        return res

    def _is_exit_ret(self, ea):
        if ea not in self._exit:
            i = self.insn(ea)
            self._exit[ea] = i is not None and i.group(CS_GRP_RET) and not self.successors(ea)
        return self._exit[ea]

    def _reg_const(self, ea, reg):
        """Constant in reg at ea from a nearby `mov reg, imm`, looking through one call
        (the `mov eax, N; call __chkstk; sub rsp, rax` pattern). None if unknown."""
        a, calls = ea, 0
        for _ in range(4):
            a = self._prev(a)
            if a is None:
                return None
            j = self.insn(a)
            if j.group(CS_GRP_CALL) and calls == 0:
                calls += 1
                continue
            if reg in self._regs_written(j):
                if (j.mnemonic == "mov" and len(j.operands) == 2
                        and j.operands[1].type == CS_OP_IMM):
                    return j.operands[1].imm & 0xFFFFFFFF
                return None
            if j.group(CS_GRP_JUMP) or j.group(CS_GRP_RET) or j.group(CS_GRP_CALL):
                return None
        return None

    def _stack_pass(self, start, items, overrides, join=False):
        """One stack-height propagation. Returns (state, problems).
        join=False: the first height to reach an instruction wins; problems are
          ('merge', ea, esp_a, esp_b) and ('ret', ea, esp, 0). Used to score fixes.
        join=True: where paths disagree the height becomes unknown (None) from there on, so
          no wrong stk_N names are produced; problems are ('merge', ea, {pred: esp}) and
          ('ret', ea, esp, 0)."""
        itemset, state, problems = set(items), {}, []
        arrive = {}  # join: ea -> {predecessor: first known esp it delivered}
        work = [(start, 0, None, None)]
        while work:
            ea, esp, ebp, pred = work.pop()
            if join and pred is not None and esp is not None:
                arrive.setdefault(ea, {}).setdefault(pred, esp)
            if ea in state:
                oesp, oebp = state[ea]
                if not join:
                    if esp is not None and oesp is not None and oesp != esp:
                        problems.append(("merge", ea, oesp, esp))
                    continue
                new = (oesp if oesp == esp else None, oebp if oebp == ebp else None)
                if new == (oesp, oebp):
                    continue
                state[ea] = new
            else:
                state[ea] = (esp, ebp)
            nesp, nebp = self.change_stack(ea, state[ea][0], state[ea][1], overrides)
            for d in self.dests(itemset, ea):
                work.append((d, nesp, nebp, ea))
        if join:
            for ea in sorted(arrive):
                if len(set(arrive[ea].values())) > 1:
                    problems.append(("merge", ea, arrive[ea]))
        for ea in items:
            if ea in state and state[ea][0] not in (0, None) and self._is_exit_ret(ea):
                problems.append(("ret", ea, state[ea][0], 0))
        return state, problems

    def _balance(self, start, items, problems):
        """Find pop counts for opaque calls (see guess_call) that make every path agree and
        every ret balance. Greedy: each round applies the single change that removes the
        most problems, so a function with several mis-guessed calls (e.g. cdecl calls whose
        cleanup the compiler merged into one later `add esp, N`) can still be fixed.
        Returns {call address: bytes popped}, or None if no full balance was found."""
        w = self.m.word
        calls = [c for c in items if self.is_opaque_call(c) and self.successors(c)
                 and not self.guess_call(c)[2]]
        if not calls:
            return None
        overrides, budget = {}, 600
        for _ in range(6):
            deltas = []
            for _, _, a, b in problems:
                deltas += [a - b, b - a]
            deltas = list(dict.fromkeys(deltas))
            best = None
            for c in calls:
                base = self.call_effect(c, overrides)[0]
                for v in dict.fromkeys([base + d for d in deltas] + [0]):
                    if v == base or v < 0 or v > 16 * w or v % w:
                        continue
                    if budget <= 0:
                        return None
                    budget -= 1
                    trial = dict(overrides)
                    trial[c] = v
                    _, pr = self._stack_pass(start, items, trial)
                    if not pr:
                        return trial
                    if best is None or len(pr) < len(best[1]):
                        best = (trial, pr)
            if best is None or len(best[1]) >= len(problems):
                return None
            overrides, problems = best
        return None

    def stack_states(self, start, items):
        """Stack heights per instruction, plus warnings/notes for the reader.
        If the heights don't balance, first try correcting the pop counts of opaque calls
        (see _balance); whatever still disagrees becomes unknown (stk_?)."""
        _, problems = self._stack_pass(start, items, {})
        notes = []
        if problems and self.m.callee_pops:
            fix = self._balance(start, items, problems)
            if fix:
                self._fx.clear()  # cached call effects change with the new pop counts
                for c, v in sorted(fix.items()):
                    self._call_fix[c] = v
                    name = self.call_name(c)
                    if name:  # reuse at every other call site of this API
                        self._api_purge[name] = v
                notes.append("note: to balance the stack, assumed %s"
                             % ", ".join("the call at 0x%x pops %d bytes" % cv
                                         for cv in sorted(fix.items())))
        state, problems = self._stack_pass(start, items, {}, join=True)
        sp, bp = self.m.sp, self.m.bp
        merges = [p for p in problems if p[0] == "merge"]
        rets = [p for p in problems if p[0] == "ret"]
        parts = []
        if merges:
            _, ea, arr = merges[0]
            s = ("stack height unknown from 0x%x (paths arrive with different %s: %s)"
                 % (ea, sp, ", ".join("%+d from 0x%x" % (v, p) for p, v in sorted(arr.items()))))
            if len(merges) > 1:
                more = ["0x%x" % p[1] for p in merges[1:]]
                s += " and at %d more place%s (%s%s)" % (len(more), "s" * (len(more) > 1),
                                                        ", ".join(more[:3]), ", ..." * (len(more) > 3))
            parts.append(s + "; %s-based slots there are shown as stk_?(%s+N)" % (sp, sp))
        if rets:
            parts.append("stack not balanced at ret %s; stk_N names in this function may be off"
                         % ", ".join("0x%x (%s = %+d, expected 0)" % (p[1], sp, p[2]) for p in rets[:3]))
        warnings = ["WARNING: " + "; ".join(parts)] if parts else []
        lost = [ea for ea in items if ea in state and state[ea][0] is not None
                and self.change_stack(ea, *state[ea])[0] is None]
        if lost:
            i = self.insn(lost[0])
            notes.append("note: %s unknown after 0x%x (%s), which sets %s in a way this tool "
                         "doesn't follow; %s-based slots after it are shown as stk_?(%s+N)%s"
                         % (sp, lost[0], self.asm(i), sp, sp, sp,
                            ", %s-based ones keep their names" % bp if state[lost[0]][1] is not None else ""))
        return state, warnings + notes

    # ---- memory operand naming (Lab 3 memoryGetName + Lab 4 mem_address) --
    def mem_name(self, op, esp, ebp, i=None):
        m = op.mem
        seg = self.cs.reg_name(m.segment) if m.segment else None
        prefix = seg + ":" if seg in ("fs", "gs") else ""
        if m.base and self.cs.reg_name(m.base) == "rip" and not m.index:
            if i is not None:
                return "%smem_0x%x" % (prefix, (i.address + i.size + m.disp) & self.m.mask), []
            return "%s[rip + 0x%x]" % (prefix, m.disp), []
        base, index = self.rname(m.base), self.rname(m.index)
        regs = [r for r in (base, index) if r]
        disp = sx(m.disp, 64) if self.bits == 64 else s32(m.disp)
        if not regs:  # 16-bit: an offset inside the data segment
            return "%smem_0x%x" % (prefix, disp & (0xFFFF if self.bits == 16 else self.m.mask)), regs
        if base in (self.m.sp, self.m.bp) and not index:
            baseval = esp if base == self.m.sp else ebp
            if baseval is not None:
                return "stk_%d" % (baseval + disp), regs
            if base == self.m.sp:  # stack slot, but tracking was lost: say so
                return "stk_?(%s%s)" % (base, "" if not disp else "%s0x%x" % ("+-"[disp < 0], abs(disp))), regs
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
        sp, bp, w = self.m.sp, self.m.bp, self.m.word

        if base_m == "nop":  # multi-byte nops have a memory operand but touch nothing
            return [], []
        if base_m in ("stosq", "stosd", "stosw", "stosb"):  # edge case from the plugins
            di = self.m.di
            d, u = ["[%s]" % di, di], [self.m.ax, di]
            if m.startswith("rep") or X86_PREFIX_REP in i.prefix or X86_PREFIX_REPNE in i.prefix:
                d.append(self.m.cx)
                u.append(self.m.cx)
            return d, u

        d, u = [], []
        for op in i.operands:
            if op.type == CS_OP_MEM:
                name, regs = self.mem_name(op, esp, ebp, i)
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
            add_unique(u, self.norm(self.cs.reg_name(r)))
        for r in written:
            add_unique(d, self.norm(self.cs.reg_name(r)))

        # implicit stack-slot effects
        if base_m == "pop":
            add_unique(d, sp)
            add_unique(u, sp)
            if esp is not None:
                add_unique(u, "stk_%d" % esp)
        elif base_m == "push":
            add_unique(d, sp)
            add_unique(u, sp)
            if esp is not None:
                add_unique(d, "stk_%d" % (esp - self._push_size(i)))
        elif i.group(CS_GRP_RET):
            add_unique(d, sp)
            add_unique(u, sp)
            if esp is not None and self.push_ret_target(ea) is not None:
                add_unique(u, "stk_%d" % esp)
        elif base_m.startswith("leave"):
            add_unique(d, bp)
            add_unique(u, bp)
            add_unique(d, sp)
            if ebp is not None:
                add_unique(u, "stk_%d" % ebp)
        elif i.group(CS_GRP_CALL) and self.getpc_target(ea) is not None:
            add_unique(d, sp)  # pushes its own address, calls nothing
            add_unique(u, sp)
            if esp is not None:
                add_unique(d, "stk_%d" % (esp - w))
        elif i.group(CS_GRP_CALL):
            add_unique(d, sp)
            add_unique(u, sp)
            add_unique(d, self.m.ax)
            _, nstack, regs = self.call_effect(ea)
            for r in regs:
                add_unique(u, r)
            if esp is not None:
                for k in range(nstack):
                    add_unique(u, "stk_%d" % (esp + self.m.arg_area + w * k))
        return d, u

    def callee_signature(self, t):
        """Heuristic stand-in for IDA's prototype lookup.
        Returns (register args, number of stack args).
          * argument registers (32-bit: ecx/edx for thiscall/fastcall; 64-bit: rcx, rdx,
            r8, r9) count if the callee reads them before writing them, scanning
            straight-line code until control flow.
          * stack args = `ret N` / word size, else the highest frame-pointer argument slot
            touched ([ebp+8+4k] in 32-bit; cap 16).
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
            for r in self.m.arg_regs:
                if r in defined:
                    continue
                if r in u and not zero_idiom:
                    regs.append(r)
                    defined.add(r)
                elif r in d or zero_idiom:
                    defined.add(r)
            a += i.size
        if self.bits == 64:  # keep rcx, rdx, r8, r9 in order, filling gaps
            regs = self.m.arg_regs[:max([self.m.arg_regs.index(r) + 1 for r in regs] or [0])]
        w = self.m.word
        first_arg = 2 * w + (self.m.arg_area if self.bits == 64 else 0)  # saved bp + return addr
        nstack = self.callee_purge(t) // w if self.m.callee_pops else 0
        if self.bits != 32 and nstack == 0:
            # stack args sit above the return address: x64 stk_40 (after the shadow space),
            # 16-bit stk_2 (near) or stk_4 (far, retf)
            items = self.collect(t)
            far = any(self.insn(x).mnemonic == "retf" for x in items)
            lowest = w + self.m.arg_area + (2 if far else 0)
            state, _ = self._stack_pass(t, items, {}, join=True)
            for x in items:
                for op in self.insn(x).operands:
                    if op.type == CS_OP_MEM:
                        off = self._frame_value(op, *state.get(x, (None, None)))
                        if off is not None and off >= lowest:
                            nstack = max(nstack, (off - lowest) // w + 1)
        elif nstack == 0:
            for x in self.collect(t):
                for op in self.insn(x).operands:
                    if (op.type == CS_OP_MEM and self.rname(op.mem.base) == self.m.bp
                            and not op.mem.index and sx(op.mem.disp, 32) >= first_arg):
                        nstack = max(nstack, (sx(op.mem.disp, 32) - first_arg) // w + 1)
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

    def about(self, start, items, stack, warnings):
        """One-line summary of the function for the reader: frame, arguments, how it ends,
        and anything unusual about its stack or control flow."""
        sp, bp, w = self.m.sp, self.m.bp, self.m.word
        out, odd = [], []
        framed = False
        for ea in items:
            i = self.insn(ea)
            if ((i.mnemonic == "mov" and self.is_reg(i, 0, bp) and self.is_reg(i, 1, sp))
                    or (i.mnemonic == "lea" and self.is_reg(i, 0, bp)) or i.mnemonic == "enter"):
                framed = stack.get(ea, (None,))[0] is not None
                break
        out.append("%s frame" % bp if framed else "no frame pointer (%s-based)" % sp)
        regs, nstack = self.callee_signature(start)
        purge = self.callee_purge(start) if self.m.callee_pops else 0
        if purge:
            out.append("callee pops %d bytes of args (ret %d)" % (purge, purge))
        elif nstack:
            out.append("reads %d stack arg%s" % (nstack, "s" * (nstack > 1)))
        if regs:
            out.append("register args: %s" % ", ".join(regs))
        exits = [ea for ea in items if not self.successors(ea)]
        rets = [ea for ea in exits if self.insn(ea).group(CS_GRP_RET)]
        noret = [ea for ea in exits if self.insn(ea).group(CS_GRP_CALL)]
        indirect = [ea for ea in items if self.insn(ea).group(CS_GRP_JUMP)
                    and self.direct_target(self.insn(ea)) is None and not self.call_name(ea)]

        def where(eas):
            return ", ".join("0x%x" % a for a in eas[:3]) + (", ..." if len(eas) > 3 else "")

        def callee(ea):
            return self.call_name(ea) or "0x%x" % (self.direct_target(self.insn(ea)) or 0)

        tails = [ea for ea in exits if self.insn(ea).group(CS_GRP_JUMP) and self.call_name(ea)]
        if rets:
            out.append("returns")
        elif tails and len(items) <= 2:
            out.append("thunk: jumps to %s" % self.call_name(tails[0]))
        elif tails and not noret:
            out.append("ends by jumping to %s" % self.call_name(tails[0]))
        elif noret:
            out.append("never returns (ends in call to %s)" % callee(noret[0]))
        elif indirect:
            out.append("no ret; leaves through an indirect jump")
        elif not exits:
            out.append("never returns (endless loop)")
        else:
            out.append("no ret")
        if rets and noret:
            out.append("some paths end in %s" % ", ".join(dict.fromkeys(callee(a) for a in noret)))
        getpc = [ea for ea in items if self.getpc_target(ea) is not None]
        if getpc:
            odd.append("call/pop reads its own address at %s" % where(getpc))
        pushret = [ea for ea in items if self.push_ret_target(ea) is not None]
        if pushret:
            odd.append("push/ret used as a jump at %s" % where(pushret))
        direct = [ea for ea in items if self.m.sp in self._regs_written(self.insn(ea))
                  and stack.get(ea, (None,))[0] is not None
                  and self.change_stack(ea, *stack[ea])[0] is None]
        if direct:
            odd.append("sets %s directly at %s (%s)" % (sp, where(direct), self.asm(self.insn(direct[0]))))
        if indirect:
            odd.append("indirect jump%s at %s (jump table or computed jump)"
                       % ("s" * (len(indirect) > 1), where(indirect)))
        if any(x.startswith("WARNING: stack height unknown") for x in warnings):
            odd.append("paths reach the same code with different stack heights")
        s = "; ".join(out)
        if odd:
            s += ". Unusual: " + "; ".join(odd)
        return s

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
            "bits": self.bits,
            "about": self.about(start, items, stack, warnings),
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
            "about": fn.get("about", ""),
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


TEXT_LEGEND = Mode(32).legend()  # kept for older imports; to_text picks the right one


def to_text(funcs, max_instructions=None, legend=False):
    """Compact, LLM-friendly listing. Stops after max_instructions (total) and says so."""
    bits = funcs[0].get("bits", 32) if funcs else 32
    lines = [Mode(bits).legend(), ""] if legend else []
    total = sum(len(fn["instructions"]) for fn in funcs)
    shown = 0
    for fn in funcs:
        if max_instructions is not None and shown >= max_instructions:
            break
        by_ea = {ins["ea"]: ins for ins in fn["instructions"]}
        names = {b["start"]: "B%d" % k for k, b in enumerate(fn["blocks"])}
        lines.append("function 0x%x  (%d instructions, %d blocks)" %
                     (fn["entry"], len(by_ea), len(fn["blocks"])))
        if fn.get("about"):
            lines.append("  about: " + fn["about"])
        for w in fn.get("warnings", []):
            lines.append("  " + w)
        for b in fn["blocks"]:
            if max_instructions is not None and shown >= max_instructions:
                break
            last = by_ea[b["instructions"][-1]]["asm"]
            end = "none (call does not return)" if last.startswith(("call", "lcall")) else "none (exit)"
            succ = ", ".join("%s(0x%x)" % (names[s], s) for s in b["successors"]) or end
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


def parse_bits(v):
    """None/'auto' -> None; otherwise 16, 32 or 64."""
    if v is None or str(v).strip().lower() in ("", "auto"):
        return None
    b = int(str(v).strip().lower().replace("bit", "").replace("-", ""))
    if b not in BITS:
        raise ValueError("bits must be 16, 32 or 64")
    return b


def run(data, base=0x401000, entries=None, fmt="text", mode="both", sweep=False, bits=None):
    img, default_entries = Image.from_bytes(data, base, bits)
    entries = [parse_addr(e) for e in entries] if entries else default_entries
    funcs = Analyzer(img).analyze(entries, sweep)
    if not funcs:
        raise ValueError("No decodable code at the entry point(s) %s" % [hex(e) for e in entries])
    return render(funcs, fmt, mode)
