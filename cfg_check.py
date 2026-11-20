#!/usr/bin/env python3
"""Developer check: analyze every function in a set of samples and report stack warnings.

No LLM, no network, and it never runs the samples, only reads their bytes.

Examples:
  python cfg_check.py samples/                 # every PE file under samples/ (recursive)
  python cfg_check.py a.exe b.dll -v           # also print each warning
  python cfg_check.py raw.bin --base 0x10000   # raw code (files given by name only)
  python cfg_check.py prog.com --bits 16 --base 0x100
  python cfg_check.py a.exe --stack-trace 0x403365   # per-instruction stack heights of one function
"""
import argparse
import hashlib
import os
import sys

from cfg_core import Analyzer, Image, parse_addr, parse_bits


def iter_files(paths):
    """Files named directly are always checked; inside folders only PE (MZ) files are."""
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    f = os.path.join(root, n)
                    try:
                        with open(f, "rb") as fh:
                            if fh.read(2) == b"MZ":
                                yield f
                    except OSError:
                        pass
        else:
            yield p


def check(path, base, sweep, bits=None):
    with open(path, "rb") as f:
        data = f.read()
    img, entries = Image.from_bytes(data, base, bits)
    an = Analyzer(img)
    funcs = an.analyze(entries, sweep)
    warn = [(fn["entry"], w) for fn in funcs for w in fn["warnings"] if w.startswith("WARNING")]
    notes = sum(1 for fn in funcs for w in fn["warnings"] if w.startswith("note: to balance"))
    return hashlib.sha256(data).hexdigest(), len(funcs), notes, warn


def stack_trace(path, base, bits, addr):
    """Developer view of one function's stack tracking."""
    with open(path, "rb") as f:
        data = f.read()
    img, entries = Image.from_bytes(data, base, bits)
    an = Analyzer(img)
    an.discover(entries)
    fn = an.analyze_function(addr)
    items = [ins["ea"] for ins in fn["instructions"]]
    state, problems = an._stack_pass(addr, items, {}, join=True)
    sp, bp = an.m.sp, an.m.bp
    h = lambda v: "?" if v is None else "%+d" % v
    print("%s  function 0x%x  sha256 %s" % (path, addr, hashlib.sha256(data).hexdigest()))
    print("about: %s" % fn["about"])
    for w in fn["warnings"]:
        print(w)
    meet = {p[1]: p[2] for p in problems if p[0] == "merge"}
    print("\n%-12s %6s %6s  instruction" % ("address", sp, bp))
    for ins in fn["instructions"]:
        e, b = state.get(ins["ea"], (None, None))
        print("0x%-10x %6s %6s  %s" % (ins["ea"], h(e), h(b), ins["asm"]))
        if ins["ea"] in meet:
            print("%26s^ paths disagree here: %s" % ("", ", ".join(
                "%s from 0x%x" % (h(v), p) for p, v in sorted(meet[ins["ea"]].items()))))


def main():
    p = argparse.ArgumentParser(description="Report stack warnings across samples.")
    p.add_argument("paths", nargs="+", help="files and/or folders")
    p.add_argument("--base", default="0x401000", type=parse_addr, help="load address for raw files")
    p.add_argument("--bits", type=parse_bits, choices=[16, 32, 64],
                   help="code width for raw files (default 32); PE and DOS files set their own")
    p.add_argument("--sweep", action="store_true", help="also analyze code not reachable from the entry")
    p.add_argument("-v", "--verbose", action="store_true", help="print every warning")
    p.add_argument("--stack-trace", type=parse_addr, metavar="ADDR",
                   help="print the stack height (esp/ebp) at every instruction of the function "
                        "at ADDR, and which paths disagree where they meet")
    a = p.parse_args()

    if a.stack_trace is not None:
        for path in iter_files(a.paths):
            stack_trace(path, a.base, a.bits, a.stack_trace)
        return

    tot_files = tot_funcs = tot_warn_funcs = errors = 0
    for path in iter_files(a.paths):
        name = os.path.relpath(path)
        if name.startswith(".."):
            name = path
        try:
            sha, nfuncs, notes, warn = check(path, a.base, a.sweep, a.bits)
        except Exception as e:
            print("%-40s ERROR: %s" % (name, e))
            errors += 1
            continue
        tot_files += 1
        tot_funcs += nfuncs
        bad = sorted({ea for ea, _ in warn})
        tot_warn_funcs += len(bad)
        summary = "%-40s %5d functions  %3d with warnings  %3d auto-fixed" % (name, nfuncs, len(bad), notes)
        if bad:
            summary += "  (%s%s)" % (", ".join("0x%x" % x for x in bad[:5]), ", ..." if len(bad) > 5 else "")
        print(summary)
        if a.verbose:
            print("    sha256 %s" % sha)
            for ea, w in warn:
                print("    0x%x  %s" % (ea, w))

    print("\n%d files, %d functions, %d with stack warnings (%.1f%%), %d errors"
          % (tot_files, tot_funcs, tot_warn_funcs,
             100.0 * tot_warn_funcs / tot_funcs if tot_funcs else 0, errors))
    sys.exit(1 if errors and not tot_files else 0)


if __name__ == "__main__":
    main()
