#!/usr/bin/env python3
"""Developer check: analyze every function in a set of samples and report stack warnings.

No LLM, no network, and it never runs the samples, only reads their bytes.

Examples:
  python cfg_check.py samples/                 # every PE file under samples/ (recursive)
  python cfg_check.py a.exe b.dll -v           # also print each warning
  python cfg_check.py raw.bin --base 0x10000   # raw code (files given by name only)
"""
import argparse
import hashlib
import os
import sys

from cfg_core import Analyzer, Image, parse_addr


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


def check(path, base, sweep):
    with open(path, "rb") as f:
        data = f.read()
    img, entries = Image.from_bytes(data, base)
    an = Analyzer(img)
    funcs = an.analyze(entries, sweep)
    warn = [(fn["entry"], w) for fn in funcs for w in fn["warnings"] if w.startswith("WARNING")]
    notes = sum(1 for fn in funcs for w in fn["warnings"] if w.startswith("note"))
    return hashlib.sha256(data).hexdigest(), len(funcs), notes, warn


def main():
    p = argparse.ArgumentParser(description="Report stack warnings across samples.")
    p.add_argument("paths", nargs="+", help="files and/or folders")
    p.add_argument("--base", default="0x401000", type=parse_addr, help="load address for raw files")
    p.add_argument("--sweep", action="store_true", help="also analyze code not reachable from the entry")
    p.add_argument("-v", "--verbose", action="store_true", help="print every warning")
    a = p.parse_args()

    tot_files = tot_funcs = tot_warn_funcs = errors = 0
    for path in iter_files(a.paths):
        name = os.path.relpath(path)
        if name.startswith(".."):
            name = path
        try:
            sha, nfuncs, notes, warn = check(path, a.base, a.sweep)
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
