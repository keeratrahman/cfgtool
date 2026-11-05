#!/usr/bin/env python3
"""Command-line front end for cfg_core.

Examples:
  python cfg_cli.py --hex "55 8b ec 5d c3" --base 0x401000
  python cfg_cli.py sample.bin --base 0x401000 --entry 0x401000 --format dot --mode cfg -o out.dot
  python cfg_cli.py malware.exe --format json --sweep
"""
import argparse
import sys

from cfg_core import parse_addr, parse_hex, run


def main():
    p = argparse.ArgumentParser(description="Build a CFG / def-use / data-dependency graph from x86-32 code.")
    p.add_argument("file", nargs="?", help="raw binary or 32-bit PE (omit when using --hex)")
    p.add_argument("--hex", help="hex bytes, e.g. '55 8b ec c3'")
    p.add_argument("--base", default="0x401000", type=parse_addr, help="load address for raw bytes (default 0x401000)")
    p.add_argument("--entry", action="append", help="function entry point (repeatable); default = base / PE entry")
    p.add_argument("--format", choices=["text", "dot", "json"], default="text")
    p.add_argument("--mode", choices=["cfg", "ddg", "both"], default="both",
                   help="DOT only: cfg = Lab 3 style, ddg = Lab 4 style, both = merged")
    p.add_argument("--sweep", action="store_true", help="also create functions for code not reachable from the entries")
    p.add_argument("-o", "--output", help="write to file instead of stdout")
    a = p.parse_args()

    if a.hex:
        data = parse_hex(a.hex)
    elif a.file:
        with open(a.file, "rb") as f:
            data = f.read()
    else:
        p.error("provide a file or --hex")

    result = run(data, a.base, a.entry, a.format, a.mode, a.sweep)
    if a.output:
        with open(a.output, "w") as f:
            f.write(result)
        print("Wrote to:", a.output, file=sys.stderr)
    else:
        print(result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError) as e:  # bad file, bad hex, unsupported PE, ...
        sys.exit("ERROR: %s" % e)
    except Exception as e:  # unexpected bug: save details for the developer
        import datetime
        import os
        import traceback
        log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfgtool_errors.log")
        with open(log, "a", encoding="utf-8") as f:
            f.write("=== %s  %s\n" % (datetime.datetime.now().isoformat(timespec="seconds"), " ".join(sys.argv)))
            traceback.print_exception(type(e), e, e.__traceback__, file=f)
        sys.exit("ERROR: unexpected %s: %s\nDetails saved to cfgtool_errors.log. Please send this file to Keerat."
                 % (type(e).__name__, e))
