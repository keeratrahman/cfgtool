"""LLM-facing tools built on cfg_core, shared by the OpenRouter agent and the MCP server.

Designed for small/cheap models:
  * few parameters, fixed choices, addresses always read as hex
  * small outputs: list functions first, then fetch one function at a time
  * never raise: every failure comes back as an "ERROR: ..." string the model can act on
"""
from __future__ import annotations

import hashlib
import json
import os

from capstone import CS_GRP_CALL

from cfg_core import Analyzer, Image, parse_hex, to_text

DEFAULT_MAX_INSTRUCTIONS = 150
FUNCTIONS_PER_PAGE = 60
_CACHE = {}  # (abs path, mtime, base) -> (Analyzer, image, default entries, sha256)

# Stack warnings seen this session: (sha256, function address, message) -> file name.
# cfg_agent.py writes these to a log for the developer.
WARNINGS = {}


def _record(sha, fname, funcs):
    n = 0
    for fn in funcs:
        for w in fn.get("warnings", []):
            if w.startswith("WARNING"):
                WARNINGS.setdefault((sha, "0x%x" % fn["entry"], w), fname)
                n += 1
    return n


# ------------------------------------------------------------------ helpers
def parse_address(v):
    """Addresses are hex: 0x401000, 401000, '0x401000' and 4198400 (JSON int) all work."""
    if isinstance(v, bool):
        raise ValueError("address must be a hex string like '0x401000'")
    if isinstance(v, int):
        return v
    s = str(v).strip().lower().rstrip("h")
    if s.startswith("0x"):
        s = s[2:]
    try:
        return int(s, 16)
    except ValueError:
        raise ValueError("bad address %r; use hex like '0x401000'" % (v,))


def _image_span(img):
    return ", ".join("0x%x-0x%x" % (b, b + len(d)) for b, d, _ in img.segments)


def _load(path, base_address):
    path = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.isfile(path):
        raise ValueError("file not found: %s" % path)
    base = parse_address(base_address)
    key = (path, os.path.getmtime(path), base)
    if key not in _CACHE:
        with open(path, "rb") as f:
            data = f.read()
        img, entries = Image.from_bytes(data, base)
        _CACHE[key] = (Analyzer(img), img, entries, hashlib.sha256(data).hexdigest())
    return _CACHE[key]


def _check_addr(an, img, addr):
    if an.insn(addr) is None:
        raise ValueError("no decodable instruction at 0x%x; image spans %s"
                         % (addr, _image_span(img)))


def _calls(an, fn_start):
    out = []
    for a in an.collect(fn_start):
        i = an.insn(a)
        if i.group(CS_GRP_CALL):
            t = an.direct_target(i)
            name = an.call_name(a)
            out.append(name or ("0x%x" % t if t is not None else "indirect(%s)" % i.op_str))
    return list(dict.fromkeys(out))


def _safe(fn):
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:  # report every failure as text so the model can retry
            return "ERROR: %s" % e
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# -------------------------------------------------------------------- tools
@_safe
def list_functions(path, base_address="0x401000", include_unreachable=False, offset=0):
    """One line per function: address, size, and the functions it calls.
    Shows FUNCTIONS_PER_PAGE functions starting at `offset`."""
    an, img, entries, sha = _load(path, base_address)
    starts = an.discover(entries, sweep=bool(include_unreachable))
    if not starts:
        return "ERROR: no decodable code at entry %s; image spans %s" % (
            [hex(e) for e in entries], _image_span(img))
    offset = max(0, int(offset or 0))
    page = starts[offset:offset + FUNCTIONS_PER_PAGE]
    lines = ["%d functions (entry point: %s). Use get_function(address) for details."
             % (len(starts), ", ".join("0x%x" % e for e in entries))]
    if len(starts) > FUNCTIONS_PER_PAGE:
        lines.append("Showing functions %d-%d of %d." % (offset + 1, offset + len(page), len(starts)))
    for s in page:
        try:
            info = an.analyze_function(s)
            calls = _calls(an, s)
        except Exception as e:  # keep listing the other functions
            lines.append("0x%x  (analysis failed: %s)" % (s, e))
            continue
        nwarn = _record(sha, os.path.basename(str(path)), [info])
        lines.append("0x%x  %d instructions, %d blocks, calls: %s%s"
                     % (s, len(info["instructions"]), len(info["blocks"]),
                        ", ".join(calls) if calls else "-",
                        "  (%d stack warning%s)" % (nwarn, "s" * (nwarn > 1)) if nwarn else ""))
    if offset + len(page) < len(starts):
        lines.append("... %d more functions: call list_functions again with offset=%d."
                     % (len(starts) - offset - len(page), offset + len(page)))
    return "\n".join(lines)


@_safe
def get_function(path, address, base_address="0x401000",
                 format="text", max_instructions=DEFAULT_MAX_INSTRUCTIONS):
    """CFG of one function: basic blocks, edges, defs/uses and data dependencies.
    An address inside a function returns the whole containing function."""
    an, img, entries, sha = _load(path, base_address)
    addr = parse_address(address)
    _check_addr(an, img, addr)
    start, note = addr, ""
    starts = an.discover(entries)
    if addr not in starts:
        # nearest discovered function at or below addr that actually contains it
        owners = [s for s in starts if s <= addr and addr in an.collect(s)]
        if owners:
            start = max(owners)
            note = ("NOTE: 0x%x is inside function 0x%x; showing the whole function.\n\n"
                    % (addr, start))
    info = an.analyze_function(start)
    _record(sha, os.path.basename(str(path)), [info])
    return note + _render([info], format, max_instructions)


@_safe
def analyze_hex(code_hex, base_address="0x401000",
                format="text", max_instructions=DEFAULT_MAX_INSTRUCTIONS):
    """CFG of a short machine-code snippet given as hex bytes (all functions it calls included)."""
    data = parse_hex(code_hex)
    img, entries = Image.from_bytes(data, parse_address(base_address))
    an = Analyzer(img)
    _check_addr(an, img, entries[0])
    funcs = an.analyze(entries)
    _record(hashlib.sha256(data).hexdigest(), "(hex snippet)", funcs)
    return _render(funcs, format, max_instructions)


def _render(funcs, format, max_instructions):
    if format == "json":
        from cfg_core import to_json
        return json.dumps(json.loads(to_json(funcs)), separators=(",", ":"))  # compact = fewer tokens
    if format != "text":
        raise ValueError("format must be 'text' or 'json'")
    n = int(max_instructions) if max_instructions else DEFAULT_MAX_INSTRUCTIONS
    return to_text(funcs, max_instructions=max(1, n), legend=True)


# ------------------------------------------- OpenAI / OpenRouter tool schemas
_ADDR = {"type": "string", "description": "Hex address, e.g. '0x401000'."}
_BASE = {"type": "string", "description": "Load address for raw (non-PE) files. "
                                           "Ignored for PE files. Default '0x401000'."}
_FMT = {"type": "string", "enum": ["text", "json"],
        "description": "'text' (default, easiest to read) or 'json'."}
_MAX = {"type": "integer", "description": "Max instructions to show, text format only (default %d)."
                                          % DEFAULT_MAX_INSTRUCTIONS}

TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "list_functions",
        "description": "List the functions in a binary file (32-bit x86 PE or raw code). "
                       "Call this first to get function addresses.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Path to the binary file."},
            "base_address": _BASE,
            "include_unreachable": {"type": "boolean",
                                    "description": "Also list code not reached from the entry point."},
            "offset": {"type": "integer",
                       "description": "Skip this many functions (for paging; default 0)."},
        }, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "get_function",
        "description": "Get the control-flow graph of ONE function: basic blocks, edges, "
                       "and for each instruction what it writes (D), reads (U) and depends on (DD).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Path to the binary file."},
            "address": _ADDR,
            "base_address": _BASE,
            "format": _FMT,
            "max_instructions": _MAX,
        }, "required": ["path", "address"]}}},
    {"type": "function", "function": {
        "name": "analyze_hex",
        "description": "Get the control-flow graph of a SHORT x86-32 machine-code snippet "
                       "given as hex bytes. Use list_functions/get_function for files instead.",
        "parameters": {"type": "object", "properties": {
            "code_hex": {"type": "string", "description": "Hex bytes, e.g. '55 8b ec 5d c3'."},
            "base_address": {"type": "string", "description": "Address of the first byte. Default '0x401000'."},
            "format": _FMT,
            "max_instructions": _MAX,
        }, "required": ["code_hex"]}}},
]

TOOLS = {"list_functions": list_functions, "get_function": get_function, "analyze_hex": analyze_hex}


def dispatch(name, arguments):
    """Run a tool call. `arguments` may be a JSON string or dict. Always returns a string."""
    if name not in TOOLS:
        return "ERROR: unknown tool %r; available: %s" % (name, ", ".join(TOOLS))
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments) if arguments.strip() else {}
        except json.JSONDecodeError as e:
            return "ERROR: tool arguments are not valid JSON (%s). Send a JSON object." % e
    if not isinstance(arguments, dict):
        return "ERROR: tool arguments must be a JSON object"
    allowed = TOOL_SCHEMAS[list(TOOLS).index(name)]["function"]["parameters"]["properties"]
    unknown = [k for k in arguments if k not in allowed]
    args = {k: v for k, v in arguments.items() if k in allowed and v is not None}
    try:
        result = TOOLS[name](**args)
    except TypeError as e:  # missing required argument
        return "ERROR: %s" % e
    if unknown:
        result = "(ignored unknown arguments: %s)\n%s" % (", ".join(unknown), result)
    return result
