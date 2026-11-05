#!/usr/bin/env python3
"""MCP server exposing the CFG builder to an LLM.

Run:  python cfg_mcp_server.py        (stdio transport)
Claude Code:  claude mcp add cfg-builder -- python /path/to/cfg_mcp_server.py
"""
from typing import List, Optional

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from cfg_core import parse_addr, parse_hex, run

mcp = _Server("cfg-builder")


@mcp.tool()
def build_cfg(code_hex: str,
              base_address: str = "0x401000",
              entry_points: Optional[List[str]] = None,
              format: str = "text",
              mode: str = "both",
              sweep: bool = False) -> str:
    """Build a control-flow graph with per-instruction defs/uses and data dependencies
    from x86-32 machine code.

    Args:
        code_hex: machine code as hex bytes, e.g. "55 8b ec 8b 45 08 5d c3".
        base_address: address the first byte is loaded at (default 0x401000).
        entry_points: function entry addresses (default: base_address). Functions called
            from these are discovered automatically.
        format: "text" (compact listing, best for reading), "json" (structured), or "dot" (Graphviz).
        mode: DOT only. "cfg" = defs/uses + control-flow edges, "ddg" = data-dependency edges,
            "both" = merged (default).
        sweep: also treat unreachable code as extra functions.

    Labels: D = locations defined, U = locations used, DD = addresses of the instructions
    whose definitions reach this one (START = value on function entry). stk_N is a stack slot
    at offset N from the entry esp.
    """
    data = parse_hex(code_hex)
    return run(data, parse_addr(base_address), entry_points, format, mode, sweep)


@mcp.tool()
def build_cfg_from_file(path: str,
                        base_address: str = "0x401000",
                        entry_points: Optional[List[str]] = None,
                        format: str = "text",
                        mode: str = "both",
                        sweep: bool = False) -> str:
    """Same as build_cfg but reads a raw binary or 32-bit PE file from disk
    (PE files use their own image base and entry point)."""
    with open(path, "rb") as f:
        data = f.read()
    return run(data, parse_addr(base_address), entry_points, format, mode, sweep)


if __name__ == "__main__":
    mcp.run()
