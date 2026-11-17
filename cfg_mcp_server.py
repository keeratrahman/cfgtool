#!/usr/bin/env python3
"""MCP server exposing the CFG tools to an LLM (Claude Code, Cursor, ...).

Run:  python cfg_mcp_server.py        (stdio transport)
Claude Code:  claude mcp add cfg-builder -- python /path/to/cfg_mcp_server.py
"""
from typing import Literal, Optional

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

import cfg_tools

mcp = _Server("cfg-builder")


@mcp.tool()
def list_functions(path: str, base_address: str = "0x401000", include_unreachable: bool = False,
                   offset: int = 0, bits: Optional[Literal[16, 32, 64]] = None) -> str:
    """List the functions in a binary file (x86 PE 32/64-bit, 16-bit DOS MZ, or raw code), 60 per
    call. Call this first to get function addresses; use offset to page. base_address and bits
    only matter for raw files (bits default 32; .COM files: bits=16, base_address='0x100')."""
    return cfg_tools.list_functions(path, base_address, include_unreachable, offset, bits)


@mcp.tool()
def get_function(path: str, address: str, base_address: str = "0x401000",
                 format: Literal["text", "json"] = "text",
                 max_instructions: int = cfg_tools.DEFAULT_MAX_INSTRUCTIONS,
                 bits: Optional[Literal[16, 32, 64]] = None) -> str:
    """Control-flow graph of ONE function (hex address, e.g. '0x401000'): basic blocks,
    edges, and per instruction what it writes (D), reads (U) and depends on (DD)."""
    return cfg_tools.get_function(path, address, base_address, format, max_instructions, bits)


@mcp.tool()
def analyze_hex(code_hex: str, base_address: str = "0x401000",
                format: Literal["text", "json"] = "text",
                max_instructions: int = cfg_tools.DEFAULT_MAX_INSTRUCTIONS,
                bits: Literal[16, 32, 64] = 32) -> str:
    """Control-flow graph of a SHORT x86 snippet (16, 32 or 64-bit; default 32) given as hex
    bytes, e.g. '55 8b ec 5d c3'. Use list_functions/get_function for files instead."""
    return cfg_tools.analyze_hex(code_hex, base_address, format, max_instructions, bits)


if __name__ == "__main__":
    mcp.run()
